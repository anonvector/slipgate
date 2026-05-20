package warp

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/config"
)

const (
	WarpDir     = "/etc/slipgate/warp"
	WarpConf    = "/etc/slipgate/warp/wg0.conf"
	ProfileFile = "/etc/slipgate/warp/wgcf-profile.conf" // legacy wgcf profile
	ServiceName = "slipgate-warp"
	RouteTable  = 200

	// SocksUser is a dedicated system user for the SOCKS5 proxy so its
	// outbound traffic can be routed through WARP independently of the
	// tunnel processes that also run as config.SystemUser.
	SocksUser = "slipgate-socks"

	// NaiveUser is a dedicated system user for the Caddy/NaiveProxy
	// process so its forward-proxy traffic can be routed through WARP.
	NaiveUser = "slipgate-naive"

	// PublicAddrRulePref is the `ip rule` priority for "from <public-ip>
	// lookup main" rules. Set well below the default uidrange rule pref
	// (~32766) so it wins for traffic sourced from the host's public IPs
	// — i.e. replies on already-accepted inbound TCP connections. Without
	// this, a SOCKS5 client SYN arrives on eth0 but the SYN-ACK exits wg0
	// (because the SOCKS user's UID rule sends everything to table 200);
	// Cloudflare drops it because the source isn't a WARP-assigned address,
	// and the client sees "connected, no traffic".
	PublicAddrRulePref = 100
)

var httpClient = &http.Client{Timeout: 120 * time.Second}

// Setup registers a WARP account, generates WireGuard config, and creates the systemd service.
func Setup(cfg *config.Config, log func(string)) error {
	if log == nil {
		log = func(string) {}
	}

	if err := os.MkdirAll(WarpDir, 0750); err != nil {
		return fmt.Errorf("create warp dir: %w", err)
	}

	log("Installing wireguard-tools...")
	if err := ensureWireGuardTools(); err != nil {
		return fmt.Errorf("install wireguard-tools: %w", err)
	}

	log("Configuring public DNS resolvers for WARP-routed services...")
	if err := ensurePublicResolvers(); err != nil {
		// Non-fatal: warn only. Install shouldn't abort on a DNS config
		// mishap, but the operator should know why naiveproxy / outbound
		// HTTPS from WARP-routed users will fail at runtime.
		log(fmt.Sprintf("warn: public resolvers setup failed: %v", err))
	}

	// Load or create WARP account
	account, err := LoadAccount()
	if err != nil {
		// Try migrating from legacy wgcf files
		if _, statErr := os.Stat(ProfileFile); statErr == nil {
			log("Migrating from wgcf profile...")
			account, err = migrateFromWgcf()
			if err != nil {
				return fmt.Errorf("migrate wgcf: %w", err)
			}
		} else {
			log("Registering WARP account...")
			account, err = registerWARP()
			if err != nil {
				return fmt.Errorf("register WARP: %w", err)
			}
		}
		if err := SaveAccount(account); err != nil {
			return fmt.Errorf("save account: %w", err)
		}
	}

	log("Creating service users...")
	if err := ensureSocksUser(); err != nil {
		return fmt.Errorf("create socks user: %w", err)
	}

	if err := ensureNaiveUser(); err != nil {
		return fmt.Errorf("create naive user: %w", err)
	}

	if err := setNaiveCapability(); err != nil {
		return fmt.Errorf("set naive capability: %w", err)
	}

	log("Generating WireGuard config...")
	if err := generateWgConf(cfg); err != nil {
		return fmt.Errorf("generate wg config: %w", err)
	}

	if err := createService(); err != nil {
		return err
	}

	// If WARP is already running, the new wg0.conf won't take effect until
	// the interface is restarted — which would drop every in-flight TCP
	// stream. Live-install the public-addr rules now so existing servers
	// upgrading via `slipgate install` get the asymmetric-routing fix
	// without a restart.
	if IsRunning() {
		ensurePublicAddrRules()
	}
	return nil
}

// Enable starts the WARP WireGuard interface.
func Enable() error {
	if err := run("systemctl", "enable", ServiceName+".service"); err != nil {
		return err
	}
	if err := run("systemctl", "start", ServiceName+".service"); err != nil {
		return err
	}
	// Backfill the public-addr rules in case wg-quick's PostUp swallowed an
	// error (PostUp lines are `|| true` to keep WARP up even if rule install
	// fails). Idempotent — no-op if PostUp already added them.
	ensurePublicAddrRules()
	return nil
}

// Disable stops the WARP WireGuard interface.
func Disable() error {
	_ = runQuiet("systemctl", "stop", ServiceName+".service")
	_ = runQuiet("systemctl", "disable", ServiceName+".service")
	// Clean up any leftover policy routing rules that wg-quick down
	// may have failed to remove. Without this, managed user UIDs
	// remain routed to table 200 which has no routes after the
	// WireGuard interface is torn down — blackholing their traffic.
	flushRoutingRules()
	return nil
}

// flushRoutingRules removes all ip rules pointing to our routing table,
// plus the public-addr "lookup main" rules. The public-addr rules look up
// the main table (not table 200), so the table-based loop above doesn't
// catch them; we delete by pref instead. Both v4 and v6 rule tables are
// independent, so iterate each family separately.
func flushRoutingRules() {
	for {
		if runQuiet("ip", "rule", "del", "table", fmt.Sprintf("%d", RouteTable)) != nil {
			break
		}
	}
	for _, fam := range []string{"-4", "-6"} {
		for {
			if runQuiet("ip", fam, "rule", "del", "pref", strconv.Itoa(PublicAddrRulePref)) != nil {
				break
			}
		}
	}
}

// IsRunning checks if the WARP interface is active.
func IsRunning() bool {
	out, err := exec.Command("systemctl", "is-active", ServiceName+".service").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// IsSetUp checks if WARP has been configured.
func IsSetUp() bool {
	_, err := os.Stat(WarpConf)
	return err == nil
}

// RefreshRouting regenerates wg0.conf with current user UIDs and, if WARP is
// running, syncs the live `ip rule` uidrange entries in place. The WireGuard
// interface is NOT restarted — doing so would drop every in-flight TCP stream
// routed through WARP (naiveproxy sessions, SOCKS traffic, etc.) every time a
// user is added or removed.
func RefreshRouting(cfg *config.Config) error {
	if !IsSetUp() {
		return nil
	}
	if err := generateWgConf(cfg); err != nil {
		return err
	}
	if IsRunning() {
		syncLiveRules(collectUserUIDs(cfg))
		ensurePublicAddrRules()
	}
	return nil
}

// syncLiveRules reconciles the kernel's `ip rule` state for our routing table
// against the desired UID set, adding missing entries and removing obsolete
// ones. Rules for UIDs that are in both sets are left untouched.
func syncLiveRules(desired []int) {
	want := make(map[int]bool, len(desired))
	for _, uid := range desired {
		want[uid] = true
	}

	have, err := listLiveRuleUIDs()
	if err != nil {
		log.Printf("warp: list live ip rules: %v (skipping live sync; run `systemctl restart %s` to pick up changes)", err, ServiceName)
		return
	}
	haveSet := make(map[int]bool, len(have))
	for _, uid := range have {
		haveSet[uid] = true
	}

	table := strconv.Itoa(RouteTable)
	var addFails, delFails int
	for uid := range want {
		if !haveSet[uid] {
			if err := ipRule("add", uid, table); err != nil {
				log.Printf("warp: %v", err)
				addFails++
			}
		}
	}
	for uid := range haveSet {
		if !want[uid] {
			if err := ipRule("del", uid, table); err != nil {
				log.Printf("warp: %v", err)
				delFails++
			}
		}
	}
	if addFails+delFails > 0 {
		log.Printf("warp: syncLiveRules: %d add / %d del failures — affected users may not route through WARP", addFails, delFails)
	}
}

// ipRule runs `ip rule <op> uidrange U-U table T` and returns an error
// that includes the combined stdout/stderr. Used by syncLiveRules so
// failures are diagnosable instead of silently dropped.
func ipRule(op string, uid int, table string) error {
	out, err := exec.Command("ip", "rule", op, "uidrange",
		fmt.Sprintf("%d-%d", uid, uid), "table", table).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip rule %s uid=%d: %w: %s",
			op, uid, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// listLiveRuleUIDs returns the single-UID uidrange entries currently pointing
// at our routing table. Lines from `ip rule show table N` look like:
//
//	32766: from all lookup 200 uidrange 1001-1001
func listLiveRuleUIDs() ([]int, error) {
	out, err := exec.Command("ip", "rule", "show", "table", strconv.Itoa(RouteTable)).Output()
	if err != nil {
		return nil, err
	}
	var uids []int
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, "uidrange ")
		if idx < 0 {
			continue
		}
		rest := strings.Fields(line[idx+len("uidrange "):])
		if len(rest) == 0 {
			continue
		}
		parts := strings.SplitN(rest[0], "-", 2)
		if len(parts) != 2 {
			continue
		}
		lo, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		hi, err := strconv.Atoi(parts[1])
		if err != nil || lo != hi {
			continue
		}
		uids = append(uids, lo)
	}
	return uids, nil
}

// addrEntry pairs a public IP address with the `ip` family flag (`-4`/`-6`)
// needed to manipulate its rule. Family is explicit because `ip rule` does
// not infer it from the address argument.
type addrEntry struct {
	family string
	addr   string
}

// detectPublicAddrs returns the host's public IP addresses (v4 and v6) by
// reading the source of the default route in the main routing table. These
// are the addresses inbound TCP connections (e.g. SOCKS5 clients) target,
// so reply traffic must be routed back via the same interface — not into
// table 200 — to avoid asymmetric routing where SYN-ACKs exit wg0 and
// Cloudflare drops them. Best-effort: returns nil if no default route is
// configured (unusual; would mean the host has no internet at all).
func detectPublicAddrs() []addrEntry {
	var addrs []addrEntry
	for _, fam := range []string{"-4", "-6"} {
		if a, err := defaultRouteSrcAddr(fam); err == nil && a != "" {
			addrs = append(addrs, addrEntry{family: fam, addr: a})
		}
	}
	return addrs
}

func defaultRouteSrcAddr(family string) (string, error) {
	out, err := exec.Command("ip", family, "route", "show", "default", "table", "main").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	var iface string
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			iface = fields[i+1]
			break
		}
	}
	if iface == "" {
		return "", fmt.Errorf("no dev in default route")
	}
	out, err = exec.Command("ip", family, "-o", "addr", "show", "dev", iface, "scope", "global").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" || f[i] == "inet6" {
				return strings.SplitN(f[i+1], "/", 2)[0], nil
			}
		}
	}
	return "", fmt.Errorf("no global-scope address on %s", iface)
}

// ensurePublicAddrRules adds "from <pub-ip> lookup main pref 100" rules for
// each detected public address that doesn't already have one. Idempotent;
// safe to run while WARP is active (no connections are dropped).
func ensurePublicAddrRules() {
	addrs := detectPublicAddrs()
	if len(addrs) == 0 {
		log.Printf("warp: could not detect public address; reverse-route rule not applied (inbound SOCKS may break)")
		return
	}
	for _, e := range addrs {
		if hasPublicAddrRule(e) {
			continue
		}
		out, err := exec.Command("ip", e.family, "rule", "add", "from", e.addr,
			"lookup", "main", "pref", strconv.Itoa(PublicAddrRulePref)).CombinedOutput()
		if err != nil {
			log.Printf("warp: ip %s rule add from %s: %v: %s",
				e.family, e.addr, err, strings.TrimSpace(string(out)))
		}
	}
}

func hasPublicAddrRule(e addrEntry) bool {
	out, err := exec.Command("ip", e.family, "rule", "show",
		"pref", strconv.Itoa(PublicAddrRulePref)).Output()
	if err != nil {
		return false
	}
	// Kernel may render the source as "<addr>" or "<addr>/32" (or /128 for v6).
	return strings.Contains(string(out), "from "+e.addr+" ") ||
		strings.Contains(string(out), "from "+e.addr+"/")
}

// Uninstall removes all WARP configuration and services.
func Uninstall() {
	_ = Disable()
	_ = removeService()
	_ = os.RemoveAll(WarpDir)
	removePublicResolversOverride()
	// Clean up legacy wgcf binary if present
	_ = os.Remove("/usr/local/bin/wgcf")
}

// RemoveUsers removes the dedicated SOCKS and NaiveProxy system users
// created for WARP routing.
func RemoveUsers() {
	_ = tryRun("userdel", SocksUser)
	_ = tryRun("userdel", NaiveUser)
}

// generateWgConf reads the WARP account and writes a custom wg0.conf
// with policy-routing rules for managed SSH users.
func generateWgConf(cfg *config.Config) error {
	account, err := LoadAccount()
	if err != nil {
		// Auto-migrate from legacy wgcf files if present
		account, err = migrateFromWgcf()
		if err != nil {
			return fmt.Errorf("load account: no account.json and no wgcf profile to migrate from")
		}
		_ = SaveAccount(account)
	}

	uids := collectUserUIDs(cfg)
	ipv6 := cfg.Warp.IPv6

	// wg-quick with Table=200 and AllowedIPs=0.0.0.0/0 already adds the
	// default route to table 200.  PostUp/PostDown only need ip-rule entries
	// to steer specific UIDs into that table.
	var postUp, postDown []string

	// "from <public-ip> lookup main" overrides the per-UID WARP rule for
	// reply traffic on accepted inbound connections — see PublicAddrRulePref.
	// `|| true` keeps a failed rule add (already exists, kernel objection,
	// odd address format) from aborting `wg-quick up` and breaking WARP
	// entirely — the rule is also backfilled live by ensurePublicAddrRules
	// so a silent PostUp failure is recoverable.
	for _, e := range detectPublicAddrs() {
		if !ipv6 && e.family == "-6" {
			continue
		}
		postUp = append(postUp, fmt.Sprintf("ip %s rule add from %s lookup main pref %d || true",
			e.family, e.addr, PublicAddrRulePref))
		postDown = append(postDown, fmt.Sprintf("ip %s rule del from %s lookup main pref %d || true",
			e.family, e.addr, PublicAddrRulePref))
	}

	for _, uid := range uids {
		postUp = append(postUp, fmt.Sprintf("ip rule add uidrange %d-%d table %d", uid, uid, RouteTable))
		postDown = append(postDown, fmt.Sprintf("ip rule del uidrange %d-%d table %d", uid, uid, RouteTable))
	}

	var conf strings.Builder
	conf.WriteString("[Interface]\n")
	conf.WriteString(fmt.Sprintf("PrivateKey = %s\n", account.PrivateKey))
	for _, addr := range account.Addresses {
		// In IPv4-only mode skip WARP's IPv6 interface address (contains ':').
		if !ipv6 && strings.Contains(addr, ":") {
			continue
		}
		conf.WriteString(fmt.Sprintf("Address = %s\n", addr))
	}
	conf.WriteString("MTU = 1280\n")
	conf.WriteString(fmt.Sprintf("Table = %d\n", RouteTable))
	for _, cmd := range postUp {
		conf.WriteString(fmt.Sprintf("PostUp = %s\n", cmd))
	}
	for _, cmd := range postDown {
		conf.WriteString(fmt.Sprintf("PostDown = %s\n", cmd))
	}

	conf.WriteString("\n[Peer]\n")
	conf.WriteString(fmt.Sprintf("PublicKey = %s\n", account.PeerKey))
	conf.WriteString(fmt.Sprintf("Endpoint = %s\n", account.Endpoint))
	if ipv6 {
		conf.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	} else {
		conf.WriteString("AllowedIPs = 0.0.0.0/0\n")
	}
	conf.WriteString("PersistentKeepalive = 25\n")

	return os.WriteFile(WarpConf, []byte(conf.String()), 0600)
}

type wgProfile struct {
	privateKey string
	addresses  []string
	publicKey  string
	endpoint   string
}

func parseWgProfile(path string) (*wgProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p := &wgProfile{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, val := splitKV(line)
		switch key {
		case "PrivateKey":
			p.privateKey = val
		case "Address":
			p.addresses = append(p.addresses, val)
		case "PublicKey":
			p.publicKey = val
		case "Endpoint":
			p.endpoint = val
		}
	}

	if p.privateKey == "" || p.publicKey == "" || p.endpoint == "" {
		return nil, fmt.Errorf("incomplete wgcf profile at %s", path)
	}
	return p, scanner.Err()
}

func splitKV(line string) (string, string) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func collectUserUIDs(cfg *config.Config) []int {
	var uids []int

	// SSH tunnel users
	for _, u := range cfg.Users {
		uid := lookupUID(u.Username)
		if uid > 0 {
			uids = append(uids, uid)
		}
	}

	// Dedicated SOCKS proxy user
	if uid := lookupUID(SocksUser); uid > 0 {
		uids = append(uids, uid)
	}

	// NaiveProxy's user (slipgate-naive) is intentionally NOT routed
	// through WARP. Caddy is just an HTTPS-wrapped TCP forwarder — actual
	// proxied traffic terminates on 127.0.0.1:1080 (slipgate-socks) or
	// 127.0.0.1:22 (per-tunnel SSH user), both of which ARE in the WARP
	// table. So proxied egress already routes through WARP at the next
	// hop. Putting Caddy itself in the WARP table is redundant and breaks
	// ACME cert acquisition because Let's Encrypt's API isn't reliably
	// reachable through WARP from cloud-provider networks.

	return uids
}

// ensureNaiveUser creates the dedicated NaiveProxy system user.
func ensureNaiveUser() error {
	if err := exec.Command("id", NaiveUser).Run(); err == nil {
		return nil
	}
	_ = tryRun("groupadd", "--system", config.SystemGroup)
	return run("useradd", "--system", "--no-create-home",
		"--shell", "/usr/sbin/nologin",
		"--gid", config.SystemGroup,
		NaiveUser)
}

// setNaiveCapability sets CAP_NET_BIND_SERVICE on caddy-naive so it can
// bind to port 443 without running as root.
func setNaiveCapability() error {
	binPath := filepath.Join(config.DefaultBinDir, "caddy-naive")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return nil // binary not installed yet, will be set later
	}
	return tryRun("setcap", "cap_net_bind_service=+ep", binPath)
}

// ensureSocksUser creates the dedicated SOCKS proxy system user.
func ensureSocksUser() error {
	// Check if already exists
	if err := exec.Command("id", SocksUser).Run(); err == nil {
		return nil
	}

	// Ensure the slipgate group exists
	_ = tryRun("groupadd", "--system", config.SystemGroup)

	return run("useradd", "--system", "--no-create-home",
		"--shell", "/usr/sbin/nologin",
		"--gid", config.SystemGroup,
		SocksUser)
}

func lookupUID(username string) int {
	out, err := exec.Command("id", "-u", username).Output()
	if err != nil {
		return -1
	}
	var uid int
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &uid)
	return uid
}

func createService() error {
	wgQuickPath, err := exec.LookPath("wg-quick")
	if err != nil {
		wgQuickPath = "/usr/bin/wg-quick"
	}

	content := fmt.Sprintf(`[Unit]
Description=SlipGate WARP (Cloudflare WireGuard)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s up %s
ExecStop=%s down %s

[Install]
WantedBy=multi-user.target
`, wgQuickPath, WarpConf, wgQuickPath, WarpConf)

	path := filepath.Join("/etc/systemd/system", ServiceName+".service")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	return exec.Command("systemctl", "daemon-reload").Run()
}

func removeService() error {
	path := filepath.Join("/etc/systemd/system", ServiceName+".service")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}

// resolvedDropIn is the systemd-resolved drop-in slipgate installs so that
// WARP-routed services can resolve DNS. Removed on Uninstall.
const resolvedDropIn = "/etc/systemd/resolved.conf.d/slipgate-warp-dns.conf"

// ensurePublicResolvers makes the system use public DNS resolvers reachable
// from behind WARP. Many cloud providers default to LAN-only resolvers
// (DigitalOcean: 67.207.67.x, AWS: 169.254.169.253, GCP: 169.254.169.254)
// that silently drop queries originating from outside their network — so
// any WARP-routed slipgate service (NaiveProxy, per-user SOCKS egress, etc.)
// can't resolve anything. That breaks Caddy's Let's Encrypt acquisition on
// first install and every outbound HTTPS call after.
//
// When systemd-resolved is active, we configure it via drop-in so it
// advertises 1.1.1.1/8.8.8.8 as the primary DNS — persisting across reboots
// and network events. When it's not, we write /etc/resolv.conf directly,
// unlinking any existing symlink first (otherwise os.WriteFile follows the
// link into /run/systemd/resolve/... which the system regenerates).
func ensurePublicResolvers() error {
	if err := exec.Command("systemctl", "is-active", "systemd-resolved").Run(); err == nil {
		if err := os.MkdirAll(filepath.Dir(resolvedDropIn), 0755); err != nil {
			return fmt.Errorf("create resolved.conf.d: %w", err)
		}
		conf := "[Resolve]\nDNS=1.1.1.1 8.8.8.8\nFallbackDNS=1.0.0.1 8.8.4.4\n"
		if err := os.WriteFile(resolvedDropIn, []byte(conf), 0644); err != nil {
			return fmt.Errorf("write %s: %w", resolvedDropIn, err)
		}
		return run("systemctl", "restart", "systemd-resolved")
	}

	// No systemd-resolved — write /etc/resolv.conf directly. Remove first
	// in case it's a symlink to a managed file.
	_ = os.Remove("/etc/resolv.conf")
	return os.WriteFile("/etc/resolv.conf",
		[]byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0644)
}

// removePublicResolversOverride reverses ensurePublicResolvers when WARP is
// uninstalled. No-op if the drop-in doesn't exist.
func removePublicResolversOverride() {
	if _, err := os.Stat(resolvedDropIn); os.IsNotExist(err) {
		return
	}
	_ = os.Remove(resolvedDropIn)
	if err := exec.Command("systemctl", "is-active", "systemd-resolved").Run(); err == nil {
		_ = runQuiet("systemctl", "restart", "systemd-resolved")
	}
}

func ensureWireGuardTools() error {
	if _, err := exec.LookPath("wg-quick"); err == nil {
		return nil
	}

	// Try apt (Debian/Ubuntu) — install the "wireguard" meta-package which
	// pulls in both wireguard-tools and the kernel module (wireguard-dkms on
	// older kernels). Installing only wireguard-tools leaves the kernel
	// module missing on some Debian systems, causing wg-quick to fail.
	cmd := exec.Command("apt-get", "install", "-y", "wireguard")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cmd.Run() == nil {
		return nil
	}

	// Try dnf (Fedora/RHEL 8+)
	if run("dnf", "install", "-y", "wireguard-tools") == nil {
		return nil
	}
	// Try yum (CentOS/RHEL 7)
	if run("yum", "install", "-y", "wireguard-tools") == nil {
		return nil
	}
	return fmt.Errorf("please install wireguard-tools manually")
}


func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runQuiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func tryRun(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
