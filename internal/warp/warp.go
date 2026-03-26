package warp

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/config"
)

const (
	WarpDir     = "/etc/slipgate/warp"
	WarpConf    = "/etc/slipgate/warp/wg0.conf"
	AccountFile = "/etc/slipgate/warp/wgcf-account.toml"
	ProfileFile = "/etc/slipgate/warp/wgcf-profile.conf"
	WgcfBin     = "/usr/local/bin/wgcf"
	ServiceName = "slipgate-warp"
	RouteTable  = 200

	// SocksUser is a dedicated system user for the SOCKS5 proxy so its
	// outbound traffic can be routed through WARP independently of the
	// tunnel processes that also run as config.SystemUser.
	SocksUser = "slipgate-socks"

	// NaiveUser is a dedicated system user for the Caddy/NaiveProxy
	// process so its forward-proxy traffic can be routed through WARP.
	NaiveUser = "slipgate-naive"
)

const wgcfVersion = "2.2.22"

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

	if _, err := os.Stat(WgcfBin); os.IsNotExist(err) {
		log("Downloading wgcf...")
		if err := downloadWgcf(); err != nil {
			return fmt.Errorf("download wgcf: %w", err)
		}
	}

	// Register WARP account
	if _, err := os.Stat(AccountFile); os.IsNotExist(err) {
		log("Registering WARP account...")
		cmd := exec.Command(WgcfBin, "register", "--accept-tos")
		cmd.Dir = WarpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wgcf register: %w\n%s", err, string(out))
		}
	}

	// Generate WireGuard profile
	if _, err := os.Stat(ProfileFile); os.IsNotExist(err) {
		log("Generating WireGuard profile...")
		cmd := exec.Command(WgcfBin, "generate")
		cmd.Dir = WarpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wgcf generate: %w\n%s", err, string(out))
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

	return createService()
}

// Enable starts the WARP WireGuard interface.
func Enable() error {
	if err := run("systemctl", "enable", ServiceName+".service"); err != nil {
		return err
	}
	return run("systemctl", "start", ServiceName+".service")
}

// Disable stops the WARP WireGuard interface.
func Disable() error {
	_ = runQuiet("systemctl", "stop", ServiceName+".service")
	_ = runQuiet("systemctl", "disable", ServiceName+".service")
	return nil
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

// RefreshRouting regenerates the wg0.conf with current user UIDs and restarts if running.
func RefreshRouting(cfg *config.Config) error {
	if !IsSetUp() {
		return nil
	}
	if err := generateWgConf(cfg); err != nil {
		return err
	}
	if IsRunning() {
		// Bring interface down and back up with new config
		_ = runQuiet("systemctl", "restart", ServiceName+".service")
	}
	return nil
}

// Uninstall removes all WARP configuration, services, and the wgcf binary.
func Uninstall() {
	_ = Disable()
	_ = removeService()
	_ = os.RemoveAll(WarpDir)
	_ = os.Remove(WgcfBin)
}

// RemoveUsers removes the dedicated SOCKS and NaiveProxy system users
// created for WARP routing.
func RemoveUsers() {
	_ = tryRun("userdel", SocksUser)
	_ = tryRun("userdel", NaiveUser)
}

// generateWgConf parses the wgcf profile and writes a custom wg0.conf
// with policy-routing rules for managed SSH users.
func generateWgConf(cfg *config.Config) error {
	profile, err := parseWgProfile(ProfileFile)
	if err != nil {
		return err
	}

	uids := collectUserUIDs(cfg)

	// wg-quick with Table=200 and AllowedIPs=0.0.0.0/0 already adds the
	// default route to table 200.  PostUp/PostDown only need ip-rule entries
	// to steer specific UIDs into that table.
	var postUp, postDown []string
	for _, uid := range uids {
		postUp = append(postUp, fmt.Sprintf("ip rule add uidrange %d-%d table %d", uid, uid, RouteTable))
		postDown = append(postDown, fmt.Sprintf("ip rule del uidrange %d-%d table %d", uid, uid, RouteTable))
	}

	var conf strings.Builder
	conf.WriteString("[Interface]\n")
	conf.WriteString(fmt.Sprintf("PrivateKey = %s\n", profile.privateKey))
	for _, addr := range profile.addresses {
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
	conf.WriteString(fmt.Sprintf("PublicKey = %s\n", profile.publicKey))
	conf.WriteString(fmt.Sprintf("Endpoint = %s\n", profile.endpoint))
	conf.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
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

	// Dedicated NaiveProxy user
	if uid := lookupUID(NaiveUser); uid > 0 {
		uids = append(uids, uid)
	}

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

func ensureWireGuardTools() error {
	if _, err := exec.LookPath("wg-quick"); err == nil {
		return nil
	}

	// Try apt (Debian/Ubuntu) with noninteractive frontend
	cmd := exec.Command("apt-get", "install", "-y", "wireguard-tools")
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

func downloadWgcf() error {
	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/ViRb3/wgcf/releases/download/v%s/wgcf_%s_linux_%s",
		wgcfVersion, wgcfVersion, arch,
	)

	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	tmp := WgcfBin + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()

	if err := os.Rename(tmp, WgcfBin); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
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
