package handlers

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/version"
	"github.com/anonvector/slipgate/internal/warp"
)

func handleSystemDiag(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	out.Print("")
	out.Print("  SlipGate Diagnostics")
	out.Print("  " + version.String())
	out.Print("  ────────────────────────────────────────")

	pass := 0
	warn := 0
	fail := 0

	check := func(label string, ok bool, detail string) {
		if ok {
			pass++
			out.Success(fmt.Sprintf("%-40s %s", label, detail))
		} else {
			fail++
			out.Error(fmt.Sprintf("%-40s %s", label, detail))
		}
	}

	info := func(label string, detail string) {
		warn++
		out.Warning(fmt.Sprintf("%-40s %s", label, detail))
	}

	// ── System ──────────────────────────────────────────────
	out.Print("")
	out.Print("  System")
	out.Print("  ──────")

	// System user
	_, err := user.Lookup(config.SystemUser)
	check("System user (slipgate)", err == nil, boolStr(err == nil, "exists", "missing — run install"))

	// Config directory
	_, err = os.Stat(config.DefaultConfigDir)
	check("Config directory", err == nil, config.DefaultConfigDir)

	// Tunnel directory
	_, err = os.Stat(config.DefaultTunnelDir)
	check("Tunnel directory", err == nil, config.DefaultTunnelDir)

	// Config file
	_, cfgErr := config.Load()
	check("Config file", cfgErr == nil, boolStr(cfgErr == nil, "valid", fmt.Sprintf("error: %v", cfgErr)))

	// systemd-resolved stub
	stubDisabled := isResolvedStubDisabled()
	hasDNSTunnels := false
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() {
			hasDNSTunnels = true
			break
		}
	}
	if hasDNSTunnels {
		check("systemd-resolved stub", stubDisabled, boolStr(stubDisabled, "disabled", "still active — port 53 conflict"))
	}

	// ── Tunnels ─────────────────────────────────────────────
	out.Print("")
	out.Print(fmt.Sprintf("  Tunnels (%d configured)", len(cfg.Tunnels)))
	out.Print("  ───────")

	if len(cfg.Tunnels) == 0 {
		info("No tunnels configured", "run install or tunnel add")
	}

	for _, t := range cfg.Tunnels {
		// Direct transports use system services (sshd, microsocks), not slipgate-managed ones
		if t.IsDirectTransport() {
			continue
		}

		tag := t.Tag
		isExternal := t.Transport == config.TransportExternal

		// Service status (external tunnels have no managed service)
		if isExternal {
			out.Info(fmt.Sprintf("%-40s %s", fmt.Sprintf("[%s] service", tag), "external (user-managed)"))
		} else {
			svcName := service.TunnelServiceName(tag)
			svcExists := service.Exists(svcName)
			status := "missing"
			if svcExists {
				status, _ = service.Status(svcName)
			}

			svcOK := status == "active"
			check(fmt.Sprintf("[%s] service", tag), svcOK,
				boolStr(svcOK, "active", status))

			if svcExists && !svcOK {
				showRecentLogs(out, svcName)
			}

			// Service enabled (survives reboot)
			if svcExists {
				enabled := isServiceEnabled(svcName)
				check(fmt.Sprintf("[%s] enabled at boot", tag), enabled,
					boolStr(enabled, "yes", "no — will not start after reboot"))
			}
		}

		// Tunnel directory
		tunnelDir := config.TunnelDir(tag)
		_, err := os.Stat(tunnelDir)
		check(fmt.Sprintf("[%s] tunnel directory", tag), err == nil, tunnelDir)

		// Transport-specific file checks
		switch t.Transport {
		case config.TransportDNSTT:
			if t.DNSTT != nil {
				checkFileExists(check, tag, "private key", t.DNSTT.PrivateKey)
			}
		case config.TransportVayDNS:
			if t.VayDNS != nil {
				checkFileExists(check, tag, "private key", t.VayDNS.PrivateKey)
			}
		case config.TransportSlipstream:
			if t.Slipstream != nil {
				checkFileExists(check, tag, "certificate", t.Slipstream.Cert)
				checkFileExists(check, tag, "key", t.Slipstream.Key)
			}
		}

		// Port check for DNS tunnels
		if t.IsDNSTunnel() && t.Port > 0 {
			portOK := isPortListening(t.Port, "udp")
			if isExternal {
				// External: port not listening is expected if user hasn't started their service
				if portOK {
					check(fmt.Sprintf("[%s] port %d/udp", tag, t.Port), true, "listening")
				} else {
					out.Info(fmt.Sprintf("%-40s %s", fmt.Sprintf("[%s] port %d/udp", tag, t.Port), "not listening (start your service)"))
				}
			} else {
				check(fmt.Sprintf("[%s] port %d/udp", tag, t.Port), portOK,
					boolStr(portOK, "listening", "not listening"))
			}
		}
	}

	// ── Services ────────────────────────────────────────────
	out.Print("")
	out.Print("  Infrastructure Services")
	out.Print("  ───────────────────────")

	// DNS router
	if hasDNSTunnels {
		routerExists := service.Exists("slipgate-dnsrouter")
		if routerExists {
			status, _ := service.Status("slipgate-dnsrouter")
			routerOK := status == "active"
			check("DNS router service", routerOK,
				boolStr(routerOK, "active", status))
			if !routerOK {
				showRecentLogs(out, "slipgate-dnsrouter")
			}

			enabled := isServiceEnabled("slipgate-dnsrouter")
			check("DNS router enabled at boot", enabled,
				boolStr(enabled, "yes", "no — will not start after reboot"))
		} else {
			check("DNS router service", false, "not installed")
		}

		port53OK := isPortListening(53, "udp")
		check("Port 53/udp", port53OK,
			boolStr(port53OK, "listening", "not listening — DNS tunnels unreachable"))
	}

	// SOCKS5 proxy
	socksExists := service.Exists("slipgate-socks5")
	if socksExists {
		status, _ := service.Status("slipgate-socks5")
		socksOK := status == "active"
		check("SOCKS5 proxy service", socksOK,
			boolStr(socksOK, "active", status))
		if !socksOK {
			showRecentLogs(out, "slipgate-socks5")
		}

		port1080OK := isPortListening(1080, "tcp")
		check("Port 1080/tcp", port1080OK,
			boolStr(port1080OK, "listening", "not listening"))
	}

	// WARP
	if cfg.Warp.Enabled {
		out.Print("")
		out.Print("  WARP Routing")
		out.Print("  ────────────")

		warpExists := service.Exists("slipgate-warp")
		if warpExists {
			status, _ := service.Status("slipgate-warp")
			warpOK := status == "active"
			check("WARP service", warpOK,
				boolStr(warpOK, "active", status))
			if !warpOK {
				showRecentLogs(out, "slipgate-warp")
			}
		} else {
			check("WARP service", false, "enabled in config but service missing")
		}

		// WireGuard interface
		wgUp := interfaceExists("wg0")
		check("WireGuard interface (wg0)", wgUp,
			boolStr(wgUp, "up", "missing — WARP tunnel not established"))

		// WireGuard handshake
		if wgUp {
			hsAge, hsOK := wgLatestHandshake()
			if hsOK {
				check("WireGuard handshake", hsAge < 3*time.Minute,
					boolStr(hsAge < 3*time.Minute,
						fmt.Sprintf("%s ago", hsAge.Truncate(time.Second)),
						fmt.Sprintf("%s ago — tunnel may be stale", hsAge.Truncate(time.Second))))
			} else {
				check("WireGuard handshake", false, "never completed — endpoint unreachable?")
			}
		}

		// Routing table 200
		hasRoute := routeTableHasDefault(warp.RouteTable)
		check("Routing table 200", hasRoute,
			boolStr(hasRoute, "default route via wg0", "no default route — traffic bypasses WARP"))

		// Policy routing rules for managed UIDs
		expectedUIDs := collectExpectedWarpUIDs(cfg)
		rules := listIPRules(warp.RouteTable)
		allRulesOK := true
		for label, uid := range expectedUIDs {
			found := uidInRules(uid, rules)
			check(fmt.Sprintf("ip rule for %s (uid %d)", label, uid), found,
				boolStr(found, "present", "MISSING — traffic from this user bypasses WARP"))
			if !found {
				allRulesOK = false
			}
		}
		if len(expectedUIDs) == 0 {
			info("WARP routing rules", "no managed UIDs found — no traffic will route through WARP")
		} else if !allRulesOK {
			out.Info("  Hint: run 'slipgate restart' or re-enable WARP to fix missing rules")
		}

		// SOCKS5 service user
		if service.Exists("slipgate-socks5") {
			actualUser := service.GetUser("slipgate-socks5")
			userOK := actualUser == warp.SocksUser
			check("SOCKS5 service user", userOK,
				boolStr(userOK,
					fmt.Sprintf("%s (correct)", actualUser),
					fmt.Sprintf("%s — should be %s; run 'slipgate restart' to fix", actualUser, warp.SocksUser)))
		}

		// NaiveProxy service users
		for _, t := range cfg.Tunnels {
			if t.Transport == config.TransportNaive {
				svcName := service.TunnelServiceName(t.Tag)
				if service.Exists(svcName) {
					actualUser := service.GetUser(svcName)
					userOK := actualUser == warp.NaiveUser
					check(fmt.Sprintf("[%s] NaiveProxy user", t.Tag), userOK,
						boolStr(userOK,
							fmt.Sprintf("%s (correct)", actualUser),
							fmt.Sprintf("%s — should be %s; re-enable WARP to fix", actualUser, warp.NaiveUser)))
				}
			}
		}

	}

	// ── Orphaned Services ───────────────────────────────────
	allSvc := service.ListSlipgateServices()
	knownSvc := map[string]bool{
		"slipgate-dnsrouter": true,
		"slipgate-socks5":    true,
		"slipgate-warp":      true,
		"slipgate-iptables":  true,
	}
	for _, t := range cfg.Tunnels {
		knownSvc[service.TunnelServiceName(t.Tag)] = true
	}
	var orphaned []string
	for _, svc := range allSvc {
		if !knownSvc[svc] {
			orphaned = append(orphaned, svc)
		}
	}
	if len(orphaned) > 0 {
		out.Print("")
		out.Print("  Orphaned Services")
		out.Print("  ─────────────────")
		for _, svc := range orphaned {
			info(svc, "service exists but not in config")
		}
	}

	// ── Summary ─────────────────────────────────────────────
	out.Print("")
	out.Print("  ────────────────────────────────────────")
	out.Print(fmt.Sprintf("  Results: %d passed, %d warnings, %d failed", pass, warn, fail))
	out.Print("")

	return nil
}

func showRecentLogs(out actions.OutputWriter, svcName string) {
	logs, err := service.Logs(svcName, "10")
	if err != nil || strings.TrimSpace(logs) == "" {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		out.Print(fmt.Sprintf("         %s", line))
	}
}

func checkFileExists(check func(string, bool, string), tag, label, path string) {
	_, err := os.Stat(path)
	check(fmt.Sprintf("[%s] %s", tag, label), err == nil,
		boolStr(err == nil, filepath.Base(path), "missing: "+path))
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func isResolvedStubDisabled() bool {
	data, err := os.ReadFile("/etc/systemd/resolved.conf.d/slipgate-no-stub.conf")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "DNSStubListener=no")
}

func isServiceEnabled(name string) bool {
	out, err := exec.Command("systemctl", "is-enabled", name+".service").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "enabled"
}

func isPortListening(port int, proto string) bool {
	switch proto {
	case "tcp":
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1e9)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	case "udp":
		// For UDP, check if we can bind — if we can, nothing is listening
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			// Can't bind = something is already listening = good
			return true
		}
		conn.Close()
		return false
	}
	return false
}

// ── WARP routing helpers ──────────────────────────────────────

// interfaceExists checks if a network interface exists and is up.
// WireGuard interfaces report state UNKNOWN (no physical link state),
// so we accept both UP and UNKNOWN in the flags/state line.
func interfaceExists(name string) bool {
	out, err := exec.Command("ip", "link", "show", "dev", name).Output()
	if err != nil {
		return false
	}
	// First line looks like: "N: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu ..."
	// or state field: "state UNKNOWN"
	first := strings.SplitN(string(out), "\n", 2)[0]
	return strings.Contains(first, ",UP") || strings.Contains(first, "state UNKNOWN")
}

// wgLatestHandshake returns the age of the most recent WireGuard handshake
// on wg0. Returns (age, true) if a handshake has occurred, or (0, false) if
// no handshake has ever completed.
func wgLatestHandshake() (time.Duration, bool) {
	out, err := exec.Command("wg", "show", "wg0", "latest-handshakes").Output()
	if err != nil {
		return 0, false
	}
	// Output format: "<peer-pubkey>\t<unix-timestamp>\n"
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return 0, false
	}
	ts, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || ts == 0 {
		return 0, false
	}
	return time.Since(time.Unix(ts, 0)), true
}

// routeTableHasDefault checks if a routing table has a default route.
func routeTableHasDefault(table int) bool {
	out, err := exec.Command("ip", "route", "show", "table", strconv.Itoa(table), "default").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// listIPRules returns all ip rules pointing to a given table as raw text lines.
func listIPRules(table int) []string {
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return nil
	}
	tableStr := fmt.Sprintf("lookup %d", table)
	var matches []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, tableStr) {
			matches = append(matches, line)
		}
	}
	return matches
}

// uidInRules checks if any rule line contains a uidrange matching the given uid.
func uidInRules(uid int, rules []string) bool {
	// Rules look like: "32765: from all uidrange 998-998 lookup 200"
	target := fmt.Sprintf("%d-%d", uid, uid)
	for _, r := range rules {
		if strings.Contains(r, target) {
			return true
		}
	}
	return false
}

// collectExpectedWarpUIDs returns a map of label→uid for all users that
// should have WARP routing rules.
func collectExpectedWarpUIDs(cfg *config.Config) map[string]int {
	uids := make(map[string]int)

	for _, u := range cfg.Users {
		if uid := lookupSystemUID(u.Username); uid > 0 {
			uids[u.Username] = uid
		}
	}
	if uid := lookupSystemUID(warp.SocksUser); uid > 0 {
		uids[warp.SocksUser] = uid
	}
	// slipgate-naive (Caddy) is intentionally NOT WARP-routed — see
	// warp.collectUserUIDs for the reason. Don't expect a rule for it.

	return uids
}

// lookupSystemUID returns the numeric UID for a system user, or -1 if not found.
func lookupSystemUID(username string) int {
	u, err := user.Lookup(username)
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}

