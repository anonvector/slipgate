package handlers

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/backup"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/dnsrouter"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/transport"
	"github.com/anonvector/slipgate/internal/version"
	"github.com/anonvector/slipgate/internal/warp"
)

func handleSystemBackup(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output
	dest := ctx.GetArg("file")

	if _, err := os.Stat(config.DefaultConfigFile); err != nil {
		return actions.NewError(actions.SystemBackup, "no slipgate configuration on this server", err)
	}
	text, skipped, err := encodeBackup(cfg)
	if err != nil {
		return actions.NewError(actions.SystemBackup, "failed to create backup", err)
	}
	for _, path := range skipped {
		out.Warning(fmt.Sprintf("Skipped %s (too large to be a key or certificate)", path))
	}

	// "-" writes nothing but the backup to stdout, for piping:
	//   ssh old-server slipgate backup - | ssh new-server slipgate restore -
	if dest == "-" {
		fmt.Print(text)
		return nil
	}

	if dest == "" {
		how, err := prompt.Select("Save the backup as", []actions.SelectOption{
			{Value: "file", Label: "A file on this server"},
			{Value: "text", Label: "Text to copy & paste"},
		})
		if err != nil {
			return err
		}
		if how == "file" {
			if dest, err = prompt.String("File", defaultBackupPath("slipgate-backup")); err != nil {
				return err
			}
		}
	}

	summary := fmt.Sprintf("%d tunnel(s) and %d user(s)", len(cfg.Tunnels), len(cfg.Users))
	if dest == "" {
		out.Print("")
		out.Print(strings.TrimSuffix(text, "\n"))
		out.Print("")
		out.Success("Backup of " + summary + " printed above")
		out.Info("Copy everything from the BEGIN line to the END line, then run 'slipgate restore' on the new server and paste it")
	} else {
		if err := writePrivateFile(dest, text); err != nil {
			return actions.NewError(actions.SystemBackup, "failed to write backup", err)
		}
		out.Success(fmt.Sprintf("Backup of %s saved to %s", summary, dest))
		out.Info(fmt.Sprintf("Copy it to the new server and run: slipgate restore %s", dest))
	}
	out.Warning("The backup contains every private key and user password. Anyone who has it can run your tunnels and log in as your users, so keep it private.")
	return nil
}

func handleSystemRestore(ctx *actions.Context) error {
	out := ctx.Output
	if runtime.GOOS != "linux" {
		return actions.NewError(actions.SystemRestore, "slipgate only supports Linux servers", nil)
	}

	text, err := readBackupText(ctx.GetArg("file"), out)
	if err != nil {
		return actions.NewError(actions.SystemRestore, "failed to read backup", err)
	}
	b, err := backup.Decode(text)
	if err != nil {
		return actions.NewError(actions.SystemRestore, err.Error(), nil)
	}
	incoming := b.Config
	for _, reason := range b.DroppedUsers {
		out.Warning("Skipping a user: " + reason)
	}

	out.Print("")
	out.Print(fmt.Sprintf("  Backup from %s (slipgate %s)", b.Created.Local().Format("2006-01-02 15:04"), b.Version))
	for _, t := range incoming.Tunnels {
		out.Print(fmt.Sprintf("    %-20s %-14s %s", t.Tag, t.Transport, t.Domain))
	}
	warpState := "off"
	if incoming.Warp.Enabled {
		warpState = "on"
	}
	out.Print(fmt.Sprintf("    %d user(s), WARP %s", len(incoming.Users), warpState))
	out.Print("")

	current := ctx.Config.(*config.Config)
	_, statErr := os.Stat(config.DefaultConfigFile)
	replacing := statErr == nil && (len(current.Tunnels) > 0 || len(current.Users) > 0)
	if replacing {
		out.Warning(fmt.Sprintf("This server already has %d tunnel(s) and %d user(s). The backup replaces them (they are saved to a file first).",
			len(current.Tunnels), len(current.Users)))
	}
	if ctx.GetArg("yes") == "" {
		ok, err := prompt.Confirm("Restore this backup on this server?")
		if err != nil {
			return actions.NewError(actions.SystemRestore, "can't ask for confirmation (no terminal); run again with --yes", err)
		}
		if !ok {
			out.Info("Cancelled")
			return nil
		}
	}

	// Download first: if that fails, nothing on the server has changed.
	for _, bin := range neededBinaries(incoming) {
		out.Info(fmt.Sprintf("Installing %s...", bin))
		if err := binary.EnsureInstalled(bin); err != nil {
			return actions.NewError(actions.SystemRestore, fmt.Sprintf("failed to install %s; nothing was changed", bin), err)
		}
	}

	if replacing {
		path := defaultBackupPath("slipgate-pre-restore")
		text, _, err := encodeBackup(current)
		if err == nil {
			err = writePrivateFile(path, text)
		}
		if err != nil {
			return actions.NewError(actions.SystemRestore, "failed to save the current setup; nothing was changed", err)
		}
		out.Info("Current setup saved to " + path)
		clearSetup(current, incoming, out)
	} else if statErr == nil {
		// Nothing to replace, but the file may be one that failed to load.
		_ = copyFile(config.DefaultConfigFile, config.DefaultConfigFile+".pre-restore")
	}

	if err := system.EnsureUser(); err != nil {
		return actions.NewError(actions.SystemRestore, "failed to create system user", err)
	}
	for _, dir := range []string{config.DefaultConfigDir, config.DefaultTunnelDir} {
		if err := system.EnsureDir(dir, config.SystemUser); err != nil {
			return actions.NewError(actions.SystemRestore, fmt.Sprintf("failed to create %s", dir), err)
		}
	}

	cfg, err := b.Restore(config.DefaultTunnelDir)
	if err != nil {
		return actions.NewError(actions.SystemRestore, "failed to write tunnel keys", err)
	}
	restoreUsers(cfg, out)
	if err := cfg.SaveTo(config.DefaultConfigFile); err != nil {
		return actions.NewError(actions.SystemRestore, "failed to save config", err)
	}
	out.Success("Config, keys and users restored")

	openTunnelPorts(cfg, out)

	if current.Warp.Enabled && !cfg.Warp.Enabled {
		_ = warp.Disable()
	}
	if cfg.Warp.Enabled {
		out.Info("Setting up Cloudflare WARP...")
		err := warp.Setup(cfg, func(msg string) { out.Info(msg) })
		if err == nil {
			err = warp.Enable()
		}
		if err != nil {
			out.Warning("WARP setup failed, continuing without it: " + err.Error())
			cfg.Warp.Enabled = false
			if err := cfg.SaveTo(config.DefaultConfigFile); err != nil {
				out.Warning("Failed to save config: " + err.Error())
			}
		}
	}
	proxy.RunAsUser = ""
	if cfg.Warp.Enabled {
		proxy.RunAsUser = warp.SocksUser
	}

	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		if t.HasManagedService() && t.Port > 0 {
			network.FreePort(t.Port, "udp")
		}
		if err := transport.CreateService(t, cfg); err != nil {
			out.Warning(fmt.Sprintf("Failed to start %s: %v", t.Tag, err))
			continue
		}
		if service.Exists(service.TunnelServiceName(t.Tag)) {
			out.Success(fmt.Sprintf("  %s started", t.Tag))
		}
	}

	// Also when the backup needs none: an existing proxy must drop the old users.
	if needsSOCKS(cfg) || service.Exists("slipgate-socks5") {
		network.FreePort(1080, "tcp")
		if err := setupSOCKS(cfg); err != nil {
			out.Warning("Failed to set up SOCKS5 proxy: " + err.Error())
		}
	}

	hasDNS := false
	for _, t := range cfg.Tunnels {
		hasDNS = hasDNS || t.IsDNSTunnel()
	}
	if hasDNS {
		network.FreePort(53, "udp")
		if err := dnsrouter.CreateRouterService(); err != nil {
			out.Warning("Failed to create DNS router service: " + err.Error())
		} else if err := dnsrouter.RestartRouterService(); err != nil {
			out.Warning("Failed to start DNS router: " + err.Error())
		} else {
			out.Success("DNS router started on port 53")
		}
	} else if service.Exists("slipgate-dnsrouter") {
		_ = dnsrouter.RestartRouterService()
	}

	out.Print("")
	out.Success(fmt.Sprintf("Restore complete: %d tunnel(s), %d user(s)", len(cfg.Tunnels), len(cfg.Users)))
	if records := dnsRecordsToMove(cfg); len(records) > 0 {
		out.Info("Point these DNS records at this server's IP; clients then work unchanged (same keys and passwords):")
		for _, r := range records {
			out.Print("      A  record: " + r)
		}
	}
	return nil
}

// encodeBackup returns cfg and its tunnels' files as backup text, and the
// files left out because they were too large.
func encodeBackup(cfg *config.Config) (string, []string, error) {
	b, err := backup.Create(cfg, config.DefaultTunnelDir, version.String())
	if err != nil {
		return "", nil, err
	}
	text, err := b.Encode()
	return text, b.Skipped, err
}

// readBackupText reads a backup from a file, from stdin ("-"), or, with no
// argument, asks for a file or a paste.
func readBackupText(arg string, out actions.OutputWriter) (string, error) {
	if arg == "-" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20))
		return string(data), err
	}
	if arg == "" {
		how, err := prompt.Select("Restore from", []actions.SelectOption{
			{Value: "file", Label: "A file on this server"},
			{Value: "text", Label: "Pasted text"},
		})
		if err != nil {
			return "", err
		}
		if how == "text" {
			out.Info("Paste the backup, from the BEGIN line to the END line:")
			return prompt.Lines(backup.EndMarker)
		}
		if arg, err = prompt.String("Backup file", ""); err != nil {
			return "", err
		}
		if arg == "" {
			return "", fmt.Errorf("no file given")
		}
	}
	data, err := os.ReadFile(arg)
	return string(data), err
}

// clearSetup stops and removes the current tunnels and removes the users the
// backup doesn't have, so nothing from the old setup keeps running or keeps
// access. Both are in the pre-restore backup.
func clearSetup(current, incoming *config.Config, out actions.OutputWriter) {
	for _, t := range current.Tunnels {
		if err := transport.RemoveService(t.Tag); err != nil {
			out.Warning(fmt.Sprintf("Failed to remove service for %s: %v", t.Tag, err))
		}
		if err := os.RemoveAll(config.TunnelDir(t.Tag)); err != nil {
			out.Warning(fmt.Sprintf("Failed to remove %s: %v", config.TunnelDir(t.Tag), err))
		}
	}
	for _, u := range current.Users {
		if incoming.GetUser(u.Username) != nil {
			continue
		}
		if err := system.RemoveSSHUser(u.Username); err != nil {
			out.Warning(fmt.Sprintf("Failed to remove user %q: %v", u.Username, err))
		} else {
			out.Info(fmt.Sprintf("Removed user %q (not in the backup)", u.Username))
		}
	}
}

// restoreUsers creates cfg's users as SSH accounts. A name taken by an
// account slipgate didn't create (e.g. "ubuntu") is skipped and dropped from
// cfg: a restore must never change another account's password.
func restoreUsers(cfg *config.Config, out actions.OutputWriter) {
	kept := cfg.Users[:0]
	for _, u := range cfg.Users {
		if system.UserExists(u.Username) && !system.IsSSHUser(u.Username) {
			out.Warning(fmt.Sprintf("Skipped user %q: an account with that name already exists on this server", u.Username))
			continue
		}
		if err := system.AddSSHUser(u.Username, u.Password); err != nil {
			out.Warning(fmt.Sprintf("Failed to set up user %q: %v", u.Username, err))
		}
		kept = append(kept, u)
	}
	cfg.Users = kept
}

// openTunnelPorts opens the firewall ports cfg's tunnels listen on.
func openTunnelPorts(cfg *config.Config, out actions.OutputWriter) {
	type port struct {
		num   int
		proto string
	}
	var ports []port
	dns := false
	for _, t := range cfg.Tunnels {
		switch {
		case t.IsDNSTunnel():
			dns = true
			ports = append(ports, port{53, "udp"}, port{53, "tcp"})
		case t.Transport == config.TransportNaive:
			https := 443
			if t.Naive.Port > 0 {
				https = t.Naive.Port
			}
			ports = append(ports, port{80, "tcp"}, port{https, "tcp"})
		case t.Transport == config.TransportStunTLS && t.StunTLS.Port > 0:
			ports = append(ports, port{t.StunTLS.Port, "tcp"})
		case t.Transport == config.TransportSSH:
			ports = append(ports, port{sshPort(cfg), "tcp"})
		case t.Transport == config.TransportSOCKS:
			ports = append(ports, port{1080, "tcp"})
		}
	}

	opened := make(map[port]bool)
	for _, p := range ports {
		if opened[p] {
			continue
		}
		opened[p] = true
		if err := network.AllowPort(p.num, p.proto); err != nil {
			out.Warning(fmt.Sprintf("Failed to open port %d/%s: %v", p.num, p.proto, err))
		}
	}
	if dns {
		if err := network.DisableResolvedStub(); err != nil {
			out.Warning("Failed to disable systemd-resolved stub: " + err.Error())
		}
	}
	if len(ports) > 0 && !network.HostFirewallActive() {
		out.Info("No host firewall detected. If your VPS has an external firewall (cloud security groups, provider firewall), open the required ports there.")
	}
}

// sshPort returns the port of the SSH backend, 22 if unset.
func sshPort(cfg *config.Config) int {
	if b := cfg.GetBackend(config.BackendSSH); b != nil {
		if _, p, err := net.SplitHostPort(b.Address); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				return n
			}
		}
	}
	return 22
}

// neededBinaries lists the transport binaries cfg's tunnels run.
func neededBinaries(cfg *config.Config) []string {
	seen := make(map[string]bool)
	var bins []string
	for _, t := range cfg.Tunnels {
		if bin, ok := config.TransportBinaries[t.Transport]; ok && !seen[bin] {
			seen[bin] = true
			bins = append(bins, bin)
		}
	}
	sort.Strings(bins)
	return bins
}

// needsSOCKS reports whether any tunnel relays to the SOCKS5 proxy or
// exposes it directly. NaiveProxy is its own forward proxy.
func needsSOCKS(cfg *config.Config) bool {
	for _, t := range cfg.Tunnels {
		if t.Transport == config.TransportSOCKS || (t.Backend == config.BackendSOCKS && t.Transport != config.TransportNaive) {
			return true
		}
	}
	return false
}

// setupSOCKS (re)creates the SOCKS5 proxy with cfg's users, on all
// interfaces when a direct-socks5 tunnel exposes it.
func setupSOCKS(cfg *config.Config) error {
	for _, t := range cfg.Tunnels {
		if t.Transport == config.TransportSOCKS {
			return proxy.SetupSOCKSExternalWithUsers(cfg.Users)
		}
	}
	if len(cfg.Users) > 0 {
		return proxy.SetupSOCKSWithUsers(cfg.Users)
	}
	return proxy.SetupSOCKS()
}

// dnsRecordsToMove lists the A records that must point at the server for
// cfg's tunnels: ns.<parent> for DNS tunnels, the domain itself for
// NaiveProxy.
func dnsRecordsToMove(cfg *config.Config) []string {
	seen := make(map[string]bool)
	var records []string
	for _, t := range cfg.Tunnels {
		var r string
		switch {
		case t.Domain == "":
			continue
		case t.Transport == config.TransportNaive:
			r = t.Domain
		case t.IsDNSTunnel():
			r = "ns." + baseDomain(t.Domain)
		default:
			continue
		}
		if !seen[r] {
			seen[r] = true
			records = append(records, r)
		}
	}
	return records
}

// defaultBackupPath returns a timestamped file name in the home directory.
func defaultBackupPath(prefix string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}
	return filepath.Join(home, fmt.Sprintf("%s-%s.txt", prefix, time.Now().Format("20060102-150405")))
}

// writePrivateFile writes text to path readable only by its owner.
func writePrivateFile(path, text string) error {
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600) // WriteFile keeps the mode of an existing file
}
