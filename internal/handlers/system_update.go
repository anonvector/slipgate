package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/transport"
	"github.com/anonvector/slipgate/internal/version"
	"github.com/anonvector/slipgate/internal/warp"
)

func handleSystemUpdate(ctx *actions.Context) error {
	out := ctx.Output
	out.Info("Current version: " + version.String())

	base := binary.DownloadBase()
	downloadURL := fmt.Sprintf("%s/slipgate-%s-%s", base, runtime.GOOS, runtime.GOARCH)
	out.Info("Downloading from: " + downloadURL)

	tmpPath, err := binary.Download(downloadURL)
	if err != nil {
		return actions.NewError(actions.SystemUpdate, "failed to download update", err)
	}
	defer os.Remove(tmpPath)

	execPath, err := os.Executable()
	if err != nil {
		return actions.NewError(actions.SystemUpdate, "failed to find current binary", err)
	}

	if runtime.GOOS == "linux" {
		if err := os.Rename(tmpPath, execPath); err != nil {
			// Rename fails across filesystems (EXDEV). Remove the running
			// binary first to avoid ETXTBSY, then copy the new one in.
			os.Remove(execPath)
			cpCmd := exec.Command("cp", tmpPath, execPath)
			if err := cpCmd.Run(); err != nil {
				return actions.NewError(actions.SystemUpdate, "failed to replace binary", err)
			}
		}
		os.Chmod(execPath, 0755)
	}

	out.Success("slipgate updated")

	// Hand off to the newly installed binary for transport updates and
	// service regeneration so the new code's URLs and logic are used.
	out.Print("")
	postCmd := exec.Command(execPath, "post-update")
	postCmd.Stdout = os.Stdout
	postCmd.Stderr = os.Stderr
	postCmd.Stdin = os.Stdin
	if err := postCmd.Run(); err != nil {
		out.Warning(fmt.Sprintf("Post-update handoff failed: %v", err))
		out.Info("Falling back to current process...")
		return runPostUpdate(ctx)
	}
	return nil
}

// HandlePostUpdate runs the post-update steps (transport binary updates,
// service regeneration). Exported for use by the hidden post-update command.
func HandlePostUpdate(ctx *actions.Context) error {
	return runPostUpdate(ctx)
}

func runPostUpdate(ctx *actions.Context) error {
	out := ctx.Output

	// Update transport binaries
	out.Info("Updating transport binaries...")

	transportBins := []string{"dnstt-server", "slipstream-server", "vaydns-server", "caddy-naive"}
	for _, name := range transportBins {
		binPath := filepath.Join(config.DefaultBinDir, name)
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			continue // not installed, skip
		}

		out.Info(fmt.Sprintf("  Updating %s...", name))

		// Backup old binary before replacing so we can restore on failure
		backupPath := binPath + ".bak"
		if err := os.Rename(binPath, backupPath); err != nil {
			out.Warning(fmt.Sprintf("  Failed to backup %s: %v", name, err))
			continue
		}
		if err := binary.EnsureInstalled(name); err != nil {
			// Restore from backup
			if restoreErr := os.Rename(backupPath, binPath); restoreErr != nil {
				out.Warning(fmt.Sprintf("  Failed to restore %s backup: %v", name, restoreErr))
			}
			out.Warning(fmt.Sprintf("  Failed to update %s: %v (kept old version)", name, err))
			continue
		}
		os.Remove(backupPath)
		out.Success(fmt.Sprintf("  %s updated", name))
	}

	// Migrate from microsocks to built-in SOCKS5 proxy
	microsocksPath := filepath.Join(config.DefaultBinDir, "microsocks")
	if _, err := os.Stat(microsocksPath); err == nil {
		out.Print("")
		out.Info("Migrating from microsocks to built-in SOCKS5 proxy...")
		cfg := ctx.Config.(*config.Config)

		// Determine listen mode from existing config
		directSOCKS := false
		for _, t := range cfg.Tunnels {
			if t.Transport == config.TransportSOCKS {
				directSOCKS = true
			}
		}

		if cfg.Warp.Enabled {
			proxy.RunAsUser = warp.SocksUser
		}
		var setupErr error
		if directSOCKS {
			setupErr = proxy.SetupSOCKSExternalWithUsers(cfg.Users)
		} else if len(cfg.Users) > 0 {
			setupErr = proxy.SetupSOCKSWithUsers(cfg.Users)
		} else {
			setupErr = proxy.SetupSOCKS()
		}
		if setupErr != nil {
			out.Warning("Failed to migrate SOCKS5 proxy: " + setupErr.Error())
		} else {
			os.Remove(microsocksPath)
			out.Success("Migrated to built-in SOCKS5 proxy")
		}
	}

	// Re-apply cap_net_bind_service to caddy-naive if WARP is enabled,
	// since the capability is lost when the binary is replaced.
	{
		cfg := ctx.Config.(*config.Config)
		if cfg.Warp.Enabled {
			naivePath := filepath.Join(config.DefaultBinDir, "caddy-naive")
			if _, err := os.Stat(naivePath); err == nil {
				if err := exec.Command("setcap", "cap_net_bind_service=+ep", naivePath).Run(); err != nil {
					out.Warning("Failed to re-set caddy-naive capability: " + err.Error())
				}
			}
		}
	}

	// Regenerate and restart all tunnel services
	// This ensures systemd unit files match the current binary interface.
	out.Print("")
	out.Info("Regenerating services...")
	cfg := ctx.Config.(*config.Config)

	// Ensure port 53 is available (OS updates can re-enable systemd-resolved stub)
	// and open 53/tcp, which the DNS router serves since TCP forwarding was added.
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() {
			if err := network.DisableResolvedStub(); err != nil {
				out.Warning("Failed to disable systemd-resolved stub: " + err.Error())
			}
			if err := network.AllowPort(53, "tcp"); err != nil {
				out.Warning("Failed to open port 53/tcp: " + err.Error())
			}
			break
		}
	}

	// Bring the SSH tunnel users' sshd settings up to date (e.g. password
	// logins on images that turn them off globally)
	if len(cfg.Users) > 0 {
		if err := system.EnsureSSHConfig(); err != nil {
			out.Warning("Failed to update SSH settings: " + err.Error())
		}
	}

	// Regenerate and restart tunnel services first
	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		if t.IsDirectTransport() {
			continue
		}
		svcName := service.TunnelServiceName(t.Tag)
		wasActive := false
		if status, _ := service.Status(svcName); status == "active" {
			wasActive = true
			_ = service.Stop(svcName)
		}
		if err := transport.CreateService(t, cfg); err != nil {
			out.Warning(fmt.Sprintf("Failed to regenerate %s: %v", svcName, err))
			continue
		}
		if wasActive {
			out.Success(fmt.Sprintf("  %s regenerated and restarted", svcName))
		} else {
			out.Success(fmt.Sprintf("  %s regenerated", svcName))
		}
	}

	// Recreate SOCKS5 proxy service to pick up new ExecStart format (e.g. --creds)
	if service.Exists("slipgate-socks5") {
		directSOCKS := false
		for _, t := range cfg.Tunnels {
			if t.Transport == config.TransportSOCKS {
				directSOCKS = true
			}
		}
		if cfg.Warp.Enabled {
			proxy.RunAsUser = warp.SocksUser
		}
		var setupErr error
		if directSOCKS {
			setupErr = proxy.SetupSOCKSExternalWithUsers(cfg.Users)
		} else if len(cfg.Users) > 0 {
			setupErr = proxy.SetupSOCKSWithUsers(cfg.Users)
		} else {
			setupErr = proxy.SetupSOCKS()
		}
		if setupErr != nil {
			out.Warning("Failed to regenerate SOCKS5 proxy: " + setupErr.Error())
		} else {
			out.Success("  slipgate-socks5 regenerated and restarted")
		}
	}

	// Restart DNS router last so tunnels are ready
	if service.Exists("slipgate-dnsrouter") {
		if err := service.Restart("slipgate-dnsrouter"); err != nil {
			out.Warning(fmt.Sprintf("Failed to restart slipgate-dnsrouter: %v", err))
		} else {
			out.Success("  slipgate-dnsrouter restarted")
		}
	}

	out.Print("")
	out.Success("Update complete!")
	return nil
}
