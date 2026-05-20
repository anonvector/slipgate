package handlers

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/transport"
	"github.com/anonvector/slipgate/internal/warp"
)

func handleWarp(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	if !warp.IsSetUp() {
		ok, err := prompt.Confirm("WARP is not configured. Set it up now?")
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}

		warpIPv6, err := prompt.Confirm("Route IPv6 through WARP? (No = IPv4 only, safer on most VPS)")
		if err != nil {
			return err
		}
		cfg.Warp.IPv6 = warpIPv6

		out.Info(fmt.Sprintf("Setting up Cloudflare WARP (%s)...", map[bool]string{true: "IPv4+IPv6", false: "IPv4 only"}[cfg.Warp.IPv6]))
		if err := warp.Setup(cfg, func(msg string) { out.Info(msg) }); err != nil {
			return actions.NewError(actions.WarpToggle, "WARP setup failed", err)
		}
		out.Success("WARP configured")

		if err := warp.Enable(); err != nil {
			return actions.NewError(actions.WarpToggle, "failed to start WARP", err)
		}
		cfg.Warp.Enabled = true
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}

		recreateProxies(cfg, true, out)
		out.Success("WARP enabled — tunnel user traffic now routes through Cloudflare")
		return nil
	}

	// Already set up — show status and offer toggle
	ipv6Label := "IPv4 only"
	if cfg.Warp.IPv6 {
		ipv6Label = "IPv4+IPv6"
	}
	if warp.IsRunning() {
		out.Info(fmt.Sprintf("WARP is currently ENABLED (active, %s)", ipv6Label))
	} else {
		out.Info(fmt.Sprintf("WARP is currently DISABLED (inactive, %s)", ipv6Label))
	}

	action, err := prompt.Select("Action", []actions.SelectOption{
		{Value: "enable", Label: "Enable WARP"},
		{Value: "disable", Label: "Disable WARP"},
		{Value: "ipv6", Label: fmt.Sprintf("Change IPv6 routing (currently: %s)", ipv6Label)},
		{Value: "cancel", Label: "Cancel"},
	})
	if err != nil {
		return err
	}

	switch action {
	case "enable":
		if err := warp.RefreshRouting(cfg); err != nil {
			out.Warning("Failed to refresh routing: " + err.Error())
		}
		if err := warp.Enable(); err != nil {
			return actions.NewError(actions.WarpToggle, "failed to start WARP", err)
		}
		cfg.Warp.Enabled = true
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}
		recreateProxies(cfg, true, out)
		out.Success("WARP enabled")

	case "disable":
		if err := warp.Disable(); err != nil {
			return actions.NewError(actions.WarpToggle, "failed to stop WARP", err)
		}
		cfg.Warp.Enabled = false
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}
		recreateProxies(cfg, false, out)
		out.Success("WARP disabled")

	case "ipv6":
		warpIPv6, err := prompt.Confirm("Route IPv6 through WARP? (No = IPv4 only, safer on most VPS)")
		if err != nil {
			return err
		}
		cfg.Warp.IPv6 = warpIPv6
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}
		// Regenerate wg0.conf with updated AllowedIPs and restart if running
		if err := warp.RefreshRouting(cfg); err != nil {
			out.Warning("Failed to refresh routing config: " + err.Error())
		}
		if warp.IsRunning() {
			if err := warp.Disable(); err != nil {
				out.Warning("Failed to stop WARP for restart: " + err.Error())
			}
			if err := warp.Enable(); err != nil {
				out.Warning("Failed to restart WARP: " + err.Error())
			} else {
				out.Success(fmt.Sprintf("WARP restarted with %s", map[bool]string{true: "IPv4+IPv6", false: "IPv4 only"}[cfg.Warp.IPv6]))
			}
		} else {
			out.Success(fmt.Sprintf("IPv6 routing set to: %s (takes effect on next WARP enable)", map[bool]string{true: "IPv4+IPv6", false: "IPv4 only"}[cfg.Warp.IPv6]))
		}
	}

	return nil
}

// recreateProxies restarts the SOCKS5 proxy and NaiveProxy services
// under the appropriate user after a WARP toggle.
func recreateProxies(cfg *config.Config, warpEnabled bool, out actions.OutputWriter) {
	// SOCKS proxy
	if warpEnabled {
		proxy.RunAsUser = warp.SocksUser
	} else {
		proxy.RunAsUser = ""
	}
	directSOCKS := false
	for _, t := range cfg.Tunnels {
		if t.Transport == config.TransportSOCKS {
			directSOCKS = true
		}
	}
	var socksErr error
	if directSOCKS {
		if len(cfg.Users) > 0 {
			socksErr = proxy.SetupSOCKSExternalWithUsers(cfg.Users)
		} else {
			socksErr = proxy.SetupSOCKS()
		}
	} else if len(cfg.Users) > 0 {
		socksErr = proxy.SetupSOCKSWithUsers(cfg.Users)
	} else {
		socksErr = proxy.SetupSOCKS()
	}
	if socksErr != nil {
		out.Warning("Failed to update SOCKS proxy: " + socksErr.Error())
	}

	// NaiveProxy tunnels — recreate so Caddy runs under the right user
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Transport == config.TransportNaive {
			out.Info(fmt.Sprintf("Updating NaiveProxy %q...", cfg.Tunnels[i].Tag))
			if err := transport.CreateService(&cfg.Tunnels[i], cfg); err != nil {
				out.Warning(fmt.Sprintf("Failed to update %s: %s", cfg.Tunnels[i].Tag, err.Error()))
			}
		}
	}
}
