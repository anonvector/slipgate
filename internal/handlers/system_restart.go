package handlers

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/service"
)

func handleSystemRestart(ctx *actions.Context) error {
	out := ctx.Output
	cfg := ctx.Config.(*config.Config)

	out.Info("Restarting all services...")

	// Ensure port 53 is available
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() {
			if err := network.DisableResolvedStub(); err != nil {
				out.Warning("Failed to disable systemd-resolved stub: " + err.Error())
			}
			break
		}
	}

	// 1. Restart SOCKS5 backend first (tunnels forward to it)
	if service.Exists("slipgate-socks5") {
		if err := service.Restart("slipgate-socks5"); err != nil {
			out.Warning(fmt.Sprintf("Failed to restart slipgate-socks5: %v", err))
		} else {
			out.Success("  slipgate-socks5 restarted")
		}
	}

	// 2. Restart tunnel services (connect clients to backends)
	for _, t := range cfg.Tunnels {
		if t.IsDirectTransport() {
			continue
		}
		svcName := service.TunnelServiceName(t.Tag)
		if service.Exists(svcName) {
			if err := service.Restart(svcName); err != nil {
				out.Warning(fmt.Sprintf("Failed to restart %s: %v", svcName, err))
			} else {
				out.Success(fmt.Sprintf("  %s restarted", svcName))
			}
		}
	}

	// 3. Restart DNS router last (routes to tunnels, needs them up)
	if service.Exists("slipgate-dnsrouter") {
		if err := service.Restart("slipgate-dnsrouter"); err != nil {
			out.Warning(fmt.Sprintf("Failed to restart slipgate-dnsrouter: %v", err))
		} else {
			out.Success("  slipgate-dnsrouter restarted")
		}
	}

	out.Print("")
	out.Success("All services restarted")
	return nil
}
