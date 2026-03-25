package router

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/dnsrouter"
	"github.com/anonvector/slipgate/internal/service"
)

// SwitchMode transitions between single and multi mode.
func SwitchMode(cfg *config.Config, newMode string) error {
	oldMode := cfg.Route.Mode

	switch {
	case oldMode == "single" && newMode == "multi":
		return switchToMulti(cfg)
	case oldMode == "multi" && newMode == "single":
		return switchToSingle(cfg)
	default:
		return fmt.Errorf("already in %s mode", newMode)
	}
}

func switchToMulti(cfg *config.Config) error {
	// Restart all DNS tunnel services — they'll bind to internal ports (5310+)
	// since config mode is now "multi"
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() && t.Enabled {
			svcName := service.TunnelServiceName(t.Tag)
			if err := service.Restart(svcName); err != nil {
				return fmt.Errorf("start tunnel %s: %w", t.Tag, err)
			}
		}
	}

	// Start DNS router to forward :53 → internal ports
	return ensureRouterRunning()
}

func switchToSingle(cfg *config.Config) error {
	// Stop DNS router — transport will bind directly to :53
	_ = dnsrouter.StopRouterService()

	// Stop all DNS tunnel services except the active one
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() && t.Enabled && t.Tag != cfg.Route.Active {
			svcName := service.TunnelServiceName(t.Tag)
			_ = service.Stop(svcName)
		}
	}

	// Restart the active tunnel — it'll bind directly to :53
	// since config mode is now "single"
	if cfg.Route.Active != "" {
		svcName := service.TunnelServiceName(cfg.Route.Active)
		if err := service.Restart(svcName); err != nil {
			return fmt.Errorf("restart active tunnel: %w", err)
		}
	}

	return nil
}
