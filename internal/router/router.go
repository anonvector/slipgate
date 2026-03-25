package router

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/dnsrouter"
	"github.com/anonvector/slipgate/internal/service"
)

// AddTunnel registers a tunnel with the routing layer.
// In multi mode, the DNS router must be running to forward port 53 traffic.
// In single mode, the transport binds directly to port 53 — no router needed.
func AddTunnel(cfg *config.Config, tunnel *config.TunnelConfig) error {
	if !tunnel.IsDNSTunnel() {
		return nil // NaiveProxy doesn't need DNS routing
	}

	// Single mode: no DNS router needed
	if cfg.Route.Mode != "multi" {
		return nil
	}

	status, _ := service.Status("slipgate-dnsrouter")
	if status == "active" {
		return dnsrouter.RestartRouterService()
	}
	return ensureRouterRunning()
}

// RemoveTunnel unregisters a tunnel from routing.
// Restarts the router to drop the removed tunnel's route.
func RemoveTunnel(cfg *config.Config, tag string) error {
	status, _ := service.Status("slipgate-dnsrouter")
	if status == "active" {
		return dnsrouter.RestartRouterService()
	}
	return nil
}

// SwitchActive changes the active tunnel in single mode.
func SwitchActive(cfg *config.Config, tag string) error {
	tunnel := cfg.GetTunnel(tag)
	if tunnel == nil {
		return fmt.Errorf("tunnel %q not found", tag)
	}

	// Stop current active tunnel's DNS forwarding
	if cfg.Route.Active != "" && cfg.Route.Active != tag {
		oldName := service.TunnelServiceName(cfg.Route.Active)
		_ = service.Stop(oldName)
	}

	// Start new active tunnel
	newName := service.TunnelServiceName(tag)
	return service.Start(newName)
}

func ensureRouterRunning() error {
	status, err := service.Status("slipgate-dnsrouter")
	if err != nil || status != "active" {
		if err := dnsrouter.CreateRouterService(); err != nil {
			return err
		}
		return dnsrouter.StartRouterService()
	}
	return nil
}
