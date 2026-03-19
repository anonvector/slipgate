package handlers

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleTunnelEdit(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output
	tag := ctx.GetArg("tag")

	if tag == "" {
		return actions.NewError(actions.TunnelEdit, "tunnel tag is required", nil)
	}

	tunnel := cfg.GetTunnel(tag)
	if tunnel == nil {
		return actions.NewError(actions.TunnelEdit, fmt.Sprintf("tunnel %q not found", tag), nil)
	}

	changed := false

	// MTU (DNSTT tunnels only)
	if tunnel.DNSTT != nil {
		mtuStr := ctx.GetArg("mtu")
		if mtuStr == "" {
			var err error
			mtuStr, err = prompt.String("MTU", fmt.Sprintf("%d", tunnel.DNSTT.MTU))
			if err != nil {
				return err
			}
		}
		var newMTU int
		if n, err := fmt.Sscanf(mtuStr, "%d", &newMTU); n == 1 && err == nil && newMTU != tunnel.DNSTT.MTU {
			tunnel.DNSTT.MTU = newMTU
			changed = true
			out.Success(fmt.Sprintf("MTU set to %d", newMTU))
		}
	} else {
		out.Info("MTU is only configurable for DNSTT tunnels")
	}

	if !changed {
		out.Info("No changes")
		return nil
	}

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelEdit, "failed to save config", err)
	}

	// Recreate and restart the tunnel service to apply new MTU
	svcName := service.TunnelServiceName(tag)
	_ = service.Stop(svcName)
	out.Info("Restarting tunnel service...")
	if err := transport.CreateService(tunnel, cfg); err != nil {
		return actions.NewError(actions.TunnelEdit, "failed to recreate service", err)
	}

	out.Success(fmt.Sprintf("Tunnel %q updated", tag))
	return nil
}
