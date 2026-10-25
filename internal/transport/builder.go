package transport

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

// CreateService creates and starts a systemd service for a tunnel.
func CreateService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	switch tunnel.Transport {
	case config.TransportDNSTT:
		return createDNSTTService(tunnel, cfg)
	case config.TransportSlipstream:
		return createSlipstreamService(tunnel, cfg)
	case config.TransportVayDNS:
		return createVayDNSService(tunnel, cfg)
	case config.TransportSoar:
		return createSoarService(tunnel, cfg)
	case config.TransportNaive:
		return createNaiveService(tunnel, cfg)
	case config.TransportStunTLS:
		return createStunTLSService(tunnel, cfg)
	case config.TransportSSH, config.TransportSOCKS:
		// Direct transports use existing system services (sshd, microsocks)
		return nil
	case config.TransportExternal:
		// External tunnels use a user-managed service; nothing to create
		return nil
	default:
		return fmt.Errorf("unknown transport: %s", tunnel.Transport)
	}
}

func createDNSTTService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	execStart, err := buildDNSTTExecStart(tunnel, cfg)
	if err != nil {
		return err
	}

	unit := &service.Unit{
		Name:        service.TunnelServiceName(tunnel.Tag),
		Description: fmt.Sprintf("SlipGate tunnel: %s (%s/%s)", tunnel.Tag, tunnel.Transport, tunnel.Backend),
		ExecStart:   execStart,
		User:        "root",
		Group:       config.SystemGroup,
		After:       "network.target",
		Restart:     "always",
	}

	if err := service.Create(unit); err != nil {
		return err
	}
	return service.Start(unit.Name)
}

func createSlipstreamService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	execStart, err := buildSlipstreamExecStart(tunnel, cfg)
	if err != nil {
		return err
	}

	unit := &service.Unit{
		Name:        service.TunnelServiceName(tunnel.Tag),
		Description: fmt.Sprintf("SlipGate tunnel: %s (%s/%s)", tunnel.Tag, tunnel.Transport, tunnel.Backend),
		ExecStart:   execStart,
		User:        "root",
		Group:       config.SystemGroup,
		After:       "network.target",
		Restart:     "always",
	}

	if err := service.Create(unit); err != nil {
		return err
	}
	return service.Start(unit.Name)
}

// RemoveService stops and removes a tunnel's systemd service.
func RemoveService(tag string) error {
	name := service.TunnelServiceName(tag)
	_ = service.Stop(name)
	return service.Remove(name)
}
