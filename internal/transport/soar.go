package transport

import (
	"fmt"
	"os"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

func createSoarService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	execStart, err := buildSoarExecStart(tunnel, cfg)
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

// buildSoarExecStart builds the ExecStart command for the built-in soar server.
func buildSoarExecStart(tunnel *config.TunnelConfig, cfg *config.Config) (string, error) {
	if tunnel.Soar == nil {
		return "", fmt.Errorf("soar config is nil")
	}

	// slipgate binary itself serves soar — no external binary needed
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}

	// Loopback only: queries reach soar through the DNS router on port 53.
	return fmt.Sprintf("%s soar serve --listen 127.0.0.1:%d --zone %s --key-file %s --allow-ports %s",
		execPath, tunnel.Port, tunnel.Domain, tunnel.Soar.PrivateKey, tunnel.Soar.ResolvedAllowPorts()), nil
}
