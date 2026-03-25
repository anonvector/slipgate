package transport

import (
	"fmt"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/config"
)

// buildSlipstreamExecStart builds the ExecStart for slipstream-server.
func buildSlipstreamExecStart(tunnel *config.TunnelConfig, cfg *config.Config) (string, error) {
	if tunnel.Slipstream == nil {
		return "", fmt.Errorf("slipstream config is nil")
	}

	backend := cfg.GetBackend(tunnel.Backend)
	if backend == nil {
		return "", fmt.Errorf("backend %q not found", tunnel.Backend)
	}

	binPath := filepath.Join(config.DefaultBinDir, "slipstream-server")

	// Single mode: bind directly to port 53 (no DNS router).
	// Multi mode: bind to internal port, DNS router forwards from 53.
	port := tunnel.Port
	listenHost := "127.0.0.1"
	if cfg.Route.Mode != "multi" {
		port = 53
		listenHost = "0.0.0.0"
	}

	return fmt.Sprintf("%s --dns-listen-host %s --dns-listen-port %d --cert %s --key %s --domain %s --target-address %s",
		binPath,
		listenHost,
		port,
		tunnel.Slipstream.Cert,
		tunnel.Slipstream.Key,
		tunnel.Domain,
		backend.Address,
	), nil
}
