package transport

import (
	"fmt"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/config"
)

// dnsttService holds the ExecStart and Environment for dnstt-server.
type dnsttService struct {
	execStart   string
	environment []string
}

// buildDNSTTService builds the ExecStart and PT environment for noizdns dnstt-server.
// Uses Tor Pluggable Transports protocol:
//
//	TOR_PT_MANAGED_TRANSPORT_VER=1
//	TOR_PT_SERVER_TRANSPORTS=dnstt
//	TOR_PT_SERVER_BINDADDR=dnstt-LISTEN_ADDR:PORT
//	TOR_PT_ORPORT=BACKEND_ADDR
//	ExecStart=dnstt-server -privkey-file KEY -mtu MTU DOMAIN
func buildDNSTTService(tunnel *config.TunnelConfig, cfg *config.Config) (*dnsttService, error) {
	if tunnel.DNSTT == nil {
		return nil, fmt.Errorf("dnstt config is nil")
	}

	backend := cfg.GetBackend(tunnel.Backend)
	if backend == nil {
		return nil, fmt.Errorf("backend %q not found", tunnel.Backend)
	}

	binPath := filepath.Join(config.DefaultBinDir, "dnstt-server")

	// Single mode: bind directly to port 53 (no DNS router in the path).
	// Multi mode: bind to internal port, DNS router forwards from 53.
	port := tunnel.Port
	if cfg.Route.Mode != "multi" {
		port = 53
	}
	listenAddr := fmt.Sprintf("0.0.0.0:%d", port)

	mtu := tunnel.DNSTT.MTU
	if mtu == 0 {
		mtu = config.DefaultMTU
	}

	execStart := fmt.Sprintf("%s -privkey-file %s -mtu %d %s",
		binPath,
		tunnel.DNSTT.PrivateKey,
		mtu,
		tunnel.Domain,
	)

	env := []string{
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_SERVER_TRANSPORTS=dnstt",
		fmt.Sprintf("TOR_PT_SERVER_BINDADDR=dnstt-%s", listenAddr),
		fmt.Sprintf("TOR_PT_ORPORT=%s", backend.Address),
	}

	return &dnsttService{
		execStart:   execStart,
		environment: env,
	}, nil
}
