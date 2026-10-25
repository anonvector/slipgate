package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/getlantern/soar"
)

// soarMaxBytesPerPrefix raises soar's per-/24 answer rate limit. Every query
// reaches us through the DNS router on 127.0.0.1, so the default 8 MB/s
// budget would be shared by all clients instead of applying per source.
const soarMaxBytesPerPrefix = 1 << 30

// soarUDPBuffer is the kernel buffer requested for soar's UDP socket.
const soarUDPBuffer = 4 << 20

// ServeSoar runs a Soar DNS tunnel server for zone on a UDP address. Like
// upstream soar-server, it dials the destination each stream names, so stock
// soar clients work; allowPorts ("80,443" or "any") limits the destination
// ports and non-public addresses are refused unless allowPrivate is set.
func ServeSoar(listen, zone, keyFile, allowPorts string, allowPrivate, verbose bool) error {
	priv, err := keys.LoadSoarKey(keyFile)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	logOpts := &slog.HandlerOptions{} // Info and up by default
	if verbose {
		logOpts.Level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, logOpts))

	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: soar.PublicOnly}
	if allowPrivate {
		dialer.Control = nil
	}
	allowed := strings.Split(strings.ReplaceAll(allowPorts, " ", ""), ",")
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if allowPorts != "any" && !slices.Contains(allowed, port) {
			return nil, fmt.Errorf("port %s not allowed", port)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	// Every client's queries arrive here from the DNS router; bursts must
	// queue rather than drop.
	if uc, ok := pc.(*net.UDPConn); ok {
		network.GrowUDPBuffers(uc, soarUDPBuffer)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Never log the zone or key: a leaked log would hand a censor what it needs to block us.
	logger.Info("soar serving", "listen", pc.LocalAddr(), "allow-ports", allowPorts)
	return soar.Serve(ctx, pc, soar.ServerConfig{
		Zone:              zone,
		PrivateKey:        priv,
		Dial:              dial,
		MaxBytesPerPrefix: soarMaxBytesPerPrefix,
		Logger:            logger,
	})
}
