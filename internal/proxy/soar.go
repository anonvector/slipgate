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

// soarDialTimeout bounds how long a stream waits for its destination.
const soarDialTimeout = 15 * time.Second

// SoarOptions configures a Soar DNS tunnel server.
type SoarOptions struct {
	Listen  string // UDP address the DNS router forwards the zone's queries to
	Zone    string
	KeyFile string // base64 Ed25519 seed
	// Backend, when set, is the only destination streams may reach (the SSH
	// backend), so access goes through SSH logins. Otherwise streams reach
	// public destinations on AllowPorts, like upstream soar-server.
	Backend      string
	AllowPorts   string // "80,443" or "any"
	AllowPrivate bool   // allow non-public destinations (no backend only)
	Verbose      bool
}

// ServeSoar runs a Soar DNS tunnel server until SIGTERM or SIGINT.
func ServeSoar(opts SoarOptions) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return RunSoar(ctx, opts)
}

// RunSoar runs a Soar DNS tunnel server until ctx ends.
func RunSoar(ctx context.Context, opts SoarOptions) error {
	priv, err := keys.LoadSoarKey(opts.KeyFile)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	dial, err := soarDialer(opts.Backend, opts.AllowPorts, opts.AllowPrivate)
	if err != nil {
		return err
	}

	logOpts := &slog.HandlerOptions{} // Info and up by default
	if opts.Verbose {
		logOpts.Level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, logOpts))

	pc, err := net.ListenPacket("udp", opts.Listen)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	// Every client's queries arrive here from the DNS router; bursts must
	// queue rather than drop.
	if uc, ok := pc.(*net.UDPConn); ok {
		network.GrowUDPBuffers(uc, soarUDPBuffer)
	}

	// Never log the zone or key: a leaked log would hand a censor what it needs to block us.
	if opts.Backend != "" {
		logger.Info("soar serving", "listen", pc.LocalAddr(), "backend", opts.Backend)
	} else {
		logger.Info("soar serving", "listen", pc.LocalAddr(), "allow-ports", opts.AllowPorts)
	}
	return soar.Serve(ctx, pc, soar.ServerConfig{
		Zone:              opts.Zone,
		PrivateKey:        priv,
		Dial:              dial,
		MaxBytesPerPrefix: soarMaxBytesPerPrefix,
		Logger:            logger,
	})
}

type soarDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// soarDialer returns the policy streams are dialed under. With a backend,
// the backend address is the only destination: anyone who finds the zone
// reaches nothing but the SSH login. Otherwise destinations must be public
// (soar.PublicOnly also refuses the server's own addresses) and on an allowed
// port, unless allowPrivate is set.
func soarDialer(backend, allowPorts string, allowPrivate bool) (soarDialFunc, error) {
	if backend != "" {
		if _, _, err := net.SplitHostPort(backend); err != nil {
			return nil, fmt.Errorf("backend %q: %w", backend, err)
		}
		d := &net.Dialer{Timeout: soarDialTimeout}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != backend {
				return nil, fmt.Errorf("destination %s not allowed (only the backend)", addr)
			}
			return d.DialContext(ctx, network, addr)
		}, nil
	}

	d := &net.Dialer{Timeout: soarDialTimeout, Control: soar.PublicOnly}
	if allowPrivate {
		d.Control = nil
	}
	allowed := strings.Split(strings.ReplaceAll(allowPorts, " ", ""), ",")
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if allowPorts != "any" && !slices.Contains(allowed, port) {
			return nil, fmt.Errorf("port %s not allowed", port)
		}
		return d.DialContext(ctx, network, addr)
	}, nil
}
