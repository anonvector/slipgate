package dnsrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/network"
)

// Router is a pure Go DNS forwarder that routes queries by domain.
type Router struct {
	listenAddr   string
	routes       map[string]string // domain → backend address (host:port)
	verifyRoutes []verifyRoute     // HMAC verification routes
	defaultDst   string
	mu           sync.RWMutex
	conn         *net.UDPConn

	// Persistent backend connections and pending query tracking (backend.go)
	backends   map[string]*backendConn
	backendsMu sync.Mutex
}

// replyFunc delivers a response to the client that sent the query, over
// whichever transport (UDP or TCP) it arrived on. It must not retain msg.
type replyFunc func(msg []byte)

// New creates a new DNS router.
func New(listenAddr string) *Router {
	return &Router{
		listenAddr: listenAddr,
		routes:     make(map[string]string),
		backends:   make(map[string]*backendConn),
	}
}

// AddRoute maps a domain to a backend address.
func (r *Router) AddRoute(domain, backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Normalize: ensure trailing dot
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	r.routes[strings.ToLower(domain)] = backend
}

// AddVerifyRoute registers a domain's public key and MTU for HMAC verification.
func (r *Router) AddVerifyRoute(domain string, pubkey []byte, mtu int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	r.verifyRoutes = append(r.verifyRoutes, verifyRoute{
		domainLabels: strings.Split(domain, "."),
		pubkey:       pubkey,
		mtu:          mtu,
	})
}

// SetDefault sets the default backend for unmatched queries.
func (r *Router) SetDefault(backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultDst = backend
}

// ListenAndServe starts the DNS router.
func (r *Router) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen addr: %w", err)
	}

	r.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer r.conn.Close()
	network.GrowUDPBuffers(r.conn, udpBufferSize)

	// TCP/53 (RFC 7766) for clients and resolvers that can't or won't use
	// UDP. Failing to bind it is not fatal: UDP keeps working as before.
	if ln, err := net.Listen("tcp", r.listenAddr); err != nil {
		log.Printf("tcp listen %s: %v (continuing with UDP only)", r.listenAddr, err)
	} else {
		go r.serveTCP(ln)
		log.Printf("DNS router listening on %s (tcp)", r.listenAddr)
	}

	log.Printf("DNS router listening on %s", r.listenAddr)

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		// Copy packet for goroutine
		packet := make([]byte, n)
		copy(packet, buf[:n])

		go r.handleQuery(packet, clientAddr, func(msg []byte) {
			r.conn.WriteToUDP(msg, clientAddr)
		})
	}
}

func (r *Router) handleQuery(packet []byte, from net.Addr, reply replyFunc) {
	// Check for HMAC verification query first
	if r.handleVerify(packet, from, reply) {
		return
	}

	// Extract domain from DNS query
	domain := extractDomain(packet)
	if domain == "" {
		return
	}

	// Find matching backend
	r.mu.RLock()
	backend := r.findBackend(domain)
	r.mu.RUnlock()

	if backend == "" {
		return
	}

	if len(packet) < 12 {
		return
	}
	// A backend that is down refuses with ICMP; its service status already
	// shows that, so don't log it for every query.
	if err := r.forward(backend, packet, reply); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
		log.Printf("forward to %s: %v", backend, err)
	}
}

func (r *Router) findBackend(domain string) string {
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Try exact match first
	if dst, ok := r.routes[domain]; ok {
		return dst
	}

	// Try suffix match (for subdomains)
	for routeDomain, dst := range r.routes {
		if strings.HasSuffix(domain, "."+routeDomain) || domain == routeDomain {
			return dst
		}
	}

	return r.defaultDst
}

// Serve loads config and starts the DNS router.
func Serve(cfgInterface interface{}) error {
	cfg, ok := cfgInterface.(*config.Config)
	if !ok {
		return fmt.Errorf("invalid config type")
	}

	r := New(cfg.Listen.Address)

	for _, tunnel := range cfg.Tunnels {
		if !tunnel.Enabled || !tunnel.IsDNSTunnel() {
			continue
		}
		backend := fmt.Sprintf("127.0.0.1:%d", tunnel.Port)
		r.AddRoute(tunnel.Domain, backend)
		log.Printf("route: %s → %s", tunnel.Domain, backend)

		// Register HMAC verification
		switch tunnel.Transport {
		case config.TransportDNSTT:
			if tunnel.DNSTT != nil && tunnel.DNSTT.PublicKey != "" {
				pubkey, err := loadPubkey(tunnel.DNSTT.PublicKey)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				mtu := tunnel.DNSTT.MTU
				if mtu == 0 {
					mtu = config.DefaultMTU
				}
				r.AddVerifyRoute(tunnel.Domain, pubkey, mtu)
				log.Printf("verify: %s (HMAC via pubkey, mtu=%d)", tunnel.Domain, mtu)
			}
		case config.TransportVayDNS:
			if tunnel.VayDNS != nil && tunnel.VayDNS.PublicKey != "" {
				pubkey, err := loadPubkey(tunnel.VayDNS.PublicKey)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				mtu := tunnel.VayDNS.MTU
				if mtu == 0 {
					mtu = config.DefaultMTU
				}
				r.AddVerifyRoute(tunnel.Domain, pubkey, mtu)
				log.Printf("verify: %s (HMAC via pubkey, mtu=%d)", tunnel.Domain, mtu)
			}
		case config.TransportSlipstream:
			if tunnel.Slipstream != nil && tunnel.Slipstream.Cert != "" {
				hmacKey, err := certToHMACKey(tunnel.Slipstream.Cert)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				r.AddVerifyRoute(tunnel.Domain, hmacKey, 0)
				log.Printf("verify: %s (HMAC via cert fingerprint)", tunnel.Domain)
			}
		}
	}

	if cfg.Route.Default != "" {
		defaultTunnel := cfg.GetTunnel(cfg.Route.Default)
		if defaultTunnel != nil && defaultTunnel.IsDNSTunnel() {
			r.SetDefault(fmt.Sprintf("127.0.0.1:%d", defaultTunnel.Port))
		}
	}

	return r.ListenAndServe()
}

// certToHMACKey derives a 32-byte HMAC key from a PEM certificate file.
func certToHMACKey(certPath string) ([]byte, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	hash := sha256.Sum256(block.Bytes)
	return hash[:], nil
}

// loadPubkey loads a hex-encoded public key.
func loadPubkey(pubkeyOrPath string) ([]byte, error) {
	hexStr := pubkeyOrPath
	if _, err := os.Stat(pubkeyOrPath); err == nil {
		data, err := os.ReadFile(pubkeyOrPath)
		if err != nil {
			return nil, fmt.Errorf("read pubkey file: %w", err)
		}
		hexStr = strings.TrimSpace(string(data))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey hex: %w", err)
	}
	return b, nil
}
