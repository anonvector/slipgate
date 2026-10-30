package clientcfg

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/anonvector/slipgate/internal/config"
)

// ServerAddress returns the address client configs use to reach this
// server, and whether it is known to be public. A configured public address
// wins. Otherwise it is this machine's outbound IP when that is public, else
// the public IP the server's DNS records (ns.<domain>, NaiveProxy domains)
// point at: cloud servers such as Oracle, AWS, GCP and Azure only see a
// private IP on their interface, which clients can't reach.
func ServerAddress(cfg *config.Config) (string, bool) {
	if cfg == nil {
		return detectServerAddress(nil)
	}
	if cfg.PublicAddress != "" {
		return cfg.PublicAddress, true
	}
	return detectServerAddress(cfg.ServerHostnames())
}

type detectedAddress struct {
	addr   string
	public bool
}

// Detection is cached per set of hostnames: a config is generated for every
// user and tunnel, and each lookup can take a DNS round trip.
var (
	detectMu    sync.Mutex
	detectCache = map[string]detectedAddress{}
)

func detectServerAddress(hostnames []string) (string, bool) {
	key := strings.Join(hostnames, ",")
	detectMu.Lock()
	defer detectMu.Unlock()
	if d, ok := detectCache[key]; ok {
		return d.addr, d.public
	}

	d := detectedAddress{addr: localIP()}
	d.public = isPublicIP(net.ParseIP(d.addr))
	if !d.public {
		if ip := lookupPublicIP(hostnames); ip != "" {
			d = detectedAddress{addr: ip, public: true}
		}
	}
	detectCache[key] = d
	return d.addr, d.public
}

// localIP returns the source address this machine uses for outbound
// traffic. Dialing UDP sends no packets.
var localIP = func() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// lookupPublicIP returns the first public IP the hostnames resolve to,
// preferring IPv4.
func lookupPublicIP(hostnames []string) string {
	var v6 string
	for _, h := range hostnames {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := lookupIP(ctx, h)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if !isPublicIP(ip) {
				continue
			}
			if ip.To4() != nil {
				return ip.String()
			}
			if v6 == "" {
				v6 = ip.String()
			}
		}
	}
	return v6
}

// cgnat is the shared address space carriers put behind NAT (RFC 6598).
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// isPublicIP reports whether clients on the internet could reach ip.
func isPublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !ip.IsMulticast() && !cgnat.Contains(ip)
}
