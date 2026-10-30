package clientcfg

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/anonvector/slipgate/internal/config"
)

// stubDetection replaces the local IP and DNS lookups for one test, and
// returns the hostnames looked up so far.
func stubDetection(t *testing.T, local string, records map[string][]string) *[]string {
	t.Helper()
	oldLocal, oldLookup := localIP, lookupIP
	t.Cleanup(func() {
		localIP, lookupIP = oldLocal, oldLookup
		detectCache = map[string]detectedAddress{}
	})
	detectCache = map[string]detectedAddress{}

	var looked []string
	localIP = func() string { return local }
	lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		looked = append(looked, host)
		addrs, ok := records[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var ips []net.IP
		for _, a := range addrs {
			ips = append(ips, net.ParseIP(a))
		}
		return ips, nil
	}
	return &looked
}

func addressTestConfig() *config.Config {
	return &config.Config{
		Backends: config.DefaultBackends(),
		Tunnels: []config.TunnelConfig{
			{Tag: "dnstt", Transport: config.TransportDNSTT, Backend: config.BackendSOCKS, Domain: "t.example.com"},
			{Tag: "naive", Transport: config.TransportNaive, Backend: config.BackendSOCKS, Domain: "n.example.org"},
			{Tag: "ssh", Transport: config.TransportSSH, Backend: config.BackendSSH},
		},
	}
}

func TestServerAddressConfigured(t *testing.T) {
	looked := stubDetection(t, "10.0.0.5", nil)
	cfg := addressTestConfig()
	cfg.PublicAddress = "vpn.example.net"
	if addr, public := ServerAddress(cfg); addr != "vpn.example.net" || !public {
		t.Errorf("got %q, %v", addr, public)
	}
	if len(*looked) != 0 {
		t.Errorf("looked up %v despite a configured address", *looked)
	}
}

func TestServerAddressPublicLocalIP(t *testing.T) {
	looked := stubDetection(t, "203.0.113.7", nil)
	if addr, public := ServerAddress(addressTestConfig()); addr != "203.0.113.7" || !public {
		t.Errorf("got %q, %v", addr, public)
	}
	if len(*looked) != 0 {
		t.Errorf("looked up %v despite a public local IP", *looked)
	}
}

// TestServerAddressFromDNS: a cloud server sees only its private IP, so the
// address comes from its DNS records, IPv4 first, skipping private answers.
func TestServerAddressFromDNS(t *testing.T) {
	looked := stubDetection(t, "10.0.0.5", map[string][]string{
		"ns.example.com": {"10.1.1.1", "2001:db8::1"},
		"n.example.org":  {"198.51.100.9"},
	})
	if addr, public := ServerAddress(addressTestConfig()); addr != "198.51.100.9" || !public {
		t.Errorf("got %q, %v", addr, public)
	}
	if want := []string{"ns.example.com", "n.example.org"}; len(*looked) != 2 || (*looked)[0] != want[0] || (*looked)[1] != want[1] {
		t.Errorf("looked up %v, want %v", *looked, want)
	}

	// Detection is cached: configs are generated per user and tunnel
	ServerAddress(addressTestConfig())
	if len(*looked) != 2 {
		t.Errorf("looked up again: %v", *looked)
	}
}

func TestServerAddressIPv6FromDNS(t *testing.T) {
	stubDetection(t, "10.0.0.5", map[string][]string{"ns.example.com": {"2001:db8::1"}})
	if addr, public := ServerAddress(addressTestConfig()); addr != "2001:db8::1" || !public {
		t.Errorf("got %q, %v", addr, public)
	}
}

func TestServerAddressUnknown(t *testing.T) {
	stubDetection(t, "10.0.0.5", nil)
	if addr, public := ServerAddress(addressTestConfig()); addr != "10.0.0.5" || public {
		t.Errorf("got %q, %v; want the private IP, not public", addr, public)
	}
}

func TestIsPublicIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "203.0.113.7": true, "2001:4860:4860::8888": true,
		"10.0.0.5": false, "172.16.0.1": false, "192.168.1.1": false, "100.64.0.1": false,
		"127.0.0.1": false, "169.254.1.1": false, "0.0.0.0": false, "fd00::1": false, "fe80::1": false,
	} {
		if got := isPublicIP(net.ParseIP(ip)); got != want {
			t.Errorf("isPublicIP(%s) = %v, want %v", ip, got, want)
		}
	}
	if isPublicIP(nil) {
		t.Error("isPublicIP(nil) = true")
	}
}

// TestGenerateURIUsesPublicAddress: configs that connect by address get the
// configured public one.
func TestGenerateURIUsesPublicAddress(t *testing.T) {
	stubDetection(t, "10.0.0.5", nil)
	cfg := addressTestConfig()
	cfg.PublicAddress = "198.51.100.9"
	for _, tunnel := range []*config.TunnelConfig{
		{Tag: "ssh", Transport: config.TransportSSH, Backend: config.BackendSSH},
		{Tag: "socks", Transport: config.TransportSOCKS, Backend: config.BackendSOCKS},
		{Tag: "stun", Transport: config.TransportStunTLS, Backend: config.BackendSSH, StunTLS: &config.StunTLSConfig{Port: 443}},
	} {
		uri, err := GenerateURI(tunnel, cfg.GetBackend(tunnel.Backend), cfg, URIOptions{Username: "u", Password: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if f := decodeFields(t, uri); f[FDomain] != "198.51.100.9" || f[FSSHHost] != "198.51.100.9" {
			t.Errorf("%s: domain %q, SSH host %q", tunnel.Tag, f[FDomain], f[FSSHHost])
		}
	}
}

// TestGenerateURITunneledKeepsLocalIP: through a tunnel the server itself
// dials the SSH host (NaiveProxy CONNECTs to it), so that stays the IP the
// server can always reach, and nothing is looked up.
func TestGenerateURITunneledKeepsLocalIP(t *testing.T) {
	looked := stubDetection(t, "10.0.0.5", nil)
	cfg := addressTestConfig()
	cfg.PublicAddress = "198.51.100.9"
	tunnel := &config.TunnelConfig{Tag: "naive", Transport: config.TransportNaive, Backend: config.BackendSSH,
		Domain: "n.example.org", Naive: &config.NaiveConfig{Port: 443}}
	uri, err := GenerateURI(tunnel, cfg.GetBackend(config.BackendSSH), cfg, URIOptions{Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if f := decodeFields(t, uri); f[FDomain] != "n.example.org" || f[FSSHHost] != "10.0.0.5" {
		t.Errorf("domain %q, SSH host %q", f[FDomain], f[FSSHHost])
	}
	if len(*looked) != 0 {
		t.Errorf("looked up %v", *looked)
	}
}
