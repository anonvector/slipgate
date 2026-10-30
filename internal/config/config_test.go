package config

import (
	"slices"
	"testing"
)

// TestServerHostnames: ns.<parent> for DNS tunnels and the domain for
// NaiveProxy, once each; tunnels without a domain have none.
func TestServerHostnames(t *testing.T) {
	got := importable().ServerHostnames()
	want := []string{"ns.example.com", "example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	c := &Config{Tunnels: []TunnelConfig{
		{Transport: TransportDNSTT, Domain: "t.a.example.com"},
		{Transport: TransportNaive, Domain: "n.example.org"},
		{Transport: TransportSoar, Domain: "s.a.example.com"},
		{Transport: TransportStunTLS},
		{Transport: TransportSSH},
	}}
	if got, want := c.ServerHostnames(), []string{"ns.a.example.com", "n.example.org"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParentDomain(t *testing.T) {
	for in, want := range map[string]string{
		"t.example.com": "example.com", "a.b.example.com": "b.example.com",
		"example.com": "example.com", "t..example.com": "example.com",
	} {
		if got := ParentDomain(in); got != want {
			t.Errorf("ParentDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidatePublicAddress(t *testing.T) {
	for _, ok := range []string{"203.0.113.7", "2001:db8::1", "vpn.example.com"} {
		if err := ValidatePublicAddress(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "203.0.113.7:22", "https://vpn.example.com", "vpn example.com", "localhost", "-x"} {
		if ValidatePublicAddress(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
