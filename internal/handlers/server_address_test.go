package handlers

import (
	"path/filepath"
	"testing"

	"github.com/anonvector/slipgate/internal/config"
)

func TestSetPublicAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := config.Default().SaveTo(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := setPublicAddress(cfg, "203.0.113.7:22"); err == nil || cfg.PublicAddress != "" {
		t.Errorf("address with a port accepted: %v, %q", err, cfg.PublicAddress)
	}
	if err := setPublicAddress(cfg, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if saved, _ := config.LoadFrom(path); saved.PublicAddress != "203.0.113.7" {
		t.Errorf("saved %q", saved.PublicAddress)
	}
	if err := setPublicAddress(cfg, "auto"); err != nil {
		t.Fatal(err)
	}
	if saved, _ := config.LoadFrom(path); saved.PublicAddress != "" {
		t.Errorf(`"auto" left %q`, saved.PublicAddress)
	}
}

// TestEnsureServerAddressQuiet: nothing to ask or warn about when no tunnel
// connects by address, or when the public address is known.
func TestEnsureServerAddressQuiet(t *testing.T) {
	dnsOnly := []config.TunnelConfig{{Tag: "dnstt", Transport: config.TransportDNSTT, Domain: "t.example.com"}}
	direct := []config.TunnelConfig{{Tag: "ssh", Transport: config.TransportSSH}}

	out := &printOutput{}
	ensureServerAddress(&config.Config{}, out, dnsOnly)
	ensureServerAddress(&config.Config{PublicAddress: "203.0.113.7"}, out, direct)
	if len(out.lines) != 0 {
		t.Errorf("printed %q", out.lines)
	}
}
