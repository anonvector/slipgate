package clientcfg

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/anonvector/slipgate/internal/config"
)

const testSoarKey = "tCd7Qm7FolQBkQfQUWLVrLBktDMirri+SlUaAHT1gxM="

func decodeFields(t *testing.T, uri string) []string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, uriScheme))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(data), "|")
}

// TestGenerateURISoar: a direct Soar link is v29, carries the server key and
// no login, since the direct backend has none.
func TestGenerateURISoar(t *testing.T) {
	cfg := &config.Config{Backends: config.DefaultBackends()}
	tunnel := &config.TunnelConfig{
		Tag: "soar", Transport: config.TransportSoar, Backend: config.BackendDirect, Domain: "r.example.com",
		Soar: &config.SoarConfig{PublicKey: testSoarKey},
	}
	uri, err := GenerateURI(tunnel, nil, cfg, URIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := decodeFields(t, uri)
	if len(f) != TotalFields || f[FVersion] != "29" || f[FTunnelType] != "soar" {
		t.Fatalf("got %d fields, version %q, type %q", len(f), f[FVersion], f[FTunnelType])
	}
	if f[FDomain] != "r.example.com" || f[FPublicKey] != testSoarKey {
		t.Errorf("domain %q key %q", f[FDomain], f[FPublicKey])
	}
	if f[FSoarDiscovery] != "0" || f[FSoarCountry] != "" || f[FSoarTCPMode] != "auto" {
		t.Errorf("soar fields %q %q %q", f[FSoarDiscovery], f[FSoarCountry], f[FSoarTCPMode])
	}
	if f[FSSHEnabled] != "0" || f[FSOCKSUser] != "" || f[FSOCKSPass] != "" {
		t.Errorf("direct link carries a login: ssh %q socks %q/%q", f[FSSHEnabled], f[FSOCKSUser], f[FSOCKSPass])
	}
}

// TestGenerateURISoarSSH: the app must ask the Soar server for exactly the SSH
// backend address, the only destination the server allows.
func TestGenerateURISoarSSH(t *testing.T) {
	cfg := &config.Config{Backends: config.DefaultBackends()}
	tunnel := &config.TunnelConfig{
		Tag: "soar-ssh", Transport: config.TransportSoar, Backend: config.BackendSSH, Domain: "rs.example.com",
		Soar: &config.SoarConfig{PublicKey: testSoarKey},
	}
	uri, err := GenerateURI(tunnel, cfg.GetBackend(config.BackendSSH), cfg, URIOptions{Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	f := decodeFields(t, uri)
	if f[FVersion] != "29" || f[FTunnelType] != "soar_ssh" || f[FSSHEnabled] != "1" || f[FSSHUser] != "u" || f[FSSHPass] != "p" {
		t.Errorf("version %q type %q ssh %q user %q pass %q", f[FVersion], f[FTunnelType], f[FSSHEnabled], f[FSSHUser], f[FSSHPass])
	}
	if f[FSSHHost] != "127.0.0.1" || f[FSSHPort] != "22" {
		t.Errorf("ssh target %s:%s, want the backend 127.0.0.1:22", f[FSSHHost], f[FSSHPort])
	}
}

// TestGenerateURIUnchangedForV22: transports older apps understand still export as v22.
func TestGenerateURIUnchangedForV22(t *testing.T) {
	cfg := &config.Config{Backends: config.DefaultBackends()}
	tunnel := &config.TunnelConfig{
		Tag: "vay", Transport: config.TransportVayDNS, Backend: config.BackendSOCKS, Domain: "v.example.com",
		VayDNS: &config.VayDNSConfig{PublicKey: "ab"},
	}
	uri, err := GenerateURI(tunnel, cfg.GetBackend(config.BackendSOCKS), cfg, URIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := decodeFields(t, uri)
	if len(f) != V22Fields || f[FVersion] != "22" || f[FTunnelType] != "vaydns" {
		t.Errorf("got %d fields, version %q, type %q", len(f), f[FVersion], f[FTunnelType])
	}
}
