package config

import (
	"strings"
	"testing"
)

func importable() *Config {
	c := Default()
	c.Tunnels = []TunnelConfig{
		{Tag: "dnstt", Transport: TransportDNSTT, Backend: BackendSOCKS, Domain: "t.example.com", Port: 5310,
			DNSTT: &DNSTTConfig{PrivateKey: "server.key", PublicKey: strings.Repeat("ab", 32)}},
		{Tag: "vay", Transport: TransportVayDNS, Backend: BackendSSH, Domain: "v.example.com", Port: 5311,
			VayDNS: &VayDNSConfig{PrivateKey: "server.key", IdleTimeout: "2m", RecordType: "cname", Fallback: "8.8.8.8:53"}},
		{Tag: "soar", Transport: TransportSoar, Backend: BackendDirect, Domain: "r.example.com", Port: 5312,
			Soar: &SoarConfig{PrivateKey: "server.key", PublicKey: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", AllowPorts: "80, 443"}},
		{Tag: "naive-socks", Transport: TransportNaive, Backend: BackendSOCKS, Domain: "example.com",
			Naive: &NaiveConfig{Email: "a@example.com", DecoyURL: "https://www.kernel.org", Port: 443, User: "alice", Password: "pw"}},
		{Tag: "naive-ssh", Transport: TransportNaive, Backend: BackendSSH, Domain: "example.com",
			Naive: &NaiveConfig{Email: "a@example.com", Port: 443}},
		{Tag: "ext", Transport: TransportExternal, Backend: BackendSOCKS, Domain: "x.example.com", Port: 5313},
		{Tag: "soar-ssh", Transport: TransportSoar, Backend: BackendSSH, Domain: "rs.example.com", Port: 5314,
			Soar: &SoarConfig{PrivateKey: "server.key", PublicKey: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="}},
	}
	c.Users = []UserConfig{{Username: "alice", Password: "pw"}, {Username: "bob_2", Password: "with space"}, {Username: "Carol.9", Password: "x"}}
	return c
}

func TestValidateImportedAcceptsRealConfig(t *testing.T) {
	if err := importable().ValidateImported(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateImportedRejectsInjection(t *testing.T) {
	cases := map[string]func(c *Config){
		"newline in domain":         func(c *Config) { c.Tunnels[0].Domain = "t.example.com\nExecStartPre=/bin/sh" },
		"extra argument in domain":  func(c *Config) { c.Tunnels[0].Domain = "t.example.com -privkey-file /etc/shadow" },
		"space in backend address":  func(c *Config) { c.Backends[0].Address = "127.0.0.1:1080 --x" },
		"bad vaydns fallback":       func(c *Config) { c.Tunnels[1].VayDNS.Fallback = "8.8.8.8:53 -x" },
		"bad vaydns duration":       func(c *Config) { c.Tunnels[1].VayDNS.IdleTimeout = "2m -x" },
		"bad vaydns record type":    func(c *Config) { c.Tunnels[1].VayDNS.RecordType = "txt -x" },
		"bad soar ports":            func(c *Config) { c.Tunnels[2].Soar.AllowPorts = "80 --allow-private" },
		"soar via socks":            func(c *Config) { c.Tunnels[2].Backend = BackendSOCKS },
		"bad dnstt public key":      func(c *Config) { c.Tunnels[0].DNSTT.PublicKey = "/etc/shadow" },
		"caddyfile brace":           func(c *Config) { c.Tunnels[3].Naive.Password = "pw}" },
		"caddyfile space":           func(c *Config) { c.Tunnels[3].Naive.Email = "a@example.com import /x" },
		"decoy not a URL":           func(c *Config) { c.Tunnels[3].Naive.DecoyURL = "file:///etc/passwd" },
		"username as option":        func(c *Config) { c.Users[0].Username = "-o" },
		"numeric username":          func(c *Config) { c.Users[0].Username = "0" },
		"username with newline":     func(c *Config) { c.Users[0].Username = "alice\nroot" },
		"chpasswd line injection":   func(c *Config) { c.Users[0].Password = "pw\nroot:owned" },
		"duplicate user":            func(c *Config) { c.Users[1].Username = "alice" },
		"port out of range":         func(c *Config) { c.Tunnels[0].Port = 70000 },
		"transport settings absent": func(c *Config) { c.Tunnels[0].DNSTT = nil },
		"control char anywhere":     func(c *Config) { c.Route.Default = "dnstt\x00" },
	}
	for name, mutate := range cases {
		c := importable()
		mutate(c)
		if err := c.ValidateImported(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateDomainPerBackend(t *testing.T) {
	c := importable()
	if err := c.Validate(); err != nil {
		t.Fatalf("same domain, different backends: %v", err)
	}
	c.Tunnels[4].Backend = BackendSOCKS
	if err := c.Validate(); err == nil {
		t.Fatal("same domain and backend twice accepted")
	}
}
