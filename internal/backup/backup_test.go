package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
)

// testServer builds a tunnel directory tree and a config like a real server's.
func testServer(t *testing.T) (*config.Config, string) {
	t.Helper()
	root := t.TempDir()
	dir := func(tag string) string {
		d := filepath.Join(root, tag)
		if err := os.MkdirAll(d, 0750); err != nil {
			t.Fatal(err)
		}
		return d
	}
	write := func(path, data string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}

	dnsttDir := dir("dnstt")
	dnsttPub, err := keys.GenerateDNSTTKeys(filepath.Join(dnsttDir, "server.key"), filepath.Join(dnsttDir, "server.pub"))
	if err != nil {
		t.Fatal(err)
	}
	soarDir := dir("soar")
	soarPub, err := keys.GenerateSoarKeys(filepath.Join(soarDir, "server.key"), filepath.Join(soarDir, "server.pub"))
	if err != nil {
		t.Fatal(err)
	}
	slipDir := dir("slipstream")
	write(filepath.Join(slipDir, "cert.pem"), "CERT", 0644)
	write(filepath.Join(slipDir, "key.pem"), "KEY", 0600)

	naiveDir := dir("naive")
	write(filepath.Join(naiveDir, "Caddyfile"), "caddy", 0644)
	if err := os.MkdirAll(filepath.Join(naiveDir, ".caddy", "certificates"), 0750); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(naiveDir, ".caddy", "certificates", "acme.pem"), "ACME", 0600)

	// A StunTLS certificate kept outside its tunnel directory.
	elsewhere := t.TempDir()
	write(filepath.Join(elsewhere, "cert.pem"), "STUN-CERT", 0644)
	write(filepath.Join(elsewhere, "key.pem"), "STUN-KEY", 0600)

	cfg := config.Default()
	cfg.Tunnels = []config.TunnelConfig{
		{Tag: "dnstt", Transport: config.TransportDNSTT, Backend: config.BackendSOCKS, Domain: "t.example.com", Port: 5310, Enabled: true,
			DNSTT: &config.DNSTTConfig{MTU: 1232, PrivateKey: filepath.Join(dnsttDir, "server.key"), PublicKey: dnsttPub}},
		{Tag: "soar", Transport: config.TransportSoar, Backend: config.BackendDirect, Domain: "r.example.com", Port: 5311, Enabled: true,
			Soar: &config.SoarConfig{PrivateKey: filepath.Join(soarDir, "server.key"), PublicKey: soarPub, AllowPorts: "80, 443"}},
		{Tag: "slipstream", Transport: config.TransportSlipstream, Backend: config.BackendSSH, Domain: "s.example.com", Port: 5312, Enabled: true,
			Slipstream: &config.SlipstreamConfig{Cert: filepath.Join(slipDir, "cert.pem"), Key: filepath.Join(slipDir, "key.pem")}},
		{Tag: "naive", Transport: config.TransportNaive, Backend: config.BackendSOCKS, Domain: "example.com", Enabled: true,
			Naive: &config.NaiveConfig{Email: "admin@example.com", DecoyURL: "https://www.kernel.org", Port: 443, User: "alice", Password: "pw1"}},
		{Tag: "stuntls", Transport: config.TransportStunTLS, Backend: config.BackendSSH, Enabled: true,
			StunTLS: &config.StunTLSConfig{Cert: filepath.Join(elsewhere, "cert.pem"), Key: filepath.Join(elsewhere, "key.pem"), Port: 8443}},
		{Tag: "ext", Transport: config.TransportExternal, Backend: config.BackendSOCKS, Domain: "x.example.com", Port: 5313, Enabled: true},
	}
	cfg.Users = []config.UserConfig{{Username: "alice", Password: "pw1"}, {Username: "bob", Password: "p w2"}}
	cfg.Route = config.RouteConfig{Mode: "multi", Active: "dnstt", Default: "dnstt"}
	cfg.Warp.Enabled = true
	return cfg, root
}

func TestBackupRestoresEverything(t *testing.T) {
	cfg, root := testServer(t)
	b, err := Create(cfg, root, "test")
	if err != nil {
		t.Fatal(err)
	}
	text, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if len(line) > lineWidth && line != BeginMarker && line != EndMarker {
			t.Fatalf("line longer than %d columns: %q", lineWidth, line)
		}
	}
	if cfg.Tunnels[0].DNSTT.PrivateKey != filepath.Join(root, "dnstt", "server.key") {
		t.Fatal("Create changed the live config")
	}

	got, err := Decode(text)
	if err != nil {
		t.Fatal(err)
	}
	newRoot := t.TempDir()
	restored, err := got.Restore(newRoot)
	if err != nil {
		t.Fatal(err)
	}

	// Every file, including the server.pub files no config field names,
	// arrives with its content; private keys stay private.
	for _, f := range []struct {
		tag, name string
		perm      os.FileMode
	}{
		{"dnstt", "server.key", 0600}, {"dnstt", "server.pub", 0644},
		{"soar", "server.key", 0600}, {"soar", "server.pub", 0644},
		{"slipstream", "cert.pem", 0644}, {"slipstream", "key.pem", 0600},
		{"naive", "Caddyfile", 0644},
	} {
		want, err := os.ReadFile(filepath.Join(root, f.tag, f.name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(newRoot, f.tag, f.name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s/%s not restored: %v", f.tag, f.name, err)
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s/%s content differs", f.tag, f.name)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != f.perm {
			t.Errorf("%s/%s mode = %v, want %v", f.tag, f.name, info.Mode().Perm(), f.perm)
		}
	}
	if _, err := os.Stat(filepath.Join(newRoot, "naive", ".caddy")); !os.IsNotExist(err) {
		t.Error("NaiveProxy's .caddy state was included")
	}

	// Paths point into the new root; the outside StunTLS files moved in.
	byTag := func(tag string) *config.TunnelConfig { return restored.GetTunnel(tag) }
	if p := byTag("dnstt").DNSTT.PrivateKey; p != filepath.Join(newRoot, "dnstt", "server.key") {
		t.Errorf("dnstt key path = %s", p)
	}
	st := byTag("stuntls").StunTLS
	if filepath.Dir(st.Cert) != filepath.Join(newRoot, "stuntls") || filepath.Dir(st.Key) != filepath.Join(newRoot, "stuntls") {
		t.Errorf("stuntls paths not moved into its directory: %s %s", st.Cert, st.Key)
	}
	if data, _ := os.ReadFile(st.Key); string(data) != "STUN-KEY" {
		t.Errorf("stuntls key = %q", data)
	}

	if byTag("dnstt").DNSTT.PublicKey != cfg.Tunnels[0].DNSTT.PublicKey || byTag("soar").Soar.PublicKey != cfg.Tunnels[1].Soar.PublicKey {
		t.Error("public keys changed")
	}
	if len(restored.Users) != 2 || restored.Users[1].Password != "p w2" {
		t.Errorf("users = %+v", restored.Users)
	}
	if !restored.Warp.Enabled || restored.Route.Mode != "multi" || len(restored.Tunnels) != len(cfg.Tunnels) {
		t.Error("route, WARP or tunnels not restored")
	}
}

func TestDecodeToleratesCopyPaste(t *testing.T) {
	cfg, root := testServer(t)
	b, err := Create(cfg, root, "test")
	if err != nil {
		t.Fatal(err)
	}
	text, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(text), "\n")
	var mangled strings.Builder
	mangled.WriteString("root@old:~# slipgate backup\nsome output\n")
	for _, l := range lines {
		mangled.WriteString("    " + l + "  \r\n") // indented, CRLF, trailing spaces
	}
	mangled.WriteString("root@old:~#\n")
	if _, err := Decode(mangled.String()); err != nil {
		t.Fatalf("indented CRLF paste: %v", err)
	}

	// Lines joined into one, as some chat apps do.
	joined := lines[0] + "\n" + strings.Join(lines[1:len(lines)-1], "") + "\n" + lines[len(lines)-1]
	if _, err := Decode(joined); err != nil {
		t.Fatalf("joined lines: %v", err)
	}
}

func TestDecodeDetectsDamage(t *testing.T) {
	cfg, root := testServer(t)
	b, err := Create(cfg, root, "test")
	if err != nil {
		t.Fatal(err)
	}
	text, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(text, "\n")

	missingLine := strings.Join(append(append([]string{}, lines[:3]...), lines[4:]...), "\n")
	flipped := []byte(text)
	mid := len(BeginMarker) + len(text[len(BeginMarker):])/2
	if flipped[mid] == 'A' {
		flipped[mid] = 'B'
	} else {
		flipped[mid] = 'A'
	}

	for name, damaged := range map[string]string{
		"no END line":  strings.Join(lines[:len(lines)/2], "\n"),
		"missing line": missingLine,
		"changed char": string(flipped),
		"not a backup": "hello",
	} {
		if _, err := Decode(damaged); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
}

// One unusable user (e.g. a legacy password with ':') must not make the whole
// backup unrestorable: it is left out and reported.
func TestDecodeSkipsUnsafeUsers(t *testing.T) {
	cfg, root := testServer(t)
	cfg.Users = append(cfg.Users,
		config.UserConfig{Username: "eve", Password: "pw\nroot:owned"},
		config.UserConfig{Username: "-o", Password: "pw"},
		config.UserConfig{Username: "alice", Password: "again"},
	)
	b, err := Create(cfg, root, "test")
	if err != nil {
		t.Fatal(err)
	}
	text, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.DroppedUsers) != 3 {
		t.Errorf("dropped = %q, want 3 entries", got.DroppedUsers)
	}
	for _, d := range got.DroppedUsers {
		if strings.Contains(d, "owned") {
			t.Errorf("drop reason reveals the password: %q", d)
		}
	}
	if len(got.Config.Users) != 2 || got.Config.Users[0].Password != "pw1" {
		t.Errorf("users = %+v, want the two valid ones", got.Config.Users)
	}
}

func TestDecodeRejectsUnsafeBundles(t *testing.T) {
	valid := func(t *testing.T) *Bundle {
		cfg, root := testServer(t)
		b, err := Create(cfg, root, "test")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string]func(b *Bundle){
		"file name escapes directory": func(b *Bundle) {
			b.Files["dnstt"]["../../../etc/cron.d/x"] = File{Mode: 0644, Data: []byte("* * * * * root sh")}
		},
		"key path escapes directory": func(b *Bundle) {
			b.Config.Tunnels[0].DNSTT.PrivateKey = "../soar/server.key"
		},
		"files for unknown tunnel": func(b *Bundle) {
			b.Files["ghost"] = map[string]File{"x": {Data: []byte("x")}}
		},
		"missing key file": func(b *Bundle) {
			delete(b.Files["dnstt"], "server.key")
		},
		"newline in domain": func(b *Bundle) {
			b.Config.Tunnels[0].Domain = "t.example.com\nExecStartPre=/bin/sh -c id"
		},
		"newer format": func(b *Bundle) {
			b.Format = formatVersion + 1
		},
	}
	for name, mutate := range cases {
		b := valid(t)
		mutate(b)
		text, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
