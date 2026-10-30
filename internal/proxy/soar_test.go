package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anonvector/slipgate/internal/keys"
	"github.com/getlantern/soar"
)

// startEcho runs a TCP echo server on loopback and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// echoThroughSoar runs RunSoar with opts (its key and listen address filled
// in) and sends a message to dest through a Soar client.
func echoThroughSoar(t *testing.T, opts SoarOptions, dest string) {
	t.Helper()
	dir := t.TempDir()
	opts.KeyFile = filepath.Join(dir, "server.key")
	pubB64, err := keys.GenerateSoarKeys(opts.KeyFile, filepath.Join(dir, "server.pub"))
	if err != nil {
		t.Fatal(err)
	}
	opts.Zone = "r.example.com"
	opts.Listen = freeUDPAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunSoar(ctx, opts)

	pub, _ := base64.StdEncoding.DecodeString(pubB64)
	c, err := soar.NewClient(soar.Config{Zone: opts.Zone, ServerKey: pub, Resolvers: []string{opts.Listen}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
	defer dcancel()
	conn, err := c.DialContext(dctx, "tcp", dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	msg := []byte("hello through soar")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo %q", got)
	}
}

// TestRunSoarBackend: with a backend (Soar+SSH), a client reaches the backend.
func TestRunSoarBackend(t *testing.T) {
	echo := startEcho(t)
	echoThroughSoar(t, SoarOptions{Backend: echo}, echo)
}

// TestRunSoarDirect: without a backend, a client reaches the destination it
// names (loopback here, so only with allowPrivate).
func TestRunSoarDirect(t *testing.T) {
	echo := startEcho(t)
	echoThroughSoar(t, SoarOptions{AllowPorts: "any", AllowPrivate: true}, echo)
}

func TestSoarDialerBackendOnly(t *testing.T) {
	echo := startEcho(t)
	dial, err := soarDialer(echo, "", false)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("backend refused: %v", err)
	}
	conn.Close()
	if _, err := dial(context.Background(), "tcp", "93.184.215.14:443"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("other destination: err = %v, want not allowed", err)
	}
	if _, err := soarDialer("no-port", "", false); err == nil {
		t.Error("backend without a port accepted")
	}
}

func TestSoarDialerPublicPorts(t *testing.T) {
	dial, err := soarDialer("", "80,443", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(context.Background(), "tcp", "93.184.215.14:25"); err == nil || !strings.Contains(err.Error(), "port 25 not allowed") {
		t.Errorf("port 25: err = %v, want refused", err)
	}

	// Loopback is never a public destination, whatever the ports.
	dial, _ = soarDialer("", "any", false)
	if _, err := dial(context.Background(), "tcp", startEcho(t)); err == nil || !strings.Contains(err.Error(), "not public") {
		t.Errorf("loopback: err = %v, want not public", err)
	}
}
