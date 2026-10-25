package dnsrouter

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"
)

// buildQuery returns a minimal TXT query for name with the given TXID.
func buildQuery(txid uint16, name string) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], txid)
	binary.BigEndian.PutUint16(q[4:6], 1) // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0x00, 0x10, 0x00, 0x01) // root, TXT, IN
}

// startEchoBackend answers every query with itself, QR set, after a random
// delay so pipelined answers come back out of order.
func startEchoBackend(t *testing.T) string {
	t.Helper()
	return startEchoBackendAt(t, "127.0.0.1:0").LocalAddr().String()
}

// startEchoBackendAt runs an echo backend on addr until the test ends or the
// returned socket is closed.
func startEchoBackendAt(t *testing.T, addr string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte(nil), buf[:n]...)
			resp[2] |= 0x80
			go func() {
				time.Sleep(time.Duration(rand.IntN(20)) * time.Millisecond)
				pc.WriteTo(resp, addr)
			}()
		}
	}()
	return pc
}

// startRouter runs a router routing t.example.com to backend on a port free
// for both UDP and TCP, and waits until it accepts TCP connections.
func startRouter(t *testing.T, backend string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	r := New(addr)
	r.AddRoute("t.example.com", backend)
	go r.ListenAndServe()

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("router did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTCPPipelinedQueries(t *testing.T) {
	addr := startRouter(t, startEchoBackend(t))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Pipeline every query in one write, as RFC 7766 clients may.
	const count = 100
	want := make(map[uint16]string, count)
	var out []byte
	for i := range count {
		txid := uint16(40000 + i)
		name := "q" + string(rune('a'+i%26)) + ".t.example.com"
		want[txid] = name
		q := buildQuery(txid, name)
		out = binary.BigEndian.AppendUint16(out, uint16(len(q)))
		out = append(out, q...)
	}
	if _, err := conn.Write(out); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var hdr [2]byte
	for range count {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			t.Fatalf("read length: %v (%d answers missing)", err, len(want))
		}
		resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatal(err)
		}
		txid := binary.BigEndian.Uint16(resp[:2])
		name, ok := want[txid]
		if !ok {
			t.Fatalf("unexpected or duplicate TXID %d", txid)
		}
		if resp[2]&0x80 == 0 {
			t.Fatalf("TXID %d: not a response", txid)
		}
		if got := extractDomain(resp); got != name+"." {
			t.Fatalf("TXID %d: answer for %q, want %q", txid, got, name+".")
		}
		delete(want, txid)
	}
}

// A client that pipelines queries but never reads must be disconnected once
// its answers back up, not left waiting on answers that were dropped.
func TestTCPClosesClientNotReading(t *testing.T) {
	saved := tcpWriteQueue
	tcpWriteQueue = 4
	t.Cleanup(func() { tcpWriteQueue = saved })

	addr := startRouter(t, startEchoBackend(t))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(4096)

	// 300 answers of ~16 KB: far more than kernel buffers plus the queue hold.
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		padding := make([]byte, 16000)
		for i := range 300 {
			q := append(buildQuery(uint16(i), "x.t.example.com"), padding...)
			msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
			if _, err := conn.Write(append(msg, q...)); err != nil {
				return // the router closed on us
			}
		}
	}()
	select {
	case <-wrote:
	case <-time.After(10 * time.Second):
		t.Fatal("writes stalled")
	}
	time.Sleep(500 * time.Millisecond) // let answers arrive and back up

	// Drain what was buffered; the connection must then end, not idle.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection stayed open after its answer queue overflowed")
	}
}

// udpQuery sends one query through the router over UDP and reports whether
// its answer came back.
func udpQuery(t *testing.T, router string, txid uint16) bool {
	t.Helper()
	conn, err := net.Dial("udp", router)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(buildQuery(txid, "x.t.example.com"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	return err == nil && n >= 12 && binary.BigEndian.Uint16(buf[:2]) == txid
}

// A tunnel service restarting must not break its route: the router's next
// send gets ICMP port-unreachable, which Linux reports on the router's next
// read from that backend socket.
func TestBackendRestartRecovers(t *testing.T) {
	backend := startEchoBackendAt(t, "127.0.0.1:0")
	addr := backend.LocalAddr().String()
	router := startRouter(t, addr)
	if !udpQuery(t, router, 1) {
		t.Fatal("no answer before restart")
	}

	backend.Close()
	udpQuery(t, router, 2) // unanswered; triggers ICMP port-unreachable
	startEchoBackendAt(t, addr)

	if !udpQuery(t, router, 3) {
		t.Fatal("no answer after the backend came back")
	}
}

func TestUDPQueriesStillRouted(t *testing.T) {
	addr := startRouter(t, startEchoBackend(t))

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write(buildQuery(1234, "x.t.example.com")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(buf[:2]); got != 1234 || buf[2]&0x80 == 0 || n < 12 {
		t.Fatalf("bad UDP answer: txid=%d flags=%#x len=%d", got, buf[2], n)
	}
}
