package dnsrouter

import (
	"encoding/binary"
	"testing"
	"time"
)

func currentBackend(r *Router, addr string) *backendConn {
	r.backendsMu.Lock()
	defer r.backendsMu.Unlock()
	return r.backends[addr]
}

// A connection sends each TXID once. The query after the last one goes out
// on a new connection, and the old one stays open for answers in flight.
func TestTXIDNotReusedOnConnection(t *testing.T) {
	addr := startEchoBackend(t)
	r := New("127.0.0.1:0")
	ignore := func([]byte) {}

	query := buildQuery(0, "x.t.example.com")
	used := make([]bool, 1<<16)
	var bc *backendConn
	for i := 0; i < 1<<16; i++ {
		if err := r.forward(addr, query, ignore); err != nil {
			t.Fatal(err)
		}
		id := binary.BigEndian.Uint16(query[:2])
		if used[id] {
			t.Fatalf("query %d: TXID %d sent twice on one connection", i, id)
		}
		used[id] = true
		if i == 0 {
			bc = currentBackend(r, addr)
		} else if currentBackend(r, addr) != bc {
			t.Fatalf("query %d: switched connection before all TXIDs were used", i)
		}
	}

	if err := r.forward(addr, query, ignore); err != nil {
		t.Fatal(err)
	}
	next := currentBackend(r, addr)
	if next == bc || !bc.retired.Load() {
		t.Fatal("spent connection was not replaced")
	}
	if next.conn.LocalAddr().String() == bc.conn.LocalAddr().String() {
		t.Fatal("new connection kept the old source port")
	}
	if id := binary.BigEndian.Uint16(query[:2]); id != 1 {
		t.Fatalf("new connection started at TXID %d, want 1", id)
	}
	if err := bc.conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("retired connection closed while answers may be in flight: %v", err)
	}
}

func TestRetiredBackendClosedOnceDrained(t *testing.T) {
	defer func(d time.Duration) { cleanInterval = d }(cleanInterval)
	cleanInterval = 20 * time.Millisecond

	addr := startEchoBackend(t)
	r := New("127.0.0.1:0")
	answered := make(chan struct{}, 1)
	if err := r.forward(addr, buildQuery(9, "x.t.example.com"), func([]byte) { answered <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("no answer from backend")
	}

	bc := currentBackend(r, addr)
	r.retireBackend(addr, bc)
	for start := time.Now(); bc.conn.SetReadDeadline(time.Time{}) == nil; {
		if time.Since(start) > 5*time.Second {
			t.Fatal("retired connection with nothing pending was never closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAnswerMustEchoQuestion(t *testing.T) {
	query := buildQuery(7, "abc.t.example.com")
	q := questionSection(query)
	if q == nil {
		t.Fatal("no question parsed from query")
	}
	answer := func(name string, qtype uint16) []byte {
		resp := buildQuery(7, name)
		resp[2] |= 0x80
		binary.BigEndian.PutUint16(resp[len(resp)-4:], qtype)
		return resp
	}
	noQuestion := make([]byte, 12) // e.g. FORMERR with QDCOUNT=0
	noQuestion[2] = 0x80

	cases := []struct {
		name string
		q    []byte
		resp []byte
		want bool
	}{
		{"same question", q, answer("abc.t.example.com", 16), true},
		{"0x20 case randomization", q, answer("AbC.T.eXaMpLe.CoM", 16), true},
		{"different name", q, answer("abd.t.example.com", 16), false},
		{"different type", q, answer("abc.t.example.com", 28), false},
		{"answer without question", q, noQuestion, true},
		{"query without question", nil, answer("other.example.com", 1), true},
		{"truncated header", q, noQuestion[:6], false},
	}
	for _, c := range cases {
		if got := questionMatches(c.q, c.resp); got != c.want {
			t.Errorf("%s: questionMatches = %v, want %v", c.name, got, c.want)
		}
	}
}
