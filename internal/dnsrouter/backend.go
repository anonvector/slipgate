package dnsrouter

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/anonvector/slipgate/internal/network"
)

const (
	// pendingTimeout is how long a forwarded query waits for its answer. It
	// must exceed the longest a backend holds a query (soar: 1.5 s).
	pendingTimeout = 10 * time.Second
	// udpBufferSize is the kernel buffer requested for every router UDP
	// socket, so bursts of tunnel traffic queue instead of being dropped.
	udpBufferSize = 4 << 20
)

// cleanInterval is how often cleanPending sweeps a connection. A variable so
// tests can shrink it.
var cleanInterval = 5 * time.Second

// backendConn is a persistent UDP connection to a backend (dnstt-server).
//
// A connection never sends two queries under the same server TXID, so an
// answer that arrives late (or twice) can't be taken for the answer to a
// newer query. Once all 65536 IDs are spent, the connection is retired: new
// queries go out on a fresh connection, while the retired one keeps reading
// until nothing is pending on it and is then closed.
type backendConn struct {
	conn     *net.UDPConn
	pending  sync.Map      // serverTxID (uint16) → *pendingQuery
	nextTxID atomic.Uint32 // counter for server-side TXID allocation
	retired  atomic.Bool   // replaced by a new connection; see cleanPending
}

// pendingQuery tracks a forwarded query so the response can be routed back.
// originalTxID is the client's TXID, which we restore before writing the
// response back. Multiplexing clients over a single backend UDP socket
// requires server-generated TXIDs; using the client's TXID directly would
// cause cross-client collisions (two clients easily pick the same 16-bit ID)
// and mis-deliver responses.
type pendingQuery struct {
	reply        replyFunc
	originalTxID uint16
	question     []byte // the query's question section; the answer must echo it
	timestamp    time.Time
}

// forward sends packet to the backend at addr and arranges for the answer to
// reach reply. It rewrites packet's TXID in place.
func (r *Router) forward(addr string, packet []byte, reply replyFunc) error {
	pq := &pendingQuery{
		reply:        reply,
		originalTxID: binary.BigEndian.Uint16(packet[:2]),
		question:     questionSection(packet),
		timestamp:    time.Now(),
	}
	for {
		bc, err := r.getBackend(addr)
		if err != nil {
			return err
		}
		n := bc.nextTxID.Add(1)
		if n > 1<<16 {
			// Every ID has been used on this connection.
			r.retireBackend(addr, bc)
			continue
		}
		serverTxID := uint16(n) // 1, 2, … 65535, then 0
		bc.pending.Store(serverTxID, pq)

		binary.BigEndian.PutUint16(packet[:2], serverTxID)
		if _, err := bc.conn.Write(packet); err != nil {
			bc.pending.Delete(serverTxID)
			return err
		}
		return nil
	}
}

// getBackend returns a persistent connection to the backend, creating one if needed.
func (r *Router) getBackend(addr string) (*backendConn, error) {
	r.backendsMu.Lock()
	defer r.backendsMu.Unlock()

	if bc, ok := r.backends[addr]; ok {
		return bc, nil
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	network.GrowUDPBuffers(conn, udpBufferSize)

	bc := &backendConn{conn: conn}
	r.backends[addr] = bc

	// Start response reader goroutine
	go r.readBackendResponses(bc, addr)

	// Start stale query cleanup
	go r.cleanPending(bc)

	return bc, nil
}

// retireBackend takes bc out of use; the next query to addr opens a new
// connection (and so a new source port). bc stays open for the answers to
// queries already sent on it.
func (r *Router) retireBackend(addr string, bc *backendConn) {
	r.backendsMu.Lock()
	if r.backends[addr] == bc {
		delete(r.backends, addr)
	}
	r.backendsMu.Unlock()
	bc.retired.Store(true)
}

// readBackendResponses reads responses from a backend and routes them to clients.
func (r *Router) readBackendResponses(bc *backendConn, addr string) {
	// Large enough for any DNS message, since TCP clients aren't bound by UDP sizes.
	buf := make([]byte, 65535)
	for {
		n, err := bc.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // retired and drained
			}
			// A backend that is restarting answers with ICMP port-unreachable,
			// which Linux reports as ECONNREFUSED on this connected socket. It
			// is reported once and the socket keeps working: keep reading, or
			// the route stays dead after the backend comes back.
			if !errors.Is(err, syscall.ECONNREFUSED) {
				log.Printf("read from %s: %v", addr, err)
				time.Sleep(10 * time.Millisecond) // don't spin on a persistent error
			}
			continue
		}
		if n < 2 {
			continue
		}

		serverTxID := binary.BigEndian.Uint16(buf[:2])
		val, ok := bc.pending.Load(serverTxID)
		if !ok {
			continue // no matching query (stale or duplicate)
		}
		pq := val.(*pendingQuery)
		// A packet that doesn't echo the question isn't this query's answer.
		// Leave the query pending so its real answer can still be delivered.
		if !questionMatches(pq.question, buf[:n]) || !bc.pending.CompareAndDelete(serverTxID, val) {
			continue
		}

		// Restore the client's original TXID before forwarding.
		binary.BigEndian.PutUint16(buf[:2], pq.originalTxID)
		pq.reply(buf[:n])
	}
}

// cleanPending removes stale pending queries every cleanInterval. When bc
// has been retired and nothing is left pending, it closes bc, which also
// stops readBackendResponses.
func (r *Router) cleanPending(bc *backendConn) {
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()
	// A query can still be storing its TXID at the moment bc is retired, so
	// closing waits for one sweep after the retirement was first seen.
	sawRetired := false
	for range ticker.C {
		now := time.Now()
		drained := true
		bc.pending.Range(func(key, value any) bool {
			pq := value.(*pendingQuery)
			if now.Sub(pq.timestamp) > pendingTimeout {
				bc.pending.Delete(key)
			} else {
				drained = false
			}
			return true
		})
		if !bc.retired.Load() {
			continue
		}
		if sawRetired && drained {
			bc.conn.Close()
			return
		}
		sawRetired = true
	}
}

// questionSection returns msg's question (name, type, class) when it has
// exactly one, or nil.
func questionSection(msg []byte) []byte {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return nil
	}
	off := 12
	for {
		if off >= len(msg) {
			return nil
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 { // compression pointer or reserved: not in a question
			return nil
		}
		off += 1 + l
	}
	if off+4 > len(msg) {
		return nil
	}
	return msg[12 : off+4]
}

// questionMatches reports whether resp answers the query whose question
// section is q. Names compare case-insensitively, since resolvers randomize
// case (DNS 0x20); type and class compare exactly. A query without a single
// question, or a response without one (e.g. FORMERR), can't be compared and
// matches on TXID alone, which is unique on its connection.
func questionMatches(q, resp []byte) bool {
	if len(resp) < 12 {
		return false
	}
	if q == nil || binary.BigEndian.Uint16(resp[4:6]) == 0 {
		return true
	}
	rq := questionSection(resp)
	if len(rq) != len(q) {
		return false
	}
	name := len(q) - 4
	for i := range name {
		if lowerASCII(q[i]) != lowerASCII(rq[i]) {
			return false
		}
	}
	return string(q[name:]) == string(rq[name:])
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
