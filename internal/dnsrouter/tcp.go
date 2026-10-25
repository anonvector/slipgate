package dnsrouter

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// tcpIdleTimeout closes connections that send no query for this long.
	tcpIdleTimeout = 2 * time.Minute
	// tcpWriteTimeout bounds how long a stalled client can hold a write.
	tcpWriteTimeout = 10 * time.Second
	// tcpMaxConns caps concurrent TCP connections; extras are closed at once.
	tcpMaxConns = 1024
)

// tcpWriteQueue is how many responses may wait for one connection's writer
// before the connection is closed. A variable so tests can shrink it.
var tcpWriteQueue = 256

// serveTCP accepts DNS-over-TCP connections (RFC 7766). Queries are forwarded
// to backends over the same UDP sockets as UDP queries, so tunnel servers only
// ever see UDP; DNS messages and size limits are the same on either transport.
func (r *Router) serveTCP(ln net.Listener) {
	defer ln.Close()
	slots := make(chan struct{}, tcpMaxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("tcp accept: %v", err)
			time.Sleep(50 * time.Millisecond) // e.g. out of file descriptors
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			r.handleTCPConn(conn)
		}()
	}
}

// handleTCPConn reads length-prefixed queries until the client closes or goes
// idle. Queries may be pipelined and answers return in any order (RFC 7766),
// matched by the client on TXID.
func (r *Router) handleTCPConn(conn net.Conn) {
	defer conn.Close()

	// Responses arrive on backend reader goroutines shared by all clients. A
	// per-connection writer keeps one slow client from stalling them.
	out := make(chan []byte, tcpWriteQueue)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case msg := <-out:
				conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
				if _, err := conn.Write(msg); err != nil {
					abort(conn) // unblocks the reader below
					return
				}
			}
		}
	}()
	from := conn.RemoteAddr()
	var overflow sync.Once
	reply := func(msg []byte) {
		select {
		case <-done:
			return // connection finished; a late answer has nowhere to go
		default:
		}
		if len(msg) > 0xFFFF {
			return
		}
		framed := make([]byte, 2, 2+len(msg))
		binary.BigEndian.PutUint16(framed, uint16(len(msg)))
		framed = append(framed, msg...)
		select {
		case out <- framed:
		default:
			// The client has stopped reading. Over TCP it expects every
			// answer, so dropping some would leave each of those queries to
			// time out; closing fails them all at once and the client retries
			// on a new connection (RFC 7766), or on other paths (soar).
			overflow.Do(func() {
				log.Printf("tcp %s: client not reading, %d answers queued; resetting", from, tcpWriteQueue)
				abort(conn)
			})
		}
	}

	var hdr [2]byte
	for {
		conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n < 12 { // shorter than a DNS header: not a DNS client
			return
		}
		packet := make([]byte, n)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}
		r.handleQuery(packet, from, reply)
	}
}

// abort resets conn instead of closing it gracefully. A graceful close of a
// client that has stopped reading leaves the kernel holding the unsent answers
// (up to the whole send buffer) and retrying for minutes; a reset frees them
// at once and tells the client immediately.
func abort(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	conn.Close()
}
