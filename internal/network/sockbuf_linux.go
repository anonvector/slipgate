//go:build linux

package network

import (
	"net"
	"syscall"
)

// GrowUDPBuffers sets conn's kernel receive and send buffers to size bytes,
// so bursts of DNS tunnel traffic queue instead of being dropped. A plain
// SO_RCVBUF request is silently capped at net.core.rmem_max (often ~208 KB);
// as root (CAP_NET_ADMIN) the *FORCE variants bypass that cap. Without the
// capability it falls back to the capped request. Best effort: errors are
// ignored and the socket keeps working either way.
func GrowUDPBuffers(conn *net.UDPConn, size int) {
	var rerr, werr error
	if raw, err := conn.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			rerr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, size)
			werr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, size)
		})
	} else {
		rerr, werr = err, err
	}
	if rerr != nil {
		conn.SetReadBuffer(size)
	}
	if werr != nil {
		conn.SetWriteBuffer(size)
	}
}
