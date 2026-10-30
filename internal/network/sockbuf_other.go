//go:build !linux

package network

import "net"

// GrowUDPBuffers sets conn's kernel receive and send buffers to size bytes,
// as far as the OS allows. Best effort: errors are ignored.
func GrowUDPBuffers(conn *net.UDPConn, size int) {
	conn.SetReadBuffer(size)
	conn.SetWriteBuffer(size)
}
