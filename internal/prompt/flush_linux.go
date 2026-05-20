//go:build linux

package prompt

import (
	"os"

	"golang.org/x/sys/unix"
)

// FlushStdin discards any pending unread bytes from stdin. Uses a non-blocking
// read loop rather than ioctl(TCFLSH) because TCFLSH counts as a terminal
// attribute change and will trigger SIGTTOU — stopping the process — when sudo's
// use_pty has not yet promoted the child to the terminal's foreground process group.
func FlushStdin() {
	fd := int(os.Stdin.Fd())

	// Claim foreground before touching the terminal (see claimTerminalForeground).
	claimTerminalForeground(fd)

	// Save current file-status flags.
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return
	}
	// Set O_NONBLOCK — fcntl(F_SETFL) is not a terminal attribute change so it
	// never triggers SIGTTOU, even from a background process group.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		return
	}
	// Drain: read until no bytes remain (EAGAIN/EWOULDBLOCK).
	var buf [4096]byte
	for {
		n, _ := unix.Read(fd, buf[:])
		if n <= 0 {
			break
		}
	}
	// Restore flags.
	_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
}
