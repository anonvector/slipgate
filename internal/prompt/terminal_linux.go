//go:build linux

package prompt

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// claimTerminalForeground sets the calling process's process group as the
// foreground group of the terminal at fd (tcsetpgrp). Required under sudo's
// use_pty (default on Ubuntu 22.04+): sudo creates a new session for the child
// but does not always call tcsetpgrp before the child runs. With SIGTTOU
// already ignored (see init), this succeeds from a background pgrp without
// stopping. Errors are silently ignored — the worst case is that the subsequent
// MakeRaw or read fails and the caller gets an EIO it can report.
func claimTerminalForeground(fd int) {
	pgid, err := syscall.Getpgid(0)
	if err != nil {
		return
	}
	// TIOCSPGRP requires a pointer to pid_t (int32 on Linux), not the value.
	pgid32 := int32(pgid)
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TIOCSPGRP), uintptr(unsafe.Pointer(&pgid32)))
}
