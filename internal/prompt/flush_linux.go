//go:build linux

package prompt

import (
	"os"

	"golang.org/x/sys/unix"
)

// FlushStdin discards any pending unread bytes from stdin. Call this before
// prompting the user after a long non-interactive step (e.g. binary download)
// so that keystrokes typed during the wait don't silently answer the next prompt.
func FlushStdin() {
	fd := int(os.Stdin.Fd())
	// TCFLSH / TCIFLUSH: discard received data not yet read by the application.
	unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) //nolint:errcheck
}
