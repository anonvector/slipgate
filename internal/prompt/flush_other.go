//go:build !linux

package prompt

// FlushStdin is a no-op on non-Linux platforms.
func FlushStdin() {}
