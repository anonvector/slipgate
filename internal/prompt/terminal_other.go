//go:build !linux

package prompt

func claimTerminalForeground(fd int) {}
