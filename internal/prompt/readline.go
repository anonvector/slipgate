package prompt

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/term"
)

// rawMu guards the saved terminal state so the SIGINT handler can restore it.
var (
	rawMu    sync.Mutex
	rawFD    = -1
	rawState *term.State
)

func setRaw(fd int, state *term.State) {
	rawMu.Lock()
	rawFD, rawState = fd, state
	rawMu.Unlock()
}

func clearRaw() {
	rawMu.Lock()
	rawFD, rawState = -1, nil
	rawMu.Unlock()
}

func init() {
	// Ignore SIGTTOU and SIGTTIN so the process is never stopped by background
	// terminal-I/O signals. sudo's use_pty (default on Ubuntu 22.04+) creates a
	// new session for the child and may not promote it to the terminal's foreground
	// process group before it performs terminal control operations (tcsetattr,
	// tcflush). Without this, the process silently enters T (stopped) state before
	// printing a single character.
	signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		rawMu.Lock()
		fd, state := rawFD, rawState
		rawMu.Unlock()
		if state != nil && fd >= 0 {
			term.Restore(fd, state)
		}
		os.Exit(130)
	}()
}

// readLine reads a line with arrow keys, home/end, delete, backspace support.
// prompt is printed first and used to calculate redraw positions.
func readLine(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		fmt.Print(prompt)
		return readSimple()
	}

	// Claim the terminal foreground before any attribute changes.
	// Under sudo use_pty the child may not be promoted yet; with SIGTTOU
	// ignored this always succeeds (see claimTerminalForeground).
	claimTerminalForeground(fd)

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Print(prompt)
		return readSimple()
	}
	setRaw(fd, oldState)
	defer func() {
		clearRaw()
		term.Restore(fd, oldState)
	}()

	// Print prompt
	writeStr(prompt)

	var buf []byte
	pos := 0

	for {
		b, err := readByte()
		if err != nil {
			return "", err
		}

		switch b {
		case '\r', '\n':
			writeStr("\r\n")
			return string(buf), nil

		case 3: // Ctrl-C
			writeStr("\r\n")
			return "", fmt.Errorf("interrupted")

		case 4: // Ctrl-D
			if len(buf) == 0 {
				writeStr("\r\n")
				return "", fmt.Errorf("interrupted")
			}

		case 127, 8: // Backspace
			if pos > 0 {
				buf = append(buf[:pos-1], buf[pos:]...)
				pos--
				refreshLine(prompt, buf, pos)
			}

		case 27: // ESC sequence
			seq0, _ := readByte()
			if seq0 != '[' {
				continue
			}
			seq1, _ := readByte()
			switch seq1 {
			case 'D': // Left
				if pos > 0 {
					pos--
					writeStr("\033[D")
				}
			case 'C': // Right
				if pos < len(buf) {
					pos++
					writeStr("\033[C")
				}
			case 'H': // Home
				pos = 0
				setCursorCol(len(prompt) + 1)
			case 'F': // End
				pos = len(buf)
				setCursorCol(len(prompt) + len(buf) + 1)
			case '3': // Delete (ESC [ 3 ~)
				readByte() // consume ~
				if pos < len(buf) {
					buf = append(buf[:pos], buf[pos+1:]...)
					refreshLine(prompt, buf, pos)
				}
			case '1': // Home alt (ESC [ 1 ~)
				readByte() // consume ~
				pos = 0
				setCursorCol(len(prompt) + 1)
			case '4': // End alt (ESC [ 4 ~)
				readByte() // consume ~
				pos = len(buf)
				setCursorCol(len(prompt) + len(buf) + 1)
			default:
				// Consume the remainder of any unrecognised CSI sequence
				// (e.g. Kitty keyboard protocol "\x1b[99;1u" for Ctrl+C).
				// CSI parameter bytes are 0x30-0x3F; the final byte is 0x40-0x7E.
				if seq1 < 0x40 {
					for {
						b, err := readByte()
						if err != nil {
							return "", err
						}
						if b >= 0x40 && b <= 0x7E {
							break
						}
					}
				}
			}

		case 1: // Ctrl-A (Home)
			pos = 0
			setCursorCol(len(prompt) + 1)

		case 5: // Ctrl-E (End)
			pos = len(buf)
			setCursorCol(len(prompt) + len(buf) + 1)

		case 21: // Ctrl-U (clear to start)
			buf = buf[pos:]
			pos = 0
			refreshLine(prompt, buf, pos)

		case 11: // Ctrl-K (clear to end)
			buf = buf[:pos]
			refreshLine(prompt, buf, pos)

		default:
			if b >= 0x20 && b < 0x7F {
				buf = append(buf, 0)
				copy(buf[pos+1:], buf[pos:])
				buf[pos] = b
				pos++
				if pos == len(buf) {
					// Appending at end — just echo the character
					os.Stdout.Write([]byte{b})
				} else {
					refreshLine(prompt, buf, pos)
				}
			}
		}
	}
}

// refreshLine redraws the prompt + buffer and places cursor at pos.
func refreshLine(prompt string, buf []byte, pos int) {
	// Move to column 1, reprint prompt + buffer, clear remainder, reposition cursor
	writeStr("\r")                // go to column 1
	writeStr(prompt)              // reprint prompt
	os.Stdout.Write(buf)          // print buffer
	writeStr("\033[K")            // clear to end of line
	setCursorCol(len(prompt) + pos + 1) // position cursor
}

// setCursorCol moves the cursor to an absolute column (1-based).
func setCursorCol(col int) {
	writeStr(fmt.Sprintf("\033[%dG", col))
}

func writeStr(s string) {
	os.Stdout.WriteString(s)
}

func readByte() (byte, error) {
	var b [1]byte
	for {
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return b[0], nil
		}
	}
}
