package prompt

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
)

// String asks for a string value with line editing support.
func String(label, defaultVal string) (string, error) {
	var prompt string
	if defaultVal != "" {
		prompt = fmt.Sprintf("  %s [%s]: ", label, defaultVal)
	} else {
		prompt = fmt.Sprintf("  %s: ", label)
	}

	line, err := readLine(prompt)
	if err != nil {
		return "", err
	}
	line = sanitize(strings.TrimSpace(line))
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}

// Lines reads pasted multi-line text from the terminal up to and including
// the first line that contains end, or until EOF (Ctrl-D). Unlike String it
// leaves the terminal in line mode, so a long paste isn't redrawn key by key.
func Lines(end string) (string, error) {
	var in io.Reader = os.Stdin
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		in = tty
	}
	r := bufio.NewReader(in)
	var text strings.Builder
	for {
		line, err := r.ReadString('\n')
		text.WriteString(line)
		if strings.Contains(line, end) || err == io.EOF {
			return text.String(), nil
		}
		if err != nil {
			return "", err
		}
	}
}

// sanitize strips non-printable and non-ASCII bytes from input.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7F {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Select asks user to choose from a list.
func Select(label string, options []actions.SelectOption) (string, error) {
	fmt.Printf("\n  %s:\n", label)
	for i, opt := range options {
		fmt.Printf("    %d) %s\n", i+1, opt.Label)
	}

	defaultLabel := ""
	if len(options) > 0 {
		defaultLabel = options[0].Label
	}
	line, err := readLine(fmt.Sprintf("  Choice [%s]: ", defaultLabel))
	if err != nil {
		return "", err
	}
	line = sanitize(strings.TrimSpace(line))

	if line == "" && len(options) > 0 {
		return options[0].Value, nil
	}

	if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(options) {
		return options[n-1].Value, nil
	}

	for _, opt := range options {
		if strings.EqualFold(line, opt.Value) {
			return opt.Value, nil
		}
	}

	return "", fmt.Errorf("invalid choice: %s", line)
}

// MultiSelect asks user to select multiple options.
func MultiSelect(label string, options []actions.SelectOption) ([]string, error) {
	fmt.Printf("\n  %s:\n", label)
	for i, opt := range options {
		fmt.Printf("    %d) %s\n", i+1, opt.Label)
	}
	fmt.Printf("    %d) All\n", len(options)+1)

	line, err := readLine("  Choice (comma-separated, e.g. 1,3,4): ")
	if err != nil {
		return nil, err
	}
	line = sanitize(strings.TrimSpace(line))

	allIdx := len(options) + 1
	seen := make(map[string]bool)
	var result []string

	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		if strings.EqualFold(part, "all") {
			var all []string
			for _, opt := range options {
				all = append(all, opt.Value)
			}
			return all, nil
		}
		if n, err := strconv.Atoi(part); err == nil {
			if n == allIdx {
				var all []string
				for _, opt := range options {
					all = append(all, opt.Value)
				}
				return all, nil
			}
			if n >= 1 && n <= len(options) && !seen[options[n-1].Value] {
				seen[options[n-1].Value] = true
				result = append(result, options[n-1].Value)
			}
		}
	}

	return result, nil
}

// Confirm asks a yes/no question (default: no).
func Confirm(message string) (bool, error) {
	line, err := readLine(fmt.Sprintf("  %s [y/N]: ", message))
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

// ConfirmYes asks a yes/no question (default: yes).
func ConfirmYes(message string) (bool, error) {
	line, err := readLine(fmt.Sprintf("  %s [Y/n]: ", message))
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return true, nil
	}
	return line != "n" && line != "no", nil
}

// readSimple is a fallback line reader for non-terminal input.
func readSimple() (string, error) {
	var buf [4096]byte
	n, err := os.Stdin.Read(buf[:])
	if err != nil {
		return "", err
	}
	return sanitize(strings.TrimRight(string(buf[:n]), "\r\n")), nil
}

// CollectInputs collects all required inputs for an action.
func CollectInputs(a *actions.Action, existing map[string]string) (map[string]string, error) {
	result := make(map[string]string)
	for k, v := range existing {
		result[k] = v
	}

	for _, input := range a.Inputs {
		if result[input.Key] != "" {
			continue
		}

		if input.CLIOnly {
			continue
		}

		if input.DependsOn != "" {
			depVal := result[input.DependsOn]
			if depVal == "" {
				continue
			}
			if len(input.DependsOnValues) > 0 {
				match := false
				for _, v := range input.DependsOnValues {
					if v == depVal {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
		}

		if len(input.Options) > 0 {
			val, err := Select(input.Label, input.Options)
			if err != nil {
				return nil, err
			}
			result[input.Key] = val
		} else {
			val, err := String(input.Label, input.Default)
			if err != nil {
				return nil, err
			}
			if input.Required && val == "" {
				return nil, fmt.Errorf("%s is required", input.Label)
			}
			result[input.Key] = val
		}
	}

	return result, nil
}
