package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
)

var reader = bufio.NewReader(os.Stdin)

// String asks for a string value.
func String(label, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("  %s: ", label)
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = sanitize(strings.TrimSpace(line))
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
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
	fmt.Print("  Choice: ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)

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
	fmt.Print("  Choice: ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)

	allIdx := fmt.Sprintf("%d", len(options)+1)
	if strings.EqualFold(line, "all") || line == allIdx {
		var result []string
		for _, opt := range options {
			result = append(result, opt.Value)
		}
		return result, nil
	}

	var result []string
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		if n, err := strconv.Atoi(part); err == nil && n >= 1 && n <= len(options) {
			result = append(result, options[n-1].Value)
		}
	}

	return result, nil
}

// Confirm asks a yes/no question (default: no).
func Confirm(message string) (bool, error) {
	fmt.Printf("  %s [y/N]: ", message)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

// ConfirmYes asks a yes/no question (default: yes).
func ConfirmYes(message string) (bool, error) {
	fmt.Printf("  %s [Y/n]: ", message)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return true, nil
	}
	return line != "n" && line != "no", nil
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

		if input.DependsOn != "" && result[input.DependsOn] == "" {
			continue
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
