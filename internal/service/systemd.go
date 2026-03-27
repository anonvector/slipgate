package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const systemdDir = "/etc/systemd/system"

// TunnelServiceName returns the systemd service name for a tunnel.
func TunnelServiceName(tag string) string {
	return "slipgate-" + tag
}

// Unit represents a systemd unit file.
type Unit struct {
	Name        string
	Description string
	ExecStart   string
	User        string
	Group       string
	After       string
	Restart     string
	WorkingDir  string
	Environment []string
}

// Create writes a systemd unit file and reloads the daemon.
func Create(u *Unit) error {
	content := fmt.Sprintf(`[Unit]
Description=%s
After=%s
StartLimitIntervalSec=300
StartLimitBurst=15

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s
Restart=%s
RestartSec=5
LogRateLimitIntervalSec=30
LogRateLimitBurst=100
`, u.Description, u.After, u.User, u.Group, u.ExecStart, u.Restart)

	if u.WorkingDir != "" {
		content += fmt.Sprintf("WorkingDirectory=%s\n", u.WorkingDir)
	}
	for _, env := range u.Environment {
		content += fmt.Sprintf("Environment=%s\n", env)
	}

	content += "\n[Install]\nWantedBy=multi-user.target\n"

	path := filepath.Join(systemdDir, u.Name+".service")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	return daemonReload()
}

// Start enables and starts a service.
func Start(name string) error {
	if err := run("systemctl", "enable", name+".service"); err != nil {
		return err
	}
	return run("systemctl", "start", name+".service")
}

// Stop stops and disables a service. Silently skips if the service doesn't exist.
func Stop(name string) error {
	if !Exists(name) {
		return nil
	}
	_ = runQuiet("systemctl", "stop", name+".service")
	_ = runQuiet("systemctl", "disable", name+".service")
	return nil
}

// Restart restarts a service.
func Restart(name string) error {
	return run("systemctl", "restart", name+".service")
}

// Status returns the active state of a service.
func Status(name string) (string, error) {
	out, err := exec.Command("systemctl", "is-active", name+".service").Output()
	if err != nil {
		return strings.TrimSpace(string(out)), err
	}
	return strings.TrimSpace(string(out)), nil
}

// Logs returns recent log lines for a service.
func Logs(name string, lines string) (string, error) {
	out, err := exec.Command("journalctl", "-u", name+".service", "-n", lines, "--no-pager").Output()
	if err != nil {
		return "", fmt.Errorf("journalctl: %w", err)
	}
	return string(out), nil
}

// Remove removes a service unit file. Silently skips if it doesn't exist.
func Remove(name string) error {
	path := filepath.Join(systemdDir, name+".service")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return daemonReload()
}

func daemonReload() error {
	return run("systemctl", "daemon-reload")
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runQuiet runs a command suppressing all output.
func runQuiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// Exists checks if a systemd unit file exists.
func Exists(name string) bool {
	path := filepath.Join(systemdDir, name+".service")
	_, err := os.Stat(path)
	return err == nil
}
