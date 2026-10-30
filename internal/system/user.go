package system

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"

	"github.com/anonvector/slipgate/internal/config"
)

// EnsureUser creates the slipgate system user and groups if they don't exist.
func EnsureUser() error {
	// Create group
	if !groupExists(config.SystemGroup) {
		if err := run("groupadd", "--system", config.SystemGroup); err != nil {
			return fmt.Errorf("create group %s: %w", config.SystemGroup, err)
		}
	}

	// Create SSH group
	if !groupExists(config.SSHGroup) {
		if err := run("groupadd", "--system", config.SSHGroup); err != nil {
			return fmt.Errorf("create group %s: %w", config.SSHGroup, err)
		}
	}

	// Create user
	if !userExists(config.SystemUser) {
		if err := run("useradd", "--system", "--no-create-home",
			"--shell", "/usr/sbin/nologin",
			"--gid", config.SystemGroup,
			config.SystemUser); err != nil {
			return fmt.Errorf("create user %s: %w", config.SystemUser, err)
		}
	}

	return nil
}

// RemoveUser removes the slipgate system user and groups.
func RemoveUser() error {
	_ = run("userdel", config.SystemUser)
	_ = run("groupdel", config.SSHGroup)
	_ = run("groupdel", config.SystemGroup)
	return nil
}

// RemoveSpecificUser removes a system user by name.
func RemoveSpecificUser(username string) error {
	return run("userdel", username)
}

// EnsureDir creates a directory owned by the slipgate user.
func EnsureDir(path, owner string) error {
	if err := os.MkdirAll(path, 0750); err != nil {
		return err
	}
	return run("chown", "-R", owner+":"+config.SystemGroup, path)
}

// AddSSHUser creates a system user in the slipgate-ssh group.
// If the user already exists, it updates the password instead.
func AddSSHUser(username, password string) error {
	// Ensure SSH group exists
	if !groupExists(config.SSHGroup) {
		if err := run("groupadd", "--system", config.SSHGroup); err != nil {
			return fmt.Errorf("create group %s: %w", config.SSHGroup, err)
		}
	}

	if !userExists(username) {
		if err := run("useradd", "--system", "--no-create-home",
			"--shell", "/bin/false",
			"--gid", config.SSHGroup,
			username); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
	}

	// Set password
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("set password: %w", err)
	}

	// Ensure sshd Match Group config
	return ensureSSHMatchGroup()
}

// RemoveSSHUser kills active sessions and removes a user from the system.
func RemoveSSHUser(username string) error {
	// SIGKILL all processes owned by the user so userdel isn't blocked by a
	// live SSH session. pkill returns before the kernel reaps the processes,
	// so userdel -f forces removal even if a process is briefly still listed.
	_ = run("pkill", "-KILL", "-u", username)
	return run("userdel", "-f", username)
}

// ListSSHUsers returns all users in the slipgate-ssh group.
func ListSSHUsers() ([]string, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[0] == config.SSHGroup {
			if parts[3] == "" {
				return nil, nil
			}
			return strings.Split(parts[3], ","), nil
		}
	}
	return nil, nil
}

// GeneratePassword generates a random alphanumeric password.
func GeneratePassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

const sshGlobalSettings = `
# SlipGate global SSH settings
MaxStartups 100:30:300
MaxSessions 100
TCPKeepAlive no
`

// sshMatchBlock configures the tunnel users. They log in with passwords,
// which many images turn off globally (e.g. cloud-init's
// PasswordAuthentication no, or AuthenticationMethods publickey), so the
// block turns them back on for this group alone; other accounts keep the
// server's own rules.
const sshMatchBlock = `
# SlipGate SSH tunnel users
Match Group slipgate-ssh
    PasswordAuthentication yes
    AuthenticationMethods any
    AllowTcpForwarding yes
    X11Forwarding no
    AllowAgentForwarding no
    ForceCommand /bin/false
    ClientAliveInterval 30
    ClientAliveCountMax 10
`

// EnsureSSHConfig brings sshd_config's SlipGate settings up to date, e.g.
// after an update changes them.
func EnsureSSHConfig() error {
	return ensureSSHMatchGroup()
}

// withSlipgateSSHConfig returns sshd_config content with SlipGate's global
// settings and its current Match block.
func withSlipgateSSHConfig(content string) string {
	// Global settings must come before any Match block
	if !strings.Contains(content, "# SlipGate global SSH settings") {
		// Insert before the first Match block or SlipGate block, or append
		if idx := strings.Index(content, "# SlipGate SSH tunnel users"); idx >= 0 {
			content = content[:idx] + sshGlobalSettings + "\n" + content[idx:]
		} else if idx := strings.Index(content, "\nMatch "); idx >= 0 {
			content = content[:idx] + sshGlobalSettings + content[idx:]
		} else {
			content += sshGlobalSettings
		}
	}

	if strings.Contains(content, sshMatchBlock) {
		return content // already up to date
	}
	// Replace an older SlipGate block, which is always last in the file
	if idx := strings.Index(content, "# SlipGate SSH tunnel users"); idx >= 0 {
		content = strings.TrimRight(content[:idx], "\n") + "\n"
	} else if strings.Contains(content, "Match Group slipgate-ssh") {
		return content // a block we didn't write: can't safely replace it
	}
	return content + sshMatchBlock
}

func ensureSSHMatchGroup() error {
	const path = "/etc/ssh/sshd_config"
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := withSlipgateSSHConfig(string(data))
	if content == string(data) {
		return nil
	}

	// Validate before replacing the live config: an sshd_config that fails
	// to parse stops sshd from starting and locks out the server.
	tmp := path + ".slipgate-new"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return err
	}
	if err := run("sshd", "-t", "-f", tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("sshd config validation failed: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}

	// Try reload first, fall back to restart (needed on Ubuntu 24.04+ with socket activation)
	for _, svc := range []string{"sshd", "ssh"} {
		if exec.Command("systemctl", "is-active", svc+".service").Run() == nil {
			if err := run("systemctl", "reload", svc); err == nil {
				return nil
			}
			return run("systemctl", "restart", svc)
		}
	}
	return nil
}

// UserExists reports whether a system account with this name exists.
func UserExists(name string) bool {
	return userExists(name)
}

// IsSSHUser reports whether name is an account in the slipgate-ssh group.
// AddSSHUser makes that group the primary one, which /etc/group's member
// list doesn't show, so this asks id instead.
func IsSSHUser(name string) bool {
	out, err := exec.Command("id", "-Gn", name).Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == config.SSHGroup {
			return true
		}
	}
	return false
}

func userExists(name string) bool {
	err := exec.Command("id", name).Run()
	return err == nil
}

func groupExists(name string) bool {
	err := exec.Command("getent", "group", name).Run()
	return err == nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(output)))
	}
	return nil
}
