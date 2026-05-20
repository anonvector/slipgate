package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	DefaultConfigDir  = "/etc/slipgate"
	DefaultConfigFile = "/etc/slipgate/config.json"
	DefaultTunnelDir  = "/etc/slipgate/tunnels"
	DefaultBinDir     = "/usr/local/bin"
	SystemUser        = "slipgate"
	SystemGroup       = "slipgate"
	SSHGroup          = "slipgate-ssh"
)

// WarpConfig tracks Cloudflare WARP outbound state.
type WarpConfig struct {
	Enabled bool `json:"enabled"`
	// IPv6 controls whether WARP routes IPv6 traffic. Default false (IPv4 only)
	// because many VPS providers have flaky or mis-configured IPv6, and routing
	// ::/0 through WARP can break DNS tunnels and outbound connectivity.
	IPv6 bool `json:"ipv6,omitempty"`
}

// Config is the top-level slipgate configuration.
type Config struct {
	mu       sync.RWMutex
	path     string
	Listen   ListenConfig    `json:"listen"`
	Tunnels  []TunnelConfig  `json:"tunnels"`
	Backends []BackendConfig `json:"backends"`
	Users    []UserConfig    `json:"users,omitempty"`
	Route    RouteConfig     `json:"route"`
	Warp     WarpConfig      `json:"warp,omitempty"`
}

// UserConfig tracks a managed user (same credentials for SSH + SOCKS).
type UserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ListenConfig defines the DNS listen address.
type ListenConfig struct {
	Address string `json:"address"`
}

// RouteConfig defines routing behavior.
type RouteConfig struct {
	Mode    string `json:"mode"`    // "single" or "multi"
	Active  string `json:"active"`  // active tunnel tag (single mode)
	Default string `json:"default"` // default tunnel tag (multi mode fallback)
}

// Load reads config from the default path.
func Load() (*Config, error) {
	return LoadFrom(DefaultConfigFile)
}

// LoadFrom reads config from a specific path.
func LoadFrom(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.path = path
	return &cfg, nil
}

// Save writes the config to disk.
func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	path := c.path
	if path == "" {
		path = DefaultConfigFile
	}
	return c.SaveTo(path)
}

// SaveTo writes the config to a specific path.
func (c *Config) SaveTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

// Default returns a new config with sensible defaults.
func Default() *Config {
	return &Config{
		path: DefaultConfigFile,
		Listen: ListenConfig{
			Address: "0.0.0.0:53",
		},
		Backends: []BackendConfig{
			{Tag: "socks", Type: BackendSOCKS, Address: "127.0.0.1:1080", SOCKS: &SOCKSConfig{}},
			{Tag: "ssh", Type: BackendSSH, Address: "127.0.0.1:22"},
		},
		Route: RouteConfig{
			Mode: "single",
		},
	}
}

// GetTunnel returns a tunnel by tag.
func (c *Config) GetTunnel(tag string) *TunnelConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Tunnels {
		if c.Tunnels[i].Tag == tag {
			return &c.Tunnels[i]
		}
	}
	return nil
}

// UniqueTag returns a tag that doesn't conflict with existing tunnels.
// If base is available it is returned as-is, otherwise a numeric suffix is appended.
func (c *Config) UniqueTag(base string) string {
	if c.GetTunnel(base) == nil {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if c.GetTunnel(candidate) == nil {
			return candidate
		}
	}
}

// AddTunnel adds a tunnel to the config.
func (c *Config) AddTunnel(t TunnelConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Tunnels = append(c.Tunnels, t)
}

// UpdateTunnel replaces a tunnel config by tag.
func (c *Config) UpdateTunnel(t TunnelConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Tunnels {
		if c.Tunnels[i].Tag == t.Tag {
			c.Tunnels[i] = t
			return
		}
	}
}

// RemoveTunnel removes a tunnel by tag.
func (c *Config) RemoveTunnel(tag string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Tunnels {
		if c.Tunnels[i].Tag == tag {
			c.Tunnels = append(c.Tunnels[:i], c.Tunnels[i+1:]...)
			return true
		}
	}
	return false
}

// GetBackend returns a backend by tag.
func (c *Config) GetBackend(tag string) *BackendConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Backends {
		if c.Backends[i].Tag == tag {
			return &c.Backends[i]
		}
	}
	return nil
}

// GetUser returns a user by username.
func (c *Config) GetUser(username string) *UserConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Users {
		if c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}

// AddUser adds a user to the config. If a user with the same username
// already exists, it is updated in place instead of creating a duplicate.
func (c *Config) AddUser(u UserConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Users {
		if c.Users[i].Username == u.Username {
			c.Users[i] = u
			return
		}
	}
	c.Users = append(c.Users, u)
}

// RemoveUser removes a user by username.
func (c *Config) RemoveUser(username string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Users {
		if c.Users[i].Username == username {
			c.Users = append(c.Users[:i], c.Users[i+1:]...)
			return true
		}
	}
	return false
}

// TunnelDir returns the directory for a tunnel's files.
func TunnelDir(tag string) string {
	return filepath.Join(DefaultTunnelDir, tag)
}
