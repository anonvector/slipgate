package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	tagRegex      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	usernameRegex = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$`)
	domainRegex   = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$`)
	hexKeyRegex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	portListRegex = regexp.MustCompile(`^[0-9]{1,5}(,[0-9]{1,5})*$`)
)

// Validate checks the entire config for errors.
func (c *Config) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tags := make(map[string]bool)
	domains := make(map[string]bool)

	for _, t := range c.Tunnels {
		if err := validateTag(t.Tag); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}
		if tags[t.Tag] {
			return fmt.Errorf("duplicate tunnel tag: %s", t.Tag)
		}
		tags[t.Tag] = true

		if t.Domain == "" && t.Transport != TransportSSH && t.Transport != TransportSOCKS && t.Transport != TransportStunTLS {
			return fmt.Errorf("tunnel %q: domain is required", t.Tag)
		}
		// Same rule as ValidateNewTunnel: a domain may be shared by tunnels
		// with different backends (e.g. naive-socks and naive-ssh).
		if t.Domain != "" {
			key := t.Domain + "|" + t.Backend
			if domains[key] {
				return fmt.Errorf("duplicate domain %s for backend %s", t.Domain, t.Backend)
			}
			domains[key] = true
		}

		if err := validateTransport(t.Transport); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}

		if err := validateBackend(t.Backend); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}

		if err := validateTransportBackend(t.Transport, t.Backend); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}
	}

	if c.Route.Mode != "" && c.Route.Mode != "single" && c.Route.Mode != "multi" {
		return fmt.Errorf("invalid route mode: %s", c.Route.Mode)
	}

	return nil
}

// ValidateNewTunnel checks a tunnel against the existing config.
func (c *Config) ValidateNewTunnel(t *TunnelConfig) error {
	if err := validateTag(t.Tag); err != nil {
		return err
	}
	if c.GetTunnel(t.Tag) != nil {
		return fmt.Errorf("tunnel tag %q already exists", t.Tag)
	}
	if t.Domain == "" && t.Transport != TransportSSH && t.Transport != TransportSOCKS && t.Transport != TransportStunTLS {
		return fmt.Errorf("domain is required")
	}
	c.mu.RLock()
	for _, existing := range c.Tunnels {
		if t.Domain != "" && existing.Domain == t.Domain && existing.Backend == t.Backend {
			c.mu.RUnlock()
			return fmt.Errorf("domain %q with backend %q already in use by tunnel %q", t.Domain, t.Backend, existing.Tag)
		}
	}
	c.mu.RUnlock()
	return validateTransportBackend(t.Transport, t.Backend)
}

// ValidateTagName checks if a tag name is valid.
func ValidateTagName(tag string) error {
	return validateTag(tag)
}

// ValidatePassword rejects characters that can't round-trip through every
// place slipgate serializes a password: `chpasswd` stdin (`user:pass` lines,
// so ':' splits and '\n' terminates), and the SOCKS5 creds file (same
// `user:pass\n` framing). Also rejects control characters, which are
// generally unsafe in shadow-file passwords.
func ValidatePassword(p string) error {
	if p == "" {
		return fmt.Errorf("password cannot be empty")
	}
	for i, r := range p {
		if r == ':' {
			return fmt.Errorf("password cannot contain ':' (position %d)", i)
		}
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("password cannot contain control characters (position %d)", i)
		}
	}
	return nil
}

// ValidateUsername checks that name is usable as a Linux account name and
// can't be taken for a command-line option.
func ValidateUsername(name string) error {
	if !usernameRegex.MatchString(name) || strings.Trim(name, "0123456789") == "" {
		return fmt.Errorf("invalid username %q: use letters, digits, '.', '_' and '-' (max 32, not starting with '.' or '-', not all digits)", name)
	}
	return nil
}

// RemoveInvalidUsers drops the users ValidateImported would reject (bad or
// duplicate name, or a password that can't be set safely) and describes each
// one dropped, so a restore can skip them instead of refusing the backup.
func (c *Config) RemoveInvalidUsers() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var dropped []string
	seen := make(map[string]bool)
	kept := c.Users[:0]
	for _, u := range c.Users {
		err := ValidateUsername(u.Username)
		if err == nil && seen[u.Username] {
			err = fmt.Errorf("duplicate user %q", u.Username)
		}
		if err == nil {
			if perr := ValidatePassword(u.Password); perr != nil {
				err = fmt.Errorf("user %q: %w", u.Username, perr)
			}
		}
		if err != nil {
			dropped = append(dropped, err.Error())
			continue
		}
		seen[u.Username] = true
		kept = append(kept, u)
	}
	c.Users = kept
	return dropped
}

// ValidateImported checks a config that comes from outside this server, such
// as a backup being restored, before any of it is used. On top of Validate it
// requires each value to have the form slipgate itself writes: these values
// end up in systemd unit lines, the NaiveProxy Caddyfile, useradd and
// chpasswd, where a crafted one could run commands or take over an account.
// Key and certificate paths are not checked here; the caller decides where
// those files go.
func (c *Config) ValidateImported() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := rejectControlChars(c); err != nil {
		return err
	}

	if c.Listen.Address != "" {
		if err := validateAddr(c.Listen.Address); err != nil {
			return fmt.Errorf("listen address: %w", err)
		}
	}
	for _, b := range c.Backends {
		if err := validateTag(b.Tag); err != nil {
			return fmt.Errorf("backend %q: %w", b.Tag, err)
		}
		if b.Type != BackendSOCKS && b.Type != BackendSSH {
			return fmt.Errorf("backend %q: unknown type %q", b.Tag, b.Type)
		}
		if err := validateAddr(b.Address); err != nil {
			return fmt.Errorf("backend %q: %w", b.Tag, err)
		}
		if s := b.SOCKS; s != nil && s.Password != "" {
			if err := ValidatePassword(s.Password); err != nil {
				return fmt.Errorf("backend %q: %w", b.Tag, err)
			}
		}
	}

	for i := range c.Tunnels {
		if err := c.Tunnels[i].validateImported(); err != nil {
			return fmt.Errorf("tunnel %q: %w", c.Tunnels[i].Tag, err)
		}
	}

	seen := make(map[string]bool)
	for _, u := range c.Users {
		if err := ValidateUsername(u.Username); err != nil {
			return err
		}
		if seen[u.Username] {
			return fmt.Errorf("duplicate user %q", u.Username)
		}
		seen[u.Username] = true
		if err := ValidatePassword(u.Password); err != nil {
			return fmt.Errorf("user %q: %w", u.Username, err)
		}
	}
	return nil
}

func (t *TunnelConfig) validateImported() error {
	if t.Domain != "" && !domainRegex.MatchString(t.Domain) {
		return fmt.Errorf("invalid domain %q", t.Domain)
	}
	if err := validatePort(t.Port); err != nil {
		return err
	}

	missing := func() error { return fmt.Errorf("missing %s settings", t.Transport) }
	switch t.Transport {
	case TransportDNSTT:
		if t.DNSTT == nil {
			return missing()
		}
	case TransportVayDNS:
		if t.VayDNS == nil {
			return missing()
		}
	case TransportSlipstream:
		if t.Slipstream == nil {
			return missing()
		}
	case TransportSoar:
		if t.Soar == nil {
			return missing()
		}
	case TransportNaive:
		if t.Naive == nil {
			return missing()
		}
	case TransportStunTLS:
		if t.StunTLS == nil {
			return missing()
		}
	}

	if d := t.DNSTT; d != nil && d.PublicKey != "" && !hexKeyRegex.MatchString(d.PublicKey) {
		return fmt.Errorf("invalid dnstt public key")
	}
	if v := t.VayDNS; v != nil {
		if v.PublicKey != "" && !hexKeyRegex.MatchString(v.PublicKey) {
			return fmt.Errorf("invalid vaydns public key")
		}
		if v.RecordType != "" && !slices.Contains(ValidVayDNSRecordTypes, v.RecordType) {
			return fmt.Errorf("invalid vaydns record type %q", v.RecordType)
		}
		if v.QueueOverflow != "" && v.QueueOverflow != "drop" && v.QueueOverflow != "block" {
			return fmt.Errorf("invalid vaydns queue overflow %q", v.QueueOverflow)
		}
		for _, d := range []string{v.IdleTimeout, v.KeepAlive} {
			if _, err := time.ParseDuration(d); d != "" && err != nil {
				return fmt.Errorf("invalid vaydns duration %q", d)
			}
		}
		if v.Fallback != "" {
			if err := validateAddr(v.Fallback); err != nil {
				return fmt.Errorf("vaydns fallback: %w", err)
			}
		}
	}
	if s := t.Soar; s != nil {
		if s.PublicKey != "" {
			if key, err := base64.StdEncoding.DecodeString(s.PublicKey); err != nil || len(key) != 32 {
				return fmt.Errorf("invalid soar public key")
			}
		}
		if p := s.ResolvedAllowPorts(); p != "any" && !portListRegex.MatchString(p) {
			return fmt.Errorf("invalid soar allow-ports %q", s.AllowPorts)
		}
	}
	if n := t.Naive; n != nil {
		if err := validatePort(n.Port); err != nil {
			return err
		}
		// Each of these is one token on a Caddyfile line.
		for _, v := range []string{n.Email, n.Password} {
			if v != "" && !isCaddyToken(v) {
				return fmt.Errorf("naive settings contain characters a Caddyfile can't hold")
			}
		}
		if n.User != "" {
			if err := ValidateUsername(n.User); err != nil {
				return err
			}
		}
		if n.DecoyURL != "" {
			u, err := url.Parse(n.DecoyURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || !isCaddyToken(n.DecoyURL) {
				return fmt.Errorf("invalid decoy URL %q", n.DecoyURL)
			}
		}
	}
	if s := t.StunTLS; s != nil {
		if err := validatePort(s.Port); err != nil {
			return err
		}
	}
	return nil
}

// rejectControlChars fails if any string anywhere in c holds a control
// character. A newline in any value written to a unit file or Caddyfile
// would start a new directive.
func rejectControlChars(c *Config) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		return err
	}
	// The error names the field, not the value, which may be a password.
	var walk func(field string, v any) error
	walk = func(field string, v any) error {
		switch v := v.(type) {
		case string:
			if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7F }) {
				return fmt.Errorf("%s contains control characters", field)
			}
		case []any:
			for i, e := range v {
				if err := walk(fmt.Sprintf("%s[%d]", field, i), e); err != nil {
					return err
				}
			}
		case map[string]any:
			for k, e := range v {
				if err := walk(strings.TrimPrefix(field+"."+k, "."), e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk("", tree)
}

// validateAddr checks a host:port value that is passed on a command line.
func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q", addr)
	}
	if strings.ContainsAny(host, " \t") {
		return fmt.Errorf("invalid address %q", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port in address %q", addr)
	}
	return nil
}

func validatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

func isCaddyToken(s string) bool {
	return !strings.ContainsAny(s, " \t{}\"'`\\")
}

func validateTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag is required")
	}
	if !tagRegex.MatchString(tag) {
		return fmt.Errorf("tag must start with a letter and contain only lowercase letters, numbers, and hyphens")
	}
	return nil
}

func validateTransport(transport string) error {
	switch transport {
	case TransportDNSTT, TransportSlipstream, TransportVayDNS, TransportSoar, TransportNaive, TransportStunTLS, TransportSSH, TransportSOCKS, TransportExternal:
		return nil
	}
	return fmt.Errorf("unknown transport: %s", transport)
}

func validateBackend(backend string) error {
	switch backend {
	case BackendSOCKS, BackendSSH, BackendDirect:
		return nil
	}
	return fmt.Errorf("unknown backend: %s", backend)
}

func validateTransportBackend(transport, backend string) error {
	// All combinations are valid
	return nil
}
