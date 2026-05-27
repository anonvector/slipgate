package clientcfg

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
	"os"
	
	"github.com/anonvector/slipgate/internal/config"
)

// URIOptions controls URI generation.
type URIOptions struct {
	ClientMode string // "dnstt" or "noizdns" (DNSTT transport only)
	Username   string // override SOCKS/SSH username
	Password   string // override SOCKS/SSH password
}

// b64 encodes a string as base64 (matching Android's Base64.NO_WRAP).
func b64(s string) string {
	if s == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// GenerateURI builds a slipnet:// URI from tunnel + backend config.
func GenerateURI(tunnel *config.TunnelConfig, backend *config.BackendConfig, cfg *config.Config, opts URIOptions) (string, error) {
	var fields [TotalFields]string

	// Version and type
	fields[FVersion] = "22"
	fields[FTunnelType] = GetTunnelType(tunnel.Transport, tunnel.Backend, opts.ClientMode)

	name := tunnel.Tag
	if opts.ClientMode == ClientModeNoizDNS {
		name = strings.ReplaceAll(name, "dnstt", "noizdns")
	}
	fields[FName] = name
	fields[FDomain] = tunnel.Domain

	// Defaults
	fields[FResolvers] = "8.8.8.8:53:0"
	fields[FAuthMode] = "0"
	fields[FKeepAlive] = "5000"
	fields[FCongestionControl] = "bbr"
	fields[FTCPListenPort] = "1080"
	fields[FTCPListenHost] = "127.0.0.1"
	fields[FGSOEnabled] = "0"
	fields[FSSHEnabled] = "0"
	fields[FSSHPort] = "22"
	fields[FFwdDNSThroughSSH] = "0"
	fields[FSSHHost] = getServerIP()
	fields[FUseServerDNS] = "0"
	fields[FDNSTransport] = "udp"
	fields[FSSHAuthType] = "password"
	fields[FSSHPrivateKey] = b64("")
	fields[FSSHKeyPassphrase] = b64("")
	fields[FTorBridgeLines] = b64("")
	fields[FDNSTTAuthoritative] = "0"
	fields[FNaivePort] = "443"
	fields[FNaivePass] = b64("")
	fields[FIsLocked] = "0"
	fields[FExpirationDate] = "0"
	fields[FAllowSharing] = "0"
	fields[FResolversHidden] = "0"
	fields[FNoizDNSStealth] = "0"
	fields[FDNSPayloadSize] = "0"
	fields[FSOCKS5ServerPort] = "1080"
	// v19-v20 VayDNS defaults
	fields[FVayDNSDnsttCompat] = "0"
	fields[FVayDNSRecordType] = "txt"
	fields[FVayDNSMaxQnameLen] = "101"
	fields[FVayDNSRps] = "0"
	fields[FVayDNSIdleTimeout] = "0"
	fields[FVayDNSKeepalive] = "0"
	fields[FVayDNSUdpTimeout] = "0"
	fields[FVayDNSMaxNumLabels] = "0"
	fields[FVayDNSClientIdSize] = "0"
	// v21 defaults
	fields[FSSHTlsEnabled] = "0"
	fields[FSSHWsEnabled] = "0"
	fields[FSSHWsPath] = "/"
	fields[FSSHWsUseTls] = "1"
	fields[FSSHHttpProxyPort] = "8080"
	// v22 defaults
	fields[FSSHPayload] = b64("")

	// Transport-specific
	switch tunnel.Transport {
	case config.TransportDNSTT:
		if tunnel.DNSTT != nil {
			fields[FPublicKey] = tunnel.DNSTT.PublicKey
		}

	case config.TransportVayDNS:
		if tunnel.VayDNS != nil {
			fields[FPublicKey] = tunnel.VayDNS.PublicKey
			if tunnel.VayDNS.DnsttCompat {
				fields[FVayDNSDnsttCompat] = "1"
			} else {
				fields[FVayDNSDnsttCompat] = "0"
			}
			if tunnel.VayDNS.RecordType != "" {
				fields[FVayDNSRecordType] = tunnel.VayDNS.RecordType
			} else {
				fields[FVayDNSRecordType] = "txt"
			}
			if tunnel.VayDNS.IdleTimeout != "" {
				fields[FVayDNSIdleTimeout] = durationToSeconds(tunnel.VayDNS.ResolvedIdleTimeout())
			}
			if tunnel.VayDNS.KeepAlive != "" {
				fields[FVayDNSKeepalive] = durationToSeconds(tunnel.VayDNS.ResolvedKeepAlive())
			}
			fields[FVayDNSClientIdSize] = fmt.Sprintf("%d", tunnel.VayDNS.ResolvedClientIDSize())
		}

	case config.TransportSlipstream:
		// No pubkey field needed

	case config.TransportNaive:
		if tunnel.Naive != nil {
			fields[FNaivePort] = fmt.Sprintf("%d", tunnel.Naive.Port)
			fields[FNaiveUser] = tunnel.Naive.User
			fields[FNaivePass] = b64(tunnel.Naive.Password)
			// Match server-side defaults from buildCaddyfile()
			if fields[FNaiveUser] == "" {
				fields[FNaiveUser] = "slipgate"
			}
			if tunnel.Naive.Password == "" {
				fields[FNaivePass] = b64("slipgate")
			}
		}

	case config.TransportStunTLS:
		if tunnel.StunTLS != nil {
			// StunTLS server accepts raw TLS, WebSocket, HTTP CONNECT, and payload.
			// Default to WebSocket (most compatible with CDNs and restrictive firewalls).
			// Only set WebSocket fields — don't also set sshTlsEnabled, which is
			// a Direct-mode flag and would be dead weight.
			fields[FDomain] = getServerIP()
			fields[FSSHPort] = fmt.Sprintf("%d", tunnel.StunTLS.Port)
			fields[FSSHWsEnabled] = "1"
			fields[FSSHWsUseTls] = "1"
			fields[FSSHWsPath] = "/"
		}

	case config.TransportSSH, config.TransportSOCKS:
		// Direct transports have no domain — use server IP
		fields[FDomain] = getServerIP()
	}

	// User credentials — always populate both SOCKS and SSH fields
	// The user/password is shared across SOCKS and SSH in slipgate
	username := opts.Username
	password := opts.Password

	if username == "" && backend != nil && backend.Type == config.BackendSOCKS && backend.SOCKS != nil {
		username = backend.SOCKS.User
		password = backend.SOCKS.Password
	}

	// SOCKS credentials (fields 12-13) — always set when we have a user
	fields[FSOCKSUser] = username
	fields[FSOCKSPass] = password

	// SSH fields (14-17, 19) — set for SSH tunnel types
	if tunnel.Backend == config.BackendSSH {
		fields[FSSHEnabled] = "1"
		fields[FSSHUser] = username
		fields[FSSHPass] = password
		// Only set port/host from the SSH backend when the transport
		// hasn't already filled them in (e.g. StunTLS sets the TLS port).
		if fields[FSSHPort] == "" && backend != nil {
			if _, port, err := net.SplitHostPort(backend.Address); err == nil {
				fields[FSSHPort] = port
			}
		}
		if fields[FSSHHost] == "" {
			fields[FSSHHost] = getServerIP()
		}
	}

	// NaiveProxy requires naiveUsername/naivePassword (fields 29/30)
	if tunnel.Transport == config.TransportNaive && username != "" {
		fields[FNaiveUser] = username
		fields[FNaivePass] = b64(password)
	}

	return Encode(fields), nil
}

func durationToSeconds(d string) string {
	if d == "" {
		return "0"
	}
	dur, err := time.ParseDuration(d)
	if err != nil {
		return "0"
	}
	return fmt.Sprintf("%d", int(dur.Seconds()))
}

func getServerIP() string {
// Check if a custom host override exists in the system environment variables first
    if envIP := os.Getenv("SLIPGATE_HOST"); envIP != "" {
        return envIP
    }

    // Default fallback logic for normal servers
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        return ""
    }
    defer conn.Close()
    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP.String()
}
