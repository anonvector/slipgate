package clientcfg

import "github.com/anonvector/slipgate/internal/config"

// v17 field positions (pipe-delimited, 38 fields).
// Matches the SlipNet Android app's ConfigImporter/ConfigExporter.
const (
	FVersion            = 0  // "17"
	FTunnelType         = 1  // dnstt, sayedns, dnstt_ssh, sayedns_ssh, naive, naive_ssh, ss, slipstream_ssh
	FName               = 2  // profile name
	FDomain             = 3  // tunnel domain
	FResolvers          = 4  // comma-separated "host:port:auth"
	FAuthMode           = 5  // "0" or "1"
	FKeepAlive          = 6  // "5000"
	FCongestionControl  = 7  // "bbr"
	FTCPListenPort      = 8  // "1080"
	FTCPListenHost      = 9  // "127.0.0.1"
	FGSOEnabled         = 10 // "0"
	FPublicKey          = 11 // hex-encoded Curve25519 public key
	FSOCKSUser          = 12 // SOCKS5 username
	FSOCKSPass          = 13 // SOCKS5 password
	FSSHEnabled         = 14 // "0" or "1"
	FSSHUser            = 15 // SSH username
	FSSHPass            = 16 // SSH password
	FSSHPort            = 17 // "22"
	FFwdDNSThroughSSH   = 18 // "0" (deprecated)
	FSSHHost            = 19 // SSH host address
	FUseServerDNS       = 20 // "0" (deprecated)
	FDoHURL             = 21 // DoH URL
	FDNSTransport       = 22 // "udp"
	FSSHAuthType        = 23 // "password"
	FSSHPrivateKey      = 24 // base64-encoded
	FSSHKeyPassphrase   = 25 // base64-encoded
	FTorBridgeLines     = 26 // base64-encoded
	FDNSTTAuthoritative = 27 // "0" or "1"
	FNaivePort          = 28 // "443"
	FNaiveUser          = 29 // NaiveProxy username
	FNaivePass          = 30 // NaiveProxy password (base64)
	FIsLocked           = 31 // "0"
	FLockPasswordHash   = 32 // ""
	FExpirationDate     = 33 // "0"
	FAllowSharing       = 34 // "0"
	FBoundDeviceId      = 35 // ""
	FResolversHidden    = 36 // "0" (v17)
	FHiddenResolvers    = 37 // "" (v17)
	FNoizDNSStealth     = 38 // "0" or "1" (v18)
	FDNSPayloadSize     = 39 // integer (v18)
	FSOCKS5ServerPort   = 40 // integer, default 1080 (v18)
	TotalFields         = 41
)

// Client modes for DNSTT transport (server is the same, client behavior differs).
const (
	ClientModeDNSTT   = "dnstt"
	ClientModeNoizDNS = "noizdns"
)

// TunnelTypeMap maps transport+clientMode+backend to slipnet:// field[1] value.
var TunnelTypeMap = map[string]map[string]map[string]string{
	config.TransportDNSTT: {
		ClientModeDNSTT: {
			config.BackendSOCKS: "dnstt",
			config.BackendSSH:   "dnstt_ssh",
		},
		ClientModeNoizDNS: {
			config.BackendSOCKS: "sayedns",
			config.BackendSSH:   "sayedns_ssh",
		},
	},
	config.TransportSlipstream: {
		"": {
			config.BackendSOCKS: "ss",
			config.BackendSSH:   "slipstream_ssh",
		},
	},
	config.TransportNaive: {
		"": {
			config.BackendSOCKS: "naive",
			config.BackendSSH:   "naive_ssh",
		},
	},
	config.TransportSSH: {
		"": {
			config.BackendSSH: "ssh",
		},
	},
	config.TransportSOCKS: {
		"": {
			config.BackendSOCKS: "socks5",
		},
	},
}

// GetTunnelType returns the slipnet:// type string.
func GetTunnelType(transport, backend, clientMode string) string {
	modes, ok := TunnelTypeMap[transport]
	if !ok {
		return "unknown"
	}
	if transport != config.TransportDNSTT {
		clientMode = ""
	}
	if m, ok := modes[clientMode]; ok {
		if t, ok := m[backend]; ok {
			return t
		}
	}
	return "unknown"
}
