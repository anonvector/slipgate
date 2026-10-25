package actions

// Shared select options used across multiple actions.

// TransportOptions is the full list shown in `tunnel add`.
var TransportOptions = []SelectOption{
	{Value: "dnstt", Label: "DNSTT / NoizDNS — DNS tunnel"},
	{Value: "slipstream", Label: "Slipstream — QUIC DNS tunnel"},
	{Value: "vaydns", Label: "VayDNS — KCP DNS tunnel"},
	{Value: "soar", Label: "Soar — multipath DNS tunnel (soar-client compatible)"},
	{Value: "naive", Label: "NaiveProxy — HTTPS proxy with Caddy"},
	{Value: "stuntls", Label: "StunTLS — SSH over TLS + WebSocket proxy"},
	{Value: "external", Label: "External — Route DNS to a custom port"},
	{Value: "direct-ssh", Label: "SSH — Direct SSH tunnel"},
	{Value: "direct-socks5", Label: "SOCKS5 — Direct SOCKS5 proxy"},
}

// InstallTransportOptions is the subset shown in the install/wizard flows.
// External is excluded because it routes to a user-managed service that
// wouldn't exist yet during initial setup.
var InstallTransportOptions = []SelectOption{
	{Value: "dnstt", Label: "DNSTT / NoizDNS — DNS tunnel"},
	{Value: "slipstream", Label: "Slipstream — QUIC DNS tunnel"},
	{Value: "vaydns", Label: "VayDNS — KCP DNS tunnel"},
	{Value: "soar", Label: "Soar — multipath DNS tunnel (soar-client compatible)"},
	{Value: "naive", Label: "NaiveProxy — HTTPS proxy with Caddy"},
	{Value: "stuntls", Label: "StunTLS — SSH over TLS + WebSocket proxy"},
	{Value: "direct-ssh", Label: "SSH — Direct SSH tunnel"},
	{Value: "direct-socks5", Label: "SOCKS5 — Direct SOCKS5 proxy"},
}

// ClientModeOptions is used during `tunnel share` to pick the slipnet:// URL type.
var ClientModeOptions = []SelectOption{
	{Value: "dnstt", Label: "DNSTT — Classic DNS tunnel client"},
	{Value: "noizdns", Label: "NoizDNS — DNS tunnel with DPI evasion"},
}

var BackendOptions = []SelectOption{
	{Value: "socks", Label: "SOCKS — SOCKS5 proxy"},
	{Value: "ssh", Label: "SSH — SSH tunnel"},
	{Value: "both", Label: "Both — SOCKS5 + SSH tunnel"},
}

var RouterModeOptions = []SelectOption{
	{Value: "single", Label: "Single — one active tunnel at a time"},
	{Value: "multi", Label: "Multi — domain-based routing to multiple tunnels"},
}
