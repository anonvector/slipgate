# SlipGate

Unified tunnel manager for Linux servers. Manages DNS tunnels (DNSTT, NoizDNS, Slipstream) and HTTPS proxies (NaiveProxy) with systemd services, multi-tunnel DNS routing, and user management. Designed for use with the [SlipNet](https://github.com/anonvector/SlipNet) Android VPN app.

## Features

- **Multi-transport**: DNSTT/NoizDNS (DNS tunnels with Curve25519 encryption), Slipstream (QUIC-based DNS), NaiveProxy (HTTPS with Caddy)
- **Dual backend**: Built-in SOCKS5 proxy or SSH forwarding
- **DNS routing**: Single-tunnel or multi-tunnel mode with domain-based dispatch
- **User management**: Managed SSH + SOCKS credentials per user
- **Interactive TUI + CLI**: Menu-driven setup or scriptable subcommands
- **Systemd integration**: Service creation, lifecycle, and logs
- **Auto-TLS**: Let's Encrypt via Caddy for NaiveProxy tunnels
- **Self-update**: Version checking and binary replacement from GitHub releases
- **Client sharing**: Generates `slipnet://` URIs for one-tap app import

## Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, or similar)
- **Domain**: DNS A record pointed at your server (required for DNS tunnels and NaiveProxy)
- **Ports**: 53/udp (DNS tunnels), 443/tcp (NaiveProxy)

## Quick Start

**One-liner install:**

```bash
curl -fsSL https://raw.githubusercontent.com/anonvector/slipgate/main/install.sh | sudo bash
```

**Or build from source:**

```bash
git clone https://github.com/anonvector/slipgate.git
cd slipgate
make build
sudo ./slipgate install
```

**Offline install (SCP to server):**

Download the binaries you need from the [latest release](https://github.com/anonvector/slipgate/releases):

```bash
# On your local machine — download binaries
mkdir slipgate-bundle && cd slipgate-bundle
curl -LO https://github.com/anonvector/slipgate/releases/latest/download/slipgate-linux-amd64
curl -LO https://github.com/anonvector/slipgate/releases/latest/download/dnstt-server-linux-amd64
curl -LO https://github.com/anonvector/slipgate/releases/latest/download/slipstream-server-linux-amd64
curl -LO https://github.com/anonvector/slipgate/releases/latest/download/caddy-naive-linux-amd64

# SCP to server
scp * user@server:/tmp/slipgate/

# On the server
chmod +x /tmp/slipgate/*
sudo cp /tmp/slipgate/slipgate-linux-amd64 /usr/local/bin/slipgate
sudo slipgate install --bin-dir /tmp/slipgate
```

Then launch the interactive menu:

```bash
sudo slipgate
```

## CLI Usage

```
slipgate                        # Interactive TUI menu
slipgate install                # Install dependencies and configure server
slipgate uninstall              # Remove all services, configs, and binaries
slipgate update                 # Self-update and restart all services
slipgate restart                # Restart all services (DNS router, tunnels, SOCKS)
slipgate users                  # Manage SSH/SOCKS users and view configs

# Tunnel management
slipgate tunnel add             # Add tunnel(s) — supports multi-select and "both" backend
slipgate tunnel edit [tag]      # Edit tunnel settings (MTU)
slipgate tunnel remove [tag]    # Remove a tunnel
slipgate tunnel start [tag]     # Start a tunnel
slipgate tunnel stop [tag]      # Stop a tunnel
slipgate tunnel status          # Show all tunnel statuses
slipgate tunnel share [tag]     # Generate slipnet:// URI for clients
slipgate tunnel logs [tag]      # View tunnel logs

# DNS routing
slipgate router status          # Show DNS routing config
slipgate router mode            # Switch between single/multi mode
slipgate router switch          # Change active tunnel (single mode)

# Configuration
slipgate config export          # Export configuration
slipgate config import          # Import configuration

# Internal (used by systemd services)
slipgate dnsrouter serve        # Start DNS router
slipgate socks serve            # Start built-in SOCKS5 proxy
```

### Non-Interactive Examples

All commands support flags for scripting and automation. If any required flag is omitted, slipgate falls back to an interactive prompt.

```bash
# DNSTT tunnel
sudo slipgate tunnel add \
  --transport dnstt \
  --backend socks \
  --tag mydnstt \
  --domain t.example.com

# DNSTT tunnel with custom Curve25519 keys
sudo slipgate tunnel add \
  --transport dnstt \
  --backend socks \
  --tag mytunnel \
  --domain t.example.com \
  --private-key <64-char-hex> \
  --public-key <64-char-hex>   # optional, validated if provided

# DNSTT with both backends (creates mydnstt-socks + mydnstt-ssh)
sudo slipgate tunnel add \
  --transport dnstt \
  --backend both \
  --tag mydnstt \
  --domain t.example.com

# Slipstream tunnel
sudo slipgate tunnel add \
  --transport slipstream \
  --backend ssh \
  --tag myslip \
  --domain s.example.com

# NaiveProxy tunnel
sudo slipgate tunnel add \
  --transport naive \
  --backend socks \
  --tag myproxy \
  --domain example.com \
  --email admin@example.com \
  --decoy-url https://www.wikipedia.org

# Direct SSH / SOCKS5 transports
sudo slipgate tunnel add --transport direct-ssh --tag myssh
sudo slipgate tunnel add --transport direct-socks5 --tag mysocks

# Change MTU on a DNSTT tunnel
sudo slipgate tunnel edit --tag mydnstt --mtu 1232

# Share tunnel config as slipnet:// URI
sudo slipgate tunnel share mydnstt
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                            SERVER                             │
│                                                               │
│  DNS (port 53)              HTTPS (port 443)                  │
│       │                          │                            │
│       v                          v                            │
│  ┌──────────────────┐   ┌─────────────────┐                  │
│  │    DNS Router     │   │ NaiveProxy      │                  │
│  │ single/multi mode │   │ (Caddy + decoy) │                  │
│  └──┬──────────┬─────┘   └────────┬────────┘                  │
│     │          │                  │                            │
│     v          v                  │                            │
│  ┌──────────┐ ┌───────────┐      │                            │
│  │DNSTT/Noiz│ │Slipstream │      │                            │
│  └────┬─────┘ └─────┬─────┘      │                            │
│       v             v             v                            │
│  ┌──────────────────────────────────────────────────────┐     │
│  │                     Backend                            │     │
│  │              SOCKS5 (built-in) / SSH                   │     │
│  └──────────────────────┬─────────────────────────────┘     │
│                          v                                    │
│                      Internet                                 │
└─────────────────────────────────────────────────────────────┘
```

### Transport Types

| Transport | Protocol | Port | Description |
|-----------|----------|------|-------------|
| **DNSTT/NoizDNS** | DNS | 53/udp | Curve25519 encrypted DNS tunnel. A single server serves both DNSTT and NoizDNS clients. NoizDNS adds DPI evasion with base36/hex encoding and CDN prefix stripping |
| **Slipstream** | QUIC DNS | 53/udp | QUIC-based tunnel with certificate authentication |
| **NaiveProxy** | HTTPS | 443/tcp | Caddy with forwardproxy plugin. Auto-TLS via Let's Encrypt. Probe-resistant with decoy site |

### Domain Layout

Each DNS tunnel instance requires its own subdomain. When using both SOCKS and SSH backends, the install auto-generates subdomains by appending `s` to the SSH variant:

| Tunnel | Domain | Backend |
|--------|--------|---------|
| dnstt-socks | `t.example.com` | SOCKS5 |
| dnstt-ssh | `ts.example.com` | SSH |
| slipstream-socks | `s.example.com` | SOCKS5 |
| slipstream-ssh | `ss.example.com` | SSH |
| naive-socks | `example.com` | SOCKS5 (shared domain) |
| naive-ssh | `example.com` | SSH (shared domain) |

NaiveProxy tunnels share a domain since they use HTTPS (port 443), not DNS. DNSTT and NoizDNS also share a domain — the same server handles both client types.

**Required DNS records** (for the example above):

```
A   ns.example.com       → <server IP>
NS  t.example.com        → ns.example.com
NS  ts.example.com       → ns.example.com
NS  s.example.com        → ns.example.com
NS  ss.example.com       → ns.example.com
A   example.com           → <server IP>
```

### Routing Modes

- **Single mode**: One active tunnel runs; DNS router on port 53 forwards to it
- **Multi mode**: All tunnels run on local ports; DNS router on port 53 dispatches queries by domain. Auto-enabled when multiple DNS tunnels are created.

## Client Configuration

After creating a tunnel, generate a shareable config:

```bash
sudo slipgate tunnel share mytunnel
```

This outputs a `slipnet://` URI that can be scanned or imported into the SlipNet Android app. For DNSTT tunnels, you'll be asked to choose between a DNSTT or NoizDNS client profile — both connect to the same server, but NoizDNS profiles enable DPI evasion on the client side.

## File Locations

| Path | Description |
|------|-------------|
| `/etc/slipgate/config.json` | Main configuration |
| `/etc/slipgate/tunnels/` | Per-tunnel keys, certs, and configs |
| `/usr/local/bin/slipgate` | SlipGate binary (includes built-in SOCKS5 proxy) |
| `/usr/local/bin/dnstt-server` | DNSTT transport binary |
| `/usr/local/bin/slipstream-server` | Slipstream transport binary |
| `/usr/local/bin/caddy-naive` | Caddy with NaiveProxy plugin |

## Building

```bash
make build              # Build for current platform
make build-linux        # Cross-compile for linux/amd64 and linux/arm64
make test               # Run tests
make release            # Build release binaries
```

## Credits

Built on top of [dnstm](https://github.com/net2share/dnstm) by [net2share](https://github.com/net2share).

## License

AGPL-3.0
