# SlipGate

Unified tunnel manager for Linux servers. Manages DNS tunnels (DNSTT, Slipstream) and HTTPS proxies (NaiveProxy) with systemd services, multi-tunnel DNS routing, and user management. Designed for use with the [SlipNet](https://github.com/anonvector/SlipNet) Android VPN app.

## Features

- **Multi-transport**: DNSTT (DNS-over-TCP tunnel), Slipstream (QUIC-based DNS), NaiveProxy (HTTPS with Caddy)
- **Dual backend**: SOCKS5 proxy (microsocks) or SSH forwarding
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
curl -fsSL https://raw.githubusercontent.com/anonvector/SlipNet/main/install.sh | sudo bash
```

**Or build from source:**

```bash
git clone https://github.com/anonvector/SlipNet.git
cd SlipNet
make build
sudo ./slipgate install
```

Then launch the interactive menu:

```bash
sudo slipgate
```

## CLI Usage

```
slipgate                        # Interactive TUI
slipgate install                # Install dependencies and configure server
slipgate uninstall              # Remove everything
slipgate update                 # Check for updates and self-update

slipgate tunnel add             # Add a new tunnel (interactive)
slipgate tunnel remove [tag]    # Remove a tunnel
slipgate tunnel start [tag]     # Start a tunnel
slipgate tunnel stop [tag]      # Stop a tunnel
slipgate tunnel status          # Show all tunnel statuses
slipgate tunnel share [tag]     # Generate slipnet:// URI for clients
slipgate tunnel logs [tag]      # View tunnel logs

slipgate router status          # Show DNS routing config
slipgate router mode            # Switch between single/multi mode
slipgate router switch          # Change active tunnel (single mode)

slipgate users                  # Manage SSH/SOCKS users
slipgate config export          # Export configuration
slipgate config import          # Import configuration
```

### Non-Interactive Tunnel Creation

All tunnel types can be created without interactive prompts, useful for scripting and automation:

```bash
# DNSTT tunnel
sudo slipgate tunnel add \
  --transport dnstt \
  --backend socks \
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
```

If any required flag is omitted, slipgate falls back to an interactive prompt for that field.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                           SERVER                              │
│                                                               │
│  DNS (port 53)                        HTTPS (port 443)        │
│       │                                     │                 │
│       v                                     v                 │
│  ┌─────────────────────┐          ┌───────────────────────┐   │
│  │     DNS Router       │          │   NaiveProxy (Caddy)  │   │
│  │  single / multi mode │          │   + decoy website     │   │
│  └──┬──────────┬────────┘          └──────────┬────────────┘   │
│     │          │                              │               │
│     v          v                              │               │
│  ┌──────┐  ┌───────────┐                     │               │
│  │DNSTT │  │Slipstream │                     │               │
│  └──┬───┘  └─────┬─────┘                     │               │
│     │            │                            │               │
│     v            v                            v               │
│  ┌────────────────────────────────────────────────────────┐   │
│  │                    Backend                              │   │
│  │           SOCKS5 (microsocks) or SSH                    │   │
│  └────────────────────────┬───────────────────────────────┘   │
│                           │                                   │
│                           v                                   │
│                       Internet                                │
└──────────────────────────────────────────────────────────────┘
```

### Transport Types

| Transport | Protocol | Port | Description |
|-----------|----------|------|-------------|
| **DNSTT** | DNS-over-TCP | 53/udp | Curve25519 encrypted DNS tunnel. Supports DNSTT and NoizDNS clients |
| **Slipstream** | QUIC DNS | 53/udp | QUIC-based tunnel with certificate authentication |
| **NaiveProxy** | HTTPS | 443/tcp | Caddy with forwardproxy plugin. Auto-TLS via Let's Encrypt. Probe-resistant with decoy site |

### Routing Modes

- **Single mode**: One active tunnel listens directly on port 53
- **Multi mode**: DNS router on port 53 dispatches queries by domain to different tunnels running on local ports

## Client Configuration

After creating a tunnel, generate a shareable config:

```bash
sudo slipgate tunnel share mytunnel
```

This outputs a `slipnet://` URI that can be scanned or imported into the SlipNet Android app.

## File Locations

| Path | Description |
|------|-------------|
| `/etc/slipgate/config.json` | Main configuration |
| `/etc/slipgate/tunnels/` | Per-tunnel keys, certs, and configs |
| `/usr/local/bin/slipgate` | SlipGate binary |
| `/usr/local/bin/dnstt-server` | DNSTT transport binary |
| `/usr/local/bin/slipstream-server` | Slipstream transport binary |
| `/usr/local/bin/caddy-naive` | Caddy with NaiveProxy plugin |
| `/usr/local/bin/microsocks` | SOCKS5 proxy binary |

## Building

```bash
make build              # Build for current platform
make build-linux        # Cross-compile for linux/amd64 and linux/arm64
make test               # Run tests
make release            # Build release binaries
```

## License

MIT
