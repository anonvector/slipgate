# SlipGate — NaiveProxy + SSH Server Setup

Interactive setup script that configures a server for use with the SlipNet Android VPN app. Builds Caddy with [klzgrad's forwardproxy](https://github.com/klzgrad/forwardproxy) plugin (NaiveProxy), configures automatic TLS via Let's Encrypt, and serves a decoy website to resist probe detection.

## Requirements

- **OS**: Ubuntu 20.04+ or Debian 11+
- **Domain**: A domain with a DNS A record pointed at your server's IP
- **Ports**: 80 and 443 must be available (not used by Apache, Nginx, etc.)
- **SSH** *(optional)*: An SSH server already running — only needed if you enable SSH tunnel access for users

## Quick Start

**Option 1 — Clone and run:**

```bash
git clone https://github.com/anonvector/slipgate.git
cd slipgate
sudo bash setup.sh
```

**Option 2 — One-liner:**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/anonvector/slipgate/main/setup.sh)
```

## Menu

The script presents a menu with all available actions:

```
══════════════════════════════════════════
  SlipNet Server — NaiveProxy + SSH
══════════════════════════════════════════
  Status: not installed

  1) Install         Set up NaiveProxy server
  2) Reconfigure     Change domain/email/decoy
  3) Show config     Print current configuration
  4) Uninstall       Remove everything
  5) Manage users    Add/delete/list proxy+SSH users
  0) Exit
```

- **Install** — prompts for domain, email, credentials, and decoy site, then builds and starts everything
- **Reconfigure** — shows current values, lets you change domain/email/decoy, restarts the service
- **Show config** — prints current configuration and user list with SSH status
- **Uninstall** — stops the service and removes all files (binary, config, systemd unit, SSH users, UFW rules)
- **Manage users** — add, delete, or list proxy users (SSH access is optional per user)

## What It Does

1. Verifies OS compatibility and that ports 80/443 are free
2. Installs dependencies (curl, git, Go 1.21+)
3. Builds Caddy with the NaiveProxy forwardproxy plugin using xcaddy
4. Creates a Caddyfile with TLS, forward proxy auth, and a decoy reverse proxy
5. Optionally creates an SSH tunnel user (default: **no** — proxy-only)
6. Creates and enables a `caddy-naive` systemd service
7. Opens firewall ports if UFW is active
8. Starts the service and waits for TLS certificate issuance

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│                         DEVICE                               │
│                                                              │
│  ┌─────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │  Apps    │───>│  TUN Interface   │───>│ hev-socks5-    │  │
│  │ (Chrome, │    │  (VPN capture)   │    │ tunnel         │  │
│  │  etc.)   │    └──────────────────┘    │ (tun2socks)    │  │
│  └─────────┘                             └───────┬────────┘  │
│                                                  │           │
│                                          SOCKS5  │           │
│                                                  v           │
│                                          ┌───────────────┐   │
│                                          │ SSH Tunnel    │   │
│                                          │ SOCKS5 server │   │
│                                          │ (port 1080)   │   │
│                                          └───────┬───────┘   │
│                                                  │           │
│                                     SSH channels │           │
│                                    (direct-tcpip)│           │
│                                                  v           │
│                                          ┌───────────────┐   │
│                                          │  NaiveProxy   │   │
│                                          │  SOCKS5 proxy │   │
│                                          │  (port 1081)  │   │
│                                          └───────┬───────┘   │
│                                                  │           │
└──────────────────────────────────────────────────┼───────────┘
                                                   │
                              HTTPS (looks like    │
                              normal Chrome        │
                              browsing to ISP)     │
                                                   v
┌──────────────────────────────────────────────────────────────┐
│                         SERVER                               │
│                                                              │
│  ┌─────────────────┐     ┌──────────────┐     ┌──────────┐  │
│  │  Caddy + forward│────>│  SSH Server  │────>│ Internet │  │
│  │  proxy (443)    │     │  (port 22)   │     │          │  │
│  │                 │     └──────────────┘     └──────────┘  │
│  │  TLS termination│                                        │
│  │  + decoy website│  <── probes see a normal website       │
│  └─────────────────┘                                        │
└──────────────────────────────────────────────────────────────┘
```

**What the ISP/censor sees:** Your phone making a normal HTTPS connection to `your-domain.com:443` — identical to regular Chrome browsing. No VPN signatures.

**What actually happens inside that HTTPS:**

```
App traffic → SOCKS5 → SSH tunnel → NaiveProxy → HTTPS CONNECT → Caddy → SSH → Internet
```

## SlipNet App Configuration

After setup completes, create a profile in the SlipNet app with these settings:

| App Setting    | Value                          |
|----------------|--------------------------------|
| Tunnel Type    | NaiveProxy + SSH               |
| Server         | your-domain.com                |
| Server Port    | 443                            |
| Proxy Username | *(shown after setup)*          |
| Proxy Password | *(shown after setup)*          |
| SSH Port       | 22 *(only if SSH enabled)*     |
| SSH Username   | *(only if SSH enabled)*        |
| SSH Password   | *(only if SSH enabled)*        |

The NaiveProxy connection carries your SSH tunnel through an HTTPS connection that looks like normal web traffic to network observers. SSH tunnel access is **optional** — during install or when adding users, answer `y` to "Create SSH tunnel access?" to enable it. By default, users are proxy-only.

## File Locations

| Path | Description |
|------|-------------|
| `/usr/bin/caddy-naive` | Caddy binary with forwardproxy plugin |
| `/etc/caddy-naive/Caddyfile` | Caddy configuration |
| `/etc/systemd/system/caddy-naive.service` | Systemd unit file |

## Managing the Service

```bash
# Check status
systemctl status caddy-naive

# View logs
journalctl -u caddy-naive -f

# Restart
systemctl restart caddy-naive

# Stop
systemctl stop caddy-naive
```

## Troubleshooting

### TLS certificate not obtained
- Verify your domain's DNS A record points to this server: `dig +short your-domain.com`
- Ensure port 80 is open (Let's Encrypt uses HTTP-01 challenge)
- Check logs: `journalctl -u caddy-naive --no-pager -n 50`

### Port already in use
- Find what's using the port: `ss -tlnp | grep ':80\|:443'`
- Common culprits: Apache (`apache2`), Nginx (`nginx`), another Caddy instance
- Stop the conflicting service before running setup

### Connection refused in SlipNet app
- Verify the service is running: `systemctl status caddy-naive`
- Test from the server: `curl -I https://your-domain.com`
- Test proxy auth: `curl --proxy https://user:pass@your-domain.com https://ifconfig.me`

### Decoy website not loading
- The reverse proxy to the decoy site requires the upstream to be accessible
- Try a different decoy URL if the default doesn't work

## Manual Setup

For advanced users who want to customize the configuration:

1. **Install Go 1.21+** from https://go.dev/dl/

2. **Build Caddy with forwardproxy:**
   ```bash
   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
   ~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive
   sudo mv caddy /usr/bin/caddy-naive
   sudo setcap cap_net_bind_service=+ep /usr/bin/caddy-naive
   ```

3. **Create Caddyfile** at `/etc/caddy-naive/Caddyfile`:
   ```
   {
       order forward_proxy before file_server
   }
   :443, your-domain.com {
       tls your-email@example.com
       route {
           forward_proxy {
               basic_auth username password
               hide_ip
               hide_via
               probe_resistance
           }
           reverse_proxy https://www.wikipedia.org {
               header_up Host {upstream_hostport}
           }
       }
   }
   ```

4. **Create systemd service** and start it (see `setup.sh` for the unit file).

## Uninstall

Run the same script and choose option 4:

```bash
sudo bash setup.sh
# → Choose 4) Uninstall
```

This stops the service and removes the binary, Caddyfile, systemd unit, and UFW rules.
