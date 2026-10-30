# SlipGate — Complete Operator Guide

> The official server for the [SlipNet](https://github.com/anonvector/SlipNet) Android app.
> Source: https://github.com/anonvector/slipgate
> SlipNet channel: [@SlipNet_app](https://t.me/SlipNet_app)

---

## Table of Contents

1. What SlipGate is
2. What you need before starting
3. Picking a VPS
4. Setting up your domain & DNS records
5. Installing SlipGate
6. The interactive menu vs. CLI
7. Adding your first tunnel
8. Tunnel transports — when to use which
9. Adding & managing users
10. Sharing configs with clients (`slipnet://` URIs)
11. Running multiple tunnels at once
12. WARP outbound (optional)
13. Daily operations: stats, logs, diagnostics
14. Updating SlipGate
15. Backup & migration
16. A note on VLESS
17. Troubleshooting
18. File locations & systemd reference
19. Uninstalling

---

## 1. What SlipGate is

SlipGate is a one-binary tunnel manager for Linux servers. You run it on your VPS, and it sets up the server side of every protocol SlipNet supports — DNSTT, NoizDNS, VayDNS, Slipstream, NaiveProxy, and StunTLS — with `systemd` services, a DNS router, user management, a live dashboard, and `slipnet://` URI generation for one-tap import in the SlipNet app.

In practice: **one command** turns a fresh Ubuntu/Debian VPS into a full anti-censorship endpoint that your phone (and your friends' phones) can connect to.

What SlipGate does for you:
- Installs the right transport binaries (`dnstt-server`, `slipstream-server`, `vaydns-server`, `caddy-naive`).
- Generates Curve25519 keys per tunnel.
- Configures `systemd` units that auto-start on boot.
- Runs a built-in SOCKS5 proxy and a DNS router that dispatches queries by domain.
- Manages users (one credential, all tunnels).
- Auto-generates Let's Encrypt certs for NaiveProxy via Caddy.
- Self-updates from GitHub releases.

---

## 2. What you need before starting

- A **Linux VPS** with **root SSH access** — Ubuntu 20.04+, Debian 10+, or any modern systemd-based distro.
- A **domain name** with control over its DNS records (Cloudflare, Namecheap, Porkbun, your registrar's panel, anything works).
- **Open ports** on the server:
  - `53/udp` for DNS tunnels (DNSTT, NoizDNS, VayDNS, Slipstream)
  - `443/tcp` for NaiveProxy and StunTLS
- About **15 minutes** of your time.
- **Cost estimate:** a $4–6/month VPS handles personal use comfortably.

---

## 3. Picking a VPS

The "right" VPS depends on where your users are.

**Avoid** providers that block UDP/53 inbound, since that kills DNS tunnels:
- DigitalOcean blocks UDP/53 on most plans.
- AWS blocks UDP/53 on Lightsail and on EC2 with default security groups.
- Some big US clouds throttle UDP heavily.

**Good choices** for serving users in Iran (and similar):
- **Hetzner** (Germany / Finland) — cheap, fast, doesn't block ports.
- **Contabo** (Germany) — very cheap, generous bandwidth.
- **OVH** (Europe) — no port restrictions.
- **BuyVM** — small but robust.
- Smaller European or Asian providers — usually fine.

**Pick a region that's geographically close to your users** but not blocked by your ISP. For Iran users, Germany / Finland / Netherlands are typical sweet spots.

**Sizing:** 1 vCPU, 1 GB RAM, 20 GB disk is enough for a personal/small-group server. Bandwidth matters more than CPU.

---

## 4. Setting up your domain & DNS records

You need one domain (e.g., `example.com`) that you control. Add these records before installing SlipGate:

```
A    ns.example.com   →  <server IP>
A    example.com      →  <server IP>          (only if using NaiveProxy / StunTLS)

NS   t.example.com    →  ns.example.com       (DNSTT/NoizDNS — SOCKS backend)
NS   ts.example.com   →  ns.example.com       (DNSTT/NoizDNS — SSH backend)
NS   s.example.com    →  ns.example.com       (Slipstream — SOCKS backend)
NS   ss.example.com   →  ns.example.com       (Slipstream — SSH backend)
NS   v.example.com    →  ns.example.com       (VayDNS — SOCKS backend)
NS   vs.example.com   →  ns.example.com       (VayDNS — SSH backend)
```

You only need the records for the tunnel types you plan to use. **Minimum**:
- For NaiveProxy only: just the root `A example.com → <IP>`.
- For DNSTT only: `A ns.example.com → <IP>` plus `NS t.example.com → ns.example.com`.

**Important about NS delegation**: the `NS` records mean "queries for `t.example.com` go to `ns.example.com`, which lives at `<server IP>`." Your server's port 53 will answer them via the DNS tunnel binary.

DNS changes propagate within a few minutes to a few hours. Verify with:

```bash
dig +short NS t.example.com
dig +short A ns.example.com
```

> If you're using **Cloudflare** for DNS, set the records to **DNS only** (gray cloud). Don't proxy them — the tunnel needs raw DNS at the server.

---

## 5. Installing SlipGate

SSH into your server as root, then run the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/anonvector/slipgate/main/install.sh | sudo bash
```

The script:
- Detects your distro.
- Installs system packages it needs.
- Downloads the SlipGate binary plus `dnstt-server`, `slipstream-server`, `vaydns-server`, and `caddy-naive`.
- Installs systemd services (`slipgate-dnsrouter`, `slipgate-socks5`).
- Sets up the firewall rules where applicable.

**Offline install** (when your VPS can't reach GitHub directly):

1. On your laptop, download from https://github.com/anonvector/slipgate/releases.
2. SCP the binaries to the server: `scp slipgate-* user@server:/tmp/slipgate/`
3. On the server: `sudo slipgate install --bin-dir /tmp/slipgate`

After install, launch the interactive menu:

```bash
sudo slipgate
```

---

## 6. The interactive menu vs. CLI

SlipGate has two interfaces:

**Interactive TUI** — `sudo slipgate` with no arguments. A friendly menu that walks you through tunnels, users, stats, diagnostics, etc. Best for first-time setup and exploration.

**CLI subcommands** — for scripting and automation. Every interactive option has a CLI equivalent:

```
slipgate install                Install dependencies, set up server
slipgate uninstall              Remove everything
slipgate update                 Self-update + restart services
slipgate restart                Restart all services
slipgate backup [file]          Back up config, keys and users (file or copy-paste text)
slipgate restore [file]         Restore a backup on this server
slipgate users                  Add / list / remove users (interactive)
slipgate users add              Add one user
slipgate users bulk_add         Add many users with random passwords
slipgate users list             List users + per-tunnel configs
slipgate stats                  Live dashboard
slipgate diag                   Run diagnostic checks
slipgate mtu [value]            Set MTU on all DNS tunnels at once

slipgate tunnel add             Add a tunnel
slipgate tunnel edit [tag]      Edit settings (rename, MTU, keys)
slipgate tunnel remove [tag]    Remove one tunnel
slipgate tunnel remove --all    Remove all tunnels
slipgate tunnel start [tag]     Start a tunnel
slipgate tunnel stop [tag]      Stop a tunnel
slipgate tunnel status [tag]    Show status / details
slipgate tunnel share [tag]     Print slipnet:// URI + QR
slipgate tunnel logs [tag]      Show systemd logs

slipgate router status          DNS routing config
slipgate router mode            Switch single ↔ multi mode
slipgate router switch          Change active tunnel (single mode)

slipgate config export          Print config.json (no keys; use backup to move a server)
slipgate config import [path]   Replace config.json (no keys)
```

---

## 7. Adding your first tunnel

The simplest possible setup — a DNSTT tunnel with the built-in SOCKS5 backend:

```bash
sudo slipgate tunnel add \
  --transport dnstt \
  --backend socks \
  --tag mytunnel \
  --domain t.example.com
```

What this does:
1. Generates a fresh Curve25519 keypair.
2. Spins up `dnstt-server` listening on UDP/53 for `t.example.com`.
3. Forwards decrypted traffic into the built-in SOCKS5 proxy on `127.0.0.1:1080`.
4. Creates a systemd service `slipgate-mytunnel` that starts on boot.

**Confirm it's running:**

```bash
sudo slipgate tunnel status
```

You should see your tunnel listed as **active**. If anything looks off, run:

```bash
sudo slipgate diag
```

---

## 8. Tunnel transports — when to use which

SlipGate manages six transports. Pick based on the network your users have to escape from.

| Transport | Port | What it is | Use when |
|-----------|------|------------|----------|
| **DNSTT** | 53/udp | Encrypted DNS tunnel (Curve25519). Mature, reliable | Default; also serves NoizDNS clients on the same port |
| **NoizDNS** | 53/udp | Same server as DNSTT — clients enable DPI evasion | Network does DNS-tunnel detection |
| **VayDNS** | 53/udp | KCP-based DNS tunnel with tunable wire format | Advanced; flaky DNS paths; need per-record-type tweaks |
| **Slipstream** | 53/udp | QUIC over DNS, very fast | Clean networks; users want speed |
| **NaiveProxy** | 443/tcp | Caddy + forwardproxy plugin, real Let's Encrypt cert, decoy site | DNS-tunneling banned; HTTPS still works |
| **StunTLS** | 443/tcp | SSH-over-TLS / SSH-over-WebSocket, self-signed cert | No domain available; or want CDN-friendly WS layer |

**Backends** for each transport:
- `socks` — built-in Go SOCKS5 proxy. Simple, fast, no SSH overhead.
- `ssh` — server's OpenSSH does the forwarding. Zero DNS leaks, slightly more secure.
- `both` — creates two tunnels in parallel (e.g., `mytunnel-socks` and `mytunnel-ssh`). Auto-generates the second subdomain by appending `s`.

**Examples**

```bash
# VayDNS — newer DNS tunnel, optimized
sudo slipgate tunnel add --transport vaydns --backend socks \
  --tag myvaydns --domain v.example.com

# VayDNS with all tuning knobs
sudo slipgate tunnel add --transport vaydns --backend both \
  --tag myvaydns --domain v.example.com \
  --record-type txt --idle-timeout 10s --keep-alive 2s \
  --clientid-size 2 --queue-size 512

# Slipstream over QUIC
sudo slipgate tunnel add --transport slipstream --backend ssh \
  --tag myslip --domain s.example.com

# NaiveProxy — auto Let's Encrypt cert
sudo slipgate tunnel add --transport naive --backend socks \
  --tag myproxy --domain example.com \
  --email admin@example.com --decoy-url https://www.wikipedia.org

# StunTLS — SSH over TLS + WebSocket, no domain needed
sudo slipgate tunnel add --transport stuntls --tag mytls

# Direct SSH or SOCKS5 (no tunnel transport)
sudo slipgate tunnel add --transport direct-ssh --tag myssh
sudo slipgate tunnel add --transport direct-socks5 --tag mysocks

# External: forward DNS for a domain to a custom UDP port (BYO protocol)
sudo slipgate tunnel add --transport external --tag my-proto \
  --domain j.example.com --port 5301
```

---

## 9. Adding & managing users

Users in SlipGate are **global**. The same `username:password` authenticates against every tunnel, regardless of transport. The protocol is a property of the **tunnel**, not the user.

> ⚠️ **Never hand out the server's `root` (or any sudoer / shell login) account as a VPN credential.** SlipGate users are isolated SOCKS/SSH-forwarding accounts with no shell access — losing one only loses tunnel access. A leaked `root` account loses the whole server: your keys, your other users' credentials, and any other service running on the box. Always create dedicated SlipGate users with `slipgate users add` (or `bulk_add`) for everyone you give a config to, including yourself.

**Add one user (interactive):**

```bash
sudo slipgate users add
```

You'll be prompted for username and password.

**Bulk-create users (random passwords, up to 500 in one go):**

```bash
sudo slipgate users bulk_add --count=50 --prefix=user
# Creates user001..user050
```

**List all users with their per-tunnel configs:**

```bash
sudo slipgate users list
```

This prints one config block per (user × tunnel) pair, including the `slipnet://` URI for each.

**Remove a user:**

```bash
sudo slipgate users remove
```

> Tip: if you're running a small group, give each person a unique username so you can revoke just theirs later if a phone is lost.

---

## 10. Sharing configs with clients

After creating a tunnel, generate a `slipnet://` URI for one-tap import in the SlipNet app:

```bash
sudo slipgate tunnel share mytunnel
```

This prints:
- A `slipnet://...` URI (long base64 string).
- A QR code (in the TUI).

Send the URI to your user. They open SlipNet → **+ → Import from URI** → paste → done.

For DNSTT tunnels, the share command asks whether to generate a **DNSTT** or **NoizDNS** profile. The same server handles both — NoizDNS just enables DPI evasion on the client side, so:
- **DNSTT** profile: a bit faster, easier to detect.
- **NoizDNS** profile: slower, harder to fingerprint.

> ⚠️ The URI contains the user's credentials. Send it via a private channel, never in a public group.

---

## 11. Running multiple tunnels at once

You can run as many tunnels as you want. SlipGate auto-switches into **multi-mode** when you create a second DNS tunnel — the DNS router on port 53 dispatches queries by domain to the correct tunnel.

Example: DNSTT + VayDNS + NaiveProxy at the same time:

```bash
sudo slipgate tunnel add --transport dnstt   --backend socks --tag dnstt1   --domain t.example.com
sudo slipgate tunnel add --transport vaydns  --backend socks --tag vaydns1  --domain v.example.com
sudo slipgate tunnel add --transport naive   --backend socks --tag naive1   --domain example.com --email you@example.com
```

Each tunnel becomes its own systemd service (`slipgate-dnstt1`, etc.). Manage them like any service:

```bash
sudo slipgate tunnel status
sudo slipgate tunnel start vaydns1
sudo slipgate tunnel stop vaydns1
sudo slipgate tunnel logs naive1
```

**Routing modes**
- **Single mode** — one DNS tunnel active; port 53 forwards to it.
- **Multi mode** — all DNS tunnels run on local ports; port 53 dispatches by domain.

```bash
sudo slipgate router status      # see current mode
sudo slipgate router mode        # switch between single and multi
sudo slipgate router switch      # change active tunnel (single mode only)
```

---

## 12. WARP outbound (optional)

Cloudflare WARP can be enabled as the server's **outbound** path — useful when:
- Your VPS provider's IP is blacklisted by sites your users want to reach (Netflix, OpenAI, ChatGPT, banking).
- You want to add an extra layer between the tunnel server and the public internet.

Enable it from the interactive menu (**WARP** option). SlipGate sets up a `wireguard-go` link to WARP and routes user traffic through it.

> Trade-off: a small latency penalty, and you depend on Cloudflare. Skip it if your VPS IP already reaches everywhere your users need.

---

## 13. Daily operations

**Live dashboard** — CPU, RAM, traffic sparklines, per-protocol connection counts, tunnel status:

```bash
sudo slipgate stats
```

**Diagnostics** — checks services, ports, keys, DNS resolution, boot persistence:

```bash
sudo slipgate diag
```

**Logs for a specific tunnel:**

```bash
sudo slipgate tunnel logs mytunnel
```

**Restart everything** (DNS router, SOCKS, all tunnels):

```bash
sudo slipgate restart
```

**Tune MTU on all DNS tunnels at once** — useful if links are flaky:

```bash
sudo slipgate mtu 1200
# Common values: 1232 (default), 1200 (cautious), 1100 (very flaky links)
```

**Tweak one tunnel:**

```bash
sudo slipgate tunnel edit --tag mydnstt --new-tag my-tunnel  # rename
sudo slipgate tunnel edit --tag mydnstt --mtu 1232           # change MTU
sudo slipgate tunnel status --tag mydnstt                    # keys, port, MTU
```

---

## 14. Updating SlipGate

Pulls the latest binary from GitHub releases and restarts services:

```bash
sudo slipgate update
```

The update is in-place — your tunnels, users, and keys are untouched. Existing client `slipnet://` URIs keep working.

---

## 15. Backup & migration

A backup holds everything needed to run your setup on another server: the config, every tunnel's private keys and certificates, and all users with their passwords. Restoring it on a new server brings back the same tunnels with the same keys, so clients keep working without new `slipnet://` URIs.

**Make a backup** (menu → 10 Backup / Restore, or):

```bash
sudo slipgate backup                              # asks: save to a file, or print as text to copy
sudo slipgate backup /root/slipgate-backup.txt
```

The backup is one block of text between a `-----BEGIN SLIPGATE BACKUP-----` and an `-----END SLIPGATE BACKUP-----` line, so you can keep it as a file or copy-paste it. It contains every private key and password: keep it private.

**Restore on a new server:**

1. Install SlipGate (`curl ... | sudo bash`). When the install wizard asks which transports to install, press Ctrl-C: the restore sets them up.
2. Run `sudo slipgate restore` and paste the text, or give the file: `sudo slipgate restore /root/slipgate-backup.txt`.
3. Point the DNS records at the new server's IP. Restore lists the ones to change (`ns.<your domain>`, and the domain of any NaiveProxy tunnel).

Restore installs the transport binaries, writes the keys and config, creates the users, opens the firewall ports, sets up WARP if it was on (with a new WARP account), and starts every service. If the server already has tunnels or users, they are replaced; the current setup is first saved to `/root/slipgate-pre-restore-<date>.txt`, which can be restored the same way.

Straight from one server to another:

```bash
ssh root@old-server slipgate backup - | ssh root@new-server slipgate restore - --yes
```

`-` writes the backup to stdout or reads it from stdin; `--yes` skips the confirmation question, which needs a terminal.

`slipgate config export` prints only `config.json`, without keys. Use `backup` to move a server.

---

## 16. A note on VLESS

The SlipNet client supports **VLESS** (over WebSocket / TLS, typically fronted through Cloudflare). **SlipGate does not run a VLESS server itself** — VLESS is part of the [Xray / V2Ray](https://github.com/XTLS/Xray-core) ecosystem.

If you want to give your users a VLESS option, you have two paths:

1. **Run Xray separately on the same VPS.** Standard Xray installers (e.g., `Xray-install`, `x-ui`, `3x-ui`) work fine alongside SlipGate, since they typically listen on a different port (or on 443 if SlipGate isn't using NaiveProxy/StunTLS). Your users build a manual VLESS profile in SlipNet using the UUID, domain, and CDN settings from your Xray panel.
2. **Skip VLESS** — SlipGate's six transports already cover most censorship environments. NaiveProxy and StunTLS solve the "443 is the only port left" problem.

VLESS support may land in SlipGate in the future. Track the channel for updates.

---

## 17. Troubleshooting

| Symptom | Try this |
|---------|----------|
| Tunnel won't start | `sudo slipgate diag` — checks ports, keys, DNS records |
| Client connects but no traffic | `sudo slipgate tunnel logs <tag>` for handshake / auth errors |
| Port 53 already in use | `sudo systemctl disable --now systemd-resolved` (then add `nameserver 1.1.1.1` to `/etc/resolv.conf`) |
| Let's Encrypt fails (NaiveProxy) | A record may not have propagated, or port 80 is blocked. Wait, then `sudo slipgate restart` |
| `dig` against your server times out | VPS provider blocks UDP/53 inbound. Switch provider or stick to NaiveProxy/StunTLS on 443 |
| User can't authenticate | `sudo slipgate users list` — confirm credentials present; check tunnel has matching backend |
| Slow DNS tunnel | Lower MTU: `sudo slipgate mtu 1200` |
| Multiple tunnels but only one works | `sudo slipgate router status` — confirm multi-mode is active |
| Need to reset a key | `sudo slipgate tunnel edit --tag <tag>` and regenerate; clients will need a fresh URI |

For deeper inspection, every tunnel is a regular systemd service:

```bash
journalctl -u slipgate-mytunnel -n 200 --no-pager
journalctl -u slipgate-dnsrouter -n 200 --no-pager
journalctl -u slipgate-socks5 -n 200 --no-pager
```

---

## 18. File locations & systemd reference

| Path | Description |
|------|-------------|
| `/etc/slipgate/config.json` | Main configuration (tunnels, users, routing mode) |
| `/etc/slipgate/tunnels/` | Per-tunnel keys, certs, configs |
| `/usr/local/bin/slipgate` | SlipGate binary |
| `/usr/local/bin/dnstt-server` | DNSTT/NoizDNS transport |
| `/usr/local/bin/slipstream-server` | Slipstream transport |
| `/usr/local/bin/vaydns-server` | VayDNS transport |
| `/usr/local/bin/caddy-naive` | NaiveProxy (Caddy + forwardproxy plugin) |
| `/etc/caddy/Caddyfile` | Caddy config (managed by SlipGate) |

**systemd units:**
- `slipgate-dnsrouter` — port 53 DNS dispatcher
- `slipgate-socks5` — built-in SOCKS5 proxy
- `slipgate-<tag>` — one per tunnel you create

---

## 19. Uninstalling

```bash
sudo slipgate uninstall
```

Removes all services, configs, and binaries. Your DNS records are untouched — delete them manually in your DNS provider's panel if you want.

---

Channel: [@SlipNet_app](https://t.me/SlipNet_app)
SlipGate source: https://github.com/anonvector/slipgate
SlipNet source: https://github.com/anonvector/SlipNet

---
---

# راهنمای کامل SlipGate برای ادمین (فارسی)

> سرور رسمی اپ اندرویدی [SlipNet](https://github.com/anonvector/SlipNet)
> سورس: https://github.com/anonvector/slipgate
> کانال SlipNet: [@SlipNet_app](https://t.me/SlipNet_app)

---

## فهرست

۱. SlipGate چیست
۲. پیش‌نیازها
۳. انتخاب VPS
۴. تنظیم دامنه و رکوردهای DNS
۵. نصب SlipGate
۶. منوی تعاملی در برابر CLI
۷. اولین تونل
۸. transportها — کدام را برای چه شبکه‌ای
۹. مدیریت کاربران
۱۰. اشتراک کانفیگ با کلاینت‌ها
۱۱. چند تونل هم‌زمان
۱۲. خروجی WARP (اختیاری)
۱۳. عملیات روزمره
۱۴. به‌روزرسانی SlipGate
۱۵. بکاپ و مهاجرت
۱۶. درباره‌ی VLESS
۱۷. عیب‌یابی
۱۸. مسیر فایل‌ها و systemd
۱۹. حذف نصب

---

## ۱. SlipGate چیست

SlipGate یک مدیر تونل تک‌باینری برای سرورهای لینوکس است. روی VPS اجرا می‌کنید و سمت سرور تمام پروتکل‌هایی که SlipNet پشتیبانی می‌کند — DNSTT، NoizDNS، VayDNS، Slipstream، NaiveProxy و StunTLS — به همراه سرویس‌های `systemd`، روتر DNS، مدیریت کاربر، داشبورد زنده و تولید لینک `slipnet://` برای ایمپورت یک‌ضربه‌ای در اپ راه‌اندازی می‌کند.

به‌طور خلاصه: **یک دستور** کافی است تا یک VPS تازه‌ی Ubuntu/Debian تبدیل به یک نقطه‌ی کامل ضد سانسور شود که گوشی شما (و دوستانتان) به آن وصل می‌شود.

SlipGate برای شما این کارها را انجام می‌دهد:
- نصب باینری‌های transport (`dnstt-server`، `slipstream-server`، `vaydns-server`، `caddy-naive`).
- تولید کلید Curve25519 برای هر تونل.
- پیکربندی یونیت‌های systemd که در بوت بالا می‌آیند.
- اجرای پراکسی SOCKS5 داخلی و یک روتر DNS که کوئری‌ها را بر اساس دامنه دیسپچ می‌کند.
- مدیریت کاربر (یک credential برای همه‌ی تونل‌ها).
- تولید خودکار گواهی Let's Encrypt برای NaiveProxy از طریق Caddy.
- خود-آپدیت از Releases گیت‌هاب.

---

## ۲. پیش‌نیازها

- یک **VPS لینوکس** با **دسترسی روت SSH** — اوبونتو ۲۰.۰۴ به بالا، دبیان ۱۰ به بالا یا هر توزیع مدرن مبتنی بر systemd.
- یک **دامنه** که DNS آن را در دست دارید (Cloudflare، Namecheap، Porkbun، یا پنل ثبت‌کننده).
- پورت‌های باز روی سرور:
  - `53/udp` برای تونل‌های DNS (DNSTT، NoizDNS، VayDNS، Slipstream)
  - `443/tcp` برای NaiveProxy و StunTLS
- حدود **۱۵ دقیقه** زمان.
- **هزینه:** یک VPS ۴ تا ۶ دلاری در ماه برای مصرف شخصی کافی است.

---

## ۳. انتخاب VPS

«درست‌»بودن VPS بستگی به محل کاربران شما دارد.

از سرویس‌دهنده‌هایی که UDP/53 ورودی را می‌بندند **پرهیز کنید** (تونل DNS کار نمی‌کند):
- DigitalOcean در اکثر پلن‌ها UDP/53 را می‌بندد.
- AWS در Lightsail و EC2 (با security group پیش‌فرض) UDP/53 را می‌بندد.
- بعضی ابرهای بزرگ آمریکا UDP را به‌شدت محدود می‌کنند.

**انتخاب‌های خوب** برای کاربران ایران (و مشابه):
- **Hetzner** (آلمان / فنلاند) — ارزان، سریع، بدون محدودیت پورت.
- **Contabo** (آلمان) — خیلی ارزان، پهنای باند سخاوتمندانه.
- **OVH** (اروپا) — بدون محدودیت پورت.
- **BuyVM** — کوچک ولی پایدار.
- سرویس‌دهنده‌های کوچک‌تر اروپا یا آسیا — معمولاً خوب هستند.

**منطقه‌ای انتخاب کنید که از نظر جغرافیایی به کاربران نزدیک باشد** ولی توسط ISP آن‌ها بلاک نشده باشد. برای ایران، آلمان / فنلاند / هلند معمولاً جواب می‌دهد.

**سایز:** ۱ vCPU، ۱ GB RAM، ۲۰ GB دیسک برای سرور شخصی/گروه کوچک کافی است. پهنای باند مهم‌تر از CPU است.

---

## ۴. تنظیم دامنه و رکوردهای DNS

به یک دامنه نیاز دارید (مثلاً `example.com`). قبل از نصب SlipGate این رکوردها را اضافه کنید:

```
A    ns.example.com   →  <server IP>
A    example.com      →  <server IP>          (فقط اگر NaiveProxy / StunTLS می‌خواهید)

NS   t.example.com    →  ns.example.com       (DNSTT/NoizDNS — backend SOCKS)
NS   ts.example.com   →  ns.example.com       (DNSTT/NoizDNS — backend SSH)
NS   s.example.com    →  ns.example.com       (Slipstream — backend SOCKS)
NS   ss.example.com   →  ns.example.com       (Slipstream — backend SSH)
NS   v.example.com    →  ns.example.com       (VayDNS — backend SOCKS)
NS   vs.example.com   →  ns.example.com       (VayDNS — backend SSH)
```

فقط رکوردهای تونل‌هایی که می‌خواهید استفاده کنید لازم است. **حداقل**:
- فقط NaiveProxy: همان `A example.com → <IP>` کافی است.
- فقط DNSTT: `A ns.example.com → <IP>` به‌علاوه `NS t.example.com → ns.example.com`.

**نکته‌ی مهم درباره‌ی NS delegation**: رکورد `NS` یعنی «کوئری برای `t.example.com` برو به `ns.example.com` که روی `<server IP>` است.» پورت ۵۳ سرور شما با باینری تونل DNS پاسخ می‌دهد.

پراپاگیت DNS از چند دقیقه تا چند ساعت طول می‌کشد. تأیید با:

```bash
dig +short NS t.example.com
dig +short A ns.example.com
```

> اگر از **Cloudflare** برای DNS استفاده می‌کنید، رکوردها را روی **DNS only** (ابر خاکستری) بگذارید. proxy نکنید — تونل به DNS خام روی سرور نیاز دارد.

---

## ۵. نصب SlipGate

با SSH به‌عنوان روت به سرور وصل شوید:

```bash
curl -fsSL https://raw.githubusercontent.com/anonvector/slipgate/main/install.sh | sudo bash
```

اسکریپت:
- توزیع شما را تشخیص می‌دهد.
- پکیج‌های لازم سیستم را نصب می‌کند.
- باینری SlipGate و `dnstt-server`، `slipstream-server`، `vaydns-server` و `caddy-naive` را دانلود می‌کند.
- سرویس‌های systemd (`slipgate-dnsrouter`، `slipgate-socks5`) را نصب می‌کند.
- در صورت نیاز قواعد فایروال را تنظیم می‌کند.

**نصب آفلاین** (اگر VPS به گیت‌هاب دسترسی ندارد):

۱. روی لپ‌تاپ از https://github.com/anonvector/slipgate/releases دانلود کنید.
۲. باینری‌ها را با SCP به سرور بفرستید: `scp slipgate-* user@server:/tmp/slipgate/`
۳. روی سرور: `sudo slipgate install --bin-dir /tmp/slipgate`

پس از نصب، منوی تعاملی را باز کنید:

```bash
sudo slipgate
```

---

## ۶. منوی تعاملی در برابر CLI

SlipGate دو رابط دارد:

**TUI تعاملی** — `sudo slipgate` بدون پارامتر. منوی دوستانه‌ای که شما را در ساخت تونل، کاربر، آمار و عیب‌یابی راه می‌برد. برای نصب اولیه و کاوش بهترین انتخاب است.

**زیردستورهای CLI** — برای اسکریپت و اتوماسیون. هر گزینه‌ی منو یک معادل CLI دارد:

```
slipgate install                نصب وابستگی‌ها و راه‌اندازی سرور
slipgate uninstall              حذف همه‌چیز
slipgate update                 خود-آپدیت + ری‌استارت سرویس‌ها
slipgate restart                ری‌استارت همه سرویس‌ها
slipgate backup [file]          بکاپ کانفیگ، کلیدها و کاربران (فایل یا متن برای کپی‌پیست)
slipgate restore [file]         ریستور بکاپ روی این سرور
slipgate users                  افزودن / لیست / حذف کاربر (تعاملی)
slipgate users add              افزودن یک کاربر
slipgate users bulk_add         افزودن گروهی با پسورد تصادفی
slipgate users list             لیست کاربران + کانفیگ تونل‌ها
slipgate stats                  داشبورد زنده
slipgate diag                   اجرای بررسی‌های تشخیصی
slipgate mtu [value]            تنظیم MTU روی همه‌ی تونل‌های DNS

slipgate tunnel add             افزودن یک تونل
slipgate tunnel edit [tag]      ویرایش (نام، MTU، کلید)
slipgate tunnel remove [tag]    حذف یک تونل
slipgate tunnel remove --all    حذف همه‌ی تونل‌ها
slipgate tunnel start [tag]     استارت تونل
slipgate tunnel stop [tag]      استاپ تونل
slipgate tunnel status [tag]    وضعیت / جزئیات
slipgate tunnel share [tag]     چاپ slipnet:// URI + QR
slipgate tunnel logs [tag]      دیدن لاگ‌های systemd

slipgate router status          وضعیت روتر DNS
slipgate router mode            تعویض single ↔ multi
slipgate router switch          تغییر تونل فعال (single mode)

slipgate config export          چاپ config.json (بدون کلیدها؛ برای انتقال سرور از backup استفاده کنید)
slipgate config import [path]   جایگزینی config.json (بدون کلیدها)
```

---

## ۷. اولین تونل

ساده‌ترین راه‌اندازی ممکن — یک تونل DNSTT با backend SOCKS5 داخلی:

```bash
sudo slipgate tunnel add \
  --transport dnstt \
  --backend socks \
  --tag mytunnel \
  --domain t.example.com
```

این کار:
۱. یک کلید Curve25519 جدید می‌سازد.
۲. `dnstt-server` را روی UDP/53 برای `t.example.com` اجرا می‌کند.
۳. ترافیک رمزگشایی‌شده را به پراکسی SOCKS5 داخلی (`127.0.0.1:1080`) می‌فرستد.
۴. سرویس systemd `slipgate-mytunnel` می‌سازد که در بوت اجرا می‌شود.

**تأیید اجرا:**

```bash
sudo slipgate tunnel status
```

تونل باید **active** نشان داده شود. اگر مشکلی هست:

```bash
sudo slipgate diag
```

---

## ۸. transportها — کدام برای چه شبکه‌ای

SlipGate شش transport را مدیریت می‌کند. بر اساس شبکه‌ای که کاربران از آن می‌خواهند فرار کنند انتخاب کنید.

| Transport | پورت | چیست | کاربرد |
|-----------|------|------|--------|
| **DNSTT** | 53/udp | تونل DNS رمزنگاری‌شده (Curve25519). پایدار، بالغ | پیش‌فرض؛ سرور یکسان به کلاینت‌های NoizDNS هم پاسخ می‌دهد |
| **NoizDNS** | 53/udp | همان سرور DNSTT — کلاینت‌ها مقاومت DPI را روشن می‌کنند | شبکه DNS-tunnel-detection دارد |
| **VayDNS** | 53/udp | تونل DNS مبتنی بر KCP، فرمت سیمی قابل تنظیم | پیشرفته؛ مسیر DNS ناپایدار؛ نیاز به تنظیم record-type |
| **Slipstream** | 53/udp | QUIC روی DNS، خیلی سریع | شبکه سالم؛ کاربر سرعت می‌خواهد |
| **NaiveProxy** | 443/tcp | Caddy + forwardproxy، گواهی Let's Encrypt واقعی، سایت decoy | تونل DNS بسته است؛ HTTPS باز است |
| **StunTLS** | 443/tcp | SSH روی TLS / SSH روی WebSocket، گواهی self-signed | دامنه نداری؛ یا لایه‌ی WS سازگار با CDN می‌خواهی |

**Backendها:**
- `socks` — پراکسی SOCKS5 داخلی (Go). ساده، سریع، بدون اوورهد SSH.
- `ssh` — OpenSSH سرور forwarding می‌کند. نشت DNS صفر، کمی امن‌تر.
- `both` — هر دو تونل را موازی می‌سازد (مثلاً `mytunnel-socks` و `mytunnel-ssh`). زیردامنه‌ی دوم با اضافه کردن `s` خودکار تولید می‌شود.

**نمونه‌ها:**

```bash
# VayDNS — تونل DNS جدیدتر و بهینه
sudo slipgate tunnel add --transport vaydns --backend socks \
  --tag myvaydns --domain v.example.com

# VayDNS با تمام پارامترها
sudo slipgate tunnel add --transport vaydns --backend both \
  --tag myvaydns --domain v.example.com \
  --record-type txt --idle-timeout 10s --keep-alive 2s \
  --clientid-size 2 --queue-size 512

# Slipstream روی QUIC
sudo slipgate tunnel add --transport slipstream --backend ssh \
  --tag myslip --domain s.example.com

# NaiveProxy — گواهی Let's Encrypt خودکار
sudo slipgate tunnel add --transport naive --backend socks \
  --tag myproxy --domain example.com \
  --email admin@example.com --decoy-url https://www.wikipedia.org

# StunTLS — SSH روی TLS + WebSocket، نیاز به دامنه ندارد
sudo slipgate tunnel add --transport stuntls --tag mytls

# SSH یا SOCKS5 مستقیم (بدون transport تونل)
sudo slipgate tunnel add --transport direct-ssh --tag myssh
sudo slipgate tunnel add --transport direct-socks5 --tag mysocks

# External: کوئری DNS یک دامنه را به پورت UDP خاص هدایت کن (پروتکل دلخواه)
sudo slipgate tunnel add --transport external --tag my-proto \
  --domain j.example.com --port 5301
```

---

## ۹. مدیریت کاربران

کاربر در SlipGate **سراسری** است. همان `username:password` روی همه‌ی تونل‌ها معتبر است، فارغ از transport. پروتکل ویژگی **تونل** است نه کاربر.

> ⚠️ **هیچ‌وقت اکانت `root` سرور (یا هر اکانت sudoer / لاگین shell) را به‌عنوان credential VPN در اختیار کاربران نگذارید.** کاربر SlipGate یک اکانت ایزوله‌ی SOCKS/SSH-forwarding است که دسترسی shell ندارد — اگر یکی لو برود، فقط دسترسی به تونل از دست می‌رود. اما لو رفتن `root` یعنی از دست رفتن کل سرور: کلیدها، credential سایر کاربران و هر سرویس دیگری که روی سرور است. همیشه برای هر کسی که کانفیگ می‌دهید (حتی خودتان) با `slipgate users add` (یا `bulk_add`) یک کاربر مخصوص بسازید.

**افزودن یک کاربر (تعاملی):**

```bash
sudo slipgate users add
```

نام کاربری و رمز را خواهد پرسید.

**ساخت گروهی با پسورد تصادفی (تا ۵۰۰ نفر در یک مرحله):**

```bash
sudo slipgate users bulk_add --count=50 --prefix=user
# می‌سازد user001 تا user050
```

**لیست کاربران به همراه کانفیگ هر تونل:**

```bash
sudo slipgate users list
```

برای هر زوج (کاربر × تونل) یک بلوک کانفیگ چاپ می‌شود، شامل URI به فرمت `slipnet://`.

**حذف کاربر:**

```bash
sudo slipgate users remove
```

> پیشنهاد: اگر گروه کوچک دارید، به هر نفر یک نام کاربری منحصربه‌فرد بدهید تا در صورت گم شدن گوشی فقط همان را revoke کنید.

---

## ۱۰. اشتراک کانفیگ با کلاینت‌ها

پس از ساخت تونل، یک URI به فرمت `slipnet://` بسازید:

```bash
sudo slipgate tunnel share mytunnel
```

این چاپ می‌کند:
- یک URI `slipnet://...` (رشته‌ی base64 طولانی).
- یک کد QR (در TUI).

URI را به کاربر بدهید. در SlipNet **+ → Import from URI** را می‌زند → پیست → تمام.

برای تونل DNSTT، دستور share می‌پرسد پروفایل **DNSTT** بسازد یا **NoizDNS**. سرور یکسان است — NoizDNS فقط مقاومت در برابر DPI را در کلاینت روشن می‌کند:
- پروفایل **DNSTT**: کمی سریع‌تر، تشخیص آسان‌تر.
- پروفایل **NoizDNS**: کندتر، تشخیص سخت‌تر.

> ⚠️ این URI شامل اطلاعات کاربر است. در کانال خصوصی بفرستید، نه گروه عمومی.

---

## ۱۱. چند تونل هم‌زمان

می‌توانید هر تعداد تونل می‌خواهید اجرا کنید. SlipGate وقتی تونل DNS دوم را می‌سازید خودکار به **multi-mode** سوییچ می‌کند — روتر DNS روی پورت ۵۳ کوئری را بر اساس دامنه به تونل درست می‌فرستد.

مثال: DNSTT + VayDNS + NaiveProxy هم‌زمان:

```bash
sudo slipgate tunnel add --transport dnstt   --backend socks --tag dnstt1   --domain t.example.com
sudo slipgate tunnel add --transport vaydns  --backend socks --tag vaydns1  --domain v.example.com
sudo slipgate tunnel add --transport naive   --backend socks --tag naive1   --domain example.com --email you@example.com
```

هر تونل سرویس systemd خودش را دارد (`slipgate-dnstt1` و…). مثل هر سرویس مدیریتش کنید:

```bash
sudo slipgate tunnel status
sudo slipgate tunnel start vaydns1
sudo slipgate tunnel stop vaydns1
sudo slipgate tunnel logs naive1
```

**حالت‌های روتر**
- **Single mode** — یک تونل DNS فعال؛ پورت ۵۳ به آن فوروارد می‌کند.
- **Multi mode** — همه‌ی تونل‌های DNS روی پورت‌های local؛ پورت ۵۳ بر اساس دامنه دیسپچ می‌کند.

```bash
sudo slipgate router status      # حالت فعلی
sudo slipgate router mode        # تغییر بین single و multi
sudo slipgate router switch      # تغییر تونل فعال (فقط در single mode)
```

---

## ۱۲. خروجی WARP (اختیاری)

می‌توانید Cloudflare WARP را به‌عنوان مسیر **خروجی** سرور فعال کنید — مفید وقتی:
- IP سرویس‌دهنده‌ی VPS شما توسط سایت‌های مقصد بلاک شده (Netflix، OpenAI، ChatGPT، بانک).
- می‌خواهید لایه‌ی اضافی بین سرور تونل و اینترنت عمومی داشته باشید.

از منوی تعاملی گزینه‌ی **WARP** را روشن کنید. SlipGate یک لینک `wireguard-go` به WARP می‌سازد و ترافیک کاربر را از آن عبور می‌دهد.

> هزینه: کمی تأخیر و وابستگی به Cloudflare. اگر IP VPS شما همه‌جای موردنیاز کاربر را می‌رسد، WARP لازم نیست.

---

## ۱۳. عملیات روزمره

**داشبورد زنده** — CPU، RAM، اسپارک‌لاین ترافیک، تعداد کانکشن هر پروتکل، وضعیت تونل‌ها:

```bash
sudo slipgate stats
```

**تشخیص** — بررسی سرویس‌ها، پورت‌ها، کلیدها، DNS و پایداری بعد از بوت:

```bash
sudo slipgate diag
```

**لاگ یک تونل خاص:**

```bash
sudo slipgate tunnel logs mytunnel
```

**ری‌استارت همه چیز** (روتر DNS، SOCKS، تمام تونل‌ها):

```bash
sudo slipgate restart
```

**تنظیم MTU برای همه‌ی تونل‌های DNS** — وقتی شبکه ناپایدار است:

```bash
sudo slipgate mtu 1200
# مقادیر معمول: 1232 (پیش‌فرض)، 1200 (محتاط)، 1100 (شبکه خیلی ناپایدار)
```

**ویرایش یک تونل:**

```bash
sudo slipgate tunnel edit --tag mydnstt --new-tag my-tunnel  # تغییر نام
sudo slipgate tunnel edit --tag mydnstt --mtu 1232           # تغییر MTU
sudo slipgate tunnel status --tag mydnstt                    # کلید، پورت، MTU
```

---

## ۱۴. به‌روزرسانی SlipGate

آخرین باینری از Releases گیت‌هاب را می‌گیرد و سرویس‌ها را ری‌استارت می‌کند:

```bash
sudo slipgate update
```

به‌روزرسانی in-place است — تونل‌ها، کاربران و کلیدها دست‌نخورده می‌مانند. URIهای کلاینت موجود کار می‌کنند.

---

## ۱۵. بکاپ و مهاجرت

بکاپ همه‌ی چیزهایی را که برای اجرای همین تنظیمات روی سرور دیگری لازم است در خود دارد: کانفیگ، کلیدهای خصوصی و گواهی‌های همه‌ی تونل‌ها، و همه‌ی کاربران با رمزهایشان. با ریستور آن روی سرور جدید، همان تونل‌ها با همان کلیدها برمی‌گردند و کلاینت‌ها بدون URI جدید `slipnet://` کار می‌کنند.

**گرفتن بکاپ** (منو ← ۱۰ Backup / Restore، یا):

```bash
sudo slipgate backup                              # می‌پرسد: ذخیره در فایل یا چاپ به‌صورت متن برای کپی
sudo slipgate backup /root/slipgate-backup.txt
```

بکاپ یک بلوک متن بین خط `-----BEGIN SLIPGATE BACKUP-----` و خط `-----END SLIPGATE BACKUP-----` است؛ می‌توانید آن را به‌صورت فایل نگه دارید یا کپی‌پیست کنید. این متن شامل همه‌ی کلیدهای خصوصی و رمزهاست: آن را خصوصی نگه دارید.

**ریستور روی سرور جدید:**

۱. SlipGate را نصب کنید (`curl ... | sudo bash`). وقتی ویزارد نصب پرسید کدام ترنسپورت‌ها نصب شوند، Ctrl-C بزنید؛ ریستور آن‌ها را راه‌اندازی می‌کند.
۲. `sudo slipgate restore` را اجرا کنید و متن را پیست کنید، یا فایل را بدهید: `sudo slipgate restore /root/slipgate-backup.txt`
۳. رکوردهای DNS را به IP سرور جدید تغییر دهید. ریستور رکوردهایی را که باید عوض شوند نشان می‌دهد (`ns.<دامنه‌ی شما>` و دامنه‌ی تونل‌های NaiveProxy).

ریستور باینری‌های ترنسپورت را نصب می‌کند، کلیدها و کانفیگ را می‌نویسد، کاربران را می‌سازد، پورت‌های فایروال را باز می‌کند، اگر WARP روشن بوده آن را (با یک اکانت WARP جدید) راه‌اندازی می‌کند و همه‌ی سرویس‌ها را اجرا می‌کند. اگر روی سرور از قبل تونل یا کاربری باشد، جایگزین می‌شود؛ تنظیمات فعلی پیش از آن در `/root/slipgate-pre-restore-<تاریخ>.txt` ذخیره می‌شود و به همین روش قابل ریستور است.

مستقیم از یک سرور به سرور دیگر:

```bash
ssh root@old-server slipgate backup - | ssh root@new-server slipgate restore - --yes
```

`-` بکاپ را در stdout می‌نویسد یا از stdin می‌خواند؛ `--yes` سؤال تأیید را رد می‌کند، چون آن سؤال به ترمینال نیاز دارد.

`slipgate config export` فقط `config.json` را بدون کلیدها چاپ می‌کند. برای انتقال سرور از `backup` استفاده کنید.

---

## ۱۶. درباره‌ی VLESS

اپ SlipNet از **VLESS** پشتیبانی می‌کند (روی WebSocket / TLS، معمولاً پشت Cloudflare). **اما SlipGate خودش سرور VLESS اجرا نمی‌کند** — VLESS بخشی از اکوسیستم [Xray / V2Ray](https://github.com/XTLS/Xray-core) است.

اگر می‌خواهید به کاربران گزینه‌ی VLESS بدهید، دو راه دارید:

۱. **Xray را جدا روی همان VPS اجرا کنید.** نصاب‌های استاندارد Xray (مثل `Xray-install`، `x-ui`، `3x-ui`) در کنار SlipGate خوب کار می‌کنند، چون معمولاً روی پورت متفاوتی گوش می‌دهند (یا روی ۴۴۳ اگر SlipGate از NaiveProxy/StunTLS استفاده نمی‌کند). کاربر شما در SlipNet به‌صورت دستی پروفایل VLESS می‌سازد با UUID، دامنه، و تنظیمات CDN از پنل Xray شما.
۲. **VLESS را رها کنید** — شش transport SlipGate برای اکثر محیط‌های سانسوری کافی است. NaiveProxy و StunTLS مشکل «فقط ۴۴۳ باز است» را حل می‌کنند.

ممکن است در آینده پشتیبانی VLESS به SlipGate اضافه شود. کانال را برای اپدیت دنبال کنید.

---

## ۱۷. عیب‌یابی

| نشانه | راه‌حل |
|-------|------|
| تونل بالا نمی‌آید | `sudo slipgate diag` — پورت‌ها، کلیدها و رکوردهای DNS را بررسی می‌کند |
| کلاینت وصل می‌شود ولی ترافیک نمی‌رود | `sudo slipgate tunnel logs <tag>` برای دیدن خطای handshake / احراز هویت |
| پورت ۵۳ از قبل اشغال است | `sudo systemctl disable --now systemd-resolved` (سپس `nameserver 1.1.1.1` به `/etc/resolv.conf` اضافه کنید) |
| Let's Encrypt در NaiveProxy fail می‌شود | احتمالاً رکورد A پراپاگیت نشده یا پورت ۸۰ بسته است. صبر کنید و `sudo slipgate restart` |
| `dig` به سرور تایم‌اوت می‌شود | سرویس‌دهنده UDP/53 ورودی را می‌بندد. سرویس‌دهنده عوض کنید یا به NaiveProxy/StunTLS روی ۴۴۳ بسنده کنید |
| کاربر احراز نمی‌شود | `sudo slipgate users list` — وجود credential را بررسی کنید؛ مطمئن شوید تونل backend متناظر دارد |
| تونل DNS کند است | MTU را پایین بیاورید: `sudo slipgate mtu 1200` |
| چند تونل ساخته‌ام ولی فقط یکی کار می‌کند | `sudo slipgate router status` — تأیید کنید multi-mode فعال است |
| نیاز به ریست کلید دارم | `sudo slipgate tunnel edit --tag <tag>` و کلید جدید بسازید؛ کلاینت‌ها به URI جدید نیاز دارند |

برای بررسی عمیق‌تر، هر تونل یک سرویس systemd معمولی است:

```bash
journalctl -u slipgate-mytunnel -n 200 --no-pager
journalctl -u slipgate-dnsrouter -n 200 --no-pager
journalctl -u slipgate-socks5 -n 200 --no-pager
```

---

## ۱۸. مسیر فایل‌ها و systemd

| مسیر | توضیح |
|------|------|
| `/etc/slipgate/config.json` | کانفیگ اصلی (تونل، کاربر، حالت روتینگ) |
| `/etc/slipgate/tunnels/` | کلید، گواهی و کانفیگ هر تونل |
| `/usr/local/bin/slipgate` | باینری SlipGate |
| `/usr/local/bin/dnstt-server` | باینری DNSTT/NoizDNS |
| `/usr/local/bin/slipstream-server` | باینری Slipstream |
| `/usr/local/bin/vaydns-server` | باینری VayDNS |
| `/usr/local/bin/caddy-naive` | NaiveProxy (Caddy + پلاگین forwardproxy) |
| `/etc/caddy/Caddyfile` | کانفیگ Caddy (مدیریت‌شده توسط SlipGate) |

**یونیت‌های systemd:**
- `slipgate-dnsrouter` — دیسپچر DNS روی پورت ۵۳
- `slipgate-socks5` — پراکسی SOCKS5 داخلی
- `slipgate-<tag>` — یکی به ازای هر تونل

---

## ۱۹. حذف نصب

```bash
sudo slipgate uninstall
```

تمام سرویس‌ها، کانفیگ‌ها و باینری‌ها حذف می‌شوند. رکوردهای DNS دست‌نخورده می‌مانند — اگر می‌خواهید، در پنل DNS خودتان دستی پاک کنید.

---

کانال: [@SlipNet_app](https://t.me/SlipNet_app)
سورس SlipGate: https://github.com/anonvector/slipgate
سورس SlipNet: https://github.com/anonvector/SlipNet
