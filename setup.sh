#!/usr/bin/env bash
set -euo pipefail

# ══════════════════════════════════════════
#  SlipNet Server Setup — NaiveProxy + SSH
# ══════════════════════════════════════════

clear
STEP=""
cleanup() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 && -n "${STEP}" ]]; then
        echo ""
        echo "ERROR: Failed during: ${STEP}"
        echo "Fix the issue and re-run the script."
        rm -f ./caddy 2>/dev/null || true
    fi
    exit ${exit_code}
}
trap cleanup ERR

# ─── Helper functions ───────────────────

generate_password() {
    local length="${1:-24}"
    head -c 256 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "${length}"
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "Error: This script must be run as root."
        echo "Usage: sudo bash setup.sh"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        echo "Error: Cannot detect OS (missing /etc/os-release)."
        exit 1
    fi
    source /etc/os-release
    case "${ID}" in
        ubuntu)
            local major="${VERSION_ID%%.*}"
            if [[ "${major}" -lt 20 ]]; then
                echo "Error: Ubuntu 20.04 or newer required (detected ${VERSION_ID})."
                exit 1
            fi
            ;;
        debian)
            local major="${VERSION_ID%%.*}"
            if [[ "${major}" -lt 11 ]]; then
                echo "Error: Debian 11 or newer required (detected ${VERSION_ID})."
                exit 1
            fi
            ;;
        *)
            echo "Error: Only Ubuntu 20.04+ and Debian 11+ are supported (detected ${ID})."
            exit 1
            ;;
    esac
    echo "  OS: ${PRETTY_NAME} — OK"
}

is_installed() {
    [[ -f /usr/bin/caddy-naive ]] && [[ -f /etc/systemd/system/caddy-naive.service ]]
}

print_header() {
    echo ""
    echo "══════════════════════════════════════════"
    echo "  SlipNet Server — NaiveProxy + SSH"
    echo "══════════════════════════════════════════"
}

# ─── Menu ───────────────────────────────

show_menu() {
    print_header

    if is_installed; then
        local status="installed"
        if systemctl is-active --quiet caddy-naive 2>/dev/null; then
            status="running"
        fi
        echo "  Status: caddy-naive is ${status}"
    else
        echo "  Status: not installed"
    fi

    echo ""
    echo "  1) Install         Set up NaiveProxy server"
    echo "  2) Reconfigure     Change domain/credentials"
    echo "  3) Show config     Print current credentials"
    echo "  4) Uninstall       Remove everything"
    echo "  0) Exit"
    echo ""
    read -rp "  Choose [0-4]: " choice
    echo ""

    case "${choice}" in
        1) do_install ;;
        2) do_reconfigure ;;
        3) do_show_config ;;
        4) do_uninstall ;;
        0) exit 0 ;;
        *)
            echo "Invalid choice."
            exit 1
            ;;
    esac
}

# ─── Install ────────────────────────────

do_install() {
    STEP="Pre-flight checks"
    echo "[Pre-flight] Checking requirements..."

    check_os

    if is_installed; then
        echo ""
        echo "  caddy-naive is already installed."
        echo "  Use option 2 (Reconfigure) to change settings,"
        echo "  or option 4 (Uninstall) first."
        exit 0
    fi

    # Check ports 80 and 443
    for port in 80 443; do
        if ss -tlnp | grep -q ":${port} "; then
            echo "Error: Port ${port} is already in use."
            ss -tlnp | grep ":${port} " || true
            echo ""
            echo "Stop the process using port ${port} and re-run this script."
            exit 1
        fi
    done
    echo "  Ports 80, 443 — free"
    echo ""

    # ─── Prompts ────────────────────────

    STEP="Interactive prompts"

    read -rp "Domain name (e.g. example.com): " DOMAIN
    if [[ -z "${DOMAIN}" ]]; then
        echo "Error: Domain name is required."
        exit 1
    fi

    DEFAULT_EMAIL="admin@${DOMAIN}"
    read -rp "Email for Let's Encrypt [${DEFAULT_EMAIL}]: " EMAIL
    EMAIL="${EMAIL:-${DEFAULT_EMAIL}}"

    DEFAULT_USER="$(generate_password 8)"
    read -rp "Proxy username [${DEFAULT_USER}]: " PROXY_USER
    PROXY_USER="${PROXY_USER:-${DEFAULT_USER}}"

    DEFAULT_PASS="$(generate_password 24)"
    read -rp "Proxy password [${DEFAULT_PASS}]: " PROXY_PASS
    PROXY_PASS="${PROXY_PASS:-${DEFAULT_PASS}}"

    DEFAULT_DECOY="https://www.wikipedia.org"
    read -rp "Decoy website URL [${DEFAULT_DECOY}]: " DECOY_URL
    DECOY_URL="${DECOY_URL:-${DEFAULT_DECOY}}"

    echo ""
    echo "  Domain:   ${DOMAIN}"
    echo "  Email:    ${EMAIL}"
    echo "  Username: ${PROXY_USER}"
    echo "  Password: ${PROXY_PASS}"
    echo "  Decoy:    ${DECOY_URL}"
    echo ""
    read -rp "Proceed with these settings? [Y/n] " proceed
    if [[ "${proceed}" == [nN] ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""

    # ─── Dependencies ───────────────────

    STEP="Installing dependencies"
    echo "[1/6] Installing dependencies..."

    apt-get update -qq
    apt-get install -y -qq curl git golang-go > /dev/null 2>&1 || \
        apt-get install -y -qq curl git > /dev/null 2>&1

    ensure_go
    echo "  Dependencies installed."

    # ─── Build Caddy ────────────────────

    STEP="Building Caddy with forwardproxy"
    echo "[2/6] Building Caddy with NaiveProxy plugin (this may take a few minutes)..."

    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

    BUILD_DIR="$(mktemp -d)"
    pushd "${BUILD_DIR}" > /dev/null

    "${GOPATH}/bin/xcaddy" build \
        --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive

    mv caddy /usr/bin/caddy-naive
    chmod +x /usr/bin/caddy-naive
    setcap cap_net_bind_service=+ep /usr/bin/caddy-naive

    popd > /dev/null
    rm -rf "${BUILD_DIR}"

    echo "  Built: $(/usr/bin/caddy-naive version)"

    # ─── Caddyfile ──────────────────────

    write_caddyfile

    # ─── Systemd service ────────────────

    STEP="Creating systemd service"
    echo "[4/6] Creating systemd service..."

    cat > /etc/systemd/system/caddy-naive.service <<'UNITEOF'
[Unit]
Description=SlipNet Caddy-Naive Proxy Server
Documentation=https://github.com/klzgrad/naiveproxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/caddy-naive run --config /etc/caddy-naive/Caddyfile
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNITEOF

    echo "  Created /etc/systemd/system/caddy-naive.service"

    # ─── Firewall ───────────────────────

    STEP="Configuring firewall"
    echo "[5/6] Checking firewall..."

    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow 80,443/tcp > /dev/null 2>&1
        echo "  UFW: allowed ports 80, 443/tcp"
    else
        echo "  UFW not active, skipping. Make sure ports 80 and 443 are open."
    fi

    # ─── Start service ──────────────────

    start_and_verify

    # ─── Summary ────────────────────────

    print_summary
}

# ─── Reconfigure ────────────────────────

do_reconfigure() {
    if ! is_installed; then
        echo "caddy-naive is not installed. Use option 1 (Install) first."
        exit 1
    fi

    STEP="Reconfigure"

    # Read current values from Caddyfile
    local current_caddyfile="/etc/caddy-naive/Caddyfile"
    local current_domain current_email current_user current_pass current_decoy
    current_domain="$(grep -oP '^:443, \K[^ ]+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_domain=""
    current_email="$(grep -oP 'tls \K\S+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_email=""
    current_user="$(grep -oP 'basic_auth \K\S+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_user=""
    current_pass="$(grep -oP 'basic_auth \S+ \K\S+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_pass=""
    current_decoy="$(grep -oP 'reverse_proxy \K\S+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_decoy=""

    echo "Current configuration:"
    echo "  Domain:   ${current_domain}"
    echo "  Email:    ${current_email}"
    echo "  Username: ${current_user}"
    echo "  Password: ${current_pass}"
    echo "  Decoy:    ${current_decoy}"
    echo ""
    echo "Press Enter to keep current value."
    echo ""

    read -rp "Domain name [${current_domain}]: " DOMAIN
    DOMAIN="${DOMAIN:-${current_domain}}"

    read -rp "Email for Let's Encrypt [${current_email}]: " EMAIL
    EMAIL="${EMAIL:-${current_email}}"

    read -rp "Proxy username [${current_user}]: " PROXY_USER
    PROXY_USER="${PROXY_USER:-${current_user}}"

    read -rp "Proxy password [${current_pass}]: " PROXY_PASS
    PROXY_PASS="${PROXY_PASS:-${current_pass}}"

    read -rp "Decoy website URL [${current_decoy}]: " DECOY_URL
    DECOY_URL="${DECOY_URL:-${current_decoy}}"

    echo ""
    echo "  Domain:   ${DOMAIN}"
    echo "  Email:    ${EMAIL}"
    echo "  Username: ${PROXY_USER}"
    echo "  Password: ${PROXY_PASS}"
    echo "  Decoy:    ${DECOY_URL}"
    echo ""
    read -rp "Apply these settings? [Y/n] " proceed
    if [[ "${proceed}" == [nN] ]]; then
        echo "Aborted."
        exit 0
    fi

    echo ""
    systemctl stop caddy-naive 2>/dev/null || true

    write_caddyfile
    start_and_verify
    print_summary
}

# ─── Show config ────────────────────────

do_show_config() {
    if ! is_installed; then
        echo "caddy-naive is not installed."
        exit 1
    fi

    local caddyfile="/etc/caddy-naive/Caddyfile"
    if [[ ! -f "${caddyfile}" ]]; then
        echo "Error: Caddyfile not found at ${caddyfile}"
        exit 1
    fi

    local domain email user pass
    domain="$(grep -oP '^:443, \K[^ ]+' "${caddyfile}" 2>/dev/null | head -1)" || domain="unknown"
    email="$(grep -oP 'tls \K\S+' "${caddyfile}" 2>/dev/null | head -1)" || email="unknown"
    user="$(grep -oP 'basic_auth \K\S+' "${caddyfile}" 2>/dev/null | head -1)" || user="unknown"
    pass="$(grep -oP 'basic_auth \S+ \K\S+' "${caddyfile}" 2>/dev/null | head -1)" || pass="unknown"

    local status="stopped"
    if systemctl is-active --quiet caddy-naive 2>/dev/null; then
        status="running"
    fi

    echo "══════════════════════════════════════════"
    echo " SlipNet Server — Current Configuration"
    echo "══════════════════════════════════════════"
    echo " Status:         ${status}"
    echo " Domain:         ${domain}"
    echo " Email:          ${email}"
    echo " Proxy Username: ${user}"
    echo " Proxy Password: ${pass}"
    echo " Proxy Port:     443"
    echo "──────────────────────────────────────────"
    echo " SlipNet App Profile Settings:"
    echo "   Tunnel Type:    NaiveProxy + SSH"
    echo "   Server:         ${domain}"
    echo "   Server Port:    443"
    echo "   Proxy Username: ${user}"
    echo "   Proxy Password: ${pass}"
    echo "   SSH Host:       127.0.0.1"
    echo "   SSH Port:       22"
    echo "   SSH Username:   <your SSH user>"
    echo "══════════════════════════════════════════"
    echo ""
}

# ─── Uninstall ──────────────────────────

do_uninstall() {
    if ! is_installed; then
        echo "caddy-naive is not installed. Nothing to remove."
        exit 0
    fi

    echo "This will remove caddy-naive and all its configuration."
    read -rp "Continue? [y/N] " confirm
    if [[ "${confirm}" != [yY] ]]; then
        echo "Aborted."
        exit 0
    fi

    echo ""
    echo "[1/4] Stopping caddy-naive service..."
    if systemctl is-active --quiet caddy-naive 2>/dev/null; then
        systemctl stop caddy-naive
        echo "  Service stopped."
    else
        echo "  Service not running."
    fi

    echo "[2/4] Disabling caddy-naive service..."
    if systemctl is-enabled --quiet caddy-naive 2>/dev/null; then
        systemctl disable caddy-naive
        echo "  Service disabled."
    else
        echo "  Service not enabled."
    fi

    echo "[3/4] Removing files..."
    rm -f /etc/systemd/system/caddy-naive.service
    rm -rf /etc/caddy-naive
    rm -f /usr/bin/caddy-naive
    systemctl daemon-reload
    echo "  Removed:"
    echo "    /etc/systemd/system/caddy-naive.service"
    echo "    /etc/caddy-naive/"
    echo "    /usr/bin/caddy-naive"

    echo "[4/4] Checking firewall..."
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw delete allow 80,443/tcp 2>/dev/null || true
        echo "  Removed UFW rules for ports 80,443."
    else
        echo "  UFW not active, skipping."
    fi

    echo ""
    echo "══════════════════════════════════════════"
    echo " caddy-naive has been completely removed."
    echo "══════════════════════════════════════════"
    echo ""
}

# ─── Shared helpers ─────────────────────

ensure_go() {
    install_go_from_tarball() {
        echo "  Installing Go from official tarball..."
        local GO_VERSION
        GO_VERSION="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
        local ARCH
        ARCH="$(dpkg --print-architecture)"
        case "${ARCH}" in
            amd64) ARCH="amd64" ;;
            arm64) ARCH="arm64" ;;
            armhf) ARCH="armv6l" ;;
            *) echo "Error: Unsupported architecture: ${ARCH}"; exit 1 ;;
        esac
        curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH="/usr/local/go/bin:${PATH}"
        echo "  Installed $(go version)"
    }

    if command -v go &>/dev/null; then
        local GO_VER GO_MAJOR GO_MINOR
        GO_VER="$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')"
        GO_MAJOR="${GO_VER%%.*}"
        GO_MINOR="${GO_VER#*.}"
        if [[ "${GO_MAJOR}" -lt 1 ]] || { [[ "${GO_MAJOR}" -eq 1 ]] && [[ "${GO_MINOR}" -lt 21 ]]; }; then
            echo "  Go ${GO_VER} is too old (need 1.21+)."
            install_go_from_tarball
        else
            echo "  Go ${GO_VER} — OK"
        fi
    else
        install_go_from_tarball
    fi

    export GOPATH="${GOPATH:-/root/go}"
    export PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"
}

write_caddyfile() {
    STEP="Creating Caddyfile"
    echo "[3/6] Creating Caddyfile..."

    mkdir -p /etc/caddy-naive

    cat > /etc/caddy-naive/Caddyfile <<CADDYEOF
{
    order forward_proxy before file_server
}
:443, ${DOMAIN} {
    tls ${EMAIL}
    route {
        forward_proxy {
            basic_auth ${PROXY_USER} ${PROXY_PASS}
            hide_ip
            hide_via
            probe_resistance
        }
        reverse_proxy ${DECOY_URL} {
            header_up Host {upstream_hostport}
        }
    }
}
CADDYEOF

    chmod 600 /etc/caddy-naive/Caddyfile
    echo "  Created /etc/caddy-naive/Caddyfile"
}

start_and_verify() {
    STEP="Starting service"
    echo "[6/6] Starting caddy-naive..."

    systemctl daemon-reload
    systemctl enable --now caddy-naive

    echo "  Waiting for TLS certificate (up to 60s)..."
    local TLS_OK=false
    for _ in $(seq 1 12); do
        sleep 5
        if curl -fsSo /dev/null "https://${DOMAIN}" 2>/dev/null; then
            TLS_OK=true
            break
        fi
    done

    if [[ "${TLS_OK}" == true ]]; then
        echo "  TLS certificate obtained successfully."
    else
        echo ""
        echo "  WARNING: Could not verify TLS certificate after 60s."
        echo "  This may be normal if DNS is still propagating."
        echo "  Check status:  systemctl status caddy-naive"
        echo "  Check logs:    journalctl -u caddy-naive -f"
        echo ""
    fi
}

print_summary() {
    echo ""
    echo "══════════════════════════════════════════"
    echo " SlipNet Server Setup Complete"
    echo "══════════════════════════════════════════"
    echo " Domain:         ${DOMAIN}"
    echo " Proxy Username: ${PROXY_USER}"
    echo " Proxy Password: ${PROXY_PASS}"
    echo " Proxy Port:     443"
    echo "──────────────────────────────────────────"
    echo " SlipNet App Profile Settings:"
    echo "   Tunnel Type:    NaiveProxy + SSH"
    echo "   Server:         ${DOMAIN}"
    echo "   Server Port:    443"
    echo "   Proxy Username: ${PROXY_USER}"
    echo "   Proxy Password: ${PROXY_PASS}"
    echo "   SSH Host:       127.0.0.1"
    echo "   SSH Port:       22"
    echo "   SSH Username:   <your SSH user>"
    echo "══════════════════════════════════════════"
    echo ""
}

# ─── Main ───────────────────────────────

check_root
show_menu
