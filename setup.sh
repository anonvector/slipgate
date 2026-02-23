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

random_decoy() {
    local sites=(
        "https://www.wikipedia.org"
        "https://www.npmjs.com"
        "https://www.python.org"
        "https://www.rust-lang.org"
        "https://www.docker.com"
        "https://www.mozilla.org"
        "https://www.w3.org"
        "https://www.kernel.org"
        "https://www.apache.org"
        "https://www.jquery.com"
    )
    echo "${sites[$((RANDOM % ${#sites[@]}))]}"
}

wait_for_enter() {
    echo ""
    read -rp "  Press Enter to continue..." _
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

validate_username() {
    local name="$1"
    if [[ ! "${name}" =~ ^[a-zA-Z_][a-zA-Z0-9_-]{1,31}$ ]]; then
        echo "  Error: Invalid username. Must start with a letter or underscore,"
        echo "         contain only letters, digits, underscores, hyphens (2-32 chars)."
        return 1
    fi
    local reserved=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail"
                     "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats"
                     "nobody" "systemd-network" "systemd-resolve" "messagebus" "sshd")
    local r
    for r in "${reserved[@]}"; do
        if [[ "${name}" == "${r}" ]]; then
            echo "  Error: '${name}' is a reserved system username."
            return 1
        fi
    done
    return 0
}

backup_caddyfile() {
    local caddyfile="/etc/caddy-naive/Caddyfile"
    if [[ -f "${caddyfile}" ]]; then
        cp "${caddyfile}" "${caddyfile}.bak"
    fi
}

reload_caddy() {
    local caddyfile="/etc/caddy-naive/Caddyfile"
    if ! /usr/bin/caddy-naive validate --config "${caddyfile}" 2>/dev/null; then
        echo "  Error: Caddyfile validation failed. Rolling back..."
        if [[ -f "${caddyfile}.bak" ]]; then
            cp "${caddyfile}.bak" "${caddyfile}"
            echo "  Rolled back to previous Caddyfile."
        fi
        return 1
    fi
    if systemctl is-active --quiet caddy-naive 2>/dev/null; then
        /usr/bin/caddy-naive reload --config "${caddyfile}" 2>/dev/null
        echo "  Caddy reloaded."
    else
        systemctl start caddy-naive
        echo "  Caddy started."
    fi
}

ensure_slipnet_group() {
    if ! getent group slipnet &>/dev/null; then
        groupadd slipnet
        echo "  Created 'slipnet' group."
    fi
    if ! grep -q "^# BEGIN SlipNet" /etc/ssh/sshd_config 2>/dev/null; then
        cat >> /etc/ssh/sshd_config <<'SSHEOF'

# BEGIN SlipNet
Match Group slipnet
    AllowTcpForwarding yes
    PasswordAuthentication yes
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
    ForceCommand /bin/false
# END SlipNet
SSHEOF
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        echo "  Configured sshd for SlipNet tunnel users."
    fi
}

rewrite_caddyfile_settings() {
    local domain="$1" email="$2" decoy="$3"
    local caddyfile="/etc/caddy-naive/Caddyfile"
    local auth_lines
    auth_lines="$(grep '            basic_auth ' "${caddyfile}" 2>/dev/null)" || auth_lines=""

    if [[ -z "${auth_lines}" ]]; then
        echo "Error: No users found in Caddyfile."
        return 1
    fi

    cat > "${caddyfile}" <<CADDYEOF
{
    order forward_proxy before file_server
}
:443, ${domain} {
    tls ${email}
    route {
        forward_proxy {
${auth_lines}
            hide_ip
            hide_via
            probe_resistance
        }
        reverse_proxy ${decoy} {
            header_up Host {upstream_hostport}
        }
    }
}
CADDYEOF
    chmod 600 "${caddyfile}"
}

print_header() {
    echo ""
    echo "══════════════════════════════════════════"
    echo "  SlipNet Server — NaiveProxy + SSH"
    echo "══════════════════════════════════════════"
}

# ─── Menu ───────────────────────────────

show_menu() {
    while true; do
        clear
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
        if is_installed; then
            echo "  1) Reconfigure     Change domain/email/decoy"
            echo "  2) Show config     Print current configuration"
            echo "  3) Manage users    Add/delete/list proxy+SSH users"
            echo "  4) Uninstall       Remove everything"
            echo "  0) Exit"
            echo ""
            read -rp "  Choose [0-4]: " choice
            echo ""

            case "${choice}" in
                1) do_reconfigure; wait_for_enter ;;
                2) do_show_config; wait_for_enter ;;
                3) do_manage_users ;;
                4) do_uninstall; wait_for_enter ;;
                0) exit 0 ;;
                *) echo "Invalid choice." ;;
            esac
        else
            echo "  1) Install         Set up NaiveProxy server"
            echo "  0) Exit"
            echo ""
            read -rp "  Choose [0-1]: " choice
            echo ""

            case "${choice}" in
                1) do_install; wait_for_enter ;;
                0) exit 0 ;;
                *) echo "Invalid choice." ;;
            esac
        fi
    done
}

# ─── Install ────────────────────────────

do_install() {
    clear
    STEP="Pre-flight checks"
    echo "[Pre-flight] Checking requirements..."

    check_os

    if is_installed; then
        echo ""
        echo "  caddy-naive is already installed."
        echo "  Use option 2 (Reconfigure) to change settings,"
        echo "  or option 4 (Uninstall) first."
        STEP=""
        return
    fi

    # Check ports 80 and 443
    for port in 80 443; do
        if ss -tlnp | grep -q ":${port} "; then
            echo "Error: Port ${port} is already in use."
            ss -tlnp | grep ":${port} " || true
            echo ""
            echo "Stop the process using port ${port} and re-run this script."
            STEP=""
            return
        fi
    done
    echo "  Ports 80, 443 — free"
    echo ""

    # ─── Prompts ────────────────────────

    STEP="Interactive prompts"

    read -rp "Domain name (e.g. example.com): " DOMAIN
    if [[ -z "${DOMAIN}" ]]; then
        echo "Error: Domain name is required."
        STEP=""
        return
    fi

    DEFAULT_EMAIL="admin@${DOMAIN}"
    read -rp "Email for Let's Encrypt [${DEFAULT_EMAIL}]: " EMAIL
    EMAIL="${EMAIL:-${DEFAULT_EMAIL}}"

    DEFAULT_USER="user$(generate_password 6)"
    read -rp "Proxy username [${DEFAULT_USER}]: " PROXY_USER
    PROXY_USER="${PROXY_USER:-${DEFAULT_USER}}"

    if ! validate_username "${PROXY_USER}"; then
        STEP=""
        return
    fi

    DEFAULT_PASS="$(generate_password 24)"
    read -rp "Proxy password [${DEFAULT_PASS}]: " PROXY_PASS
    PROXY_PASS="${PROXY_PASS:-${DEFAULT_PASS}}"

    read -rp "Create SSH tunnel access for this user? [y/N]: " CREATE_SSH
    CREATE_SSH="${CREATE_SSH:-n}"

    DEFAULT_DECOY="$(random_decoy)"
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
        STEP=""
        return
    fi
    echo ""

    # ─── Dependencies ───────────────────

    STEP="Installing dependencies"
    echo "[1/7] Installing dependencies..."

    apt-get update -qq
    apt-get install -y -qq curl git golang-go > /dev/null 2>&1 || \
        apt-get install -y -qq curl git > /dev/null 2>&1

    ensure_go
    echo "  Dependencies installed."

    # ─── Build Caddy ────────────────────

    STEP="Building Caddy with forwardproxy"
    echo "[2/7] Building Caddy with NaiveProxy plugin (this may take a few minutes)..."

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

    # ─── SSH user ───────────────────────

    if [[ "${CREATE_SSH}" == [yY] ]]; then
        STEP="Creating SSH user"
        echo "[4/7] Creating SSH user..."

        ensure_slipnet_group
        if ! id "${PROXY_USER}" &>/dev/null; then
            useradd -m -s /bin/false -G slipnet "${PROXY_USER}"
        else
            usermod -aG slipnet "${PROXY_USER}"
        fi
        echo "${PROXY_USER}:${PROXY_PASS}" | chpasswd
        echo "  Created SSH user '${PROXY_USER}'."
    else
        echo "[4/7] Skipping SSH user (proxy-only)."
    fi

    # ─── Systemd service ────────────────

    STEP="Creating systemd service"
    echo "[5/7] Creating systemd service..."

    cat > /etc/systemd/system/caddy-naive.service <<'UNITEOF'
[Unit]
Description=SlipNet Caddy-Naive Proxy Server
Documentation=https://github.com/klzgrad/naiveproxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/caddy-naive run --config /etc/caddy-naive/Caddyfile
ExecReload=/usr/bin/caddy-naive reload --config /etc/caddy-naive/Caddyfile
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
    echo "[6/7] Checking firewall..."

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
    STEP=""
}

# ─── Reconfigure ────────────────────────

do_reconfigure() {
    clear
    if ! is_installed; then
        echo "caddy-naive is not installed. Use option 1 (Install) first."
        return
    fi

    STEP="Reconfigure"

    # Read current values from Caddyfile
    local current_caddyfile="/etc/caddy-naive/Caddyfile"
    local current_domain current_email current_decoy
    current_domain="$(grep -oP '^:443, \K[^ ]+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_domain=""
    current_email="$(grep -oP 'tls \K\S+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_email=""
    current_decoy="$(grep -oP 'reverse_proxy \K\S+' "${current_caddyfile}" 2>/dev/null | head -1)" || current_decoy=""

    echo "Current configuration:"
    echo "  Domain: ${current_domain}"
    echo "  Email:  ${current_email}"
    echo "  Decoy:  ${current_decoy}"
    echo ""
    echo "Press Enter to keep current value."
    echo ""

    read -rp "Domain name [${current_domain}]: " DOMAIN
    DOMAIN="${DOMAIN:-${current_domain}}"

    read -rp "Email for Let's Encrypt [${current_email}]: " EMAIL
    EMAIL="${EMAIL:-${current_email}}"

    read -rp "Decoy website URL [${current_decoy}]: " DECOY_URL
    DECOY_URL="${DECOY_URL:-${current_decoy}}"

    echo ""
    echo "  Domain: ${DOMAIN}"
    echo "  Email:  ${EMAIL}"
    echo "  Decoy:  ${DECOY_URL}"
    echo ""
    read -rp "Apply these settings? [Y/n] " proceed
    if [[ "${proceed}" == [nN] ]]; then
        echo "Aborted."
        STEP=""
        return
    fi

    echo ""
    backup_caddyfile

    if ! rewrite_caddyfile_settings "${DOMAIN}" "${EMAIL}" "${DECOY_URL}"; then
        echo "Error: Failed to rewrite Caddyfile."
        STEP=""
        return
    fi

    if ! reload_caddy; then
        STEP=""
        return
    fi

    STEP=""
    echo ""
    echo "  Configuration updated successfully."
    echo "  Domain: ${DOMAIN}"
    echo "  Email:  ${EMAIL}"
    echo "  Decoy:  ${DECOY_URL}"
    echo ""
}

# ─── Show config ────────────────────────

do_show_config() {
    clear
    if ! is_installed; then
        echo "caddy-naive is not installed."
        return
    fi

    local caddyfile="/etc/caddy-naive/Caddyfile"
    if [[ ! -f "${caddyfile}" ]]; then
        echo "Error: Caddyfile not found at ${caddyfile}"
        return
    fi

    local domain email
    domain="$(grep -oP '^:443, \K[^ ]+' "${caddyfile}" 2>/dev/null | head -1)" || domain="unknown"
    email="$(grep -oP 'tls \K\S+' "${caddyfile}" 2>/dev/null | head -1)" || email="unknown"

    local status="stopped"
    if systemctl is-active --quiet caddy-naive 2>/dev/null; then
        status="running"
    fi

    echo "══════════════════════════════════════════"
    echo " SlipNet Server — Current Configuration"
    echo "══════════════════════════════════════════"
    echo " Status:  ${status}"
    echo " Domain:  ${domain}"
    echo " Email:   ${email}"
    echo " Port:    443"
    echo "──────────────────────────────────────────"
    echo " Users:"
    list_users
    echo "──────────────────────────────────────────"
    echo " SlipNet App Profile Settings:"
    echo "   Tunnel Type:  NaiveProxy + SSH"
    echo "   Server:       ${domain}"
    echo "   Server Port:  443"
    echo "   SSH Host:     127.0.0.1"
    echo "   SSH Port:     22"
    echo "══════════════════════════════════════════"
    echo ""
}

# ─── Uninstall ──────────────────────────

do_uninstall() {
    clear
    if ! is_installed; then
        echo "caddy-naive is not installed. Nothing to remove."
        return
    fi

    echo "This will remove caddy-naive, all SlipNet SSH users, and configuration."
    read -rp "Continue? [y/N] " confirm
    if [[ "${confirm}" != [yY] ]]; then
        echo "Aborted."
        return
    fi

    echo ""
    echo "[1/5] Stopping caddy-naive service..."
    if systemctl is-active --quiet caddy-naive 2>/dev/null; then
        systemctl stop caddy-naive
        echo "  Service stopped."
    else
        echo "  Service not running."
    fi

    echo "[2/5] Disabling caddy-naive service..."
    if systemctl is-enabled --quiet caddy-naive 2>/dev/null; then
        systemctl disable caddy-naive
        echo "  Service disabled."
    else
        echo "  Service not enabled."
    fi

    echo "[3/5] Removing SlipNet SSH users..."
    if getent group slipnet &>/dev/null; then
        local members
        members="$(getent group slipnet | cut -d: -f4)" || members=""
        if [[ -n "${members}" ]]; then
            IFS=',' read -ra user_array <<< "${members}"
            for u in "${user_array[@]}"; do
                userdel -r "${u}" 2>/dev/null || true
                echo "  Removed SSH user: ${u}"
            done
        fi
        groupdel slipnet 2>/dev/null || true
        echo "  Removed slipnet group."
    else
        echo "  No slipnet group found."
    fi

    if grep -q "^# BEGIN SlipNet" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i '/^# BEGIN SlipNet$/,/^# END SlipNet$/d' /etc/ssh/sshd_config
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        echo "  Cleaned sshd configuration."
    fi

    echo "[4/5] Removing files..."
    rm -f /etc/systemd/system/caddy-naive.service
    rm -rf /etc/caddy-naive
    rm -f /usr/bin/caddy-naive
    systemctl daemon-reload
    echo "  Removed:"
    echo "    /etc/systemd/system/caddy-naive.service"
    echo "    /etc/caddy-naive/"
    echo "    /usr/bin/caddy-naive"

    echo "[5/5] Checking firewall..."
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

# ─── User Management ──────────────────

add_user() {
    local caddyfile="/etc/caddy-naive/Caddyfile"
    local default_user default_pass
    default_user="user$(generate_password 6)"
    default_pass="$(generate_password 24)"

    read -rp "  Username [${default_user}]: " username
    username="${username:-${default_user}}"

    if ! validate_username "${username}"; then
        return
    fi

    if grep -q "basic_auth ${username} " "${caddyfile}" 2>/dev/null; then
        echo "  Error: User '${username}' already exists in Caddyfile."
        return
    fi

    read -rp "  Password [${default_pass}]: " password
    password="${password:-${default_pass}}"

    read -rp "  Create SSH tunnel access? [y/N]: " create_ssh
    create_ssh="${create_ssh:-n}"

    if [[ "${create_ssh}" == [yY] ]] && id "${username}" &>/dev/null; then
        echo "  Error: OS user '${username}' already exists."
        return
    fi

    echo ""
    echo "  Adding user: ${username}"

    local ssh_created=false
    backup_caddyfile
    sed -i "/hide_ip/i\\            basic_auth ${username} ${password}" "${caddyfile}"

    if [[ "${create_ssh}" == [yY] ]]; then
        ensure_slipnet_group
        if ! useradd -m -s /bin/false -G slipnet "${username}" 2>/dev/null; then
            echo "  Error: Failed to create OS user '${username}'. Rolling back Caddyfile..."
            if [[ -f "${caddyfile}.bak" ]]; then
                cp "${caddyfile}.bak" "${caddyfile}"
            fi
            return
        fi
        echo "${username}:${password}" | chpasswd
        ssh_created=true
    fi

    if ! reload_caddy; then
        if [[ "${ssh_created}" == true ]]; then
            userdel -r "${username}" 2>/dev/null || true
        fi
        return
    fi

    echo ""
    echo "  User '${username}' added successfully."
    echo "    Proxy: ${username} / ${password}"
    if [[ "${ssh_created}" == true ]]; then
        echo "    SSH:   ${username} / ${password}"
    fi
    echo ""
}

delete_user() {
    local caddyfile="/etc/caddy-naive/Caddyfile"

    local -a users
    mapfile -t users < <(grep -oP 'basic_auth \K\S+' "${caddyfile}" 2>/dev/null || true)

    if [[ ${#users[@]} -eq 0 ]]; then
        echo "  No users found."
        return
    fi

    if [[ ${#users[@]} -eq 1 ]]; then
        echo "  Cannot delete the last user. At least one user is required."
        return
    fi

    echo "  Current users:"
    local i
    for i in "${!users[@]}"; do
        echo "    $((i + 1))) ${users[${i}]}"
    done
    echo "    0) Cancel"
    echo ""

    read -rp "  Delete user number: " num
    if [[ "${num}" == "0" ]] || [[ -z "${num}" ]]; then
        echo "  Cancelled."
        return
    fi

    if [[ ! "${num}" =~ ^[0-9]+$ ]] || [[ "${num}" -lt 1 ]] || [[ "${num}" -gt ${#users[@]} ]]; then
        echo "  Invalid selection."
        return
    fi

    local target="${users[$((num - 1))]}"
    read -rp "  Delete user '${target}'? [y/N] " confirm
    if [[ "${confirm}" != [yY] ]]; then
        echo "  Cancelled."
        return
    fi

    backup_caddyfile
    sed -i "/basic_auth ${target} /d" "${caddyfile}"

    if id "${target}" &>/dev/null; then
        userdel -r "${target}" 2>/dev/null || true
        echo "  Removed OS user '${target}'."
    fi

    if ! reload_caddy; then
        return
    fi

    echo "  User '${target}' deleted."
    echo ""
}

list_users() {
    local caddyfile="/etc/caddy-naive/Caddyfile"

    echo ""
    echo "  ┌────────────────────┬──────────────────────────┬──────────┐"
    echo "  │ Username           │ Password                 │ SSH User │"
    echo "  ├────────────────────┼──────────────────────────┼──────────┤"

    local found=false
    while read -r _ user pass _; do
        local ssh_status="no"
        if id "${user}" &>/dev/null; then
            ssh_status="yes"
        fi
        printf "  │ %-18.18s │ %-24.24s │ %-8s │\n" "${user}" "${pass}" "${ssh_status}"
        found=true
    done < <(grep 'basic_auth' "${caddyfile}" 2>/dev/null || true)

    if [[ "${found}" == false ]]; then
        echo "  │          No users configured yet.                     │"
    fi

    echo "  └────────────────────┴──────────────────────────┴──────────┘"
    echo ""
}

do_manage_users() {
    if ! is_installed; then
        echo "caddy-naive is not installed. Use option 1 (Install) first."
        return
    fi

    while true; do
        clear
        echo ""
        echo "──────────────────────────────────────────"
        echo "  User Management"
        echo "──────────────────────────────────────────"
        echo "  1) Add user"
        echo "  2) Delete user"
        echo "  3) List users"
        echo "  0) Back to main menu"
        echo ""
        read -rp "  Choose [0-3]: " uchoice
        echo ""

        case "${uchoice}" in
            1) add_user; wait_for_enter ;;
            2) delete_user; wait_for_enter ;;
            3) list_users; wait_for_enter ;;
            0) break ;;
            *) echo "  Invalid choice." ;;
        esac
    done
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
    echo "[3/7] Creating Caddyfile..."

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
    echo "[7/7] Starting caddy-naive..."

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
    if [[ "${CREATE_SSH}" == [yY] ]]; then
        echo "   Tunnel Type:    NaiveProxy + SSH"
    else
        echo "   Tunnel Type:    NaiveProxy"
    fi
    echo "   Server:         ${DOMAIN}"
    echo "   Server Port:    443"
    echo "   Proxy Username: ${PROXY_USER}"
    echo "   Proxy Password: ${PROXY_PASS}"
    if [[ "${CREATE_SSH}" == [yY] ]]; then
        echo "   SSH Host:       127.0.0.1"
        echo "   SSH Port:       22"
        echo "   SSH Username:   ${PROXY_USER}"
    fi
    echo "══════════════════════════════════════════"
    echo ""
    echo " Manage users with option 5 from the main menu."
    echo ""
}

# ─── Main ───────────────────────────────

check_root
show_menu
