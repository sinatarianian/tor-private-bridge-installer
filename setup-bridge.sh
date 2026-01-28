#!/usr/bin/env bash
#
# ==============================================================================
# PRIVATE TOR BRIDGE INSTALLER (Ubuntu / Debian)
#
# Features:
# - Official Tor Project repo with GPG fingerprint validation
# - Interactive port selection (or env vars) + port conflict detection
# - Safe UFW handling (only if active; preserves SSH by detecting sshd listeners)
# - Hardened Tor bridge config (private, SOCKS disabled, ControlPort localhost)
# - Prints complete obfs4 bridge line with PUBLIC IP + fingerprint
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- Defaults (override via env) ---
DEFAULT_OR_PORT="${DEFAULT_OR_PORT:-9001}"
DEFAULT_PT_PORT="${DEFAULT_PT_PORT:-54321}"
DEFAULT_EMAIL="${DEFAULT_EMAIL:-change_me@example.com}"

# --- Tor Project constants ---
TOR_KEY_FPR_EXPECTED="A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"
TOR_KEY_URL="https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc"
TOR_KEYRING="/usr/share/keyrings/tor-archive-keyring.gpg"
TOR_LIST="/etc/apt/sources.list.d/tor.list"
TORRC="/etc/tor/torrc"

# --- File paths ---
BRIDGE_FILE="/var/lib/tor/pt_state/obfs4_bridgeline.txt"
TOR_FINGERPRINT_FILE="/var/lib/tor/fingerprint"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }
is_tty() { [[ -t 0 && -t 1 ]]; }

prompt_value() {
  local label="$1" def="$2" val=""
  if ! is_tty; then
    echo "$def"
    return 0
  fi
  read -r -p "$(echo -e "${BLUE}${label} [${def}]:${NC} ")" val
  echo "${val:-$def}"
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

# --- Port utilities ---

port_in_range_and_numeric() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "${name} must be numeric."
  (( value >= 1025 && value <= 65535 )) || die "${name} must be between 1025-65535."
}

is_port_free() {
  local port="$1"
  # Match 0.0.0.0:PORT, [::]:PORT, 127.0.0.1:PORT, etc.
  if ss -Hltpn 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${port}$"; then
    return 1
  fi
  return 0
}

next_free_port() {
  local start="$1"
  local p=$((start + 1))
  while (( p <= 65535 )); do
    if is_port_free "$p"; then
      echo "$p"
      return 0
    fi
    ((p++))
  done
  die "No free TCP port found in range ${start}-65535."
}

resolve_port() {
  local name="$1"
  local desired="$2"

  port_in_range_and_numeric "$name" "$desired"

  if is_port_free "$desired"; then
    echo "$desired"
    return 0
  fi

  if is_tty; then
    warn "Port ${desired} (${name}) is already in use."
    while true; do
      desired="$(prompt_value "Choose a different ${name}" "$desired")"
      port_in_range_and_numeric "$name" "$desired"
      if is_port_free "$desired"; then
        echo "$desired"
        return 0
      fi
      warn "Port ${desired} is still in use."
    done
  else
    local picked
    picked="$(next_free_port "$desired")"
    warn "Port ${desired} (${name}) is in use. Auto-selected ${picked}."
    echo "$picked"
  fi
}

# --- Main steps ---

collect_config() {
  echo -e "${GREEN}=== Configuration ===${NC}"

  OR_PORT="${OR_PORT:-}"
  PT_PORT="${PT_PORT:-}"
  EMAIL="${EMAIL:-}"

  [[ -n "$OR_PORT" ]] || OR_PORT="$(prompt_value "Tor OR_PORT (ORPort traffic)" "$DEFAULT_OR_PORT")"
  OR_PORT="$(resolve_port "OR_PORT" "$OR_PORT")"

  [[ -n "$PT_PORT" ]] || PT_PORT="$(prompt_value "Tor PT_PORT (obfs4 transport port for Tor Browser)" "$DEFAULT_PT_PORT")"
  PT_PORT="$(resolve_port "PT_PORT" "$PT_PORT")"

  if [[ "$OR_PORT" == "$PT_PORT" ]]; then
    warn "OR_PORT and PT_PORT ended up identical (${OR_PORT}). Picking a new PT_PORT..."
    PT_PORT="$(resolve_port "PT_PORT" "$(next_free_port "$PT_PORT")")"
  fi

  [[ -n "$EMAIL" ]] || EMAIL="$(prompt_value "Contact email (optional)" "$DEFAULT_EMAIL")"
}

install_prereqs() {
  log "Installing prerequisites..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    ca-certificates curl gpg lsb-release apt-transport-https iproute2 >/dev/null
}

add_tor_repo() {
  log "Setting up Tor Project APT repository..."
  require_cmd curl
  require_cmd gpg
  require_cmd lsb_release

  log "Downloading Tor Project signing key..."
  local tmpkey
  tmpkey="$(mktemp)"

  curl -fsSL "$TOR_KEY_URL" -o "$tmpkey"

  log "Verifying signing key fingerprint..."
  local fpr
  fpr="$(gpg --with-colons --show-keys "$tmpkey" | awk -F: '/^fpr:/ {print $10; exit}')"
  rm -f -- "$tmpkey"

  [[ "$fpr" == "$TOR_KEY_FPR_EXPECTED" ]] || die "Key fingerprint mismatch. Expected $TOR_KEY_FPR_EXPECTED, got $fpr"

  rm -f "$TOR_KEYRING"
  # Re-download for dearmor (keeps logic simple and avoids trap issues)
  curl -fsSL "$TOR_KEY_URL" | gpg --dearmor > "$TOR_KEYRING"
  chmod 0644 "$TOR_KEYRING"

  local codename
  codename="$(lsb_release -cs)"
  echo "deb [signed-by=$TOR_KEYRING] https://deb.torproject.org/torproject.org ${codename} main" > "$TOR_LIST"
  log "Repo added for distro codename: ${codename}"
}

install_packages() {
  log "Installing Tor, obfs4proxy and nyx..."
  apt-get update -qq
  apt-get install -y -qq tor obfs4proxy nyx >/dev/null
  require_cmd tor
  require_cmd obfs4proxy
  require_cmd ss
}

backup_torrc() {
  if [[ -f "$TORRC" ]]; then
    local ts
    ts="$(date +%F_%H%M%S)"
    cp -a "$TORRC" "${TORRC}.backup.${ts}"
    log "Backed up existing torrc to ${TORRC}.backup.${ts}"
  fi
}

write_torrc() {
  log "Writing Tor bridge configuration to ${TORRC}..."

  cat > "$TORRC" <<EOF
# --- Private Tor Bridge Configuration ---
# Generated by setup-bridge.sh

BridgeRelay 1
PublishServerDescriptor 0

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:${PT_PORT}

ORPort ${OR_PORT}

SocksPort 0
ExitPolicy reject *:*

ControlPort 127.0.0.1:9051
CookieAuthentication 1

ContactInfo ${EMAIL}

DataDirectory /var/lib/tor
User debian-tor
EOF

  log "Verifying Tor configuration..."
  local verify_out=""
  if ! verify_out="$(tor --verify-config -f "$TORRC" 2>&1)"; then
    echo "$verify_out" >&2
    die "Tor config verification failed."
  fi

  log "Tor configuration verified OK."
}

get_sshd_listening_ports() {
  ss -Hltpn 2>/dev/null \
    | awk '/users:\(\("sshd"/ {print $4}' \
    | sed -E 's/.*:([0-9]+)$/\1/' \
    | grep -E '^[0-9]+$' \
    | sort -u || true
}

ufw_rule_exists() {
  local port="$1"
  ufw status 2>/dev/null | grep -Eq "(^|[[:space:]])${port}/tcp[[:space:]]+ALLOW"
}

configure_firewall() {
  if ! command -v ufw >/dev/null 2>&1; then
    warn "UFW not installed. Ensure provider firewall allows TCP ${OR_PORT} and ${PT_PORT}."
    return 0
  fi

  if ! ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "UFW installed but inactive. If enabled later, allow TCP ${OR_PORT}, ${PT_PORT} (and SSH)."
    return 0
  fi

  log "UFW is active. Updating rules safely..."

  local ssh_ports
  ssh_ports="$(get_sshd_listening_ports || true)"
  if [[ -n "$ssh_ports" ]]; then
    while read -r p; do
      [[ -n "$p" ]] || continue
      if ! ufw_rule_exists "$p"; then
        warn "Allowing detected SSH port ${p}/tcp to reduce lockout risk."
        ufw allow "${p}/tcp" >/dev/null
      fi
    done <<< "$ssh_ports"
  else
    warn "Could not detect sshd listening port. SSH rules are not modified."
  fi

  if ! ufw_rule_exists "$OR_PORT"; then ufw allow "${OR_PORT}/tcp" >/dev/null; fi
  if ! ufw_rule_exists "$PT_PORT"; then ufw allow "${PT_PORT}/tcp" >/dev/null; fi

  log "UFW rules ensured for TCP: OR_PORT=${OR_PORT}, PT_PORT=${PT_PORT}"
}

restart_tor() {
  log "Enabling and restarting Tor service..."
  systemctl daemon-reload || true
  systemctl stop tor >/dev/null 2>&1 || true
  systemctl enable --now tor >/dev/null
  systemctl restart tor

  sleep 2
  systemctl is-active --quiet tor || die "Tor failed to start. Check: journalctl -u tor -e"
  log "Tor service is active."
}

get_public_ip() {
  local ip=""
  ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL https://ifconfig.me 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="<YOUR_SERVER_PUBLIC_IP>"
  echo "$ip"
}

wait_for_bridge_line() {
  log "Waiting for obfs4 bridge line to appear..."
  local retries=90 i=0
  while [[ $i -lt $retries ]]; do
    if [[ -f "$BRIDGE_FILE" ]] && grep -q "obfs4" "$BRIDGE_FILE" 2>/dev/null; then
      return 0
    fi
    sleep 1
    ((i++))
  done
  return 1
}

get_tor_fingerprint() {
  if [[ -f "$TOR_FINGERPRINT_FILE" ]]; then
    awk '{print $2}' "$TOR_FINGERPRINT_FILE" | tr -d '\r'
  else
    echo ""
  fi
}

render_bridge_line_for_user() {
  local public_ip="$1"
  local raw
  raw="$(grep -m1 '^Bridge obfs4 ' "$BRIDGE_FILE" 2>/dev/null || true)"
  [[ -n "$raw" ]] || raw="$(grep -m1 'obfs4' "$BRIDGE_FILE" 2>/dev/null || true)"
  [[ -n "$raw" ]] || die "Could not read obfs4 bridge line from ${BRIDGE_FILE}"

  local stripped t1 rest
  stripped="$(echo "$raw" | sed -E 's/^Bridge[[:space:]]+//')"
  t1="$(awk '{print $1}' <<<"$stripped")"
  rest="$(cut -d' ' -f3- <<<"$stripped")"

  echo "${t1} ${public_ip}:${PT_PORT} ${rest}"
}

extract_obfs4_fingerprint_from_line() {
  awk '{print $3}' <<<"$1" | tr -d '\r'
}

print_result() {
  echo -e "\n${GREEN}======================================================${NC}"
  echo -e "${GREEN}              INSTALLATION COMPLETE                   ${NC}"
  echo -e "${GREEN}======================================================${NC}\n"

  local public_ip tor_fp
  public_ip="$(get_public_ip)"
  tor_fp="$(get_tor_fingerprint)"

  if ! wait_for_bridge_line; then
    warn "Bridge line not generated yet: ${BRIDGE_FILE}"
    warn "Tor may still be bootstrapping. Check: sudo journalctl -u tor -e"
    warn "Try later: sudo cat ${BRIDGE_FILE}"
    return 0
  fi

  local user_line obfs4_fp
  user_line="$(render_bridge_line_for_user "$public_ip")"
  obfs4_fp="$(extract_obfs4_fingerprint_from_line "$user_line")"

  echo -e "${YELLOW}Detected parameters:${NC}"
  echo "  Public IP:         ${public_ip}"
  echo "  OR_PORT (ORPort):  ${OR_PORT}"
  echo "  PT_PORT (obfs4):   ${PT_PORT}"
  [[ -n "$tor_fp" ]] && echo "  Tor Fingerprint:   ${tor_fp}" || warn "Tor fingerprint not found yet: ${TOR_FINGERPRINT_FILE}"
  echo "  obfs4 Fingerprint: ${obfs4_fp}"

  echo -e "\n${YELLOW}Bridge Line (paste into Tor Browser):${NC}"
  echo "----------------------------------------------------------------"
  echo "${user_line}"
  echo "----------------------------------------------------------------"
  [[ "$public_ip" != "<YOUR_SERVER_PUBLIC_IP>" ]] || warn "Public IP detection failed; replace placeholder with your real public IP."

  echo -e "\n${BLUE}Management:${NC}"
  echo "  • Monitor:     sudo nyx"
  echo "  • Logs:        sudo journalctl -u tor -e"
  echo "  • Restart:     sudo systemctl restart tor"
  echo "  • Bridge line: sudo cat ${BRIDGE_FILE}"
  echo "  • Ports:       sudo ss -tulpn | egrep '(:${OR_PORT}|:${PT_PORT})'"
}

main() {
  require_root
  collect_config
  install_prereqs
  add_tor_repo
  install_packages
  backup_torrc
  write_torrc
  configure_firewall
  restart_tor
  print_result
}

main "$@"
