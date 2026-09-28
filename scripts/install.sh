#!/usr/bin/env bash
# tlsvpn-rs one-click installer / upgrader
# Supported core platforms: Debian, Ubuntu, Rocky Linux, Alpine Linux.
# Optional XanMod support is intentionally limited to x86_64 Debian/Ubuntu.
# Optional tcp-brutal uses the upstream DKMS installer and is skipped on Alpine.

set -Eeuo pipefail
IFS=$'\n\t'

PROGRAM="tlsvpn"
REPO="NNdroid/tlsvpn-rs"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tlsvpn"
STATE_DIR="/var/lib/tlsvpn-installer"
BACKUP_DIR="$STATE_DIR/backups"
STATE_FILE="$STATE_DIR/state.env"
INSTALLER_COPY="/usr/local/lib/tlsvpn/install.sh"
CONFIG_FILE="$CONFIG_DIR/config.json"
CERT_DIR="$CONFIG_DIR/certs"
LEGO_HOME="$STATE_DIR/lego"
SYSCTL_FILE="/etc/sysctl.d/99-tlsvpn.conf"
SYSTEMD_SERVICE="/etc/systemd/system/tlsvpn.service"
SYSTEMD_MAINT_SERVICE="/etc/systemd/system/tlsvpn-maintenance.service"
SYSTEMD_MAINT_TIMER="/etc/systemd/system/tlsvpn-maintenance.timer"
OPENRC_SERVICE="/etc/init.d/tlsvpn"
ALPINE_DAILY="/etc/periodic/daily/tlsvpn-maintenance"
XANMOD_LIST="/etc/apt/sources.list.d/xanmod-release.list"
XANMOD_KEY="/etc/apt/keyrings/xanmod-archive-keyring.gpg"

ACTION=""
MODE=""
VERSION="latest"
ARCH="auto"
PSK=""
LISTEN_ADDR=":4000"
SERVER_ADDR=""
WEB_ADDR=":8080"
WEB_BIND="tunnel"
WEB_AUTH=""
CERT_MODE=""
CERT_NAME=""
CERT_FILE=""
KEY_FILE=""
EMAIL=""
ACME_SERVER="https://acme-v02.api.letsencrypt.org/directory"
ACME_CHALLENGE="http"
DAILY_UPDATE="yes"
XANMOD="no"
XANMOD_PACKAGE="linux-xanmod-lts-x64v2"
TCP_BRUTAL="no"
FORCE_TCP_BRUTAL="no"
KERNEL_TUNING="no"
WORKERS="0"
MTU="1500"
PURGE="no"
REMOVE_OPTIONAL="no"
BACKUP_ID=""
NON_INTERACTIVE="no"
ASSUME_YES="no"
DRY_RUN="no"
QUIET="no"
NO_START="no"

DISTRO=""
DISTRO_LIKE=""
PKG_MGR=""
INIT_SYSTEM=""
HOST_ARCH=""
RELEASE_TAG=""
RELEASE_ASSET=""
CURRENT_BACKUP=""
ROLLBACK_ON_ERROR="no"

say() { [[ "$QUIET" == "yes" ]] || printf '%s\n' "$*"; }
info() { say "[INFO] $*"; }
warn() { printf '%s\n' "[WARN] $*" >&2; }
die() { printf '%s\n' "[ERROR] $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
run() {
  if [[ "$DRY_RUN" == "yes" ]]; then
    printf '[DRY-RUN]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

usage() {
  cat <<'EOF'
tlsvpn-rs installer

Usage:
  install.sh [action] [options]

Actions:
  install       Install TLSVPN and create a service/configuration.
  upgrade       Upgrade the TLSVPN binary while preserving configuration.
  uninstall     Remove TLSVPN-managed files. Add --purge to remove data/config.
  rollback      Restore the newest (or --backup-id) TLSVPN-managed snapshot.
  maintenance   Renew certificates and check/install a newer TLSVPN release.
  status        Show installation, service, certificate and optional-component status.
  help          Show this help.

Run without an action for the interactive wizard. Enter "back" at wizard prompts to
return to the previous step. Actual installation changes can be reverted with rollback.

Core options:
  --mode server|client
  --version latest|vX.Y.Z
  --arch auto|amd64|arm64|armv7|arm64-a55
  --install-dir PATH
  --config-dir PATH
  --config PATH
  --psk SECRET
  --listen ADDRESS              Server listen address (default :4000).
  --server ADDRESS              Client server address/list.
  --web-addr ADDRESS            Dashboard address (default :8080).
  --web-bind all|tunnel
  --web-auth USER:PASSWORD
  --workers N                   Rust server worker count; 0 = automatic.
  --mtu N                       TAP MTU, 576..9000.

Certificate options:
  --cert-mode lego|self-signed|existing|none
  --cert-name DOMAIN_OR_IP      DNS name or public IPv4/IPv6 identifier.
  --email EMAIL                 Required for lego/ACME.
  --acme-challenge http|tls     HTTP-01 or TLS-ALPN-01 (default http).
  --acme-server URL             Default: Let's Encrypt production.
  --cert-file PATH --key-file PATH

Automation and optional system components:
  --daily-update yes|no         Daily certificate renewal + release check (default yes).
  --xanmod yes|no               Optional XanMod kernel (Debian/Ubuntu x86_64 only).
  --xanmod-package NAME         Default linux-xanmod-lts-x64v2.
  --tcp-brutal yes|no           Optional upstream tcp-brutal DKMS module.
  --force-tcp-brutal            Attempt tcp-brutal even on a kernel combination warned as risky.
  --optimize-kernel yes|no      Install conservative network sysctl tuning.

Lifecycle/safety options:
  --backup-id ID                Snapshot to restore with rollback.
  --purge                       With uninstall, also remove config/certs/state/backups.
  --remove-optional             With uninstall, also remove tcp-brutal if installed by this script.
  --non-interactive             Never prompt; missing required values are errors.
  -y, --yes                     Assume yes for confirmations.
  --dry-run                     Print mutations instead of executing them.
  --no-start                    Install/update files without starting TLSVPN.
  --quiet                       Reduce normal output.
  -h, --help                    Show this help.

Examples:
  install.sh install --mode server --psk '...' --cert-mode lego \
    --cert-name vpn.example.com --email admin@example.com --daily-update yes

  install.sh install --mode server --psk '...' --cert-mode lego \
    --cert-name 203.0.113.10 --email admin@example.com

  install.sh install --mode client --server vpn.example.com:4000 --psk '...' \
    --tcp-brutal yes --optimize-kernel yes

  install.sh upgrade --version latest
  install.sh rollback
  install.sh uninstall --purge
EOF
}

need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || die "$1 requires a value"; }
parse_args() {
  if [[ $# -gt 0 && "$1" != -* ]]; then ACTION="$1"; shift; fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      install|upgrade|uninstall|rollback|maintenance|status|help) ACTION="$1" ;;
      --mode) need_arg "$@"; MODE="$2"; shift ;;
      --version) need_arg "$@"; VERSION="$2"; shift ;;
      --arch) need_arg "$@"; ARCH="$2"; shift ;;
      --install-dir) need_arg "$@"; INSTALL_DIR="$2"; shift ;;
      --config-dir) need_arg "$@"; CONFIG_DIR="$2"; CONFIG_FILE="$CONFIG_DIR/config.json"; CERT_DIR="$CONFIG_DIR/certs"; shift ;;
      --config) need_arg "$@"; CONFIG_FILE="$2"; CONFIG_DIR="$(dirname "$CONFIG_FILE")"; CERT_DIR="$CONFIG_DIR/certs"; shift ;;
      --psk) need_arg "$@"; PSK="$2"; shift ;;
      --listen) need_arg "$@"; LISTEN_ADDR="$2"; shift ;;
      --server) need_arg "$@"; SERVER_ADDR="$2"; shift ;;
      --web-addr) need_arg "$@"; WEB_ADDR="$2"; shift ;;
      --web-bind) need_arg "$@"; WEB_BIND="$2"; shift ;;
      --web-auth) need_arg "$@"; WEB_AUTH="$2"; shift ;;
      --workers) need_arg "$@"; WORKERS="$2"; shift ;;
      --mtu) need_arg "$@"; MTU="$2"; shift ;;
      --cert-mode) need_arg "$@"; CERT_MODE="$2"; shift ;;
      --cert-name) need_arg "$@"; CERT_NAME="$2"; shift ;;
      --email) need_arg "$@"; EMAIL="$2"; shift ;;
      --acme-challenge) need_arg "$@"; ACME_CHALLENGE="$2"; shift ;;
      --acme-server) need_arg "$@"; ACME_SERVER="$2"; shift ;;
      --cert-file) need_arg "$@"; CERT_FILE="$2"; shift ;;
      --key-file) need_arg "$@"; KEY_FILE="$2"; shift ;;
      --daily-update) need_arg "$@"; DAILY_UPDATE="$2"; shift ;;
      --xanmod) need_arg "$@"; XANMOD="$2"; shift ;;
      --xanmod-package) need_arg "$@"; XANMOD_PACKAGE="$2"; shift ;;
      --tcp-brutal) need_arg "$@"; TCP_BRUTAL="$2"; shift ;;
      --force-tcp-brutal) FORCE_TCP_BRUTAL="yes" ;;
      --optimize-kernel) need_arg "$@"; KERNEL_TUNING="$2"; shift ;;
      --backup-id) need_arg "$@"; BACKUP_ID="$2"; shift ;;
      --purge) PURGE="yes" ;;
      --remove-optional) REMOVE_OPTIONAL="yes" ;;
      --non-interactive) NON_INTERACTIVE="yes" ;;
      -y|--yes) ASSUME_YES="yes" ;;
      --dry-run) DRY_RUN="yes" ;;
      --no-start) NO_START="yes" ;;
      --quiet) QUIET="yes" ;;
      -h|--help) ACTION="help" ;;
      --) shift; break ;;
      *) die "Unknown argument: $1" ;;
    esac
    shift
  done
}

validate_yes_no() { [[ "$1" == "yes" || "$1" == "no" ]] || die "$2 must be yes or no"; }
validate_common() {
  [[ "$WEB_BIND" == "all" || "$WEB_BIND" == "tunnel" ]] || die "--web-bind must be all or tunnel"
  [[ "$ACME_CHALLENGE" == "http" || "$ACME_CHALLENGE" == "tls" ]] || die "--acme-challenge must be http or tls"
  validate_yes_no "$DAILY_UPDATE" "--daily-update"
  validate_yes_no "$XANMOD" "--xanmod"
  validate_yes_no "$TCP_BRUTAL" "--tcp-brutal"
  validate_yes_no "$KERNEL_TUNING" "--optimize-kernel"
  [[ "$WORKERS" =~ ^[0-9]+$ ]] || die "--workers must be a non-negative integer"
  [[ "$MTU" =~ ^[0-9]+$ ]] && (( MTU >= 576 && MTU <= 9000 )) || die "--mtu must be in [576, 9000]"
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this action as root (or with sudo)."
}

detect_platform() {
  [[ -r /etc/os-release ]] || die "Cannot detect Linux distribution (/etc/os-release missing)."
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
  case "$DISTRO" in
    debian|ubuntu) PKG_MGR="apt" ;;
    rocky|rhel|almalinux|centos|fedora) PKG_MGR="dnf" ;;
    alpine) PKG_MGR="apk" ;;
    *)
      case " $DISTRO_LIKE " in
        *" debian "*) PKG_MGR="apt" ;;
        *" rhel "*|*" fedora "*) PKG_MGR="dnf" ;;
        *) die "Unsupported distribution: $DISTRO (supported: Debian, Ubuntu, Rocky/RHEL-family, Alpine)" ;;
      esac
      ;;
  esac
  if have systemctl && [[ -d /run/systemd/system ]]; then INIT_SYSTEM="systemd";
  elif have rc-service || [[ "$DISTRO" == "alpine" ]]; then INIT_SYSTEM="openrc";
  else die "Unsupported init system: systemd or OpenRC is required."; fi

  case "$(uname -m)" in
    x86_64|amd64) HOST_ARCH="amd64" ;;
    aarch64|arm64) HOST_ARCH="arm64" ;;
    armv7l|armv7*) HOST_ARCH="armv7" ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
}

install_packages() {
  local pkgs=("$@")
  [[ ${#pkgs[@]} -gt 0 ]] || return 0
  case "$PKG_MGR" in
    apt)
      run env DEBIAN_FRONTEND=noninteractive apt-get update -y
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
      ;;
    dnf) run dnf install -y "${pkgs[@]}" ;;
    apk) run apk add --no-cache "${pkgs[@]}" ;;
  esac
}

install_base_dependencies() {
  case "$PKG_MGR" in
    apt) install_packages ca-certificates curl openssl tar gzip iproute2 ;;
    dnf) install_packages ca-certificates curl openssl tar gzip iproute ;;
    apk) install_packages ca-certificates curl openssl tar gzip iproute2 bash ;;
  esac
}

confirm() {
  local prompt="$1"
  [[ "$ASSUME_YES" == "yes" ]] && return 0
  [[ "$NON_INTERACTIVE" == "no" && -t 0 ]] || return 1
  local answer
  read -r -p "$prompt [y/N]: " answer || return 1
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

prompt_value() {
  local label="$1" current="$2" secret="${3:-no}" answer
  if [[ "$secret" == "yes" ]]; then
    read -r -s -p "$label${current:+ [set]}: " answer; printf '\n'
  else
    read -r -p "$label${current:+ [$current]}: " answer
  fi
  if [[ "$answer" == "back" ]]; then printf '%s' "__BACK__"; return; fi
  printf '%s' "${answer:-$current}"
}

interactive_wizard() {
  [[ -t 0 ]] || die "No action specified and stdin is not interactive. Use install|upgrade|... and flags."
  cat <<'EOF'
TLSVPN-RS Setup Wizard
Type "back" at any prompt to return to the previous step.
EOF
  local step=1 v
  while (( step <= 10 )); do
    case "$step" in
      1)
        v="$(prompt_value "Action (install/upgrade/uninstall/rollback/status)" "${ACTION:-install}")"
        [[ "$v" == "__BACK__" ]] && { step=1; continue; }
        ACTION="$v"; [[ "$ACTION" == "install" ]] || return 0; step=2 ;;
      2)
        v="$(prompt_value "Mode (server/client)" "${MODE:-server}")"; [[ "$v" == "__BACK__" ]] && { step=1; continue; }; MODE="$v"; step=3 ;;
      3)
        if [[ "$MODE" == "client" ]]; then v="$(prompt_value "Server address (host:port)" "$SERVER_ADDR")"; [[ "$v" == "__BACK__" ]] && { step=2; continue; }; SERVER_ADDR="$v"; fi
        step=4 ;;
      4)
        v="$(prompt_value "PSK (blank = generate a random secret)" "$PSK" "yes")"; [[ "$v" == "__BACK__" ]] && { step=3; continue; }; PSK="$v"; step=5 ;;
      5)
        if [[ "$MODE" == "server" ]]; then
          v="$(prompt_value "Certificate mode (lego/self-signed/existing)" "${CERT_MODE:-self-signed}")"; [[ "$v" == "__BACK__" ]] && { step=4; continue; }; CERT_MODE="$v"
        else CERT_MODE="none"; fi
        step=6 ;;
      6)
        if [[ "$MODE" == "server" && ( "$CERT_MODE" == "lego" || "$CERT_MODE" == "self-signed" ) ]]; then
          v="$(prompt_value "Certificate DNS name or IP" "$CERT_NAME")"; [[ "$v" == "__BACK__" ]] && { step=5; continue; }; CERT_NAME="$v"
          if [[ "$CERT_MODE" == "lego" ]]; then v="$(prompt_value "ACME account email" "$EMAIL")"; [[ "$v" == "__BACK__" ]] && { step=5; continue; }; EMAIL="$v"; fi
        fi
        step=7 ;;
      7)
        v="$(prompt_value "Install XanMod kernel? (yes/no)" "$XANMOD")"; [[ "$v" == "__BACK__" ]] && { step=6; continue; }; XANMOD="$v"; step=8 ;;
      8)
        v="$(prompt_value "Install tcp-brutal? (yes/no)" "$TCP_BRUTAL")"; [[ "$v" == "__BACK__" ]] && { step=7; continue; }; TCP_BRUTAL="$v"; step=9 ;;
      9)
        v="$(prompt_value "Apply network kernel tuning? (yes/no)" "$KERNEL_TUNING")"; [[ "$v" == "__BACK__" ]] && { step=8; continue; }; KERNEL_TUNING="$v"; step=10 ;;
      10)
        v="$(prompt_value "Enable daily renewal/update check? (yes/no)" "$DAILY_UPDATE")"; [[ "$v" == "__BACK__" ]] && { step=9; continue; }; DAILY_UPDATE="$v"; step=11 ;;
    esac
  done
}

json_escape() {
  local s="$1"
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

is_ip() {
  local value="$1"
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0
  [[ "$value" == *:* ]] && return 0
  return 1
}

random_secret() {
  if have openssl; then openssl rand -hex 32; else od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; fi
}

release_arch() {
  local want="$ARCH"
  [[ "$want" == "auto" ]] && want="$HOST_ARCH"
  case "$want" in
    amd64) RELEASE_ASSET="tlsvpn-x86_64-unknown-linux-musl" ;;
    arm64) RELEASE_ASSET="tlsvpn-aarch64-unknown-linux-musl" ;;
    arm64-a55) [[ "$HOST_ARCH" == "arm64" ]] || die "arm64-a55 can only run on ARM64"; RELEASE_ASSET="tlsvpn-aarch64-unknown-linux-musl-cortex-a55" ;;
    armv7) RELEASE_ASSET="tlsvpn-armv7-unknown-linux-musleabihf" ;;
    *) die "Unsupported --arch: $want" ;;
  esac
}

latest_release_tag() {
  curl -fsSL --retry 4 --connect-timeout 10 "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | head -n1 | cut -d'"' -f4
}

resolve_release() {
  if [[ "$VERSION" == "latest" ]]; then RELEASE_TAG="$(latest_release_tag)"; else RELEASE_TAG="$VERSION"; fi
  [[ -n "$RELEASE_TAG" ]] || die "Could not resolve a TLSVPN release tag."
  [[ "$RELEASE_TAG" == v* ]] || RELEASE_TAG="v$RELEASE_TAG"
  release_arch
}

create_backup() {
  run mkdir -p "$BACKUP_DIR"
  local id; id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  local dir="$BACKUP_DIR/$id"
  run mkdir -p "$dir/root"
  local p
  local paths=(
    "$INSTALL_DIR/$PROGRAM" "$CONFIG_FILE" "$CERT_DIR" "$SYSTEMD_SERVICE"
    "$SYSTEMD_MAINT_SERVICE" "$SYSTEMD_MAINT_TIMER" "$OPENRC_SERVICE" "$ALPINE_DAILY"
    "$SYSCTL_FILE" "$STATE_FILE" "$INSTALLER_COPY"
  )
  : >"$dir/manifest" || true
  : >"$dir/absent" || true
  for p in "${paths[@]}"; do
    if [[ -e "$p" || -L "$p" ]]; then
      printf '%s\n' "$p" >>"$dir/manifest"
      if [[ "$DRY_RUN" != "yes" ]]; then
        mkdir -p "$dir/root$(dirname "$p")"
        cp -a "$p" "$dir/root$p"
      fi
    else
      printf '%s\n' "$p" >>"$dir/absent"
    fi
  done
  CURRENT_BACKUP="$id"
  info "Backup snapshot: $id"
}

restore_backup() {
  local id="$1" dir="$BACKUP_DIR/$1"
  [[ -d "$dir" ]] || die "Backup not found: $id"
  stop_service || true
  local p
  while IFS= read -r p; do [[ -n "$p" ]] && run rm -rf "$p"; done <"$dir/absent"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    run rm -rf "$p"
    if [[ "$DRY_RUN" != "yes" ]]; then
      mkdir -p "$(dirname "$p")"
      cp -a "$dir/root$p" "$p"
    fi
  done <"$dir/manifest"
  reload_init
  start_service || true
  info "Rollback restored snapshot $id"
}

on_error() {
  local rc=$?
  trap - ERR
  if [[ "$ROLLBACK_ON_ERROR" == "yes" && -n "$CURRENT_BACKUP" && "$DRY_RUN" != "yes" ]]; then
    warn "Operation failed; restoring TLSVPN-managed files from $CURRENT_BACKUP."
    restore_backup "$CURRENT_BACKUP" || true
  fi
  exit "$rc"
}
trap on_error ERR

install_tlsvpn_binary() {
  resolve_release
  local url="https://github.com/$REPO/releases/download/$RELEASE_TAG/$RELEASE_ASSET"
  local tmp; tmp="$(mktemp)"
  info "Downloading $RELEASE_TAG ($RELEASE_ASSET)"
  if [[ "$DRY_RUN" == "yes" ]]; then
    printf '[DRY-RUN] curl -fL %q -o %q\n' "$url" "$tmp"
    rm -f "$tmp"
    return 0
  fi
  curl -fL --retry 5 --connect-timeout 15 "$url" -o "$tmp"
  chmod 0755 "$tmp"
  "$tmp" --print-config >/dev/null || { rm -f "$tmp"; die "Downloaded binary failed its self-check."; }
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$tmp" "$INSTALL_DIR/$PROGRAM.new"
  mv -f "$INSTALL_DIR/$PROGRAM.new" "$INSTALL_DIR/$PROGRAM"
  rm -f "$tmp"
  printf '%s\n' "$RELEASE_TAG" >"$STATE_DIR/installed-version"
}

install_lego() {
  have lego && return 0
  local lego_arch
  case "$HOST_ARCH" in amd64) lego_arch="amd64";; arm64) lego_arch="arm64";; armv7) lego_arch="armv7";; esac
  local tag version url tmpdir
  tag="$(curl -fsSL --retry 4 https://api.github.com/repos/go-acme/lego/releases/latest | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n1 | cut -d'"' -f4)"
  [[ -n "$tag" ]] || die "Could not resolve the latest lego release."
  version="${tag#v}"
  url="https://github.com/go-acme/lego/releases/download/$tag/lego_${tag}_linux_${lego_arch}.tar.gz"
  tmpdir="$(mktemp -d)"
  info "Installing lego $tag"
  if [[ "$DRY_RUN" == "yes" ]]; then printf '[DRY-RUN] download/extract %s\n' "$url"; rm -rf "$tmpdir"; return 0; fi
  curl -fL --retry 5 "$url" -o "$tmpdir/lego.tgz"
  tar -xzf "$tmpdir/lego.tgz" -C "$tmpdir" lego
  install -m 0755 "$tmpdir/lego" /usr/local/bin/lego
  rm -rf "$tmpdir"
  /usr/local/bin/lego --version >/dev/null
}

lego_args() {
  local action="$1"
  LEGO_ARGS=(--path "$LEGO_HOME" --email "$EMAIL" --accept-tos --server "$ACME_SERVER" --domains "$CERT_NAME" --cert.name tlsvpn)
  if is_ip "$CERT_NAME"; then LEGO_ARGS+=(--profile shortlived); fi
  case "$ACME_CHALLENGE" in
    http) LEGO_ARGS+=(--http --http.port :80) ;;
    tls) LEGO_ARGS+=(--tls --tls.port :443) ;;
  esac
  LEGO_ARGS+=("$action")
}

sync_lego_certificate() {
  local crt="$LEGO_HOME/certificates/tlsvpn.crt" key="$LEGO_HOME/certificates/tlsvpn.key"
  [[ -s "$crt" && -s "$key" ]] || die "lego did not create the expected tlsvpn.crt/tlsvpn.key files."
  run mkdir -p "$CERT_DIR"
  run install -m 0644 "$crt" "$CERT_DIR/server.crt"
  run install -m 0600 "$key" "$CERT_DIR/server.key"
}

issue_lego_certificate() {
  [[ -n "$CERT_NAME" ]] || die "--cert-name is required for --cert-mode lego"
  [[ -n "$EMAIL" ]] || die "--email is required for --cert-mode lego"
  install_lego
  run mkdir -p "$LEGO_HOME"
  local -a LEGO_ARGS
  lego_args run
  info "Requesting ACME certificate for $CERT_NAME"
  run lego "${LEGO_ARGS[@]}"
  [[ "$DRY_RUN" == "yes" ]] || sync_lego_certificate
}

renew_lego_certificate() {
  [[ -n "$CERT_NAME" && -n "$EMAIL" ]] || return 0
  install_lego
  local -a LEGO_ARGS
  lego_args renew
  # IP certificates use the short-lived profile; renew while at least two days remain.
  if is_ip "$CERT_NAME"; then LEGO_ARGS+=(--days 2); else LEGO_ARGS+=(--days 30); fi
  info "Checking ACME certificate renewal for $CERT_NAME"
  if run lego "${LEGO_ARGS[@]}"; then [[ "$DRY_RUN" == "yes" ]] || sync_lego_certificate; else warn "lego renewal failed; keeping the current certificate."; return 1; fi
}

create_self_signed_certificate() {
  [[ -n "$CERT_NAME" ]] || CERT_NAME="$(hostname -f 2>/dev/null || hostname)"
  local san
  if is_ip "$CERT_NAME"; then san="IP:$CERT_NAME"; else san="DNS:$CERT_NAME"; fi
  run mkdir -p "$CERT_DIR"
  info "Creating self-signed certificate for $CERT_NAME"
  run openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/CN=$CERT_NAME" -addext "subjectAltName=$san"
  [[ "$DRY_RUN" == "yes" ]] || chmod 0600 "$CERT_DIR/server.key"
}

prepare_existing_certificate() {
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] || die "--cert-file and --key-file must point to existing non-empty files."
  run mkdir -p "$CERT_DIR"
  run install -m 0644 "$CERT_FILE" "$CERT_DIR/server.crt"
  run install -m 0600 "$KEY_FILE" "$CERT_DIR/server.key"
}

prepare_certificate() {
  [[ "$MODE" == "server" ]] || return 0
  [[ -n "$CERT_MODE" ]] || CERT_MODE="self-signed"
  case "$CERT_MODE" in
    lego) issue_lego_certificate ;;
    self-signed) create_self_signed_certificate ;;
    existing) prepare_existing_certificate ;;
    none) die "Server mode requires a TLS certificate; use lego, self-signed, or existing." ;;
    *) die "Unknown certificate mode: $CERT_MODE" ;;
  esac
}

write_config() {
  [[ -n "$MODE" ]] || die "--mode is required"
  [[ "$MODE" == "server" || "$MODE" == "client" ]] || die "--mode must be server or client"
  [[ -n "$PSK" ]] || PSK="$(random_secret)"
  [[ -n "$WEB_AUTH" ]] || WEB_AUTH="admin:$(random_secret | cut -c1-24)"
  [[ "$WEB_AUTH" == *:* ]] || die "--web-auth must be USER:PASSWORD"
  [[ "$MODE" == "server" || -n "$SERVER_ADDR" ]] || die "--server is required in client mode"
  run mkdir -p "$CONFIG_DIR"
  if [[ "$DRY_RUN" == "yes" ]]; then info "Would write $CONFIG_FILE"; return 0; fi
  umask 077
  local psk webauth cert key addr
  psk="$(json_escape "$PSK")"; webauth="$(json_escape "$WEB_AUTH")"
  if [[ "$MODE" == "server" ]]; then
    addr="$(json_escape "$LISTEN_ADDR")"; cert="$(json_escape "$CERT_DIR/server.crt")"; key="$(json_escape "$CERT_DIR/server.key")"
    cat >"$CONFIG_FILE.tmp" <<EOF
{
  "mode": "server",
  "psk": "$psk",
  "addr": "$addr",
  "log_level": "info",
  "up": "",
  "down": "",
  "encrypt": true,
  "enc_algo": "gcm256",
  "min_enc": "gcm",
  "pad_mode": "bucket",
  "brutal": $([[ "$TCP_BRUTAL" == "yes" ]] && echo true || echo false),
  "brutal_up": 100,
  "brutal_down": 500,
  "traffic_days": 30,
  "traffic_file": "$CONFIG_DIR/tlsvpn-traffic.json",
  "workers": $WORKERS,
  "mtu": $MTU,
  "tap": "tap0",
  "mac": "",
  "web": {"addr":"$(json_escape "$WEB_ADDR")","bind":"$(json_escape "$WEB_BIND")","auth":"$webauth","cert":"$cert","key":"$key"},
  "server": {"v4_cidr":"10.0.0.0/24","v6_cidr":"fd00::/64","cert":"$cert","key":"$key","max_sessions":1024,"fec_group_min":2,"fec_group_max":64},
  "client": {"interface_manager":"self","conns":1,"fec":false,"fec_group":4,"sni":"www.cloudflare.com","insecure":false,"cert_sha256":"","req_v4":"","req_v6":"","fwmark":0,"fwmark_priority":0,"extra_routes":[],"source_rules":[]}
}
EOF
  else
    addr="$(json_escape "$SERVER_ADDR")"
    cat >"$CONFIG_FILE.tmp" <<EOF
{
  "mode": "client",
  "psk": "$psk",
  "addr": "$addr",
  "log_level": "info",
  "up": "",
  "down": "",
  "encrypt": true,
  "enc_algo": "gcm256",
  "min_enc": "gcm",
  "pad_mode": "bucket",
  "socks5": "",
  "brutal": $([[ "$TCP_BRUTAL" == "yes" ]] && echo true || echo false),
  "brutal_up": 100,
  "brutal_down": 500,
  "traffic_days": 30,
  "traffic_file": "$CONFIG_DIR/tlsvpn-traffic.json",
  "workers": $WORKERS,
  "mtu": $MTU,
  "tap": "tap0",
  "mac": "",
  "web": {"addr":"$(json_escape "$WEB_ADDR")","bind":"$(json_escape "$WEB_BIND")","auth":"$webauth","cert":"","key":""},
  "server": {"v4_cidr":"10.0.0.0/24","v6_cidr":"fd00::/64","cert":"","key":"","max_sessions":1024,"fec_group_min":2,"fec_group_max":64},
  "client": {"interface_manager":"self","conns":4,"fec":true,"fec_group":4,"sni":"www.cloudflare.com","insecure":false,"cert_sha256":"","req_v4":"","req_v6":"","fwmark":0,"fwmark_priority":0,"extra_routes":[],"source_rules":[]}
}
EOF
  fi
  "$INSTALL_DIR/$PROGRAM" -c "$CONFIG_FILE.tmp" >/dev/null 2>&1 &
  local pid=$!; sleep 0.4; kill "$pid" >/dev/null 2>&1 || true; wait "$pid" >/dev/null 2>&1 || true
  mv -f "$CONFIG_FILE.tmp" "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
  info "Configuration written to $CONFIG_FILE"
}

write_systemd_service() {
  cat >"$SYSTEMD_SERVICE.tmp" <<EOF
[Unit]
Description=TLSVPN Rust Layer-2 VPN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$PROGRAM -c $CONFIG_FILE
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  run mv -f "$SYSTEMD_SERVICE.tmp" "$SYSTEMD_SERVICE"
}

write_openrc_service() {
  cat >"$OPENRC_SERVICE.tmp" <<EOF
#!/sbin/openrc-run
name="tlsvpn"
description="TLSVPN Rust Layer-2 VPN"
command="$INSTALL_DIR/$PROGRAM"
command_args="-c $CONFIG_FILE"
command_background="yes"
pidfile="/run/tlsvpn.pid"
output_log="/var/log/tlsvpn.log"
error_log="/var/log/tlsvpn.log"
depend() { need net; after firewall; }
EOF
  run mv -f "$OPENRC_SERVICE.tmp" "$OPENRC_SERVICE"
  run chmod 0755 "$OPENRC_SERVICE"
}

write_service() {
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then write_systemd_service; run systemctl daemon-reload; run systemctl enable tlsvpn.service;
  else write_openrc_service; run rc-update add tlsvpn default; fi
}

reload_init() {
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then run systemctl daemon-reload || true; fi
}

stop_service() {
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl stop tlsvpn.service >/dev/null 2>&1 || true;
  else rc-service tlsvpn stop >/dev/null 2>&1 || true; fi
}
start_service() {
  [[ "$NO_START" == "yes" ]] && return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then run systemctl restart tlsvpn.service;
  else run rc-service tlsvpn restart; fi
}

write_state() {
  run mkdir -p "$STATE_DIR" "$(dirname "$INSTALLER_COPY")"
  if [[ "$DRY_RUN" == "yes" ]]; then return 0; fi
  install -m 0755 "$0" "$INSTALLER_COPY" 2>/dev/null || cp -f "$0" "$INSTALLER_COPY"
  chmod 0755 "$INSTALLER_COPY"
  umask 077
  cat >"$STATE_FILE" <<EOF
MODE=$(printf '%q' "$MODE")
VERSION=$(printf '%q' "$VERSION")
ARCH=$(printf '%q' "$ARCH")
CONFIG_FILE=$(printf '%q' "$CONFIG_FILE")
CERT_MODE=$(printf '%q' "$CERT_MODE")
CERT_NAME=$(printf '%q' "$CERT_NAME")
EMAIL=$(printf '%q' "$EMAIL")
ACME_SERVER=$(printf '%q' "$ACME_SERVER")
ACME_CHALLENGE=$(printf '%q' "$ACME_CHALLENGE")
DAILY_UPDATE=$(printf '%q' "$DAILY_UPDATE")
XANMOD=$(printf '%q' "$XANMOD")
TCP_BRUTAL=$(printf '%q' "$TCP_BRUTAL")
KERNEL_TUNING=$(printf '%q' "$KERNEL_TUNING")
EOF
}

load_state() {
  [[ -r "$STATE_FILE" ]] || return 1
  # File is root-owned mode 0600 and only generated by this script.
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  return 0
}

write_daily_task() {
  if [[ "$DAILY_UPDATE" != "yes" ]]; then remove_daily_task; return; fi
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    cat >"$SYSTEMD_MAINT_SERVICE" <<EOF
[Unit]
Description=TLSVPN daily maintenance
After=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALLER_COPY maintenance --non-interactive --yes
EOF
    cat >"$SYSTEMD_MAINT_TIMER" <<'EOF'
[Unit]
Description=Run TLSVPN maintenance daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=45m

[Install]
WantedBy=timers.target
EOF
    run systemctl daemon-reload
    run systemctl enable --now tlsvpn-maintenance.timer
  else
    run mkdir -p /etc/periodic/daily
    cat >"$ALPINE_DAILY" <<EOF
#!/bin/sh
exec $INSTALLER_COPY maintenance --non-interactive --yes
EOF
    run chmod 0755 "$ALPINE_DAILY"
    run rc-update add crond default || true
    run rc-service crond start || true
  fi
}

remove_daily_task() {
  if have systemctl; then systemctl disable --now tlsvpn-maintenance.timer >/dev/null 2>&1 || true; fi
  run rm -f "$SYSTEMD_MAINT_SERVICE" "$SYSTEMD_MAINT_TIMER" "$ALPINE_DAILY"
  reload_init
}

install_xanmod() {
  [[ "$XANMOD" == "yes" ]] || return 0
  if [[ "$PKG_MGR" != "apt" || "$HOST_ARCH" != "amd64" ]]; then warn "XanMod is only automated on Debian/Ubuntu x86_64; skipping."; return 0; fi
  install_packages wget gnupg ca-certificates
  run mkdir -p /etc/apt/keyrings
  if [[ "$DRY_RUN" == "yes" ]]; then info "Would install XanMod repository and $XANMOD_PACKAGE"; return 0; fi
  curl -fsSL https://dl.xanmod.org/archive.key | gpg --dearmor -o "$XANMOD_KEY.tmp"
  mv -f "$XANMOD_KEY.tmp" "$XANMOD_KEY"
  local codename
  codename="$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")"
  [[ -n "$codename" ]] || { have lsb_release && codename="$(lsb_release -sc)"; }
  [[ -n "$codename" ]] || { warn "Cannot determine distro codename; skipping XanMod."; return 0; }
  printf 'deb [signed-by=%s] http://deb.xanmod.org %s main\n' "$XANMOD_KEY" "$codename" >"$XANMOD_LIST"
  apt-get update -y
  if apt-get install -y "$XANMOD_PACKAGE"; then
    info "XanMod installed. Reboot is required before the new kernel is active."
  else
    warn "XanMod package installation failed; TLSVPN installation will continue."
  fi
}

kernel_brutal_risky() {
  local k="$(uname -r)" major minor
  major="${k%%.*}"; minor="${k#*.}"; minor="${minor%%.*}"
  [[ "$k" == *xanmod* && "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ && ( "$major" -gt 7 || ( "$major" -eq 7 && "$minor" -ge 1 ) ) ]]
}

install_tcp_brutal() {
  [[ "$TCP_BRUTAL" == "yes" ]] || return 0
  if [[ "$DISTRO" == "alpine" ]]; then warn "tcp-brutal DKMS is not reliably supported on Alpine; skipping the optional module."; return 0; fi
  if kernel_brutal_risky && [[ "$FORCE_TCP_BRUTAL" != "yes" ]]; then
    warn "Current XanMod 7.1+ combinations have upstream tcp-brutal compatibility reports; skipping. Use --force-tcp-brutal to attempt it."
    return 0
  fi
  info "Installing tcp-brutal with the upstream DKMS installer"
  local tmp; tmp="$(mktemp)"
  if [[ "$DRY_RUN" == "yes" ]]; then printf '[DRY-RUN] upstream tcp-brutal installer\n'; rm -f "$tmp"; return 0; fi
  if curl -fsSL --retry 4 https://raw.githubusercontent.com/HyNetworks/tcp-brutal/master/scripts/install_dkms.sh -o "$tmp" \
     && bash "$tmp" install; then
    modprobe brutal >/dev/null 2>&1 || true
    info "tcp-brutal installed."
  else
    warn "tcp-brutal installation failed; TLSVPN remains installed and usable without Brutal."
  fi
  rm -f "$tmp"
}

uninstall_tcp_brutal() {
  local tmp; tmp="$(mktemp)"
  if curl -fsSL --retry 4 https://raw.githubusercontent.com/HyNetworks/tcp-brutal/master/scripts/install_dkms.sh -o "$tmp"; then bash "$tmp" uninstall || true; fi
  rm -f "$tmp"
}

apply_kernel_tuning() {
  [[ "$KERNEL_TUNING" == "yes" ]] || return 0
  local bbr=""
  modprobe tcp_bbr >/dev/null 2>&1 || true
  if [[ -r /proc/sys/net/ipv4/tcp_available_congestion_control ]] && grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then bbr='net.ipv4.tcp_congestion_control = bbr'; fi
  cat >"$SYSCTL_FILE.tmp" <<EOF
# Managed by tlsvpn-rs scripts/install.sh
net.core.default_qdisc = fq
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
$bbr
EOF
  run mv -f "$SYSCTL_FILE.tmp" "$SYSCTL_FILE"
  run sysctl --system >/dev/null
  info "Network kernel tuning installed in $SYSCTL_FILE"
}

install_action() {
  require_root; detect_platform; validate_common; install_base_dependencies
  [[ -n "$MODE" ]] || die "--mode is required in non-interactive mode"
  create_backup; ROLLBACK_ON_ERROR="yes"
  run mkdir -p "$STATE_DIR" "$BACKUP_DIR"
  install_tlsvpn_binary
  prepare_certificate
  write_config
  write_service
  install_xanmod || true
  install_tcp_brutal || true
  apply_kernel_tuning
  write_state
  write_daily_task
  start_service
  ROLLBACK_ON_ERROR="no"
  info "TLSVPN installation complete."
  info "Config: $CONFIG_FILE"
  [[ -n "$WEB_AUTH" ]] && info "Dashboard credential: ${WEB_AUTH%%:*}:<the configured password>"
  [[ "$XANMOD" == "yes" ]] && info "If XanMod was newly installed, reboot when convenient."
}

upgrade_action() {
  require_root; detect_platform; install_base_dependencies
  load_state || true
  create_backup; ROLLBACK_ON_ERROR="yes"
  local before=""
  [[ -x "$INSTALL_DIR/$PROGRAM" ]] && before="$($INSTALL_DIR/$PROGRAM --version 2>/dev/null || true)"
  install_tlsvpn_binary
  start_service
  ROLLBACK_ON_ERROR="no"
  info "TLSVPN upgrade complete${before:+ (previous: $before)}."
}

maintenance_action() {
  require_root; detect_platform; install_base_dependencies
  load_state || die "No installer state found at $STATE_FILE"
  local cert_changed="no"
  if [[ "$CERT_MODE" == "lego" ]]; then renew_lego_certificate && cert_changed="yes" || true
  elif [[ "$CERT_MODE" == "self-signed" && -s "$CERT_DIR/server.crt" ]] && ! openssl x509 -checkend 2592000 -noout -in "$CERT_DIR/server.crt" >/dev/null 2>&1; then create_self_signed_certificate; cert_changed="yes"; fi
  local installed="" latest=""
  [[ -r "$STATE_DIR/installed-version" ]] && installed="$(cat "$STATE_DIR/installed-version")"
  latest="$(latest_release_tag || true)"
  if [[ -n "$latest" && "$latest" != "$installed" ]]; then
    info "New release detected: ${installed:-unknown} -> $latest"
    VERSION="$latest"; upgrade_action
  elif [[ "$cert_changed" == "yes" ]]; then start_service; else info "No TLSVPN update is available."; fi
}

uninstall_action() {
  require_root; detect_platform
  if [[ "$ASSUME_YES" != "yes" ]] && ! confirm "Remove TLSVPN managed files?"; then die "Cancelled."; fi
  create_backup
  stop_service
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl disable tlsvpn.service >/dev/null 2>&1 || true; else rc-update del tlsvpn default >/dev/null 2>&1 || true; fi
  remove_daily_task
  run rm -f "$SYSTEMD_SERVICE" "$OPENRC_SERVICE" "$INSTALL_DIR/$PROGRAM" "$SYSCTL_FILE"
  if [[ "$REMOVE_OPTIONAL" == "yes" && -x /usr/local/bin/brutalctl ]]; then uninstall_tcp_brutal; fi
  reload_init
  if [[ "$PURGE" == "yes" ]]; then
    run rm -rf "$CONFIG_DIR" "$STATE_DIR" /usr/local/lib/tlsvpn
  else
    run rm -f "$INSTALLER_COPY"
    info "Configuration, certificates and rollback snapshots were preserved. Use --purge to remove them."
  fi
  info "TLSVPN uninstalled. XanMod kernel packages are never removed automatically to avoid removing the running kernel."
}

rollback_action() {
  require_root; detect_platform
  local id="$BACKUP_ID"
  if [[ -z "$id" ]]; then id="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort | tail -n1)"; fi
  [[ -n "$id" ]] || die "No rollback snapshot is available."
  restore_backup "$id"
}

status_action() {
  detect_platform
  printf 'Distribution: %s\nArchitecture: %s\nInit: %s\n' "$DISTRO" "$HOST_ARCH" "$INIT_SYSTEM"
  if [[ -x "$INSTALL_DIR/$PROGRAM" ]]; then printf 'TLSVPN binary: %s\n' "$INSTALL_DIR/$PROGRAM"; else printf 'TLSVPN binary: not installed\n'; fi
  [[ -r "$STATE_DIR/installed-version" ]] && printf 'Installed release: %s\n' "$(cat "$STATE_DIR/installed-version")"
  printf 'Config: %s\n' "$([[ -r "$CONFIG_FILE" ]] && echo "$CONFIG_FILE" || echo 'not found')"
  if [[ -s "$CERT_DIR/server.crt" ]]; then
    printf 'Certificate: '; openssl x509 -noout -subject -enddate -in "$CERT_DIR/server.crt" 2>/dev/null | tr '\n' ' '; printf '\n'
  fi
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl --no-pager --full status tlsvpn.service 2>/dev/null | sed -n '1,8p' || true; else rc-service tlsvpn status 2>/dev/null || true; fi
  if [[ -r /proc/sys/net/ipv4/tcp_available_congestion_control ]]; then printf 'Congestion controls: %s\n' "$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"; fi
  [[ -x /usr/local/bin/brutalctl ]] && printf 'tcp-brutal: installed\n' || true
  [[ "$(uname -r)" == *xanmod* ]] && printf 'Kernel: %s (XanMod)\n' "$(uname -r)" || printf 'Kernel: %s\n' "$(uname -r)"
}

main() {
  parse_args "$@"
  if [[ -z "$ACTION" ]]; then interactive_wizard; fi
  [[ -n "$ACTION" ]] || ACTION="install"
  [[ "$ACTION" == "help" ]] && { usage; exit 0; }
  validate_common
  case "$ACTION" in
    install) install_action ;;
    upgrade) upgrade_action ;;
    uninstall) uninstall_action ;;
    rollback) rollback_action ;;
    maintenance) maintenance_action ;;
    status) status_action ;;
    *) die "Unknown action: $ACTION" ;;
  esac
}

main "$@"
