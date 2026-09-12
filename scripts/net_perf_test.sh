#!/usr/bin/env bash
# net_perf_test.sh — end-to-end network tests over a REAL TAP tunnel:
#
#   * ping        (v4 + v6: RTT avg, packet loss; asserts 0% loss)
#   * traceroute  (v4 + v6: gateway must answer through the tunnel)
#   * throughput  (iperf3 up/down if installed; librespeed if
#                  LIBRESPEED_CLI + a backend binary are available)
#
# Requirements: root + CAP_NET_ADMIN (a real TAP device). GitHub-hosted
# runners cannot create one, so the script prints SKIP and exits 0 there,
# keeping CI green — point the workflow job at a privileged self-hosted
# runner to execute for real. Both endpoints run on the same machine, so
# the measured throughput reflects the tunnel stack itself (TLS + inner
# crypto + vswitch), not the physical network.
#
# Env:
#   BIN_SRV / BIN_CLI       server/client binary paths (required)
#   FLAVOR_SRV / FLAVOR_CLI "rs" | "go" (default rs)
#   PORT                    tunnel TCP port (default 18600)
#   IPERF_MIN_MBPS          throughput assert threshold (default 100)
#   LIBRESPEED_CLI          path to librespeed-cli (optional)
#   LIBRESPEED_SRV_BIN      librespeed backend binary (optional;
#                           default "speedtest-backend" if on PATH)
#
# Fixed addressing (defaults): v4 10.77.0.0/24 (gw .1 = server, client .2),
# v6 fd77::/64 (gw fd77::1, client fd77::2).
set -uo pipefail

PORT="${PORT:-18600}"
SUBNET_V4="${SUBNET_V4:-10.77.0.0/24}"
GW_V4="10.77.0.1"
CLI_V4="10.77.0.2"
GW_V6="fd77::1"
CLI_V6="fd77::2"
IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-100}"
FLAVOR_SRV="${FLAVOR_SRV:-rs}"
FLAVOR_CLI="${FLAVOR_CLI:-rs}"
TAP_SRV="tap_t0"
TAP_CLI="tap_t1"

PASS=0; FAIL=0; SKIPPED=0
log()  { echo "[netperf] $*"; }
ok()   { echo "[netperf] ✅ $*"; PASS=$((PASS+1)); }
fail() { echo "[netperf] ❌ $*"; FAIL=$((FAIL+1)); }
skip() { echo "[netperf] ⏭️  $*"; SKIPPED=$((SKIPPED+1)); }

# ---------------------------------------------------------------------------
# Capability gate: real TAP needs root + CAP_NET_ADMIN. Hosted runners exit
# here with SKIP so the CI job stays green.
# ---------------------------------------------------------------------------
skip_reason=""
if [[ $EUID -ne 0 ]]; then
  skip_reason="not running as root"
elif [[ ! -c /dev/net/tun ]]; then
  skip_reason="/dev/net/tun not available"
else
  if ! ip tuntap add dev tap_capchk mode tap 2>/dev/null; then
    skip_reason="cannot create TAP (no CAP_NET_ADMIN, e.g. GitHub-hosted runner)"
  else
    ip link del tap_capchk 2>/dev/null || true
  fi
fi
if [[ -n "$skip_reason" ]]; then
  log "SKIP: $skip_reason"
  log "Run this on a privileged/self-hosted runner (or a server) for real results."
  exit 0
fi

if [[ -z "${BIN_SRV:-}" || -z "${BIN_CLI:-}" ]]; then
  log "SKIP: BIN_SRV / BIN_CLI not provided"
  exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
  log "SKIP: openssl missing (needed for the tunnel TLS certificate)"
  exit 0
fi

# Best-effort optional tools (root can apt-install; ignore failures).
if ! command -v iperf3 >/dev/null 2>&1 || ! command -v traceroute >/dev/null 2>&1; then
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq iperf3 traceroute >/dev/null 2>&1 || true
fi
HAVE_IPERF=$(command -v iperf3 || true)
HAVE_TRACEROUTE=$(command -v traceroute || true)
HAVE_PY3=$(command -v python3 || true)

# ---------------------------------------------------------------------------
# Flag mapping (Go: single-dash; Rust: long double-dash), mirrors e2e_test.sh.
# ---------------------------------------------------------------------------
flag_for() {
  local flavor="$1" verb="$2"
  if [[ "$flavor" == "rs" ]]; then
    case "$verb" in
      mode) echo "--mode";; addr) echo "--addr";; tap) echo "--tap";;
      cert) echo "--cert";; key) echo "--key";; v4cidr) echo "--v4cidr";;
      v6cidr) echo "--v6cidr";; encrypt) echo "--encrypt";;
      loglevel) echo "--loglevel";; certsha) echo "--cert_sha256";;
      insecure) echo "--insecure";;
    esac
  else
    case "$verb" in
      mode) echo "-mode";; addr) echo "-addr";; tap) echo "-tap";;
      cert) echo "-cert";; key) echo "-key";; v4cidr) echo "-v4cidr";;
      v6cidr) echo "-v6cidr";; encrypt) echo "-encrypt";;
      loglevel) echo "-loglevel";; certsha) echo "-cert-sha256";;
      insecure) echo "-insecure";;
    esac
  fi
}

SRV_DIR=""
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  sleep 0.5
  ip link del "$TAP_SRV" 2>/dev/null || true
  ip link del "$TAP_CLI" 2>/dev/null || true
  [[ -n "$SRV_DIR" && -d "$SRV_DIR" ]] && rm -rf "$SRV_DIR"
  return 0
}
trap cleanup EXIT

wait_for_port() {
  local host="$1" port="$2" deadline=$(( $(date +%s) + ${3:-20} ))
  while ! (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
    [[ $(date +%s) -lt $deadline ]] || return 1
    sleep 0.3
  done
  exec 3>&- 2>/dev/null || true
  return 0
}

# Wait until the client's tunnel IP shows up on its TAP (handshake done).
wait_for_client_ip() {
  local deadline=$(( $(date +%s) + 30 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if ip -4 addr show "$TAP_CLI" 2>/dev/null | grep -q "$CLI_V4"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# ---------------------------------------------------------------------------
# ping: 0% loss asserted; avg RTT reported.
# ---------------------------------------------------------------------------
ping_check() {
  local label="$1" target="$2" v6="$3"
  local out loss avg
  if [[ "$v6" == "v6" ]]; then
    out=$(ping -6 -c 10 -i 0.2 -W 1 "$target" 2>&1) || true
  else
    out=$(ping -c 10 -i 0.2 -W 1 "$target" 2>&1) || true
  fi
  loss=$(echo "$out" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' | grep -oE '^[0-9]+(\.[0-9]+)?')
  avg=$(echo "$out" | grep -oE '= [0-9.]+/[0-9.]+/[0-9.]+' | head -1 | cut -d/ -f2)
  if [[ "${loss:-100}" == "0" || "${loss:-100}" == "0.0" ]]; then
    ok "ping $label ($target): 0% loss, avg ${avg:-?} ms"
  else
    fail "ping $label ($target): loss ${loss:-?}%"
  fi
}

# ---------------------------------------------------------------------------
# traceroute: the gateway itself must answer through the tunnel (1 hop).
# ---------------------------------------------------------------------------
traceroute_check() {
  local label="$1" target="$2" v6="$3"
  if [[ -z "$HAVE_TRACEROUTE" ]]; then
    skip "traceroute not installed — $label skipped"
    return 0
  fi
  local out
  if [[ "$v6" == "v6" ]]; then
    out=$(traceroute -6 -n -w 1 -q 1 -m 3 "$target" 2>&1) || true
  else
    out=$(traceroute -n -w 1 -q 1 -m 3 "$target" 2>&1) || true
  fi
  log "traceroute $label:"
  echo "$out" | sed 's/^/[netperf]     /'
  if echo "$out" | grep -q "$target"; then
    ok "traceroute $label: gateway answered through the tunnel"
  else
    fail "traceroute $label: gateway did not answer"
  fi
}

# ---------------------------------------------------------------------------
# iperf3: server binds the tunnel gateway IP; client tests through tunnel.
# Loopback endpoints → measures the tunnel stack overhead itself.
# ---------------------------------------------------------------------------
iperf_one_way() {
  local label="$1" extra="${2:-}"
  local json mbps
  json=$(iperf3 -c "$GW_V4" -p "$((PORT + 1))" -t 3 -J $extra 2>/dev/null) || {
    fail "iperf3 $label: transfer failed"; return 1;
  }
  if [[ -n "$HAVE_PY3" ]]; then
    mbps=$(printf '%s' "$json" | python3 -c '
import json,sys
d=json.load(sys.stdin)
end=d.get("end",{})
s=end.get("sum_received") or end.get("sum_sent") or {}
print(f"{s.get(\"bits_per_second\",0)/1e6:.1f}")' 2>/dev/null || echo "?")
  else
    mbps="?"
  fi
  if [[ "$mbps" == "?" ]]; then
    ok "iperf3 $label: transfer ok (install python3 for Mbps parsing)"
    return 0
  fi
  if (( $(echo "$mbps >= $IPERF_MIN_MBPS" | bc -l 2>/dev/null || echo 1) )); then
    ok "iperf3 $label: ${mbps} Mbps (>= ${IPERF_MIN_MBPS})"
  else
    fail "iperf3 $label: ${mbps} Mbps < ${IPERF_MIN_MBPS} threshold"
  fi
}

iperf_check() {
  if [[ -z "$HAVE_IPERF" ]]; then
    skip "iperf3 not installed — throughput test skipped"
    return 0
  fi
  iperf3 -s -B "$GW_V4" -p "$((PORT + 1))" >/dev/null 2>&1 &
  PIDS+=($!)
  sleep 0.5
  iperf_one_way "upload (cli→srv)"
  iperf_one_way "download (srv→cli)" "-R"
  kill "${PIDS[-1]}" 2>/dev/null || true
  PIDS=("${PIDS[@]:0:${#PIDS[@]}-1}")
}

# ---------------------------------------------------------------------------
# librespeed (optional): needs LIBRESPEED_CLI plus a backend binary. The
# backend is started on the tunnel gateway IP; the CLI runs a standard
# HTML5-speedtest (ping/jitter/download/upload) through the tunnel.
# ---------------------------------------------------------------------------
librespeed_check() {
  local cli="${LIBRESPEED_CLI:-$(command -v librespeed-cli || true)}"
  local srv_bin="${LIBRESPEED_SRV_BIN:-$(command -v speedtest-backend || command -v librespeed-backend || true)}"
  if [[ -z "$cli" || -z "$srv_bin" ]]; then
    skip "librespeed not available (need LIBRESPEED_CLI + backend binary)"
    return 0
  fi
  local dir; dir=$(mktemp -d)
  "$srv_bin" >/dev/null 2>&1 &
  local srv_pid=$!
  PIDS+=($srv_pid)
  sleep 1
  cat > "$dir/servers.json" <<'JSONEOF'
[{"name":"tunnel","id":1,"server":"http://SERVERURL","dl":"/backend/garbage.php","ul":"/backend/empty.php","ping":"/backend/empty.php","getIP":"/backend/getIP.php"}]
JSONEOF
  sed -i "s|SERVERURL|${GW_V4}:8080|" "$dir/servers.json"
  local out
  out=$("$cli" --server-json "$dir/servers.json" --json 2>/dev/null) || true
  kill "$srv_pid" 2>/dev/null || true
  PIDS=("${PIDS[@]:0:${#PIDS[@]}-1}")
  rm -rf "$dir"
  log "librespeed output:"
  echo "$out" | sed 's/^/[netperf]     /' | head -5
  if echo "$out" | grep -q '"download"'; then
    ok "librespeed: speed test completed through the tunnel"
  else
    fail "librespeed: no result produced"
  fi
}

# ---------------------------------------------------------------------------
# One full group = server + client (real TAP) + all checks.
# ---------------------------------------------------------------------------
run_group() {
  SRV_DIR=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$SRV_DIR/e2e_key.pem" -out "$SRV_DIR/e2e_cert.pem" \
    -days 2 -subj "/CN=tlsvpn-netperf" >/dev/null 2>&1

  log "--- group: ${FLAVOR_SRV}_srv <- ${FLAVOR_CLI}_cli (real TAP) ---"

  local m_flag a_flag t_flag c_flag k_flag f4_flag f6_flag e_flag l_flag
  m_flag=$(flag_for "$FLAVOR_SRV" mode);   a_flag=$(flag_for "$FLAVOR_SRV" addr)
  t_flag=$(flag_for "$FLAVOR_SRV" tap);    c_flag=$(flag_for "$FLAVOR_SRV" cert)
  k_flag=$(flag_for "$FLAVOR_SRV" key);    f4_flag=$(flag_for "$FLAVOR_SRV" v4cidr)
  f6_flag=$(flag_for "$FLAVOR_SRV" v6cidr); e_flag=$(flag_for "$FLAVOR_SRV" encrypt)
  l_flag=$(flag_for "$FLAVOR_SRV" loglevel)
  "$BIN_SRV" $m_flag server $a_flag "127.0.0.1:$PORT" $t_flag "$TAP_SRV" \
    $c_flag "$SRV_DIR/e2e_cert.pem" $k_flag "$SRV_DIR/e2e_key.pem" \
    $f4_flag "$SUBNET_V4" $f6_flag "fd77::/64" $e_flag $l_flag debug \
    > "$SRV_DIR/srv.log" 2>&1 &
  PIDS+=($!)
  wait_for_port 127.0.0.1 "$PORT" 20 || { fail "server did not start"; return 1; }

  # 自签证书：客户端必须 pin 指纹（或 insecure），否则 TLS 校验失败
  local fp
  fp=$(openssl x509 -in "$SRV_DIR/e2e_cert.pem" -noout -fingerprint -sha256 \
       | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z')
  log "server cert sha256 pinned: $fp"

  local cm_flag ca_flag ct_flag ce_flag cl_flag cs_flag
  cm_flag=$(flag_for "$FLAVOR_CLI" mode); ca_flag=$(flag_for "$FLAVOR_CLI" addr)
  ct_flag=$(flag_for "$FLAVOR_CLI" tap);  ce_flag=$(flag_for "$FLAVOR_CLI" encrypt)
  cl_flag=$(flag_for "$FLAVOR_CLI" loglevel); cs_flag=$(flag_for "$FLAVOR_CLI" certsha)
  # Go 客户端的 -cert-sha256 仅设置 VerifyPeerCertificate，链验证先行失败
  # （自签证书），需配合 -insecure 才能真正生效；Rust 客户端的 cert_sha256
  # 走 dangerous() 完整替换验证器，无需也不应叠加 insecure。
  local extra_cli=""
  if [[ "$FLAVOR_CLI" == "go" ]]; then
    extra_cli="$(flag_for go insecure)"
  fi
  "$BIN_CLI" $cm_flag client $ca_flag "127.0.0.1:$PORT" $ct_flag "$TAP_CLI" \
    $cs_flag "$fp" $extra_cli $ce_flag $cl_flag info > "$SRV_DIR/cli.log" 2>&1 &
  PIDS+=($!)

  if ! wait_for_client_ip; then
    fail "client tunnel IP ($CLI_V4) never appeared"
    log "--- server log tail ---"; tail -5 "$SRV_DIR/srv.log" || true
    log "--- client log tail ---"; tail -5 "$SRV_DIR/cli.log" || true
    return 1
  fi
  sleep 1  # let the vswitch learn MACs via first ARPs

  ping_check "v4 cli→gw" "$GW_V4" v4
  ping_check "v6 cli→gw" "$GW_V6" v6
  traceroute_check "v4" "$GW_V4" v4
  traceroute_check "v6" "$GW_V6" v6
  iperf_check
  librespeed_check
  return 0
}

run_group
log "=== summary: pass=$PASS fail=$FAIL skip=$SKIPPED ==="
[[ $FAIL -eq 0 ]]
