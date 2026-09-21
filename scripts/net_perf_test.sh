#!/usr/bin/env bash
# net_perf_test.sh — end-to-end network tests over a REAL TAP tunnel:
#
#   * ping        (v4 + v6: RTT avg, packet loss; asserts 0% loss)
#   * traceroute  (v4 + v6: gateway must answer through the tunnel)
#   * throughput  (iperf3 up/down if installed; librespeed if
#                  LIBRESPEED_CLI + a backend binary are available)
#
# Requirements: root + the full RTNL path over a real TAP device — create,
# bring the link up, and assign addresses. Anything short of that prints
# SKIP with the precise missing step and exits 0, keeping CI green.
#
# Note the gate is deliberately stricter than "can I create a TAP?": that
# alone passes on ubuntu-latest, where TUNSETIFF is allowed but RTNL is not,
# so the job would proceed and the server would die before binding its port,
# which looked like "server did not start". Both endpoints run on the same
# machine, so the measured throughput reflects the tunnel stack itself
# (TLS + inner crypto + vswitch), not the physical network.
#
# Env:
#   BIN_SRV / BIN_CLI       server/client binary paths (required)
#   FLAVOR_SRV / FLAVOR_CLI "rs" | "go" (default rs)
#   PORT                    tunnel TCP port (default 18600)
#   PSK                     tunnel secret (default: openssl rand -hex 16)
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
# Capability gate: a real tunnel needs root + the whole RTNL path, not just
# TAP creation. The gate used to test only `ip tuntap add`, which passes on
# ubuntu-latest — the device is created but `ip link set ... up` / `ip addr
# replace` are the steps that decide whether a tunnel can actually run. A
# partial grant here made the gate report "capable" and then let the server
# die before it ever bound its port, surfacing only as "server did not start".
# Test the create+up+address sequence instead, so an environment that cannot
# run a tunnel SKIPs instead of failing inside the server.
# ---------------------------------------------------------------------------
skip_reason=""
if [[ $EUID -ne 0 ]]; then
  skip_reason="not running as root"
elif [[ ! -c /dev/net/tun ]]; then
  skip_reason="/dev/net/tun not available"
else
  if ! ip tuntap add dev tap_capchk mode tap 2>/dev/null; then
    skip_reason="cannot create TAP (no CAP_NET_ADMIN, e.g. GitHub-hosted runner)"
  elif ! ip link set dev tap_capchk up 2>/dev/null; then
    skip_reason="TAP created but cannot bring the link up (TUNSETIFF allowed, RTNL refused)"
  elif ! ip addr replace 10.77.99.1/24 dev tap_capchk 2>/dev/null; then
    skip_reason="TAP created but cannot assign an address (RTNL refused)"
  fi
  ip link del tap_capchk 2>/dev/null || true
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

# 放在上面的 openssl 门之后：openssl 缺失时这里会生成空串，而两实现的配置
# 校验都会以 "psk is required" 拒绝空串。两实现只拒空串加 4 个占位符
# (quic_secret / change-me / change-me-please / replace-with-a-random-secret)，
# 十六进制随机串必然通过。
PSK="${PSK:-$(openssl rand -hex 16)}"

# Best-effort optional tools (root can apt-install; ignore failures).
if ! command -v iperf3 >/dev/null 2>&1 || ! command -v traceroute >/dev/null 2>&1; then
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq iperf3 traceroute >/dev/null 2>&1 || true
fi
HAVE_IPERF=$(command -v iperf3 || true)
HAVE_TRACEROUTE=$(command -v traceroute || true)
HAVE_PY3=$(command -v python3 || true)
HAVE_AWK=$(command -v awk || true)

SRV_DIR=""
PIDS=()

# Generate a JSON config for either implementation — both are config-file-only
# since 2026-09-19 (their command-line flags were removed; launch with -c),
# and both consume the same top-level key names.
#   impl_config OUT MODE ADDR [json-fragment...]
# "tap" is NOT preset here — the real TAP device name is passed as a fragment
# (unlike the mem-tap e2e helper).
impl_config() {
  local out="$1" mode="$2" addr="$3"; shift 3
  {
    # mode / addr / psk 是两实现都必需的顶层键，在这里预置而不是让每个
    # 调用点自己记得带。psk 曾就是这样被漏掉的：三处调用都没写，脚本自
    # 2026-09-19 改为 -c 配置启动起就没真正跑通过，托管 runner 上一直被
    # TAP 能力门拦成 SKIP，所以没人发现。
    printf '{\n  "mode": "%s",\n  "addr": "%s",\n  "psk": "%s"' "$mode" "$addr" "$PSK"
    local frag
    for frag in "$@"; do
      [ -n "$frag" ] && printf ',\n  %s' "$frag"
    done
    printf '\n}\n'
  } >"$out"
}

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
    # python3 存在但解析不出数字时 mbps 是空串：Windows Store 的占位程序会
    # 静默以 0 退出而不打印任何内容。空串必须当成"没解析出来"，否则下一步会
    # 拿 0 去比阈值，把一个跑通的传输判成未达标。
    [[ "$mbps" =~ ^[0-9]+([.][0-9]+)?$ ]] || mbps="?"
  else
    mbps="?"
  fi
  if [[ "$mbps" == "?" ]]; then
    ok "iperf3 $label: transfer ok (install python3 for Mbps parsing)"
    return 0
  fi
  # awk 做浮点比较：POSIX 且每个 runner 都有。此前用 bc，而 bc 缺失时
  # `… | bc -l 2>/dev/null || echo 1` 把失败的比较替换成字面量 1，
  # `(( 1 ))` 为真 —— 吞吐断言静默通过，等于没断言。
  if [[ -z "$HAVE_AWK" ]]; then
    ok "iperf3 $label: transfer ok (no awk — Mbps assertion skipped)"
    return 0
  fi
  if "$HAVE_AWK" -v a="$mbps" -v b="$IPERF_MIN_MBPS" 'BEGIN { exit !(a + 0 >= b + 0) }'; then
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

  log "--- group: ${FLAVOR_SRV}_srv <- ${FLAVOR_CLI}_cli (real TAP) ---"

  # 两实现 flags 均已移除（2026-09-19）：键名两边一致，服务端配置共用一份
  local scfg="$SRV_DIR/srv.json"
  impl_config "$scfg" server "127.0.0.1:$PORT" \
    '"encrypt": true' \
    '"log_level": "debug"' \
    "\"tap\": \"$TAP_SRV\"" \
    "\"server\": {\"cert\": \"$SRV_DIR/e2e_cert.pem\", \"key\": \"$SRV_DIR/e2e_key.pem\", \"v4_cidr\": \"$SUBNET_V4\", \"v6_cidr\": \"fd77::/64\"}"

  # 证书生成失败以前是被 >/dev/null 吞掉的：服务端随后在 build_server_tls
  # 退出（"Invalid configuration: ..."），表象只有 "server did not start"，
  # 看不出是证书没生成还是别的原因。这里直接断掉。
  if ! openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$SRV_DIR/e2e_key.pem" -out "$SRV_DIR/e2e_cert.pem" \
      -days 2 -subj "/CN=tlsvpn-netperf" >/dev/null 2>&1 \
     || { [ ! -s "$SRV_DIR/e2e_key.pem" ] || [ ! -s "$SRV_DIR/e2e_cert.pem" ]; }; then
    fail "TLS cert generation failed ($SRV_DIR) — openssl is $(openssl version 2>/dev/null || echo 'missing')"
    return 1
  fi

  "$BIN_SRV" -c "$scfg" > "$SRV_DIR/srv.log" 2>&1 &
  local srv_pid=$!
  PIDS+=($srv_pid)
  if ! wait_for_port 127.0.0.1 "$PORT" 20; then
    fail "server did not start (127.0.0.1:$PORT never opened within 20s)"
    log "server process: $(kill -0 "$srv_pid" 2>/dev/null && echo 'still alive (hangs before binding)' || echo 'already exited (see log)')"
    log "--- server log ---"; sed 's/^/[netperf]     /' "$SRV_DIR/srv.log" | tail -25 || true
    log "--- server config ---"; sed 's/^/[netperf]     /' "$scfg" || true
    return 1
  fi

  # 自签证书：客户端必须 pin 指纹（或 insecure），否则 TLS 校验失败
  local fp
  fp=$(openssl x509 -in "$SRV_DIR/e2e_cert.pem" -noout -fingerprint -sha256 \
       | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z')
  log "server cert sha256 pinned: $fp"

  # Go 客户端的 cert_sha256 仅设置 VerifyPeerCertificate，链验证先行失败
  # （自签证书），需配合 insecure 才能真正生效；Rust 客户端的 cert_sha256
  # 走 dangerous() 完整替换验证器，无需也不应叠加 insecure。
  local ccfg="$SRV_DIR/cli.json"
  if [[ "$FLAVOR_CLI" == "go" ]]; then
    impl_config "$ccfg" client "127.0.0.1:$PORT" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "\"tap\": \"$TAP_CLI\"" \
      "\"client\": {\"cert_sha256\": \"$fp\", \"insecure\": true}"
  else
    impl_config "$ccfg" client "127.0.0.1:$PORT" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "\"tap\": \"$TAP_CLI\"" \
      "\"client\": {\"cert_sha256\": \"$fp\"}"
  fi
  "$BIN_CLI" -c "$ccfg" > "$SRV_DIR/cli.log" 2>&1 &
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
