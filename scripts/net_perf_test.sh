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

# Keep tunnel endpoints in separate network namespaces. If both tunnel IPs
# live in one namespace, Linux table local can satisfy ping/iperf without TAP.
NS_SRV="tlsvpn-srv-$"
NS_CLI="tlsvpn-cli-$"
UNDERLAY_SRV="192.0.2.1"
UNDERLAY_CLI="192.0.2.2"
UNDERLAY_PREFIX=30
VETH_SRV="tvs$"
VETH_CLI="tvc$"

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
CAP_NS="tlsvpn-cap-$$"
CAP_VETH_A="tca$$"
CAP_VETH_B="tcb$$"
if [[ $EUID -ne 0 ]]; then
  skip_reason="not running as root"
elif [[ ! -c /dev/net/tun ]]; then
  skip_reason="/dev/net/tun not available"
else
  # Probe the exact primitives required by the isolated real-TAP test.
  if ! ip netns add "$CAP_NS" 2>/dev/null; then
    skip_reason="cannot create network namespace (netns unavailable)"
  elif ! ip link add "$CAP_VETH_A" type veth peer name "$CAP_VETH_B" 2>/dev/null; then
    skip_reason="cannot create veth pair (CAP_NET_ADMIN unavailable)"
  elif ! ip link set "$CAP_VETH_B" netns "$CAP_NS" 2>/dev/null; then
    skip_reason="cannot move veth into network namespace"
  elif ! ip netns exec "$CAP_NS" ip link set lo up 2>/dev/null; then
    skip_reason="cannot configure loopback inside network namespace"
  elif ! ip netns exec "$CAP_NS" ip tuntap add dev tap_capchk mode tap 2>/dev/null; then
    skip_reason="cannot create TAP inside network namespace"
  elif ! ip netns exec "$CAP_NS" ip link set dev tap_capchk up 2>/dev/null; then
    skip_reason="TAP created but cannot bring the link up (RTNL refused)"
  elif ! ip netns exec "$CAP_NS" ip addr replace 10.77.99.1/24 dev tap_capchk 2>/dev/null; then
    skip_reason="TAP created but cannot assign an address (RTNL refused)"
  fi
  ip link del "$CAP_VETH_A" 2>/dev/null || true
  ip netns del "$CAP_NS" 2>/dev/null || true
fi
if [[ -n "$skip_reason" ]]; then
  log "SKIP: $skip_reason"
  log "Run this on a runner/server with network namespaces + CAP_NET_ADMIN for real results."
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
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip netns del "$NS_CLI" 2>/dev/null || true
  # Cover partial setup failures before the veths were moved.
  ip link del "$VETH_SRV" 2>/dev/null || true
  ip link del "$VETH_CLI" 2>/dev/null || true
  [[ -n "$SRV_DIR" && -d "$SRV_DIR" ]] && rm -rf "$SRV_DIR"
  return 0
}
trap cleanup EXIT

setup_namespaces() {
  ip netns add "$NS_SRV" || return 1
  ip netns add "$NS_CLI" || return 1
  ip link add "$VETH_SRV" type veth peer name "$VETH_CLI" || return 1
  ip link set "$VETH_SRV" netns "$NS_SRV" || return 1
  ip link set "$VETH_CLI" netns "$NS_CLI" || return 1

  ip netns exec "$NS_SRV" ip link set lo up || return 1
  ip netns exec "$NS_CLI" ip link set lo up || return 1
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" name underlay0 || return 1
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" name underlay0 || return 1
  ip netns exec "$NS_SRV" ip addr add "$UNDERLAY_SRV/$UNDERLAY_PREFIX" dev underlay0 || return 1
  ip netns exec "$NS_CLI" ip addr add "$UNDERLAY_CLI/$UNDERLAY_PREFIX" dev underlay0 || return 1
  ip netns exec "$NS_SRV" ip link set underlay0 up || return 1
  ip netns exec "$NS_CLI" ip link set underlay0 up || return 1
}

if ! setup_namespaces; then
  fail "failed to create isolated server/client network namespaces"
  exit 1
fi

wait_for_port() {
  local ns="$1" host="$2" port="$3" timeout="${4:-20}"
  local deadline=$(( $(date +%s) + timeout ))
  while ! ip netns exec "$ns" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; do
    [[ $(date +%s) -lt $deadline ]] || return 1
    sleep 0.3
  done
  return 0
}

# Wait until the client tunnel IP shows up inside its namespace (handshake done).
wait_for_client_ip() {
  local deadline=$(( $(date +%s) + 30 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if ip netns exec "$NS_CLI" ip -4 addr show "$TAP_CLI" 2>/dev/null | grep -q "$CLI_V4"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# Prove that benchmark traffic cannot take a table-local/loopback shortcut.
route_path_check() {
  local croute sroute
  croute=$(ip netns exec "$NS_CLI" ip -4 route get "$GW_V4" 2>&1) || {
    fail "client route lookup to $GW_V4 failed"; return 1;
  }
  sroute=$(ip netns exec "$NS_SRV" ip -4 route get "$CLI_V4" 2>&1) || {
    fail "server route lookup to $CLI_V4 failed"; return 1;
  }
  log "client route: $croute"
  log "server route: $sroute"
  if [[ "$croute" == *"dev $TAP_CLI"* ]]; then
    ok "client route to server tunnel IP uses $TAP_CLI"
  else
    fail "client route bypasses $TAP_CLI (benchmark would be invalid)"
    return 1
  fi
  if [[ "$sroute" == *"dev $TAP_SRV"* ]]; then
    ok "server route to client tunnel IP uses $TAP_SRV"
  else
    fail "server route bypasses $TAP_SRV (benchmark would be invalid)"
    return 1
  fi
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
  # iperf3 -J 的 end.sum_received / end.sum_sent 位于 JSON 尾部；
  # 最后一个 bits_per_second 就是最终汇总速率。用 grep+awk 解析，避免
  # hosted runner / 极简 rootfs 缺 Python 时把吞吐断言静默降级成“transfer ok”。
  if [[ -n "$HAVE_AWK" ]]; then
    mbps=$(printf '%s' "$json" |
      grep -oE '"bits_per_second"[[:space:]]*:[[:space:]]*[0-9.eE+-]+' |
      tail -1 |
      "$HAVE_AWK" -F: '{gsub(/[[:space:]]/,"",$2); printf "%.1f", ($2+0)/1000000}')
    [[ "$mbps" =~ ^[0-9]+([.][0-9]+)?$ ]] || mbps="?"
  else
    mbps="?"
  fi
  if [[ "$mbps" == "?" ]]; then
    fail "iperf3 $label: transfer completed but Mbps result could not be parsed"
    return 1
  fi
  # awk 做浮点比较：POSIX 且每个 runner 都有。此前用 bc，而 bc 缺失时
  # `… | bc -l 2>/dev/null || echo 1` 把失败的比较替换成字面量 1，
  # `(( 1 ))` 为真 —— 吞吐断言静默通过，等于没断言。
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
