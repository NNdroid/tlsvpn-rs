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
# Server and client run in separate network namespaces connected only by a
# veth underlay. Their 10.77.0.x / fd77:: tunnel addresses therefore cannot
# become local addresses in the same namespace and bypass the TAP/tunnel path.
# The measured throughput is local-machine tunnel-stack throughput
# (TAP + TLS + inner crypto + vswitch), not physical-network throughput.
#
# Env:
#   BIN_SRV / BIN_CLI       server/client binary paths (required)
#   FLAVOR_SRV / FLAVOR_CLI "rs" | "go" (default rs)
#   PORT                    tunnel TCP port (default 18600)
#   PSK                     tunnel secret (default: openssl rand -hex 16)
#   IPERF_MIN_MBPS          throughput assert threshold (default 100)
#   PERF_CONNS              parallel TLSVPN connections (default 4)
#   LIBRESPEED_CLI          path to librespeed-cli (optional)
#   LIBRESPEED_SRV_BIN      librespeed backend binary (optional;
#                           default "speedtest-backend" if on PATH)
#
# Fixed addressing (defaults): v4 10.77.0.0/24 (gw .1 = server, client .2),
# v6 fd77::/64 (gw fd77::1, client fd77::2).
set -uo pipefail
PERF_METRICS_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/perf_metrics.py"

PORT="${PORT:-18600}"
SUBNET_V4="${SUBNET_V4:-10.77.0.0/24}"
GW_V4="10.77.0.1"
CLI_V4="10.77.0.2"
GW_V6="fd77::1"
CLI_V6="fd77::2"
IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-100}"
IPERF_SECONDS="${IPERF_SECONDS:-3}"
[[ "$IPERF_SECONDS" =~ ^[0-9]+$ ]] && (( IPERF_SECONDS >= 1 && IPERF_SECONDS <= 120 )) || {
  echo '[netperf] invalid IPERF_SECONDS (expected 1..120)'; exit 2;
}
PERF_CONNS="${PERF_CONNS:-4}"
FLAVOR_SRV="${FLAVOR_SRV:-rs}"
FLAVOR_CLI="${FLAVOR_CLI:-rs}"
TAP_SRV="tap_t0"
TAP_CLI="tap_t1"
WEB_ADDR="127.0.0.1:18780"
WEB_AUTH="perf:tlsvpn"

case "$PERF_CONNS" in
  1|2|4) ;;
  *) echo "[netperf] invalid PERF_CONNS=$PERF_CONNS (expected 1, 2 or 4)"; exit 2 ;;
esac

# Keep tunnel endpoints in separate network namespaces. If both tunnel IPs
# live in one namespace, Linux table local can satisfy ping/iperf without TAP.
NS_SRV="tlsvpn-srv-$$"
NS_CLI="tlsvpn-cli-$$"
UNDERLAY_SRV="192.0.2.1"
UNDERLAY_CLI="192.0.2.2"
UNDERLAY_PREFIX=30
VETH_SRV="tvs$$"
VETH_CLI="tvc$$"

PASS=0; FAIL=0; SKIPPED=0
log()  { echo "[netperf] $*"; }
ok()   { echo "[netperf] ✅ $*"; PASS=$((PASS+1)); }
fail() { echo "[netperf] ❌ $*"; FAIL=$((FAIL+1)); }
skip() { echo "[netperf] ⏭️  $*"; SKIPPED=$((SKIPPED+1)); }

# ---------------------------------------------------------------------------
# Capability gate: a valid benchmark needs root, netns/veth, and the whole
# TAP/RTNL path. Probe those exact primitives before building the topology so
# an incapable runner SKIPs instead of producing a partial or misleading test.
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
  if [[ -n "${PERF_PROFILE_DIR:-}" && -d "$SRV_DIR" ]]; then
    mkdir -p "$PERF_PROFILE_DIR"
    cp "$SRV_DIR"/*.log "$PERF_PROFILE_DIR/" 2>/dev/null || true
  fi
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
    out=$(ip netns exec "$NS_CLI" ping -6 -c 10 -i 0.2 -W 1 "$target" 2>&1) || true
  else
    out=$(ip netns exec "$NS_CLI" ping -c 10 -i 0.2 -W 1 "$target" 2>&1) || true
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
    out=$(ip netns exec "$NS_CLI" traceroute -6 -n -w 1 -q 1 -m 3 "$target" 2>&1) || true
  else
    out=$(ip netns exec "$NS_CLI" traceroute -n -w 1 -q 1 -m 3 "$target" 2>&1) || true
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
# Adaptive multipath diagnostics. Upload is scheduled by the client; download
# by the server. The scheduler widens/narrows the active path set with demand
# (active_target, Go-aligned), so "all N paths must carry traffic" is NOT the
# contract anymore. What must hold:
#   1. at least one participating path (>= 1 MiB assigned bytes; handshake
#      dust left on deactivated paths does not count),
#   2. every path the scheduler marks active must be participating — an
#      active-but-starved path is a real scheduling defect,
#   3. with >= 2 participating paths, none may hold > 80% of the bytes; a lone
#      active path is the scheduler's deliberate low-demand concentration.
# ---------------------------------------------------------------------------
scheduler_diag() {
  local direction="$1" ns role
  [[ "$PERF_CONNS" -gt 1 ]] || return 0
  if [[ "$direction" == "upload" ]]; then
    ns="$NS_CLI"; role="client"
  else
    ns="$NS_SRV"; role="server"
  fi

  ip netns exec "$ns" python3 - "$WEB_ADDR" "$WEB_AUTH" "$PERF_CONNS" "$role" "$direction" <<'PY'
import base64, json, sys, time, urllib.request
addr, auth, want_s, role, direction = sys.argv[1:]
want = int(want_s)
req = urllib.request.Request(
    "http://" + addr + "/api/stats",
    headers={"Authorization": "Basic " + base64.b64encode(auth.encode()).decode()},
)
last = None
for _ in range(30):
    try:
        with urllib.request.urlopen(req, timeout=0.5) as r:
            data = json.load(r)
        break
    except Exception as exc:
        last = exc
        time.sleep(0.05)
else:
    raise SystemExit(f"scheduler stats unavailable from {role}: {last}")
rows = data.get("conns", []) if role == "client" else data.get("server_conns", [])
rows = [r for r in rows if isinstance(r.get("scheduler"), dict)][:want]
if len(rows) < want:
    raise SystemExit(f"scheduler telemetry has {len(rows)}/{want} paths for {role}")
assigned = [int((r.get("scheduler") or {}).get("assigned_bytes", 0) or 0) for r in rows]
active = [bool((r.get("scheduler") or {}).get("active", False)) for r in rows]
total = sum(assigned)
if total <= 0:
    raise SystemExit(f"scheduler assigned no bytes: {assigned}")
# "Real payload" floor: handshake/control traffic leaves deactivated paths at
# hundreds of bytes. 1 MiB is an order of magnitude above control-plane volume
# and far below any striped payload share at throughput-test rates.
real_payload = 1 << 20
participating = [i for i in range(want) if assigned[i] >= real_payload]
starved = [i for i in range(want) if active[i] and assigned[i] < real_payload]
print(f"[netperf] scheduler {direction}/{role}: assigned={assigned} active={active} participating={participating}")
if not participating:
    raise SystemExit(f"adaptive scheduler has no participating path (>= {real_payload} bytes): {assigned}")
if starved:
    raise SystemExit(f"adaptive scheduler active-but-starved paths {starved}: {assigned}")
if len(participating) > 1:
    worst = max(assigned[i] for i in participating) / sum(assigned[i] for i in participating)
    if worst > 0.80:
        raise SystemExit(f"adaptive scheduler path monopoly {worst * 100:.1f}% among participating paths: {assigned}")
PY
}

# ---------------------------------------------------------------------------
# iperf3: server binds the tunnel gateway IP; client tests through tunnel.
# Namespace-isolated tunnel endpoints measure the tunnel stack overhead itself.
# ---------------------------------------------------------------------------
iperf_one_way() {
  local label="$1" extra="${2:-}" direction="${3:-upload}"
  local json mbps
  local metrics_file="$SRV_DIR/metrics-$direction.json"
  local metrics_args=("$srv_tunnel_pid" "$cli_tunnel_pid" "$NS_SRV" "$NS_CLI" "$TAP_SRV" "$TAP_CLI")
  local profiler=""
  local pinger=""
  if [[ "${PERF_LATENCY:-0}" == 1 ]]; then
    ip netns exec "$NS_CLI" ping -n -i 0.05 -c "$((IPERF_SECONDS * 20))" -w "$((IPERF_SECONDS + 2))" "$GW_V4" \
      > "$SRV_DIR/ping-load-$direction.log" 2>&1 &
    pinger=$!
    PIDS+=("$pinger")
  fi
  if [[ -n "${PERF_PROFILE_DIR:-}" && "${PERF_PROFILE_CPU:-1}" == 1 ]]; then
    mkdir -p "$PERF_PROFILE_DIR"
    local perf_tool="${PERF_TOOL:-perf}"
    if ! "$perf_tool" stat -e cpu-clock -- true >/dev/null 2>&1; then
      for tool in /usr/lib/linux-tools/*/perf; do
        if [[ -x "$tool" ]] && "$tool" stat -e cpu-clock -- true >/dev/null 2>&1; then perf_tool="$tool"; break; fi
      done
    fi
    if "$perf_tool" stat -e cpu-clock -- true >/dev/null 2>&1; then
      "$perf_tool" record -e cpu-clock -F 99 -g --call-graph fp -p "$srv_tunnel_pid,$cli_tunnel_pid" \
        -o "$PERF_PROFILE_DIR/$direction.data" -- sleep "$IPERF_SECONDS" \
        >"$PERF_PROFILE_DIR/$direction-perf.log" 2>&1 &
      profiler=$!
      PIDS+=("$profiler")
    else
      echo 'PERF_PROFILE SKIP: perf tool or CPU-clock permission unavailable' | tee "$PERF_PROFILE_DIR/SKIP.txt"
    fi
  fi
  python3 "$PERF_METRICS_SCRIPT" start "$metrics_file" "$direction" "${metrics_args[@]}" || {
    fail "could not sample VPN CPU/TAP counters before $direction"; return 1;
  }
  json=$(ip netns exec "$NS_CLI" iperf3 -c "$GW_V4" -p "$((PORT + 1))" -t "$IPERF_SECONDS" -J $extra 2>/dev/null) || {
    fail "iperf3 $label: transfer failed"; return 1;
  }
  python3 "$PERF_METRICS_SCRIPT" finish "$metrics_file" "$direction" "${metrics_args[@]}" || {
    fail "could not sample VPN CPU/TAP counters after $direction"; return 1;
  }
  if [[ -n "$profiler" ]]; then
    wait "$profiler" || { fail 'perf record failed'; return 1; }
    # perf creates root-owned mode-0600 data; the CI artifact uploader is not root.
    chmod a+r "$PERF_PROFILE_DIR/$direction.data"
    "$perf_tool" report --stdio -i "$PERF_PROFILE_DIR/$direction.data" \
      > "$PERF_PROFILE_DIR/$direction-report.txt"
    "$perf_tool" script -i "$PERF_PROFILE_DIR/$direction.data" \
      > "$PERF_PROFILE_DIR/$direction-stacks.txt"
    python3 "$(dirname "$PERF_METRICS_SCRIPT")/perf_flame.py" \
      "$PERF_PROFILE_DIR/$direction-stacks.txt" "$PERF_PROFILE_DIR/$direction-flame.svg"
    echo "PERF_PROFILE captured direction=$direction"
  fi
  if [[ -n "$pinger" ]]; then
    wait "$pinger" || true
    python3 "$(dirname "$PERF_METRICS_SCRIPT")/latency_metrics.py" \
      "$SRV_DIR/ping-load-$direction.log" "$direction" || { fail 'load latency sample invalid'; return 1; }
  fi
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
    log "iperf3 $label end-summary diagnostics:"
    printf "%s\n" "$json" |
      grep -E '"(error|bytes|bits_per_second|retransmits)"' | tail -24 |
      sed 's/^/[netperf]     /' || true
  fi
  if ! scheduler_diag "$direction"; then
    fail "adaptive scheduler utilization gate failed ($direction, conns=$PERF_CONNS)"
    return 1
  fi
}

iperf_check() {
  if [[ -z "$HAVE_IPERF" ]]; then
    skip "iperf3 not installed — throughput test skipped"
    return 0
  fi
  ip netns exec "$NS_SRV" iperf3 -s -B "$GW_V4" -p "$((PORT + 1))" >/dev/null 2>&1 &
  PIDS+=($!)
  sleep 0.5
  iperf_one_way "upload (cli→srv)" "" upload
  iperf_one_way "download (srv→cli)" "-R" download
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
  ip netns exec "$NS_SRV" "$srv_bin" >/dev/null 2>&1 &
  local srv_pid=$!
  PIDS+=($srv_pid)
  sleep 1
  cat > "$dir/servers.json" <<'JSONEOF'
[{"name":"tunnel","id":1,"server":"http://SERVERURL","dl":"/backend/garbage.php","ul":"/backend/empty.php","ping":"/backend/empty.php","getIP":"/backend/getIP.php"}]
JSONEOF
  sed -i "s|SERVERURL|${GW_V4}:8080|" "$dir/servers.json"
  local out
  out=$(ip netns exec "$NS_CLI" "$cli" --server-json "$dir/servers.json" --json 2>/dev/null) || true
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

  log "--- group: ${FLAVOR_SRV}_srv <- ${FLAVOR_CLI}_cli (real TAP, conns=$PERF_CONNS) ---"

  # 两实现 flags 均已移除（2026-09-19）：键名两边一致，服务端配置共用一份
  local scfg="$SRV_DIR/srv.json"
  impl_config "$scfg" server "$UNDERLAY_SRV:$PORT" \
    '"encrypt": true' \
    '"log_level": "debug"' \
    "\"web\": {\"addr\": \"$WEB_ADDR\", \"bind\": \"all\", \"auth\": \"$WEB_AUTH\"}" \
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

  ip netns exec "$NS_SRV" "$BIN_SRV" -c "$scfg" > "$SRV_DIR/srv.log" 2>&1 &
  local srv_pid=$!
  local srv_tunnel_pid=$srv_pid
  PIDS+=($srv_pid)
  if ! wait_for_port "$NS_CLI" "$UNDERLAY_SRV" "$PORT" 20; then
    fail "server did not start ($UNDERLAY_SRV:$PORT never opened/reached within 20s)"
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
    impl_config "$ccfg" client "$UNDERLAY_SRV:$PORT" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "\"web\": {\"addr\": \"$WEB_ADDR\", \"bind\": \"all\", \"auth\": \"$WEB_AUTH\"}" \
      "\"tap\": \"$TAP_CLI\"" \
      "\"client\": {\"cert_sha256\": \"$fp\", \"insecure\": true, \"conns\": $PERF_CONNS}"
  else
    impl_config "$ccfg" client "$UNDERLAY_SRV:$PORT" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "\"web\": {\"addr\": \"$WEB_ADDR\", \"bind\": \"all\", \"auth\": \"$WEB_AUTH\"}" \
      "\"tap\": \"$TAP_CLI\"" \
      "\"client\": {\"cert_sha256\": \"$fp\", \"conns\": $PERF_CONNS}"
  fi
  ip netns exec "$NS_CLI" "$BIN_CLI" -c "$ccfg" > "$SRV_DIR/cli.log" 2>&1 &
  local cli_tunnel_pid=$!
  PIDS+=($!)

  if ! wait_for_client_ip; then
    fail "client tunnel IP ($CLI_V4) never appeared"
    log "--- server log tail ---"; tail -5 "$SRV_DIR/srv.log" || true
    log "--- client log tail ---"; tail -5 "$SRV_DIR/cli.log" || true
    return 1
  fi
  sleep 1  # let the vswitch learn MACs via first ARPs

  route_path_check || return 1
  ping_check "v4 cli→gw" "$GW_V4" v4
  ping_check "v6 cli→gw" "$GW_V6" v6
  traceroute_check "v4" "$GW_V4" v4
  traceroute_check "v6" "$GW_V6" v6
  local fail_before_iperf=$FAIL
  iperf_check
  if (( FAIL > fail_before_iperf )); then
    log "--- client TAP counters after iperf failure ---"
    ip netns exec "$NS_CLI" ip -s link show "$TAP_CLI" 2>&1 | sed 's/^/[netperf]     /' || true
    log "--- server TAP counters after iperf failure ---"
    ip netns exec "$NS_SRV" ip -s link show "$TAP_SRV" 2>&1 | sed 's/^/[netperf]     /' || true
    log "--- client log tail after iperf failure ---"
    tail -80 "$SRV_DIR/cli.log" 2>/dev/null | sed 's/^/[netperf]     /' || true
    log "--- server log tail after iperf failure ---"
    tail -80 "$SRV_DIR/srv.log" 2>/dev/null | sed 's/^/[netperf]     /' || true
  fi
  librespeed_check
  return 0
}

run_group
log "=== summary: pass=$PASS fail=$FAIL skip=$SKIPPED ==="
[[ $FAIL -eq 0 ]]
