#!/usr/bin/env bash
# e2e_cfg.sh — 配置维度互通 + 配置校验 e2e。
#
# accept / pad / minenc / tok 那几套固定配置、只动协议参数；这套固定协议、只动
# 配置，目的是把「配置项真的生效」钉住。历史上踩过的坑：
#   * mac 只在算 client_id 时用到、从不写进 TAP → 握手声明一个值、帧里带内核
#     随机分配的另一值，服务端 src_mac_allowed 把本端自己的帧当外来帧丢掉；
#   * server.v4_cidr 写错被 parse_v4_cidr 静默降级成默认网段；
#   * log_level 拼错只让日志行为莫名变化；
#   * web.auth 写成不带冒号的值让面板对所有请求返回 401；
#   * web.bind=tunnel 里 IPv6 网关没就绪时整批绑定被放弃，已成功的监听被自己
#     占住，两个地址都再绑不上（用户实际遇到的 8000 端口被自己占用）。
#
# CASE
#   互通（真实 server+client，断言会话建立且配置真的生效）
#     cidr       自定义网段 + req_v4/req_v6 → 分配必须落在池内
#     multi      client.conns=2 → 面板 /api/stats 里该客户端 active_conns 必须是 2
#     webauth    web.auth → 无凭证 401、带凭证 200
#     webtunnel  web.bind=tunnel：mem 后端没有网关 IP 可绑，必须逐个地址告警并
#                限流（每地址 30s 一次），且不得拖垮隧道本身
#     logquiet   两端 log_level=warn → 日志里没有 INFO/DEBUG/TRACE，面板照常服务
#   校验（进程必须以非零退出并给出对应错误）
#     badlog badauth badv4 badv6 badmac badbind
#
# Go 的 Validate 不检查 mac 和 web.bind（validate_args 比 Go 严），badmac /
# badbind 在 SRV=go 时打印跳过并退出 0。
#
# Env: CASE SRV CLI PORT WEB_BASE MAC LABEL
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

CASE="${CASE:-}"
SRV="${SRV:-rs}"
CLI="${CLI:-rs}"
PORT="${PORT:-20000}"
WEB_BASE="${WEB_BASE:-9700}"
PSK="$E2E_PSK"
MAC="${MAC:-aa:bb:cc:dd:ee:07}"
LABEL="${LABEL:-}"

SRV_BIN="$E2E_RS_BIN"; [ "$SRV" = go ] && SRV_BIN="$E2E_GO_BIN"
CLI_BIN="$E2E_RS_BIN"; [ "$CLI" = go ] && CLI_BIN="$E2E_GO_BIN"

[ -n "$CASE" ] || { echo "e2e_cfg: CASE 必填 (cidr|multi|webauth|webtunnel|logquiet|bad*)"; exit 2; }
e2e_require RS_BIN "$SRV_BIN" "先构建：scripts/build.sh native" || exit 2
e2e_ensure_cert || { echo "e2e_cfg: 需要 e2e_cert.pem/e2e_key.pem 或 openssl"; exit 2; }
CERT="$E2E_CERT"
KEY="$E2E_KEY"

e2e_kill_port "$PORT"
[ "$WEB_BASE" != 0 ] && e2e_kill_port "$WEB_BASE"

TMP="$(mktemp -d)"
SRV_LOG="$(e2e_winpath "$TMP/srv.log")"
CLI_LOG="$(e2e_winpath "$TMP/cli.log")"
cleanup() {
  e2e_kill_port "$PORT"
  [ "$WEB_BASE" != 0 ] && e2e_kill_port "$WEB_BASE"
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# 不依赖 curl：/dev/tcp 发一个最小请求，回完整响应。timeout 兜底——服务端不回
# Connection: close 时不能让套件挂住。$4 是可选的整行请求头（含自己的 CRLF）。
http_get() {
  local host="$1" port="$2" path="$3" hdr="$4"
  exec 3<>"/dev/tcp/$host/$port" 2>/dev/null || return 1
  printf 'GET %s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n' \
    "$path" "$host" "$port" >&3
  [ -n "$hdr" ] && printf '%s\r\n' "$hdr" >&3
  printf '\r\n' >&3
  timeout 8 cat <&3
  exec 3>&-
}

# 故意避开默认网段（10.0.0.0/24、fd00::/64）：这样「配置没生效」和
# 「静默回落到默认网段」都骗不过断言。
V4CIDR="10.99.0.0/24"
V6CIDR="fd99::/64"
V4PREFIX="10.99.0."

# ============================ 校验失败类 ============================
case "$CASE" in
  bad*)
    if { [ "$CASE" = badmac ] || [ "$CASE" = badbind ]; } && [ "$SRV" = go ]; then
      echo "  SKIP  [$LABEL] $CASE 需要 Rust 服务端（Go 的 Validate 不检查该字段）"
      exit 0
    fi

    MODE=server
    FRAG=''        # 新键（web / mac）：默认配置里没有，不会撞车
    LOG_FRAG='"log_level": "info"'
    SERVER_FRAG="\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"$V4CIDR\", \"v6_cidr\": \"$V6CIDR\"}"
    WANT=''
    case "$CASE" in
      badlog)
        LOG_FRAG='"log_level": "verbose"'
        WANT='invalid log_level'
        ;;
      badauth)
        FRAG='"web": {"auth": "admin"}'
        if [ "$SRV" = go ]; then WANT='user:password'; else WANT='invalid web.auth'; fi
        ;;
      badv4)
        SERVER_FRAG="\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"not-a-cidr\"}"
        WANT='invalid server.v4_cidr'
        ;;
      badv6)
        SERVER_FRAG="\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v6_cidr\": \"fd00::/129\"}"
        WANT='invalid server.v6_cidr'
        ;;
      badmac)
        MODE=client
        FRAG='"mac": "aa:bb:cc:dd:ee"'
        WANT='invalid mac'
        ;;
      badbind)
        FRAG='"web": {"bind": "Any"}'
        WANT='invalid web.bind'
        ;;
    esac

    cfg="$TMP/cfg.json"
    # 每个键只出现一次：serde_json 见到重复键直接报 "duplicate field"，会把想
    # 验证的那条校验盖掉。Go 的 encoding/json 是「后者胜出」，Rust 是「拒绝」，
    # 这里按 Rust 的严格行为构造，所以 override 走替换变量而不是追加片段。
    FRAGS=("\"psk\": \"$PSK\"" "$LOG_FRAG")
    [ "$MODE" = server ] && FRAGS+=("$SERVER_FRAG")
    [ -n "$FRAG" ] && FRAGS+=("$FRAG")
    e2e_config "$cfg" "$MODE" "127.0.0.1:$PORT" "${FRAGS[@]}"

    # 注意不要把输出重定向到文件：那样 OUT 只会拿到下面的 EXIT= 行，
    # 错误文案本身永远匹配不上（第一次跑这一类用例时就是这样全挂的）。
    OUT="$( { "$SRV_BIN" -c "$(e2e_winpath "$cfg")" 2>&1; echo "EXIT=$?"; } | timeout 20 cat )"
    PASS=0
    EXITLINE="$(echo "$OUT" | grep -o 'EXIT=[0-9]*' | tail -1)"
    if echo "$OUT" | grep -q "$WANT" && [ "$EXITLINE" != "EXIT=0" ]; then
      PASS=1
    fi
    if echo "$OUT" | grep -qi "panic"; then PASS=0; fi

    echo "===== case=$CASE srv=$SRV want=\"$WANT\" exit=$EXITLINE ====="
    if [ "$PASS" = 1 ]; then
      echo "$OUT" | grep -Ei "$WANT" | head -3
    else
      echo "$OUT" | tail -8
    fi
    echo "-------------------------------------"
    e2e_result "$PASS" "${LABEL:-$SRV $CASE}"
    exit "$((1 - PASS))"
    ;;
esac

# ============================ 互通类 ============================
SRV_LOGFRAG='"log_level": "info"'   # 与 SRV_FX 分开：serde_json 拒绝重复键，
CLI_LOGFRAG='"log_level": "info"'   # 想覆盖 log_level 必须整段替换而不是追加
SRV_FX=''        # 服务端额外顶层键
CLI_FX='"client": {"insecure": true, "conns": 1}'
WEB_FX=''        # web 对象里的额外键
case "$CASE" in
  cidr)
    # req_v4/req_v6 落在池内 → 必须原样分配，而不是退回池的下一个空位
    CLI_FX='"client": {"insecure": true, "conns": 1, "req_v4": "10.99.0.77", "req_v6": "fd99::77"}'
    ;;
  multi)
    # 客户端开 2 条 TCP 连接。服务端必须真的记到 2——面板 /api/stats 暴露
    # active_conns，两端（Rust stats_json / Go api.go）都有这个字段，所以这条
    # 断言可以跨语言。conns 是那种「配了但没人读」就会静默退化成单连接的字段。
    CLI_FX='"client": {"insecure": true, "conns": 2}'
    ;;
  webauth)
    WEB_FX='"auth": "admin:s3cret"'
    ;;
  webtunnel)
    WEB_FX='"bind": "tunnel"'
    ;;
  logquiet)
    SRV_LOGFRAG='"log_level": "warn"'
    CLI_LOGFRAG='"log_level": "warn"'
    ;;
  *)
    echo "e2e_cfg: 未知 CASE=$CASE" >&2
    exit 2
    ;;
esac

# web 对象本身拼一次，避免 web.auth / web.bind 与默认 addr 拆成两个 "web" 键
WEB_JSON="\"web\": {\"addr\": \"127.0.0.1:$WEB_BASE\""
[ -n "$WEB_FX" ] && WEB_JSON="$WEB_JSON, $WEB_FX"
WEB_JSON="$WEB_JSON}"

e2e_config "$TMP/srv.json" server "127.0.0.1:$PORT" \
  "\"psk\": \"$PSK\"" \
  '"encrypt": true' \
  "$SRV_LOGFRAG" \
  "$SRV_FX" \
  "$WEB_JSON" \
  "\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"$V4CIDR\", \"v6_cidr\": \"$V6CIDR\"}"
"$SRV_BIN" -c "$(e2e_winpath "$TMP/srv.json")" >"$SRV_LOG" 2>&1 &
e2e_wait_port 127.0.0.1 "$PORT" 25 || {
  echo "FAIL: server 未启动"
  cat "$SRV_LOG"
  e2e_result 0 "${LABEL:-$SRV->$CLI $CASE}"
  exit 1
}

e2e_config "$TMP/cli.json" client "127.0.0.1:$PORT" \
  "\"psk\": \"$PSK\"" \
  '"encrypt": true' \
  "$CLI_LOGFRAG" \
  "\"mac\": \"$MAC\"" \
  "$CLI_FX"
"$CLI_BIN" -c "$(e2e_winpath "$TMP/cli.json")" >"$CLI_LOG" 2>&1 &

ERRRE="ERROR|panic|panicked|fatal"
PASS=1

# logquiet 把日志压到 warn，而上线日志本身是 info，改从面板的 /api/stats 判断
# 客户端是否真的接上了（顺带证明网段配置生效）。
if [ "$CASE" = logquiet ]; then
  e2e_wait_port 127.0.0.1 "$WEB_BASE" 20 || { echo "面板端口未监听"; PASS=0; }
  sleep 6
else
  if ! e2e_wait_log "新逻辑 Client 上线" "$SRV_LOG" 30; then
    echo "服务端没有报出客户端上线"
    echo "--- server ---"
    e2e_strip "$SRV_LOG" | tail -20
    echo "--- client ---"
    e2e_strip "$CLI_LOG" | tail -20
    e2e_result 0 "${LABEL:-$SRV->$CLI $CASE}"
    exit 1
  fi
fi

case "$CASE" in
  cidr)
    # 分配必须来自配置的池，而不是默认池或池外
    e2e_wait_log "$V4PREFIX" "$SRV_LOG" 10 || { echo "v4 分配不来自 $V4CIDR"; PASS=0; }
    e2e_wait_log "fd99" "$SRV_LOG" 10 || { echo "v6 分配不来自 $V6CIDR"; PASS=0; }
    ;;
  multi)
    sleep 3
    BODY="$(http_get 127.0.0.1 "$WEB_BASE" /api/stats '')" || { echo "面板请求失败"; PASS=0; }
    if ! echo "$BODY" | grep -qE '"active_conns"[[:space:]]*:[[:space:]]*2'; then
      echo "面板里没有 active_conns=2，client.conns 没生效"
      echo "$BODY" | tail -c 400
      PASS=0
    fi
    ;;
  webauth)
    AUTH_HDR="Authorization: Basic $(printf 'admin:s3cret' | base64 -w0)"
    CODE_NO="$(http_get 127.0.0.1 "$WEB_BASE" /api/stats '' | head -1)"
    CODE_YES="$(http_get 127.0.0.1 "$WEB_BASE" /api/stats "$AUTH_HDR" | head -1)"
    echo "webauth: 无凭证=[$CODE_NO] 带凭证=[$CODE_YES]"
    echo "$CODE_NO"  | grep -q " 401" || { echo "未带凭证应当 401"; PASS=0; }
    echo "$CODE_YES" | grep -q " 200" || { echo "带凭证应当 200"; PASS=0; }
    ;;
  webtunnel)
    # mem 后端没有任何接口挂着网关 IP，两个地址都必须绑定失败；限流意味着
    # 10 秒里每个地址只告警一次。grep 的是 "will retry"——两端文案不同
    # （Rust: "bind failed on ... will retry"，Go: "[Web] ... will retry"），
    # 但这个子串两者都有，同一断言能钉住两端的限流行为；旧实现每 2 秒刷一条，
    # 10 秒里会有 4-5 条。
    sleep 10
    RETRY="$(e2e_strip "$SRV_LOG" | grep -c "will retry" || true)"
    if ! e2e_strip "$SRV_LOG" | grep -q "Dashboard manager started"; then
      echo "bind=tunnel 的管理器没启动"
      PASS=0
    fi
    if [ "${RETRY:-0}" -gt 2 ]; then
      echo "绑定失败告警 ${RETRY} 条，超过每地址一次的上限（没有限流）"
      PASS=0
    fi
    # 隧道本身不能被拖垮：客户端照样要上线
    e2e_wait_log "新逻辑 Client 上线" "$SRV_LOG" 10 || { echo "bind=tunnel 拖垮了隧道"; PASS=0; }
    ;;
  logquiet)
    BODY="$(http_get 127.0.0.1 "$WEB_BASE" /api/stats '')" || { echo "面板请求失败"; PASS=0; }
    echo "$BODY" | head -1
    echo "$BODY" | grep -q " 200" || { echo "面板应当返回 200"; PASS=0; }
    echo "$BODY" | grep -q "$V4PREFIX" || { echo "客户端未上线或网段未生效（stats 里没有 $V4PREFIX）"; PASS=0; }
    QUIET="$(e2e_strip "$SRV_LOG" | grep -Ec " (INFO|DEBUG|TRACE) " || true)"
    if [ "${QUIET:-0}" -gt 0 ]; then
      echo "log_level=warn 却出现了 ${QUIET} 条 INFO/DEBUG/TRACE 日志"
      PASS=0
    fi
    ;;
esac

SRV_ERRS="$(e2e_strip "$SRV_LOG" | grep -E "$ERRRE" | grep -v "will retry" | tail -5 || true)"
CLI_ERRS="$(e2e_strip "$CLI_LOG" | grep -E "$ERRRE" | tail -5 || true)"
[ -z "$SRV_ERRS" ] || { echo "srv errors: $SRV_ERRS"; PASS=0; }
[ -z "$CLI_ERRS" ] || { echo "cli errors: $CLI_ERRS"; PASS=0; }

echo "===== label=$LABEL case=$CASE srv=$SRV cli=$CLI ====="
e2e_strip "$SRV_LOG" | grep -E "上线|will retry|Dashboard|Web Server" | tail -6
echo "-------------------------------------"
e2e_result "$PASS" "${LABEL:-$SRV->$CLI $CASE}"
exit "$((1 - PASS))"
