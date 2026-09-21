#!/usr/bin/env bash
# e2e_tok.sh — protocol v2 e2e：两台同 MAC 客户端，验证跨实例接管被拒。
#
# 威胁模型：client_id 完全由 (MAC, PSK) 推导，持密者只要知道目标 MAC 就能算出
# 对方 client_id，走"会话复活"分支接管既有隧道。v2 随机令牌只在原会话的
# TLS 连接里下发，第三方从未见过；client_instance 也不同，因此接管必须被拒。
#
# 与 e2e_accept.sh 的探针不同：这里用真实客户端，因为只有完整客户端才会
# 重连并回带上次拿到的令牌 —— 探针只做一次会话，覆盖不到重连路径。
#
# Env:
#   SRV          rs | go   server implementation   default rs
#   CLI          rs | go   client implementation   default rs
#   PORT         default 18500
#   WEB_BASE     client A 的 Web 面板端口，B 用 +1   default 9500
#   PSK          default e2e_secret
#   MAC          default aa:bb:cc:dd:ee:01
#   TOKEN_FIELD  true | false   default true
#     session_token 是配置兼容字段；false 也不得关闭 protocol v2 的令牌保护。
#   LABEL
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

SRV="${SRV:-rs}"
CLI="${CLI:-rs}"
PORT="${PORT:-18500}"
WEB_BASE="${WEB_BASE:-9500}"
PSK="$E2E_PSK"
MAC="${MAC:-aa:bb:cc:dd:ee:01}"
TOKEN_FIELD="${TOKEN_FIELD:-true}"
LABEL="${LABEL:-}"

SRV_BIN="$E2E_RS_BIN"; [ "$SRV" = go ] && SRV_BIN="$E2E_GO_BIN"
CLI_BIN="$E2E_RS_BIN"; [ "$CLI" = go ] && CLI_BIN="$E2E_GO_BIN"

e2e_ensure_cert || { echo "e2e: 需要 e2e_cert.pem/e2e_key.pem 或 openssl"; exit 2; }
CERT="$E2E_CERT"
KEY="$E2E_KEY"

# 两台客户端 + 一台服务端都会带 :PORT 命令行，按端口定位最稳。
e2e_kill_port "$PORT"

TMP="$(mktemp -d)"
SRV_LOG="$(e2e_winpath "$TMP/srv.log")"
A_LOG="$(e2e_winpath "$TMP/a.log")"
B_LOG="$(e2e_winpath "$TMP/b.log")"
cleanup() {
  e2e_kill_port "$PORT"
  # 两台客户端不监听隧道端口，只能靠各自的 Web 面板端口定位；漏掉任何一个，
  # 泄漏的进程都会占住下一个套件的面板端口（CI 上 tok 泄漏 9500-9511 坑死 pad）。
  e2e_kill_port "$WEB_BASE"
  e2e_kill_port "$((WEB_BASE + 1))"
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# --- 服务端 ---
if [ "$SRV" = rs ]; then
  # Rust 服务端：flags 已移除（2026-09-19），一律走配置文件。
  ST="$TOKEN_FIELD"
  e2e_config "$TMP/srv.json" server "127.0.0.1:$PORT" \
    "\"psk\": \"$PSK\"" \
    '"encrypt": true' \
    '"log_level": "info"' \
    "\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"10.77.0.0/24\", \"v6_cidr\": \"fd77::/64\", \"session_token\": $ST}"
  "$SRV_BIN" -c "$(e2e_winpath "$TMP/srv.json")" >"$SRV_LOG" 2>&1 &
else
  # Go/Rust 都保留该字段用于配置互读，但 v2 安全语义不受其值影响。
  ST="$TOKEN_FIELD"
  cat >"$TMP/srv.json" <<EOF
{
  "mode": "server",
  "psk": "$PSK",
  "addr": "127.0.0.1:$PORT",
  "log_level": "info",
  "encrypt": true,
  "tap": "mem",
  "server": {
    "v4_cidr": "10.77.0.0/24",
    "v6_cidr": "fd77::/64",
    "cert": "$CERT",
    "key": "$KEY",
    "session_token": $ST
  }
}
EOF
  "$E2E_GO_BIN" -c "$(e2e_winpath "$TMP/srv.json")" >"$SRV_LOG" 2>&1 &
fi
e2e_wait_port 127.0.0.1 "$PORT" 20 || { echo "FAIL: server did not start"; cat "$SRV_LOG"; exit 2; }

# --- 客户端：同一 MAC、同一 PSK → 同一个 client_id ---
start_cli() {
  local logf="$1" webport="$2"
  if [ "$CLI" = rs ]; then
    # Rust 客户端：flags 已移除（2026-09-19），一律走配置文件
    local cfg="$TMP/cli_$webport.json"
    e2e_config "$cfg" client "127.0.0.1:$PORT" \
      "\"psk\": \"$PSK\"" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "\"mac\": \"$MAC\"" \
      "\"web\": {\"addr\": \"127.0.0.1:$webport\", \"auth\": \"e2e:web-test-password\"}" \
      '"client": {"insecure": true, "conns": 1}'
    "$CLI_BIN" -c "$(e2e_winpath "$cfg")" >"$logf" 2>&1 &
  else
    # Go 客户端：flags 已移除（2026-09-19），一律走配置文件
    local cfg="$TMP/cli_$webport.json"
    e2e_config "$cfg" client "127.0.0.1:$PORT" \
      "\"psk\": \"$PSK\"" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "\"mac\": \"$MAC\"" \
      "\"web\": {\"addr\": \"127.0.0.1:$webport\", \"auth\": \"e2e:web-test-password\"}" \
      '"client": {"insecure": true, "conns": 1}'
    "$CLI_BIN" -c "$(e2e_winpath "$cfg")" >"$logf" 2>&1 &
  fi
}
start_cli "$A_LOG" "$WEB_BASE"
sleep 5
start_cli "$B_LOG" "$((WEB_BASE + 1))"
sleep 6

echo "===== label=$LABEL srv=$SRV cli=$CLI token_field=$TOKEN_FIELD ====="
echo "----- server log (handshake decisions) -----"
e2e_strip "$SRV_LOG" | grep -Ei "online|revive|reconnect refused|session|token" | tail -15
echo "----- client A log (tail 8) -----"
tail -8 "$A_LOG"
echo "----- client B log (tail 8) -----"
tail -8 "$B_LOG"
echo "---------------------------------------------"

# 两实现的日志都已是英文，这里取两端都有的公共前缀：上线文案逐字一致；复活有两条
# 路径（倒计时内复活 / 既有会话多挂一条物理连接），Rust 两条都含 "session revived"，
# Go 的第二条是 "existing session gained a new physical connection"，故保留后半段；
# 令牌拒绝两端后半句不同，公共前缀到 invalid session token 为止。
UP=$(grep -c "new logical client online" "$SRV_LOG" || true)
REVIVE=$(grep -Ec "session revived|new physical connection" "$SRV_LOG" || true)
DENY=$(grep -c "reconnect refused: invalid session token" "$SRV_LOG" || true)
echo "server: 上线=$UP 复活=$REVIVE 令牌拒绝=$DENY"

PASS=0
# A 上线一次；B 被令牌/实例校验拦下；配置字段 false 也不得允许接管。
if [ "$UP" -eq 1 ] && [ "$DENY" -ge 1 ] && [ "$REVIVE" -eq 0 ]; then
  PASS=1
fi
e2e_result "$PASS" "${LABEL:-$SRV->$CLI token_field=$TOKEN_FIELD}"
exit $((1 - PASS))
