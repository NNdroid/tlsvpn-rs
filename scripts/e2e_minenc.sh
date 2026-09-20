#!/usr/bin/env bash
# e2e_minenc.sh — 档 D：min_enc 强度下限跨语言互测。
#
# 探针用 --enc-algo 声明内层加密能力。内层只剩一种算法（2 = GCM），所以 2 是
# 唯一合格值；9 是两端都不认识的算法 ID，用来守住"按数值大小推断能力"这类回归。
# 服务端按 min_enc 下限决定是否放行。判据只看服务端日志，不看探针退出码：探针在
# 协商不出 GCM 时会主动报错退出，那不属于服务端行为。
#
# Env:
#   SRV         rs | go   server implementation
#   PROBE       rs | go   probe implementation
#   MINENC      "" | gcm   default gcm
#   ENCALGO     2 | 9   default 2
#   ENCRYPT     1 | 0       default 1
#   PORT        default 18800
#   PSK / MAC   同 e2e_tok.sh
#   LABEL
#   MODE        accept | reject | configerr   default accept
#     accept     期望服务端放行（日志出现"新逻辑 Client 上线"）
#     reject     期望服务端拒连（日志出现"低于 min_enc 下限"）
#     configerr  期望服务端启动期以配置错误失败，不进入业务路径
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

SRV="${SRV:-rs}"
PROBE="${PROBE:-rs}"
if [ -z "${MINENC+x}" ]; then MINENC=gcm; fi
ENCALGO="${ENCALGO:-2}"
ENCRYPT="${ENCRYPT:-1}"
MODE="${MODE:-accept}"
PORT="${PORT:-18800}"
PSK="$E2E_PSK"
MAC="${MAC:-aa:bb:cc:dd:ee:01}"
LABEL="${LABEL:-}"

SRV_BIN="$E2E_RS_BIN"; [ "$SRV" = go ] && SRV_BIN="$E2E_GO_BIN"
PROBE_BIN="$E2E_RS_PROBE"; [ "$PROBE" = go ] && PROBE_BIN="$E2E_GO_PROBE"

e2e_ensure_cert || { echo "e2e: 需要 e2e_cert.pem/e2e_key.pem 或 openssl"; exit 2; }
CERT="$E2E_CERT"
KEY="$E2E_KEY"

e2e_kill_port "$PORT"

TMP="$(mktemp -d)"
SRV_LOG="$(e2e_winpath "$TMP/srv.log")"
CLI_LOG="$(e2e_winpath "$TMP/cli.log")"
cleanup() {
  e2e_kill_port "$PORT"
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

strip() { e2e_strip "$1"; }

start_srv() {
  if [ "$SRV" = rs ]; then
    # Rust 服务端：flags 已移除（2026-09-19），一律走配置文件。
    # min_enc 为空串是合法值（= 不设下限）；configerr 场景依赖
    # min_enc requires encrypt=true / invalid min_enc 这类启动期校验失败。
    local cfg="$TMP/srv.json" encjson="false"
    [ "$ENCRYPT" = 1 ] && encjson="true"
    e2e_config "$cfg" server "127.0.0.1:$PORT" \
      "\"psk\": \"$PSK\"" \
      "\"encrypt\": $encjson" \
      '"log_level": "info"' \
      "\"min_enc\": \"$MINENC\"" \
      "\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"10.77.0.0/24\", \"v6_cidr\": \"fd77::/64\"}"
    "$SRV_BIN" -c "$(e2e_winpath "$cfg")" >"$SRV_LOG" 2>&1 &
  else
    # Go 服务端：flags 已移除（2026-09-19），一律走配置文件。
    # min_enc 为空串是合法值（= 不设下限）；configerr 场景依赖
    # min_enc requires encrypt=true / invalid pad_mode 这类启动期校验失败。
    local cfg="$TMP/srv.json" encjson="false"
    [ "$ENCRYPT" = 1 ] && encjson="true"
    e2e_config "$cfg" server "127.0.0.1:$PORT" \
      "\"psk\": \"$PSK\"" \
      "\"encrypt\": $encjson" \
      '"log_level": "info"' \
      "\"min_enc\": \"$MINENC\"" \
      "\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"10.77.0.0/24\", \"v6_cidr\": \"fd77::/64\"}"
    "$SRV_BIN" -c "$(e2e_winpath "$cfg")" >"$SRV_LOG" 2>&1 &
  fi
}

# 配置错误：进程必须在启动早期失败，且不得打印任何业务日志。
# start_srv 把输出写到 SRV_LOG，所以判定直接读日志（不要像以前那样去 grep
# 一个空的子进程捕获变量）。
if [ "$MODE" = configerr ]; then
  start_srv
  sleep 3
  PASSED=0
  strip "$SRV_LOG" | grep -Ei "min_enc|invalid" >/dev/null && PASSED=1
  strip "$SRV_LOG" | grep -Eqi "panic" && PASSED=0
  strip "$SRV_LOG" | grep -Eq "below the min_enc floor|new logical client online" && PASSED=0
  echo "===== label=$LABEL srv=$SRV min_enc=$MINENC encrypt=$ENCRYPT (configerr) ====="
  strip "$SRV_LOG" | grep -Ei "min_enc|invalid|fatal|panic|error" | head -5
  echo "-------------------------------------"
  e2e_result "$PASSED" "${LABEL:-$SRV min_enc=$MINENC encrypt=$ENCRYPT configerr}"
  exit $((1 - PASSED))
fi

start_srv
e2e_wait_port 127.0.0.1 "$PORT" 20
if [ "$PROBE" = rs ]; then
  timeout 12 "$PROBE_BIN" --addr "127.0.0.1:$PORT" --psk "$PSK" --mac "$MAC" \
    --send 5 --timeout 9 --enc-algo "$ENCALGO" >"$CLI_LOG" 2>&1
else
  timeout 12 "$PROBE_BIN" -addr "127.0.0.1:$PORT" -psk "$PSK" -mac "$MAC" \
    -send 5 -timeout 9 -enc-algo "$ENCALGO" >"$CLI_LOG" 2>&1
fi
e2e_kill_port "$PORT"

ONLINE="$(strip "$SRV_LOG" | grep -c "new logical client online" || true)"
DENY="$(strip "$SRV_LOG" | grep -c "below the min_enc floor" || true)"
PANIC="$(strip "$SRV_LOG" | grep -Eic "panic|GCM.*(fail|FAIL)|decrypt.*fail|校验失败" || true)"

echo "===== label=$LABEL srv=$SRV probe=$PROBE min_enc=$MINENC enc_algo=$ENCALGO ====="
echo "server: 上线=$ONLINE min_enc拒绝=$DENY 异常=$PANIC"
echo "----- server 相关日志 -----"
strip "$SRV_LOG" | grep -Ei "min_enc|上线|拒绝|加密能力" | tail -4
echo "----- probe 输出 (tail 6) -----"
tail -6 "$CLI_LOG"
echo "-------------------------------------"

PASSED=0
case "$MODE" in
  accept)
    [ "$ONLINE" -ge 1 ] && [ "$DENY" -eq 0 ] && PASSED=1 ;;
  reject)
    [ "$DENY" -ge 1 ] && [ "$ONLINE" -eq 0 ] && PASSED=1 ;;
esac
[ "$PANIC" -eq 0 ] || PASSED=0

e2e_result "$PASSED" "${LABEL:-$SRV probe=$PROBE min_enc=$MINENC enc_algo=$ENCALGO}"
exit $((1 - PASSED))
