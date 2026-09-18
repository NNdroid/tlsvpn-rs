#!/usr/bin/env bash
# e2e_pad.sh — 档 C：pad_mode 跨语言互测。
#
# 服务端与客户端同时应用同一 pad_mode（填充只由发送方决定，长度走帧头，
# 所以两侧都用同一模式才能把两条发送路径都跑一遍）。断言：
#   1. 两个进程都打印 "Confusion padding: <mode>" —— 模式真的生效了
#   2. 服务端打印 "新逻辑 Client 上线" —— 加密帧带着 pad_len 头成功往返
#   3. 两侧日志都没有错误标记
#
# Env:
#   SRV / CLI   rs | go          服务端与客户端实现
#   PAD         off | legacy | bucket   default bucket
#   PORT        default 18700
#   WEB_BASE    client 的 Web 面板端口              default 9502
#   PSK / MAC   同 e2e_tok.sh
#   LABEL
#   PAD=bogus 时改判失败：进程必须以 "invalid pad_mode" 立即退出
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

SRV="${SRV:-rs}"
CLI="${CLI:-rs}"
PAD="${PAD:-bucket}"
PORT="${PORT:-18700}"
WEB_BASE="${WEB_BASE:-9502}"
PSK="$E2E_PSK"
MAC="${MAC:-aa:bb:cc:dd:ee:01}"
LABEL="${LABEL:-}"

SRV_BIN="$E2E_RS_BIN"; [ "$SRV" = go ] && SRV_BIN="$E2E_GO_BIN"
CLI_BIN="$E2E_RS_BIN"; [ "$CLI" = go ] && CLI_BIN="$E2E_GO_BIN"

e2e_ensure_cert || { echo "e2e: 需要 e2e_cert.pem/e2e_key.pem 或 openssl"; exit 2; }
CERT="$E2E_CERT"
KEY="$E2E_KEY"

e2e_kill_port "$PORT"

TMP="$(mktemp -d)"
SRV_LOG="$(e2e_winpath "$TMP/srv.log")"
CLI_LOG="$(e2e_winpath "$TMP/cli.log")"
cleanup() {
  e2e_kill_port "$PORT"
  # 客户端只监听自己的 Web 面板端口，不杀会累积泄漏（16 组 = 16 个残留进程）。
  e2e_kill_port "$WEB_BASE"
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

strip() { e2e_strip "$1"; }

# 非法值：必须在启动早期以 invalid pad_mode 失败，且不得进入业务路径
if [ "$PAD" = "bogus" ]; then
  if [ "$SRV" = rs ]; then
    OUT="$( { "$SRV_BIN" --mode server --addr "127.0.0.1:$PORT" --psk "$PSK" --encrypt \
      --cert "$CERT" --key "$KEY" --v4cidr 10.77.0.0/24 --v6cidr fd77::/64 \
      --tap mem --pad-mode bogus 2>&1; } | timeout 15 cat )"
  else
    OUT="$( { "$SRV_BIN" -mode server -addr "127.0.0.1:$PORT" -psk "$PSK" -encrypt \
      -cert "$CERT" -key "$KEY" -v4cidr 10.77.0.0/24 -v6cidr fd77::/64 \
      -tap mem -pad-mode bogus 2>&1; } | timeout 15 cat )"
  fi
  PASS=0
  if echo "$OUT" | grep -q "invalid pad_mode"; then PASS=1; else PASS=0; fi
  if echo "$OUT" | grep -qi "panic"; then PASS=0; fi
  echo "===== label=$LABEL srv=$SRV pad=$PAD (invalid path) ====="
  echo "$OUT" | grep -Ei "invalid pad_mode|panic|Fatal|error" | head -5
  echo "-------------------------------------"
  e2e_result "$PASS" "${LABEL:-$SRV pad=bogus}"
  exit $((1 - PASS))
fi

if [ "$SRV" = rs ]; then
  "$SRV_BIN" --mode server --addr "127.0.0.1:$PORT" --psk "$PSK" --encrypt \
    --cert "$CERT" --key "$KEY" --v4cidr 10.77.0.0/24 --v6cidr fd77::/64 \
    --tap mem --loglevel info --pad-mode "$PAD" >"$SRV_LOG" 2>&1 &
else
  "$SRV_BIN" -mode server -addr "127.0.0.1:$PORT" -psk "$PSK" -encrypt \
    -cert "$CERT" -key "$KEY" -v4cidr 10.77.0.0/24 -v6cidr fd77::/64 \
    -tap mem -loglevel info -pad-mode "$PAD" >"$SRV_LOG" 2>&1 &
fi
e2e_wait_port 127.0.0.1 "$PORT" 20

if [ "$CLI" = rs ]; then
  "$CLI_BIN" --mode client --addr "127.0.0.1:$PORT" --psk "$PSK" --encrypt \
    --insecure --tap mem --conns 1 --loglevel info --mac "$MAC" \
    --web "127.0.0.1:$WEB_BASE" --pad-mode "$PAD" >"$CLI_LOG" 2>&1 &
else
  "$CLI_BIN" -mode client -addr "127.0.0.1:$PORT" -psk "$PSK" -encrypt \
    -insecure -tap mem -conns 1 -loglevel info -mac "$MAC" \
    -web "127.0.0.1:$WEB_BASE" -pad-mode "$PAD" >"$CLI_LOG" 2>&1 &
fi
sleep 8

ERRRE="ERROR|panic|panicked|GCM.*(fail|FAIL)|decrypt.*fail|解密失败|校验失败|拒绝连接|fatal"
SRV_ERRS="$(strip "$SRV_LOG" | grep -E "$ERRRE" | tail -5 || true)"
CLI_ERRS="$(strip "$CLI_LOG" | grep -E "$ERRRE" | tail -5 || true)"

SRV_PAD="$(strip "$SRV_LOG" | grep -c "Confusion padding: $PAD" || true)"
CLI_PAD="$(strip "$CLI_LOG" | grep -c "Confusion padding: $PAD" || true)"
ONLINE="$(strip "$SRV_LOG" | grep -c "新逻辑 Client 上线" || true)"

echo "===== label=$LABEL srv=$SRV cli=$CLI pad=$PAD ====="
echo "srv pad applied: $SRV_PAD  cli pad applied: $CLI_PAD  client online: $ONLINE"
if [ -n "$SRV_ERRS" ]; then echo "srv errors: $SRV_ERRS"; fi
if [ -n "$CLI_ERRS" ]; then echo "cli errors: $CLI_ERRS"; fi
echo "-------------------------------------"

RC=0
[ "$SRV_PAD" -ge 1 ] || RC=1
[ "$CLI_PAD" -ge 1 ] || RC=1
[ "$ONLINE" -ge 1 ] || RC=1
[ -z "$SRV_ERRS" ] || RC=1
[ -z "$CLI_ERRS" ] || RC=1
e2e_result $((1 - RC)) "${LABEL:-$SRV->$CLI pad=$PAD}"
exit $RC
