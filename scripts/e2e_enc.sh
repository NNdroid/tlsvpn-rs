#!/usr/bin/env bash
# e2e_enc.sh — inner AEAD cross-language interoperability check.
#
# Starts one real Go/Rust server with the requested enc_algo, then connects the
# opposite implementation's protocol probe. The probe sends authenticated data
# records, so success proves handshake agreement plus actual C2S AEAD wire
# compatibility rather than only config parsing.
#
# Env:
#   SRV       rs | go
#   PROBE     rs | go
#   ALGO      gcm256 | gcm128 | chacha20 | xchacha20
#   PORT      default 21100
#   PSK/MAC   optional
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

SRV="${SRV:-rs}"
PROBE="${PROBE:-go}"
ALGO="${ALGO:-chacha20}"
PORT="${PORT:-21100}"
PSK="${PSK:-$E2E_PSK}"
MAC="${MAC:-aa:bb:cc:dd:ee:71}"

case "$ALGO" in
  gcm256)    ENCALGO=2 ;;
  gcm128)    ENCALGO=4 ;;
  chacha20)  ENCALGO=5 ;;
  xchacha20) ENCALGO=6 ;;
  *) echo "unknown ALGO=$ALGO" >&2; exit 2 ;;
esac
case "$SRV:$PROBE" in
  rs:go|go:rs) ;;
  *) echo "cross-language case required: SRV=$SRV PROBE=$PROBE" >&2; exit 2 ;;
esac

SRV_BIN="$E2E_RS_BIN"; [ "$SRV" = go ] && SRV_BIN="$E2E_GO_BIN"
PROBE_BIN="$E2E_RS_PROBE"; [ "$PROBE" = go ] && PROBE_BIN="$E2E_GO_PROBE"

e2e_require E2E_RS_BIN "$E2E_RS_BIN" "cargo build --bin tlsvpn" || exit 2
e2e_require E2E_GO_BIN "$E2E_GO_BIN" "build NNdroid/tlsvpn" || exit 2
e2e_require E2E_RS_PROBE "$E2E_RS_PROBE" "cargo build --example interop_client" || exit 2
e2e_require E2E_GO_PROBE "$E2E_GO_PROBE" "go build ./interop" || exit 2

e2e_ensure_cert || { echo "e2e: unable to prepare test certificate" >&2; exit 2; }
CERT="$E2E_CERT"
KEY="$E2E_KEY"

TMP="$(mktemp -d)"
SRV_LOG="$(e2e_winpath "$TMP/srv.log")"
PROBE_LOG="$(e2e_winpath "$TMP/probe.log")"
cleanup() {
  e2e_kill_port "$PORT"
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

e2e_kill_port "$PORT"
CFG="$TMP/server.json"
e2e_config "$CFG" server "127.0.0.1:$PORT" \
  "\"psk\": \"$PSK\"" \
  '"encrypt": true' \
  '"min_enc": "gcm"' \
  "\"enc_algo\": \"$ALGO\"" \
  '"pad_mode": "off"' \
  '"log_level": "info"' \
  "\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"10.77.0.0/24\", \"v6_cidr\": \"fd77::/64\"}"

"$SRV_BIN" -c "$(e2e_winpath "$CFG")" >"$SRV_LOG" 2>&1 &
if ! e2e_wait_port 127.0.0.1 "$PORT" 20; then
  echo "server failed to listen: SRV=$SRV ALGO=$ALGO" >&2
  cat "$SRV_LOG" >&2
  exit 1
fi

if [ "$PROBE" = rs ]; then
  timeout 15 "$PROBE_BIN" --addr "127.0.0.1:$PORT" --psk "$PSK" --mac "$MAC" \
    --send 8 --timeout 10 --enc-algo "$ENCALGO" >"$PROBE_LOG" 2>&1
  RC=$?
else
  timeout 15 "$PROBE_BIN" -addr "127.0.0.1:$PORT" -psk "$PSK" -mac "$MAC" \
    -send 8 -timeout 10 -enc-algo "$ENCALGO" >"$PROBE_LOG" 2>&1
  RC=$?
fi

e2e_kill_port "$PORT"

strip() { e2e_strip "$1"; }
ONLINE="$(strip "$SRV_LOG" | grep -c 'new logical client online' || true)"
ERRORS="$(strip "$SRV_LOG" | grep -Ei 'panic|panicked|decrypt.*fail|verification failed|authentication failed|connection refused|fatal' | tail -8 || true)"

printf 'AEAD E2E: srv=%s probe=%s algo=%s(%s) probe_rc=%s online=%s\n' \
  "$SRV" "$PROBE" "$ALGO" "$ENCALGO" "$RC" "$ONLINE"
if [ "$RC" -ne 0 ]; then
  echo '--- probe ---'
  cat "$PROBE_LOG"
fi
if [ -n "$ERRORS" ]; then
  echo '--- server errors ---'
  echo "$ERRORS"
fi

PASS=1
[ "$RC" -eq 0 ] || PASS=0
[ "$ONLINE" -ge 1 ] || PASS=0
[ -z "$ERRORS" ] || PASS=0

e2e_result "$PASS" "$SRV<-$PROBE $ALGO"
exit $((1 - PASS))
