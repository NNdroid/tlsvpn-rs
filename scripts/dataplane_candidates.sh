#!/usr/bin/env bash
# Each candidate has a same-binary negative control. Final ABBA uses all pairs.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RS_BIN:?set RS_BIN}" "${GO_BIN:?set GO_BIN}"
out="${RX_PERF_OUTPUT:-perf-results/rx-real-tap}/candidates"
mkdir -p "$out"
run_case() {
  local name="$1" pair="$2" seconds="$3"; shift 3
  local srv="${pair%-*}" cli="${pair#*-}" srv_bin="$RS_BIN" cli_bin="$RS_BIN"
  [[ "$srv" == go ]] && srv_bin="$GO_BIN"
  [[ "$cli" == go ]] && cli_bin="$GO_BIN"
  local log="$out/$name-$pair.txt"
  echo "DATAPLANE_CASE name=$name pair=$pair seconds=$seconds flags=$*" | tee "$log"
  env TLSVPN_RX_OWNED=0 TLSVPN_TX_BATCH=0 TLSVPN_RX_COMPACT=0 TLSVPN_SWITCH_BATCH=0 \
    TLSVPN_TX_BATCH_SIZE=8 TLSVPN_RX_BATCH_SIZE=16 TLSVPN_RX_BYPASS=1 PERF_CONNS=1 \
    PERF_LATENCY=1 IPERF_SECONDS="$seconds" BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" \
    FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" "$@" bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"
  if grep -Fq '[netperf] SKIP:' "$log"; then
    echo 'DATAPLANE_CASE SKIP; no performance evidence' | tee "$out/SKIP.txt"
    exit 0
  fi
  grep -Fq VPN_METRICS "$log" || exit 1
  grep -Fq LOAD_LATENCY "$log" || exit 1
}
for flag in TLSVPN_RX_OWNED TLSVPN_TX_BATCH TLSVPN_RX_COMPACT TLSVPN_SWITCH_BATCH; do
  for enabled in 0 1; do run_case "$flag-$enabled" rs-rs 5 "$flag=$enabled"; done
done
for size in 8 16 32; do
  run_case "tx-size-$size" rs-rs 5 TLSVPN_TX_BATCH=1 "TLSVPN_TX_BATCH_SIZE=$size"
done
trial=0
for enabled in 0 1 1 0; do
  trial=$((trial + 1))
  for pair in rs-rs rs-go go-rs go-go; do
    run_case "all-$enabled-trial$trial" "$pair" 10 \
      "TLSVPN_RX_OWNED=$enabled" "TLSVPN_TX_BATCH=$enabled" \
      "TLSVPN_RX_COMPACT=$enabled" "TLSVPN_SWITCH_BATCH=$enabled"
  done
done
