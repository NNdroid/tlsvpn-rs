#!/usr/bin/env bash
# ABBA negative control at batch=16, with go/go as a runner-noise reference.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RS_BIN:?set RS_BIN}"
: "${GO_BIN:?set GO_BIN}"
out="${RX_PERF_OUTPUT:-perf-results/rx-real-tap}/recycling"
mkdir -p "$out"
trial=0
for recycle in 0 1 1 0; do
  trial=$((trial + 1))
  for pair in rs-rs go-rs go-go; do
    srv="${pair%-*}"; cli="${pair#*-}"
    srv_bin="$RS_BIN"; cli_bin="$RS_BIN"
    [[ "$srv" == go ]] && srv_bin="$GO_BIN"
    [[ "$cli" == go ]] && cli_bin="$GO_BIN"
    log="$out/${pair}-trial${trial}-recycle${recycle}.txt"
    printf 'TAP_RECYCLE pair=%s trial=%s recycle=%s batch=16 bypass=1 seconds=%s\n' "$pair" "$trial" "$recycle" "${IPERF_SECONDS:-10}" | tee "$log"
    IPERF_SECONDS="${IPERF_SECONDS:-10}" TLSVPN_RX_RECYCLE="$recycle" TLSVPN_RX_BATCH_SIZE=16 TLSVPN_RX_BYPASS=1 PERF_CONNS=1 \
      BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" \
      bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"
    if grep -Fq '[netperf] SKIP:' "$log"; then
      echo 'TAP_RECYCLE capability/dependency SKIP; no performance evidence.' | tee "$out/SKIP.txt"
      exit 0
    fi
    grep -Fq 'VPN_METRICS ' "$log" || { echo 'Missing VPN CPU/TAP metrics'; exit 1; }
  done
done
