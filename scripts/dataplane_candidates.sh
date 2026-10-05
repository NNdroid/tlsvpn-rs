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
  # The utilization gate reads one cumulative stats snapshot; on a noisy
  # runner the adaptive scheduler can legitimately concentrate traffic on the
  # healthy paths for that sample. Treat a gate trip as an invalid sample and
  # redraw it (same contract as crypto_backend_ab.sh's rc=75 retries).
  local attempt rc
  for ((attempt = 1; attempt <= 3; attempt++)); do
    echo "DATAPLANE_CASE name=$name pair=$pair seconds=$seconds flags=$* attempt=$attempt" | tee "$log"
    set +e
    env TLSVPN_RX_OWNED=0 TLSVPN_TX_BATCH=0 TLSVPN_RX_COMPACT=0 TLSVPN_SWITCH_BATCH=0 \
      TLSVPN_TX_BATCH_SIZE=8 TLSVPN_RX_BATCH_SIZE=16 TLSVPN_RX_BYPASS=1 PERF_CONNS=1 \
      PERF_LATENCY=1 IPERF_SECONDS="$seconds" BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" \
      FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" "$@" bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"
    rc=${PIPESTATUS[0]}
    set -e
    if grep -Fq '[netperf] SKIP:' "$log"; then
      echo 'DATAPLANE_CASE SKIP; no performance evidence' | tee "$out/SKIP.txt"
      exit 0
    fi
    if grep -Fq 'adaptive scheduler utilization gate failed' "$log"; then
      [[ $attempt -lt 3 ]] || break
      echo "[candidates] invalid scheduler sample; retrying attempt=$attempt"
      continue
    fi
    break
  done
  [[ $rc -eq 0 ]] || exit "$rc"
  grep -Fq VPN_METRICS "$log" || exit 1
  grep -Fq LOAD_LATENCY "$log" || exit 1
}
# Single-draw flag A/Bs flipped sign between runner days (SWITCH_BATCH c1 up:
# -11% on 2026-10-04, +1.7% on 2026-10-05), so every flag now gets the same
# 10 s ABBA treatment the conns=4 cases use before a default change.
trial=0
for enabled in 0 1 1 0; do
  trial=$((trial + 1))
  for flag in TLSVPN_RX_OWNED TLSVPN_TX_BATCH TLSVPN_RX_COMPACT TLSVPN_SWITCH_BATCH; do
    run_case "$flag-abba-trial$trial" rs-rs 10 "$flag=$enabled"
  done
done
for size in 8 16 32; do
  run_case "tx-size-$size" rs-rs 5 TLSVPN_TX_BATCH=1 "TLSVPN_TX_BATCH_SIZE=$size"
done

# The netperf matrix shows the Rust server falling behind the go/go control at
# conns=4 (rs-rs down 1226 vs 2874 Mbps on 2026-10-04) while go_srv <- rs_cli
# keeps pace, so the server TX path is the suspect. First single-draw c4 A/Bs
# (2026-10-05) put SWITCH_BATCH up +35% and TX_BATCH down -26%, but c4 spreads
# 25%+ between same-config runs, so these ABBA trials at 10 s with a go/go
# control per trial firm the signals up before any server-side default change.
trial=0
for enabled in 0 1 1 0; do
  trial=$((trial + 1))
  run_case "c4-control-trial$trial" go-go 10 "PERF_CONNS=4"
  run_case "sw-batch-c4-trial$trial" rs-rs 10 "PERF_CONNS=4" "TLSVPN_SWITCH_BATCH=$enabled"
  run_case "tx-batch-c4-trial$trial" rs-rs 10 "PERF_CONNS=4" "TLSVPN_TX_BATCH=$enabled"
done

# Compare rustls' outer TLS crypto provider without changing the production
# manifest: the helper builds ring/aws-lc variants from this exact source tree,
# restores Cargo.toml/Cargo.lock, then runs same-runner B/A/A/B Real-TAP cases.
GO_BIN="$GO_BIN" RX_PERF_OUTPUT="${RX_PERF_OUTPUT:-perf-results/rx-real-tap}" \
  bash scripts/crypto_backend_ab.sh

trial=0
for enabled in 0 1 1 0; do
  trial=$((trial + 1))
  for pair in rs-rs rs-go go-rs go-go; do
    run_case "all-$enabled-trial$trial" "$pair" 10 \
      "TLSVPN_RX_OWNED=$enabled" "TLSVPN_TX_BATCH=$enabled" \
      "TLSVPN_RX_COMPACT=$enabled" "TLSVPN_SWITCH_BATCH=$enabled"
  done
done
