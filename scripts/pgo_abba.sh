#!/usr/bin/env bash
# Compare baseline and profile-use binaries in B/A/A/B order on the same runner.
# Go/Go is retained as a noise control but is excluded from the PGO improvement
# geomean by pgo_gate.py.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${BASE_BIN:?set BASE_BIN}" "${PGO_BIN:?set PGO_BIN}" "${GO_BIN:?set GO_BIN}"
PGO_ABBA_SECONDS="${PGO_ABBA_SECONDS:-5}"
PGO_ABBA_OUTPUT="${PGO_ABBA_OUTPUT:-$PWD/perf-results/pgo/abba}"
mkdir -p "$PGO_ABBA_OUTPUT"

run_case() {
  local trial="$1" variant="$2" pair="$3" conns="$4"
  local rs_bin="$BASE_BIN"
  [[ "$variant" == pgo ]] && rs_bin="$PGO_BIN"
  local srv="${pair%-*}" cli="${pair#*-}"
  local srv_bin="$rs_bin" cli_bin="$rs_bin"
  [[ "$srv" == go ]] && srv_bin="$GO_BIN"
  [[ "$cli" == go ]] && cli_bin="$GO_BIN"
  local log="$PGO_ABBA_OUTPUT/trial${trial}-${variant}-${pair}-c${conns}.txt"

  echo "PGO_ABBA trial=$trial variant=$variant pair=$pair conns=$conns seconds=$PGO_ABBA_SECONDS" | tee "$log"
  env \
    PERF_CONNS="$conns" PERF_LATENCY=1 \
    IPERF_SECONDS="$PGO_ABBA_SECONDS" IPERF_MIN_MBPS=50 \
    BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" \
    FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" \
    bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"

  if grep -Fq '[netperf] SKIP:' "$log"; then
    echo "PGO ABBA requires a real-TAP capable runner; $variant/$pair/c$conns skipped" >&2
    exit 1
  fi
  grep -Fq 'VPN_METRICS ' "$log"
  grep -Fq 'LOAD_LATENCY ' "$log"
  grep -Fq 'iperf3 upload' "$log"
  grep -Fq 'iperf3 download' "$log"
}

trial=0
for variant in baseline pgo pgo baseline; do
  trial=$((trial + 1))
  for conns in 1 4; do
    for pair in rs-rs rs-go go-rs go-go; do
      run_case "$trial" "$variant" "$pair" "$conns"
    done
  done
done

python3 scripts/pgo_gate.py "$PGO_ABBA_OUTPUT"
