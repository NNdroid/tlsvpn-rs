#!/usr/bin/env bash
# Train an LLVM profile with real TAP traffic. The matrix deliberately covers
# both tunnel directions, one/four physical connections and Go interoperability.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${RS_BIN:?set RS_BIN to the instrumented tlsvpn-rs binary}"
PGO_ROOT="${PGO_ROOT:-$PWD/target/pgo}"
PGO_RAW_DIR="${PGO_RAW_DIR:-$PGO_ROOT/raw}"
PGO_TRAIN_SECONDS="${PGO_TRAIN_SECONDS:-6}"
PGO_TRAIN_OUTPUT="${PGO_TRAIN_OUTPUT:-$PWD/perf-results/pgo/train}"
PGO_FLUSH_TIMEOUT_TENTHS="${PGO_FLUSH_TIMEOUT_TENTHS:-150}"
GO_BIN="${GO_BIN:-}"

mkdir -p "$PGO_RAW_DIR" "$PGO_TRAIN_OUTPUT"
RS_REAL="$(readlink -f "$RS_BIN")"

profile_count_for_case() {
  local pair="$1" conns="$2"
  find "$PGO_RAW_DIR" -type f \
    -name "${pair}-c${conns}-*.profraw" -size +0c 2>/dev/null | wc -l
}

dump_instrumented_processes() {
  local proc exe
  echo 'PGO profile flush timeout; instrumented process state:' >&2
  for proc in /proc/[0-9]*; do
    [[ -e "$proc/exe" ]] || continue
    exe="$(readlink -f "$proc/exe" 2>/dev/null || true)"
    [[ "$exe" == "$RS_REAL" ]] || continue
    printf '  pid=%s state=' "${proc##*/}" >&2
    awk '{print $3}' "$proc/stat" 2>/dev/null || echo '?' >&2
  done
}

wait_for_profile_flush() {
  local pair="$1" conns="$2" expected="$3" log="$4"
  local i count
  for ((i=0; i<PGO_FLUSH_TIMEOUT_TENTHS; i++)); do
    count="$(profile_count_for_case "$pair" "$conns")"
    if (( count >= expected )); then
      echo "PGO_PROFILE_FLUSH pair=$pair conns=$conns profiles=$count expected=$expected" | tee -a "$log"
      return 0
    fi
    sleep 0.1
  done
  count="$(profile_count_for_case "$pair" "$conns")"
  echo "PGO_PROFILE_FLUSH_FAILED pair=$pair conns=$conns profiles=$count expected=$expected" | tee -a "$log" >&2
  dump_instrumented_processes | tee -a "$log" >&2 || true
  return 1
}

run_case() {
  local pair="$1" conns="$2"
  local srv="${pair%-*}" cli="${pair#*-}"
  local srv_bin="$RS_BIN" cli_bin="$RS_BIN"
  [[ "$srv" == go ]] && srv_bin="$GO_BIN"
  [[ "$cli" == go ]] && cli_bin="$GO_BIN"
  local log="$PGO_TRAIN_OUTPUT/train-${pair}-c${conns}.txt"
  local profile_pattern="$PGO_RAW_DIR/${pair}-c${conns}-%p-%m.profraw"
  local expected=0
  [[ "$srv" == rs ]] && expected=$((expected + 1))
  [[ "$cli" == rs ]] && expected=$((expected + 1))

  echo "PGO_TRAIN pair=$pair conns=$conns seconds=$PGO_TRAIN_SECONDS" | tee "$log"
  env \
    LLVM_PROFILE_FILE="$profile_pattern" \
    PERF_CONNS="$conns" PERF_LATENCY=0 \
    IPERF_SECONDS="$PGO_TRAIN_SECONDS" IPERF_MIN_MBPS=25 \
    BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" \
    FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" \
    bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"

  if grep -Fq '[netperf] SKIP:' "$log"; then
    echo "PGO training requires a real-TAP capable runner; case $pair/c$conns skipped" >&2
    exit 1
  fi
  grep -Fq 'iperf3 upload' "$log"
  grep -Fq 'iperf3 download' "$log"

  # net_perf cleanup sends SIGTERM. tlsvpn's ctrlc handler is built with the
  # `termination` feature in this branch, so SIGTERM now reaches the cooperative
  # EXIT path and LLVM gets a normal process teardown in which to flush .profraw.
  wait_for_profile_flush "$pair" "$conns" "$expected" "$log"
}

# rs/rs trains both Rust endpoints. rs/go and go/rs make the same Rust binary
# see the asymmetric interoperability paths that are part of the promotion gate.
for conns in 1 4; do
  run_case rs-rs "$conns"
  if [[ -n "$GO_BIN" ]]; then
    run_case rs-go "$conns"
    run_case go-rs "$conns"
  fi
done

count=$(find "$PGO_RAW_DIR" -type f -name '*.profraw' -size +0c | wc -l)
if (( count == 0 )); then
  echo "training finished without producing .profraw files" >&2
  exit 1
fi
echo "PGO_TRAIN_COMPLETE raw_profiles=$count dir=$PGO_RAW_DIR"
