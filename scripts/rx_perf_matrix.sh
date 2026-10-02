#!/usr/bin/env bash
# Same-binary negative control: bypass=0 keeps the original dedup/reorder route.
# Run serially because net_perf_test.sh owns fixed TAP and web endpoint names.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RS_BIN:?set RS_BIN to the Rust binary}"
: "${GO_BIN:?set GO_BIN to the Go binary}"
out="${RX_PERF_OUTPUT:-perf-results/rx-real-tap}"
mkdir -p "$out"
{
  git rev-parse HEAD
  uname -a
  command -v lscpu >/dev/null && lscpu || true
  sha256sum "$RS_BIN" "$GO_BIN"
} > "$out/host.txt"
for batch in 16 32 64 128; do
  for bypass in 0 1; do
    for pair in rs-rs rs-go go-rs; do
      srv="${pair%-*}"; cli="${pair#*-}"
      srv_bin="$RS_BIN"; cli_bin="$RS_BIN"
      [[ "$srv" == go ]] && srv_bin="$GO_BIN"
      [[ "$cli" == go ]] && cli_bin="$GO_BIN"
      log="$out/${pair}-batch${batch}-bypass${bypass}.txt"
      printf 'RX_REAL_TAP pair=%s batch=%s bypass=%s conns=1 fec=false\n' "$pair" "$batch" "$bypass" | tee "$log"
      TLSVPN_RX_BATCH_SIZE="$batch" TLSVPN_RX_BYPASS="$bypass" PERF_CONNS=1 \
        BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" \
        bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"
      if grep -Fq '[netperf] SKIP:' "$log"; then
        echo 'RX_REAL_TAP unavailable: capability/dependency gate skipped; no throughput result.' | tee "$out/SKIP.txt"
        exit 0
      fi
    done
  done
done
