#!/usr/bin/env bash
# Build the same source tree twice with rustls backed by ring and aws-lc-rs,
# then compare both binaries on the same privileged Real-TAP runner.
# The inner TLSVPN AEAD remains ring::aead in both builds; only rustls' outer
# TLS provider changes. Cargo.toml/Cargo.lock and temporary source edits are
# restored before benchmarking and again on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${GO_BIN:?set GO_BIN}"

out="${RX_PERF_OUTPUT:-perf-results/rx-real-tap}/crypto-provider"
work="${CRYPTO_AB_WORKDIR:-target/crypto-provider-ab}"
mkdir -p "$out" "$work"

cargo_toml_backup="$work/Cargo.toml.original"
cargo_lock_backup="$work/Cargo.lock.original"
main_backup="$work/main.rs.original"
client_backup="$work/client.rs.original"
cp Cargo.toml "$cargo_toml_backup"
cp Cargo.lock "$cargo_lock_backup"
cp src/main.rs "$main_backup"
cp src/client.rs "$client_backup"
restore_workspace() {
  cp "$cargo_toml_backup" Cargo.toml
  cp "$cargo_lock_backup" Cargo.lock
  cp "$main_backup" src/main.rs
  cp "$client_backup" src/client.rs
}
trap restore_workspace EXIT

build_provider() {
  # One `local` statement per assignment dependency: bash expands every word
  # of a single `local` before any of them lands, so referencing $provider in
  # the same statement dies with "unbound variable" under set -u.
  local provider="$1"
  local target_dir="$work/target-$provider" bin="$work/tlsvpn-$provider"
  restore_workspace
  if [[ "$provider" == "aws-lc" ]]; then
    python3 - <<'PY'
from pathlib import Path

p = Path("Cargo.toml")
s = p.read_text()
old = 'rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }'
new = 'rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12"] }'
if old not in s:
    raise SystemExit("expected rustls ring dependency line not found")
p.write_text(s.replace(old, new, 1))

for path in (Path("src/main.rs"), Path("src/client.rs")):
    text = path.read_text()
    old_provider = "rustls::crypto::ring::default_provider()"
    count = text.count(old_provider)
    if count == 0:
        raise SystemExit(f"expected explicit ring provider hook not found in {path}")
    path.write_text(text.replace(old_provider, "rustls::crypto::aws_lc_rs::default_provider()"))
PY
  fi
  echo "[crypto-ab] building provider=$provider"
  CARGO_TARGET_DIR="$target_dir" cargo build --release --bin tlsvpn
  cp "$target_dir/release/tlsvpn" "$bin"
  chmod +x "$bin"
  test -x "$bin"
}

build_provider ring
build_provider aws-lc
restore_workspace

RING_BIN="$work/tlsvpn-ring"
AWS_BIN="$work/tlsvpn-aws-lc"

run_case_once() {
  local provider="$1" trial="$2" pair="$3" conns="$4" seconds="$5" attempt="$6"
  local rust_bin="$RING_BIN"
  [[ "$provider" == "aws-lc" ]] && rust_bin="$AWS_BIN"
  local srv="${pair%-*}" cli="${pair#*-}" srv_bin="$rust_bin" cli_bin="$rust_bin"
  [[ "$srv" == go ]] && srv_bin="$GO_BIN"
  [[ "$cli" == go ]] && cli_bin="$GO_BIN"
  local name="${provider}-trial${trial}-${pair}-c${conns}-attempt${attempt}"
  local log="$out/$name.txt"
  echo "CRYPTO_AB provider=$provider trial=$trial pair=$pair conns=$conns seconds=$seconds attempt=$attempt" | tee "$log"
  set +e
  env TLSVPN_RX_OWNED=1 TLSVPN_TX_BATCH=1 TLSVPN_RX_COMPACT=0 TLSVPN_SWITCH_BATCH=0 \
    TLSVPN_TX_BATCH_SIZE=8 TLSVPN_RX_BATCH_SIZE=16 TLSVPN_RX_BYPASS=1 \
    PERF_CONNS="$conns" PERF_LATENCY=1 IPERF_SECONDS="$seconds" \
    BIN_SRV="$srv_bin" BIN_CLI="$cli_bin" FLAVOR_SRV="$srv" FLAVOR_CLI="$cli" \
    bash scripts/net_perf_test.sh 2>&1 | tee -a "$log"
  local rc=${PIPESTATUS[0]}
  set -e
  if grep -Fq '[netperf] SKIP:' "$log"; then
    echo 'CRYPTO_AB SKIP; no performance evidence' | tee "$out/SKIP.txt"
    return 0
  fi
  if [[ $rc -eq 0 ]] && grep -Fq VPN_METRICS "$log" && grep -Fq LOAD_LATENCY "$log"; then
    return 0
  fi
  if grep -Fq 'adaptive scheduler utilization gate failed' "$log"; then
    return 75
  fi
  if [[ $rc -eq 0 ]]; then
    echo "[crypto-ab] missing required VPN_METRICS/LOAD_LATENCY markers" | tee -a "$log"
    return 1
  fi
  return "$rc"
}

run_case() {
  local provider="$1" trial="$2" pair="$3" conns="$4" seconds="$5"
  local max_attempts=1
  (( conns > 1 )) && max_attempts="${CRYPTO_AB_C4_ATTEMPTS:-3}"
  local attempt rc
  for ((attempt=1; attempt<=max_attempts; attempt++)); do
    if run_case_once "$provider" "$trial" "$pair" "$conns" "$seconds" "$attempt"; then
      return 0
    else
      rc=$?
    fi
    if [[ $rc -eq 75 && $attempt -lt $max_attempts ]]; then
      echo "[crypto-ab] retrying invalid scheduler sample provider=$provider trial=$trial attempt=$attempt"
      continue
    fi
    return "$rc"
  done
}

# B/A/A/B order controls runner drift. rs/go and go/rs isolate the Rust server
# and client sides; go/go is sampled at the two ends as a runner control.
trial=0
for provider in ring aws-lc aws-lc ring; do
  trial=$((trial + 1))
  for pair in rs-rs rs-go go-rs; do
    run_case "$provider" "$trial" "$pair" 1 "${CRYPTO_AB_SECONDS:-8}"
  done
  run_case "$provider" "$trial" rs-rs 4 "${CRYPTO_AB_SECONDS:-8}"
  if [[ $trial -eq 1 || $trial -eq 4 ]]; then
    run_case "$provider" "$trial" go-go 1 "${CRYPTO_AB_SECONDS:-8}"
  fi
done

echo "[crypto-ab] completed; logs: $out"
