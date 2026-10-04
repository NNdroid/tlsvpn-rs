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
probe_backup="$work/interop_client.rs.original"
cp Cargo.toml "$cargo_toml_backup"
cp Cargo.lock "$cargo_lock_backup"
cp src/main.rs "$main_backup"
cp src/client.rs "$client_backup"
cp examples/interop_client.rs "$probe_backup"
restore_workspace() {
  cp "$cargo_toml_backup" Cargo.toml
  cp "$cargo_lock_backup" Cargo.lock
  cp "$main_backup" src/main.rs
  cp "$client_backup" src/client.rs
  cp "$probe_backup" examples/interop_client.rs
}
trap restore_workspace EXIT

# The two cold provider builds are the expensive part of this harness; pay
# for them only on runners that can produce evidence. net_perf_test.sh runs
# its RTNL/TAP capability gate before any case, so this go/go probe either
# SKIPs within seconds on an incapable runner or confirms the runner is
# usable before any build starts.
probe_log="$out/probe.txt"
echo "[crypto-ab] probing runner capability with go/go"
set +e
env BIN_SRV="$GO_BIN" BIN_CLI="$GO_BIN" FLAVOR_SRV=go FLAVOR_CLI=go \
  PERF_CONNS=1 PERF_LATENCY=0 IPERF_SECONDS=1 \
  bash scripts/net_perf_test.sh 2>&1 | tee "$probe_log"
set -e
if grep -Fq '[netperf] SKIP:' "$probe_log"; then
  echo 'CRYPTO_AB SKIP; runner cannot produce performance evidence' | tee "$out/SKIP.txt"
  exit 0
fi

# The caller runs this harness under `sudo -E`, and sudo's secure_path drops
# ~/.cargo/bin while HOME may point at /root — every pre-existing sudo step
# either runs prebuilt binaries or builds outside sudo. Resolve the toolchain
# by absolute path, pin the rustup home so the shim resolves the same
# toolchain regardless of HOME, and keep every cargo write inside our work
# dir so the runner user's ~/.cargo cache is never touched as root.
cargo_env=()
if [[ -n "${SUDO_USER:-}" ]]; then
  cargo_env+=("CARGO_HOME=$work/cargo-home")
fi
cargo_bin="${CRYPTO_AB_CARGO:-}"
if [[ -z "$cargo_bin" ]]; then
  cargo_bin="$(command -v cargo 2>/dev/null || true)"
fi
if [[ -z "$cargo_bin" ]]; then
  for cand in "$HOME/.cargo/bin/cargo" /home/runner/.cargo/bin/cargo \
              /root/.cargo/bin/cargo /usr/local/cargo/bin/cargo; do
    if [[ -x "$cand" ]]; then cargo_bin="$cand"; break; fi
  done
fi
if [[ -z "$cargo_bin" ]]; then
  echo "[crypto-ab] cargo not found; sudo strips ~/.cargo/bin from PATH" >&2
  exit 1
fi
if [[ "$cargo_bin" == *"/.cargo/bin/cargo" ]]; then
  cargo_home_root="${cargo_bin%/.cargo/bin/cargo}"
  if [[ -n "${SUDO_USER:-}" && -z "${RUSTUP_HOME:-}" ]]; then
    cargo_env+=("RUSTUP_HOME=$cargo_home_root/.rustup")
  fi
fi
# cargo spawns `rustc` (and rustdoc) by name through PATH, and sudo's
# secure_path has no rustup shims either. Prepend the shim dir so the cargo
# process resolves the same toolchain rustc that RUSTUP_HOME points at.
cargo_env+=("PATH=${cargo_bin%/*}:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}")

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
# Anchor on the rustls dependency line itself instead of its full literal
# text: feature-list edits stay tolerated, anything else fails loudly
# instead of benchmarking ring against itself.
rustls_lines = [ln for ln in s.splitlines() if ln.startswith("rustls = {")]
if len(rustls_lines) != 1:
    raise SystemExit(f"expected exactly one rustls dependency line, found {len(rustls_lines)}")
line = rustls_lines[0]
if "default-features = false" not in line:
    raise SystemExit("rustls dependency must disable default features for the provider swap")
if '"ring"' not in line:
    raise SystemExit("rustls dependency does not select ring; cannot swap to aws_lc_rs")
p.write_text(s.replace(line, line.replace('"ring"', '"aws_lc_rs"', 1), 1))

# The interop probe is patched alongside the daemon sources so every binary
# built from the aws-lc tree picks the same outer provider, not just tlsvpn.
for path in (Path("src/main.rs"), Path("src/client.rs"), Path("examples/interop_client.rs")):
    text = path.read_text()
    old_provider = "rustls::crypto::ring::default_provider()"
    count = text.count(old_provider)
    if count == 0:
        raise SystemExit(f"expected explicit ring provider hook not found in {path}")
    path.write_text(text.replace(old_provider, "rustls::crypto::aws_lc_rs::default_provider()"))
PY
  fi
  echo "[crypto-ab] building provider=$provider"
  env "${cargo_env[@]}" CARGO_TARGET_DIR="$target_dir" "$cargo_bin" build --release --bin tlsvpn
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
