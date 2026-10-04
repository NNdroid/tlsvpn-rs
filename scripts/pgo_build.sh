#!/usr/bin/env bash
# Build tlsvpn-rs with LLVM instrumentation and consume the merged profile.
#
# Usage:
#   scripts/pgo_build.sh baseline
#   scripts/pgo_build.sh instrument
#   scripts/pgo_build.sh merge
#   scripts/pgo_build.sh optimize
#
# The training workload is intentionally separate (pgo_train_real_tap.sh) so
# profile generation can be reused on dedicated benchmark hosts.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-}"
HOST_TRIPLE="$(rustc -vV | awk -F': ' '/^host:/{print $2}')"
PGO_ROOT="${PGO_ROOT:-$PWD/target/pgo}"
PGO_RAW_DIR="${PGO_RAW_DIR:-$PGO_ROOT/raw}"
PGO_PROFDATA="${PGO_PROFDATA:-$PGO_ROOT/merged.profdata}"
PGO_BASE_TARGET_DIR="${PGO_BASE_TARGET_DIR:-$PWD/target/pgo-base}"
PGO_GEN_TARGET_DIR="${PGO_GEN_TARGET_DIR:-$PWD/target/pgo-gen}"
PGO_USE_TARGET_DIR="${PGO_USE_TARGET_DIR:-$PWD/target/pgo-use}"
PGO_OUT_DIR="${PGO_OUT_DIR:-$PWD/dist/pgo}"

usage() {
  cat <<'EOF'
usage: scripts/pgo_build.sh baseline|instrument|merge|optimize

Environment:
  PGO_ROOT             profile workspace (default target/pgo)
  PGO_RAW_DIR          .profraw directory
  PGO_PROFDATA         merged .profdata path
  PGO_*_TARGET_DIR     independent Cargo target directories
  PGO_OUT_DIR          output directory (default dist/pgo)
  RUSTFLAGS            optional target tuning flags preserved by this script
EOF
}

[[ -n "$MODE" ]] || { usage; exit 2; }
mkdir -p "$PGO_OUT_DIR" "$PGO_ROOT"

append_flags() {
  local extra="$1"
  if [[ -n "${RUSTFLAGS:-}" ]]; then
    printf '%s %s' "$RUSTFLAGS" "$extra"
  else
    printf '%s' "$extra"
  fi
}

artifact_path() {
  local target_dir="$1"
  printf '%s/%s/release/tlsvpn\n' "$target_dir" "$HOST_TRIPLE"
}

find_llvm_profdata() {
  local sysroot tool
  sysroot="$(rustc --print sysroot)"
  tool="$sysroot/lib/rustlib/$HOST_TRIPLE/bin/llvm-profdata"
  if [[ -x "$tool" ]]; then
    printf '%s\n' "$tool"
    return 0
  fi
  command -v llvm-profdata || {
    echo 'llvm-profdata not found. Install: rustup component add llvm-tools-preview' >&2
    return 1
  }
}

build_baseline() {
  echo "[pgo] building baseline release binary ($HOST_TRIPLE)"
  rm -rf "$PGO_BASE_TARGET_DIR"
  CARGO_TARGET_DIR="$PGO_BASE_TARGET_DIR" \
    cargo build --release --target "$HOST_TRIPLE"
  cp "$(artifact_path "$PGO_BASE_TARGET_DIR")" "$PGO_OUT_DIR/tlsvpn-baseline"
}

build_instrumented() {
  echo "[pgo] building profile-generate binary ($HOST_TRIPLE)"
  rm -rf "$PGO_GEN_TARGET_DIR" "$PGO_RAW_DIR"
  mkdir -p "$PGO_RAW_DIR"
  local flags
  flags="$(append_flags "-Cprofile-generate=$PGO_RAW_DIR -Ccodegen-units=1")"
  # --target keeps these RUSTFLAGS off host build scripts/proc-macros, matching
  # rustc's documented Cargo PGO workflow and avoiding irrelevant profiles.
  CARGO_TARGET_DIR="$PGO_GEN_TARGET_DIR" RUSTFLAGS="$flags" \
    cargo build --release --target "$HOST_TRIPLE"
  cp "$(artifact_path "$PGO_GEN_TARGET_DIR")" "$PGO_OUT_DIR/tlsvpn-instrumented"
  echo "[pgo] instrumented binary: $PGO_OUT_DIR/tlsvpn-instrumented"
  echo "[pgo] raw profile dir:     $PGO_RAW_DIR"
}

merge_profiles() {
  local profdata
  profdata="$(find_llvm_profdata)"
  mapfile -d '' raws < <(find "$PGO_RAW_DIR" -type f -name '*.profraw' -print0 2>/dev/null || true)
  if (( ${#raws[@]} == 0 )); then
    echo "no .profraw files found in $PGO_RAW_DIR" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$PGO_PROFDATA")"
  echo "[pgo] merging ${#raws[@]} raw profiles"
  "$profdata" merge -sparse "${raws[@]}" -o "$PGO_PROFDATA"
  "$profdata" show --summary-only "$PGO_PROFDATA" || true
  test -s "$PGO_PROFDATA"
}

build_optimized() {
  test -s "$PGO_PROFDATA" || {
    echo "missing merged profile: $PGO_PROFDATA" >&2
    exit 1
  }
  echo "[pgo] building profile-use release binary ($HOST_TRIPLE)"
  rm -rf "$PGO_USE_TARGET_DIR"
  local flags
  # Missing-function warnings are useful during the candidate phase: they make
  # profile drift visible without turning expected cold-code misses into errors.
  flags="$(append_flags "-Cprofile-use=$PGO_PROFDATA -Cllvm-args=-pgo-warn-missing-function -Ccodegen-units=1")"
  CARGO_TARGET_DIR="$PGO_USE_TARGET_DIR" RUSTFLAGS="$flags" \
    cargo build --release --target "$HOST_TRIPLE"
  cp "$(artifact_path "$PGO_USE_TARGET_DIR")" "$PGO_OUT_DIR/tlsvpn-pgo"
  echo "[pgo] optimized binary: $PGO_OUT_DIR/tlsvpn-pgo"
}

case "$MODE" in
  baseline)   build_baseline ;;
  instrument) build_instrumented ;;
  merge)      merge_profiles ;;
  optimize)   build_optimized ;;
  -h|--help|help) usage ;;
  *) echo "unknown mode: $MODE" >&2; usage; exit 2 ;;
esac
