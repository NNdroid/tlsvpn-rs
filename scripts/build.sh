#!/usr/bin/env bash
# build.sh — tlsvpn-rs multi-mode build.
#
# Usage: scripts/build.sh [MODE] [OUTPUT_DIR]
#
#   native (default)  Build the current host target with cargo. Fast, no
#                     cross toolchain needed — this is what CI and local
#                     development want.
#   musl              Build the three STATIC musl targets that the GitHub
#                     release workflow publishes (x86_64 / aarch64 / armv7);
#                     these are exactly the asset names the Go repo's e2e
#                     suite downloads. Requires `cross` (docker).
#   gnu               Build x86_64 + aarch64 GNU targets with the local
#                     toolchain (installs the aarch64 cross-gcc if missing).
#                     Static musl is preferred for distribution; gnu is for
#                     local-use fallback when cross/docker is unavailable.
#   a55               Build an additional aarch64 GNU binary tuned for
#                     Cortex-A55 (e.g. RK3568/R5S). The generic ARM64 binary
#                     remains the compatibility default.
#   all               musl + gnu.
#
# Artifacts are copied to OUTPUT_DIR (default: dist/) as
#   dist/tlsvpn-<target-triple>   (native also writes plain dist/tlsvpn)
#
# Env:
#   CARGO_ARGS   extra args appended to cargo/cross build (e.g. --offline)
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="${1:-native}"
OUT_DIR="${2:-dist}"
HOST_TRIPLE="$(rustc -vV | awk -F': ' '/^host:/{print $2}')"

MUSL_TARGETS=(
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
    armv7-unknown-linux-musleabihf
)

GNU_TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
)

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

case "$MODE" in
    -h|--help|help) usage 0 ;;
    native|musl|gnu|a55|all) ;;
    *) echo "❌ unknown mode: $MODE" >&2; usage 1 ;;
esac

copy_artifact() {
    # $1 = cargo target dir ("" for host), $2 = artifact base name
    local triple_dir="$1" name="$2" src
    if [[ -z "$triple_dir" ]]; then
        src="target/release/tlsvpn"
    else
        src="target/$triple_dir/release/tlsvpn"
    fi
    # Windows hosts produce tlsvpn.exe
    [[ -f "$src" ]] || src="$src.exe"
    if [[ ! -f "$src" ]]; then
        echo "❌ artifact not found: $src" >&2
        return 1
    fi
    mkdir -p "$OUT_DIR"
    cp "$src" "$OUT_DIR/$name"
    echo "   -> $OUT_DIR/$name"
}

require_c_compiler() {
    # mimalloc + ring compile C on the plain-cargo paths
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        echo "❌ No host C compiler found (required by mimalloc/ring)." >&2
        echo "   Install build-essential / base-devel / gcc, or use 'musl'" >&2
        echo "   mode with cross (compiles inside docker images)." >&2
        exit 1
    fi
}

build_native() {
    echo "🔨 native build ($HOST_TRIPLE)"
    require_c_compiler
    cargo build --release ${CARGO_ARGS:-}
    copy_artifact "" "tlsvpn-$HOST_TRIPLE"
    copy_artifact "" "tlsvpn"
}

build_musl() {
    if ! command -v cross >/dev/null 2>&1; then
        echo "❌ musl mode needs 'cross' (cargo install cross) + docker." >&2
        echo "   It builds the same static binaries the release workflow ships." >&2
        exit 1
    fi
    rustup target add "${MUSL_TARGETS[@]}"
    for t in "${MUSL_TARGETS[@]}"; do
        echo "🔨 cross build --release --target $t"
        cross build --release --target "$t" ${CARGO_ARGS:-}
        copy_artifact "$t" "tlsvpn-$t"
    done
}

ensure_aarch64_gnu_toolchain() {
    require_c_compiler
    if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo "📦 installing aarch64 cross toolchain..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y gcc-aarch64-linux-gnu
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y gcc-aarch64-linux-gnu
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm aarch64-linux-gnu-gcc
        else
            echo "❌ unknown package manager; install aarch64-linux-gnu-gcc manually" >&2
            exit 1
        fi
    fi
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
    rustup target add aarch64-unknown-linux-gnu
}

build_gnu() {
    ensure_aarch64_gnu_toolchain
    rustup target add x86_64-unknown-linux-gnu
    for t in "${GNU_TARGETS[@]}"; do
        echo "🔨 cargo build --release --target $t"
        cargo build --release --target "$t" ${CARGO_ARGS:-}
        copy_artifact "$t" "tlsvpn-$t"
    done
}

build_a55() {
    ensure_aarch64_gnu_toolchain
    local target="aarch64-unknown-linux-gnu"
    echo "🔨 cargo build --release --target $target -C target-cpu=cortex-a55"
    RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-cpu=cortex-a55" \
        cargo build --release --target "$target" ${CARGO_ARGS:-}
    copy_artifact "$target" "tlsvpn-$target-cortex-a55"
}

echo "🦀 tlsvpn-rs build — mode: $MODE, output: $OUT_DIR/"
case "$MODE" in
    native) build_native ;;
    musl)   build_musl ;;
    gnu)    build_gnu ;;
    a55)    build_a55 ;;
    all)    build_musl; build_gnu ;;
esac

echo "==========================================="
echo "✅ done. artifacts:"
ls -lh "$OUT_DIR"
