#!/usr/bin/env bash
# build.sh — release-aligned build for tlsvpn-rs.
#
# The GitHub release workflow (build_and_release.yml) publishes STATIC musl
# binaries (x86_64 / aarch64 / armv7), and the cross-language e2e suite in
# the Go repo downloads exactly those asset names. This script mirrors that:
#
#   * with `cross` (docker) available: builds the same musl targets the
#     release publishes — this is the supported, reproducible path;
#   * without cross: falls back to gnu targets via local cargo for
#     development use only (prints a warning; these are NOT release assets).
#
# Note: mimalloc + ring compile C, so the gnu fallback requires a host C
# compiler (and the aarch64 cross-gcc, which this script installs).
set -euo pipefail

MUSL_TARGETS=(
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
    armv7-unknown-linux-musleabihf
)
GNU_TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
)

if command -v cross >/dev/null 2>&1; then
    echo "🚀 'cross' found — building STATIC musl binaries (release-aligned)."
    echo "   (docker images are pulled on first use; may take a while)"
    rustup target add "${MUSL_TARGETS[@]}"
    for t in "${MUSL_TARGETS[@]}"; do
        echo "==========================================="
        echo "🔨 cross build --release --target $t"
        cross build --release --target "$t"
    done
    echo "==========================================="
    echo "✅ musl binaries built (same targets as the release workflow):"
    for t in "${MUSL_TARGETS[@]}"; do
        echo "   - target/$t/release/tlsvpn"
    done
    exit 0
fi

echo "⚠️  'cross' not found — falling back to GNU targets via local cargo."
echo "   These binaries are for LOCAL USE ONLY: GitHub release assets and"
echo "   the cross-language e2e suite expect musl static builds. Install"
echo "   cross (cargo install cross) + docker to build release-aligned ones."

# mimalloc / ring build C code → a C compiler is mandatory on this path.
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "❌ No host C compiler found (required by mimalloc/ring)."
    echo "   Install build-essential (apt) / base-devel (pacman) / gcc (dnf),"
    echo "   or use 'cross' which compiles inside its docker images."
    exit 1
fi

rustup target add "${GNU_TARGETS[@]}"

# aarch64 cross toolchain for the gnu path
if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "📦 'aarch64-linux-gnu-gcc' not found. Attempting to install it..."
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
        echo "❌ Could not determine package manager. Install the aarch64"
        echo "   cross-compiler (aarch64-linux-gnu-gcc) manually and re-run."
        exit 1
    fi
fi

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++

echo "==========================================="
echo "🔨 Building for Linux x86_64 (x86_64-unknown-linux-gnu)..."
cargo build --release --target x86_64-unknown-linux-gnu

echo "==========================================="
echo "🔨 Building for Linux aarch64 (aarch64-unknown-linux-gnu)..."
cargo build --release --target aarch64-unknown-linux-gnu

echo "==========================================="
echo "✅ Build completed successfully!"
echo "📂 Binaries (gnu, local-use):"
echo "   - target/x86_64-unknown-linux-gnu/release/tlsvpn"
echo "   - target/aarch64-unknown-linux-gnu/release/tlsvpn"
