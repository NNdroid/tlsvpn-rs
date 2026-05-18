#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define targets
TARGET_X86="x86_64-unknown-linux-gnu"
TARGET_ARM="aarch64-unknown-linux-gnu"

echo "🦀 Adding required Rust targets..."
rustup target add $TARGET_X86
rustup target add $TARGET_ARM

# Ensure cross-compilation toolchain is installed for aarch64
if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
    echo "📦 'aarch64-linux-gnu-gcc' not found. Attempting to install it..."
    if [ -x "$(command -v apt-get)" ]; then
        sudo apt-get update
        sudo apt-get install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross
    elif [ -x "$(command -v dnf)" ]; then
        sudo dnf install -y gcc-aarch64-linux-gnu
    elif [ -x "$(command -v yum)" ]; then
        sudo yum install -y gcc-aarch64-linux-gnu
    elif [ -x "$(command -v pacman)" ]; then
        sudo pacman -S --noconfirm aarch64-linux-gnu-gcc
    else
        echo "❌ Could not determine package manager. Please manually install the aarch64 cross-compiler (e.g., gcc-aarch64-linux-gnu)."
        exit 1
    fi
else
    echo "✅ 'aarch64-linux-gnu-gcc' is already installed."
fi

# Check if cross is installed, as it makes cross-compilation much easier
if command -v cross >/dev/null 2>&1; then
    BUILD_CMD="cross build"
    echo "🚀 Found 'cross', using it for building."
else
    BUILD_CMD="cargo build"
    echo "⚠️ 'cross' not found, using standard 'cargo'. "
fi

echo "==========================================="
echo "🔨 Building for Linux x86_64 ($TARGET_X86)..."
$BUILD_CMD --release --target $TARGET_X86

echo "==========================================="
echo "🔨 Building for Linux aarch64 ($TARGET_ARM)..."
# Setting the linker and CC specifically for cargo when cross-compiling ARM on Linux
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++

$BUILD_CMD --release --target $TARGET_ARM

echo "==========================================="
echo "✅ Build completed successfully!"
echo "📂 Binaries can be found in:"
echo "   - target/$TARGET_X86/release/tlsvpn"
echo "   - target/$TARGET_ARM/release/tlsvpn"
