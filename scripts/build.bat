@echo off
setlocal enabledelayedexpansion

set TARGET_X86=x86_64-pc-windows-msvc
set TARGET_ARM=aarch64-pc-windows-msvc

echo 🦀 Adding required Rust targets...
rustup target add %TARGET_X86%
rustup target add %TARGET_ARM%

echo ===========================================
echo 🔨 Building for Windows x86_64 (%TARGET_X86%)...
cargo build --release --target %TARGET_X86%
if %ERRORLEVEL% neq 0 (
    echo ❌ Failed to build for x86_64.
    exit /b %ERRORLEVEL%
)

echo ===========================================
echo 🔨 Building for Windows aarch64 (%TARGET_ARM%)...
echo 💡 Note: Cross-compiling for ARM64 on Windows requires "MSVC v14x - VS 20xx C++ ARM64 build tools"
echo    installed via the Visual Studio Installer.
cargo build --release --target %TARGET_ARM%
if %ERRORLEVEL% neq 0 (
    echo ❌ Failed to build for aarch64.
    exit /b %ERRORLEVEL%
)

echo ===========================================
echo ✅ Build completed successfully!
echo 📂 Binaries can be found in:
echo    - target\%TARGET_X86%\release\tlsvpn.exe
echo    - target\%TARGET_ARM%\release\tlsvpn.exe
