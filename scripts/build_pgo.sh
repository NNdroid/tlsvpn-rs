#!/bin/bash
# PGO + native-CPU 优化构建（同机部署用；产物不可跨机器分发）
#
# 三阶段：
#   1. 插桩构建
#   2. 跑真实工作负载（自包含协议基准 + e2e 探针流量）生成 profile
#   3. 用 profile 优化构建（附带 -C target-cpu=native）
#
# 依赖：rustup component add llvm-tools-preview
set -e
cd "$(dirname "$0")/.."

PROF_DIR="$(mktemp -d)"
export PROF_DIR

echo "🧪 [1/3] 插桩构建..."
RUSTFLAGS="-Cprofile-generate=$PROF_DIR -Ctarget-cpu=native" cargo build --release
# 示例探针同样插桩（提供真实流量）
RUSTFLAGS="-Cprofile-generate=$PROF_DIR -Ctarget-cpu=native" cargo build --release --example interop_client

echo "🏃 [2/3] 采集 profile：运行协议基准 + 本地 e2e..."
# 协议基准（自包含，无需网络）
cargo test --release bench_protocol_throughput -- --ignored --nocapture || true

# 本地 e2e：起 mem-TAP 服务端 + Go/Rust 探针打流量（尽力而为，失败不阻断）
# flags 已移除（2026-09-19）：服务端同样走配置文件
cat > "$PROF_DIR/pgo_srv.json" <<'EOF'
{"mode": "server", "psk": "pgo_secret", "addr": "127.0.0.1:2999", "tap": "mem",
 "log_level": "warn", "encrypt": true,
 "server": {"cert": "e2e_cert.pem", "key": "e2e_key.pem"}}
EOF
./target/release/tlsvpn -c "$PROF_DIR/pgo_srv.json" &
SRV_PID=$!
sleep 2
# Go 探针源码在 Go 仓库（../tlsvpn/interop）——本仓库曾 vendored 一份超集副本，
# 没有任何脚本用到那些多出来的 flag，已删。产物写进 PROF_DIR，不污染 Go 仓库。
# 注意该探针没有 --encrypt（恒加密），只认 addr/psk/mac/send/timeout/enc-algo。
if command -v go >/dev/null 2>&1 && [ -d ../tlsvpn/interop ]; then
  (cd ../tlsvpn/interop && go build -o "$PROF_DIR/probe_pgo" . && \
    "$PROF_DIR/probe_pgo" --addr 127.0.0.1:2999 --psk pgo_secret --send 200 --timeout 8 || true; \
    rm -f "$PROF_DIR/probe_pgo")
fi
./target/release/examples/interop_client --addr 127.0.0.1:2999 --psk pgo_secret \
  --encrypt --send 200 --timeout 8 || true
kill $SRV_PID 2>/dev/null || true
wait 2>/dev/null || true

echo "🔧 [3/3] 合并 profile 并优化构建..."
llvm-profdata merge -o "$PROF_DIR/merged.profdata" "$PROF_DIR"/*.profraw
RUSTFLAGS="-Cprofile-use=$PROF_DIR/merged.profdata -Cprofile-sample-use=$PROF_DIR/merged.profdata -Ctarget-cpu=native" \
  cargo build --release --example interop_client
RUSTFLAGS="-Cprofile-use=$PROF_DIR/merged.profdata -Ctarget-cpu=native" cargo build --release

echo "✅ PGO 构建完成：target/release/tlsvpn（针对本机 CPU 优化）"
rm -rf "$PROF_DIR"
