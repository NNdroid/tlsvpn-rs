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
./target/release/tlsvpn --mode server --psk pgo_secret --tap mem \
  --addr 127.0.0.1:2999 --cert e2e_cert.pem --key e2e_key.pem --encrypt --loglevel warn &
SRV_PID=$!
sleep 2
if command -v go >/dev/null 2>&1 && [ -d interop ]; then
  (cd interop && go build -o probe_pgo . && \
    ./probe_pgo --addr 127.0.0.1:2999 --psk pgo_secret --encrypt --send 200 --timeout 8 || true; \
    rm -f probe_pgo)
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
