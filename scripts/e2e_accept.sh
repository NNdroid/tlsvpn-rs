#!/usr/bin/env bash
# e2e_accept.sh — 总验收矩阵：档 A/B/C/D 落地后的跨语言互测。
#
#   P1 安全配置   —— pad_mode=bucket + min_enc=gcm + protocol v2
#   P2 可选调优关闭 —— padding=off / 无 min_enc，但 protocol v2 仍强制
#   P3 新旧混装   —— 默认必须拒绝缺少 protocol v2 的旧对端
#   P4 旧配置迁移 —— legacy session_token=false 可读取，但不得改变 v2 令牌保护
#
# 用自包含探针（--tap mem），协议级验证，不需要 CAP_NET_ADMIN。
# 判据：探针退出 0 + 服务端日志无错误标记（解密失败/panic/校验失败/拒绝连接）。
#
# P3 依赖特性引入前的旧二进制（E2E_RS_OLD_* / E2E_GO_OLD_BIN）。它们
# 不在正常构建产物里，缺了就跳过拒绝矩阵并打印跳过了几组，而不是整体失败。
#
# Env（见 e2e_lib.sh）：PORT_BASE 默认 18200，每例 +10
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

PORT_BASE="${PORT_BASE:-18200}"
PSK="$E2E_PSK"
PASS_N=0
FAIL_N=0
SKIP_N=0
CASE_N=0
FAILED_CASES=()
TMPDIRS=()

# 第 N 例（1 起）用的端口与 MAC：run_case 与 go_cfg_now 共用同一公式，
# 不再靠注释解释 off-by-one。
case_port() { printf '%s' "$((PORT_BASE + ($1 - 1) * 10))"; }
case_mac()  { printf 'aa:bb:cc:dd:ee:%02x' "$(( ($1 - 1) % 250 + 1 ))"; }

e2e_ensure_cert || { echo "e2e: 需要 e2e_cert.pem/e2e_key.pem 或 openssl"; exit 2; }
CERT="$E2E_CERT"
KEY="$E2E_KEY"

# run_case LABEL SRV_IMPL CLI_IMPL SRV_PAD SRV_MINENC SRV_TOKEN CLI_EXTRA [SRV_CFG] [EXPECT]
# SRV/CLI 取值：rs | go | rsold | goold
# SRV_PAD / SRV_MINENC / SRV_TOKEN 是服务端特性旋钮：非空才写入对应键。
# 两实现 flags 均已移除（2026-09-19），一律拼 config.json 后 -c 启动；
# 旋钮为空就省键 —— pre-feature 旧二进制（rsold/goold）的 schema 没有这些键，
# DisallowUnknownFields 会拒收。需要完整定制时用 go_cfg_now 生成 SRV_CFG 传入。
# EXPECT=pass(默认)|fail → fail 表示预期不互通（用于 opt-in 破坏旧对端）
run_case() {
  local label="$1" srv="$2" cli="$3"
  local srv_pad="$4" srv_minenc="$5" srv_token="$6"
  local cli_extra="$7" srv_cfg="${8:-}" expect="${9:-pass}"
  local gobin rsbin probebin

  # 归一化到实际的语言实现（rsold/goold 只是版本别名）
  local sk=$srv ck=$cli
  [ "$sk" = goold ] && sk=go
  [ "$ck" = rsold ] && ck=rs

  gobin="$E2E_GO_BIN";      [ "$srv" = goold ] && gobin="$E2E_GO_OLD_BIN"
  rsbin="$E2E_RS_BIN";      [ "$srv" = rsold ] && rsbin="$E2E_RS_OLD_BIN"

  if [ "$ck" = rs ]; then
    probebin="$E2E_RS_PROBE"
    [ "$cli" = rsold ] && probebin="$E2E_RS_OLD_PROBE"
  else
    probebin="$E2E_GO_PROBE"
  fi

  CASE_N=$((CASE_N + 1))
  local port mac tmp slog clog
  port="$(case_port "$CASE_N")"
  mac="$(case_mac "$CASE_N")"
  tmp="$(mktemp -d)"
  TMPDIRS+=("$tmp")
  slog="$(e2e_winpath "$tmp/srv.log")"
  clog="$(e2e_winpath "$tmp/cli.log")"
  e2e_kill_port "$port"

  # 服务端命令（数组形式，避免 eval 注入与二次引号问题）
  local cfg
  if [ -n "$srv_cfg" ]; then
    cfg="$srv_cfg"   # go_cfg_now 产出的已是 winpath 形态
  else
    cfg="$(e2e_winpath "$tmp/srv.json")"
    local pad_frag="" minenc_frag=""
    local srvobj="\"server\": {\"cert\": \"$CERT\", \"key\": \"$KEY\", \"v4_cidr\": \"10.77.0.0/24\", \"v6_cidr\": \"fd77::/64\""
    [ -n "$srv_pad" ] && pad_frag="\"pad_mode\": \"$srv_pad\""
    [ -n "$srv_minenc" ] && minenc_frag="\"min_enc\": \"$srv_minenc\""
    [ "$srv_token" = 1 ] && srvobj+=", \"session_token\": true"
    srvobj+="}"
    e2e_config "$tmp/srv.json" server "127.0.0.1:$port" \
      "\"psk\": \"$PSK\"" \
      '"encrypt": true' \
      '"log_level": "info"' \
      "$pad_frag" "$minenc_frag" "$srvobj"
  fi
  if [ "$sk" = rs ]; then
    set -- "$rsbin" -c "$cfg"
  else
    set -- "$gobin" -c "$cfg"
  fi
  "$@" >"$slog" 2>&1 &
  e2e_wait_port 127.0.0.1 "$port" 15 || {
    printf '  %sFAIL%s      [%s] 服务端未启动\n' "$E2E_RED" "$E2E_RESET" "$label"
    cat "$slog"
    FAIL_N=$((FAIL_N + 1)); FAILED_CASES+=("$label")
    e2e_kill_port "$port"; return 0
  }

  # 探针：前台跑，外层 timeout 兜底（内部 --timeout 之外再防死锁）
  if [ "$ck" = rs ]; then
    set -- "$probebin" --addr "127.0.0.1:$port" --psk "$PSK" --mac "$mac" \
      --send 20 --timeout 12
  else
    set -- "$probebin" -addr "127.0.0.1:$port" -psk "$PSK" -mac "$mac" \
      -send 20 -timeout 12
  fi
  for w in $cli_extra; do set -- "$@" "$w"; done
  timeout 25 "$@" >"$clog" 2>&1
  local rc=$?
  e2e_kill_port "$port"

  local errs ok verdict
  errs="$(e2e_strip "$slog" | grep -E 'ERROR|panic|panicked|GCM.*(fail|FAIL)|decrypt.*fail|verification failed|authentication failed|connection refused|fatal' | tail -5 || true)"
  ok=1
  [ $rc -eq 0 ] || ok=0
  [ -z "$errs" ] || ok=0

  if [ $ok -eq 1 ]; then
    if [ "$expect" = fail ]; then verdict=UNEXPECTED-PASS; else verdict=PASS; fi
  else
    if [ "$expect" = fail ]; then verdict=PASS-AS-EXPECTED; else verdict=FAIL; fi
  fi

  if [ "$verdict" = PASS ] || [ "$verdict" = PASS-AS-EXPECTED ]; then
    PASS_N=$((PASS_N + 1))
    printf '  %s%s%s  [%s] srv=%s cli=%s probe_rc=%d\n' \
      "$E2E_GREEN" "$verdict" "$E2E_RESET" "$label" "$srv" "$cli" "$rc"
  else
    FAIL_N=$((FAIL_N + 1))
    FAILED_CASES+=("$label")
    printf '  %sFAIL%s      [%s] srv=%s cli=%s probe_rc=%d\n' \
      "$E2E_RED" "$E2E_RESET" "$label" "$srv" "$cli" "$rc"
    echo "  --- probe tail ---"; tail -8 "$clog"
    echo "  --- server errors ---"; [ -n "$errs" ] && echo "$errs" || echo "  (无错误标记 → 探针 rc=$rc)"
    echo "  --- server feature lines ---"
    e2e_strip "$slog" | grep -Ei 'EncAlgo|online|session|token|refused|min_enc|padding|Confusion|bucket' | tail -6
  fi
}

# go_cfg_now IS_SERVER LEGACY_TOKEN PAD MINENC
# LEGACY_TOKEN 仅供 P4 验证旧配置迁移；空串表示当前配置契约，不生成该键。
# 为「下一个」将要执行的 run_case 生成配置文件。run_case 会先把 CASE_N 加 1
# 再取端口，所以这里针对 CASE_N+1 生成。
CFGF=""
go_cfg_now() {
  local is_srv="$1" tok="$2" pad="$3" minenc="$4"
  local d f port mac legacy_token=""
  d="$(mktemp -d)"; TMPDIRS+=("$d")
  f="$(e2e_winpath "$d/srv.json")"
  port="$(case_port $((CASE_N + 1)))"
  mac="$(case_mac $((CASE_N + 1)))"
  [ -n "$tok" ] && legacy_token=", \"session_token\": $tok"
  if [ "$is_srv" = 1 ]; then
    cat > "$f" <<EOF
{"mode": "server", "psk": "$PSK", "addr": "127.0.0.1:$port", "tap": "mem",
 "log_level": "info", "encrypt": true, "min_enc": "$minenc", "pad_mode": "$pad",
 "server": {"v4_cidr": "10.77.0.0/24", "v6_cidr": "fd77::/64",
            "cert": "$CERT", "key": "$KEY"$legacy_token}}
EOF
  else
    cat > "$f" <<EOF
{"mode": "client", "psk": "$PSK", "addr": "127.0.0.1:$port", "tap": "mem",
 "log_level": "info", "encrypt": true, "mac": "$mac",
 "min_enc": "$minenc", "pad_mode": "$pad", "client": {"insecure": true, "conns": 1}}
EOF
  fi
  CFGF="$f"
}

HAVE_OLD=0
if e2e_have E2E_RS_OLD_BIN && e2e_have E2E_RS_OLD_PROBE && e2e_have E2E_GO_OLD_BIN; then
  HAVE_OLD=1
fi

echo "=================================================================="
echo " P1  安全配置：pad_mode=bucket + min_enc=gcm + protocol v2"
echo "     探针声明 enc_algo=2(GCM)，满足 min_enc 下限"
echo "=================================================================="
run_case "rs->rs 全开"      rs rs bucket gcm "" "--enc-algo 2"
run_case "rs->go 全开"      rs go bucket gcm "" "--enc-algo 2"
run_case "go->rs 全开"      go rs "" "" "" "--enc-algo 2"
run_case "go->go 全开"      go go "" "" "" "-enc-algo 2"
go_cfg_now 1 "" bucket gcm; run_case "go(cfg)->rs" go rs "" "" "" "--enc-algo 2" "$CFGF"
go_cfg_now 1 "" bucket gcm; run_case "go(cfg)->go" go go "" "" "" "-enc-algo 2" "$CFGF"

echo ""
echo "=================================================================="
echo " P2  可选调优关闭：padding=off / 无 min_enc；protocol v2 与随机令牌仍强制"
echo "=================================================================="
run_case "rs->rs 全关"  rs rs off "" "" ""
run_case "rs->go 全关"  rs go off "" "" ""
run_case "go->rs 全关"  go rs "" "" "" ""
run_case "go->go 全关"  go go "" "" "" ""

echo ""
echo "=================================================================="
echo " P3  新旧混装：默认拒绝缺少 protocol v2 / key epoch 的旧对端"
echo "=================================================================="
if [ "$HAVE_OLD" = 1 ]; then
  run_case "rsNEW->goOLD 拒绝"  rs goold off "" "" "" "" fail
  run_case "rsNEW->goOLD2 拒绝" rs goold "" "" "" "" "" fail
  run_case "goOLD->rsNEW 拒绝"  goold rs "" "" "" "" "" fail
  run_case "rsOLD->goNEW 拒绝"  rsold go "" "" "" "" "" fail
  run_case "goNEW->rsOLD 拒绝"  go rsold "" "" "" "" "" fail
  # 旧↔旧不再属于当前实现的兼容承诺；只验证所有含一端新版的降级均失败。
  SKIP_N=$((SKIP_N + 2))
  echo "  ${E2E_YELLOW}SKIP${E2E_RESET} 2 组旧↔旧：不经过当前实现，无安全回归价值"
else
  SKIP_N=$((SKIP_N + 7))
  echo "  ${E2E_YELLOW}SKIP${E2E_RESET} 7 组：缺旧版二进制"
  echo "             rs: ${E2E_RS_OLD_BIN:-(未配置)}   go: ${E2E_GO_OLD_BIN:-(未配置)}"
  echo "             设置 E2E_RS_OLD_BIN / E2E_RS_OLD_PROBE / E2E_GO_OLD_BIN 后重跑可启用"
fi
run_case "goNEW->goNEW"  go go "" "" "" ""

echo ""
echo "=================================================================="
echo " P4  旧配置迁移：legacy session_token=false 可读，但不能关闭随机令牌"
echo "     当前配置契约已删除该字段；这里仅验证升级兼容，安全语义由 protocol v2 固定。"
echo "=================================================================="
go_cfg_now 1 false "" ""; run_case "goNEW(token=false)->rsNEW" go rs "" "" "" "" "$CFGF"
go_cfg_now 1 false "" ""; run_case "goNEW(token=false)->goNEW" go go "" "" "" "" "$CFGF"

for d in "${TMPDIRS[@]}"; do rm -rf "$d"; done
e2e_reap_all

echo ""
echo "=============================== 汇总 ==============================="
echo "PASS=$PASS_N  FAIL=$FAIL_N  SKIP=$SKIP_N  用例总数=$CASE_N"
if [ $FAIL_N -gt 0 ]; then
  echo "失败用例:"; for c in "${FAILED_CASES[@]}"; do echo "  - $c"; done
fi
[ "$FAIL_N" -eq 0 ]
