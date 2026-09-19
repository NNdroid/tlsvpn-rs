#!/usr/bin/env bash
# e2e_accept.sh — 总验收矩阵：档 A/B/C/D 落地后的跨语言互测。
#
#   P1 三项全开   —— pad_mode=bucket + session_token + min_enc=gcm
#   P2 三项全关   —— 回退路径，回到特性引入前的行为
#   P3 新旧混装   —— rs-new<->go-old / rs-old<->go-new（特性关闭 = fallback 模式）
#   P4 opt-in 代价 —— 新特性字段对旧对端的影响
#
# 用自包含探针（--tap mem），协议级验证，不需要 CAP_NET_ADMIN。
# 判据：探针退出 0 + 服务端日志无错误标记（解密失败/panic/校验失败/拒绝连接）。
#
# P3 和 P4 依赖特性引入前的旧二进制（E2E_RS_OLD_* / E2E_GO_OLD_BIN）。它们
# 不在正常构建产物里，缺了就跳过那些用例并打印跳过了几组，而不是整体失败。
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

# run_case LABEL SRV_IMPL CLI_IMPL SRV_EXTRA CLI_EXTRA [SRV_CFG] [EXPECT]
# SRV/CLI 取值：rs | go | rsold | goold
# SRV_CFG 非空 → 服务端用 Go 配置文件启动（-c 覆盖所有 flag）
# EXPECT=pass(默认)|fail → fail 表示预期不互通（用于 opt-in 破坏旧对端）
run_case() {
  local label="$1" srv="$2" cli="$3"
  local srv_extra="$4" cli_extra="$5" srv_cfg="${6:-}" expect="${7:-pass}"
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
  if [ -n "$srv_cfg" ]; then
    set -- "$gobin" -c "$srv_cfg"
  elif [ "$sk" = rs ]; then
    set -- "$rsbin" --mode server --addr "127.0.0.1:$port" --psk "$PSK" --encrypt \
      --cert "$CERT" --key "$KEY" --v4cidr 10.77.0.0/24 --v6cidr fd77::/64 \
      --tap mem --loglevel info
    for w in $srv_extra; do set -- "$@" "$w"; done
  else
    set -- "$gobin" -mode server -addr "127.0.0.1:$port" -psk "$PSK" -encrypt \
      -cert "$CERT" -key "$KEY" -v4cidr 10.77.0.0/24 -v6cidr fd77::/64 \
      -tap mem -loglevel info
    for w in $srv_extra; do set -- "$@" "$w"; done
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
  errs="$(e2e_strip "$slog" | grep -E 'ERROR|panic|panicked|GCM.*(fail|FAIL)|decrypt.*fail|解密失败|校验失败|拒绝连接' | tail -5 || true)"
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
    e2e_strip "$slog" | grep -Ei 'EncAlgo|上线|session|token|拒绝|min_enc|padding|Confusion|bucket|legacy' | tail -6
  fi
}

# go_cfg_now IS_SERVER TOK PAD MINENC
# 为「下一个」将要执行的 run_case 生成配置文件。run_case 会先把 CASE_N 加 1
# 再取端口，所以这里针对 CASE_N+1 生成。
CFGF=""
go_cfg_now() {
  local is_srv="$1" tok="$2" pad="$3" minenc="$4"
  local d f port mac
  d="$(mktemp -d)"; TMPDIRS+=("$d")
  f="$(e2e_winpath "$d/srv.json")"
  port="$(case_port $((CASE_N + 1)))"
  mac="$(case_mac $((CASE_N + 1)))"
  if [ "$is_srv" = 1 ]; then
    cat > "$f" <<EOF
{"mode": "server", "psk": "$PSK", "addr": "127.0.0.1:$port", "tap": "mem",
 "log_level": "info", "encrypt": true, "min_enc": "$minenc", "pad_mode": "$pad",
 "server": {"v4_cidr": "10.77.0.0/24", "v6_cidr": "fd77::/64",
            "cert": "$CERT", "key": "$KEY", "session_token": $tok}}
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
echo " P1  三项全开：pad_mode=bucket + session_token + min_enc=gcm"
echo "     探针声明 enc_algo=3(GCM-v2)，满足 min_enc 下限并走完独立密钥标签路径"
echo "=================================================================="
run_case "rs->rs 全开"      rs rs "--pad-mode bucket --min-enc gcm --session-token" "--enc-algo 3"
run_case "rs->go 全开"      rs go "--pad-mode bucket --min-enc gcm --session-token" "--enc-algo 3"
run_case "go->rs 全开"      go rs "" "--enc-algo 3"
run_case "go->go 全开"      go go "" "-enc-algo 3"
go_cfg_now 1 true bucket gcm; run_case "go(tok,cfg)->rs" go rs "" "--enc-algo 3" "$CFGF"
go_cfg_now 1 true bucket gcm; run_case "go(tok,cfg)->go" go go "" "-enc-algo 3" "$CFGF"

echo ""
echo "=================================================================="
echo " P2  三项全关（回退路径）：pad_mode=legacy / 空，无 min_enc，无 session_token"
echo "=================================================================="
run_case "rs->rs 全关"  rs rs "--pad-mode legacy" ""
run_case "rs->go 全关"  rs go "--pad-mode legacy" ""
run_case "go->rs 全关"  go rs "" ""
run_case "go->go 全关"  go go "" ""

echo ""
echo "=================================================================="
echo " P3  新旧混装（fallback 模式 = 特性全关）"
echo "=================================================================="
if [ "$HAVE_OLD" = 1 ]; then
  run_case "rsNEW->goOLD"  rs goold "--pad-mode legacy" ""
  run_case "rsNEW->goOLD2" rs goold "" ""
  run_case "goOLD->rsNEW"  goold rs "" ""
  run_case "rsOLD->goNEW"  rsold go "" ""
  run_case "goNEW->rsOLD"  go rsold "" ""
  run_case "rsOLD->goOLD"  rsold goold "" ""
  run_case "goOLD->rsOLD"  goold rsold "" ""
else
  SKIP_N=$((SKIP_N + 7))
  echo "  ${E2E_YELLOW}SKIP${E2E_RESET} 7 组：缺旧版二进制"
  echo "             rs: ${E2E_RS_OLD_BIN:-(未配置)}   go: ${E2E_GO_OLD_BIN:-(未配置)}"
  echo "             设置 E2E_RS_OLD_BIN / E2E_RS_OLD_PROBE / E2E_GO_OLD_BIN 后重跑可启用"
fi
run_case "goNEW->goNEW"  go go "" ""

echo ""
echo "=================================================================="
echo " P4  session_token 开启后的兼容性"
echo "     HandshakeResp 没有 deny_unknown_fields（只有关配置文件结构体才有），"
echo "     所以「首次接入」对旧客户端无害：多出的 session_token 字段被直接忽略。"
echo "     真实代价只出现在重连路径 —— 旧客户端拿不到令牌，重连会被拒。"
echo "     那一半由 e2e_tok.sh 用真实客户端覆盖（本矩阵的探针不做重连）。"
echo "=================================================================="
if [ "$HAVE_OLD" = 1 ]; then
  run_case "rsNEW(tok)->rsOLD 首次接入" rs rsold "--session-token" ""
else
  SKIP_N=$((SKIP_N + 1))
  echo "  ${E2E_YELLOW}SKIP${E2E_RESET} 1 组：rsNEW(tok)->rsOLD 缺旧版 Rust 二进制"
fi
if [ "$HAVE_OLD" = 1 ]; then
  go_cfg_now 1 true "" ""; run_case "goNEW(tok)->rsOLD 首次接入" go rsold "" "" "$CFGF"
else
  SKIP_N=$((SKIP_N + 1))
  echo "  ${E2E_YELLOW}SKIP${E2E_RESET} 1 组：goNEW(tok)->rsOLD 缺旧版 Rust 探针"
fi
go_cfg_now 1 true "" ""; run_case "goNEW(tok)->go 首次接入"  go go "" "" "$CFGF"

for d in "${TMPDIRS[@]}"; do rm -rf "$d"; done
e2e_reap_all

echo ""
echo "=============================== 汇总 ==============================="
echo "PASS=$PASS_N  FAIL=$FAIL_N  SKIP=$SKIP_N  用例总数=$CASE_N"
if [ $FAIL_N -gt 0 ]; then
  echo "失败用例:"; for c in "${FAILED_CASES[@]}"; do echo "  - $c"; done
fi
[ "$FAIL_N" -eq 0 ]
