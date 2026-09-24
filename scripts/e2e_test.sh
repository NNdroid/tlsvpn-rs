#!/usr/bin/env bash
# e2e_test.sh — 跨语言 e2e 的唯一入口。
#
# 跑五个套件：
#   accept  总验收矩阵（v2 安全配置 / 可选调优 / 旧版拒绝 / 兼容字段）
#   tok     protocol v2：同 MAC 两台真实客户端，验证跨实例接管被拒
#   pad     pad_mode：off / bucket 两档 + 非法值
#   minenc  min_enc："" / gcm 下限，含未知算法 ID 回归
#   cfg     配置维度：v4/v6 网段 / client.conns / web.auth / web.cert+web.key
#           (HTTPS) / web.bind=tunnel / log_level 互通，外加 badlog / badauth /
#           badv4 / badv6 / badmac / badbind / badwebtls 七个配置校验
#
# 全部用 --tap mem 的自包含探针，不需要 CAP_NET_ADMIN，托管 CI 上也能真跑
# （net_perf_test.sh 那套需要真实 TAP，只能在有权限的 runner 上执行）。
#
# Usage:  scripts/e2e_test.sh [suite ...]      不带参数跑全部
#
# Env（全部可选，见 scripts/e2e_lib.sh）：
#   E2E_RS_BIN / E2E_GO_BIN / E2E_RS_PROBE / E2E_GO_PROBE
#   E2E_RS_OLD_BIN / E2E_RS_OLD_PROBE / E2E_GO_OLD_BIN   特性引入前的构建
#   E2E_GO_DIR / E2E_CERT / E2E_KEY / E2E_PSK
#   PORT_BASE_ACCEPT / _TOK / _PAD / _MINENC / _CFG   各套件端口基址
#   KEEP_TMP=1   保留套件日志目录（默认退出时清理）
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

# --- 依赖检查：缺什么就明确说怎么补，而不是跑到一半报错 -----------------
MISSING=""
need() {
  if [ ! -e "$2" ]; then
    MISSING="${MISSING}
  $1 = $2
     → $3"
  fi
}
need E2E_RS_BIN   "$E2E_RS_BIN"   "先构建：scripts/build.sh native"
need E2E_GO_BIN   "$E2E_GO_BIN"   "先构建：(cd <go 仓库> && scripts/build.sh)"
need E2E_RS_PROBE "$E2E_RS_PROBE" "先构建：cargo build --examples"
need E2E_GO_PROBE "$E2E_GO_PROBE" "先构建：(cd <go 仓库> && go build -C interop -o probe .)"
if [ -n "$MISSING" ]; then
  echo "e2e: 缺少依赖，无法运行："
  echo "$MISSING"
  exit 2
fi

SUITE_TOTAL=0
SUITE_FAIL=0
FAILED_SUITES=()

# 兜底清扫放 EXIT trap：任何套件泄漏的客户端（Web 面板 bind 失败时不监听任何
# 端口，按端口清不掉）都会占住后续套件的面板端口。KEEP_TMP=1 时保留日志目录。
LOGDIR="$(mktemp -d)"
trap 'e2e_reap_all; [ -n "${KEEP_TMP:-}" ] || rm -rf "$LOGDIR"' EXIT

run_suite() {
  local name="$1"; shift
  local logfile=""
  [ -n "$LOGDIR" ] && logfile="$LOGDIR/${name}.log"
  echo ""
  echo "=================================================================="
  echo " $name"
  echo "=================================================================="
  local start rc
  start=$(date +%s)
  if [ -n "$logfile" ]; then
    "$@" 2>&1 | tee "$logfile"
    rc=${PIPESTATUS[0]}
  else
    "$@"
    rc=$?
  fi
  if [ "$rc" -eq 0 ]; then
    echo "  → $name 通过"
  else
    SUITE_FAIL=$((SUITE_FAIL + 1))
    FAILED_SUITES+=("$name")
    echo "  ${E2E_RED}→ $name 有失败${E2E_RESET}"
  fi
  SUITE_TOTAL=$((SUITE_TOTAL + 1))
  local secs=$(( $(date +%s) - start ))
  if [ -n "$logfile" ]; then
    echo "  （用时 ${secs}s，日志 $logfile）"
  else
    echo "  （用时 ${secs}s）"
  fi
}

PORT_BASE_ACCEPT="${PORT_BASE_ACCEPT:-18200}"
PORT_BASE_TOK="${PORT_BASE_TOK:-18500}"
PORT_BASE_PAD="${PORT_BASE_PAD:-18700}"
PORT_BASE_MINENC="${PORT_BASE_MINENC:-19200}"
PORT_BASE_CFG="${PORT_BASE_CFG:-20000}"

# --- 各套件的用例矩阵（原来是在终端里手工敲的 for 循环，这里固化）--------

suite_accept() {
  PORT_BASE="$PORT_BASE_ACCEPT" bash "$HERE/e2e_accept.sh"
}

suite_tok() {
  # Session token 是 protocol v2 固定能力；四种跨语言组合都必须拒绝同 MAC 的新实例劫持。
  local -a jobs=("rs rs" "rs go" "go rs" "go go")
  local i=0 s c fails=0
  echo "  protocol v2：4 组跨语言固定 session-token 接管拒绝"
  for spec in "${jobs[@]}"; do
    set -- $spec; s="$1"; c="$2"
    SRV="$s" CLI="$c" PORT="$((PORT_BASE_TOK + i * 10))" \
      WEB_BASE="$((9500 + i * 2))" LABEL="tok_${s}->${c}" \
      bash "$HERE/e2e_tok.sh" || fails=$((fails + 1))
    i=$((i + 1))
  done
  return $((fails > 0 ? 1 : 0))
}

suite_pad() {
  local -a pads=(off bucket bogus)
  local i=0 p s c fails=0
  echo "  pad_mode：3 个取值 × 2 服务端 × 2 客户端 = 12 组（bogus 走配置校验）"
  for p in "${pads[@]}"; do
    for s in rs go; do
      for c in rs go; do
        SRV="$s" CLI="$c" PAD="$p" PORT="$((PORT_BASE_PAD + i * 10))" \
          WEB_BASE="$((9502 + i))" LABEL="pad_${s}->${c}_${p}" \
          bash "$HERE/e2e_pad.sh" || fails=$((fails + 1))
        i=$((i + 1))
      done
    done
  done
  return $((fails > 0 ? 1 : 0))
}

suite_minenc() {
  # 8 个组合 × 2 个服务端 = 16 组，再加 3 组 Go 探针交叉 = 19 组。
  # 内层只剩 GCM（2），所以探针声明的合格能力只有 2；9 是两端都不认识的算法
  # ID，用来守住"按数值大小推断能力"这类回归——服务端必须按精确比较判定强度。
  # min_enc 留空已经不是"不设下限"：两端都在 encrypt=true 且 min_enc 为空时把它
  # 默认成 gcm（Rust src/main.rs、Go config.go），所以 "" + algo≠2 一律拒连；
  # 想表达"不设下限"得显式写 "any"。
  local -a combos=(
    ""            2  accept
    ""            0  reject
    ""            9  reject
    gcm           2  accept
    gcm           0  reject      # 声明不了 GCM → 不满足下限
    gcm           9  reject      # 真未知算法（>= bug 回归锁）
    gcm           2  configerr   # ENCRYPT=0
    bogus         2  configerr
  )
  local i=0 n=0 fails=0 m en mo s port enc
  echo "  min_enc：8 个组合 × 2 个服务端 + 3 组 Go 探针交叉 = 19 组"
  for s in rs go; do
    for ((i = 0; i < ${#combos[@]}; i += 3)); do
      m="${combos[i]}"; en="${combos[i+1]}"; mo="${combos[i+2]}"
      port=$((PORT_BASE_MINENC + n * 10))
      # configerr 组要么关掉加密（min_enc 与 encrypt=false 冲突），要么喂非法值
      if [ "$mo" = configerr ] && [ "$m" != bogus ]; then enc=0; else enc=1; fi
      SRV="$s" PROBE=rs MODE="$mo" MINENC="$m" ENCALGO="$en" ENCRYPT="$enc" \
        PORT="$port" LABEL="minenc_${s}_${m}_${en}_${mo}" \
        bash "$HERE/e2e_minenc.sh" || fails=$((fails + 1))
      n=$((n + 1))
    done
  done
  # Go 探针交叉：确认判据在服务端，探针语言不影响结果。第三组让 Go 探针
  # 声明两端都不认识的算法 ID，跨语言验证精确比较而不是数值比较。
  n=16
  for spec in "gcm 2 accept" "gcm 0 reject" "gcm 9 reject"; do
    set -- $spec; m="$1"; en="$2"; mo="$3"
    SRV=rs PROBE=go MODE="$mo" MINENC="$m" ENCALGO="$en" ENCRYPT=1 \
      PORT="$((PORT_BASE_MINENC + n * 10))" LABEL="minenc_go-probe_${m}_${en}_${mo}" \
      bash "$HERE/e2e_minenc.sh" || fails=$((fails + 1))
    n=$((n + 1))
  done
  return $((fails > 0 ? 1 : 0))
}

suite_cfg() {
  # 前 6 个是互通类：固定协议、只动配置，断言配置真的生效。跑全 4 种实现组合
  # （rs/rs、rs/go、go/rs、go/go），因为「配置生效」必须跨语言成立。
  # 后 7 个是校验类：进程必须以非零退出并给出对应错误，两种实现都覆盖。
  local -a interop=(cidr multi webauth webtls webtunnel logquiet)
  local -a reject=(badlog badauth badv4 badv6)
  local i=0 s c fails=0 case
  echo "  互通：6 个配置维度 × 4 种实现组合 = 24 组"
  for case in "${interop[@]}"; do
    for s in rs go; do
      for c in rs go; do
        SRV="$s" CLI="$c" CASE="$case" PORT="$((PORT_BASE_CFG + i * 10))" \
          WEB_BASE="$((9700 + i))" LABEL="cfg_${s}->${c}_${case}" \
          bash "$HERE/e2e_cfg.sh" || fails=$((fails + 1))
        i=$((i + 1))
      done
    done
  done
  i=24
  echo "  校验：7 个非法配置 × 2 实现 = 14 组"
  for case in "${reject[@]}"; do
    for s in rs go; do
      SRV="$s" CASE="$case" PORT="$((PORT_BASE_CFG + i * 10))" \
        WEB_BASE="$((9700 + i))" LABEL="cfg_${s}_${case}" \
        bash "$HERE/e2e_cfg.sh" || fails=$((fails + 1))
      i=$((i + 1))
    done
  done
  for case in badmac badbind badwebtls; do
    for s in rs go; do
      SRV="$s" CASE="$case" PORT="$((PORT_BASE_CFG + i * 10))" \
        WEB_BASE="$((9700 + i))" LABEL="cfg_${s}_${case}" \
        bash "$HERE/e2e_cfg.sh" || fails=$((fails + 1))
      i=$((i + 1))
    done
  done
  return $((fails > 0 ? 1 : 0))
}

declare -A SUITE_FN=( [accept]=suite_accept [tok]=suite_tok [pad]=suite_pad [minenc]=suite_minenc [cfg]=suite_cfg )

SELECTED=("$@")
[ ${#SELECTED[@]} -eq 0 ] && SELECTED=(accept tok pad minenc cfg)

echo "e2e_test.sh — 跨语言 e2e（mem TAP，无需 CAP_NET_ADMIN）"
echo "  RS_BIN   $E2E_RS_BIN"
echo "  GO_BIN   $E2E_GO_BIN"
echo "  RS_PROBE $E2E_RS_PROBE"
echo "  GO_PROBE $E2E_GO_PROBE"
if e2e_have E2E_RS_OLD_BIN && e2e_have E2E_RS_OLD_PROBE && e2e_have E2E_GO_OLD_BIN; then
  echo "  OLD      $E2E_RS_OLD_BIN / $E2E_GO_OLD_BIN"
else
  echo "  OLD      (缺旧版二进制 → accept 的 P3 降级拒绝用例会跳过并计数)"
fi
echo "  套件     ${SELECTED[*]}"

TOTAL_START=$(date +%s)
for s in "${SELECTED[@]}"; do
  if [ -z "${SUITE_FN[$s]+x}" ]; then
    echo "${E2E_RED}未知套件: $s${E2E_RESET}（可用：${!SUITE_FN[*]}）" >&2
    exit 2
  fi
  run_suite "$s" "${SUITE_FN[$s]}"
done

echo ""
echo "=============================== 汇总 ==============================="
echo "套件：跑 $SUITE_TOTAL 个，失败 $SUITE_FAIL 个"
[ ${#SELECTED[@]} -gt 1 ] && echo "总用时 $(( $(date +%s) - TOTAL_START ))s"
if [ "$SUITE_FAIL" -gt 0 ]; then
  echo "失败套件：${FAILED_SUITES[*]}"
  exit 1
fi
echo "全部通过"
exit 0
