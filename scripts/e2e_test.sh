#!/usr/bin/env bash
# e2e_test.sh — 跨语言 e2e 的唯一入口。
#
# 跑四个套件：
#   accept  总验收矩阵（P1 全开 / P2 全关 / P3 新旧混装 / P4 opt-in 代价）
#   tok     session_token：同 MAC 两台真实客户端互踢，验证接管被拒
#   pad     pad_mode：off / legacy / bucket 三档 + 非法值
#   minenc  min_enc："" / ctr / legacy / gcm 下限，含未知算法 ID 回归
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
#   PORT_BASE_ACCEPT / _TOK / _PAD / _MINENC   各套件端口基址
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
need E2E_GO_PROBE "$E2E_GO_PROBE" "先构建：go build -C interop -o probe ."
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

# --- 各套件的用例矩阵（原来是在终端里手工敲的 for 循环，这里固化）--------

suite_accept() {
  PORT_BASE="$PORT_BASE_ACCEPT" bash "$HERE/e2e_accept.sh"
}

suite_tok() {
  # 4 组 reject（服务端开启 token，第二台必须被拒）+ 2 组 takeover（对照）
  local -a jobs=(
    "rs rs reject" "rs go reject" "go rs reject" "go go reject"
    "rs rs takeover" "go go takeover"
  )
  local i=0 s c e fails=0
  echo "  session_token：4 组 reject + 2 组 takeover 对照"
  for spec in "${jobs[@]}"; do
    set -- $spec; s="$1"; c="$2"; e="$3"
    SRV="$s" CLI="$c" EXPECT="$e" PORT="$((PORT_BASE_TOK + i * 10))" \
      WEB_BASE="$((9500 + i * 2))" LABEL="tok_${s}->${c}_${e}" \
      bash "$HERE/e2e_tok.sh" || fails=$((fails + 1))
    i=$((i + 1))
  done
  return $((fails > 0 ? 1 : 0))
}

suite_pad() {
  local -a pads=(off legacy bucket bogus)
  local i=0 p s c fails=0
  echo "  pad_mode：4 个取值 × 2 服务端 × 2 客户端 = 16 组（bogus 走配置校验）"
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
  # 14 个组合 × 2 个服务端 = 28 组，再加 2 组 Go 探针交叉 = 30 组。
  # encalgo=3 是两端都不认识的算法 ID：服务端必须按"精确比较"处理，
  # 不得因为 3 >= 2 就当成满足 gcm 下限（Go 侧历史上正是这么错的）。
  local -a combos=(
    ""            0  accept
    ""            2  accept
    ctr           0  accept
    ctr           2  accept
    legacy        0  accept
    legacy        2  accept
    gcm           2  accept
    gcm           0  reject
    gcm           3  reject      # 未知算法不算 GCM → 必拒（真正的 >= bug 回归锁）
    ctr           3  accept      # 未知算法回落 CTR 档，ctr 下限本就该放行
    legacy        3  accept      # 同上；legacy 与 ctr 是同一档下限
    gcm           2  configerr   # ENCRYPT=0
    ctr           2  configerr   # ENCRYPT=0
    bogus         2  configerr
  )
  local i=0 n=0 fails=0 m en mo s port enc
  echo "  min_enc：14 个组合 × 2 个服务端 + 2 组 Go 探针交叉 = 30 组"
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
  # Go 探针交叉：确认判据在服务端，探针语言不影响结果
  n=28
  for spec in "gcm 2 accept" "gcm 0 reject"; do
    set -- $spec; m="$1"; en="$2"; mo="$3"
    SRV=rs PROBE=go MODE="$mo" MINENC="$m" ENCALGO="$en" ENCRYPT=1 \
      PORT="$((PORT_BASE_MINENC + n * 10))" LABEL="minenc_go-probe_${m}_${en}_${mo}" \
      bash "$HERE/e2e_minenc.sh" || fails=$((fails + 1))
    n=$((n + 1))
  done
  return $((fails > 0 ? 1 : 0))
}

declare -A SUITE_FN=( [accept]=suite_accept [tok]=suite_tok [pad]=suite_pad [minenc]=suite_minenc )

SELECTED=("$@")
[ ${#SELECTED[@]} -eq 0 ] && SELECTED=(accept tok pad minenc)

echo "e2e_test.sh — 跨语言 e2e（mem TAP，无需 CAP_NET_ADMIN）"
echo "  RS_BIN   $E2E_RS_BIN"
echo "  GO_BIN   $E2E_GO_BIN"
echo "  RS_PROBE $E2E_RS_PROBE"
echo "  GO_PROBE $E2E_GO_PROBE"
if e2e_have E2E_RS_OLD_BIN && e2e_have E2E_RS_OLD_PROBE && e2e_have E2E_GO_OLD_BIN; then
  echo "  OLD      $E2E_RS_OLD_BIN / $E2E_GO_OLD_BIN"
else
  echo "  OLD      (缺旧版二进制 → accept 的 P3/P4 混装用例会跳过并计数)"
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
