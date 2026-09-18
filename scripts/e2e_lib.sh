#!/usr/bin/env bash
# e2e_lib.sh — shared helpers for the cross-language e2e suites in scripts/.
#
# Source it, do not execute it:
#   source "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"
#
# Every location is derived from this file and overridable via env, so a suite
# can run against another checkout, a pre-feature build, or a cross-compiled
# artifact:
#   E2E_RS_BIN / E2E_GO_BIN         server+client binaries
#   E2E_RS_PROBE / E2E_GO_PROBE     protocol-level probes (in-memory TAP)
#   E2E_RS_OLD_BIN / E2E_RS_OLD_PROBE / E2E_GO_OLD_BIN   pre-feature builds
#   E2E_GO_DIR                      Go implementation checkout (../tlsvpn)
#   E2E_CERT / E2E_KEY              TLS cert pair (repo root)
#   E2E_PSK                         shared secret
#
# The "old" builds exist only to exercise the mixed-version phases. A fresh
# runner never builds them, so every suite gates those cases on their presence
# and reports how many it skipped rather than failing.
#
# This file deliberately sets neither -e nor -u: the suites own their strictness
# and the helpers below return 1 from guards instead of dying.

export MSYS_NO_PATHCONV=1   # keep bash from rewriting drive paths to POSIX form

E2E_OS=linux
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) E2E_OS=windows ;;
esac
E2E_EXE=""
[ "$E2E_OS" = windows ] && E2E_EXE=".exe"

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_REPO="$(cd "$E2E_DIR/.." && pwd)"
E2E_GO_DIR="${E2E_GO_DIR:-$(cd "$E2E_REPO/.." 2>/dev/null && pwd)/tlsvpn}"

# Windows binaries reject /e/GolandProjects/... paths — hand them drive form.
# Identity function on Linux. Anything a child process receives as an argument
# or embeds in a config file must go through this.
e2e_winpath() {
  if [ "$E2E_OS" = windows ] && command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

# Same conversion but with forward slashes, which Windows APIs accept and which
# stay readable when the path lands inside a JSON config file.
e2e_drvpath() {
  if [ "$E2E_OS" = windows ] && command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s' "$1"
  fi
}

# Binaries are executed by bash, which accepts POSIX paths on Windows too —
# only arguments handed to a Windows process need e2e_winpath.
E2E_RS_BIN="${E2E_RS_BIN:-$E2E_REPO/target/debug/tlsvpn$E2E_EXE}"
E2E_GO_BIN="${E2E_GO_BIN:-$E2E_GO_DIR/bin/tlsvpn$E2E_EXE}"
E2E_RS_PROBE="${E2E_RS_PROBE:-$E2E_REPO/target/debug/examples/interop_client$E2E_EXE}"
E2E_GO_PROBE="${E2E_GO_PROBE:-$E2E_REPO/interop/probe$E2E_EXE}"

E2E_RS_OLD_BIN="${E2E_RS_OLD_BIN:-}"
E2E_RS_OLD_PROBE="${E2E_RS_OLD_PROBE:-}"
E2E_GO_OLD_BIN="${E2E_GO_OLD_BIN:-}"

# e2e_cert.pem / e2e_key.pem are gitignored, so a clean checkout has neither —
# the cert is generated on demand below and treated as a derived artifact.
# These DO get converted: they are passed as --cert/--key arguments and also
# embedded as values inside the generated Go config JSON.
E2E_CERT="$(e2e_drvpath "${E2E_CERT:-$E2E_REPO/e2e_cert.pem}")"
E2E_KEY="$(e2e_drvpath "${E2E_KEY:-$E2E_REPO/e2e_key.pem}")"

E2E_PSK="${E2E_PSK:-e2e_secret}"


# True when the env var named by $1 is set and the file it points to exists.
# Lets a suite opt out of a phase instead of failing on a missing old build.
e2e_have() {
  local v="${!1:-}"
  [ -n "$v" ] && [ -e "$v" ]
}

# Fail fast on a prerequisite that is genuinely required, with a build hint.
e2e_require() {
  local name="$1" path="$2" hint="$3"
  if [ -z "$path" ]; then
    echo "  $E2E_RED missing$E2E_RESET $name is not configured" >&2
    return 1
  fi
  if [ ! -e "$path" ]; then
    echo "  $E2E_RED missing$E2E_RESET $name = $path" >&2
    [ -n "$hint" ] && echo "             $hint" >&2
    return 1
  fi
  return 0
}

# Reap whatever is still listening on a port.
# On Windows bash's $! is not a usable Windows PID, so port lookup is the only
# reliable way to clean up after a case that died before it could self-terminate.
# 注意 -ExpandProperty OwningProcess 输出的已是裸 PID：再取 $_.ProcessId 会得到
# null，Stop-Process 静默失败（曾因此让全部按端口清理失效，tok 的客户端泄漏进
# pad 的面板端口段）。
e2e_kill_port() {
  local port="$1"
  case "$E2E_OS" in
    windows)
      powershell -NoProfile -Command \
        "Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue }" \
        2>/dev/null
      ;;
    *)
      if command -v fuser >/dev/null 2>&1; then
        fuser -k "$port/tcp" >/dev/null 2>&1
      elif command -v lsof >/dev/null 2>&1; then
        lsof -ti tcp:"$port" 2>/dev/null | xargs -r kill -9
      fi
      ;;
  esac
  sleep 0.3
}

# Remove ANSI colour escapes from a log.
e2e_strip() { sed -e 's/\x1b\[[0-9;]*m//g' "$1"; }

# Last-resort sweep: kill every tlsvpn/probe process left over by a suite.
# Per-case cleanup reaps by port, but a client whose Web panel failed to bind
# listens on nothing and would survive it — and a leaked client from one suite
# occupies the next suite's panel port (CI: tok leaked 9500-9511 into pad).
# Safe on a dedicated runner or dev box; do not run suites concurrently.
e2e_reap_all() {
  case "$E2E_OS" in
    windows)
      powershell -NoProfile -Command \
        "Get-Process | Where-Object {\$_.ProcessName -match 'tlsvpn|probe|interop_client'} | Stop-Process -Force -ErrorAction SilentlyContinue" \
        2>/dev/null
      ;;
    *)
      pkill -f 'tlsvpn|interop_client|/probe' 2>/dev/null || true
      ;;
  esac
}

# Wait for a TCP port to accept, or return 1 after the deadline (default 20s).
e2e_wait_port() {
  local host="$1" port="$2" deadline=$(( $(date +%s) + ${3:-20} ))
  while ! (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 0.3
  done
  exec 3>&- 2>/dev/null || true
}

# A free TCP port in [lo, hi). Returns 1 when the whole range is busy.
e2e_pick_port() {
  local lo="${1:-18200}" hi="${2:-18900}" p
  for ((p = lo; p < hi; p++)); do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
    exec 3>&- 2>/dev/null || true
  done
  echo "  e2e: no free port in [$lo,$hi)" >&2
  return 1
}

# Ensure E2E_CERT/E2E_KEY are readable, generating a throwaway self-signed pair
# when they are absent. Sets both vars to the resolved paths — callers use them
# directly, which is safer than parsing "cert key" output when a path has spaces.
e2e_ensure_cert() {
  if [ -r "$E2E_CERT" ] && [ -r "$E2E_KEY" ]; then
    return 0
  fi
  command -v openssl >/dev/null 2>&1 || return 1
  local d; d="$(mktemp -d)" || return 1
  if ! openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
      -keyout "$d/key.pem" -out "$d/cert.pem" -subj "/CN=tlsvpn-e2e" >/dev/null 2>&1; then
    rm -rf "$d"
    return 1
  fi
  E2E_CERT="$d/cert.pem"
  E2E_KEY="$d/key.pem"
  return 0
}

# Colour helpers; suppressed when stdout is not a terminal.
if [ -t 1 ]; then
  E2E_GREEN="\033[32m"; E2E_RED="\033[31m"; E2E_YELLOW="\033[33m"; E2E_RESET="\033[0m"
else
  E2E_GREEN=""; E2E_RED=""; E2E_YELLOW=""; E2E_RESET=""
fi

# e2e_result PASS LABEL DETAIL → prints a verdict line and returns 0/1.
# DETAIL should already carry any leading space.
e2e_result() {
  local pass="$1" label="$2" detail="${3:-}"
  if [ "$pass" = 1 ]; then
    printf '  %sPASS%s  [%s]%s\n' "$E2E_GREEN" "$E2E_RESET" "$label" "$detail"
    return 0
  fi
  printf '  %sFAIL%s      [%s]%s\n' "$E2E_RED" "$E2E_RESET" "$label" "$detail"
  return 1
}
