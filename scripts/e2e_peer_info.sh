#!/usr/bin/env bash
# Cross-language peer_info handshake + logical-session/Web API regression.
# Uses real tlsvpn server/client binaries over the existing in-memory TAP mode.
# Do not enable `set -e`: shared e2e cleanup helpers intentionally return nonzero
# when there is nothing to clean (for example fuser on an unused port).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/e2e_lib.sh"

for spec in "E2E_RS_BIN:$E2E_RS_BIN" "E2E_GO_BIN:$E2E_GO_BIN"; do
  name="${spec%%:*}"; path="${spec#*:}"
  e2e_require "$name" "$path" "build both implementations before running peer-info e2e" || exit 2
done
command -v python3 >/dev/null 2>&1 || { echo "peer-info e2e requires python3" >&2; exit 2; }
e2e_ensure_cert || { echo "peer-info e2e requires cert/key or openssl" >&2; exit 2; }

TMP="$(mktemp -d)"
WEB_AUTH='peercheck:S3curePeerInfo-2026'
trap 'e2e_reap_all; rm -rf "$TMP"' EXIT

bin_for() {
  if [ "$1" = go ]; then printf '%s' "$E2E_GO_BIN"; else printf '%s' "$E2E_RS_BIN"; fi
}

run_case() {
  local srv="$1" cli="$2" port="$3" srv_web="$4" cli_web="$5" mac="$6"
  local srv_bin cli_bin case_dir srv_log cli_log
  srv_bin="$(bin_for "$srv")"
  cli_bin="$(bin_for "$cli")"
  case_dir="$TMP/${srv}_${cli}"
  mkdir -p "$case_dir"
  srv_log="$case_dir/server.log"
  cli_log="$case_dir/client.log"

  e2e_kill_port "$port"
  e2e_kill_port "$srv_web"
  e2e_kill_port "$cli_web"

  e2e_config "$case_dir/server.json" server "127.0.0.1:$port" \
    "\"psk\": \"$E2E_PSK\"" \
    '"encrypt": true' \
    '"log_level": "info"' \
    "\"web\": {\"addr\": \"127.0.0.1:$srv_web\", \"auth\": \"$WEB_AUTH\"}" \
    "\"server\": {\"cert\": \"$E2E_CERT\", \"key\": \"$E2E_KEY\", \"v4_cidr\": \"10.89.0.0/24\", \"v6_cidr\": \"fd89::/64\"}"
  "$srv_bin" -c "$(e2e_winpath "$case_dir/server.json")" >"$srv_log" 2>&1 &
  e2e_wait_port 127.0.0.1 "$port" 20 || { echo "FAIL $srv server did not start"; cat "$srv_log"; return 1; }
  e2e_wait_port 127.0.0.1 "$srv_web" 20 || { echo "FAIL $srv server WebUI did not start"; cat "$srv_log"; return 1; }

  e2e_config "$case_dir/client.json" client "127.0.0.1:$port" \
    "\"psk\": \"$E2E_PSK\"" \
    '"encrypt": true' \
    '"log_level": "info"' \
    "\"mac\": \"$mac\"" \
    "\"web\": {\"addr\": \"127.0.0.1:$cli_web\", \"auth\": \"$WEB_AUTH\"}" \
    '"client": {"insecure": true, "conns": 1}'
  "$cli_bin" -c "$(e2e_winpath "$case_dir/client.json")" >"$cli_log" 2>&1 &
  e2e_wait_port 127.0.0.1 "$cli_web" 20 || { echo "FAIL $cli client WebUI did not start"; cat "$cli_log"; return 1; }

  if ! python3 - "$srv" "$cli" "$srv_web" "$cli_web" "$WEB_AUTH" <<'PY'
import base64, http.cookiejar, json, sys, time, urllib.request
srv, cli, srv_port, cli_port, auth = sys.argv[1:]
username, password = auth.split(":", 1)
basic_header = "Basic " + base64.b64encode(auth.encode()).decode()
openers = {}
wire_impl = {"go": "go", "rs": "rust"}

def opener_for(port, impl):
    key = (port, impl)
    if key in openers:
        return openers[key]
    if impl == "go":
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        body = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/login",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req, timeout=2) as r:
            if r.status != 200:
                raise RuntimeError(f"Go dashboard login status={r.status}")
    else:
        class BasicHandler(urllib.request.BaseHandler):
            def http_request(self, req):
                req.add_unredirected_header("Authorization", basic_header)
                return req
            https_request = http_request
        opener = urllib.request.build_opener(BasicHandler())
    openers[key] = opener
    return opener

def get(port, impl):
    opener = opener_for(port, impl)
    with opener.open(f"http://127.0.0.1:{port}/api/stats", timeout=2) as r:
        return json.load(r)

def validate(info, expected, where):
    if not isinstance(info, dict):
        raise AssertionError(f"{where}: missing peer metadata: {info!r}")
    if info.get("implementation") != expected:
        raise AssertionError(f"{where}: implementation={info.get('implementation')!r}, want {expected!r}")
    for key in ("hostname", "os", "arch", "version"):
        val = info.get(key)
        if not isinstance(val, str) or not val.strip():
            raise AssertionError(f"{where}: missing {key}: {info!r}")

deadline = time.time() + 20
last = None
last_ss = last_cs = None
while time.time() < deadline:
    try:
        last_ss = get(srv_port, srv)
        last_cs = get(cli_port, cli)
        peers = [c.get("peer_info") for c in (last_ss.get("clients") or {}).values() if isinstance(c, dict)]
        peer = next((p for p in peers if isinstance(p, dict)), None)
        validate(peer, wire_impl[cli], "server stats -> client")
        validate(last_cs.get("peer"), wire_impl[srv], "client stats -> server")
        print("PASS", f"{srv}_server<-{cli}_client",
              "client=", json.dumps(peer, ensure_ascii=False, sort_keys=True),
              "server=", json.dumps(last_cs["peer"], ensure_ascii=False, sort_keys=True))
        break
    except Exception as exc:
        last = exc
        time.sleep(0.5)
else:
    print(f"peer metadata did not converge: {last!r}", file=sys.stderr)
    print("server stats:", json.dumps(last_ss, ensure_ascii=False, sort_keys=True) if last_ss else "<unavailable>", file=sys.stderr)
    print("client stats:", json.dumps(last_cs, ensure_ascii=False, sort_keys=True) if last_cs else "<unavailable>", file=sys.stderr)
    raise SystemExit(1)
PY
  then
    echo "FAIL peer metadata $srv server <- $cli client"
    echo "----- server tail -----"
    tail -40 "$srv_log" || true
    echo "----- client tail -----"
    tail -40 "$cli_log" || true
    return 1
  fi

  e2e_kill_port "$cli_web"
  e2e_kill_port "$srv_web"
  e2e_kill_port "$port"
  return 0
}

# Exercise both cross-language directions. Values differ by language on purpose
# (Go reports amd64, Rust reports x86_64); the contract is semantic, not string-equal.
fails=0
run_case rs go 21300 21301 21302 aa:bb:cc:dd:89:01 || fails=$((fails + 1))
run_case go rs 21310 21311 21312 aa:bb:cc:dd:89:02 || fails=$((fails + 1))

if [ "$fails" -ne 0 ]; then
  echo "peer-info cross-language e2e: $fails direction(s) failed"
  exit 1
fi
echo "peer-info cross-language e2e: all directions passed"
