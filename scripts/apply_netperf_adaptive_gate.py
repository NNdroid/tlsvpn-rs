#!/usr/bin/env python3
import os
from pathlib import Path


def replace_one(path: str, old: str, new: str) -> None:
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"anchor missing in {path}: {old[:120]!r}")
    if s.count(old) != 1:
        raise SystemExit(f"anchor is not unique in {path}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1))

p = "scripts/net_perf_test.sh"
replace_one(p,
'''#   IPERF_MIN_MBPS          throughput assert threshold (default 100)\n#   LIBRESPEED_CLI          path to librespeed-cli (optional)\n''',
'''#   IPERF_MIN_MBPS          throughput assert threshold (default 100)\n#   PERF_CONNS              parallel TLSVPN connections (default 4)\n#   LIBRESPEED_CLI          path to librespeed-cli (optional)\n''')
replace_one(p,
'''IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-100}"\nFLAVOR_SRV="${FLAVOR_SRV:-rs}"\nFLAVOR_CLI="${FLAVOR_CLI:-rs}"\nTAP_SRV="tap_t0"\nTAP_CLI="tap_t1"\n''',
'''IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-100}"\nPERF_CONNS="${PERF_CONNS:-4}"\nFLAVOR_SRV="${FLAVOR_SRV:-rs}"\nFLAVOR_CLI="${FLAVOR_CLI:-rs}"\nTAP_SRV="tap_t0"\nTAP_CLI="tap_t1"\nWEB_ADDR="127.0.0.1:18780"\nWEB_AUTH="perf:tlsvpn"\n\ncase "$PERF_CONNS" in\n  1|2|4) ;;\n  *) echo "[netperf] invalid PERF_CONNS=$PERF_CONNS (expected 1, 2 or 4)"; exit 2 ;;\nesac\n''')
replace_one(p,
'''# ---------------------------------------------------------------------------\n# iperf3: server binds the tunnel gateway IP; client tests through tunnel.\n# Namespace-isolated tunnel endpoints measure the tunnel stack overhead itself.\n# ---------------------------------------------------------------------------\niperf_one_way() {\n  local label="$1" extra="${2:-}"\n''',
r'''# ---------------------------------------------------------------------------
# Adaptive multipath diagnostics. Upload is scheduled by the client; download
# is scheduled by the server. Every configured path must carry real payload,
# and no single path may monopolize more than 80% of assigned bytes.
# ---------------------------------------------------------------------------
scheduler_diag() {
  local direction="$1" ns role
  [[ "$PERF_CONNS" -gt 1 ]] || return 0
  if [[ "$direction" == "upload" ]]; then
    ns="$NS_CLI"; role="client"
  else
    ns="$NS_SRV"; role="server"
  fi

  ip netns exec "$ns" python3 - "$WEB_ADDR" "$WEB_AUTH" "$PERF_CONNS" "$role" "$direction" <<'PY'
import base64, json, sys, time, urllib.request
addr, auth, want_s, role, direction = sys.argv[1:]
want = int(want_s)
req = urllib.request.Request(
    "http://" + addr + "/api/stats",
    headers={"Authorization": "Basic " + base64.b64encode(auth.encode()).decode()},
)
last = None
for _ in range(30):
    try:
        with urllib.request.urlopen(req, timeout=0.5) as r:
            data = json.load(r)
        break
    except Exception as exc:
        last = exc
        time.sleep(0.05)
else:
    raise SystemExit(f"scheduler stats unavailable from {role}: {last}")
rows = data.get("conns", []) if role == "client" else data.get("server_conns", [])
rows = [r for r in rows if isinstance(r.get("scheduler"), dict)][:want]
if len(rows) < want:
    raise SystemExit(f"scheduler telemetry has {len(rows)}/{want} paths for {role}")
assigned = [int((r.get("scheduler") or {}).get("assigned_bytes", 0) or 0) for r in rows]
total = sum(assigned)
if total <= 0:
    raise SystemExit(f"scheduler assigned no bytes: {assigned}")
used = sum(v > 0 for v in assigned)
shares = [v / total for v in assigned]
print(f"[netperf] scheduler {direction}/{role}: assigned={assigned} shares={[round(x, 4) for x in shares]}")
if used != want:
    raise SystemExit(f"adaptive scheduler used {used}/{want} paths: {assigned}")
if max(shares) > 0.80:
    raise SystemExit(f"adaptive scheduler path monopoly {max(shares) * 100:.1f}%: {shares}")
PY
}

# ---------------------------------------------------------------------------
# iperf3: server binds the tunnel gateway IP; client tests through tunnel.
# Namespace-isolated tunnel endpoints measure the tunnel stack overhead itself.
# ---------------------------------------------------------------------------
iperf_one_way() {
  local label="$1" extra="${2:-}" direction="${3:-upload}"
''')
replace_one(p,
'''  else\n    fail "iperf3 $label: ${mbps} Mbps < ${IPERF_MIN_MBPS} threshold"\n    log "iperf3 $label end-summary diagnostics:"\n    printf "%s\\n" "$json" |\n      grep -E '\"(error|bytes|bits_per_second|retransmits)\"' | tail -24 |\n      sed 's/^/[netperf]     /' || true\n  fi\n}\n\niperf_check() {\n''',
'''  else\n    fail "iperf3 $label: ${mbps} Mbps < ${IPERF_MIN_MBPS} threshold"\n    log "iperf3 $label end-summary diagnostics:"\n    printf "%s\\n" "$json" |\n      grep -E '\"(error|bytes|bits_per_second|retransmits)\"' | tail -24 |\n      sed 's/^/[netperf]     /' || true\n  fi\n  if ! scheduler_diag "$direction"; then\n    fail "adaptive scheduler utilization gate failed ($direction, conns=$PERF_CONNS)"\n    return 1\n  fi\n}\n\niperf_check() {\n''')
replace_one(p,
'''  iperf_one_way "upload (cli→srv)"\n  iperf_one_way "download (srv→cli)" "-R"\n''',
'''  iperf_one_way "upload (cli→srv)" "" upload\n  iperf_one_way "download (srv→cli)" "-R" download\n''')
replace_one(p,
'''  log "--- group: ${FLAVOR_SRV}_srv <- ${FLAVOR_CLI}_cli (real TAP) ---"\n''',
'''  log "--- group: ${FLAVOR_SRV}_srv <- ${FLAVOR_CLI}_cli (real TAP, conns=$PERF_CONNS) ---"\n''')
replace_one(p,
'''    '\"log_level\": \"debug\"' \\\n    "\\\"tap\\\": \\\"$TAP_SRV\\\"" \\\n''',
'''    '\"log_level\": \"debug\"' \\\n    "\\\"web\\\": {\\\"addr\\\": \\\"$WEB_ADDR\\\", \\\"bind\\\": \\\"all\\\", \\\"auth\\\": \\\"$WEB_AUTH\\\"}" \\\n    "\\\"tap\\\": \\\"$TAP_SRV\\\"" \\\n''')
replace_one(p,
'''      '\"log_level\": \"info\"' \\\n      "\\\"tap\\\": \\\"$TAP_CLI\\\"" \\\n      "\\\"client\\\": {\\\"cert_sha256\\\": \\\"$fp\\\", \\\"insecure\\\": true}"\n''',
'''      '\"log_level\": \"info\"' \\\n      "\\\"web\\\": {\\\"addr\\\": \\\"$WEB_ADDR\\\", \\\"bind\\\": \\\"all\\\", \\\"auth\\\": \\\"$WEB_AUTH\\\"}" \\\n      "\\\"tap\\\": \\\"$TAP_CLI\\\"" \\\n      "\\\"client\\\": {\\\"cert_sha256\\\": \\\"$fp\\\", \\\"insecure\\\": true, \\\"conns\\\": $PERF_CONNS}"\n''')
replace_one(p,
'''      '\"log_level\": \"info\"' \\\n      "\\\"tap\\\": \\\"$TAP_CLI\\\"" \\\n      "\\\"client\\\": {\\\"cert_sha256\\\": \\\"$fp\\\"}"\n''',
'''      '\"log_level\": \"info\"' \\\n      "\\\"web\\\": {\\\"addr\\\": \\\"$WEB_ADDR\\\", \\\"bind\\\": \\\"all\\\", \\\"auth\\\": \\\"$WEB_AUTH\\\"}" \\\n      "\\\"tap\\\": \\\"$TAP_CLI\\\"" \\\n      "\\\"client\\\": {\\\"cert_sha256\\\": \\\"$fp\\\", \\\"conns\\\": $PERF_CONNS}"\n''')

Path("tests/netperf_adaptive_contract.rs").write_text(r'''use std::fs;

#[test]
fn real_tap_exercises_adaptive_multipath_and_enforces_utilization() {
    let script = fs::read_to_string("scripts/net_perf_test.sh").expect("read net_perf_test.sh");
    for marker in [
        "PERF_CONNS=\"${PERF_CONNS:-4}\"",
        "\\\"conns\\\": $PERF_CONNS",
        "/api/stats",
        "assigned_bytes",
        "adaptive scheduler used",
        "path monopoly",
        "max(shares) > 0.80",
    ] {
        assert!(script.contains(marker), "net-perf adaptive gate missing {marker:?}");
    }
}
''')

# The workflow's cleanup step tries to delete itself. Avoid staging a workflow
# change because its GITHUB_TOKEN intentionally lacks workflow-write scope.
bindir = Path(".ci-bin")
bindir.mkdir(exist_ok=True)
rm = bindir / "rm"
rm.write_text('''#!/usr/bin/env bash\nargs=()\nfor a in "$@"; do\n  [[ "$a" == ".github/workflows/apply-netperf-adaptive-gate.yml" ]] && continue\n  args+=("$a")\ndone\nexec /usr/bin/rm "${args[@]}"\n''')
rm.chmod(0o755)
with open(os.environ["GITHUB_PATH"], "a") as f:
    f.write(str(bindir.resolve()) + "\n")
