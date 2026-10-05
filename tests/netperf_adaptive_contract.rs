use std::fs;

/// The perf gate is a script, so this test pins it by literal marker instead
/// of exercising it. Markers fall into two groups: telemetry wiring, which
/// keeps the gate from going vacuous (it must read per-conn `/api/stats` and
/// honour `PERF_CONNS`), and the scheduler clauses themselves (one per
/// assertion in `scheduler_diag`). Markers must match code, not the comments
/// next to it — a comment match would let the clause be deleted unnoticed.
/// When the contract changes, update the clause markers together with
/// `scheduler_diag` in scripts/net_perf_test.sh.
#[test]
fn real_tap_exercises_adaptive_multipath_and_enforces_utilization() {
    let script = fs::read_to_string("scripts/net_perf_test.sh").expect("read net_perf_test.sh");
    for marker in [
        "PERF_CONNS=\"${PERF_CONNS:-4}\"",
        "\\\"conns\\\": $PERF_CONNS",
        "/api/stats",
        "assigned_bytes",
        ".get(\"active\"",
        "real_payload = 1 << 20",
        "if not participating:",
        "active[i] and assigned[i] < real_payload",
        "if len(participating) > 1:",
        "worst > 0.80",
    ] {
        assert!(
            script.contains(marker),
            "net-perf adaptive gate missing {marker:?}"
        );
    }
}
