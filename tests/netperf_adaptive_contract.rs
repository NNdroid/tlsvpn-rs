use std::fs;

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
        assert!(
            script.contains(marker),
            "net-perf adaptive gate missing {marker:?}"
        );
    }
}
