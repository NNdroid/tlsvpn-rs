use std::fs;
use std::path::Path;

#[test]
fn dashboard_periodic_data_is_sse_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let app = fs::read_to_string(root.join("webui/app.js")).unwrap();
    for marker in [
        "fetch(url('/api/stats')", "fetch(url('/api/trend')", "fetch(url('/api/logs')",
        "fetch(url('/api/events')", "setInterval(fetchStats", "setInterval(fetchTrend",
        "setInterval(pollLogs", "EV_POLL_MS",
    ] {
        assert!(!app.contains(marker), "legacy polling marker remains: {marker}");
    }
    let stream = fs::read_to_string(root.join("webui/stream.js")).unwrap();
    for marker in ["/api/stream", "EventSource", "applyStats(payload)", "applyTrend(payload)", "applyLogs(payload)", "applyEvents(payload)"] {
        assert!(stream.contains(marker), "stream.js missing {marker}");
    }
    let api = fs::read_to_string(root.join("src/api.rs")).unwrap();
    assert!(api.contains("\"/api/stream\""));
    assert!(api.contains("DashboardStream"));
}
