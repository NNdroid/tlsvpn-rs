use std::fs;

#[test]
fn parity_send_updates_scheduler_fec_telemetry() {
    let root = env!("CARGO_MANIFEST_DIR");
    let net = fs::read_to_string(format!("{root}/src/net.rs")).unwrap();
    assert!(net.contains("let parity_bytes = par.len() as u64;"));
    assert!(net.contains("scheduler.note_fec_assigned(parity_bytes)"));

    let metrics = fs::read_to_string(format!("{root}/webui/metrics.js")).unwrap();
    assert!(metrics.contains("fec_assigned_bytes"));
    assert!(metrics.contains("dDataBytes + dFecBytes"));
}
