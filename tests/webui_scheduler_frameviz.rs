use std::fs;
use std::path::PathBuf;

fn read(path: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn scheduler_uses_interval_metrics() {
    let s = read("webui/metrics.js");
    for want in [
        "assigned - p.assigned",
        "batches - p.batches",
        "_assign_bps",
        "_share_pct",
        "_batch_ps",
        "_queue_eta_us",
        "queued_bytes",
        "lifetime assigned",
    ] {
        assert!(s.contains(want), "metrics.js missing scheduler interval semantic {want:?}");
    }
    assert!(
        !s.contains("t('th.tx') + ' ' + fmtBytes(s.assigned_bytes"),
        "scheduler cell must not present lifetime assigned_bytes as current TX"
    );
}

#[test]
fn frameviz_matches_stream_aggregation() {
    let s = read("webui/frameviz.js");
    for want in [
        "12 KiB",
        "16 KiB",
        "padLen=0",
        "10%",
        "512 B",
        "Final frame",
        "'zh-CN'",
        "'zh-TW'",
        "en:",
        "de:",
        "fr:",
        "ja:",
    ] {
        assert!(s.contains(want), "frameviz.js missing current framing detail {want:?}");
    }
    for stale in ["bucket 1600B", "padLen=60"] {
        assert!(
            !s.contains(stale),
            "frameviz.js still contains obsolete per-frame padding example {stale:?}"
        );
    }
}
