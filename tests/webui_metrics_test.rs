use std::fs;
use std::path::Path;

#[test]
fn metric_formula_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let js = fs::read_to_string(root.join("webui/metrics.js")).expect("webui/metrics.js");
    for want in [
        "Math.ceil(v.length * 0.95) - 1",
        "const reorder = data.reorder || {}",
        "const dataTxPackets = Math.max(0, c.txPackets - parityTx)",
        "const txAttempts = c.txPackets + dropped",
        "c.rxBytes / c.rxPackets",
        "parityTx / dataTxPackets * 100",
        "const missing = recovered + lost",
        "recovered / missing * 100",
    ] {
        assert!(js.contains(want), "metric formula contract missing {want:?}");
    }
    assert!(
        !js.contains("data.quality"),
        "quality values must be derived from real counters"
    );
    for wrong in [
        "recovered / parityTx",
        "recovered / num(fec.parity_tx)",
        "parityTx / c.txPackets",
        "const txAttempts = dataTxPackets + dropped",
    ] {
        assert!(!js.contains(wrong), "mixed-domain metric formula reintroduced: {wrong:?}");
    }
}

#[test]
fn embedded_index_loads_metric_corrections_after_app() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let assets = fs::read_to_string(root.join("src/webui_assets.rs")).expect("webui_assets.rs");
    assert!(assets.contains("\"/metrics.js\""), "metrics.js route missing");
    assert!(
        assets.contains("<script src=\\\"metrics.js\\\"></script>"),
        "embedded index does not inject metrics.js"
    );

    let html = fs::read_to_string(root.join("webui/index.html")).expect("webui/index.html");
    let app = html.find("<script src=\"app.js\"></script>").expect("app.js script");
    // webui_assets injects metrics.js at </body>, therefore it is guaranteed to
    // execute after the static app.js script already present in index.html.
    let body_end = html.find("</body>").expect("body end");
    assert!(app < body_end);
}
