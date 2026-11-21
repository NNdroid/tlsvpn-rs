use std::fs;
use std::path::Path;

#[test]
fn metric_formula_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let js = fs::read_to_string(root.join("webui/metric-corrections.js"))
        .expect("webui/metric-corrections.js");
    for want in [
        "Math.ceil(v.length * 0.95) - 1",
        "const reorder = data.reorder || {}",
        "fec.counter_domain === 'written'",
        "const txAttempts = c.txPackets + dropped",
        "c.rxBytes/c.rxPackets",
        "parityWire/dataWire*100",
        "const missing = recovered + lost",
        "recovered/missing*100",
    ] {
        assert!(
            js.contains(want),
            "metric formula contract missing {want:?}"
        );
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
        assert!(
            !js.contains(wrong),
            "mixed-domain metric formula reintroduced: {wrong:?}"
        );
    }
}

#[test]
fn embedded_index_loads_metric_corrections_after_app() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let assets = fs::read_to_string(root.join("src/webui_assets.rs")).expect("webui_assets.rs");
    assert!(
        assets.contains("\"/metric-corrections.js\""),
        "metric-corrections.js route missing"
    );
    assert!(
        assets.contains("<script src=\\\"metric-corrections.js\\\"></script>"),
        "embedded index does not inject metric-corrections.js"
    );

    let html = fs::read_to_string(root.join("webui/index.html")).expect("index.html");
    let i18n = html
        .find("<script src=\"i18n.js\"></script>")
        .expect("i18n.js script");
    let app = html
        .find("<script src=\"app.js\"></script>")
        .expect("app.js script");
    assert!(i18n < app, "i18n.js must load before app.js");
    // webui_assets injects the runtime modules (frame-visualizer /
    // metric-corrections / sse / scheduler-settings / mcp-settings /
    // mcp-examples, 与 Go webui.go 同清单) at </body>, therefore they are
    // guaranteed to execute after the static app.js script already present in
    // index.html.
    let body_end = html.find("</body>").expect("body end");
    assert!(app < body_end);
}
