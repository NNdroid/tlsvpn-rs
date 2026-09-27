use std::fs;
use std::path::Path;

fn webui() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("webui")
}

#[test]
fn webui_matches_shared_static_asset_contract() {
    let root = webui();
    let index = fs::read_to_string(root.join("index.html")).expect("index.html");
    let app = fs::read_to_string(root.join("app.js")).expect("app.js");
    let css = fs::read_to_string(root.join("style.css")).expect("style.css");

    assert!(index.contains("/favicon.ico"), "missing local favicon link");
    assert!(
        index.contains("src=\"app.js\""),
        "index must load shared app.js"
    );
    assert!(
        index.contains("data-v=\"zh-TW\""),
        "Rust rendered index must include Go's zh-TW injection"
    );
    assert!(
        app.contains("platformAssetName"),
        "missing local OS/arch icon mapper"
    );
    assert!(app.contains("/api/stats"), "dashboard must use stats API");
    assert!(
        css.contains("platform-badge"),
        "missing platform icon styles"
    );

    for file in [
        "favicon.ico",
        "icons/os-linux.svg",
        "icons/os-windows.svg",
        "icons/os-macos.svg",
        "icons/os-android.svg",
        "icons/arch-x86_64.svg",
        "icons/arch-arm64.svg",
        "icons/arch-riscv64.svg",
    ] {
        let meta = fs::metadata(root.join(file)).unwrap_or_else(|e| panic!("missing {file}: {e}"));
        assert!(meta.len() > 0, "empty asset: {file}");
    }
}

#[test]
fn rust_embed_table_covers_primary_assets() {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/webui_assets.rs"))
        .expect("webui_assets.rs");
    for route in [
        "/",
        "/index.html",
        "/style.css",
        "/app.js",
        "/favicon.ico",
        "/icons/os-linux.svg",
    ] {
        assert!(
            src.contains(&format!("\"{route}\"")),
            "embed table missing {route}"
        );
    }
}
