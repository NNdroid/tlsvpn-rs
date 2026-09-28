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
    let frameviz = fs::read_to_string(root.join("frameviz.js")).expect("frameviz.js");

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

    for marker in [
        "Frame format example",
        "帧格式示例",
        "訊框格式範例",
        "AES-256-GCM",
        "AES-128-GCM",
        "ChaCha20-Poly1305",
        "XChaCha20-Poly1305",
        "1514 B",
        "1530 B",
        "60 B → 1600 B",
        "4 B BE",
        "seq=0",
        "1 MiB",
    ] {
        assert!(frameviz.contains(marker), "frameviz missing {marker:?}");
    }

    for file in [
        "favicon.ico",
        "frameviz.js",
        "frameviz-zh-tw.js",
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
        "/frameviz.js",
        "/frameviz-zh-tw.js",
        "/favicon.ico",
        "/icons/os-linux.svg",
    ] {
        assert!(
            src.contains(&format!("\"{route}\"")),
            "embed table missing {route}"
        );
    }
}

#[test]
fn rust_webui_backend_matches_go_management_contract() {
    let api = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api.rs"))
        .expect("api.rs");
    let parity =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web_parity.rs"))
            .expect("web_parity.rs");
    for marker in [
        "tlsvpn_session",
        "/api/login",
        "/api/logout",
        "/api/auth/status",
        "text/event-stream",
        "save_apply",
        "needs_restart",
        "redacted_config",
    ] {
        assert!(
            api.contains(marker) || parity.contains(marker),
            "missing WebUI backend contract marker {marker}"
        );
    }
    assert!(!api.contains("runtime config save/apply is not supported"));
}

#[test]
fn installer_has_required_lifecycle_and_platform_contract() {
    let installer =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install.sh"))
            .expect("install.sh");
    for marker in [
        "install_action",
        "upgrade_action",
        "uninstall_action",
        "rollback_action",
        "maintenance_action",
        "debian|ubuntu",
        "rocky",
        "alpine",
        "cert-mode",
        "lego",
        "self-signed",
        "XanMod",
        "tcp-brutal",
        "tlsvpn-maintenance.timer",
        "--non-interactive",
        "back",
    ] {
        assert!(installer.contains(marker), "installer missing {marker}");
    }
}
