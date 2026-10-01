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
    let i18n = fs::read_to_string(root.join("i18n.js")).expect("i18n.js");
    let css = fs::read_to_string(root.join("style.css")).expect("style.css");
    let frameviz = fs::read_to_string(root.join("frameviz.js")).expect("frameviz.js");
    assert!(index.contains("/favicon.ico"));
    let i18n_pos = index.find("src=\"i18n.js\"").expect("i18n.js script");
    let app_pos = index.find("src=\"app.js\"").expect("app.js script");
    assert!(i18n_pos < app_pos, "i18n.js must load before app.js");
    assert!(!index.contains("zh-tw.js") && !index.contains("frameviz-zh-tw.js"));
    assert!(!app.contains("const I18N={"));
    for marker in ["const I18N={", "const FRAMEVIZ_I18N=", "'zh-CN'", "'zh-TW'", "'de'", "'fr'", "'ja'", "Frame format example", "FEC recovery rate"] {
        assert!(i18n.contains(marker), "i18n.js missing {marker:?}");
    }
    assert!(app.contains("platformAssetName"));
    assert!(!app.contains("fetch(url(\'/api/stats\')"));
    assert!(css.contains("platform-badge"));
    for marker in ["FRAMEVIZ_I18N[LANG]", "AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305", "1514 B", "1530 B", "12 KiB", "16 KiB", "padLen=0", "4 B BE", "seq=0", "1 MiB"] {
        assert!(frameviz.contains(marker), "frameviz missing {marker:?}");
    }
    for file in ["favicon.ico", "i18n.js", "frameviz.js", "tcp.js", "diagnostics.js", "icons/os-linux.svg", "icons/os-windows.svg", "icons/os-macos.svg", "icons/os-android.svg", "icons/arch-x86_64.svg", "icons/arch-arm64.svg", "icons/arch-riscv64.svg"] {
        let meta = fs::metadata(root.join(file)).unwrap_or_else(|e| panic!("missing {file}: {e}"));
        assert!(meta.len() > 0, "empty asset: {file}");
    }
    for old in ["zh-tw.js", "frameviz-zh-tw.js"] { assert!(!root.join(old).exists(), "obsolete asset remains: {old}"); }
}

#[test]
fn rust_embed_table_covers_primary_assets() {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/webui_assets.rs")).expect("webui_assets.rs");
    for route in ["/", "/index.html", "/style.css", "/i18n.js", "/app.js", "/frameviz.js", "/metrics.js", "/stream.js", "/tcp.js", "/diagnostics.js", "/favicon.ico", "/icons/os-linux.svg"] {
        assert!(src.contains(&format!("\"{route}\"")), "embed table missing {route}");
    }
    assert!(!src.contains("/zh-tw.js") && !src.contains("/frameviz-zh-tw.js"));
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
        r#"os_id="$(. /etc/os-release; printf"#,
        "Invalid TLSVPN release tag:",
        "systemctl cat tlsvpn.service",
    ] {
        assert!(installer.contains(marker), "installer missing {marker}");
    }
    assert!(
        !installer.contains("\n  . /etc/os-release\n"),
        "installer must not source /etc/os-release into its global namespace"
    );
}


#[test]
fn rust_webui_exposes_go_traffic_and_background_trend_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let api = fs::read_to_string(root.join("src/api.rs")).expect("api.rs");
    let server = fs::read_to_string(root.join("src/server.rs")).expect("server.rs");
    let client = fs::read_to_string(root.join("src/client.rs")).expect("client.rs");
    for marker in [
        "start_dashboard_sampler",
        "traffic_json",
        "client_traffic",
        "trend_json(&range)",
        "apply_traffic_config",
    ] {
        assert!(api.contains(marker), "missing dashboard traffic/trend marker {marker}");
    }
    assert!(server.contains("\"global_tx_bytes\": global_tx_bytes"));
    assert!(client.contains("self.tx_bytes.load(Ordering::Relaxed)"));
}

#[test]
fn installer_uses_safe_lego_v5_and_persists_custom_paths() {
    let installer = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install.sh"),
    )
    .expect("install.sh");
    assert!(!installer.contains("-c \"$CONFIG_FILE.tmp\" >/dev/null 2>&1 &"));
    assert!(installer.contains("LEGO_ARGS=(run --path"));
    assert!(installer.contains("--renew-days"));
    assert!(installer.contains("--http.address"));
    assert!(installer.contains("--tls.address"));
    assert!(installer.contains("lego migrate --path"));
    for state_key in ["INSTALL_DIR=$(printf", "CONFIG_DIR=$(printf", "CERT_DIR=$(printf"] {
        assert!(installer.contains(state_key), "installer state missing {state_key}");
    }
}
