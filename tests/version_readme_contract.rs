use std::fs;

#[test]
fn version_and_readme_contract() {
    let main_rs = fs::read_to_string("src/main.rs").unwrap();
    assert!(main_rs.contains("-version") && main_rs.contains("--version"));
    let api_rs = fs::read_to_string("src/api.rs").unwrap();
    assert!(api_rs.contains("env!(\"TLSVPN_VERSION\")"));
    let peer = fs::read_to_string("src/peer_info.rs").unwrap();
    assert!(peer.contains("crate::api::APP_VERSION"));
    let readme = fs::read_to_string("README.md").unwrap();
    for want in ["./tlsvpn -version", "supported by both implementations", "Out-of-range configuration is rejected locally", "HttpOnly SameSite session cookie"] {
        assert!(readme.contains(want), "README missing {want:?}");
    }
    assert!(!readme.contains("Go adds `traffic_days`/`traffic_file`"));
    assert!(!readme.contains("Go-only persisted traffic-accounting keys"));
}
