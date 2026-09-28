use std::fs;

#[test]
fn installer_writes_readable_json() {
    let s = fs::read_to_string("scripts/install.sh").expect("scripts/install.sh");
    for compact in [
        r#"\"web\": {\"addr\":"#,
        r#"\"server\": {\"v4_cidr\":"#,
        r#"\"client\": {\"interface_manager\":"#,
    ] {
        assert!(
            !s.contains(compact),
            "installer still emits compact JSON object {compact}"
        );
    }
    for pretty in [
        "\"web\": {\n    \"addr\":",
        "\"server\": {\n    \"v4_cidr\":",
        "\"client\": {\n    \"interface_manager\":",
    ] {
        assert!(
            s.contains(pretty),
            "installer missing pretty JSON layout {pretty}"
        );
    }
}
