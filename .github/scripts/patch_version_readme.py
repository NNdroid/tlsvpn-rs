from pathlib import Path


def replace_one(path, old, new):
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {n}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1))

# Build metadata: derive one user-facing version string from an explicit override,
# the checked-out git tag/describe value, or Cargo package version as fallback.
replace_one(
    "build.rs",
    '''    println!("cargo:rerun-if-env-changed=TLSVPN_GIT_COMMIT");\n    println!("cargo:rerun-if-env-changed=TLSVPN_BUILD_TIME");\n    watch_git_revision();\n\n    let commit =''',
    '''    println!("cargo:rerun-if-env-changed=TLSVPN_GIT_COMMIT");\n    println!("cargo:rerun-if-env-changed=TLSVPN_BUILD_TIME");\n    println!("cargo:rerun-if-env-changed=TLSVPN_VERSION");\n    watch_git_revision();\n\n    let version = std::env::var("TLSVPN_VERSION")\n        .ok()\n        .filter(|v| !v.trim().is_empty())\n        .or_else(|| git(&["describe", "--tags", "--always"]))\n        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())\n        .unwrap_or_else(|| "dev".to_string());\n    println!("cargo:rustc-env=TLSVPN_VERSION={version}");\n\n    let commit =''')

replace_one(
    "src/api.rs",
    '''pub const APP_VERSION: &str = "1.1.0-rs";''',
    '''pub const APP_VERSION: &str = env!("TLSVPN_VERSION");''')

# Keep peer metadata, dashboard stats and CLI on the same version source.
replace_one(
    "src/peer_info.rs",
    '''        version: env!("CARGO_PKG_VERSION").into(),''',
    '''        version: crate::api::APP_VERSION.into(),''')

# Add -version/--version as a query-only CLI alongside --print-config.
replace_one(
    "src/main.rs",
    '''/// 从 argv 提取配置文件路径：`-c path`、`--config path`、`--config=path`。\n/// 除 --print-config 外这是唯一被识别的命令行面。''',
    '''/// 从 argv 提取配置文件路径：`-c path`、`--config path`、`--config=path`。\n/// 运行时配置仍只来自 JSON；--print-config 与 -version/--version 只是查询命令。''')
replace_one(
    "src/main.rs",
    '''fn main() {\n    // -print-config：输出示例 JSON 模板并退出（对齐 Go -print-config）\n    if std::env::args().any(|a| a == "--print-config") {''',
    '''fn main() {\n    if std::env::args().any(|a| a == "-version" || a == "--version") {\n        println!("{}", crate::api::APP_VERSION);\n        return;\n    }\n\n    // -print-config：输出示例 JSON 模板并退出（对齐 Go -print-config）\n    if std::env::args().any(|a| a == "--print-config" || a == "-print-config") {''')
replace_one(
    "src/main.rs",
    '''            eprintln!("Usage: tlsvpn -c config.json");\n            eprintln!("       tlsvpn --print-config > config.json   # 生成模板后编辑");''',
    '''            eprintln!("Usage: tlsvpn -c config.json");\n            eprintln!("       tlsvpn --print-config > config.json   # 生成模板后编辑");\n            eprintln!("       tlsvpn -version                       # 显示构建版本");''')

# Installer: query the real binary first and retain state-file fallback for old
# binaries/rollback snapshots.
replace_one(
    "scripts/install.sh",
    '''random_secret() {\n  if have openssl; then openssl rand -hex 32; else od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'; fi\n}\n\nrelease_arch() {''',
    '''random_secret() {\n  if have openssl; then openssl rand -hex 32; else od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'; fi\n}\n\nbinary_version() {\n  local bin="${1:-$INSTALL_DIR/$PROGRAM}"\n  [[ -x "$bin" ]] || return 1\n  "$bin" -version 2>/dev/null | head -n1\n}\n\ninstalled_version() {\n  local v=""\n  v="$(binary_version 2>/dev/null || true)"\n  if [[ -z "$v" && -r "$STATE_DIR/installed-version" ]]; then v="$(cat "$STATE_DIR/installed-version")"; fi\n  printf '%s' "$v"\n}\n\nrelease_arch() {''')
replace_one(
    "scripts/install.sh",
    '''  local before=""\n  [[ -x "$INSTALL_DIR/$PROGRAM" ]] && before="$($INSTALL_DIR/$PROGRAM --version 2>/dev/null || true)"\n  install_tlsvpn_binary''',
    '''  local before=""\n  before="$(installed_version)"\n  install_tlsvpn_binary''')
replace_one(
    "scripts/install.sh",
    '''  local installed="" latest=""\n  [[ -r "$STATE_DIR/installed-version" ]] && installed="$(cat "$STATE_DIR/installed-version")"\n  latest="$(latest_release_tag || true)"''',
    '''  local installed="" latest=""\n  installed="$(installed_version)"\n  latest="$(latest_release_tag || true)"''')
replace_one(
    "scripts/install.sh",
    '''  if [[ -x "$INSTALL_DIR/$PROGRAM" ]]; then printf 'TLSVPN binary: %s\\n' "$INSTALL_DIR/$PROGRAM"; else printf 'TLSVPN binary: not installed\\n'; fi\n  [[ -r "$STATE_DIR/installed-version" ]] && printf 'Installed release: %s\\n' "$(cat "$STATE_DIR/installed-version")"''',
    '''  if [[ -x "$INSTALL_DIR/$PROGRAM" ]]; then printf 'TLSVPN binary: %s\\n' "$INSTALL_DIR/$PROGRAM"; else printf 'TLSVPN binary: not installed\\n'; fi\n  local installed="$(installed_version)"\n  [[ -n "$installed" ]] && printf 'Installed release: %s\\n' "$installed"''')

# README consistency fixes found during audit.
replace_one(
    "README.md",
    '''Fuller ready-made examples are checked in at the repo root — `config.server.json` and `config.client.json` (same `psk`, so they pair up). They're validated by the test suite and deliberately stay inside the Go/Rust shared config subset. Rust-only `workers`/`mtu` are omitted so Go can read them; Go-only persisted traffic-accounting keys (`traffic_days`, `traffic_file`) must likewise be omitted from files intended for Rust because both implementations reject unknown fields.''',
    '''Fuller ready-made examples are checked in at the repo root — `config.server.json` and `config.client.json` (same `psk`, so they pair up). They're validated by the test suite and deliberately stay inside the Go/Rust shared config subset. Rust-only `workers`/`mtu` are omitted so Go can read them. Persistent traffic-accounting keys (`traffic_days`, `traffic_file`) are supported by both implementations.''')
replace_one(
    "README.md",
    '''`-c config.json` is the **only** runtime configuration surface (plus `--print-config` to print a template). The shared protocol/network fields intentionally track Go, but the complete config schemas are **not identical**: Rust adds `workers`/`mtu`, Go adds `traffic_days`/`traffic_file`, Rust currently supports only `client.interface_manager=self`, and Rust server mode requires an explicit certificate/key pair. Unknown fields are rejected. Start from the built-in shared-subset template:''',
    '''`-c config.json` is the **only** runtime configuration surface. `--print-config` prints a template and `-version`/`--version` prints the build version; neither adds runtime tuning flags. The shared protocol/network fields intentionally track Go, but the complete config schemas are **not identical**: Rust adds `workers`/`mtu`, Rust currently supports only `client.interface_manager=self`, and Rust server mode requires an explicit certificate/key pair. `traffic_days`/`traffic_file` are shared by both implementations. Unknown fields are rejected. Start from the built-in shared-subset template:''')
replace_one(
    "README.md",
    '''./tlsvpn --print-config > config.json''',
    '''./tlsvpn --print-config > config.json\n./tlsvpn -version''')
replace_one(
    "README.md",
    '''  "brutal_down": 500,\n  "socks5": "",''',
    '''  "brutal_down": 500,\n  "traffic_days": 30,\n  "traffic_file": "tlsvpn-traffic.json",\n  "socks5": "",''')
replace_one(
    "README.md",
    '''| `web.auth` | (required when enabled) | — | Basic Auth as `user:pass`, compared as fixed-length SHA-256 digests. Known example credentials are rejected |''',
    '''| `web.auth` | (required when enabled) | — | Credential source as `user:pass`. Browser login exchanges it for an HttpOnly SameSite session cookie; explicit Basic Auth remains accepted for scripts. Known example credentials are rejected |''')
replace_one(
    "README.md",
    '''| `client.fec_group` | `4` | client | XOR FEC group size K (2–64), clamped into range before it goes on the wire; the server may refuse an out-of-policy K |''',
    '''| `client.fec_group` | `4` | client | XOR FEC group size K (2–64). Out-of-range configuration is rejected locally; the server may also refuse a K outside its configured policy |''')

# CI checks the actual executable and version source override.
replace_one(
    ".github/workflows/rust.yml",
    '''    - name: Build\n      run: cargo build --verbose\n\n    - name: Test Core Logic''',
    '''    - name: Build\n      run: cargo build --verbose\n\n    - name: Verify version CLI\n      env:\n        TLSVPN_VERSION: ci-version-test\n      run: |\n        cargo build --quiet\n        test "$(target/debug/tlsvpn -version)" = "ci-version-test"\n        test "$(target/debug/tlsvpn --version)" = "ci-version-test"\n\n    - name: Test Core Logic''')

# Source-level regression test for README/schema claims and dynamic version use.
Path("tests/version_readme_contract.rs").write_text(r'''use std::fs;

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
''')
