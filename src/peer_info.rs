use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::OnceLock;

pub const PEER_INFO_FIELD_MAX: usize = 256;

/// Diagnostic metadata exchanged inside the authenticated TLSVPN handshake.
/// The remote peer controls these strings: they are for observability only and
/// must never influence authentication or authorization.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub implementation: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kernel: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub git_commit: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build_time: String,
}

static LOCAL: OnceLock<PeerInfo> = OnceLock::new();

pub fn local_peer_info() -> PeerInfo {
    LOCAL.get_or_init(collect_peer_info).clone()
}

fn collect_peer_info() -> PeerInfo {
    let hostname = read_trimmed("/etc/hostname")
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_default();

    let mut info = PeerInfo {
        implementation: "rust".into(),
        hostname,
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        git_commit: option_env!("TLSVPN_GIT_COMMIT").unwrap_or("").into(),
        build_time: option_env!("TLSVPN_BUILD_TIME").unwrap_or("").into(),
        ..Default::default()
    };
    if matches!(std::env::consts::OS, "linux" | "android") {
        info.os_version = os_release_pretty_name("/etc/os-release").unwrap_or_default();
        info.kernel = read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_default();
    }
    normalize_peer_info(&info)
}

pub fn normalize_peer_info(input: &PeerInfo) -> PeerInfo {
    PeerInfo {
        implementation: trim_field(&input.implementation),
        hostname: trim_field(&input.hostname),
        os: trim_field(&input.os),
        os_version: trim_field(&input.os_version),
        kernel: trim_field(&input.kernel),
        arch: trim_field(&input.arch),
        version: trim_field(&input.version),
        git_commit: trim_field(&input.git_commit),
        build_time: trim_field(&input.build_time),
    }
}

fn trim_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= PEER_INFO_FIELD_MAX {
        return trimmed.to_string();
    }
    // Keep UTF-8 valid while bounding attacker-controlled session metadata.
    let mut end = PEER_INFO_FIELD_MAX;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_string()
}

fn read_trimmed(path: &str) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn os_release_pretty_name(path: &str) -> Option<String> {
    let data = fs::read_to_string(path).ok()?;
    for line in data.lines() {
        if let Some(value) = line.trim().strip_prefix("PRETTY_NAME=") {
            let value = value.trim().trim_matches('"').trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bounds_untrusted_fields_and_preserves_utf8() {
        let info = PeerInfo {
            hostname: "  node-a  ".into(),
            os_version: "界".repeat(200),
            ..Default::default()
        };
        let got = normalize_peer_info(&info);
        assert_eq!(got.hostname, "node-a");
        assert!(got.os_version.len() <= PEER_INFO_FIELD_MAX);
        assert!(std::str::from_utf8(got.os_version.as_bytes()).is_ok());
    }

    #[test]
    fn local_info_has_stable_core_fields() {
        let p = local_peer_info();
        assert_eq!(p.implementation, "rust");
        assert!(!p.os.is_empty());
        assert!(!p.arch.is_empty());
        assert!(!p.version.is_empty());
    }
}
