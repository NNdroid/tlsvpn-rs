#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected one match, got {n}: {old[:160]!r}")
    p.write_text(s.replace(old, new, 1))


# Transformer edge: only the fallback-loop call should be fenced; the ordinary
# blocking helper has no control variable.
p = Path("src/net.rs")
s = p.read_text()
needle = "match self.try_send_payload_to_fenced(b, seq, data, control) {"
if needle not in s:
    raise SystemExit("generated net.rs fenced send token not found")
s = s.replace(needle, "match self.try_send_payload_to(b, seq, data) {", 1)
s = s.replace(
    "use crate::buffer::{release_frame_vec, release_shared_frame};",
    "use crate::buffer::release_frame_vec;",
    1,
)
# This helper is exercised only by unit tests after the scheduler hot path moved
# to selected_data_backend_index.
s = s.replace(
    "    /// 返回后端索引，避免在每帧路径构造/升级 Weak Arc。\n    fn pick_backend_index(",
    "    /// 返回后端索引，避免在每帧路径构造/升级 Weak Arc。\n    #[cfg(test)]\n    fn pick_backend_index(",
    1,
)
# The payload is retained for diagnostics/tests even though production matching
# only distinguishes the enum class.
s = s.replace(
    "enum BrutalSockError {\n    Locked,\n    NoVersion,\n    Other(String),",
    "enum BrutalSockError {\n    Locked,\n    NoVersion,\n    #[allow(dead_code)]\n    Other(String),",
    1,
)
p.write_text(s)

# FEC compile cleanup.
p = Path("src/fec.rs")
s = p.read_text()
s = s.replace("let mut complete = false;", "let complete;", 1)
s = s.replace(
    '.map_err(|e| format!("FEC_PARITY AEAD failure: {e}"))?;',
    '.map_err(|_| "FEC_PARITY AEAD failure".to_string())?;',
    1,
)
p.write_text(s)

# Strict dispatcher removed the old fec module namespace use.
p = Path("src/server.rs")
s = p.read_text().replace(
    "use crate::fec::{self, FecDecoder};", "use crate::fec::FecDecoder;", 1
)
p.write_text(s)

# Conformance shape must include the exact v3 diagnostic peer_info field on both
# request and response. serde_json::Value is sufficient here because these tests
# lock field names, while src/api.rs owns the typed PeerInfo contract.
p = Path("tests/protocol_conformance.rs")
s = p.read_text()
s = s.replace(
    '''    #[serde(skip_serializing_if = "String::is_empty")]
    session_token: String,
}

#[derive(serde::Serialize, Default)]
struct TlsHandshakeInfoShape {''',
    '''    #[serde(skip_serializing_if = "String::is_empty")]
    session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_info: Option<serde_json::Value>,
}

#[derive(serde::Serialize, Default)]
struct TlsHandshakeInfoShape {''',
    1,
)
s = s.replace(
    '''    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsHandshakeInfoShape>,
}
''',
    '''    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsHandshakeInfoShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_info: Option<serde_json::Value>,
}
''',
    1,
)
# Fully-populated request shape in test_handshake_req_field_names.
s = s.replace(
    '''        enc_algo: 2,
        session_token: "t".into(),
    };''',
    '''        enc_algo: 2,
        session_token: "t".into(),
        peer_info: Some(serde_json::json!({"implementation":"rust"})),
    };''',
    1,
)
# Fully-populated response shapes (field-name test + golden bidirectional test).
s = s.replace(
    '''        session_token: "t".into(),
        tls: Some(full_tls_info_shape()),
    };''',
    '''        session_token: "t".into(),
        tls: Some(full_tls_info_shape()),
        peer_info: Some(serde_json::json!({"implementation":"rust"})),
    };''',
)
# Second request shape uses Default tail.
s = s.replace(
    '''        fec_group: 4,
        encrypt: true,
        enc_algo: 2,
        ..Default::default()''',
    '''        fec_group: 4,
        encrypt: true,
        enc_algo: 2,
        peer_info: Some(serde_json::json!({"implementation":"rust"})),
        ..Default::default()''',
    1,
)
# Hand-coded response field set must now be exact v3 too.
s = s.replace(
    '''        "padding",
        "protocol_version",''',
    '''        "padding",
        "peer_info",
        "protocol_version",''',
    1,
)
# Default peer_info follows omitempty/skip-none semantics.
s = s.replace(
    '''        "enc_algo",
        // 旧版客户端不发 session_token：空串必须省略，服务端才收得到"无令牌"
        "session_token",''',
    '''        "enc_algo",
        "session_token",
        "peer_info",''',
    1,
)
p.write_text(s)

# Rust 1.98 warnings promoted by clippy -D warnings.
p = Path("src/main.rs")
s = p.read_text().replace(
    "enc_algo: if (if encrypt_present { cfg.encrypt } else { true }) {",
    "enc_algo: if if encrypt_present { cfg.encrypt } else { true } {",
    1,
)
p.write_text(s)

p = Path("src/buffer.rs")
s = p.read_text()
s = s.replace("const HOT_FRAME_CLASS: usize = 2048;", "#[cfg(test)]\nconst HOT_FRAME_CLASS: usize = 2048;", 1)
s = s.replace("let mut d = DeDuplicator::new();", "let d = DeDuplicator::new();", 1)
p.write_text(s)

# Dead helper no longer participates in the adaptive scheduler; delete rather
# than suppressing a stale production method.
p = Path("src/adaptive_multipath.rs")
s = p.read_text()
old = '''    #[inline]
    fn effective_rate(&self) -> u64 {
        let v = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if v == 0 {
            FALLBACK_RATE_BYTES_PER_SEC
        } else {
            v
        }
    }

'''
if old not in s:
    raise SystemExit("adaptive_multipath.rs: stale effective_rate helper not found")
s = s.replace(old, "", 1)
p.write_text(s)

print("post-transform v3 source/conformance fixes applied")
