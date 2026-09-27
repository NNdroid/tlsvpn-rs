from pathlib import Path

p=Path('src/api.rs')
s=p.read_text()

def rep(old,new,n=1):
    global s
    if s.count(old)<n:
        raise SystemExit(f'api.rs: expected {n}, got {s.count(old)} for {old[:100]!r}')
    s=s.replace(old,new,n)

rep('use tracing_subscriber::EnvFilter;\n', 'use tracing_subscriber::EnvFilter;\nuse crate::peer_info::PeerInfo;\n',1)
rep('    pub session_token: String,\n}\n\npub const TLS_CLIENT_HELLO',
    '    pub session_token: String,\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub peer_info: Option<PeerInfo>,\n}\n\npub const TLS_CLIENT_HELLO',1)
rep('    pub tls: Option<TLSHandshakeInfo>,\n}\n\npub fn is_zero_u64',
    '    pub tls: Option<TLSHandshakeInfo>,\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub peer_info: Option<PeerInfo>,\n}\n\npub fn is_zero_u64',1)

test='''#[cfg(test)]\nmod peer_info_protocol_tests {\n    use super::*;\n\n    #[test]\n    fn peer_info_is_optional_and_round_trips() {\n        let old = r#"{\"protocol_version\":2,\"client_id\":\"x\",\"psk\":\"y\"}"#;\n        let req: HandshakeReq = serde_json::from_str(old).unwrap();\n        assert!(req.peer_info.is_none());\n\n        let mut req = req;\n        req.peer_info = Some(PeerInfo {\n            implementation: \"rust\".into(), hostname: \"node-r\".into(), os: \"linux\".into(),\n            arch: \"aarch64\".into(), version: \"v1\".into(), ..Default::default()\n        });\n        let encoded = serde_json::to_string(&req).unwrap();\n        let round: HandshakeReq = serde_json::from_str(&encoded).unwrap();\n        assert_eq!(round.peer_info.unwrap().hostname, \"node-r\");\n    }\n}\n\n'''
marker='pub fn is_zero_u64(v: &u64) -> bool {'
if test not in s:
    if marker not in s: raise SystemExit('api.rs marker missing')
    s=s.replace(marker,test+marker,1)
p.write_text(s)
