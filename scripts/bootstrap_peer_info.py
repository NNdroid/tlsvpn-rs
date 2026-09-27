from pathlib import Path


def rep(path, old, new, n=1):
    p=Path(path); s=p.read_text()
    if s.count(old)<n:
        raise SystemExit(f'{path}: expected {n}, got {s.count(old)} for {old[:100]!r}')
    p.write_text(s.replace(old,new,n))

rep('src/main.rs','pub mod net;\npub mod server;', 'pub mod net;\npub mod peer_info;\npub mod server;',1)

rep('src/api.rs','use tracing_subscriber::EnvFilter;\n', 'use tracing_subscriber::EnvFilter;\nuse crate::peer_info::PeerInfo;\n',1)
rep('src/api.rs','    pub session_token: String,\n}\n\npub const TLS_CLIENT_HELLO',
    '    pub session_token: String,\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub peer_info: Option<PeerInfo>,\n}\n\npub const TLS_CLIENT_HELLO',1)
rep('src/api.rs','    pub tls: Option<TLSHandshakeInfo>,\n}\n\npub fn is_zero_u64',
    '    pub tls: Option<TLSHandshakeInfo>,\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub peer_info: Option<PeerInfo>,\n}\n\npub fn is_zero_u64',1)

rep('src/client.rs','use crate::net::*;\nuse crate::socks5', 'use crate::net::*;\nuse crate::peer_info::{local_peer_info, normalize_peer_info, PeerInfo};\nuse crate::socks5',1)
rep('src/client.rs','    tls: Option<TLSHandshakeInfo>,\n}', '    tls: Option<TLSHandshakeInfo>,\n    peer_info: Option<PeerInfo>,\n}',1)
rep('src/client.rs','        session_token,\n    };', '        session_token,\n        peer_info: Some(local_peer_info()),\n    };',1)
rep('src/client.rs','        st.tls = resp.tls.clone();\n        // 落盘',
    '        st.tls = resp.tls.clone();\n        // peer_info is optional for rolling upgrades; clear stale metadata when an old server omits it.\n        st.peer_info = resp.peer_info.as_ref().map(normalize_peer_info);\n        // 落盘',1)
rep('src/client.rs','        let negotiated_tls = sess.tls.clone();\n        drop(sess);',
    '        let negotiated_tls = sess.tls.clone();\n        let negotiated_peer = sess.peer_info.clone();\n        drop(sess);',1)
rep('src/client.rs','            "negotiate": negotiate,\n        })',
    '            "negotiate": negotiate,\n            "peer": negotiated_peer,\n        })',1)

rep('src/server.rs','use crate::net::*;\nuse crate::tap', 'use crate::net::*;\nuse crate::peer_info::{local_peer_info, normalize_peer_info, PeerInfo};\nuse crate::tap',1)
rep('src/server.rs','    pub mac: String,\n    // 握手 MAC',
    '    pub mac: String,\n    pub peer_info: RwLock<Option<PeerInfo>>,\n    // 握手 MAC',1)
rep('src/server.rs','                mac,\n                ipv4: v4ip,',
    '                mac,\n                peer_info: RwLock::new(req.peer_info.as_ref().map(normalize_peer_info)),\n                ipv4: v4ip,',1)
rep('src/server.rs','    };\n\n    let epoch_snapshot = c_sess.epoch_state.read();',
    '    };\n\n    if let Some(peer) = req.peer_info.as_ref() {\n        *c_sess.peer_info.write() = Some(normalize_peer_info(peer));\n    }\n\n    let epoch_snapshot = c_sess.epoch_state.read();',1)
rep('src/server.rs','        tls: observed_tls_handshake(sess),\n    };',
    '        tls: observed_tls_handshake(sess),\n        peer_info: Some(local_peer_info()),\n    };',1)
rep('src/server.rs','                    "online_sec": s.created_at.elapsed().as_secs(),\n                    "uptime_sec": s.created_at.elapsed().as_secs(),',
    '                    "online_sec": s.created_at.elapsed().as_secs(),\n                    "uptime_sec": s.created_at.elapsed().as_secs(),\n                    "peer_info": s.peer_info.read().clone(),',1)

# Protocol regression test alongside the contract structs.
p=Path('src/api.rs'); s=p.read_text()
marker='pub fn is_zero_u64(v: &u64) -> bool {'
test='''#[cfg(test)]\nmod peer_info_protocol_tests {\n    use super::*;\n\n    #[test]\n    fn peer_info_is_optional_and_round_trips() {\n        let old = r#"{\"protocol_version\":2,\"client_id\":\"x\",\"psk\":\"y\"}"#;\n        let req: HandshakeReq = serde_json::from_str(old).unwrap();\n        assert!(req.peer_info.is_none());\n\n        let mut req = req;\n        req.peer_info = Some(PeerInfo {\n            implementation: \"rust\".into(), hostname: \"node-r\".into(), os: \"linux\".into(),\n            arch: \"aarch64\".into(), version: \"v1\".into(), ..Default::default()\n        });\n        let encoded = serde_json::to_string(&req).unwrap();\n        let round: HandshakeReq = serde_json::from_str(&encoded).unwrap();\n        assert_eq!(round.peer_info.unwrap().hostname, \"node-r\");\n    }\n}\n\n'''
if test not in s:
    s=s.replace(marker,test+marker,1); p.write_text(s)
