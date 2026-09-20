use serde::{Deserialize, Serialize};
use std::fs;

/// 客户端落盘的进程身份：TAP MAC、会话 ID、会话令牌。
/// MAC 派生 client_id，client_id 决定服务端会话与分配的隧道 IP。三者跨进程
/// 稳定之后，客户端被杀或崩溃重启才能无缝接回原会话，而不是等 120 秒僵尸
/// 会话过期才自然恢复连通。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientState {
    pub client_id: String,
    pub mac: String,
    pub session_id: String,
    pub session_token: String,
}

/// 状态文件紧随配置文件（`<config>.state`）。`config_path` 为空（进程内测试
/// 未从文件加载配置）时不持久化。
pub fn client_state_path(config_path: &str) -> String {
    if config_path.is_empty() {
        String::new()
    } else {
        format!("{}.state", config_path)
    }
}

/// 读不到、没读到都按"没有历史身份"处理，只记一条告警；绝不让一个坏状态文件
/// 阻止客户端上线。
pub fn load_client_state(path: &str) -> ClientState {
    if path.is_empty() {
        return ClientState::default();
    }
    let data = match fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ClientState::default(),
        Err(e) => {
            tracing::warn!("Client failed to read identity state {}: {}", path, e);
            return ClientState::default();
        }
    };
    match serde_json::from_str(&data) {
        Ok(st) => st,
        Err(e) => {
            tracing::warn!("Client failed to parse identity state {}: {}", path, e);
            ClientState::default()
        }
    }
}

/// 原子写入状态文件。权限 0600：内容含会话令牌，令牌与 PSK 共同构成"持密者
/// 也不能冒充在线会话"的防御，泄露等同削弱会话隔离。
pub fn save_client_state(path: &str, st: &ClientState) -> Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }
    let data = serde_json::to_string(st).map_err(|e| e.to_string())?;
    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, data).map_err(|e| e.to_string())?;
    // 0600 只在 POSIX 上表达得了；Windows 的 ACL 语义不同，不强行设置。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).ok();
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

/// 生成随机 MAC：清掉组播位、置本地管理位，保证是合法单播地址。
pub fn generate_tap_mac() -> String {
    let mut b = [0u8; 6];
    getrandom::getrandom(&mut b).expect("Failed to generate tap MAC");
    b[0] = (b[0] & 0xfe) | 0x02;
    b.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_path_is_sibling_of_config() {
        assert_eq!(
            client_state_path("/etc/tlsvpn/client.json"),
            "/etc/tlsvpn/client.json.state"
        );
        // 空路径（进程内测试未从文件加载配置）= 不持久化
        assert_eq!(client_state_path(""), "");
    }

    #[test]
    fn state_round_trip_and_missing_file() {
        // 缺失与空路径都按"没有历史身份"处理，不得报错
        assert!(load_client_state("").client_id.is_empty());
        let missing =
            std::env::temp_dir().join(format!("tlsvpn-state-missing-{}.json", std::process::id()));
        let st = load_client_state(missing.to_str().unwrap());
        assert!(st.mac.is_empty() && st.session_token.is_empty());

        let path =
            std::env::temp_dir().join(format!("tlsvpn-state-rt-{}.json", std::process::id()));
        let sp = path.to_str().unwrap().to_string();
        let mut want = ClientState::default();
        want.client_id = "11111111-2222-3333-4444-555555555555".into();
        want.mac = "02:aa:bb:cc:dd:ee".into();
        want.session_id = "deadbeef".into();
        want.session_token = "cafef00d".into();
        save_client_state(&sp, &want).unwrap();
        let got = load_client_state(&sp);
        assert_eq!(got, want, "落盘/回读必须逐字段一致");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn state_survives_bogus_file() {
        let path =
            std::env::temp_dir().join(format!("tlsvpn-state-bogus-{}.json", std::process::id()));
        fs::write(&path, "{not json").unwrap();
        let got = load_client_state(path.to_str().unwrap());
        assert!(got.client_id.is_empty(), "坏状态文件必须退化为空身份");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_path_never_writes() {
        assert!(save_client_state("", &ClientState::default()).is_ok());
    }

    #[test]
    fn generated_mac_is_valid_unicast() {
        for _ in 0..32 {
            let mac = generate_tap_mac();
            let bytes: Result<Vec<u8>, _> =
                mac.split(':').map(|p| u8::from_str_radix(p, 16)).collect();
            let b = bytes.unwrap();
            assert_eq!(b.len(), 6, "MAC 必须是 6 字节: {}", mac);
            assert_eq!(b[0] & 1, 0, "组播位必须清掉: {}", mac);
            assert_ne!(b[0] & 2, 0, "本地管理位必须置位: {}", mac);
        }
    }

    #[test]
    fn generated_mac_is_not_reused() {
        // 两个进程若拿到同一个随机 MAC 会算出同一 client_id、互抢隧道 IP
        let a = generate_tap_mac();
        let b = generate_tap_mac();
        assert_ne!(a, b);
    }
}
