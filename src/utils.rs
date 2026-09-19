use aes::Aes256;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub fn ip4_to_u32(ip: &str) -> u32 {
    u32::from_be_bytes(
        Ipv4Addr::from_str(ip)
            .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
            .octets(),
    )
}
pub fn u32_to_ip4(val: u32) -> String {
    Ipv4Addr::from(val).to_string()
}
pub fn ip6_to_u128(ip: &str) -> u128 {
    u128::from_be_bytes(
        Ipv6Addr::from_str(ip)
            .unwrap_or(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
            .octets(),
    )
}
pub fn u128_to_ip6(val: u128) -> String {
    Ipv6Addr::from(val).to_string()
}

pub struct FastRand(u64);
impl FastRand {
    pub fn new() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut state = d.as_nanos() as u64;
        if state == 0 {
            state = 1;
        }
        Self(state)
    }
    pub fn next_u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }
    pub fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if max <= min {
            return min;
        }
        min + (self.next_u32() as usize % (max - min))
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let r = self.next_u32().to_ne_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&r[..len]);
        }
    }
}
thread_local! {
    pub static RNG: std::cell::RefCell<FastRand> = std::cell::RefCell::new(FastRand::new());
}

pub fn init_logger(level_str: &str) {
    let level = match level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .finish(),
    )
    .ok();
}

fn is_hex_digit(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

/// clientID 必须是标准 UUID 形态（36 字符，8-4-4-4-12，hex + 连字符，大小写
/// 不敏感）。clientID 由请求方自报并大量进入日志与面板：不校验格式的话，
/// 自报的 "\n..." 可以注入伪日志行（日志聚合/告警按行解析时被当成伪事件）。
/// 对齐 Go utils.isValidClientID。
pub fn is_valid_client_id(id: &str) -> bool {
    if id.len() != 36 {
        return false;
    }
    for (i, c) in id.as_bytes().iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if *c != b'-' {
                return false;
            }
        } else if !is_hex_digit(*c) {
            return false;
        }
    }
    true
}

/// 解析 "aa:bb:cc:dd:ee:ff"（大小写不敏感）为二进制 MAC。解析失败返回 None，
/// 调用方按"无 MAC"处理。对齐 Go utils.parseMACKey。
pub fn parse_mac_key(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut cur = 0usize;
    for part in s.split(':') {
        if cur == 6 {
            return None;
        }
        let b = hex::decode(part).ok()?;
        if b.len() != 1 {
            return None;
        }
        out[cur] = b[0];
        cur += 1;
    }
    (cur == 6).then_some(out)
}

/// 校验自报 MAC 的形态（允许为空 = 客户端未上报 MAC）。对齐 Go
/// utils.isValidMACString。
pub fn is_valid_mac_string(s: &str) -> bool {
    s.is_empty() || parse_mac_key(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_validation_matches_go() {
        // 大小写不敏感；两端客户端都用 UUID v5 的连字符形态生成
        for id in [
            "123e4567-e89b-12d3-a456-426614174000",
            "123E4567-E89B-12D3-A456-426614174000",
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert!(is_valid_client_id(id), "合法 clientID {id:?} 被误拒");
        }

        // 逐类构造非法样本，含换行注入（伪造日志行的实际攻击载荷）
        let invalid = [
            "",
            "\n",
            "123e4567-e89b-12d3-a456-42661417400", // 少 1 字符
            "123e4567-e89b-12d3-a456-4266141740000", // 多 1 字符
            "g23e4567-e89b-12d3-a456-42661417400",  // 非 hex 数字
            "123e4567_e89b-12d3-a456-426614174000", // 连字符位置错
            "123e4567e89b12d3a4564266141740000",   // 缺连字符
            "bad\nid-with-log-forging-attempt-xxxxxxxxxxxx", // 换行注入
            "123e4567-e89b-12d3-a456-426614174000\x1b[31mRED", // 逃逸序列
            "123e4567-e89b-12d3-a456-42661417 000", // 内嵌空白
            "中23e4567-e89b-12d3-a456-42661417400", // 非 ASCII（字节数 38）
        ];
        for id in invalid {
            assert!(!is_valid_client_id(id), "非法 clientID {id:?} 被误放行");
        }
    }

    #[test]
    fn mac_string_validation_matches_go() {
        // 空 MAC 表示客户端未上报，必须放行（兼容旧客户端）
        assert!(is_valid_mac_string(""), "空 MAC 应放行");
        assert!(is_valid_mac_string("00:1a:2b:3c:4d:5e"));
        assert!(
            is_valid_mac_string("00:1A:2B:3C:4D:5E"),
            "大写 MAC 同样合法"
        );

        let invalid = [
            "00:1a:2b:3c:4d",       // 少一段
            "00-1a-2b-3c-4d-5e",    // 分隔符错
            "zz:1a:2b:3c:4d:5e",    // 非 hex
            "0:1a:2b:3c:4d:5e",     // 段宽 1
            "00:1a:2b:3c:4d:5e:6f", // 多一段
            "00:1a:2b:3c:4d:5e:",   // 尾随分隔符
            ":00:1a:2b:3c:4d:5e",   // 首部空段
            "00:1g:2b:3c:4d:5e",    // 段内含非 hex
            "bad\nmac-xx",          // 换行注入
            "00 :1a:2b:3c:4d:5e",   // 段内空白
        ];
        for s in invalid {
            assert!(!is_valid_mac_string(s), "非法 MAC {s:?} 被误放行");
        }
    }

    #[test]
    fn parse_mac_key_roundtrip_and_rejects_garbage() {
        assert_eq!(
            parse_mac_key("00:1a:2b:3c:4d:5e").unwrap(),
            [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]
        );
        // 大小写不敏感
        assert_eq!(
            parse_mac_key("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        // 全 0 是合法 MAC，不能与 None 混淆
        assert_eq!(parse_mac_key("00:00:00:00:00:00"), Some([0u8; 6]));

        for s in [
            "", ":", "aa:", ":aa", "aa:bb", "aa:bb:cc:dd:ee:ff:gg", "aa bb",
            "aa", "zz:11:22:33:44:55",
        ] {
            assert!(parse_mac_key(s).is_none(), "parse_mac_key({s:?}) 应失败");
        }
    }
}
