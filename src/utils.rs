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

/// CIDR 形态校验，接受域与 Go 的 net.ParseCIDR 对齐：裸 IP 也算合法（无
/// 前缀时按主机位全 0 处理）。v4_cidr / v6_cidr 必须在这里断掉垃圾值——
/// parse_v4_cidr / parse_v6_cidr 遇到不可解析的地址会静默回落到默认网段，
/// 结果是地址池悄悄变成 10.0.0.0/24 之类的东西。
pub fn is_valid_cidr(s: &str, v6: bool) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let (ip, bits) = match s.split_once('/') {
        Some((a, b)) => match b.trim().parse::<u32>() {
            Ok(bits) => (a.trim(), Some(bits)),
            Err(_) => return false,
        },
        None => (s, None),
    };
    if v6 {
        ip.parse::<Ipv6Addr>().is_ok() && bits.map_or(true, |n| n <= 128)
    } else {
        ip.parse::<Ipv4Addr>().is_ok() && bits.map_or(true, |n| n <= 32)
    }
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

/// 解析配置里的 `mac`：空串 = 未配置（Ok(None)）。格式非法或本地位被置位
/// 返回 Err，拒绝条件与 Go net_linux.go setTapMac 一致。
///
/// 客户端与服务端都用它，但错误处理不同：客户端要把这个值写进握手声明给
/// 服务端，值错会让服务端把本端自己的帧当外来帧丢掉（src_mac_allowed），
/// 所以按硬错误处理；服务端只改自己 TAP 的地址，值错只该告警。
pub fn parse_config_mac(s: &str) -> Result<Option<[u8; 6]>, String> {
    if s.is_empty() {
        return Ok(None);
    }
    let Some(m) = parse_mac_key(s) else {
        return Err(format!(
            "无效的 mac 配置值 {:?}（须为 aa:bb:cc:dd:ee:ff）",
            s
        ));
    };
    if m[0] & 1 != 0 {
        return Err(format!(
            "mac 配置值 {:?} 的本地位被置位（组播/广播地址），无法作为 TAP 地址",
            s
        ));
    }
    Ok(Some(m))
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

/// 在 tap 上配置隧道地址的 `ip` 子命令序列（不含 `ip` 本身）。
///
/// 顺序本身就是行为要求，动它等于把用户实际撞上的问题再造一遍：
///   * bind 要求接口处于 IFF_UP，所以必须先 up 再挂地址；
///   * v6 地址在接口 up 的瞬间会重新触发一次 DAD——先挂地址再 up，
///     web.bind=tunnel 的第一轮绑定就白等一整个探测窗口；
///   * v6 地址由对端显式分配（或配置指定为网关），没有需要探测的重复地址，
///     所以加 `nodad` 让地址挂上即生效。不加的话，拿不到 RA 时地址会一直停在
///     tentative，面板的 `[fd00::1]:8080` 就永久 bind 不上；
///   * 用 `replace` 而不是 `add`：地址还在（进程重启、会话重建）时 `add` 报
///     "File exists" 而配不上。
pub fn tap_addr_cmds<'a>(tap: &'a str, v4cidr: &'a str, v6cidr: &'a str) -> Vec<Vec<&'a str>> {
    let mut out = vec![vec!["link", "set", "dev", tap, "up"]];
    if v4cidr != "/" && !v4cidr.is_empty() {
        out.push(vec!["addr", "replace", v4cidr, "dev", tap]);
    }
    if v6cidr != "/" && !v6cidr.is_empty() {
        out.push(vec!["-6", "addr", "replace", "nodad", v6cidr, "dev", tap]);
    }
    out
}

/// 逐条执行上面的命令并报告失败。
///
/// 地址配不上时隧道网关不可达，web.bind=tunnel 会对着一个不存在的地址反复
/// bind 失败。以前静默丢弃退出码，表现只能是"面板连不上"，看不到原因。
#[cfg(target_os = "linux")]
pub fn apply_ip_cmds(cmds: &[Vec<&str>]) {
    use std::process::Command;
    for cmd in cmds {
        let what = cmd.join(" ");
        match Command::new("ip").args(cmd).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                let detail = if err.is_empty() {
                    format!("exit {}", o.status)
                } else {
                    err
                };
                tracing::warn!("ip {what} failed: {detail}");
            }
            Err(e) => tracing::warn!("ip {what} failed: {e}"),
        }
    }
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

    #[test]
    fn parse_config_mac_empty_ok_and_rejects_garbage_or_local_bit() {
        // 未配置：空串是合法的"没设置"，不能与解析失败混淆
        assert_eq!(parse_config_mac("").unwrap(), None);
        // 全 0 合法且必须与 None 区分（否则会被当成"没设置"）
        assert_eq!(
            parse_config_mac("00:00:00:00:00:00").unwrap(),
            Some([0u8; 6])
        );
        assert_eq!(
            parse_config_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert!(parse_config_mac("AA:BB:CC:DD:EE:FF").unwrap().is_some());

        for s in [
            "aa:bb:cc:dd:ee",         // 少一段
            "aa:bb:cc:dd:ee:ff:00",   // 多一段
            "zz:11:22:33:44:55",      // 非 hex
            "aa:bb:cc:dd:ee:ff:",     // 尾随冒号
            "1", "aa bb", "00:1a:2b:3c:4d",
        ] {
            assert!(
                parse_config_mac(s).is_err(),
                "parse_config_mac({s:?}) 应返回 Err"
            );
        }
        // 本地位置位 = 组播/广播地址，不能作为 TAP 地址（对齐 Go setTapMac）
        for s in [
            "01:00:5e:00:00:01",
            "ff:ff:ff:ff:ff:ff",
            "45:aa:bb:cc:dd:ee",
            "a1:00:00:00:00:00",
        ] {
            let err = parse_config_mac(s).unwrap_err();
            assert!(
                err.contains("本地位"),
                "parse_config_mac({s:?}) 应拒绝组播地址，实际: {err}"
            );
        }
    }

    #[test]
    fn is_valid_cidr_accepts_bare_ips_and_rejects_garbage() {
        // 与 Go net.ParseCIDR 一致：裸 IP 合法
        for s in [
            "10.0.0.0/24", "10.0.0.1", "127.0.0.0/8", "192.168.1.0/32",
            " fd00::/64 ", "fd00::1", "::ffff:10.0.0.0/120",
        ] {
            let v6 = s.trim().contains(':');
            assert!(is_valid_cidr(s, v6), "合法 CIDR {s:?} 被误拒");
        }
        for s in [
            "", "  ", "10.0.0.0/33", "10.0.0.0/", "/24", "10.0.0.0/24/",
            "10.0.0.0/-1", "10.0.0.0/abc", "not-a-cidr", "10.0.0.256/24",
            "256.0.0.0/8", "fd00::zzz/64", "fd00::/129", "::ffff:10.0.0.0/200",
            "10.0.0.0/128",
        ] {
            let v6 = s.trim().contains(':');
            assert!(!is_valid_cidr(s, v6), "非法 CIDR {s:?} 被误放行");
        }
        // 跨族：同一串在两个族下都要给出符合预期的答案
        assert!(is_valid_cidr("10.0.0.0/24", false));
        assert!(is_valid_cidr("fd00::/64", true));
        assert!(!is_valid_cidr("10.0.0.0/24", true));
        assert!(!is_valid_cidr("fd00::/64", false));
        // "fd00::/128" 对 v4 来说前缀超界
        assert!(!is_valid_cidr("10.0.0.0/128", false));
    }

    #[test]
    fn tap_addr_cmds_brings_the_link_up_first_and_marks_v6_nodad() {
        let cmds = tap_addr_cmds("tap0", "10.0.0.1/24", "fd00::1/64");
        assert_eq!(cmds.len(), 3);

        // 第一条必须是 link up：bind 要求 IFF_UP，且 v6 地址在接口 up 的瞬间
        // 会重新触发 DAD，先挂地址再 up 会让 web.bind=tunnel 白等一个探测窗口
        assert_eq!(cmds[0], &["link", "set", "dev", "tap0", "up"][..]);
        assert_eq!(cmds[1], &["addr", "replace", "10.0.0.1/24", "dev", "tap0"][..]);

        // v6：nodad 让地址挂上即生效（拿不到 RA 时一直 tentative，v6 面板绑定
        // 永久失败）；replace 而不是 add（地址还在时 add 报 File exists）
        let v6 = &cmds[2];
        assert!(v6.contains(&"nodad"), "v6 必须带 nodad: {v6:?}");
        assert!(v6.contains(&"replace"), "必须用 replace: {v6:?}");
        assert!(!v6.contains(&"add"), "不能是 add: {v6:?}");
        assert!(!cmds[1].contains(&"add"), "v4 也不能是 add: {cmds:?}");

        // "/" 是"未配置"哨兵，对应族不应产生任何命令
        assert_eq!(tap_addr_cmds("tap0", "/", "").len(), 1);
        assert_eq!(tap_addr_cmds("tap0", "10.0.0.1/24", "/").len(), 2);
    }
}
