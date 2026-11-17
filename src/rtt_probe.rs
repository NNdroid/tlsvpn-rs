// ======================= 跨路径 RTT 探针 wire 格式（方案A） =======================
//
// 与 Go rtt_probe.go 逐字节对齐。用途（Phase 2 接入调度器后生效）：测量每条物理
// 连接的去程/回程单向时延，供去程按 min(fwd)、回程按 min(ret) 独立选路。核心是
// 跨路径探针：发起端在连接 i 发探针，对端在连接 j 回包，测得 RTT_{i,j} = fwd_i +
// ret_j；以参考连接 ref 为锚可分解相对单向时延，公共常数在 argmin 中抵消。
//
// 抗指纹：探针/回包是 seq==0 控制帧，由发送 goroutine 用 appendPaddedFrame 写出
// （逐帧随机桶尺寸 + randomPool 覆盖字节），与正常记录/keepalive 同尺寸分布。
//
// 载荷固定 18B（镜像 FEC 控制帧的固定长度纪律）：
//
//	[0]      kind    0x03 探针 / 0x04 回包
//	[1]      flags   必须为 0
//	[2:6]    nonce   uint32 BE，发起端关联 id
//	[6:10]   reply_on uint32 BE，探针=目标回包连接 index；回包=0
//	[10:18]  send_ts uint64 BE，探针=发起端发送时间戳（发送 goroutine 在
//	                  Write 前写入固定偏移）；回包=从探针回显

use crate::protocol::{CONTROL_KIND_RTT_PROBE, CONTROL_KIND_RTT_REPLY};

pub const RTT_PROBE_WIRE_LEN: usize = 18;

// 字段偏移（与 Go rtt_probe.go 一致）
const RTT_PROBE_OFF_KIND: usize = 0;
const RTT_PROBE_OFF_FLAGS: usize = 1;
const RTT_PROBE_OFF_NONCE: usize = 2;
const RTT_PROBE_OFF_REPLY_ON: usize = 6;
const RTT_PROBE_OFF_SEND_TS: usize = 10;

/// 构建探针帧载荷（send_ts 初始 0，由发送循环 patch 写入）。
pub fn append_rtt_probe_frame(dst: &mut Vec<u8>, nonce: u32, reply_on: u32) {
    let start = dst.len();
    dst.resize(start + RTT_PROBE_WIRE_LEN, 0);
    dst[start + RTT_PROBE_OFF_KIND] = CONTROL_KIND_RTT_PROBE;
    dst[start + RTT_PROBE_OFF_FLAGS] = 0; // 必须保持 0
    dst[start + RTT_PROBE_OFF_NONCE..start + RTT_PROBE_OFF_NONCE + 4]
        .copy_from_slice(&nonce.to_be_bytes());
    dst[start + RTT_PROBE_OFF_REPLY_ON..start + RTT_PROBE_OFF_REPLY_ON + 4]
        .copy_from_slice(&reply_on.to_be_bytes());
    dst[start + RTT_PROBE_OFF_SEND_TS..start + RTT_PROBE_OFF_SEND_TS + 8]
        .copy_from_slice(&0u64.to_be_bytes());
}

/// 构建回包帧载荷，回显探针的 nonce 与 send_ts。
pub fn append_rtt_reply_frame(dst: &mut Vec<u8>, nonce: u32, send_ts: u64) {
    let start = dst.len();
    dst.resize(start + RTT_PROBE_WIRE_LEN, 0);
    dst[start + RTT_PROBE_OFF_KIND] = CONTROL_KIND_RTT_REPLY;
    dst[start + RTT_PROBE_OFF_FLAGS] = 0; // 必须保持 0
    dst[start + RTT_PROBE_OFF_NONCE..start + RTT_PROBE_OFF_NONCE + 4]
        .copy_from_slice(&nonce.to_be_bytes());
    dst[start + RTT_PROBE_OFF_REPLY_ON..start + RTT_PROBE_OFF_REPLY_ON + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    dst[start + RTT_PROBE_OFF_SEND_TS..start + RTT_PROBE_OFF_SEND_TS + 8]
        .copy_from_slice(&send_ts.to_be_bytes());
}

/// 解析探针/回包帧；严格校验长度、kind 与 flags==0。
pub fn parse_rtt_probe_frame(payload: &[u8]) -> Result<(u8, u32, u32, u64), &'static str> {
    if payload.len() != RTT_PROBE_WIRE_LEN {
        return Err("malformed rtt probe frame: length");
    }
    let kind = payload[RTT_PROBE_OFF_KIND];
    if kind != CONTROL_KIND_RTT_PROBE && kind != CONTROL_KIND_RTT_REPLY {
        return Err("malformed rtt probe frame: kind");
    }
    if payload[RTT_PROBE_OFF_FLAGS] != 0 {
        return Err("malformed rtt probe frame: flags");
    }
    let nonce = u32::from_be_bytes(
        payload[RTT_PROBE_OFF_NONCE..RTT_PROBE_OFF_NONCE + 4]
            .try_into()
            .unwrap(),
    );
    let reply_on = u32::from_be_bytes(
        payload[RTT_PROBE_OFF_REPLY_ON..RTT_PROBE_OFF_REPLY_ON + 4]
            .try_into()
            .unwrap(),
    );
    let send_ts = u64::from_be_bytes(
        payload[RTT_PROBE_OFF_SEND_TS..RTT_PROBE_OFF_SEND_TS + 8]
            .try_into()
            .unwrap(),
    );
    Ok((kind, nonce, reply_on, send_ts))
}

/// 读循环前置拦截用：payload 是合法探针/回包帧即返回 true。不校验 flags/长度
/// 之外的字段，失败一律当作非探针帧（走原有 FEC 控制路径）。
pub fn is_rtt_probe_frame(payload: &[u8]) -> bool {
    if payload.len() != RTT_PROBE_WIRE_LEN {
        return false;
    }
    let k = payload[RTT_PROBE_OFF_KIND];
    k == CONTROL_KIND_RTT_PROBE || k == CONTROL_KIND_RTT_REPLY
}

/// 发送循环在 Write 前写入发送时间戳（固定偏移）。仅探针（0x03）需要；回包
/// （0x04）保留回显值。send_buffer 为 appendPaddedFrame 输出，探针载荷起点 = 10
/// （帧头）。
pub fn patch_rtt_probe_send_ts(send_buffer: &mut [u8], now_ns: u64) {
    let off = 10 + RTT_PROBE_OFF_SEND_TS;
    if off + 8 > send_buffer.len() {
        return;
    }
    send_buffer[off..off + 8].copy_from_slice(&now_ns.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_probe_wire_format_matches_go_layout() {
        let mut buf = Vec::new();
        append_rtt_probe_frame(&mut buf, 0x0102_0304, 0x0000_0002);
        assert_eq!(
            hex::encode(&buf),
            "030001020304000000020000000000000000",
            "探针帧布局必须与 Go rtt_probe.go 逐字节一致"
        );
        let (kind, nonce, reply_on, send_ts) = parse_rtt_probe_frame(&buf).unwrap();
        assert_eq!(kind, CONTROL_KIND_RTT_PROBE);
        assert_eq!(nonce, 0x0102_0304);
        assert_eq!(reply_on, 2);
        assert_eq!(send_ts, 0);
        assert!(is_rtt_probe_frame(&buf));

        let mut reply = Vec::new();
        append_rtt_reply_frame(&mut reply, 0x0102_0304, 0x1122_3344_5566_7788);
        assert_eq!(
            hex::encode(&reply),
            "040001020304000000001122334455667788",
            "回包帧布局必须与 Go 逐字节一致"
        );
        let (k, n, r, s) = parse_rtt_probe_frame(&reply).unwrap();
        assert_eq!(k, CONTROL_KIND_RTT_REPLY);
        assert_eq!(n, 0x0102_0304);
        assert_eq!(r, 0);
        assert_eq!(s, 0x1122_3344_5566_7788);
        assert!(is_rtt_probe_frame(&reply));

        // 严格校验：错误长度拒绝；错误 flags 被 is_* 宽松预检接受（只查 kind），
        // 但 parse 严格拒绝
        assert!(!is_rtt_probe_frame(&buf[..buf.len() - 1]));
        assert!(parse_rtt_probe_frame(&buf[..buf.len() - 1]).is_err());
        let mut bad = buf.clone();
        bad[1] = 1;
        assert!(parse_rtt_probe_frame(&bad).is_err());
        assert!(is_rtt_probe_frame(&bad), "is_* 是只查 kind 的宽松预检");
    }

    #[test]
    fn patch_send_ts_writes_at_payload_offset() {
        // 模拟 appendPaddedFrame 输出：10B 帧头 + 18B 载荷
        let mut frame = vec![0u8; 10 + RTT_PROBE_WIRE_LEN];
        frame[10 + RTT_PROBE_OFF_KIND] = CONTROL_KIND_RTT_PROBE;
        patch_rtt_probe_send_ts(&mut frame, 0x0102_0304_0506_0708);
        assert_eq!(
            &frame[20..28],
            &0x0102_0304_0506_0708u64.to_be_bytes(),
            "send_ts 必须写入帧头(10B)之后 + RTT_PROBE_OFF_SEND_TS"
        );
        // 越界安全
        let mut tiny = vec![0u8; 5];
        patch_rtt_probe_send_ts(&mut tiny, 1);
    }
}
