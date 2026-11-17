// ======================= 双向时钟偏移探针 wire 格式（虚拟时钟同步） =======================
//
// 与 Go clock_offset.go 逐字节对齐。用途（Phase 2 接入后生效）：为参考连接 ref
// 解出自身的去程/回程不对称度，从而去掉跨路径探针分解里被迫引入的公共偏移 δ，
// 恢复 fwd+ret=RTT 严格自洽。用"两端各留两枚时间戳"的往返探针补上缺失的方程：
//
//	A 发送 t1，B 接收 t2；B 回包发送 t3，A 接收 t4。
//	  去程 RTT 分量：t2-t1 = F + θ
//	  回程 RTT 分量：t4-t3 = B - θ
//	  其中 θ = A 时钟相对 B 的偏移。
//
// 抗指纹：与 RTT 探针同纪律——seq==0 控制帧，appendPaddedFrame 写出，节奏抖动。
//
// 载荷固定 30B：
//
//	[0]       kind    0x05 时钟偏移探针 / 0x06 回包
//	[1]       flags  必须为 0
//	[2:6]     nonce  uint32 BE，发起端关联 id
//	[6:10]    conn   uint32 BE，目标连接 index
//	[10:18]   send_ts uint64 BE，发起端发送时间戳（发送循环写入）
//	[18:26]   recv_ts uint64 BE，回包端接收时刻；探针=0，回包=填充
//	[26:30]   off_ts  uint32 BE，回包端注入时刻（UnixMilli 低 32 位，即 t3）

use crate::protocol::{CONTROL_KIND_CLOCK_PROBE, CONTROL_KIND_CLOCK_REPLY};

pub const CLOCK_OFFSET_WIRE_LEN: usize = 30;

// 字段偏移（与 Go clock_offset.go 一致）
const CLOCK_OFF_OFF_KIND: usize = 0;
const CLOCK_OFF_OFF_FLAGS: usize = 1;
const CLOCK_OFF_OFF_NONCE: usize = 2;
const CLOCK_OFF_OFF_CONN: usize = 6;
const CLOCK_OFF_OFF_SEND_TS: usize = 10;
const CLOCK_OFF_OFF_RECV_TS: usize = 18;
const CLOCK_OFF_OFF_TX: usize = 26;

/// 构建时钟偏移探针帧载荷（send_ts/recv_ts/off_ts 初始 0）。
pub fn append_clock_offset_probe_frame(dst: &mut Vec<u8>, nonce: u32, conn: u32) {
    let start = dst.len();
    dst.resize(start + CLOCK_OFFSET_WIRE_LEN, 0);
    dst[start + CLOCK_OFF_OFF_KIND] = CONTROL_KIND_CLOCK_PROBE;
    dst[start + CLOCK_OFF_OFF_FLAGS] = 0; // 必须保持 0
    dst[start + CLOCK_OFF_OFF_NONCE..start + CLOCK_OFF_OFF_NONCE + 4]
        .copy_from_slice(&nonce.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_CONN..start + CLOCK_OFF_OFF_CONN + 4]
        .copy_from_slice(&conn.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_SEND_TS..start + CLOCK_OFF_OFF_SEND_TS + 8]
        .copy_from_slice(&0u64.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_RECV_TS..start + CLOCK_OFF_OFF_RECV_TS + 8]
        .copy_from_slice(&0u64.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_TX..start + CLOCK_OFF_OFF_TX + 4]
        .copy_from_slice(&0u32.to_be_bytes());
}

/// 构建回包帧载荷，回显 nonce/send_ts，填 recv_ts（t2）与 off_ts（t3=注入时刻）。
pub fn append_clock_offset_reply_frame(
    dst: &mut Vec<u8>,
    nonce: u32,
    send_ts: u64,
    recv_ts: u64,
    tx_ts: u32,
) {
    let start = dst.len();
    dst.resize(start + CLOCK_OFFSET_WIRE_LEN, 0);
    dst[start + CLOCK_OFF_OFF_KIND] = CONTROL_KIND_CLOCK_REPLY;
    dst[start + CLOCK_OFF_OFF_FLAGS] = 0; // 必须保持 0
    dst[start + CLOCK_OFF_OFF_NONCE..start + CLOCK_OFF_OFF_NONCE + 4]
        .copy_from_slice(&nonce.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_CONN..start + CLOCK_OFF_OFF_CONN + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_SEND_TS..start + CLOCK_OFF_OFF_SEND_TS + 8]
        .copy_from_slice(&send_ts.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_RECV_TS..start + CLOCK_OFF_OFF_RECV_TS + 8]
        .copy_from_slice(&recv_ts.to_be_bytes());
    dst[start + CLOCK_OFF_OFF_TX..start + CLOCK_OFF_OFF_TX + 4]
        .copy_from_slice(&tx_ts.to_be_bytes());
}

/// 解析探针/回包帧；严格校验长度、kind 与 flags==0。
pub fn parse_clock_offset_frame(
    payload: &[u8],
) -> Result<(u8, u32, u32, u64, u64, u32), &'static str> {
    if payload.len() != CLOCK_OFFSET_WIRE_LEN {
        return Err("malformed clock offset frame: length");
    }
    let kind = payload[CLOCK_OFF_OFF_KIND];
    if kind != CONTROL_KIND_CLOCK_PROBE && kind != CONTROL_KIND_CLOCK_REPLY {
        return Err("malformed clock offset frame: kind");
    }
    if payload[CLOCK_OFF_OFF_FLAGS] != 0 {
        return Err("malformed clock offset frame: flags");
    }
    let nonce = u32::from_be_bytes(
        payload[CLOCK_OFF_OFF_NONCE..CLOCK_OFF_OFF_NONCE + 4]
            .try_into()
            .unwrap(),
    );
    let conn = u32::from_be_bytes(
        payload[CLOCK_OFF_OFF_CONN..CLOCK_OFF_OFF_CONN + 4]
            .try_into()
            .unwrap(),
    );
    let send_ts = u64::from_be_bytes(
        payload[CLOCK_OFF_OFF_SEND_TS..CLOCK_OFF_OFF_SEND_TS + 8]
            .try_into()
            .unwrap(),
    );
    let recv_ts = u64::from_be_bytes(
        payload[CLOCK_OFF_OFF_RECV_TS..CLOCK_OFF_OFF_RECV_TS + 8]
            .try_into()
            .unwrap(),
    );
    let tx_ts = u32::from_be_bytes(
        payload[CLOCK_OFF_OFF_TX..CLOCK_OFF_OFF_TX + 4]
            .try_into()
            .unwrap(),
    );
    Ok((kind, nonce, conn, send_ts, recv_ts, tx_ts))
}

/// 读循环前置拦截用：payload 是合法时钟偏移帧即返回 true。
pub fn is_clock_offset_frame(payload: &[u8]) -> bool {
    if payload.len() != CLOCK_OFFSET_WIRE_LEN {
        return false;
    }
    let k = payload[CLOCK_OFF_OFF_KIND];
    k == CONTROL_KIND_CLOCK_PROBE || k == CONTROL_KIND_CLOCK_REPLY
}

/// 发送循环在 Write 前写入发送时间戳（固定偏移）。仅探针（0x05）需要。
pub fn patch_clock_offset_send_ts(send_buffer: &mut [u8], now_ns: u64) {
    patch_clock_offset_send_ts_at(send_buffer, 0, now_ns);
}

/// 带 frame_start 的变体：探针帧可能不在 send_buffer 起始（与数据帧同批混排）。
pub fn patch_clock_offset_send_ts_at(send_buffer: &mut [u8], frame_start: usize, now_ns: u64) {
    let off = frame_start + 10 + CLOCK_OFF_OFF_SEND_TS;
    if off + 8 > send_buffer.len() {
        return;
    }
    send_buffer[off..off + 8].copy_from_slice(&now_ns.to_be_bytes());
}

/// 组合判断：任何探针类控制帧（RTT 或时钟偏移）。
pub fn is_probe_payload(payload: &[u8]) -> bool {
    is_rtt_probe_frame(payload) || is_clock_offset_frame(payload)
}

use crate::rtt_probe::is_rtt_probe_frame;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_offset_wire_format_matches_go_layout() {
        let mut buf = Vec::new();
        append_clock_offset_probe_frame(&mut buf, 0x0102_0304, 0x0000_0003);
        assert_eq!(
            hex::encode(&buf),
            "050001020304000000030000000000000000000000000000000000000000",
            "时钟偏移探针帧布局必须与 Go clock_offset.go 逐字节一致"
        );
        let (kind, nonce, conn, send_ts, recv_ts, tx_ts) =
            parse_clock_offset_frame(&buf).unwrap();
        assert_eq!(kind, CONTROL_KIND_CLOCK_PROBE);
        assert_eq!(nonce, 0x0102_0304);
        assert_eq!(conn, 3);
        assert_eq!(send_ts, 0);
        assert_eq!(recv_ts, 0);
        assert_eq!(tx_ts, 0);
        assert!(is_clock_offset_frame(&buf));
        assert!(is_probe_payload(&buf));

        let mut reply = Vec::new();
        append_clock_offset_reply_frame(
            &mut reply,
            0x0102_0304,
            0x1122_3344_5566_7788,
            0x99aa_bbcc_ddee_ff00,
            0x1234_5678,
        );
        assert_eq!(
            hex::encode(&reply),
            "06000102030400000000112233445566778899aabbccddeeff0012345678",
            "时钟偏移回包帧布局必须与 Go 逐字节一致"
        );
        let (k, n, c, s, r, tx) = parse_clock_offset_frame(&reply).unwrap();
        assert_eq!(k, CONTROL_KIND_CLOCK_REPLY);
        assert_eq!(n, 0x0102_0304);
        assert_eq!(c, 0);
        assert_eq!(s, 0x1122_3344_5566_7788);
        assert_eq!(r, 0x99aa_bbcc_ddee_ff00);
        assert_eq!(tx, 0x1234_5678);
        assert!(is_clock_offset_frame(&reply));
        assert!(is_probe_payload(&reply));

        // 严格校验：错误长度拒绝；错误 flags 被 is_* 宽松预检接受（只查 kind），
        // 但 parse 严格拒绝
        assert!(!is_clock_offset_frame(&buf[..buf.len() - 1]));
        assert!(parse_clock_offset_frame(&buf[..buf.len() - 1]).is_err());
        let mut bad = buf.clone();
        bad[1] = 1;
        assert!(parse_clock_offset_frame(&bad).is_err());
        assert!(is_clock_offset_frame(&bad), "is_* 是只查 kind 的宽松预检");
    }

    #[test]
    fn patch_clock_send_ts_writes_at_payload_offset() {
        let mut frame = vec![0u8; 10 + CLOCK_OFFSET_WIRE_LEN];
        frame[10 + CLOCK_OFF_OFF_KIND] = CONTROL_KIND_CLOCK_PROBE;
        patch_clock_offset_send_ts(&mut frame, 0x0102_0304_0506_0708);
        assert_eq!(
            &frame[20..28],
            &0x0102_0304_0506_0708u64.to_be_bytes(),
            "send_ts 必须写入帧头(10B)之后 + CLOCK_OFF_OFF_SEND_TS"
        );
        let mut tiny = vec![0u8; 5];
        patch_clock_offset_send_ts(&mut tiny, 1);
    }
}
