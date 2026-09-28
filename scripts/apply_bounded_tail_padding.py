#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    return text.replace(old, new, 1)

p = Path("src/frame.rs")
s = p.read_text()

s = replace_once(
    s,
    "pub const STREAM_TLS_BATCH_SOFT_LIMIT: usize = 12 * 1024;\npub const MAX_TLS_PLAINTEXT_RECORD: usize = 16 * 1024;\n",
    "pub const STREAM_TLS_BATCH_SOFT_LIMIT: usize = 12 * 1024;\npub const MAX_TLS_PLAINTEXT_RECORD: usize = 16 * 1024;\n\n// MSS alignment is a shaping hint only. TCP is already a continuous byte\n// stream, so do not burn a large fraction of useful traffic just to make one\n// application batch end exactly on an MSS boundary.\npub const STREAM_PAD_RATIO_PERCENT: usize = 10;\npub const STREAM_PAD_ABSOLUTE_LIMIT: usize = 512;\n",
    "padding constants",
)

anchor = """/// Add cover bytes only to the final frame of an aggregated plaintext batch.\n/// This aligns the conservative TLS ciphertext budget to N*TCP_MSS while\n/// bounding padding to less than one MSS.\n"""
insert = """pub fn stream_padding_budget(batch_len: usize) -> usize {\n    if batch_len == 0 {\n        return 0;\n    }\n    (batch_len * STREAM_PAD_RATIO_PERCENT / 100).min(STREAM_PAD_ABSOLUTE_LIMIT)\n}\n\n/// Add cover bytes only to the final frame of an aggregated plaintext batch.\n/// Alignment is accepted only when the required cover fits the bounded traffic\n/// budget. Otherwise the real bytes are sent unchanged and TCP naturally lets\n/// the next write fill the previous segment's remaining space.\n"""
s = replace_once(s, anchor, insert, "budget function")

s = replace_once(
    s,
    """    if pad_len == 0 || pad_len > u16::MAX as usize {\n        return 0;\n    }\n    let old_pad = BigEndian::read_u16(&buf[start + 4..start + 6]) as usize;\n""",
    """    if pad_len == 0 || pad_len > u16::MAX as usize {\n        return 0;\n    }\n    if pad_len > stream_padding_budget(buf.len()) {\n        return 0;\n    }\n    let old_pad = BigEndian::read_u16(&buf[start + 4..start + 6]) as usize;\n""",
    "budget check",
)

old_test = """    #[test]\n    fn stream_padding_only_touches_last_frame() {\n        let _g = crate::crypto::PAD_TEST_LOCK\n            .lock()\n            .unwrap_or_else(|e| e.into_inner());\n        let prev = crate::crypto::pad_mode_name();\n        let _ = crate::crypto::set_pad_mode(\"bucket\");\n        let mut buf = Vec::new();\n        let _first = append_unpadded_frame(&mut buf, 1, &vec![0u8; 700], None);\n        let last = append_unpadded_frame(&mut buf, 2, &vec![0u8; 700], None);\n        assert_eq!(BigEndian::read_u16(&buf[4..6]), 0);\n        let before = buf.len();\n        let pad = pad_stream_batch_tail(&mut buf, Some(last), mss_padding_record_limit(1440));\n        assert!(pad > 0 && buf.len() > before);\n        assert_eq!(BigEndian::read_u16(&buf[last + 4..last + 6]) as usize, pad);\n        assert_eq!((buf.len() + TLS_RECORD_OVERHEAD_RESERVE) % 1440, 0);\n        let _ = crate::crypto::set_pad_mode(&prev);\n    }\n"""
new_test = """    #[test]\n    fn stream_padding_budget_is_bounded() {\n        assert_eq!(stream_padding_budget(1500), 150);\n        assert_eq!(stream_padding_budget(10000), STREAM_PAD_ABSOLUTE_LIMIT);\n    }\n\n    #[test]\n    fn stream_padding_skips_wasteful_single_mtu_batch() {\n        let _g = crate::crypto::PAD_TEST_LOCK\n            .lock()\n            .unwrap_or_else(|e| e.into_inner());\n        let prev = crate::crypto::pad_mode_name();\n        let _ = crate::crypto::set_pad_mode(\"bucket\");\n        let mut buf = Vec::new();\n        let last = append_unpadded_frame(&mut buf, 1, &vec![0u8; 1500], None);\n        let before = buf.len();\n        let pad = pad_stream_batch_tail(&mut buf, Some(last), mss_padding_record_limit(1440));\n        assert_eq!(pad, 0);\n        assert_eq!(buf.len(), before);\n        assert_eq!(BigEndian::read_u16(&buf[last + 4..last + 6]), 0);\n        let _ = crate::crypto::set_pad_mode(&prev);\n    }\n\n    #[test]\n    fn stream_padding_only_touches_last_frame_when_cheap() {\n        let _g = crate::crypto::PAD_TEST_LOCK\n            .lock()\n            .unwrap_or_else(|e| e.into_inner());\n        let prev = crate::crypto::pad_mode_name();\n        let _ = crate::crypto::set_pad_mode(\"bucket\");\n        let mut buf = Vec::new();\n        let _first = append_unpadded_frame(&mut buf, 1, &vec![0u8; 4990], None);\n        let last = append_unpadded_frame(&mut buf, 2, &vec![0u8; 4990], None);\n        assert_eq!(BigEndian::read_u16(&buf[4..6]), 0);\n        let before = buf.len();\n        let pad = pad_stream_batch_tail(&mut buf, Some(last), mss_padding_record_limit(1440));\n        assert!(pad > 0 && pad <= stream_padding_budget(before));\n        assert_eq!(BigEndian::read_u16(&buf[last + 4..last + 6]) as usize, pad);\n        assert_eq!((buf.len() + TLS_RECORD_OVERHEAD_RESERVE) % 1440, 0);\n        let _ = crate::crypto::set_pad_mode(&prev);\n    }\n"""
s = replace_once(s, old_test, new_test, "stream padding tests")

p.write_text(s)
