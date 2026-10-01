#!/usr/bin/env python3
from pathlib import Path

p = Path("src/client.rs")
s = p.read_text()
old = "        let mut written_batch = TxFrameTotals::default();\n        let mut last_frame_start = None;"
new = "        let mut written_batch = TxFrameTotals::default();\n        let mut pad_bytes_batch = 0usize;\n        let mut last_frame_start = None;"
if old not in s:
    raise SystemExit("client writer totals marker not found")
s = s.replace(old, new, 1)
old = "            let pad_bytes_batch = if tx_packets_batch != 0 {\n                pad_stream_batch_tail(&mut send_buf, last_frame_start, pad_record_limit)\n            } else {\n                0\n            };"
new = "            pad_bytes_batch = if tx_packets_batch != 0 {\n                pad_stream_batch_tail(&mut send_buf, last_frame_start, pad_record_limit)\n            } else {\n                0\n            };"
if old not in s:
    raise SystemExit("client padding assignment marker not found")
p.write_text(s.replace(old, new, 1))
