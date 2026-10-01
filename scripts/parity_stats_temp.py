#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:160]!r}")
    p.write_text(s.replace(old, new, 1))

# Export the shared accounting module.
replace_once(
    "src/main.rs",
    "pub mod server;\npub mod socks5;",
    "pub mod server;\npub mod stats_accounting;\npub mod socks5;",
)

# Server per-session counters live on ClientStat so retired/current sessions can
# be aggregated without inspecting writer-local state.
replace_once(
    "src/api.rs",
    "    pub tx_packets: AtomicU64,\n    pub rx_packets: AtomicU64,\n    pub force_disconnect:",
    "    pub tx_packets: AtomicU64,\n    pub rx_packets: AtomicU64,\n    pub written: crate::stats_accounting::TxFrameCounters,\n    pub fec_recovered_lifetime: AtomicU64,\n    pub fec_lost_lifetime: AtomicU64,\n    pub force_disconnect:",
)
replace_once(
    "src/api.rs",
    "            tx_packets: AtomicU64::new(0),\n            rx_packets: AtomicU64::new(0),\n            force_disconnect:",
    "            tx_packets: AtomicU64::new(0),\n            rx_packets: AtomicU64::new(0),\n            written: crate::stats_accounting::TxFrameCounters::default(),\n            fec_recovered_lifetime: AtomicU64::new(0),\n            fec_lost_lifetime: AtomicU64::new(0),\n            force_disconnect:",
)

# Client-global written/lifetime counters.
replace_once(
    "src/client.rs",
    "use crate::socks5::{split_host_port, Socks5Proxy};",
    "use crate::socks5::{split_host_port, Socks5Proxy};\nuse crate::stats_accounting::{padding_snapshot, record_padding_write, TxFrameCounters, TxFrameTotals};",
)
replace_once(
    "src/client.rs",
    "    pub tx_packets: AtomicU64,\n    pub rx_packets: AtomicU64,\n    pub live_conns:",
    "    pub tx_packets: AtomicU64,\n    pub rx_packets: AtomicU64,\n    pub written: TxFrameCounters,\n    pub fec_recovered_lifetime: AtomicU64,\n    pub fec_lost_lifetime: AtomicU64,\n    pub live_conns:",
)
replace_once(
    "src/client.rs",
    "        tx_packets: AtomicU64::new(0),\n        rx_packets: AtomicU64::new(0),\n        live_conns:",
    "        tx_packets: AtomicU64::new(0),\n        rx_packets: AtomicU64::new(0),\n        written: TxFrameCounters::default(),\n        fec_recovered_lifetime: AtomicU64::new(0),\n        fec_lost_lifetime: AtomicU64::new(0),\n        live_conns:",
)

# Preserve FEC recovery/loss across decoder rebuilds.
replace_once(
    "src/client.rs",
    "                if let Some(old) = cl.fec_dec.lock().as_ref() {\n                    old.reset();\n                }",
    "                if let Some(old) = cl.fec_dec.lock().as_ref() {\n                    let (r, l) = old.stats();\n                    cl.fec_recovered_lifetime.fetch_add(r, Ordering::Relaxed);\n                    cl.fec_lost_lifetime.fetch_add(l, Ordering::Relaxed);\n                    old.reset();\n                }",
)

# Writer: accumulate per-frame wire domains before ownership release, but commit
# counters/padding only after rustls accepts the plaintext batch.
replace_once(
    "src/client.rs",
    "        let mut tx_packets_batch = 0u64;\n        let mut last_frame_start = None;",
    "        let mut tx_packets_batch = 0u64;\n        let mut written_batch = TxFrameTotals::default();\n        let mut last_frame_start = None;",
)
replace_once(
    "src/client.rs",
    "                for f in batch.frames {\n                    let ic_ref = if f.seq != 0 { ic_tx_ref } else { None };\n                    last_frame_start = Some(append_unpadded_frame(\n                        &mut send_buf,\n                        f.seq,\n                        f.data.as_slice(),\n                        ic_ref,\n                    ));\n                    f.data.release();\n                }",
    "                for f in batch.frames {\n                    let ic_ref = if f.seq != 0 { ic_tx_ref } else { None };\n                    let before = send_buf.len();\n                    last_frame_start = Some(append_unpadded_frame(\n                        &mut send_buf,\n                        f.seq,\n                        f.data.as_slice(),\n                        ic_ref,\n                    ));\n                    written_batch.add_frame(f.seq, f.data.as_slice(), send_buf.len() - before);\n                    f.data.release();\n                }",
)
replace_once(
    "src/client.rs",
    "            if tx_packets_batch != 0 {\n                let _ = pad_stream_batch_tail(&mut send_buf, last_frame_start, pad_record_limit);\n            }",
    "            let pad_bytes_batch = if tx_packets_batch != 0 {\n                pad_stream_batch_tail(&mut send_buf, last_frame_start, pad_record_limit)\n            } else {\n                0\n            };",
)
replace_once(
    "src/client.rs",
    "            if tx_packets_batch != 0 {\n                cl.tx_packets.fetch_add(tx_packets_batch, Ordering::Relaxed);\n            }\n            cl.tx_bytes.fetch_add(wire_bytes, Ordering::Relaxed);",
    "            if tx_packets_batch != 0 {\n                cl.tx_packets.fetch_add(tx_packets_batch, Ordering::Relaxed);\n                cl.written.record(written_batch);\n                record_padding_write(send_buf.len(), pad_bytes_batch);\n            }\n            cl.tx_bytes.fetch_add(wire_bytes, Ordering::Relaxed);",
)

# Client status: expose lifetime FEC and Go #72 written-domain/padding contract.
replace_once(
    "src/client.rs",
    "        let (rec, lost) = self\n            .fec_dec\n            .lock()\n            .as_ref()\n            .map(|d| d.stats())\n            .unwrap_or((0, 0));",
    "        let (active_rec, active_lost) = self\n            .fec_dec\n            .lock()\n            .as_ref()\n            .map(|d| d.stats())\n            .unwrap_or((0, 0));\n        let rec = self.fec_recovered_lifetime.load(Ordering::Relaxed).saturating_add(active_rec);\n        let lost = self.fec_lost_lifetime.load(Ordering::Relaxed).saturating_add(active_lost);\n        let written = self.written.snapshot();\n        let (pad_wire, pad_bytes) = padding_snapshot();",
)
replace_once(
    "src/client.rs",
    '            "fec": {"enabled": self.fec_mode, "parity_tx": self.tx_port.parity_sent(), "recovered": rec, "lost": lost},',
    '            "fec": {"enabled": self.fec_mode, "parity_tx": written.parity_frames, "data_tx": written.data_frames, "control_tx": written.control_frames, "data_wire_bytes": written.data_wire_bytes, "parity_wire_bytes": written.parity_wire_bytes, "counter_domain": "written", "enabled_sessions": if self.fec_mode { 1 } else { 0 }, "tx_active_sessions": if self.fec_mode && self.live_conns.load(Ordering::Relaxed) >= 2 { 1 } else { 0 }, "rx_bypass_sessions": if self.conns_count == 1 { 1 } else { 0 }, "recovered": rec, "lost": lost},\n            "padding": {"wire_bytes": pad_wire, "pad_bytes": pad_bytes, "overhead_pct": if pad_wire > 0 { pad_bytes as f64 * 100.0 / pad_wire as f64 } else { 0.0 }},',
)
# metrics_text has its own decoder snapshot; lifetime must match JSON.
replace_once(
    "src/client.rs",
    "        let (rec, lost) = self\n            .fec_dec\n            .lock()\n            .as_ref()\n            .map(|d| d.stats())\n            .unwrap_or((0, 0));",
    "        let (active_rec, active_lost) = self\n            .fec_dec\n            .lock()\n            .as_ref()\n            .map(|d| d.stats())\n            .unwrap_or((0, 0));\n        let rec = self.fec_recovered_lifetime.load(Ordering::Relaxed).saturating_add(active_rec);\n        let lost = self.fec_lost_lifetime.load(Ordering::Relaxed).saturating_add(active_lost);",
)

# Server writer/accounting.
replace_once(
    "src/server.rs",
    "use crate::tcp_cork::TlsBatchCork;",
    "use crate::tcp_cork::TlsBatchCork;\nuse crate::stats_accounting::{padding_snapshot, record_padding_write, TxFrameTotals};",
)
replace_once(
    "src/server.rs",
    "    if let Some(old) = &epoch.fec_dec {\n        old.reset();\n    }",
    "    if let Some(old) = &epoch.fec_dec {\n        let (r, l) = old.stats();\n        session.stat.fec_recovered_lifetime.fetch_add(r, Ordering::Relaxed);\n        session.stat.fec_lost_lifetime.fetch_add(l, Ordering::Relaxed);\n        old.reset();\n    }",
)
replace_once(
    "src/server.rs",
    "    let mut pulled = 0u64;\n    let mut pulled_payload = 0u64;\n    let mut last_frame_start = None;",
    "    let mut pulled = 0u64;\n    let mut pulled_payload = 0u64;\n    let mut written_batch = TxFrameTotals::default();\n    let mut last_frame_start = None;",
)
replace_once(
    "src/server.rs",
    "        for f in batch.frames {\n            let ic_ref = if f.seq != 0 { ic_tx.as_deref() } else { None };\n            last_frame_start = Some(append_unpadded_frame(\n                &mut sess.send_buf,\n                f.seq,\n                f.data.as_slice(),\n                ic_ref,\n            ));\n            f.data.release();\n        }",
    "        for f in batch.frames {\n            let ic_ref = if f.seq != 0 { ic_tx.as_deref() } else { None };\n            let before = sess.send_buf.len();\n            last_frame_start = Some(append_unpadded_frame(\n                &mut sess.send_buf,\n                f.seq,\n                f.data.as_slice(),\n                ic_ref,\n            ));\n            written_batch.add_frame(f.seq, f.data.as_slice(), sess.send_buf.len() - before);\n            f.data.release();\n        }",
)
replace_once(
    "src/server.rs",
    "    if pulled != 0 {\n        let _ = pad_stream_batch_tail(&mut sess.send_buf, last_frame_start, sess.pad_record_limit);\n    }",
    "    let pad_bytes_batch = if pulled != 0 {\n        pad_stream_batch_tail(&mut sess.send_buf, last_frame_start, sess.pad_record_limit)\n    } else {\n        0\n    };",
)
# Move existing stats from pre-write to successful-write commit point.
replace_once(
    "src/server.rs",
    "        if let Some(s) = &sess.client_session {\n            if pulled != 0 {\n                s.stat.tx_packets.fetch_add(pulled, Ordering::Relaxed);\n            }\n            s.stat\n                .tx_bytes\n                .fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed);\n        }\n        if let Err(e) = sess.tls.writer().write_all(&sess.send_buf) {\n            debug!(\"closing session: tls plaintext writer failed: {}\", e);\n            *close = true;\n            return;\n        }",
    "        if let Err(e) = sess.tls.writer().write_all(&sess.send_buf) {\n            debug!(\"closing session: tls plaintext writer failed: {}\", e);\n            *close = true;\n            return;\n        }\n        if let Some(s) = &sess.client_session {\n            if pulled != 0 {\n                s.stat.tx_packets.fetch_add(pulled, Ordering::Relaxed);\n                s.stat.written.record(written_batch);\n                record_padding_write(sess.send_buf.len(), pad_bytes_batch);\n            }\n            s.stat\n                .tx_bytes\n                .fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed);\n        }",
)

# Server stats aggregate written and lifetime domains across sessions.
replace_once(
    "src/server.rs",
    "        let mut parity = 0u64;\n        let mut dropped = 0u64;",
    "        let mut parity = 0u64;\n        let mut data_tx = 0u64;\n        let mut control_tx = 0u64;\n        let mut data_wire = 0u64;\n        let mut parity_wire = 0u64;\n        let mut enabled_sessions = 0u64;\n        let mut tx_active_sessions = 0u64;\n        let mut rx_bypass_sessions = 0u64;\n        let mut dropped = 0u64;",
)
# Inject aggregation at the start of each session loop after its declaration.
replace_once(
    "src/server.rs",
    "        for (id, s) in sessions.iter() {\n",
    "        for (id, s) in sessions.iter() {\n            let w = s.stat.written.snapshot();\n            parity = parity.saturating_add(w.parity_frames);\n            data_tx = data_tx.saturating_add(w.data_frames);\n            control_tx = control_tx.saturating_add(w.control_frames);\n            data_wire = data_wire.saturating_add(w.data_wire_bytes);\n            parity_wire = parity_wire.saturating_add(w.parity_wire_bytes);\n            let conns = s.stat.active_conns.load(Ordering::Relaxed) as u64;\n            if s.fec_enc_k > 0 {\n                enabled_sessions += 1;\n                if conns >= 2 { tx_active_sessions += 1; }\n                if conns <= 1 { rx_bypass_sessions += 1; }\n            }\n",
)
# Existing parity += generated-attempts must not double-count the written domain.
# Replace only the assignment statement if present.
ss = Path("src/server.rs").read_text()
ss = ss.replace("            parity += s.port.parity_sent();\n", "", 1)
Path("src/server.rs").write_text(ss)
# Existing decoder stats should add lifetime values too.
ss = Path("src/server.rs").read_text()
old = "                rec += r;\n                lost += l;"
if old in ss:
    ss = ss.replace(old, "                rec += r;\n                lost += l;", 1)
# Add lifetime unconditionally once per session immediately before decoder stats if marker exists.
marker = "            if let Some(dec) = &s.epoch_state.read().fec_dec {"
if marker in ss:
    ss = ss.replace(marker, "            rec = rec.saturating_add(s.stat.fec_recovered_lifetime.load(Ordering::Relaxed));\n            lost = lost.saturating_add(s.stat.fec_lost_lifetime.load(Ordering::Relaxed));\n" + marker, 1)
Path("src/server.rs").write_text(ss)
replace_once(
    "src/server.rs",
    '            "fec": {"enabled": true, "parity_tx": parity, "recovered": rec, "lost": lost},',
    '            "fec": {"enabled": enabled_sessions > 0, "parity_tx": parity, "data_tx": data_tx, "control_tx": control_tx, "data_wire_bytes": data_wire, "parity_wire_bytes": parity_wire, "counter_domain": "written", "enabled_sessions": enabled_sessions, "tx_active_sessions": tx_active_sessions, "rx_bypass_sessions": rx_bypass_sessions, "recovered": rec, "lost": lost},\n            "padding": {"wire_bytes": padding_snapshot().0, "pad_bytes": padding_snapshot().1, "overhead_pct": if padding_snapshot().0 > 0 { padding_snapshot().1 as f64 * 100.0 / padding_snapshot().0 as f64 } else { 0.0 }},',
)

# Rust WebUI smoke fixture should exercise the new contract instead of the old
# generated-parity approximation.
p = Path("scripts/webui_browser_smoke.mjs")
s = p.read_text()
s = s.replace(
    "fec: { enabled: false, parity_tx: 0, recovered: 0, lost: 0 },",
    "fec: { enabled: false, parity_tx: 0, data_tx: 0, control_tx: 0, data_wire_bytes: 0, parity_wire_bytes: 0, counter_domain: 'written', enabled_sessions: 0, tx_active_sessions: 0, rx_bypass_sessions: 0, recovered: 0, lost: 0 },",
)
p.write_text(s)
