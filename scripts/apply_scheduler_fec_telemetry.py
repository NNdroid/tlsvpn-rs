#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {n}: {old[:80]!r}")
    p.write_text(s.replace(old, new, 1))

replace_once("src/adaptive_multipath.rs",
'''    pub assigned_bytes: AtomicU64,\n    pub assigned_batches: AtomicU64,\n    pub virtual_finish_ns: AtomicI64,\n''',
'''    pub assigned_bytes: AtomicU64,\n    pub assigned_batches: AtomicU64,\n    pub fec_assigned_bytes: AtomicU64,\n    pub fec_assigned_batches: AtomicU64,\n    pub virtual_finish_ns: AtomicI64,\n''')

replace_once("src/adaptive_multipath.rs",
'''            assigned_bytes: AtomicU64::new(0),\n            assigned_batches: AtomicU64::new(0),\n            virtual_finish_ns: AtomicI64::new(0),\n''',
'''            assigned_bytes: AtomicU64::new(0),\n            assigned_batches: AtomicU64::new(0),\n            fec_assigned_bytes: AtomicU64::new(0),\n            fec_assigned_batches: AtomicU64::new(0),\n            virtual_finish_ns: AtomicI64::new(0),\n''')

replace_once("src/adaptive_multipath.rs",
'''    pub fn note_assigned(&self, n: u64) {\n        if n != 0 {\n            self.assigned_bytes.fetch_add(n, Ordering::Relaxed);\n            self.assigned_batches.fetch_add(1, Ordering::Relaxed);\n        }\n    }\n\n''',
'''    pub fn note_assigned(&self, n: u64) {\n        if n != 0 {\n            self.assigned_bytes.fetch_add(n, Ordering::Relaxed);\n            self.assigned_batches.fetch_add(1, Ordering::Relaxed);\n        }\n    }\n\n    #[inline]\n    pub fn note_fec_assigned(&self, n: u64) {\n        if n != 0 {\n            self.fec_assigned_bytes.fetch_add(n, Ordering::Relaxed);\n            self.fec_assigned_batches.fetch_add(1, Ordering::Relaxed);\n        }\n    }\n\n''')

replace_once("src/adaptive_multipath.rs",
'''            assigned_bytes: self.assigned_bytes.load(Ordering::Relaxed),\n            assigned_batches: self.assigned_batches.load(Ordering::Relaxed),\n''',
'''            assigned_bytes: self.assigned_bytes.load(Ordering::Relaxed),\n            assigned_batches: self.assigned_batches.load(Ordering::Relaxed),\n            fec_assigned_bytes: self.fec_assigned_bytes.load(Ordering::Relaxed),\n            fec_assigned_batches: self.fec_assigned_batches.load(Ordering::Relaxed),\n''')

replace_once("src/adaptive_multipath.rs",
'''    pub assigned_bytes: u64,\n    pub assigned_batches: u64,\n}\n''',
'''    pub assigned_bytes: u64,\n    pub assigned_batches: u64,\n    pub fec_assigned_bytes: u64,\n    pub fec_assigned_batches: u64,\n}\n''')

# FEC parity deliberately uses a different physical path. Count it only after
# that path accepted the payload; keep normal assigned_* data-only.
p = Path("src/net.rs")
s = p.read_text()
pat = re.compile(r'''self\.parity_sent\.fetch_add\(1, Ordering::Relaxed\);\n(?P<indent>\s*)let par = FramePayload::Owned\(par\);\n(?P=indent)if let Some\(idx\) = self\.parity_backend_index\(&backends, data_idx\) \{\n(?P=indent)    self\.send_payload_to\(&backends\[idx\], 0, par\);''')
m = pat.search(s)
if not m:
    raise SystemExit("src/net.rs: parity send path not found")
indent = m.group('indent')
rep = f'''self.parity_sent.fetch_add(1, Ordering::Relaxed);\n{indent}let parity_bytes = par.len() as u64;\n{indent}let par = FramePayload::Owned(par);\n{indent}if let Some(idx) = self.parity_backend_index(&backends, data_idx) {{\n{indent}    let dropped = self.send_payload_to(&backends[idx], 0, par);\n{indent}    if dropped == 0 {{\n{indent}        backends[idx].scheduler.note_fec_assigned(parity_bytes);\n{indent}    }}'''
s = s[:m.start()] + rep + s[m.end():]
p.write_text(s)

# Keep the shared WebUI metric code identical to Go: total displayed assignment
# is DATA + FEC while both cumulative components remain separately observable.
p = Path("webui/metrics.js")
s = p.read_text()
start = s.index("  // assigned_bytes/assigned_batches are lifetime monotonic counters.")
end = s.rindex("})();")
new_block = r'''  // Data scheduler counters and FEC parity counters are lifetime monotonic.
  // Convert both into deltas over the actual snapshot interval. assigned_* keeps
  // its original data-only meaning for scheduler tests; the WebUI displays the
  // actual transport assignment (DATA + FEC), so standby parity paths no longer
  // look idle while they are carrying real bytes.
  const schedPrev = {};
  const schedView = {};
  let schedLastAt = 0;

  function schedulerKey(mode, c, i) {
    if (c.conn_id) return c.conn_id;
    return mode === 'server'
      ? String(c.client_id || '') + '|' + String(c.remote || '')
      : String(i) + '|' + String(c.target || '') + '|' + String(c.remote || '');
  }

  function annotateSchedulers(data, fresh) {
    const mode = data && data.mode;
    const list = mode === 'server' ? (data.server_conns || []) : (data.conns || []);
    const now = performance.now();
    const dt = fresh && schedLastAt ? Math.max(0.001, (now - schedLastAt) / 1000) : 0;
    const samples = [];
    let totalDelta = 0;

    list.forEach(function (c, i) {
      const s = c.scheduler || (c.scheduler = {});
      const key = schedulerKey(mode, c, i);
      if (fresh) {
        const assigned = num(s.assigned_bytes);
        const batches = num(s.assigned_batches);
        const fecAssigned = num(s.fec_assigned_bytes);
        const fecBatches = num(s.fec_assigned_batches);
        const p = schedPrev[key];
        const valid = !!p && dt > 0 &&
          assigned >= p.assigned && batches >= p.batches &&
          fecAssigned >= p.fecAssigned && fecBatches >= p.fecBatches;
        const dDataBytes = valid ? assigned - p.assigned : 0;
        const dDataBatches = valid ? batches - p.batches : 0;
        const dFecBytes = valid ? fecAssigned - p.fecAssigned : 0;
        const dFecBatches = valid ? fecBatches - p.fecBatches : 0;
        const dBytes = dDataBytes + dFecBytes;
        const dBatches = dDataBatches + dFecBatches;
        schedPrev[key] = {assigned: assigned, batches: batches, fecAssigned: fecAssigned, fecBatches: fecBatches};
        const view = {
          sampled: valid,
          assignBps: valid ? dBytes / dt : 0,
          batchPs: valid ? dBatches / dt : 0,
          dataBps: valid ? dDataBytes / dt : 0,
          dataBatchPs: valid ? dDataBatches / dt : 0,
          fecBps: valid ? dFecBytes / dt : 0,
          fecBatchPs: valid ? dFecBatches / dt : 0,
          deltaBytes: dBytes,
          share: 0
        };
        schedView[key] = view;
        samples.push({s: s, view: view});
        totalDelta += dBytes;
      } else {
        samples.push({s: s, view: schedView[key] || {
          sampled: false, assignBps: 0, batchPs: 0, dataBps: 0, dataBatchPs: 0,
          fecBps: 0, fecBatchPs: 0, deltaBytes: 0, share: 0
        }});
      }
    });

    if (fresh) {
      samples.forEach(function (x) { x.view.share = totalDelta > 0 ? x.view.deltaBytes / totalDelta * 100 : 0; });
      schedLastAt = now;
    }

    let totalAssignBps = 0;
    samples.forEach(function (x) {
      const s = x.s, v = x.view;
      s._sampled = v.sampled;
      s._assign_bps = v.assignBps;
      s._batch_ps = v.batchPs;
      s._data_assign_bps = v.dataBps;
      s._data_batch_ps = v.dataBatchPs;
      s._fec_assign_bps = v.fecBps;
      s._fec_batch_ps = v.fecBatchPs;
      s._share_pct = v.share;
      const rateBytes = num(s.rate_mbps) > 0 ? num(s.rate_mbps) * 1000000 / 8 : 25000000;
      s._queue_eta_us = rateBytes > 0 ? num(s.queued_bytes) * 1000000 / rateBytes : 0;
      totalAssignBps += v.assignBps;
    });
    return totalAssignBps;
  }

  const legacyRenderConnsTable = renderConnsTable;
  renderConnsTable = function (data, fresh) {
    const totalAssignBps = annotateSchedulers(data || {}, !!fresh);
    const out = legacyRenderConnsTable(data, fresh);
    const ss = document.getElementById('scheduler-summary');
    if (ss && totalAssignBps > 0) ss.textContent += ' · ' + t('sched.alloc_total') + ' ' + fmtBytes(totalAssignBps, true);
    return out;
  };

  schedulerCell = function (s) {
    if (!s) return '<span class="dim">-</span>';
    const cls = s.active ? 'b-on' : 'b-off';
    const state = s.active ? t('sched.active') : t('sched.standby');
    const capacity = num(s.rate_mbps);
    const sampled = !!s._sampled;
    const alloc = sampled ? fmtBytes(num(s._assign_bps), true) : '-';
    const share = sampled ? num(s._share_pct).toFixed(1) + '%' : '-';
    const batchRate = sampled ? num(s._batch_ps).toFixed(num(s._batch_ps) < 10 ? 1 : 0) + '/s' : '-';
    const eta = fmtSchedulerEta(num(s._queue_eta_us));
    const meta = t('sched.queue') + ' ' + fmtBytes(num(s.queued_bytes)) + ' · ' +
      t('sched.assign') + ' ' + alloc + ' (' + share + ') · ' +
      t('sched.capacity') + ' ' + (capacity ? capacity.toFixed(capacity < 10 ? 1 : 0) + ' Mbps' : '-') + ' · ' +
      t('sched.qeta') + ' ' + eta + ' · ' + t('sched.batches') + ' ' + batchRate +
      (s.carry_pending ? ' · ' + t('sched.carry') : '');
    const totalBytes = num(s.assigned_bytes) + num(s.fec_assigned_bytes);
    const totalBatches = num(s.assigned_batches) + num(s.fec_assigned_batches);
    const tip = t('sched.cumulative') + ': ' + fmtBytes(totalBytes) + ' / ' + totalBatches + ' ' + t('sched.batch_unit') +
      ' | DATA ' + fmtBytes(num(s.assigned_bytes)) + ' / ' + num(s.assigned_batches) +
      ' | FEC ' + fmtBytes(num(s.fec_assigned_bytes)) + ' / ' + num(s.fec_assigned_batches);
    return '<div class="sched-cell" title="' + esc(tip) + '"><span class="badge ' + cls + '">' + esc(state) + '</span><small class="dim">' + esc(meta) + '</small></div>';
  };
'''
p.write_text(s[:start] + new_block + s[end:])

# Unit test the snapshot semantics at the counter layer.
p = Path("src/adaptive_multipath.rs")
s = p.read_text()
s += r'''

#[cfg(test)]
mod fec_assignment_telemetry_tests {
    use super::*;

    #[test]
    fn fec_assignment_is_reported_separately_from_data() {
        let s = SchedulerBackendState::default();
        s.note_assigned(1200);
        s.note_fec_assigned(300);
        let snap = s.snapshot();
        assert_eq!(snap.assigned_bytes, 1200);
        assert_eq!(snap.assigned_batches, 1);
        assert_eq!(snap.fec_assigned_bytes, 300);
        assert_eq!(snap.fec_assigned_batches, 1);
    }
}
'''
p.write_text(s)

Path("tests/scheduler_fec_telemetry_contract.rs").write_text(r'''use std::fs;

#[test]
fn parity_send_updates_scheduler_fec_telemetry() {
    let root = env!("CARGO_MANIFEST_DIR");
    let net = fs::read_to_string(format!("{root}/src/net.rs")).unwrap();
    assert!(net.contains("let parity_bytes = par.len() as u64;"));
    assert!(net.contains("scheduler.note_fec_assigned(parity_bytes)"));

    let metrics = fs::read_to_string(format!("{root}/webui/metrics.js")).unwrap();
    assert!(metrics.contains("fec_assigned_bytes"));
    assert!(metrics.contains("dDataBytes + dFecBytes"));
}
''')
