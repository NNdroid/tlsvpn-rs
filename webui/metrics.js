// Derived WebUI metric corrections shared with tlsvpn.
// Loaded after app.js so these small, testable formulas replace the legacy
// dashboard implementations without changing the stats wire contract.
(function () {
  'use strict';

  function num(v) {
    v = Number(v || 0);
    return Number.isFinite(v) && v >= 0 ? v : 0;
  }

  function aggregateClientCounters(data) {
    let txBytes = 0, rxBytes = 0, txPackets = 0, rxPackets = 0;
    const clients = data && data.clients && typeof data.clients === 'object' ? data.clients : {};
    Object.keys(clients).forEach(function (id) {
      const c = clients[id] || {};
      txBytes += num(c.tx_bytes);
      rxBytes += num(c.rx_bytes);
      txPackets += num(c.tx_packets);
      rxPackets += num(c.rx_packets);
    });
    return {txBytes: txBytes, rxBytes: rxBytes, txPackets: txPackets, rxPackets: rxPackets};
  }

  function qualityStats(data) {
    const c = aggregateClientCounters(data || {});
    const packets = c.txPackets + c.rxPackets;
    const bytes = c.txBytes + c.rxBytes;
    const queueDropped = num(data && data.dropped_frames);
    const txAttempts = c.txPackets + queueDropped;
    const fec = data && data.fec ? data.fec : {};
    const recovered = num(fec.recovered);
    const lost = num(fec.lost);
    const missing = recovered + lost;
    return {
      packets: packets,
      avgPacketBytes: packets > 0 ? bytes / packets : null,
      // dropped_frames is the TX/input-queue drop counter. Keep the denominator
      // in the same domain: successful TX frames + queue-dropped TX frames.
      queueDropPct: txAttempts > 0 ? queueDropped / txAttempts * 100 : null,
      // recovered/lost are both receive-side FEC outcomes. Do not divide them by
      // locally transmitted parity, which is the opposite traffic direction.
      fecRecoveryPct: missing > 0 ? recovered / missing * 100 : null
    };
  }

  // Nearest-rank percentile: rank=ceil(P*N), then convert the 1-based rank to
  // a zero-based array index. The old floor(N*.95) returned P100 for N=20.
  rttStats = function (rows) {
    const v = rows.map(function (r) { return r.rtt; })
      .filter(function (x) { return x > 0 && x < 100000; });
    if (!v.length) return null;
    v.sort(function (a, b) { return a - b; });
    const avg = v.reduce(function (a, b) { return a + b; }, 0) / v.length;
    const i = Math.max(0, Math.ceil(v.length * 0.95) - 1);
    return {n: v.length, avg: avg, p95: v[i], max: v[v.length - 1], min: v[0]};
  };

  // dgRun historically read skipped_frames/gap_events from drop_breakdown even
  // though the backend publishes those fields in data.reorder. Preserve the
  // rest of dgRun unchanged and feed each value from the matching source. The
  // top-level dropped_frames fallback also keeps Rust's queue-drop diagnostic
  // useful while older stats payloads do not contain drop_breakdown.
  const legacyDgRun = dgRun;
  dgRun = function (data) {
    if (!data || typeof data !== 'object') return legacyDgRun(data);
    const fixed = Object.assign({}, data);
    const reorder = data.reorder || {};
    const breakdown = data.drop_breakdown || {};
    fixed.drop_breakdown = Object.assign({}, breakdown, {
      backpressure: breakdown.backpressure === undefined ? num(data.dropped_frames) : num(breakdown.backpressure),
      reorder: breakdown.reorder === undefined ? num(reorder.dropped_frames) : num(breakdown.reorder),
      skipped_frames: num(reorder.skipped_frames),
      gap_events: num(reorder.gap_events)
    });
    return legacyDgRun(fixed);
  };

  renderConnQuality = function (data, rtt) {
    const q = qualityStats(data || {});
    const out = [];
    if (rtt) {
      out.push(chip(t('ov.rtt'), t('ov.rtt_n').replace('{n}', rtt.n)));
      out.push(chip(t('ov.avg'), Math.round(rtt.avg) + ' ms'));
      out.push(chip(t('ov.p95'), Math.round(rtt.p95) + ' ms'));
    } else {
      out.push(chip(t('ov.rtt'), '-'));
    }
    if (q.avgPacketBytes !== null) {
      out.push(chip(t('ov.avgpkt'), fmtBytes(Math.round(q.avgPacketBytes))));
    }
    if (q.queueDropPct !== null) {
      const d = q.queueDropPct;
      out.push(chip(t('ov.drop_pct'), d.toFixed(3) + '%', d > 1 ? 'bad' : (d > 0 ? 'warn' : 'good')));
    }
    const fec = data && data.fec ? data.fec : {};
    if (fec.enabled && q.fecRecoveryPct !== null) {
      const p = q.fecRecoveryPct;
      out.push(chip(t('ov.fec_eff'), p.toFixed(1) + '%', num(fec.lost) > 0 ? 'warn' : 'good'));
    }
    const el = document.getElementById('conn-quality');
    if (el) el.innerHTML = out.join('');
  };

  // The old label said “efficiency” even though the corrected statistic is the
  // receive-side recovered/(recovered+lost) ratio.
  try {
    if (I18N['zh-CN']) I18N['zh-CN'].ov.fec_eff = 'FEC 恢复率';
    if (I18N['zh-TW']) I18N['zh-TW'].ov.fec_eff = 'FEC 復原率';
    if (I18N.en) I18N.en.ov.fec_eff = 'FEC recovery rate';
    if (I18N.de) I18N.de.ov.fec_eff = 'FEC-Wiederherstellungsrate';
    if (I18N.fr) I18N.fr.ov.fec_eff = 'Taux de récupération FEC';
    if (I18N.ja) I18N.ja.ov.fec_eff = 'FEC 復元率';
  } catch (_) {}
})();
