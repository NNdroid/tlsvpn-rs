// Derived WebUI metric corrections shared with tlsvpn.
// Loaded after app.js so these formulas can correct legacy dashboard semantics
// without changing the stats wire contract.
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
    const dropped = num(data && data.dropped_frames);
    const fec = data && data.fec ? data.fec : {};
    const parityTx = num(fec.parity_tx);
    const dataTxPackets = Math.max(0, c.txPackets - parityTx);
    const txAttempts = c.txPackets + dropped;
    const recovered = num(fec.recovered);
    const lost = num(fec.lost);
    const missing = recovered + lost;
    return {
      txPackets: c.txPackets,
      rxPackets: c.rxPackets,
      dataTxPackets: dataTxPackets,
      parityTx: parityTx,
      avgPacketBytes: c.rxPackets > 0 ? c.rxBytes / c.rxPackets : null,
      txDropPct: txAttempts > 0 ? dropped / txAttempts * 100 : null,
      fecOverheadPct: dataTxPackets > 0 ? parityTx / dataTxPackets * 100 : null,
      fecRecoveryPct: missing > 0 ? recovered / missing * 100 : null
    };
  }

  rttStats = function (rows) {
    const v = rows.map(function (r) { return r.rtt; })
      .filter(function (x) { return x > 0 && x < 100000; });
    if (!v.length) return null;
    v.sort(function (a, b) { return a - b; });
    const avg = v.reduce(function (a, b) { return a + b; }, 0) / v.length;
    const i = Math.max(0, Math.ceil(v.length * 0.95) - 1);
    return {n: v.length, avg: avg, p95: v[i], max: v[v.length - 1], min: v[0]};
  };

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
    if (q.avgPacketBytes !== null) out.push(chip(t('ov.avgpkt'), fmtBytes(Math.round(q.avgPacketBytes))));
    if (q.txDropPct !== null) {
      const d = q.txDropPct;
      out.push(chip(t('ov.drop_pct'), d.toFixed(3) + '%', d > 1 ? 'bad' : (d > 0 ? 'warn' : 'good')));
    }
    const fec = data && data.fec ? data.fec : {};
    if (fec.enabled && q.fecRecoveryPct !== null) {
      const p = q.fecRecoveryPct;
      out.push(chip(t('ov.fec_eff'), p.toFixed(1) + '%', num(fec.lost) > 0 ? 'warn' : 'good'));
    }
    const fecOverhead = document.getElementById('fec-overhead');
    if (fecOverhead) fecOverhead.innerText = q.fecOverheadPct === null ? '-' : q.fecOverheadPct.toFixed(1) + '%';
    const el = document.getElementById('conn-quality');
    if (el) el.innerHTML = out.join('');
  };

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
        const p = schedPrev[key];
        const valid = !!p && dt > 0 && assigned >= p.assigned && batches >= p.batches;
        const dBytes = valid ? assigned - p.assigned : 0;
        const dBatches = valid ? batches - p.batches : 0;
        schedPrev[key] = {assigned: assigned, batches: batches};
        const view = {sampled: valid, assignBps: valid ? dBytes / dt : 0, batchPs: valid ? dBatches / dt : 0, deltaBytes: dBytes, share: 0};
        schedView[key] = view;
        samples.push({s: s, view: view});
        totalDelta += dBytes;
      } else {
        samples.push({s: s, view: schedView[key] || {sampled: false, assignBps: 0, batchPs: 0, deltaBytes: 0, share: 0}});
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
    const tip = t('sched.cumulative') + ': ' + fmtBytes(num(s.assigned_bytes)) + ' / ' + num(s.assigned_batches) + ' ' + t('sched.batch_unit');
    return '<div class="sched-cell" title="' + esc(tip) + '"><span class="badge ' + cls + '">' + esc(state) + '</span><small class="dim">' + esc(meta) + '</small></div>';
  };

  function setSchedWords(obj, words) {
    if (!obj) return;
    obj.sched = obj.sched || {};
    Object.keys(words).forEach(function (k) { obj.sched[k] = words[k]; });
  }

  try {
    if (I18N['zh-CN']) {
      I18N['zh-CN'].ov.fec_eff = 'FEC 恢复率'; I18N['zh-CN'].ov.avgpkt = '平均接收帧大小'; I18N['zh-CN'].ov.drop_pct = '发送丢帧率';
      setSchedWords(I18N['zh-CN'], {assign:'分配', capacity:'路径容量', qeta:'队列 ETA', batches:'批次', cumulative:'累计分配', batch_unit:'批', alloc_total:'调度'});
    }
    if (I18N['zh-TW']) {
      I18N['zh-TW'].ov.fec_eff = 'FEC 復原率'; I18N['zh-TW'].ov.avgpkt = '平均接收幀大小'; I18N['zh-TW'].ov.drop_pct = '傳送丟幀率';
      setSchedWords(I18N['zh-TW'], {assign:'分配', capacity:'路徑容量', qeta:'佇列 ETA', batches:'批次', cumulative:'累計分配', batch_unit:'批', alloc_total:'排程'});
    }
    if (I18N.en) {
      I18N.en.ov.fec_eff = 'FEC recovery rate'; I18N.en.ov.avgpkt = 'Avg RX frame size'; I18N.en.ov.drop_pct = 'TX frame drop rate';
      setSchedWords(I18N.en, {assign:'assigned', capacity:'path capacity', qeta:'queue ETA', batches:'batches', cumulative:'lifetime assigned', batch_unit:'batches', alloc_total:'scheduled'});
    }
    if (I18N.de) setSchedWords(I18N.de, {assign:'Zuweisung', capacity:'Pfadkapazität', qeta:'Queue-ETA', batches:'Batches', cumulative:'kumuliert', batch_unit:'Batches', alloc_total:'geplant'});
    if (I18N.fr) setSchedWords(I18N.fr, {assign:'affecté', capacity:'capacité chemin', qeta:'ETA file', batches:'lots', cumulative:'cumul affecté', batch_unit:'lots', alloc_total:'planifié'});
    if (I18N.ja) setSchedWords(I18N.ja, {assign:'割当', capacity:'パス容量', qeta:'キュー ETA', batches:'バッチ', cumulative:'累積割当', batch_unit:'バッチ', alloc_total:'スケジュール'});
  } catch (_) {}
})();
