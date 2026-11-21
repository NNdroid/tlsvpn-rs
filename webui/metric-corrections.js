// Shared WebUI metric corrections for the Go and Rust implementations.
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
    if(data && data.global_tx_packets!==undefined) c.txPackets=num(data.global_tx_packets);
    if(data && data.global_rx_packets!==undefined) c.rxPackets=num(data.global_rx_packets);
    if(data && data.global_rx_bytes!==undefined) c.rxBytes=num(data.global_rx_bytes);
    const dropped = num(data && data.dropped_frames);
    const fec = data && data.fec ? data.fec : {};
    const written = fec.counter_domain === 'written';
    const parityTx = num(fec.parity_tx);
    const dataTxPackets = written ? num(fec.data_tx) : null;
    const txAttempts = c.txPackets + dropped;
    const recovered = num(fec.recovered), lost = num(fec.lost);
    const missing = recovered + lost;
    const dataWire = num(fec.data_wire_bytes), parityWire = num(fec.parity_wire_bytes);
    return {
      txPackets:c.txPackets, rxPackets:c.rxPackets, dataTxPackets:dataTxPackets, parityTx:parityTx,
      avgPacketBytes:c.rxPackets>0?c.rxBytes/c.rxPackets:null,
      txDropPct:txAttempts>0?dropped/txAttempts*100:null,
      fecOverheadPct:written && dataWire>0?parityWire/dataWire*100:null,
      fecRecoveryPct:missing>0?recovered/missing*100:null
    };
  }
  globalThis.dashboardQualityStats = qualityStats;

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
    // reorder gap 超时冲刷：乱序严重度的直接信号（后端 reorder.timeout_flushes），
    // >0 才占位，说明有帧等到了 50ms 窗口上限才放行。
    const ro = data && data.reorder ? data.reorder : {};
    if (num(ro.timeout_flushes) > 0) {
      out.push(chip(t('ov.tflush'), fmtNum(ro.timeout_flushes), 'warn'));
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
    const state=document.getElementById('fec-state');
    if(state) state.innerText=fec.counter_domain==='written'?
      t('stats.fec_state').replace('{enabled}',num(fec.enabled_sessions)).replace('{tx}',num(fec.tx_active_sessions)).replace('{bypass}',num(fec.rx_bypass_sessions)):'-';
  };

  // Data scheduler counters and FEC parity counters are lifetime monotonic.
  // Keep lifetime assigned counters only as cumulative diagnostics/tooltips; the
  // live scheduler cells below must use interval deltas, never lifetime totals.
  // Convert both into deltas over the actual snapshot interval. assigned_* keeps
  // its original data-only meaning for scheduler tests; the WebUI displays the
  // actual transport assignment (DATA + FEC), so standby parity paths no longer
  // look idle while they are carrying real bytes.
  const schedPrev = {};
  const schedView = {};
  let schedLastAt = 0;
  let schedInstance = null;

  function schedulerKey(mode, c, i) {
    if (c.conn_id) return c.conn_id;
    return mode === 'server'
      ? String(c.client_id || '') + '|' + String(c.remote || '')
      : String(i) + '|' + String(c.target || '') + '|' + String(c.remote || '');
  }

  function annotateSchedulers(data, fresh) {
    const mode = data && data.mode;
    const list = mode === 'server' ? (data.server_conns || []) : (data.conns || []);
    const now = data.sample_time_ms === undefined ? performance.now() : Number(data.sample_time_ms);
    if(data.instance_id && schedInstance!==data.instance_id) {
      Object.keys(schedPrev).forEach(k=>delete schedPrev[k]);Object.keys(schedView).forEach(k=>delete schedView[k]);
      schedLastAt=0;schedInstance=data.instance_id;
    }
    const dt = fresh && schedLastAt ? Math.max(0.001, (now - schedLastAt) / 1000) : 0;
    const samples = [];
    const groupTotals = {};
    const present = new Set();

    list.forEach(function (c, i) {
      const s = c.scheduler || (c.scheduler = {});
      const key = schedulerKey(mode, c, i);
      present.add(key);
      const group = mode==='server'?String(c.client_id||''):'local';
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
        samples.push({s: s, view: view, group:group});
        groupTotals[group]=(groupTotals[group]||0)+dBytes;
      } else {
        samples.push({s: s, view: schedView[key] || {
          sampled: false, assignBps: 0, batchPs: 0, dataBps: 0, dataBatchPs: 0,
          fecBps: 0, fecBatchPs: 0, deltaBytes: 0, share: 0
        }});
      }
    });

    if (fresh) {
      samples.forEach(function (x) {const total=groupTotals[x.group]||0;x.view.share=total>0?x.view.deltaBytes/total*100:0;});
      Object.keys(schedPrev).forEach(k=>{if(!present.has(k)){delete schedPrev[k];delete schedView[k];}});
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
      // backend eta_us is the last scheduling-decision estimate and can remain
      // stale after a drain. Show queue-drain ETA from current queue + rate EWMA.
      // Before the first rate sample, mirror the scheduler's 200 Mbps fallback.
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

  schedulerCell = function (s, stalled) {
    if (!s) return '<span class="dim">-</span>';
    // stalled 必须保留：连接被调度器判定不健康时独立于 active/standby 展示。
    // 此前本覆盖丢掉了第二参数，失效连接显示成普通待命（回归）。
    if (stalled) return '<div class="sched-cell"><span class="badge b-off" title="' + esc(t('sched.stalled_tip')) + '">' + esc(t('sched.stalled')) + '</span><small class="dim">' + esc(t('sched.stalled_note')) + '</small></div>';
    const cls = s.active ? 'b-on' : 'b-off';
    const state = s.active ? t('sched.active') : t('sched.standby');
    const capacity = num(s.rate_mbps);
    const sampled = !!s._sampled;
    const alloc = sampled ? fmtBytes(num(s._assign_bps), true) : '-';
    const share = sampled ? num(s._share_pct).toFixed(1) + '%' : '-';
    const batchRate = sampled ? num(s._batch_ps).toFixed(num(s._batch_ps) < 10 ? 1 : 0) + '/s' : '-';
    const eta = fmtSchedulerEta(num(s._queue_eta_us));
    // 双向时钟偏移 θ/U（schedulerConnJSON，ns/µs）：只在收敛时显示。θ 的可信度
    // 直接决定 fwd/ret 单向拆分的置信度，是判断探针读数能不能当真用的关键。
    // θ ns→µs 后走 fmtMsUs；U 本身已是 µs。符号显式带出（偏移可负）。
    let clock = '';
    if (s.clock_offset_converged && s.clock_offset_ns !== undefined) {
      const thUS = Number(s.clock_offset_ns) / 1000; // ns→µs（可为小数/负数）
      clock = ' · θ ' + fmtMsUs(thUS) + 'ms ± U ' + fmtMsUs(num(s.clock_offset_unc_us)) + 'ms';
    }
    const meta = t('sched.queue') + ' ' + fmtBytes(num(s.queued_bytes)) + ' · ' +
      t('sched.assign') + ' ' + alloc + ' (' + share + ') · ' +
      t('sched.capacity') + ' ' + (capacity ? capacity.toFixed(capacity < 10 ? 1 : 0) + ' Mbps' : '-') +
      // 容量权重（deliver_rate_mbps）：饱和门控测得的路径容量，WFQ 容量加权
      // 的实际权重来源。仅在测得饱和窗后显示（0=未测得，权重走公平启动费率，
      // 此时显示 "-" 会让人误以为权重为零）。与上面"负载写入 EWMA"并置才能
      // 看出非饱和路径"被喂速率 ≠ 容量"的差别。
      (num(s.deliver_rate_mbps) > 0 ? ' · ' + t('sched.weight') + ' ' + num(s.deliver_rate_mbps).toFixed(num(s.deliver_rate_mbps) < 10 ? 1 : 0) + ' Mbps' : '') + ' · ' +
      t('sched.qeta') + ' ' + eta + ' · ' + t('sched.batches') + ' ' + batchRate +
      (s.carry_pending ? ' · ' + t('sched.carry') : '') + clock;
    // TCP 重传（最近 200ms 采样窗的差分）：时延地板对丢包不敏感，重传是
    // "正在丢段"的独立信号。>0 才显示，避免稳态路径的常驻噪音。meta 整体
    // 走 esc()，着色片段必须在转义之外单独拼接（否则显示成字面 <span>）。
    let retransHtml = '';
    if (num(s.retrans_delta) > 0) {
      retransHtml = ' · <span style="color:var(--err)">' + esc(t('sched.retrans')) + ' ×' + num(s.retrans_delta) + '</span>';
    }
    // 探针连续超时（黑洞嫌疑）：与重传并列的健康警告——写进本地发送缓冲成功
    // 但对端收不到，旧 decayed-min 地板对它钝感，选路已按 streak 抬升其排名键。
    let probeToHtml = '';
    if (num(s.probe_timeout_streak) > 0) {
      probeToHtml = ' · <span style="color:var(--err)">' + esc(t('sched.probe_to')) + ' ×' + num(s.probe_timeout_streak) + '</span>';
    }
    const totalBytes = num(s.assigned_bytes) + num(s.fec_assigned_bytes);
    const totalBatches = num(s.assigned_batches) + num(s.fec_assigned_batches);
    const tip = t('sched.cumulative') + ': ' + fmtBytes(totalBytes) + ' / ' + totalBatches + ' ' + t('sched.batch_unit') +
      ' | DATA ' + fmtBytes(num(s.assigned_bytes)) + ' / ' + num(s.assigned_batches) +
      ' | FEC ' + fmtBytes(num(s.fec_assigned_bytes)) + ' / ' + num(s.fec_assigned_batches) +
      (num(s.retrans_delta) > 0 ? ' | ' + t('sched.retrans') + ' ×' + num(s.retrans_delta) + ' (' + t('sched.retrans_tip') + ')' : '') +
      (num(s.probe_timeout_streak) > 0 ? ' | ' + t('sched.probe_to') + ' ×' + num(s.probe_timeout_streak) + ' (' + t('sched.probe_to_tip') + ')' : '') + clock;
    return '<div class="sched-cell" title="' + esc(tip) + '"><span class="badge ' + cls + '">' + esc(state) + '</span><small class="dim">' + esc(meta) + retransHtml + probeToHtml + '</small></div>';
  };
})();
