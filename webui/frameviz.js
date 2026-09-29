(() => {
  'use strict';

  const root = document.getElementById('pane-status');
  if (!root || document.getElementById('frameviz-card')) return;

  const lang = localStorage.getItem('tlsvpn_lang') || 'zh-CN';
  const dict = {
    'zh-CN': {
      title:'帧格式示例', sub:'当前数据面协议 · 聚合写入 · 非实时抓包', example:'1514 B Ethernet 数据帧（启用内层 AEAD）',
      header:'10 B 帧头', cipher:'1514 B 密文', tag:'16 B AEAD Tag', tail:'仅 batch 尾帧可选 Padding',
      hdesc:'固定大端序：[dataLen:u32][padLen:u16][seq:u32]。本例 dataLen=1514+16=1530；普通数据帧 padLen=0；seq=42。',
      cdesc:'seq>0 时按协商算法执行内层 AEAD。密文主体与 Ethernet 帧等长；AAD = dataLen(4B BE) || seq(4B BE)。',
      tdesc:'当前 AES-256-GCM、AES-128-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305 均使用 16 B 认证标签。',
      pdesc:'数据面不再逐帧做 bucket padding。多个 TLSVPN 帧先聚合；只有本次 TLS plaintext batch 的最后一帧可能增加 padLen。所需 padding 必须同时不超过 batch 有效字节的 10% 和 512 B，否则保持 padLen=0。',
      batch:'TLS plaintext batch（软上限 12 KiB）', b1:'Frame #42 · padLen=0', b2:'Frame #43 · padLen=0', b3:'Final frame · padLen=N',
      flow:'Ethernet → AEAD(+16B) → 10B TLSVPN header → 多帧聚合 → 尾帧可选 MSS 对齐 padding → TLS Write',
      note:'TLS plaintext 最大 16 KiB。尾部 padding 只用于接近 TCP MSS 对齐，并受 10% / 512 B 双重预算限制。seq=0 的握手/控制/心跳不使用内层 AEAD；控制帧仍可按 pad_mode 使用独立 bucket/off 填充。',
      nonce:'Nonce：AES-GCM / ChaCha20 = seq(4BE)||salt(8B)；XChaCha20 = 派生 20B prefix||seq(4BE)。'
    },
    'zh-TW': {
      title:'訊框格式範例', sub:'目前資料面協定 · 聚合寫入 · 非即時封包擷取', example:'1514 B Ethernet 資料幀（啟用內層 AEAD）',
      header:'10 B 訊框標頭', cipher:'1514 B 密文', tag:'16 B AEAD Tag', tail:'僅 batch 尾幀可選 Padding',
      hdesc:'固定大端序：[dataLen:u32][padLen:u16][seq:u32]。本例 dataLen=1530；一般資料幀 padLen=0；seq=42。',
      cdesc:'seq>0 時使用協商的內層 AEAD；AAD = dataLen(4B BE) || seq(4B BE)。',
      tdesc:'目前支援的所有內層 AEAD 都使用 16 B 驗證標籤。',
      pdesc:'資料面不再逐幀 bucket padding。多個 TLSVPN 幀先聚合，只有 TLS plaintext batch 的最後一幀可能增加 padLen；padding 同時受 10% batch 有效位元組與 512 B 上限限制。',
      batch:'TLS plaintext batch（軟上限 12 KiB）', b1:'Frame #42 · padLen=0', b2:'Frame #43 · padLen=0', b3:'Final frame · padLen=N',
      flow:'Ethernet → AEAD(+16B) → 10B TLSVPN header → 多幀聚合 → 尾幀可選 MSS 對齊 padding → TLS Write',
      note:'TLS plaintext 最大 16 KiB。seq=0 的握手/控制/心跳不使用內層 AEAD；控制幀仍可依 pad_mode 使用獨立 bucket/off 填充。',
      nonce:'Nonce：AES-GCM / ChaCha20 = seq(4BE)||salt(8B)；XChaCha20 = 衍生 20B prefix||seq(4BE)。'
    },
    en: {
      title:'Frame format example', sub:'Current data plane · aggregated writes · not a live capture', example:'1514 B Ethernet data frame with inner AEAD',
      header:'10 B header', cipher:'1514 B ciphertext', tag:'16 B AEAD tag', tail:'Optional padding on batch tail only',
      hdesc:'Fixed big-endian header: [dataLen:u32][padLen:u16][seq:u32]. Here dataLen=1514+16=1530; ordinary data frames use padLen=0; seq=42.',
      cdesc:'For seq>0 the negotiated inner AEAD is used. AAD = dataLen(4B BE) || seq(4B BE).',
      tdesc:'AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 and XChaCha20-Poly1305 all use a 16 B authentication tag.',
      pdesc:'The data plane no longer bucket-pads every frame. Multiple TLSVPN frames are aggregated first; only the final frame of the TLS plaintext batch may receive padLen. Padding must fit both the 10% useful-batch budget and the 512 B absolute cap.',
      batch:'TLS plaintext batch (12 KiB soft limit)', b1:'Frame #42 · padLen=0', b2:'Frame #43 · padLen=0', b3:'Final frame · padLen=N',
      flow:'Ethernet → AEAD(+16B) → 10B TLSVPN header → aggregate frames → optional MSS-alignment tail padding → TLS Write',
      note:'TLS plaintext is capped at 16 KiB. Tail padding is only an MSS-alignment hint and is skipped when it exceeds the budget. seq=0 handshake/control/heartbeat frames bypass inner AEAD; standalone control frames may still use bucket/off padding from pad_mode.',
      nonce:'Nonce: AES-GCM / ChaCha20 = seq(4BE)||salt(8B); XChaCha20 = derived 20B prefix||seq(4BE).'
    }
  };
  const s = dict[lang] || dict.en;

  const card = document.createElement('div');
  card.id = 'frameviz-card';
  card.className = 'st-block frameviz-card';
  card.innerHTML = `
    <style>
      .frameviz-card{column-span:all;margin-top:4px}.fv-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap}.fv-sub{font-size:.78rem;color:var(--muted)}
      .fv-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:12px 0}.fv-mini{border:1px solid var(--border);border-radius:10px;padding:10px}.fv-mini span{display:block;color:var(--muted);font-size:.74rem}.fv-mini b{display:block;margin-top:4px;font:600 .91rem var(--mono,monospace)}
      .fv-track{display:flex;min-height:72px;border:1px solid var(--border);border-radius:10px;overflow:hidden}.fv-seg{padding:10px 8px;border-right:1px solid var(--border);background:color-mix(in srgb,var(--card) 80%,var(--accent) 20%)}.fv-seg:last-child{border-right:0}.fv-seg b,.fv-seg small{display:block}.fv-seg small{margin-top:5px;color:var(--muted);font-family:var(--mono,monospace)}
      .fv-h{flex:0 0 18%}.fv-c{flex:1 1 55%}.fv-t{flex:0 0 17%}.fv-p{flex:0 0 20%;background:color-mix(in srgb,var(--card) 88%,var(--warn) 12%)}
      .fv-descs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:10px}.fv-desc{border:1px solid var(--border);border-radius:9px;padding:9px;color:var(--muted);font-size:.8rem;line-height:1.45}.fv-desc b{display:block;color:var(--fg);margin-bottom:4px}
      .fv-batch{margin-top:12px;border:1px solid var(--border);border-radius:10px;padding:10px}.fv-batch-title{font-size:.78rem;color:var(--muted);margin-bottom:7px}.fv-batch-row{display:flex;gap:5px;min-width:560px}.fv-batch-row span{flex:1;border:1px solid var(--border);border-radius:8px;padding:9px;text-align:center;font:12px var(--mono,monospace)}.fv-batch-row span:last-child{border-style:dashed}.fv-scroll{overflow-x:auto}.fv-flow,.fv-note{margin-top:9px;color:var(--muted);font-size:.79rem;line-height:1.5}.fv-flow{font-family:var(--mono,monospace);color:var(--fg)}
      @media(max-width:720px){.fv-kpis,.fv-descs{grid-template-columns:1fr 1fr}.fv-track{min-width:620px}.fv-scroll{overflow-x:auto}}
    </style>
    <div class="fv-head"><div><h3>${s.title}</h3><div class="fv-sub">${s.sub}</div></div><div class="fv-sub">${s.example}</div></div>
    <div class="fv-kpis">
      <div class="fv-mini"><span>header</span><b>10 B</b></div>
      <div class="fv-mini"><span>dataLen</span><b>1530 B</b></div>
      <div class="fv-mini"><span>padLen</span><b>0 B / tail N</b></div>
      <div class="fv-mini"><span>batch</span><b>≤ 12 KiB soft</b></div>
    </div>
    <div class="fv-scroll"><div class="fv-track">
      <div class="fv-seg fv-h"><b>${s.header}</b><small>dataLen | padLen | seq</small></div>
      <div class="fv-seg fv-c"><b>${s.cipher}</b><small>Ethernet payload</small></div>
      <div class="fv-seg fv-t"><b>${s.tag}</b><small>dataLen includes tag</small></div>
      <div class="fv-seg fv-p"><b>${s.tail}</b><small>0..min(10%, 512 B)</small></div>
    </div></div>
    <div class="fv-descs">
      <div class="fv-desc"><b>${s.header}</b>${s.hdesc}</div>
      <div class="fv-desc"><b>${s.cipher}</b>${s.cdesc}</div>
      <div class="fv-desc"><b>${s.tag}</b>${s.tdesc}</div>
      <div class="fv-desc"><b>${s.tail}</b>${s.pdesc}</div>
    </div>
    <div class="fv-batch"><div class="fv-batch-title">${s.batch}</div><div class="fv-scroll"><div class="fv-batch-row"><span>${s.b1}</span><span>${s.b2}</span><span>${s.b3}</span></div></div></div>
    <div class="fv-flow">${s.flow}</div><div class="fv-note">${s.note}</div><div class="fv-note">${s.nonce}</div>`;

  const host = root.querySelector('.status-grid') || root;
  host.appendChild(card);
})();
