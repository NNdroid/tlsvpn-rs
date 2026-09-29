(() => {
  'use strict';
  const root=document.getElementById('pane-status');
  if(!root||document.getElementById('frameviz-card'))return;

  const lang=localStorage.getItem('tlsvpn_lang')||'zh-CN';
  const L={
    'zh-CN':{title:'帧格式示例',sub:'当前数据面协议 · 聚合写入 · 非实时抓包',example:'1514 B Ethernet 数据帧（启用内层 AEAD）',header:'帧头',cipher:'密文',tag:'认证标签',tail:'仅 batch 尾帧可选 Padding',batch:'TLS plaintext batch',detail:'协议细节'},
    'zh-TW':{title:'訊框格式範例',sub:'目前資料面協定 · 聚合寫入 · 非即時封包擷取',example:'1514 B Ethernet 資料幀（啟用內層 AEAD）',header:'訊框標頭',cipher:'密文',tag:'驗證標籤',tail:'僅 batch 尾幀可選 Padding',batch:'TLS plaintext batch',detail:'協定細節'},
    en:{title:'Frame format example',sub:'Current data plane · aggregated writes · not a live capture',example:'1514 B Ethernet data frame with inner AEAD',header:'Header',cipher:'Ciphertext',tag:'Authentication tag',tail:'Optional padding on batch tail only',batch:'TLS plaintext batch',detail:'Protocol details'},
    de:{title:'Beispiel für Frame-Format',sub:'Aktueller Datenpfad · aggregierte Writes · kein Live-Mitschnitt',example:'1514-B-Ethernet-Datenframe mit innerem AEAD',header:'Header',cipher:'Chiffretext',tag:'Authentifizierungs-Tag',tail:'Optionales Padding nur am Batch-Ende',batch:'TLS-Plaintext-Batch',detail:'Protokolldetails'},
    fr:{title:'Exemple de format de trame',sub:'Plan de données actuel · écritures agrégées · pas une capture en direct',example:'Trame Ethernet 1514 o avec AEAD interne',header:'En-tête',cipher:'Texte chiffré',tag:'Tag d’authentification',tail:'Padding optionnel en fin de batch',batch:'Batch TLS en clair',detail:'Détails du protocole'},
    ja:{title:'フレーム形式の例',sub:'現在のデータプレーン · 集約 Write · ライブキャプチャではありません',example:'内部 AEAD を使用する 1514 B Ethernet データフレーム',header:'ヘッダー',cipher:'暗号文',tag:'認証タグ',tail:'batch 末尾のみ任意 Padding',batch:'TLS plaintext batch',detail:'プロトコル詳細'}
  };
  const s=L[lang]||L.en;
  const card=document.createElement('div');
  card.id='frameviz-card';
  card.className='st-block frameviz-card';
  card.innerHTML=`
    <style>
      .frameviz-card{column-span:all;margin-top:4px}.fv-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap}.fv-sub{font-size:.78rem;color:var(--muted)}
      .fv-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:12px 0}.fv-mini,.fv-desc,.fv-batch{border:1px solid var(--border);border-radius:10px;padding:10px}.fv-mini span{display:block;color:var(--muted);font-size:.74rem}.fv-mini b{display:block;margin-top:4px;font:600 .91rem var(--mono,monospace)}
      .fv-track{display:flex;min-width:620px;min-height:72px;border:1px solid var(--border);border-radius:10px;overflow:hidden}.fv-seg{padding:10px 8px;border-right:1px solid var(--border);background:color-mix(in srgb,var(--card) 80%,var(--accent) 20%)}.fv-seg:last-child{border-right:0}.fv-seg b,.fv-seg small{display:block}.fv-seg small{margin-top:5px;color:var(--muted);font-family:var(--mono,monospace)}.fv-h{flex:0 0 18%}.fv-c{flex:1}.fv-t{flex:0 0 17%}.fv-p{flex:0 0 22%}
      .fv-descs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:10px}.fv-desc{color:var(--muted);font-size:.8rem;line-height:1.5}.fv-desc b{display:block;color:var(--fg);margin-bottom:4px}.fv-batch{margin-top:10px}.fv-batch-row{display:flex;gap:5px;min-width:560px;margin-top:7px}.fv-batch-row span{flex:1;border:1px solid var(--border);border-radius:8px;padding:9px;text-align:center;font:12px var(--mono,monospace)}.fv-batch-row span:last-child{border-style:dashed}.fv-scroll{overflow-x:auto}.fv-flow,.fv-note{margin-top:9px;color:var(--muted);font-size:.79rem;line-height:1.5}.fv-flow{font-family:var(--mono,monospace);color:var(--fg)}
      @media(max-width:720px){.fv-kpis,.fv-descs{grid-template-columns:1fr 1fr}}
    </style>
    <div class="fv-head"><div><h3>${s.title}</h3><div class="fv-sub">${s.sub}</div></div><div class="fv-sub">${s.example}</div></div>
    <div class="fv-kpis"><div class="fv-mini"><span>header</span><b>10 B</b></div><div class="fv-mini"><span>dataLen</span><b>1530 B</b></div><div class="fv-mini"><span>padLen</span><b>0 B / tail N</b></div><div class="fv-mini"><span>batch</span><b>≤ 12 KiB soft</b></div></div>
    <div class="fv-scroll"><div class="fv-track"><div class="fv-seg fv-h"><b>${s.header}</b><small>[dataLen:u32][padLen:u16][seq:u32]</small></div><div class="fv-seg fv-c"><b>${s.cipher}</b><small>1514 B Ethernet frame</small></div><div class="fv-seg fv-t"><b>${s.tag}</b><small>16 B AEAD tag</small></div><div class="fv-seg fv-p"><b>${s.tail}</b><small>0..min(10%, 512 B)</small></div></div></div>
    <div class="fv-descs">
      <div class="fv-desc"><b>${s.header}</b>Fixed 10 B big-endian header. Example: dataLen=1514+16=1530, ordinary data frame padLen=0, seq=42. dataLen includes the AEAD tag and excludes padding.</div>
      <div class="fv-desc"><b>Inner AEAD</b>AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305. AAD = dataLen (4 B BE) || seq (4 B BE). Every current algorithm uses a 16 B authentication tag.</div>
      <div class="fv-desc"><b>${s.tail}</b>Data frames are aggregated first. Only the final frame of a TLS plaintext batch may receive cover bytes. Required padding is accepted only when it is ≤ 10% of useful batch bytes and ≤ 512 B; otherwise padLen remains 0.</div>
      <div class="fv-desc"><b>${s.detail}</b>Cover bytes are copied from the process 1 MiB random pool. AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B); XChaCha20 nonce = derived 20 B prefix || seq(4BE).</div>
    </div>
    <div class="fv-batch"><div class="fv-sub">${s.batch} · soft limit 12 KiB · maximum TLS plaintext 16 KiB</div><div class="fv-scroll"><div class="fv-batch-row"><span>Frame #42 · padLen=0</span><span>Frame #43 · padLen=0</span><span>Final frame · padLen=N</span></div></div></div>
    <div class="fv-flow">Ethernet → AEAD (+16 B) → 10 B TLSVPN header → aggregate frames → optional MSS-alignment tail padding → TLS Write</div>
    <div class="fv-note">seq=0 handshake/control/heartbeat frames bypass inner AEAD. Standalone control frames may still use bucket/off padding selected by pad_mode; the aggregated data plane does not bucket-pad every frame.</div>
    <div class="fv-note">Legacy migration note: the old per-frame bucket example “60 B → 1600 B” is no longer the data-plane behavior; it is retained here only to identify obsolete documentation.</div>`;
  const host=root.querySelector('.st-grid')||root.querySelector('.status-grid')||root;
  host.appendChild(card);
})();
