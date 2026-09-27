(() => {
  'use strict';

  const root = document.getElementById('pane-status');
  if (!root || document.getElementById('frameviz-card')) return;

  const lang = localStorage.getItem('tlsvpn_lang') || 'zh-CN';
  const dict = {
    'zh-CN': {
      title:'帧格式示例', sub:'当前协议 · 示例数据 · 非实时抓包', payload:'以太网帧载荷', aead:'内层 AEAD', wire:'dataLen', padding:'Bucket 填充',
      total:'TLS 明文中的 TLSVPN 记录', click:'点击区块查看字段详情', header:'帧头', cipher:'AEAD 密文', tag:'AEAD 认证标签', pad:'随机池填充', offset:'偏移', example:'1514 B 以太网帧示例',
      headerDesc:'固定 10 字节，大端序：[dataLen:u32][padLen:u16][seq:u32]。本例 dataLen=1514+16=1530，padLen=60，seq=42。dataLen 包含 AEAD tag，但不包含 padding。',
      cipherDesc:'seq>0 且 encrypt=true 时使用协商的内层 AEAD。支持 AES-256-GCM、AES-128-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305；密文长度与明文相同。AAD = dataLen(4B BE) || seq(4B BE)。',
      tagDesc:'当前所有内层 AEAD 都使用 16 字节认证标签；认证失败时整帧被拒绝。',
      padDesc:'bucket 模式按完整记录长度选择 128/256/384/512/768/1024/1280/1600/2048/4096 B。这里 10+1514+16=1540 B，因此补 60 B 到 1600 B；填充从启动时生成的 1 MiB 随机池复制，off 模式则 padLen=0。',
      flow:'1514B 载荷 → AEAD（+16B tag）→ 10B 帧头 → bucket 1600B → TLS',
      note:'seq=0 的控制/握手/校验帧不使用内层 AEAD。AES-GCM / ChaCha20-Poly1305 nonce = seq(4BE) || salt(8B)；XChaCha20-Poly1305 使用派生的 20B prefix || seq(4BE)。'
    },
    'zh-TW': {
      title:'訊框格式範例', sub:'目前協定 · 範例資料 · 非即時封包擷取', payload:'乙太網路訊框承載資料', aead:'內層 AEAD', wire:'dataLen', padding:'Bucket 填充',
      total:'TLS 明文中的 TLSVPN 記錄', click:'點選區塊查看欄位詳情', header:'訊框標頭', cipher:'AEAD 密文', tag:'AEAD 驗證標籤', pad:'隨機池填充', offset:'偏移', example:'1514 B 乙太網路訊框範例',
      headerDesc:'固定 10 位元組，大端序：[dataLen:u32][padLen:u16][seq:u32]。本例 dataLen=1514+16=1530，padLen=60，seq=42。dataLen 包含 AEAD tag，但不包含 padding。',
      cipherDesc:'seq>0 且 encrypt=true 時使用協商的內層 AEAD。支援 AES-256-GCM、AES-128-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305；密文長度與明文相同。AAD = dataLen(4B BE) || seq(4B BE)。',
      tagDesc:'目前所有內層 AEAD 都使用 16 位元組驗證標籤；驗證失敗時整個訊框會被拒絕。',
      padDesc:'bucket 模式依完整記錄長度選擇 128/256/384/512/768/1024/1280/1600/2048/4096 B。此例 10+1514+16=1540 B，因此補 60 B 到 1600 B；填充從啟動時產生的 1 MiB 隨機池複製，off 模式則 padLen=0。',
      flow:'1514B 承載資料 → AEAD（+16B tag）→ 10B 訊框標頭 → bucket 1600B → TLS',
      note:'seq=0 的控制/握手/校驗訊框不使用內層 AEAD。AES-GCM / ChaCha20-Poly1305 nonce = seq(4BE) || salt(8B)；XChaCha20-Poly1305 使用衍生的 20B prefix || seq(4BE)。'
    },
    en: {
      title:'Frame format example', sub:'Current protocol · example data · not a live capture', payload:'Ethernet frame payload', aead:'Inner AEAD', wire:'dataLen', padding:'Bucket padding',
      total:'TLSVPN record inside TLS plaintext', click:'Click a block to inspect its fields', header:'Header', cipher:'AEAD ciphertext', tag:'AEAD authentication tag', pad:'Random-pool padding', offset:'offset', example:'1514 B Ethernet frame example',
      headerDesc:'Fixed 10-byte big-endian header: [dataLen:u32][padLen:u16][seq:u32]. Here dataLen=1514+16=1530, padLen=60, seq=42. dataLen includes the AEAD tag and excludes padding.',
      cipherDesc:'For seq>0 with encrypt=true, the negotiated inner AEAD is used: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, or XChaCha20-Poly1305. Ciphertext length equals plaintext length. AAD = dataLen(4B BE) || seq(4B BE).',
      tagDesc:'All currently supported inner AEADs use a 16-byte authentication tag; the complete frame is rejected on authentication failure.',
      padDesc:'Bucket mode chooses a full-record target of 128/256/384/512/768/1024/1280/1600/2048/4096 B. Here 10+1514+16=1540 B, so 60 B is added to reach 1600 B. Padding is copied from the 1 MiB process random pool; off mode uses padLen=0.',
      flow:'1514B payload → AEAD (+16B tag) → 10B header → 1600B bucket → TLS',
      note:'seq=0 control/handshake/check frames bypass inner AEAD. AES-GCM / ChaCha20-Poly1305 nonce = seq(4BE) || salt(8B); XChaCha20-Poly1305 uses a derived 20B prefix || seq(4BE).'
    },
    de: {
      title:'Beispiel für Frame-Format', sub:'Aktuelles Protokoll · Beispieldaten · kein Live-Mitschnitt', payload:'Ethernet-Nutzlast', aead:'Inneres AEAD', wire:'dataLen', padding:'Bucket-Padding',
      total:'TLSVPN-Datensatz im TLS-Klartext', click:'Block anklicken, um Felder anzuzeigen', header:'Header', cipher:'AEAD-Chiffretext', tag:'AEAD-Authentifizierungs-Tag', pad:'Random-Pool-Padding', offset:'Offset', example:'1514-B-Ethernet-Beispiel',
      headerDesc:'Fester 10-Byte-Big-Endian-Header: [dataLen:u32][padLen:u16][seq:u32]. Hier dataLen=1530, padLen=60 und seq=42. dataLen enthält den 16-B-AEAD-Tag, aber kein Padding.',
      cipherDesc:'Bei seq>0 und encrypt=true wird das ausgehandelte AEAD verwendet: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 oder XChaCha20-Poly1305. AAD = dataLen(4B BE) || seq(4B BE).',
      tagDesc:'Alle unterstützten inneren AEADs verwenden einen 16-Byte-Authentifizierungs-Tag.',
      padDesc:'Bucket-Modus wählt 128/256/384/512/768/1024/1280/1600/2048/4096 B. 1540 B werden hier mit 60 B aus dem 1-MiB-Zufallspool auf 1600 B aufgefüllt; off setzt padLen=0.',
      flow:'1514B Nutzlast → AEAD (+16B Tag) → 10B Header → 1600B Bucket → TLS',
      note:'seq=0 Steuer-/Handshake-/Prüf-Frames umgehen das innere AEAD.'
    },
    fr: {
      title:'Exemple de format de trame', sub:'Protocole actuel · données d’exemple · pas une capture en direct', payload:'Charge utile Ethernet', aead:'AEAD interne', wire:'dataLen', padding:'Remplissage par bucket',
      total:'Enregistrement TLSVPN dans le texte clair TLS', click:'Cliquez sur un bloc pour voir ses champs', header:'En-tête', cipher:'Texte chiffré AEAD', tag:'Tag d’authentification AEAD', pad:'Remplissage du pool aléatoire', offset:'offset', example:'Exemple de trame Ethernet 1514 o',
      headerDesc:'En-tête fixe de 10 octets en big-endian : [dataLen:u32][padLen:u16][seq:u32]. Ici dataLen=1530, padLen=60 et seq=42. dataLen inclut le tag AEAD de 16 o et exclut le padding.',
      cipherDesc:'Avec seq>0 et encrypt=true, l’AEAD négocié est utilisé : AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 ou XChaCha20-Poly1305. AAD = dataLen(4B BE) || seq(4B BE).',
      tagDesc:'Tous les AEAD internes pris en charge utilisent un tag d’authentification de 16 octets.',
      padDesc:'Le mode bucket choisit 128/256/384/512/768/1024/1280/1600/2048/4096 o. Ici 1540 o reçoivent 60 o du pool aléatoire de 1 MiB pour atteindre 1600 o ; le mode off utilise padLen=0.',
      flow:'1514B charge utile → AEAD (+16B tag) → en-tête 10B → bucket 1600B → TLS',
      note:'Les trames de contrôle/handshake/vérification avec seq=0 n’utilisent pas l’AEAD interne.'
    },
    ja: {
      title:'フレーム形式の例', sub:'現行プロトコル · サンプルデータ · ライブキャプチャではありません', payload:'Ethernet フレーム payload', aead:'内部 AEAD', wire:'dataLen', padding:'Bucket パディング',
      total:'TLS 平文内の TLSVPN レコード', click:'ブロックをクリックしてフィールドを確認', header:'ヘッダー', cipher:'AEAD 暗号文', tag:'AEAD 認証タグ', pad:'ランダムプール・パディング', offset:'オフセット', example:'1514 B Ethernet フレーム例',
      headerDesc:'固定 10 バイトのビッグエンディアンヘッダー：[dataLen:u32][padLen:u16][seq:u32]。この例では dataLen=1530、padLen=60、seq=42。dataLen は 16B AEAD tag を含み、padding は含みません。',
      cipherDesc:'seq>0 かつ encrypt=true の場合、AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305 / XChaCha20-Poly1305 のいずれかを使用します。AAD = dataLen(4B BE) || seq(4B BE)。',
      tagDesc:'現在サポートする内部 AEAD はすべて 16 バイトの認証タグを使用します。',
      padDesc:'Bucket モードは 128/256/384/512/768/1024/1280/1600/2048/4096 B から選択します。この例は 1540 B なので 1 MiB ランダムプールから 60 B 追加して 1600 B にします。off は padLen=0 です。',
      flow:'1514B payload → AEAD（+16B tag）→ 10B ヘッダー → 1600B bucket → TLS',
      note:'seq=0 の制御/handshake/check フレームは内部 AEAD を使用しません。'
    }
  };
  const s = dict[lang] || dict.en;

  const card = document.createElement('div');
  card.id = 'frameviz-card';
  card.className = 'st-block frameviz-card';
  card.innerHTML = `
    <style>
      .frameviz-card{column-span:all;margin-top:4px}.fv-head{display:flex;gap:10px;align-items:flex-end;justify-content:space-between;flex-wrap:wrap}.fv-sub{font-size:.78rem;color:var(--muted)}
      .fv-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:12px 0}.fv-mini{border:1px solid var(--border);border-radius:10px;padding:10px}.fv-mini span{display:block;color:var(--muted);font-size:.75rem}.fv-mini b{display:block;margin-top:4px;font:600 .95rem var(--mono,monospace)}
      .fv-track{display:flex;min-width:700px;height:72px;border:1px solid var(--border);border-radius:10px;overflow:hidden}.fv-scroll{overflow-x:auto}.fv-seg{border:0;border-right:1px solid var(--border);padding:8px 6px;background:color-mix(in srgb,var(--card) 80%,var(--accent) 20%);color:inherit;cursor:pointer;min-width:88px}.fv-seg:last-child{border-right:0}.fv-seg:hover,.fv-seg:focus-visible,.fv-seg.on{outline:none;background:color-mix(in srgb,var(--card) 62%,var(--accent) 38%)}.fv-seg b,.fv-seg small{display:block}.fv-seg small{margin-top:5px;color:var(--muted);font-family:var(--mono,monospace)}
      .fv-ruler{display:flex;justify-content:space-between;min-width:700px;padding:4px 2px 0;color:var(--muted);font:11px var(--mono,monospace)}.fv-detail{margin-top:10px;border:1px solid var(--border);border-radius:10px;padding:11px}.fv-detail-top{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}.fv-range{font:12px var(--mono,monospace);color:var(--muted)}.fv-desc{margin-top:6px;color:var(--muted);font-size:.82rem;line-height:1.5}.fv-fields{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:9px}.fv-field{border:1px solid var(--border);border-radius:8px;padding:7px;text-align:center;font-size:.75rem}.fv-field b{display:block}.fv-field span{color:var(--muted);font-family:var(--mono,monospace)}.fv-flow,.fv-note{margin-top:9px;color:var(--muted);font-size:.76rem;line-height:1.55}.fv-note{padding-top:8px;border-top:1px dashed var(--border)}
      @media(max-width:760px){.fv-kpis{grid-template-columns:repeat(2,1fr)}}@media(max-width:620px){.fv-kpis,.fv-fields{grid-template-columns:1fr}}
    </style>
    <div class="fv-head"><h3>${s.title}</h3><span class="fv-sub">${s.sub}</span></div>
    <div class="fv-kpis">
      <div class="fv-mini"><span>${s.payload}</span><b>1514 B</b></div>
      <div class="fv-mini"><span>${s.aead}</span><b>4 algos · Tag 16 B</b></div>
      <div class="fv-mini"><span>${s.wire}</span><b>1530 B</b></div>
      <div class="fv-mini"><span>${s.padding}</span><b>60 B → 1600 B</b></div>
    </div>
    <div class="fv-head"><div><strong>${s.total}</strong><div class="fv-sub">${s.click}</div></div><span class="fv-sub">${s.example}</span></div>
    <div class="fv-scroll"><div class="fv-track">
      <button class="fv-seg on" data-fv="header" style="flex:0 0 13%"><b>${s.header}</b><small>10 B</small></button>
      <button class="fv-seg" data-fv="cipher" style="flex:1"><b>${s.cipher}</b><small>1514 B</small></button>
      <button class="fv-seg" data-fv="tag" style="flex:0 0 12%"><b>${s.tag}</b><small>16 B</small></button>
      <button class="fv-seg" data-fv="pad" style="flex:0 0 14%"><b>${s.pad}</b><small>60 B</small></button>
    </div><div class="fv-ruler"><span>0</span><span>10</span><span>1524</span><span>1540</span><span>1600</span></div></div>
    <div class="fv-detail"><div class="fv-detail-top"><strong id="fv-title">${s.header} · 10 B</strong><span class="fv-range" id="fv-range">${s.offset} 0–9</span></div><div class="fv-desc" id="fv-desc">${s.headerDesc}</div><div class="fv-fields" id="fv-fields"><div class="fv-field"><b>dataLen</b><span>4 B BE · 1530</span></div><div class="fv-field"><b>padLen</b><span>2 B BE · 60</span></div><div class="fv-field"><b>seq</b><span>4 B BE · #42</span></div></div></div>
    <div class="fv-flow">${s.flow}</div><div class="fv-note">${s.note}</div>`;

  const data = {
    header:[`${s.header} · 10 B`,`${s.offset} 0–9`,s.headerDesc,true],
    cipher:[`${s.cipher} · 1514 B`,`${s.offset} 10–1523`,s.cipherDesc,false],
    tag:[`${s.tag} · 16 B`,`${s.offset} 1524–1539`,s.tagDesc,false],
    pad:[`${s.pad} · 60 B`,`${s.offset} 1540–1599`,s.padDesc,false]
  };
  card.querySelectorAll('[data-fv]').forEach(btn => btn.addEventListener('click', () => {
    const d = data[btn.dataset.fv];
    card.querySelectorAll('[data-fv]').forEach(x => x.classList.toggle('on', x === btn));
    card.querySelector('#fv-title').textContent = d[0];
    card.querySelector('#fv-range').textContent = d[1];
    card.querySelector('#fv-desc').textContent = d[2];
    card.querySelector('#fv-fields').style.display = d[3] ? '' : 'none';
  }));

  const grid = root.querySelector('.st-grid');
  if (grid) grid.appendChild(card); else root.appendChild(card);
})();
