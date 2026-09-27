(() => {
  'use strict';

  const root = document.getElementById('pane-status');
  if (!root || document.getElementById('frameviz-card')) return;

  const lang = localStorage.getItem('tlsvpn_lang') || 'zh-CN';
  const dict = {
    'zh-CN': {title:'帧格式示例',sub:'示例数据 · 非实时抓包',payload:'原始载荷',encrypted:'AES-GCM',enabled:'启用',padding:'Bucket 填充',total:'TLS 明文中的 TLSVPN 帧',click:'点击区块查看字段详情',header:'帧头',cipher:'AES-GCM 密文',tag:'GCM 认证标签',pad:'随机池填充',offset:'偏移',bytes:'字节',headerDesc:'10 字节帧头描述后续数据和填充边界。dataLen 包含 GCM tag，但不包含 padding。',cipherDesc:'示例载荷经 AES-GCM 加密后的密文。',tagDesc:'16 字节 AES-GCM 认证标签；校验失败时整帧被拒绝。',padDesc:'位于 AES-GCM 输出之后，从进程启动时生成的 1 MiB 随机池复制；接收端按 padLen 跳过。',flow:'原始载荷 → AES-GCM → 10B 帧头 → 填充至 bucket → TLS',example:'示例帧'},
    en: {title:'Frame format example',sub:'Example data · not a live capture',payload:'Original payload',encrypted:'AES-GCM',enabled:'Enabled',padding:'Bucket padding',total:'TLSVPN frame inside TLS plaintext',click:'Click a block to inspect its fields',header:'Header',cipher:'AES-GCM ciphertext',tag:'GCM authentication tag',pad:'Random-pool padding',offset:'offset',bytes:'bytes',headerDesc:'The 10-byte header describes the following data and padding boundaries. dataLen includes the GCM tag but excludes padding.',cipherDesc:'Example payload encrypted with AES-GCM.',tagDesc:'16-byte AES-GCM authentication tag; the whole frame is rejected if verification fails.',padDesc:'Appended after AES-GCM output and copied from the 1 MiB random pool initialized at process startup; the receiver skips it using padLen.',flow:'Original payload → AES-GCM → 10B header → pad to bucket → TLS',example:'Example frame'},
    de: {title:'Beispiel für Frame-Format',sub:'Beispieldaten · kein Live-Mitschnitt',payload:'Ursprüngliche Nutzlast',encrypted:'AES-GCM',enabled:'Aktiviert',padding:'Bucket-Padding',total:'TLSVPN-Frame im TLS-Klartext',click:'Block anklicken, um Felder anzuzeigen',header:'Header',cipher:'AES-GCM-Chiffretext',tag:'GCM-Authentifizierungs-Tag',pad:'Random-Pool-Padding',offset:'Offset',bytes:'Bytes',headerDesc:'Der 10-Byte-Header beschreibt Daten- und Padding-Grenzen. dataLen enthält den GCM-Tag, aber nicht das Padding.',cipherDesc:'Beispiel-Nutzlast, mit AES-GCM verschlüsselt.',tagDesc:'16-Byte AES-GCM-Authentifizierungs-Tag; bei Fehler wird der gesamte Frame verworfen.',padDesc:'Nach der AES-GCM-Ausgabe angehängt und aus dem beim Prozessstart erzeugten 1-MiB-Zufallspool kopiert; der Empfänger überspringt es anhand von padLen.',flow:'Nutzlast → AES-GCM → 10B Header → Bucket-Padding → TLS',example:'Beispiel-Frame'},
    fr: {title:'Exemple de format de trame',sub:'Données d’exemple · pas une capture en direct',payload:'Charge utile originale',encrypted:'AES-GCM',enabled:'Activé',padding:'Remplissage par bucket',total:'Trame TLSVPN dans le texte clair TLS',click:'Cliquez sur un bloc pour voir ses champs',header:'En-tête',cipher:'Texte chiffré AES-GCM',tag:'Tag d’authentification GCM',pad:'Remplissage du pool aléatoire',offset:'offset',bytes:'octets',headerDesc:'L’en-tête de 10 octets décrit les limites des données et du remplissage. dataLen inclut le tag GCM mais exclut le padding.',cipherDesc:'Charge utile d’exemple chiffrée avec AES-GCM.',tagDesc:'Tag d’authentification AES-GCM de 16 octets ; la trame entière est rejetée si la vérification échoue.',padDesc:'Ajouté après la sortie AES-GCM et copié depuis le pool aléatoire de 1 Mio créé au démarrage ; le récepteur l’ignore via padLen.',flow:'Charge utile → AES-GCM → en-tête 10 o → padding bucket → TLS',example:'Trame d’exemple'},
    ja: {title:'フレーム形式の例',sub:'サンプルデータ · ライブキャプチャではありません',payload:'元のペイロード',encrypted:'AES-GCM',enabled:'有効',padding:'Bucket パディング',total:'TLS 平文内の TLSVPN フレーム',click:'ブロックをクリックしてフィールドを確認',header:'ヘッダー',cipher:'AES-GCM 暗号文',tag:'GCM 認証タグ',pad:'ランダムプール・パディング',offset:'オフセット',bytes:'バイト',headerDesc:'10 バイトのヘッダーが後続データとパディングの境界を示します。dataLen は GCM タグを含み、padding は含みません。',cipherDesc:'AES-GCM で暗号化されたサンプルペイロードです。',tagDesc:'16 バイトの AES-GCM 認証タグ。検証に失敗するとフレーム全体を破棄します。',padDesc:'AES-GCM 出力の後ろに追加され、起動時に生成した 1 MiB ランダムプールからコピーされます。受信側は padLen に従って読み飛ばします。',flow:'元ペイロード → AES-GCM → 10B ヘッダー → Bucket までパディング → TLS',example:'サンプルフレーム'}
  };
  const s = dict[lang] || dict.en;

  const card = document.createElement('div');
  card.id = 'frameviz-card';
  card.className = 'st-block frameviz-card';
  card.innerHTML = `
    <style>
      .frameviz-card{column-span:all;margin-top:4px}.fv-head{display:flex;gap:10px;align-items:flex-end;justify-content:space-between;flex-wrap:wrap}.fv-sub{font-size:.78rem;color:var(--muted)}
      .fv-kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin:12px 0}.fv-mini{border:1px solid var(--border);border-radius:10px;padding:10px}.fv-mini span{display:block;color:var(--muted);font-size:.75rem}.fv-mini b{display:block;margin-top:4px;font:600 .95rem var(--mono,monospace)}
      .fv-track{display:flex;min-width:650px;height:70px;border:1px solid var(--border);border-radius:10px;overflow:hidden}.fv-scroll{overflow-x:auto}.fv-seg{border:0;border-right:1px solid var(--border);padding:8px 6px;background:color-mix(in srgb,var(--card) 80%,var(--accent) 20%);color:inherit;cursor:pointer;min-width:76px}.fv-seg:last-child{border-right:0}.fv-seg:hover,.fv-seg:focus-visible,.fv-seg.on{outline:none;background:color-mix(in srgb,var(--card) 62%,var(--accent) 38%)}.fv-seg b,.fv-seg small{display:block}.fv-seg small{margin-top:5px;color:var(--muted);font-family:var(--mono,monospace)}
      .fv-ruler{display:flex;justify-content:space-between;min-width:650px;padding:4px 2px 0;color:var(--muted);font:11px var(--mono,monospace)}.fv-detail{margin-top:10px;border:1px solid var(--border);border-radius:10px;padding:11px}.fv-detail-top{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}.fv-range{font:12px var(--mono,monospace);color:var(--muted)}.fv-desc{margin-top:6px;color:var(--muted);font-size:.82rem;line-height:1.5}.fv-fields{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:9px}.fv-field{border:1px solid var(--border);border-radius:8px;padding:7px;text-align:center;font-size:.75rem}.fv-field b{display:block}.fv-field span{color:var(--muted);font-family:var(--mono,monospace)}.fv-flow{margin-top:9px;color:var(--muted);font-size:.76rem}
      @media(max-width:620px){.fv-kpis{grid-template-columns:1fr}.fv-fields{grid-template-columns:1fr}}
    </style>
    <div class="fv-head"><h3>${s.title}</h3><span class="fv-sub">${s.sub}</span></div>
    <div class="fv-kpis"><div class="fv-mini"><span>${s.payload}</span><b>1200 B</b></div><div class="fv-mini"><span>${s.encrypted}</span><b>${s.enabled} · Tag 16 B</b></div><div class="fv-mini"><span>${s.padding}</span><b>374 B</b></div></div>
    <div class="fv-head"><div><strong>${s.total}</strong><div class="fv-sub">${s.click}</div></div><span class="fv-sub">${s.example}</span></div>
    <div class="fv-scroll"><div class="fv-track">
      <button class="fv-seg on" data-fv="header" style="flex:0 0 12%"><b>${s.header}</b><small>10 B</small></button>
      <button class="fv-seg" data-fv="cipher" style="flex:0 0 57%"><b>${s.cipher}</b><small>1200 B</small></button>
      <button class="fv-seg" data-fv="tag" style="flex:0 0 8%"><b>${s.tag}</b><small>16 B</small></button>
      <button class="fv-seg" data-fv="pad" style="flex:1"><b>${s.pad}</b><small>374 B</small></button>
    </div><div class="fv-ruler"><span>0</span><span>10</span><span>1210</span><span>1226</span><span>1600</span></div></div>
    <div class="fv-detail"><div class="fv-detail-top"><strong id="fv-title">${s.header} · 10 B</strong><span class="fv-range" id="fv-range">${s.offset} 0–9</span></div><div class="fv-desc" id="fv-desc">${s.headerDesc}</div><div class="fv-fields" id="fv-fields"><div class="fv-field"><b>dataLen</b><span>4 B · 1216</span></div><div class="fv-field"><b>padLen</b><span>2 B · 374</span></div><div class="fv-field"><b>seq</b><span>4 B · #42</span></div></div></div>
    <div class="fv-flow">${s.flow}</div>`;

  const data = {
    header:[`${s.header} · 10 B`,`${s.offset} 0–9`,s.headerDesc,true],
    cipher:[`${s.cipher} · 1200 B`,`${s.offset} 10–1209`,s.cipherDesc,false],
    tag:[`${s.tag} · 16 B`,`${s.offset} 1210–1225`,s.tagDesc,false],
    pad:[`${s.pad} · 374 B`,`${s.offset} 1226–1599`,s.padDesc,false]
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
