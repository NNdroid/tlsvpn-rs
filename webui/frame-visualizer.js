(() => {
  'use strict';
  const root=document.getElementById('pane-status');
  if(!root||document.getElementById('frameviz-card'))return;

  // Frame visualizer-specific strings. Keep protocol field names and cipher names
  // unchanged, but route every human-readable label and explanation through i18n.
  const FRAMEVIZ_DETAIL_I18N={
    'zh-CN':{
      kpi_header:'协议头 (header)',kpi_data_len:'数据长度 (dataLen)',kpi_pad_len:'填充长度 (padLen)',kpi_batch:'聚合批次 (batch)',
      tail_n:'尾帧 N',soft:'软上限',ethernet_frame:'1514 B Ethernet 帧',aead_tag:'16 B AEAD 认证标签',inner_aead:'内层 AEAD',
      header_desc:'固定 10 B 大端序头。示例：dataLen=1514+16=1530，普通数据帧 padLen=0，seq=42。dataLen 包含 AEAD 认证标签，不包含填充字节。',
      aead_desc:'AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305。AAD = dataLen（4 B，大端序）|| seq（4 B，大端序）。当前所有算法均使用 16 B 认证标签。',
      tail_desc:'数据帧会先进行聚合。只有 TLS 明文批次中的最后一帧可以追加伪装填充字节。仅当所需填充 ≤ 有效批次字节的 10% 且 ≤ 512 B 时才会应用，否则 padLen 保持为 0。',
      detail_desc:'伪装填充字节从进程内 1 MiB 随机池复制。AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B)；XChaCha20 nonce = 派生的 20 B 前缀 || seq(4BE)。',
      batch_limits:'{batch} · 软上限 12 KiB · TLS 明文最大 16 KiB',frame:'帧 #{n} · padLen=0',final_frame:'最后一帧 · padLen=N',
      flow:'Ethernet → AEAD（+16 B）→ 10 B TLSVPN 头 → 聚合帧 → 可选的 MSS 对齐尾部填充 → TLS 写入',
      control_note:'seq=0 的握手/控制/心跳帧绕过内层 AEAD。独立控制帧仍可根据 pad_mode 使用 bucket/off 填充；聚合数据平面不会对每一帧执行 bucket 填充。',
    },
    'zh-TW':{
      kpi_header:'協定標頭 (header)',kpi_data_len:'資料長度 (dataLen)',kpi_pad_len:'填充長度 (padLen)',kpi_batch:'聚合批次 (batch)',
      tail_n:'尾幀 N',soft:'軟上限',ethernet_frame:'1514 B Ethernet 訊框',aead_tag:'16 B AEAD 驗證標籤',inner_aead:'內層 AEAD',
      header_desc:'固定 10 B 大端序標頭。範例：dataLen=1514+16=1530，一般資料幀 padLen=0，seq=42。dataLen 包含 AEAD 驗證標籤，不包含填充位元組。',
      aead_desc:'AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305。AAD = dataLen（4 B，大端序）|| seq（4 B，大端序）。目前所有演算法都使用 16 B 驗證標籤。',
      tail_desc:'資料幀會先進行聚合。只有 TLS 明文批次中的最後一幀可以追加偽裝填充位元組。僅當所需填充 ≤ 有效批次位元組的 10% 且 ≤ 512 B 時才會套用，否則 padLen 維持為 0。',
      detail_desc:'偽裝填充位元組從程序內 1 MiB 隨機池複製。AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B)；XChaCha20 nonce = 衍生的 20 B 前綴 || seq(4BE)。',
      batch_limits:'{batch} · 軟上限 12 KiB · TLS 明文最大 16 KiB',frame:'訊框 #{n} · padLen=0',final_frame:'最後一幀 · padLen=N',
      flow:'Ethernet → AEAD（+16 B）→ 10 B TLSVPN 標頭 → 聚合訊框 → 可選的 MSS 對齊尾端填充 → TLS 寫入',
      control_note:'seq=0 的握手/控制/心跳訊框會略過內層 AEAD。獨立控制訊框仍可依 pad_mode 使用 bucket/off 填充；聚合資料平面不會對每一幀執行 bucket 填充。',
    },
    en:{
      kpi_header:'Protocol header',kpi_data_len:'Data length (dataLen)',kpi_pad_len:'Padding length (padLen)',kpi_batch:'Aggregate batch',
      tail_n:'tail N',soft:'soft limit',ethernet_frame:'1514 B Ethernet frame',aead_tag:'16 B AEAD authentication tag',inner_aead:'Inner AEAD',
      header_desc:'Fixed 10 B big-endian header. Example: dataLen=1514+16=1530, ordinary data frame padLen=0, seq=42. dataLen includes the AEAD tag and excludes padding.',
      aead_desc:'AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305. AAD = dataLen (4 B BE) || seq (4 B BE). Every current algorithm uses a 16 B authentication tag.',
      tail_desc:'Data frames are aggregated first. Only the final frame of a TLS plaintext batch may receive cover bytes. Required padding is accepted only when it is ≤ 10% of useful batch bytes and ≤ 512 B; otherwise padLen remains 0.',
      detail_desc:'Cover bytes are copied from the process 1 MiB random pool. AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B); XChaCha20 nonce = derived 20 B prefix || seq(4BE).',
      batch_limits:'{batch} · soft limit 12 KiB · maximum TLS plaintext 16 KiB',frame:'Frame #{n} · padLen=0',final_frame:'Final frame · padLen=N',
      flow:'Ethernet → AEAD (+16 B) → 10 B TLSVPN header → aggregate frames → optional MSS-alignment tail padding → TLS Write',
      control_note:'seq=0 handshake/control/heartbeat frames bypass inner AEAD. Standalone control frames may still use bucket/off padding selected by pad_mode; the aggregated data plane does not bucket-pad every frame.',
    },
    de:{
      kpi_header:'Protokoll-Header',kpi_data_len:'Datenlänge (dataLen)',kpi_pad_len:'Padding-Länge (padLen)',kpi_batch:'Aggregierter Batch',
      tail_n:'Tail N',soft:'weiches Limit',ethernet_frame:'1514-B-Ethernet-Frame',aead_tag:'16-B-AEAD-Authentifizierungs-Tag',inner_aead:'Innere AEAD',
      header_desc:'Fester 10-B-Big-Endian-Header. Beispiel: dataLen=1514+16=1530, bei einem normalen Datenframe ist padLen=0 und seq=42. dataLen enthält den AEAD-Tag, aber keine Padding-Bytes.',
      aead_desc:'AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305. AAD = dataLen (4 B BE) || seq (4 B BE). Alle aktuellen Algorithmen verwenden einen 16-B-Authentifizierungs-Tag.',
      tail_desc:'Datenframes werden zuerst aggregiert. Nur der letzte Frame eines TLS-Klartext-Batches darf Tarn-Padding erhalten. Padding wird nur akzeptiert, wenn es ≤ 10 % der Nutzbytes des Batches und ≤ 512 B beträgt; andernfalls bleibt padLen 0.',
      detail_desc:'Tarnbytes werden aus dem prozessinternen 1-MiB-Zufallspool kopiert. AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B); XChaCha20 nonce = abgeleitetes 20-B-Präfix || seq(4BE).',
      batch_limits:'{batch} · weiches Limit 12 KiB · maximaler TLS-Klartext 16 KiB',frame:'Frame #{n} · padLen=0',final_frame:'Letzter Frame · padLen=N',
      flow:'Ethernet → AEAD (+16 B) → 10-B-TLSVPN-Header → Frames aggregieren → optionales MSS-ausgerichtetes Tail-Padding → TLS Write',
      control_note:'Handshake-, Steuer- und Heartbeat-Frames mit seq=0 umgehen die innere AEAD. Einzelne Steuerframes können weiterhin das über pad_mode gewählte bucket/off-Padding verwenden; die aggregierte Datenebene bucket-paddet nicht jeden Frame.',
    },
    fr:{
      kpi_header:'En-tête du protocole',kpi_data_len:'Longueur des données (dataLen)',kpi_pad_len:'Longueur du padding (padLen)',kpi_batch:'Lot agrégé',
      tail_n:'fin N',soft:'limite souple',ethernet_frame:'Trame Ethernet de 1514 o',aead_tag:'Tag d’authentification AEAD de 16 o',inner_aead:'AEAD interne',
      header_desc:'En-tête big-endian fixe de 10 o. Exemple : dataLen=1514+16=1530, une trame de données ordinaire a padLen=0 et seq=42. dataLen inclut le tag AEAD et exclut les octets de padding.',
      aead_desc:'AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305. AAD = dataLen (4 o BE) || seq (4 o BE). Tous les algorithmes actuels utilisent un tag d’authentification de 16 o.',
      tail_desc:'Les trames de données sont d’abord agrégées. Seule la dernière trame d’un lot TLS en clair peut recevoir des octets de camouflage. Le padding n’est appliqué que s’il représente ≤ 10 % des octets utiles du lot et ≤ 512 o ; sinon padLen reste à 0.',
      detail_desc:'Les octets de camouflage sont copiés depuis le pool aléatoire de 1 Mio du processus. AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B) ; XChaCha20 nonce = préfixe dérivé de 20 o || seq(4BE).',
      batch_limits:'{batch} · limite souple 12 Kio · texte clair TLS maximal 16 Kio',frame:'Trame nº {n} · padLen=0',final_frame:'Dernière trame · padLen=N',
      flow:'Ethernet → AEAD (+16 o) → en-tête TLSVPN de 10 o → agrégation des trames → padding final optionnel aligné sur le MSS → écriture TLS',
      control_note:'Les trames de handshake/contrôle/heartbeat avec seq=0 contournent l’AEAD interne. Les trames de contrôle autonomes peuvent toujours utiliser le padding bucket/off choisi par pad_mode ; le plan de données agrégé n’applique pas de bucket-padding à chaque trame.',
    },
    ja:{
      kpi_header:'プロトコルヘッダー',kpi_data_len:'データ長 (dataLen)',kpi_pad_len:'パディング長 (padLen)',kpi_batch:'集約バッチ',
      tail_n:'末尾 N',soft:'ソフト上限',ethernet_frame:'1514 B Ethernet フレーム',aead_tag:'16 B AEAD 認証タグ',inner_aead:'内部 AEAD',
      header_desc:'固定 10 B のビッグエンディアンヘッダーです。例：dataLen=1514+16=1530、通常のデータフレームでは padLen=0、seq=42。dataLen には AEAD タグが含まれ、パディングは含まれません。',
      aead_desc:'AES-256-GCM · AES-128-GCM · ChaCha20-Poly1305 · XChaCha20-Poly1305。AAD = dataLen（4 B BE）|| seq（4 B BE）。現在のすべてのアルゴリズムは 16 B の認証タグを使用します。',
      tail_desc:'データフレームは先に集約されます。TLS 平文バッチの最後のフレームだけがカバーパディングを受け取れます。必要なパディングが有効バッチバイトの 10% 以下かつ 512 B 以下の場合だけ適用され、それ以外では padLen は 0 のままです。',
      detail_desc:'カバーバイトはプロセス内の 1 MiB ランダムプールからコピーされます。AES-GCM / ChaCha20 nonce = seq(4BE) || salt(8B)、XChaCha20 nonce = 派生 20 B プレフィックス || seq(4BE)。',
      batch_limits:'{batch} · ソフト上限 12 KiB · TLS 平文最大 16 KiB',frame:'フレーム #{n} · padLen=0',final_frame:'最終フレーム · padLen=N',
      flow:'Ethernet → AEAD（+16 B）→ 10 B TLSVPN ヘッダー → フレーム集約 → 任意の MSS 整列末尾パディング → TLS Write',
      control_note:'seq=0 のハンドシェイク/制御/ハートビートフレームは内部 AEAD を迂回します。単独の制御フレームでは pad_mode で選択した bucket/off パディングを引き続き使用できますが、集約データプレーンでは各フレームに bucket パディングを行いません。',
    }
  };

  const base=FRAMEVIZ_I18N[LANG]||FRAMEVIZ_I18N.en;
  const detail=FRAMEVIZ_DETAIL_I18N[LANG]||FRAMEVIZ_DETAIL_I18N.en;
  const s={...base,...detail};
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
    <div class="fv-kpis"><div class="fv-mini"><span>${s.kpi_header}</span><b>10 B</b></div><div class="fv-mini"><span>${s.kpi_data_len}</span><b>1530 B</b></div><div class="fv-mini"><span>${s.kpi_pad_len}</span><b>0 B / ${s.tail_n}</b></div><div class="fv-mini"><span>${s.kpi_batch}</span><b>≤ 12 KiB ${s.soft}</b></div></div>
    <div class="fv-scroll"><div class="fv-track"><div class="fv-seg fv-h"><b>${s.header}</b><small>[dataLen:u32][padLen:u16][seq:u32]</small></div><div class="fv-seg fv-c"><b>${s.cipher}</b><small>${s.ethernet_frame}</small></div><div class="fv-seg fv-t"><b>${s.tag}</b><small>${s.aead_tag}</small></div><div class="fv-seg fv-p"><b>${s.tail}</b><small>0..min(10%, 512 B)</small></div></div></div>
    <div class="fv-descs">
      <div class="fv-desc"><b>${s.header}</b>${s.header_desc}</div>
      <div class="fv-desc"><b>${s.inner_aead}</b>${s.aead_desc}</div>
      <div class="fv-desc"><b>${s.tail}</b>${s.tail_desc}</div>
      <div class="fv-desc"><b>${s.detail}</b>${s.detail_desc}</div>
    </div>
    <div class="fv-batch"><div class="fv-sub">${s.batch_limits.replace('{batch}',s.batch)}</div><div class="fv-scroll"><div class="fv-batch-row"><span>${s.frame.replace('{n}','42')}</span><span>${s.frame.replace('{n}','43')}</span><span>${s.final_frame}</span></div></div></div>
    <div class="fv-flow">${s.flow}</div>
    <div class="fv-note">${s.control_note}</div>`;
  const host=root.querySelector('.st-grid')||root.querySelector('.status-grid')||root;
  host.appendChild(card);
})();
