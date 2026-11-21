/* 调度设置 UI（选路算法 + FEC parity 分发策略）。JSON 编辑器保持唯一事实来源：
   下拉/输入读写顶层 routing_algo / fec_strategy / fec_near_window_ms /
   sched_envelope / sched_envelope_ms / probe_min_half_rtt_us /
   sched_health_penalty_us（全局，client 上行 / server 下行共用）。 */
(function(){
  'use strict';

  const pane=document.getElementById('pane-settings');
  const editor=document.getElementById('cfg-editor');
  if(!pane||!editor)return;

  const COPY={
    'zh-CN':{
      title:'调度设置',sub:'选路算法、资格门与 FEC parity 分发。热更生效，无需重启。',labelAlgo:'选路算法',labelFec:'FEC parity 分发策略',labelWindow:'near 窗口 (ms)',labelGate:'候选资格门维度',labelGateWindow:'fwd 门窗口 (ms)',labelProbe:'probe_min 锚定下界 (µs)',
      labelPenalty:'健康罚时单位 (µs)',
      penaltyHint:'路径健康罚时的单位值：每次探针连续超时、每个 200ms 窗重传段在选路排名键上加的微秒数（总量各自封顶 10ms）。0=禁用健康罚时（背景丢包恒定的链路上，罚时会永久压制"仍是本组最快"的路径）。范围 0-60000，默认 2000。',
      hint:'auto=去程稳定地板+按路径容量的服务时间（粘滞+容量加权 WFQ）；latency_strict=严格最低去程地板；latency_sticky=最低去程地板+粘滞；min_rtt_strict=严格最低无拥塞地板；min_rtt_adaptive=无拥塞地板+粘滞+容量加权 WFQ；roundtrip_strict=严格最低当前往返。',
      fecHint:'auto=所有健康后端轮转（默认）；near=只投到去程单程时延与数据路径相差 ≤ 窗口的连接，抑制慢备链路的 parity 泄漏。',
      windowHint:'仅 near 生效：parity 只发给与数据路径去程时延相差 ≤ N ms 的连接。范围 1-100。',
      gateHint:'rtt=按内核 min_rtt 往返地板设门（默认，方向盲）；fwd=按本端去程排名键设门，让"去程最快但往返很慢"的极不对称路径也能准入——它慢的那一侧是对端发送方向，由对端自己的门挡掉。两端各自按发送方向设门。',
      gateWindowHint:'仅 fwd 生效：去程相对本组最小值相差 ≤ N ms 即准入。范围 1-500。组内无已收敛去程读数时自动回退 rtt 门。',
      probeHint:'单向时延分解的物理锚定下界：ref 自回包时延低于此值按此钳制，防退化链路的极端样本污染 fwd 门与 near 窗口。0=禁用锚定（仅调试）。范围 0-3600000，默认 1000。',
      algos:{auto:'auto（默认，粘滞+WFQ）',latency_strict:'latency_strict（严格最低去程）',latency_sticky:'latency_sticky（最低去程+粘滞）',min_rtt_strict:'min_rtt_strict（严格最低无拥塞地板）',min_rtt_adaptive:'min_rtt_adaptive（无拥塞地板+粘滞+WFQ）',roundtrip_strict:'roundtrip_strict（严格最低当前往返）'},
      fecs:{auto:'auto（所有健康后端轮转）',near:'near（去程时延 ≤ 数据路径 + 窗口）'},
      gates:{rtt:'rtt（内核往返地板，默认）',fwd:'fwd（本端去程排名键）'},
    },
    'zh-TW':{
      title:'排程設定',sub:'選路演算法、資格門與 FEC 同位元分發。熱更新生效，無需重新啟動。',labelAlgo:'選路演算法',labelFec:'FEC 同位元分發策略',labelWindow:'near 視窗 (ms)',labelGate:'候選資格門維度',labelGateWindow:'fwd 門視窗 (ms)',labelProbe:'probe_min 錨定下界 (µs)',
      labelPenalty:'健康罰時單位 (µs)',
      penaltyHint:'路徑健康罰時的單位值：每次探針連續逾時、每個 200ms 窗重傳段在選路排名鍵上加的微秒數（總量各自封頂 10ms）。0=停用健康罰時（背景丟包恆定的鏈路上，罰時會永久壓制「仍是本組最快」的路徑）。範圍 0-60000，預設 2000。',
      hint:'auto=去程穩定地板+按路徑容量的服務時間（黏滯+容量加權 WFQ）；latency_strict=嚴格最低去程地板；latency_sticky=最低去程地板+黏滯；min_rtt_strict=嚴格最低無壅塞地板；min_rtt_adaptive=無壅塞地板+黏滯+容量加權 WFQ；roundtrip_strict=嚴格最低目前來回。',
      fecHint:'auto=所有健康後端輪轉（預設）；near=只投到去程單程延遲與資料路徑相差 ≤ 視窗的連線，抑制慢備援鏈路的同位元洩漏。',
      windowHint:'僅 near 生效：同位元只發給與資料路徑去程延遲相差 ≤ N ms 的連線。範圍 1-100。',
      gateHint:'rtt=依內核 min_rtt 來回地板設門（預設，方向盲）；fwd=依本端去程排名鍵設門，讓「去程最快但來回很慢」的極不對稱路徑也能准入——它慢的那一側是對端發送方向，由對端自己的門擋掉。兩端各自依發送方向設門。',
      gateWindowHint:'僅 fwd 生效：去程相對本組最小值相差 ≤ N ms 即准入。範圍 1-500。組內無已收斂去程讀數時自動回退 rtt 門。',
      probeHint:'單向時延分解的物理錨定下界：ref 自回包時延低於此值按此鉗制，防退化鏈路的極端樣本污染 fwd 門與 near 視窗。0=停用錨定（僅除錯）。範圍 0-3600000，預設 1000。',
      algos:{auto:'auto（預設，黏滯+WFQ）',latency_strict:'latency_strict（嚴格最低去程）',latency_sticky:'latency_sticky（最低去程+黏滯）',min_rtt_strict:'min_rtt_strict（嚴格最低無壅塞地板）',min_rtt_adaptive:'min_rtt_adaptive（無壅塞地板+黏滯+WFQ）',roundtrip_strict:'roundtrip_strict（嚴格最低目前來回）'},
      fecs:{auto:'auto（所有健康後端輪轉）',near:'near（去程延遲 ≤ 資料路徑 + 視窗）'},
      gates:{rtt:'rtt（內核來回地板，預設）',fwd:'fwd（本端去程排名鍵）'},
    },
    'en':{
      title:'Scheduler settings',sub:'Routing algorithm, eligibility gate & FEC parity distribution. Hot-applied, no restart.',labelAlgo:'Routing algorithm',labelFec:'FEC parity strategy',labelWindow:'near window (ms)',labelGate:'Candidate eligibility gate',labelGateWindow:'fwd gate window (ms)',labelProbe:'probe_min anchor floor (µs)',
      labelPenalty:'health penalty unit (µs)',
      penaltyHint:'Per-event health penalty added to the routing rank key: one raise per consecutive probe timeout and per retransmitted segment in the 200ms window (each capped at 10ms total). 0 = disable health penalties (on links with constant background loss the penalty would permanently bury the still-fastest path). Range 0-60000, default 2000.',
      hint:'auto = stable forward floor + per-path capacity service time (sticky+capacity-weighted WFQ); latency_strict = strictly lowest forward floor; latency_sticky = lowest forward floor + sticky; min_rtt_strict = strictly lowest congestion-free floor; min_rtt_adaptive = floor + sticky+capacity-weighted WFQ; roundtrip_strict = strictly lowest current RTT.',
      fecHint:'auto = rotate across all healthy backends (default); near = only to backends within the window of the data path fwd, suppressing parity leakage to slower standby links.',
      windowHint:'Only for near: parity goes only to connections within N ms of the data path forward latency. Range 1-100.',
      gateHint:'rtt = gate on the kernel min_rtt round-trip floor (default, direction-blind); fwd = gate on this side\u2019s forward rank key, so an extremely asymmetric path that is fastest forward but slow round-trip still qualifies \u2014 its slow side is the peer\u2019s send direction, gated by the peer\u2019s own gate. Each side gates its own send direction.',
      gateWindowHint:'Only for fwd: a path qualifies when its forward latency is within N ms of the group minimum. Range 1-500. Falls back to the rtt gate when no forward reading has converged.',
      probeHint:'Physical anchor floor for the one-way delay decomposition: when the ref self-echo latency falls below it, it is clamped to this floor so extreme samples of degraded links cannot pollute the fwd gate and the near window. 0 = disable anchoring (debug only). Range 0-3600000, default 1000.',
      algos:{auto:'auto (default, sticky+WFQ)',latency_strict:'latency_strict (strict lowest forward)',latency_sticky:'latency_sticky (lowest forward + sticky)',min_rtt_strict:'min_rtt_strict (strict lowest congestion-free floor)',min_rtt_adaptive:'min_rtt_adaptive (floor + sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strict lowest current RTT)'},
      fecs:{auto:'auto (all healthy backends)',near:'near (fwd ≤ data path + window)'},
      gates:{rtt:'rtt (kernel round-trip floor, default)',fwd:'fwd (local forward rank key)'},
    },
    'de':{
      title:'Scheduler-Einstellungen',sub:'Routing-Algorithmus, Qualifikations-Tor & FEC-Parity-Verteilung. Heiß angewendet, kein Neustart.',labelAlgo:'Routing-Algorithmus',labelFec:'FEC-Parity-Strategie',labelWindow:'near-Fenster (ms)',labelGate:'Qualifikations-Tor',labelGateWindow:'fwd-Tor-Fenster (ms)',labelProbe:'probe_min-Anker-Untergrenze (µs)',
      labelPenalty:'Gesundheitsstrafe Einheit (µs)',
      penaltyHint:'Gesundheitsstrafe pro Ereignis auf den Routing-Rangschlüssel: eine Erhöhung pro aufeinanderfolgendem Probe-Timeout und je retransmittiertem Segment im 200ms-Fenster (jeweils gesamt auf 10ms begrenzt). 0 = Gesundheitsstrafen deaktiviert (auf Links mit konstantem Hintergrundverlust würde die Strafe den weiterhin schnellsten Pfad dauerhaft begraben). Bereich 0-60000, Standard 2000.',
      hint:'auto = stabiler Vorwärts-Boden + Servicezeit je Pfadkapazität (Sticky+kapazitätsgewichtetes WFQ); latency_strict = strikt niedrigster Vorwärts-Boden; latency_sticky = niedrigster Vorwärts-Boden + Sticky; min_rtt_strict = strikt niedrigster staufreier Boden; min_rtt_adaptive = Boden + Sticky+kapazitätsgewichtetes WFQ; roundtrip_strict = strikt niedrigste aktuelle RTT.',
      fecHint:'auto = Rotation über alle gesunden Backends (Standard); near = nur zu Backends im Fenster der Datenpfad-Fwd, unterdrückt Parity-Leck auf langsamere Standby-Links.',
      windowHint:'Nur für near: Parity nur zu Verbindungen innerhalb N ms der Vorwärts-Latenz des Datenpfads. Bereich 1-100.',
      gateHint:'rtt = Tor an der Kernel-min_rtt-Rundlauf-Untergrenze (Standard, richtungsblind); fwd = Tor am eigenen Forward-Rangschlüssel, sodass ein extrem asymmetrischer Pfad, der forward am schnellsten ist aber langsam rundläuft, trotzdem zugelassen wird \u2013 seine langsame Seite ist die Senderrichtung des Peers, vom Tor des Peers selbst gehalten. Jede Seite torrt ihre eigene Senderrichtung.',
      gateWindowHint:'Nur für fwd: ein Pfad ist zugelassen, wenn seine Forward-Latenz innerhalb N ms der Gruppenniedrigste liegt. Bereich 1-500. Fällt auf das rtt-Tor zurück, wenn keine Forward-Messung konvergiert ist.',
      probeHint:'Physikalische Anker-Untergrenze für die Einweg-Latenzzerlegung: Liegt die Eigen-Echo-Latenz von ref darunter, wird sie auf diesen Wert geklemmt, damit Extremwerte degradierter Links das fwd-Tor und das near-Fenster nicht verfälschen. 0 = Ankerung deaktiviert (nur Debug). Bereich 0-3600000, Standard 1000.',
      algos:{auto:'auto (Standard, Sticky+WFQ)',latency_strict:'latency_strict (strikt niedrigste Vorwärts-Latenz)',latency_sticky:'latency_sticky (niedrigste Vorwärts-Latenz + Sticky)',min_rtt_strict:'min_rtt_strict (strikt niedrigster staufreier Boden)',min_rtt_adaptive:'min_rtt_adaptive (Boden + Sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strikt niedrigste aktuelle RTT)'},
      fecs:{auto:'auto (alle gesunden Backends)',near:'near (fwd ≤ Datenpfad + Fenster)'},
      gates:{rtt:'rtt (Kernel-Rundlauf-Untergrenze, Standard)',fwd:'fwd (eigener Forward-Rangschlüssel)'},
    },
    'fr':{
      title:'Paramètres de l’ordonnanceur',sub:'Algorithme de routage, porte d’admission & distribution de parité FEC. Appliqué à chaud, sans redémarrage.',labelAlgo:'Algorithme de routage',labelFec:'Stratégie de parité FEC',labelWindow:'fenêtre near (ms)',labelGate:'Porte d’admission',labelGateWindow:'fenêtre fwd (ms)',labelProbe:'plancher d’ancrage probe_min (µs)',
      labelPenalty:'unité de pénalité santé (µs)',
      penaltyHint:'Pénalité santé par événement ajoutée à la clé de rang de routage : une hausse par timeout de sonde consécutif et par segment retransmis dans la fenêtre de 200 ms (chacune plafonnée à 10 ms au total). 0 = pénalités désactivées (sur les liens à perte de fond constante, la pénalité enterrerait durablement le chemin toujours le plus rapide). Plage 0-60000, défaut 2000.',
      hint:'auto = plancher avant stable + temps de service selon la capacité du chemin (sticky+WFQ pondéré par capacité) ; latency_strict = strictement le plancher avant le plus bas ; latency_sticky = plancher avant le plus bas + sticky ; min_rtt_strict = strictement le plancher sans congestion le plus bas ; min_rtt_adaptive = plancher + sticky+WFQ pondéré par capacité ; roundtrip_strict = strictement la RTT actuelle la plus basse.',
      fecHint:'auto = rotation sur tous les backends sains (défaut) ; near = uniquement aux backends dans la fenêtre de la fwd du chemin de données, supprime la fuite de parité vers les liens standby plus lents.',
      windowHint:'Uniquement pour near : parité envoyée aux connexions à N ms de la latence aller du chemin de données. Plage 1-100.',
      gateHint:'rtt = porte sur le plancher de min_rtt aller-retour du noyau (défaut, insensible à la direction) ; fwd = porte sur la clé de rang aller de ce côté, de sorte qu’un chemin très asymétrique, le plus rapide en aller mais lent en aller-retour, soit quand même admis — son côté lent est la direction d’envoi du pair, filtré par la porte du pair. Chaque côté filtre sa propre direction d’envoi.',
      gateWindowHint:'Uniquement pour fwd : un chemin est admis si sa latence aller est dans les N ms du minimum du groupe. Plage 1-500. Repli sur la porte rtt si aucune mesure aller n’est convergée.',
      probeHint:'Plancher physique d’ancrage pour la décomposition de la latence unidirectionnelle : quand la latence d’écho propre de ref passe dessous, elle est ramenée à ce plancher, afin que les échantillons extrêmes des liens dégradés ne polluent pas la porte fwd ni la fenêtre near. 0 = ancrage désactivé (débogage uniquement). Plage 0-3600000, défaut 1000.',
      algos:{auto:'auto (défaut, sticky+WFQ)',latency_strict:'latency_strict (strictement le plus bas aller)',latency_sticky:'latency_sticky (plus bas aller + sticky)',min_rtt_strict:'min_rtt_strict (strictement le plus bas plancher sans congestion)',min_rtt_adaptive:'min_rtt_adaptive (plancher + sticky+WFQ)',roundtrip_strict:'roundtrip_strict (strictement la plus basse RTT actuelle)'},
      fecs:{auto:'auto (tous les backends sains)',near:'near (fwd ≤ chemin de données + fenêtre)'},
      gates:{rtt:'rtt (plancher aller-retour du noyau, défaut)',fwd:'fwd (clé de rang aller locale)'},
    },
    'ja':{
      title:'スケジューラ設定',sub:'選路アルゴリズム、資格ゲートと FEC パリティ配布。ホット適用、再起動不要。',labelAlgo:'選路アルゴリズム',labelFec:'FEC パリティ戦略',labelWindow:'near ウィンドウ (ms)',labelGate:'候補資格ゲートの次元',labelGateWindow:'fwd ゲート窓 (ms)',labelProbe:'probe_min アンカー下限 (µs)',
      labelPenalty:'ヘルスペナルティ単位 (µs)',
      penaltyHint:'選路ランキングキーに加算されるイベント毎のヘルスペナルティ：プローブ連続タイムアウト毎、200ms 窓の再送セグメント毎に 1 回引き上げ（それぞれ合計 10ms で封頂）。0=ヘルスペナルティ無効（常時背景ロスのあるリンクでは、ペナルティが依然最速の経路を永久に埋没させる）。範囲 0-60000、デフォルト 2000。',
      hint:'auto=安定した往路フロア＋経路容量に応じたサービス時間（スティッキー+容量重み付きWFQ）；latency_strict=厳密に最低の往路フロア；latency_sticky=最低の往路フロア＋スティッキー；min_rtt_strict=厳密に最低の輻輳なしフロア；min_rtt_adaptive=フロア＋スティッキー+容量重み付きWFQ；roundtrip_strict=厳密に最低の現在RTT。',
      fecHint:'auto=全健全バックエンドでローテーション（デフォルト）；near=データパス fwd のウィンドウ内のみ、遅いスタンバイリンクへのパリティ漏れを抑制。',
      windowHint:'near のみ：データパスの往路遅延から N ms 以内の接続にのみパリティを送信。範囲 1-100。',
      gateHint:'rtt=カーネル min_rtt の往復フロアでゲート（デフォルト、方向盲）；fwd=本側の往路ランキングキーでゲートし、「往路は最速だが往復が遅い」極端に非対称なパスも准入できるようにする——その遅い側は対向側の送信方向であり、対向側自身のゲートが遮断する。両端がそれぞれ自らの送信方向でゲートする。',
      gateWindowHint:'fwd のみ：往路遅延がグループ最小値から N ms 以内なら准入。範囲 1-500。収束した往路読数がない場合は rtt ゲートに自動フォールバック。',
      probeHint:'片道遅延分解の物理アンカー下限：ref の自エコー遅延がこの値を下回った場合はこの値にクランプし、劣化リンクの極端なサンプルが fwd ゲートや near ウィンドウを汚染しないようにする。0=アンカー無効（デバッグ専用）。範囲 0-3600000、デフォルト 1000。',
      algos:{auto:'auto（デフォルト、スティッキー+WFQ）',latency_strict:'latency_strict（厳密に最低の往路）',latency_sticky:'latency_sticky（最低往路＋スティッキー）',min_rtt_strict:'min_rtt_strict（厳密に最低の輻輳なしフロア）',min_rtt_adaptive:'min_rtt_adaptive（フロア＋スティッキー+WFQ）',roundtrip_strict:'roundtrip_strict（厳密に最低の現在RTT）'},
      fecs:{auto:'auto（全健全バックエンド）',near:'near（往路 ≤ データパス＋ウィンドウ）'},
      gates:{rtt:'rtt（カーネル往復フロア、デフォルト）',fwd:'fwd（本側往路ランキングキー）'},
    },
  };

  const css=document.createElement('style');
  css.textContent=`
    .rts-box{margin:12px 0 16px;padding:16px;border:1px solid var(--border);border-radius:12px;background:var(--card)}
    .rts-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px}.rts-head h3{margin:0 0 4px;font-size:16px}.rts-head p{margin:0;color:var(--sub);font-size:12px}
    .rts-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
    .rts-field{display:flex;flex-direction:column;gap:6px}.rts-field.wide{grid-column:1/-1}
    .rts-field label{font-size:12px;color:var(--sub);font-weight:600}
    .rts-field select,.rts-field input{width:100%;box-sizing:border-box;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 10px;font:inherit}
    .rts-help{font-size:11px;color:var(--sub);line-height:1.45}
    @media(max-width:760px){.rts-grid{grid-template-columns:1fr}}
  `;
  document.head.appendChild(css);

  const root=document.createElement('div');
  root.className='rts-box';
  root.innerHTML=`
    <div class="rts-head"><div><h3 data-rts-t="title"></h3><p data-rts-t="sub"></p></div></div>
    <div class="rts-grid">
      <div class="rts-field wide"><label data-rts-t="labelAlgo"></label>
        <select id="routing-algo">
          <option value="auto"></option><option value="latency_strict"></option><option value="latency_sticky"></option>
          <option value="min_rtt_strict"></option><option value="min_rtt_adaptive"></option><option value="roundtrip_strict"></option>
        </select>
        <div class="rts-help" data-rts-t="hint"></div>
      </div>
      <div class="rts-field"><label data-rts-t="labelFec"></label>
        <select id="fec-strategy"><option value="auto"></option><option value="near"></option></select>
        <div class="rts-help" data-rts-t="fecHint"></div>
      </div>
      <div class="rts-field" data-fec-near style="display:none"><label data-rts-t="labelWindow"></label>
        <input id="fec-near-window" type="number" min="1" max="100" step="1" inputmode="numeric">
        <div class="rts-help" data-rts-t="windowHint"></div>
      </div>
      <div class="rts-field"><label data-rts-t="labelGate"></label>
        <select id="sched-envelope"><option value="rtt"></option><option value="fwd"></option></select>
        <div class="rts-help" data-rts-t="gateHint"></div>
      </div>
      <div class="rts-field" data-sched-fwd style="display:none"><label data-rts-t="labelGateWindow"></label>
        <input id="sched-envelope-window" type="number" min="1" max="500" step="1" inputmode="numeric">
        <div class="rts-help" data-rts-t="gateWindowHint"></div>
      </div>
      <div class="rts-field"><label data-rts-t="labelProbe"></label>
        <input id="probe-min-half-rtt" type="number" min="0" max="3600000" step="1" inputmode="numeric">
        <div class="rts-help" data-rts-t="probeHint"></div>
      </div>
      <div class="rts-field"><label data-rts-t="labelPenalty"></label>
        <input id="sched-health-penalty" type="number" min="0" max="60000" step="1" inputmode="numeric">
        <div class="rts-help" data-rts-t="penaltyHint"></div>
      </div>
    </div>`;
  editor.parentNode.insertBefore(root,editor);

  const q=id=>document.getElementById(id);
  const algo=q('routing-algo'),fec=q('fec-strategy'),windowEl=q('fec-near-window');
  const gate=q('sched-envelope'),gateWindow=q('sched-envelope-window'),probe=q('probe-min-half-rtt');
  const penalty=q('sched-health-penalty');
  if(!algo||!fec||!windowEl||!gate||!gateWindow||!probe||!penalty)return;

  function lang(){const l=document.documentElement.lang||'en';return COPY[l]||COPY.en;}
  function translate(){
    const c=lang();
    root.querySelectorAll('[data-rts-t]').forEach(el=>{const k=el.dataset.rtsT;if(c[k]!=null)el.textContent=c[k];});
    Array.from(algo.options).forEach(o=>{o.textContent=c.algos[o.value]||o.value;});
    Array.from(fec.options).forEach(o=>{o.textContent=c.fecs[o.value]||o.value;});
    Array.from(gate.options).forEach(o=>{o.textContent=c.gates[o.value]||o.value;});
  }
  function parseEditor(){try{return JSON.parse(editor.value||'{}');}catch(_){return null;}}
  // optionValue 在 options 里线性找值：不能用 querySelector('option[value="…"]')，
  // JSON 里用户可控的值拼进属性选择器（含引号）会抛 SyntaxError 把整个加载炸掉。
  function optionValue(sel,v){
    if(v===undefined||v===null)return false;
    v=String(v);
    return Array.from(sel.options).some(function(o){return o.value===v;});
  }
  function updateNearVisibility(){root.querySelectorAll('[data-fec-near]').forEach(el=>{el.style.display=fec.value==='near'?'':'none';});}
  function updateGateVisibility(){root.querySelectorAll('[data-sched-fwd]').forEach(el=>{el.style.display=gate.value==='fwd'?'':'none';});}
  function fromEditor(){
    const cfg=parseEditor();if(!cfg)return false;
    // 六字段在 Config 顶层（全局，client 上行 / server 下行共用）。
    const av=cfg.routing_algo;
    if(av&&optionValue(algo,av))algo.value=String(av);
    const fv=cfg.fec_strategy;
    if(fv&&optionValue(fec,fv))fec.value=String(fv);
    // 数值键存在（含 0 与越界值）就原样显示：number input 接受任意值，静默置空
    // 会让用户以为没写进去；保存时后端 400 才显示真实错误。键缺失才留空，
    // probe 缺失显示后端默认 1000。
    windowEl.value=(cfg.fec_near_window_ms!=null)?String(cfg.fec_near_window_ms):'';
    const gv=cfg.sched_envelope;
    if(gv&&optionValue(gate,gv))gate.value=String(gv);
    gateWindow.value=(cfg.sched_envelope_ms!=null)?String(cfg.sched_envelope_ms):'';
    probe.value=(cfg.probe_min_half_rtt_us!=null)?String(cfg.probe_min_half_rtt_us):'1000';
    penalty.value=(cfg.sched_health_penalty_us!=null)?String(cfg.sched_health_penalty_us):'2000';
    updateNearVisibility();updateGateVisibility();return true;
  }
  // syncDom=true：用户主动改下拉/输入框，DOM 值（合法）写入编辑器。probe 的
  // 空/非法值删键让后端落默认 1000——0 是合法值（禁用锚定）必须可保存，非法值
  // 不吞成 1000。
  // syncDom=false：保存前。只补空——编辑器里已有的值（无论是否合法）一律保留，
  // 让非法值原样送往后端校验并显示真实错误，而不是被静默强改成 auto/10。
  // 数值字段的补空语义与枚举字段一致：DOM 当前值合法就用它，否则落硬编码缺省
  // （probe 例外：DOM 无合法值时不写键，与"非法送后端校验"的既有语义一致）。
  function toEditor(syncDom){
    const cfg=parseEditor();if(!cfg)return false;
    if(syncDom){
      cfg.routing_algo=algo.value||'auto';
      cfg.fec_strategy=fec.value||'auto';
      const w=parseInt(windowEl.value,10);
      cfg.fec_near_window_ms=(w>=1&&w<=100)?w:10;
      cfg.sched_envelope=gate.value||'rtt';
      const gw=parseInt(gateWindow.value,10);
      cfg.sched_envelope_ms=(gw>=1&&gw<=500)?gw:20;
      const pv=parseInt(probe.value,10);
      if(pv>=0&&pv<=3600000)cfg.probe_min_half_rtt_us=pv;
      else delete cfg.probe_min_half_rtt_us;
      const hp=parseInt(penalty.value,10);
      if(hp>=0&&hp<=60000)cfg.sched_health_penalty_us=hp;
      else delete cfg.sched_health_penalty_us;
    }else{
      if(!cfg.routing_algo)cfg.routing_algo=algo.value||'auto';
      if(!cfg.fec_strategy)cfg.fec_strategy=fec.value||'auto';
      if(cfg.fec_near_window_ms==null){
        const w=parseInt(windowEl.value,10);
        cfg.fec_near_window_ms=(w>=1&&w<=100)?w:10;
      }
      if(!cfg.sched_envelope)cfg.sched_envelope=gate.value||'rtt';
      if(cfg.sched_envelope_ms==null){
        const gw=parseInt(gateWindow.value,10);
        cfg.sched_envelope_ms=(gw>=1&&gw<=500)?gw:20;
      }
      if(cfg.probe_min_half_rtt_us==null){
        const pv=parseInt(probe.value,10);
        if(pv>=0&&pv<=3600000)cfg.probe_min_half_rtt_us=pv;
      }
      if(cfg.sched_health_penalty_us==null){
        const hp=parseInt(penalty.value,10);
        if(hp>=0&&hp<=60000)cfg.sched_health_penalty_us=hp;
      }
    }
    editor.value=JSON.stringify(cfg,null,2);
    return true;
  }

  root.addEventListener('change',ev=>{
    if(ev.target===fec)updateNearVisibility();
    if(ev.target===gate)updateGateVisibility();
    if(ev.target===algo||ev.target===fec||ev.target===windowEl||ev.target===gate||ev.target===gateWindow||ev.target===probe||ev.target===penalty)toEditor(true);
  });
  translate();fromEditor();

  // JSON 编辑器是唯一事实来源：用户在编辑器里手动改字段时，下拉/输入框必须
  // 实时跟随，否则「渲染旧值、JSON 新值」分裂。programmatic 的 editor.value=
  // 赋值（loadConfig / 保存回写）不触发 input，由下方 loadConfig/saveConfig
  // 包装负责；这里只覆盖用户手动键入/粘贴。
  // fromEditor 改 DOM 值不触发 change/input（programmatic set 不发事件），
  // 因此不会与下方 change→toEditor 形成写回循环。
  editor.addEventListener('input',fromEditor);

  const originalLoad=window.loadConfig;
  if(typeof originalLoad==='function')window.loadConfig=async function(){const r=await originalLoad.apply(this,arguments);fromEditor();return r;};
  const originalSave=window.saveConfig;
  // 保存（无论是否热应用）后都回填 fromEditor：仅保存时编辑器保留用户输入值，
  // 下拉/输入框须与之对齐，否则设置页内部（渲染 vs JSON）就分裂。此前只在
  // apply=true 时回填，仅保存后下拉框停在旧值。
  if(typeof originalSave==='function')window.saveConfig=async function(){toEditor(false);const r=await originalSave.apply(this,arguments);setTimeout(fromEditor,0);return r;};

  // 兜底：loadConfig / 保存回写对 editor.value 是 programmatic 赋值（不触发
  // input），且 window.loadConfig 被多个后续脚本（mcp-settings/mcp-examples）
  // 再次包装——若其中任一包装在链上抛异常或未保存 previousLoad，上方包装的
  // fromEditor 就不会执行，下拉/输入框停在旧值。这里以轮询检测 editor 内容
  // 变化，任何来源的写入（加载、保存回写、手动）都保证 fromEditor 回填，
  // 使渲染永远跟随 JSON 编辑器这一唯一事实来源。仅比较字符串，开销可忽略。
  let lastEditorValue=editor.value;
  setInterval(function(){if(editor.value!==lastEditorValue){lastEditorValue=editor.value;fromEditor();}},400);
})();
