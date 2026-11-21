/* Server-sampled diagnostic history. Null observations deliberately break lines. */
(function(){
  'use strict';
  const words={
    'zh-CN':['路径与开销趋势','客户端','连接','全部','各连接吞吐','各连接 RTT','调度负载','FEC 效果','Padding 开销','连接与异常','上行','下行','分配速率','队列积压','校验开销','恢复','未恢复','校验字节','填充字节','线路占比','在线连接','重连尝试','队列丢帧','TAP 写失败','等待服务端采样','与顶部时间范围同步；重启清空。每 2 秒采样，长范围按分钟聚合；无实测值处断线。最多保留每点 32 条连接，默认展示最近 8 条，可筛选历史连接。','采样连接数量已达上限','字节开销为本机发送，恢复/未恢复为本机接收；FEC 开销 = 校验 / DATA 字节，Padding 占比 = 填充 / 线路字节。','长范围：速率与 RTT 为区间均值，在线连接和队列也为均值；异常为每秒速率。','各连接单向时延','去程','回程','时钟偏移未收敛','单向时延为锚定近似（未解不对称度）','时钟偏移'],
    'zh-TW':['路徑與開銷趨勢','用戶端','連線','全部','各連線吞吐','各連線 RTT','排程負載','FEC 效果','Padding 開銷','連線與異常','上行','下行','分配速率','佇列積壓','校驗開銷','恢復','未恢復','校驗位元組','填充位元組','線路占比','在線連線','重連嘗試','佇列丟幀','TAP 寫入失敗','等待伺服器採樣','與頂部時間範圍同步；重啟清空。每 2 秒採樣，長範圍按分鐘聚合；無實測值處斷線。每點最多 32 條連線，預設顯示最近 8 條，可篩選歷史連線。','採樣連線數量已達上限','位元組開銷為本機傳送，恢復/未恢復為本機接收；FEC 開銷 = 校驗 / DATA 位元組，Padding 占比 = 填充 / 線路位元組。','長範圍：速率、RTT、在線連線及佇列為區間均值；異常為每秒速率。','各連線單向時延','去程','回程','時鐘偏移未收斂','單向時延為錨定近似（未解不對稱度）','時鐘偏移'],
    en:['Path and overhead history','Client','Connection','All','Connection throughput','Connection RTT','Scheduler load','FEC effectiveness','Padding overhead','Connections and errors','Upload','Download','Assigned rate','Queued bytes','Parity overhead','Recovered','Unrecovered','Parity bytes','Padding bytes','Wire share','Online connections','Reconnect attempts','Backpressure drops','TAP write errors','Waiting for server samples','Uses the time range above; restart clears history. Samples every 2 seconds; long ranges use minute aggregates. Missing measurements break lines. Up to 32 connections per sample; the latest 8 are shown by default. Historical connections can be selected.','Sample connection limit reached','Byte overhead is local TX; recovery/loss is local RX. FEC overhead = parity / DATA bytes. Padding share = padding / wire bytes.','Long ranges: rates, RTT, online connections and queues are interval means; errors are rates per second.','Per-connection one-way delay','Forward','Return','Clock offset not converged','One-way delay is anchor-approximate (asymmetry unsolved)','Clock offset'],
    de:['Pfad- und Overhead-Verlauf','Client','Verbindung','Alle','Durchsatz je Verbindung','RTT je Verbindung','Scheduler-Last','FEC-Wirkung','Padding-Overhead','Verbindungen und Fehler','Upload','Download','Zuweisungsrate','Warteschlange','Paritäts-Overhead','Wiederhergestellt','Nicht wiederhergestellt','Paritätsbytes','Padding-Bytes','Leitungsanteil','Online-Verbindungen','Neuversuche','Warteschlangenverluste','TAP-Schreibfehler','Warten auf Server-Messwerte','Zeitraum wie oben; Neustart löscht den Verlauf. Messung alle 2 Sekunden, lange Bereiche als Minutenmittel. Fehlende Werte unterbrechen Linien. Bis 32 Verbindungen pro Messung; zuletzt 8 sichtbar, historische Verbindungen auswählbar.','Verbindungslimit erreicht','Byte-Overhead: lokaler TX; Wiederherstellung/Verlust: lokaler RX. FEC = Paritäts-/DATA-Bytes. Padding = Padding-/Leitungsbytes.','Lange Bereiche: Raten, RTT, Verbindungen und Warteschlangen sind Mittelwerte; Fehler pro Sekunde.','Einwegverzögerung je Verbindung','Hinweg','Rückweg','Uhrenversatz nicht konvergiert','Einwegverzögerung ist Anker-Approximation (Asymmetrie ungelöst)','Uhrenversatz'],
    fr:['Historique des chemins et surcoûts','Client','Connexion','Toutes','Débit par connexion','RTT par connexion','Charge de répartition','Efficacité FEC','Surcoût padding','Connexions et erreurs','Envoi','Réception','Débit affecté','Octets en attente','Surcoût parité','Récupérées','Non récupérées','Octets de parité','Octets de padding','Part du trafic','Connexions actives','Reconnexions tentées','Pertes de file','Erreurs écriture TAP','En attente des mesures serveur','Même période que ci-dessus ; historique effacé au redémarrage. Mesure toutes les 2 secondes, agrégation par minute pour les longues périodes. Les mesures absentes interrompent les courbes. Maximum 32 connexions par mesure ; les 8 dernières sont affichées, les anciennes peuvent être sélectionnées.','Limite de connexions atteinte','Octets : émission locale ; récupération/perte : réception locale. FEC = octets parité / DATA. Padding = octets padding / trafic.','Longues périodes : débits, RTT, connexions et files sont des moyennes ; erreurs par seconde.','Délai unidirectionnel par connexion','Aller','Retour','Décalage d\'horloge non convergé','Délai unidirectionnel approximatif par ancrage (asymétrie non résolue)','Décalage d\'horloge'],
    ja:['経路とオーバーヘッドの履歴','クライアント','接続','すべて','接続別スループット','接続別 RTT','スケジューラ負荷','FEC 効果','Padding オーバーヘッド','接続と異常','上り','下り','割当速度','待機バイト','パリティ比率','復元','未復元','パリティバイト','Padding バイト','通信量比率','オンライン接続','再接続試行','キュー破棄','TAP 書込エラー','サーバーの測定待ち','上部と同じ期間。再起動で履歴を消去。2 秒ごとに測定、長期間は分単位で集約。未測定箇所は線を切断。各測定は最大32接続、既定で最新8接続を表示。過去の接続も選択可能。','測定接続数の上限に達しました','バイト開銷はローカル送信、復元/未復元はローカル受信。FEC = パリティ / DATA バイト。Padding = Padding / 通信バイト。','長期間は速度、RTT、接続数、待機量の平均。異常は毎秒の発生率。','接続別の片道遅延','往路','復路','クロックオフセット未収束','片道遅延はアンカー近似（非対称未解決）','クロックオフセット']
  };
  const text=i=>(words[typeof LANG==='string'?LANG:'en']||words.en)[i];
  let history=null,hoverTime=null;
  // cssv 走 getComputedStyle：一次 draw 里要取 ~80-100 次。主题切换前不变，
  // 按 draw 缓存（applyTheme 包装器里失效）。
  const cssvCache=new Map();
  const cv=n=>{if(!cssvCache.has(n))cssvCache.set(n,cssv(n));return cssvCache.get(n);};
  // pointermove/resize 的重绘合并到 rAF/150ms 防抖：hover 每格一挪就全量重绘
  // 12 块 canvas，24h 档明显掉帧；拖拽窗口同理。
  let drawQueued=false;
  const scheduleDraw=()=>{if(drawQueued)return;drawQueued=true;requestAnimationFrame(()=>{drawQueued=false;draw();});};
  let resizeTimer=null;
  const colors=['#6554ff','#08a579','#cf8200','#2589c7','#dc5478','#9868b8','#6e9835','#bd6940'];
  // 各连接单向时延：去程/回程各用一族颜色（冷/暖）以便一眼分清方向，
  // 族内仍按连接索引错开，保证同方向多条连接彼此可辨。
  const fwdColors=['#4da3ff','#2ec4b6','#8b7bff','#39a8d8','#6b9bff','#00b3a4','#a78bfa','#2f7fd4'];
  const retColors=['#ff9f45','#f25c5c','#e0a800','#ff7ab8','#d94f9e','#ff8a5c','#c25e3a','#b8860b'];
  const section=document.createElement('section');section.className='card diagnostic-section';section.id='diagnostic-section';
  section.innerHTML='<div class="chart-head"><h2 class="card-title" id="diag-title"></h2><span id="diag-at" class="dim mono"></span><div class="seg" id="diag-range"><button data-v="2m" data-diag-range="2m"></button><button data-v="1h" data-diag-range="1h"></button><button data-v="24h" data-diag-range="24h"></button></div><label><span id="diag-client-label"></span> <select id="diag-client"></select></label><label><span id="diag-conn-label"></span> <select id="diag-conn"></select></label></div><p class="dim" id="diag-note"></p><p class="dim" id="diag-scope"></p><p class="dim" id="diag-aggregate"></p><p id="diag-limit" class="dim"></p><div class="diagnostic-grid"><div class="diagnostic-col" id="diag-col-0"></div><div class="diagnostic-col" id="diag-col-1"></div></div>';
  document.querySelector('.chart-card').after(section);
  // 卡片两列分布：按估计高度最短列优先贪心。此前是 2 列 grid，同一行的两张卡
  // 高度被行轨道拉齐——FEC 效果有 3 个子图而调度负载只有 2 个，矮卡下方留出
  // 成片空白（用户报告的"为什么不是瀑布流"）。改为两列各自堆叠（瀑布流）：
  // 子图数量是宽度的无关量（canvas 高度固定 150px），估计高度 = 子图数×常数
  // + 卡片基础高度，贪心后两列高度差只剩零头。
  const CARD_TITLES=[4,5,6,7,8,9,29];
  const CARD_PANELS=[1,1,2,3,2,2,1]; // 吞吐/RTT/调度负载/FEC/Padding/连接与异常/单向时延 各自的子图数
  const cards=CARD_TITLES.map((title,i)=>({title,i,h:CARD_PANELS[i]*178+54}));
  const diagCols=[[],[]],colH=[0,0];
  cards.forEach(card=>{const c=colH[0]<=colH[1]?0:1;diagCols[c].push(card);colH[c]+=card.h;});
  diagCols.forEach(function(list,c){
    const col=document.getElementById('diag-col-'+c);
    list.forEach(function(card){
      // 单向时延卡片是 title=29（text(29)='各连接单向时延'）：θ/U 时钟偏移徽标
      // 说明 fwd/ret 拆分的置信度，属于单向时延卡片。此前写成 title===9 把徽标
      // 挂到了"连接与异常"卡片头上，单向时延卡片反而没有。
      const badge=card.title===29?'<span id="diag-clk" class="dim" style="font-weight:400;font-size:11px;margin-left:8px"></span>':'';
      const art=document.createElement('article');art.className='diagnostic-card';
      art.innerHTML='<h3 data-diag-title="'+card.title+'">'+badge+'</h3><div id="diag-body-'+card.i+'"></div>';
      col.append(art);
    });
  });
  const client=document.getElementById('diag-client'),conn=document.getElementById('diag-conn');
  function options(select,entries){const old=select.value;select.replaceChildren();[["",text(3)],...entries].forEach(([id,label])=>{const option=document.createElement('option');option.value=id;option.textContent=label;select.append(option);});if(entries.some(e=>e[0]===old))select.value=old;buildSelect(select);syncSelect(select);}
  function identities(){const ids=new Map();(history?.points||[]).forEach(p=>(p.conns||[]).forEach(c=>{ids.delete(c.id);ids.set(c.id,c);}));return [...ids.values()].reverse();}
  function updateOptions(){const ids=identities();options(client,[...new Set(ids.map(c=>c.client))].sort().map(id=>[id,id]));options(conn,ids.filter(c=>!client.value||c.client===client.value).map(c=>[c.id,c.client+' · '+c.label+' · '+c.id.slice(0,8)]));}
  function timeLabel(tick){return chartRange==='24h'?new Date(tick).toLocaleString(typeof LANG==='string'?LANG:'en',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}):fmtHM(tick);}
  function labels(){document.getElementById('diag-title').textContent=text(0);document.getElementById('diag-client-label').textContent=text(1);document.getElementById('diag-conn-label').textContent=text(2);document.getElementById('diag-note').textContent=text(25);document.getElementById('diag-scope').textContent=text(27);document.getElementById('diag-aggregate').textContent=text(28);section.querySelectorAll('[data-diag-title]').forEach(el=>{
    // 单向时延卡片标题内含 clk 徽标 span：只改首个文本节点，勿 textContent= 清掉徽标。
    if(el.firstChild&&el.firstChild.nodeType===3){el.firstChild.nodeValue=text(Number(el.dataset.diagTitle));}else{el.textContent=text(Number(el.dataset.diagTitle));}
  });updateOptions();draw();}
  // format 时延类单位用自适应小数（与 app.js fmtMsUs 同口径）：固定 toFixed(2)
  // 会把亚毫秒真实值（LAN/回环 0.2-0.9ms、δ 相对地板 0.001ms）显示成 "0 ms"。
  const fmtMs=v=>{const d=v>=100?0:v>=10?1:v>=1?2:3;return String(Number(v.toFixed(d)));};
  function format(v,unit){if(v==null)return '—';if(unit==='bytes')return fmtBytes(v,true);if(unit==='queue')return fmtBytes(v);return (unit==='ms'?fmtMs(v):Number(v.toFixed(2)))+(unit==='ms'?' ms':unit==='pct'?'%':unit==='rate'?'/s':'');}
  function panel(card,key,series,unit){
    const body=document.getElementById('diag-body-'+card);let wrap=document.getElementById('diag-wrap-'+key);
    if(!wrap){wrap=document.createElement('div');wrap.id='diag-wrap-'+key;wrap.innerHTML='<canvas id="diag-'+key+'" height="150"></canvas><div class="legend diagnostic-legend"></div>';body.append(wrap);const canvas=wrap.querySelector('canvas');canvas.addEventListener('pointermove',ev=>{const rect=canvas.getBoundingClientRect(),plot=canvas.diagPlot;if(!plot||!history?.points.length)return;const x=Math.max(0,Math.min(1,(ev.clientX-rect.left-plot.l)/(plot.r-plot.l)));const target=plot.first+x*(plot.last-plot.first);hoverTime=history.points.reduce((best,p)=>Math.abs(p.t-target)<Math.abs(best.t-target)?p:best).t;scheduleDraw();});canvas.addEventListener('pointerleave',()=>{hoverTime=null;scheduleDraw();});}
    const canvas=wrap.querySelector('canvas'),ctx=canvas.getContext('2d'),W=canvas.clientWidth||320,H=150,dpr=window.devicePixelRatio||1;
    // 位图尺寸只在变化时重设（重设会强制布局失效，每帧 ×12 面板）。但注意：
    // width/height 赋值同时是 canvas 的清屏手段——尺寸不变而跳过重设时必须
    // 显式清屏，否则每帧都画在上一帧残影上（轴标签/悬停提示框逐帧堆积成鬼影）。
    const bw=Math.round(W*dpr),bh=Math.round(H*dpr);
    if(canvas.width!==bw||canvas.height!==bh){canvas.width=bw;canvas.height=bh;}
    ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.setTransform(dpr,0,0,dpr,0,0);ctx.font='10px sans-serif';
    const pts=history?.points||[];let max=1;series.forEach(s=>pts.forEach(p=>{const v=s.value(p);if(v!=null&&Number.isFinite(v))max=Math.max(max,v);}));
    const ticks=[max,max/2,0].map(v=>format(v,unit));const L=Math.ceil(Math.max(...ticks.map(s=>ctx.measureText(s).width)))+14,R=12,T=12,B=24,pw=W-L-R,ph=H-T-B;
    const first=pts[0]?.t||0,last=pts[pts.length-1]?.t||first+1,x=t=>L+(t-first)/Math.max(1,last-first)*pw,y=v=>T+(1-v/max)*ph;
    canvas.diagPlot={l:L,r:W-R,first,last};ctx.textAlign='right';ticks.forEach((tick,i)=>{const yy=T+i*ph/2;ctx.strokeStyle=cv('--grid');ctx.setLineDash([3,4]);ctx.beginPath();ctx.moveTo(L,yy+.5);ctx.lineTo(W-R,yy+.5);ctx.stroke();ctx.setLineDash([]);ctx.fillStyle=cv('--sub');ctx.fillText(tick,L-6,yy+3);});
    series.forEach((s,j)=>{const col=s.color||colors[j%colors.length];
      // 按 gap 切分为连续段（每段独立平滑，避免跨断点连线）
      const segments=[];let seg=[];let previous=0;
      pts.forEach(p=>{const v=s.value(p);if(v==null||!Number.isFinite(v)){if(seg.length)segments.push(seg);seg=[];return;}const xx=x(p.t),yy=y(v);if(seg.length&&p.t-previous>(history.step_sec||2)*2500){segments.push(seg);seg=[];}seg.push({x:xx,y:yy});previous=p.t;});
      if(seg.length)segments.push(seg);
      // 单系列：先铺面积渐变，折线覆盖其上
      if(series.length===1)segments.forEach(P=>{if(P.length<2)return;const grad=ctx.createLinearGradient(0,T,0,H-B);grad.addColorStop(0,col+'2e');grad.addColorStop(.55,col+'14');grad.addColorStop(1,col+'00');ctx.beginPath();ctx.moveTo(P[0].x,H-B);P.forEach(q=>ctx.lineTo(q.x,q.y));ctx.lineTo(P[P.length-1].x,H-B);ctx.closePath();ctx.fillStyle=grad;ctx.fill();});
      // 平滑曲线（Catmull-Rom→Bezier，与主趋势图一致）
      ctx.strokeStyle=col;ctx.lineWidth=2;ctx.lineJoin='round';ctx.lineCap='round';ctx.setLineDash(s.dash?[4,3]:[]);
      segments.forEach(P=>{ctx.beginPath();ctx.moveTo(P[0].x,P[0].y);for(let i=0;i<P.length-1;i++){const p0=P[Math.max(0,i-1)],p1=P[i],p2=P[i+1],p3=P[Math.min(P.length-1,i+2)];ctx.bezierCurveTo(p1.x+(p2.x-p0.x)/6,p1.y+(p2.y-p0.y)/6,p2.x-(p3.x-p1.x)/6,p2.y-(p3.y-p1.y)/6,p2.x,p2.y);}ctx.stroke();});
      ctx.setLineDash([]);
      // 数据点：密度大时稀疏点缀，稀疏时逐点
      const every=Math.max(1,Math.round(pts.length/16));ctx.fillStyle=col;
      segments.forEach(P=>P.forEach((q,i)=>{if(i%every===0||i===P.length-1){ctx.beginPath();ctx.arc(q.x,q.y,1.8,0,Math.PI*2);ctx.fill();}}));
    });
    ctx.fillStyle=cv('--sub');ctx.textAlign='center';(chartRange==='24h'?(pw<ctx.measureText(timeLabel(first)).width+ctx.measureText(timeLabel(last)).width+8?[1]:[0,1]):[0,0.5,1]).forEach(f=>{if(!pts.length)return;const label=timeLabel(first+f*(last-first));const tw=ctx.measureText(label).width;ctx.fillText(label,Math.max(L+tw/2,Math.min(L+f*pw,W-R-tw/2)),H-7);});
    const selected=pts.find(p=>p.t===hoverTime);canvas.dataset.diagHover=selected?String(selected.t):'';
    if(selected){ctx.strokeStyle=cv('--border2');ctx.setLineDash([3,3]);ctx.beginPath();ctx.moveTo(x(selected.t)+.5,T);ctx.lineTo(x(selected.t)+.5,H-B);ctx.stroke();ctx.setLineDash([]);
      // 悬停数据点圆标
      series.forEach((s,j)=>{const v=s.value(selected);if(v==null||!Number.isFinite(v))return;ctx.beginPath();ctx.arc(x(selected.t),y(v),3.5,0,Math.PI*2);ctx.fillStyle=s.color||colors[j%colors.length];ctx.fill();ctx.strokeStyle=cv('--card');ctx.lineWidth=1.5;ctx.stroke();});
      // 悬停提示框（系列过多时靠图例显示数值，避免遮挡）
      if(series.length<=6){const lines=series.map(s=>s.name+' '+format(s.value(selected),unit));ctx.font='11px sans-serif';ctx.textAlign='left';let bw=0;lines.forEach(s=>{bw=Math.max(bw,ctx.measureText(s).width);});bw+=16;const bh=lines.length*15+10;let bx=x(selected.t)+10;if(bx+bw>W-R)bx=x(selected.t)-10-bw;const by=T;ctx.globalAlpha=.95;ctx.fillStyle=cv('--card');ctx.shadowColor='rgba(0,0,0,.35)';ctx.shadowBlur=14;ctx.shadowOffsetY=4;roundRectPath(ctx,bx,by,bw,bh,7);ctx.fill();ctx.shadowColor='transparent';ctx.shadowBlur=0;ctx.shadowOffsetY=0;ctx.globalAlpha=1;ctx.strokeStyle=cv('--border2');ctx.lineWidth=1;roundRectPath(ctx,bx,by,bw,bh,7);ctx.stroke();lines.forEach((s,i)=>{ctx.fillStyle=cv('--sub');ctx.fillText(s,bx+8,by+18+i*15);});}
    }
    if(!pts.length){ctx.textAlign='center';ctx.fillText(text(24),W/2,T+ph/2,W-16);}
    else if(!series.some(s=>pts.some(p=>s.value(p)!=null))){ctx.textAlign='center';ctx.fillText('—',W/2,T+ph/2);}
    const legend=wrap.querySelector('.legend');legend.replaceChildren();series.forEach((s,j)=>{const span=document.createElement('span'),dot=document.createElement('i');dot.className='dot';dot.style.background=s.color||colors[j%colors.length];span.append(dot,document.createTextNode(s.name+(selected?' '+format(s.value(selected),unit):'')));legend.append(span);});
  }
  function draw(){
    document.getElementById('diag-at').textContent=hoverTime?timeLabel(hoverTime):'';
    setSeg('diag-range',chartRange);section.querySelectorAll('[data-diag-range]').forEach(b=>b.textContent=t('chart.r'+b.dataset.diagRange));
    document.getElementById('diag-limit').textContent=history?.points.some(p=>p.truncated)?text(26):'';
    const ids=identities().filter(c=>(!client.value||c.client===client.value)&&(!conn.value||c.id===conn.value)).slice(0,8);
    // point->(id->metrics) 每帧建一次缓存：oneway 面板 16 系列 × 24h 档 ~1440 点，
    // 逐点 conns.find 是数十万次比较；Map 直查把面板内查找降到 O(1)。
    const connCache=new Map();
    const connOf=p=>{let m=connCache.get(p);if(!m){m=new Map();(p.conns||[]).forEach(c=>m.set(c.id,c.metrics||{}));connCache.set(p,m);}return m;};
    const connectionSeries=(metric,label,dash=false,palette=colors)=>ids.map((c,i)=>({name:c.id.slice(0,8)+' '+text(label),color:palette[i%palette.length],dash,value:p=>connOf(p).get(c.id)?.[metric]??null}));
    const metric=(key,label)=>({name:text(label),value:p=>p.metrics?.[key]??null});
    panel(0,'throughput',[...connectionSeries('up',10),...connectionSeries('down',11,true)],'bytes');
    panel(1,'rtt',connectionSeries('rtt',5),'ms');
    panel(6,'oneway',[...connectionSeries('fwd',30,false,fwdColors),...connectionSeries('ret',31,true,retColors)],'ms');
    // 时钟偏移观测徽标 + θ/U 数值：θ 可信时显示"偏移观测（θ ± U）"，否则显示
    // "时钟偏移未收敛"。θ 是两端时钟偏移的纯观测值，不参与单向时延分解（相对
    // 时延不依赖两端时钟同步）；fwd/ret 为相对值，精度受 θ 的不确定度约束。
    const clk=document.getElementById('diag-clk');
    if(clk){
      let pt=null;const ptsAll=history?.points||[];
      // clk_sync 在聚合点（1h/24h）上是被平均的分数（如 0.83），严格 ===1 只匹配
      // 原始点；>0 表示该桶内有过收敛观测，徽标才不会在长范围视图下永远消失。
      for(let i=ptsAll.length-1;i>=0;i--){const p=ptsAll[i];if((p.conns||[]).some(c=>(c.metrics?.clk_sync??0)>0)){pt=p;break;}}
      const conn=pt?.conns?.find(c=>c.metrics?.clk_off!=null);
      if(conn){
        const off=conn.metrics.clk_off,unc=conn.metrics.clk_unc||0;
        clk.textContent=text(34)+' '+(off>=0?'+':'')+Number(off.toFixed(2))+' ms · U='+Number(unc.toFixed(2))+' ms';
        clk.style.color='var(--ok, #08a579)';
      }else{
        clk.textContent=text(32);
        clk.style.color='var(--sub)';
      }
    }
    panel(2,'assigned',connectionSeries('assigned',12),'bytes');panel(2,'queue',connectionSeries('queue',13),'queue');
    panel(3,'fec-pct',[metric('fec_pct',14)],'pct');panel(3,'fec-recovery',[metric('recovered',15),metric('lost',16)],'rate');panel(3,'fec-parity',[metric('fec_parity',17)],'bytes');
    panel(4,'pad-rate',[metric('pad',18)],'bytes');panel(4,'pad-pct',[metric('pad_pct',19)],'pct');
    panel(5,'online',[metric('online',20)],'count');panel(5,'errors',[metric('reconnect',21),metric('drop',22),metric('tap_error',23)],'rate');
  }
  window.applyDiagnostics=function(data){if(!data||!Array.isArray(data.points))return;if(typeof dashboardInstance==='string'&&dashboardInstance&&data.instance_id!==dashboardInstance)return;history=data;
  // 悬停点仍存在于新数据里就保留提示框，否则（范围切换/实例切换）才清除
  if(hoverTime!=null&&!(history?.points||[]).some(p=>p.t===hoverTime))hoverTime=null;
  updateOptions();draw();};
  document.getElementById('diag-range').addEventListener('click',ev=>{const button=ev.target.closest('[data-diag-range]');if(button)setRange(button.dataset.diagRange);});
  client.addEventListener('change',()=>{conn.value='';updateOptions();draw();});conn.addEventListener('change',draw);
  const oldRange=setRange;setRange=function(v){history=null;hoverTime=null;updateOptions();draw();return oldRange(v);};
  const oldStats=applyStats;applyStats=function(data){if(history&&data?.instance_id&&data.instance_id!==history.instance_id){history=null;hoverTime=null;updateOptions();draw();}return oldStats(data);};
  const oldI18n=applyI18n;applyI18n=function(){const out=oldI18n();labels();return out;};
  const oldTheme=applyTheme;applyTheme=function(){const out=oldTheme();draw();return out;};
  window.addEventListener('resize',()=>{if(resizeTimer)clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>{resizeTimer=null;draw();},150);});
  // 主题切换：cssv 缓存失效后重绘（本文件尾部的 applyTheme 包装器之上再包一层）
  const oldTheme2=applyTheme;applyTheme=function(){const out=oldTheme2();cssvCache.clear();draw();return out;};
  labels();
})();
