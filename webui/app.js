function setSeg(id,val){
  const seg=document.getElementById(id);if(!seg)return;
  seg.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.v===val));
}
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.dataset.i18n));
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>el.placeholder=t(el.dataset.i18nPh));
  document.querySelectorAll('[data-i18n-title]').forEach(el=>el.title=t(el.dataset.i18nTitle));
  setSeg('lang-seg',LANG);
  setSeg('refresh-seg',String(REFRESH_S));
  setSeg('range-seg',chartRange);
  applyTheme();
  // 下拉框文案取自 option 文本，换语言后要跟着重画
  syncSelects();
}
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+t('u.day')+h+t('u.hour');if(h>0)return h+t('u.hour')+m+t('u.min');
  if(m>0)return m+t('u.min')+(s%60)+t('u.sec');return s+t('u.sec');}
function fmtBytes(b,s=false){
  if(!isFinite(b)||b<=0)return '0 '+(s?'B/s':'B');
  const u=["B","KB","MB","GB","TB"],i=Math.min(4,Math.max(0,Math.floor(Math.log(b)/Math.log(1024))));
  return parseFloat((b/Math.pow(1024,i)).toFixed(2))+' '+u[i]+(s?'/s':'');
}
function badge(f){if(!f||f==='off')return '<span class="badge b-off">'+t('badge.off')+'</span>';
  if(f==='dup')return '<span class="badge b-dup">'+t('badge.dup')+'</span>';return '<span class="badge b-on">'+f+'</span>';}
function encBadge(a){if(a===null||a===undefined)return '<span class="badge b-off">-</span>';if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';
  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';
  if(a===5)return '<span class="badge b-on">ChaCha20-Poly1305</span>';
  if(a===6)return '<span class="badge b-on">XChaCha20-Poly1305</span>';
  return '<span class="badge b-off">'+t('badge.plain')+'</span>';}
function stBadge(s){if(s==='up')return '<span class="badge b-on">'+t('st.up')+'</span>';
  if(s==='connecting')return '<span class="badge b-dup">'+t('st.connecting')+'</span>';
  return '<span class="badge b-off">'+(s||'-')+'</span>';}
function shortId(id,n){return id.length>n?id.slice(0,n)+'…':id;}
function esc(x){return String(x==null?'':x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\x22/g,'&quot;').replace(/\x27/g,'&#39;');}
// hi 在已转义的文本上高亮首个命中（查询词为小写）；无命中原样返回
function hi(s,q){
  if(!q)return s;
  const i=s.toLowerCase().indexOf(q);
  return i<0?s:s.slice(0,i)+'<mark>'+s.slice(i,i+q.length)+'</mark>'+s.slice(i+q.length);
}
function showPane(id){
  document.querySelectorAll('#tabs button').forEach(b=>b.classList.toggle('on',b.dataset.pane===id));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  document.getElementById('pane-'+id).classList.add('on');
  // 事件在后台一直攒着，面板不在前台时不渲染；切过来补一次全量绘制
  if(id==='events')evRender(false);
  if(id==='events')evRender(false);
  if(id==='sec'||id==='topo'){if(lastStats){renderSec(lastStats);renderTopo(lastStats);}}
  if(id==='settings')loadConfig();
  // 刚显示的面板之前在 display:none 里量不到宽度，按钮的 min-width 还是 0
  syncSelects();
}
document.getElementById('tabs').addEventListener('click',function(ev){
  const btn=ev.target.closest('button');if(!btn)return;
  showPane(btn.dataset.pane);
});

// ---------- 通用折线图渲染：纵轴刻度 + 末端标签防裁剪 + 悬停提示 ----------
const chartState={};
function roundRectPath(ctx,x,y,w,h,r){
  ctx.beginPath();
  ctx.moveTo(x+r,y);ctx.arcTo(x+w,y,x+w,y+h,r);ctx.arcTo(x+w,y+h,x,y+h,r);
  ctx.arcTo(x,y+h,x,y,r);ctx.arcTo(x,y,x+w,y,r);ctx.closePath();
}
function fmtHM(ms){
  const d=new Date(ms);
  return ('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2)+':'+('0'+d.getSeconds()).slice(-2);
}
// pts: [{x∈0..1, up, down, rtt?, label}]；opts: {max, maxRtt, perSec, hover}
// 上下行共用字节纵轴（左侧刻度），RTT 独立刻度（右侧琥珀色，仅趋势图有值时）。
function renderLineChart(canvasId,pts,opts){
  const c=document.getElementById(canvasId);if(!c)return;
  const ctx=c.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const W=c.clientWidth||1100,H=c.clientHeight||216;
  if(c.width!==Math.round(W*dpr)||c.height!==Math.round(H*dpr)){c.width=Math.round(W*dpr);c.height=Math.round(H*dpr);}
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);
  const max=Math.max(1,opts.max||1);
  ctx.font='10px sans-serif';
  const ticks=Array.from({length:5},(_,g)=>fmtBytes(max*(4-g)/4,opts.perSec));
  // Reserve the measured label width, the axis gap, and an outer gutter.
  const L=Math.max(56,Math.ceil(Math.max(...ticks.map(s=>ctx.measureText(s).width)))+14);
  const R=16,T=16,B=24,pw=W-L-R,ph=H-T-B;
  // 网格 + 纵坐标刻度
  ctx.strokeStyle=cssv('--grid');ctx.lineWidth=1;
  ctx.fillStyle=cssv('--sub');ctx.font='10px sans-serif';ctx.textAlign='right';
  for(let g=0;g<=4;g++){
    const y=T+ph*g/4;
    ctx.beginPath();ctx.moveTo(L,y+.5);ctx.lineTo(W-R,y+.5);ctx.stroke();
    ctx.fillText(ticks[g],L-6,y+3);
  }
  ctx.textAlign='left';
  if(!pts||pts.length<2){
    chartState[canvasId]={pts:[],plot:{l:L,r:W-R,t:T,b:H-B},hover:-1};
    return;
  }
  // 上下行：面积填充 + 折线
  const plot=(get,col)=>{
    ctx.beginPath();
    pts.forEach((p,i)=>{
      const x=L+p.x*pw,y=T+(1-get(p)/max)*ph;
      if(i)ctx.lineTo(x,y);else ctx.moveTo(x,y);
    });
    ctx.strokeStyle=col;ctx.lineWidth=2;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
    const grad=ctx.createLinearGradient(0,T,0,H-B);
    grad.addColorStop(0,col+'3d');grad.addColorStop(1,col+'00');
    ctx.lineTo(L+pts[pts.length-1].x*pw,H-B);ctx.lineTo(L,H-B);ctx.closePath();
    ctx.fillStyle=grad;ctx.fill();
  };
  plot(p=>p.down,cssv('--down'));
  plot(p=>p.up,cssv('--up'));
  // RTT 独立刻度虚线 + 右侧刻度
  const maxRtt=opts.maxRtt||0;
  if(maxRtt>0){
    ctx.beginPath();
    pts.forEach((p,i)=>{
      const x=L+p.x*pw,y=T+(1-p.rtt/maxRtt)*ph;
      if(i)ctx.lineTo(x,y);else ctx.moveTo(x,y);
    });
    ctx.strokeStyle=cssv('--warn');ctx.lineWidth=1.5;ctx.setLineDash([4,4]);ctx.stroke();ctx.setLineDash([]);
    ctx.fillStyle=cssv('--warn');ctx.font='10px sans-serif';ctx.textAlign='right';
    ctx.fillText('RTT ≤ '+Math.ceil(maxRtt)+' ms',W-R,T+2);
    ctx.fillText(Math.ceil(maxRtt/2)+' ms',W-R,T+ph/2+2);
    ctx.textAlign='left';
  }
  // x 轴刻度：稀疏标注，末端标签钳制在画布内防裁剪
  ctx.fillStyle=cssv('--sub');ctx.font='10px sans-serif';ctx.textAlign='center';
  const step=Math.ceil(pts.length/8);
  pts.forEach((p,i)=>{
    if(i%step!==0&&i!==pts.length-1)return;
    const tw=ctx.measureText(p.label).width;
    const tx=Math.max(L+tw/2,Math.min(L+p.x*pw,W-R-tw/2));
    ctx.fillText(p.label,tx,H-8);
  });
  ctx.textAlign='left';
  // 悬停：十字线 + 数据点圆标 + 提示框
  const hover=opts.hover;
  if(hover>=0&&hover<pts.length){
    const p=pts[hover],px=L+p.x*pw;
    ctx.strokeStyle=cssv('--border2');ctx.setLineDash([3,3]);
    ctx.beginPath();ctx.moveTo(px+.5,T);ctx.lineTo(px+.5,H-B);ctx.stroke();ctx.setLineDash([]);
    const dot=(y,col)=>{
      ctx.beginPath();ctx.arc(px,y,3.5,0,Math.PI*2);
      ctx.fillStyle=col;ctx.fill();
      ctx.strokeStyle=cssv('--card');ctx.lineWidth=1.5;ctx.stroke();
    };
    dot(T+(1-p.up/max)*ph,cssv('--up'));
    dot(T+(1-p.down/max)*ph,cssv('--down'));
    if(maxRtt>0&&p.rtt)dot(T+(1-p.rtt/maxRtt)*ph,cssv('--warn'));
    const lines=[p.label,'↑ '+fmtBytes(p.up,opts.perSec),'↓ '+fmtBytes(p.down,opts.perSec)];
    if(maxRtt>0&&p.rtt)lines.push('RTT '+p.rtt.toFixed(0)+' ms');
    ctx.font='11px sans-serif';
    let bw=0;
    lines.forEach(s=>{bw=Math.max(bw,ctx.measureText(s).width);});
    bw+=16;const bh=lines.length*15+10;
    let bx=px+10;if(bx+bw>W-R)bx=px-10-bw;
    const by=T;
    ctx.globalAlpha=.95;ctx.fillStyle=cssv('--card');
    roundRectPath(ctx,bx,by,bw,bh,7);ctx.fill();
    ctx.globalAlpha=1;ctx.strokeStyle=cssv('--border2');ctx.lineWidth=1;
    roundRectPath(ctx,bx,by,bw,bh,7);ctx.stroke();
    lines.forEach((s,i)=>{
      ctx.fillStyle=i===0?cssv('--sub'):(i===1?cssv('--up'):(i===2?cssv('--down'):cssv('--warn')));
      ctx.fillText(s,bx+8,by+18+i*15);
    });
  }
  chartState[canvasId]={pts:pts,plot:{l:L,r:W-R,t:T,b:H-B},hover:opts.hover};
}
// 把横坐标换算成最近数据点的下标（几何信息存于 chartState）
function chartIdxAt(canvasId,cx){
  const st=chartState[canvasId];
  if(!st||st.pts.length<2)return -1;
  const rect=document.getElementById(canvasId).getBoundingClientRect();
  const idx=Math.round((cx-rect.left-st.plot.l)/(st.plot.r-st.plot.l)*(st.pts.length-1));
  return Math.max(0,Math.min(st.pts.length-1,idx));
}
// 悬停/点按提示：用 Pointer 事件同时覆盖鼠标悬停、触屏点按与横滑选点，
// 触屏上没有 hover，点按后提示保持停留直到移到画布外。
function bindChartHover(canvasId,redraw){
  const c=document.getElementById(canvasId);if(!c)return;
  const pick=function(ev){
    const st=chartState[canvasId];
    const idx=chartIdxAt(canvasId,ev.clientX);
    if(idx>=0&&st&&st.hover!==idx){st.hover=idx;redraw();}
  };
  c.addEventListener('pointermove',pick);
  c.addEventListener('pointerdown',pick);
  c.addEventListener('pointerleave',function(){
    const st=chartState[canvasId];
    if(st&&st.hover!==-1){st.hover=-1;redraw();}
  });
}

function drawChart(){
  const n=txHist.length;
  const pts=[];
  for(let i=0;i<n;i++){
    pts.push({x:n>1?i/(n-1):0,up:txHist[i],down:rxHist[i],label:fmtHM(txTimes[i]||Date.now())});
  }
  const old=chartState['chart'];
  const hover=(old&&old.hover>=0&&old.hover<n)?old.hover:-1;
  renderLineChart('chart',pts,{max:Math.max(1,...txHist,...rxHist,1),perSec:true,hover:hover});
  // 本地轮询视图没有 RTT 数据，图例一并收起
  const lg=document.getElementById('legend-rtt');
  if(lg)lg.style.display='none';
}

// 刷新间隔以秒存储（兼容旧版存毫秒的值）；面板顶栏为分段按钮
let REFRESH_S=parseInt(localStorage.getItem('tlsvpn_refresh')||'2',10);
if(REFRESH_S!==2&&REFRESH_S!==5&&REFRESH_S!==10){
  const ms=REFRESH_S;
  REFRESH_S=(ms===2000||ms===5000||ms===10000)?ms/1000:2;
}
let REFRESH=REFRESH_S*1000;
function setRefresh(sec){REFRESH_S=sec;REFRESH=sec*1000;localStorage.setItem('tlsvpn_refresh',String(sec));
  setSeg('refresh-seg',String(sec));
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',sec);
  if(window.tlsvpnStreamRestart)window.tlsvpnStreamRestart();}

// 用带凭据的地址（http://admin:xx@host/ 打开面板）时，Chrome 拒绝构造任何 fetch——
// "Request cannot be constructed from a URL that includes credentials"——于是每一轮轮询都抛
// 同一条 TypeError，面板永远停在初始骨架上，日志里只剩一行重复报错，完全看不出是地址栏
// 里的凭据引起的。换成 Authorization 头 + 去掉 userinfo 的 URL 即可；同域请求带这个头
// 不触发预检，所以不影响未启用认证的情况。
const AUTH_HDR=(location.username||location.password)
  ?{Authorization:'Basic '+btoa(unescape(encodeURIComponent(location.username+':'+location.password)))}
  :{};
// location.origin 按规范不含 userinfo，是构造不带凭据 URL 的可靠基址
function url(path){return location.origin+path;}

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},AUTH_HDR,opts.headers||{});return fetch(url(path),opts);}
// 控制类请求统一入口：成功与失败都给出 Toast，不再静默。成功返回解析后的响应体，
// 失败返回 null（调用方一般不依赖返回值，动作后统一 fetchStats 刷新可见状态）。
async function control(body,okMsg){
  try{
    const res=await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!res.ok){
      const err=await res.text().catch(function(){return String(res.status);});
      toast(t('toast.fail')+' '+err.slice(0,120),'err');
      return null;
    }
    toast(okMsg,'ok');
    return await res.json().catch(function(){return {};});
  }catch(e){
    toast(String(e),'err');
    return null;
  }
}
// 401：面板启用了 -web-auth 时用统一风格的认证提示页，而不是换进一张裸卡片
function showUnauthorized(){
  document.body.className='unauth';
  document.body.innerHTML=
    '<div class="auth-401">'+
      '<div class="auth-401-logo"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>'+
      '<h2>401</h2>'+
      '<div class="auth-401-title">'+esc(t('unauth.title'))+'</div>'+
      '<p class="auth-401-hint">'+esc(t('unauth.hint'))+'</p>'+
      '<code class="mono auth-401-cmd">-web-auth user:pass</code>'+
    '</div>';
}

// ---------- 交互反馈：Toast 通知 / 美化确认框 / 按钮忙碌态 ----------
const TOAST_MAX=4;
function toast(msg,kind){
  const box=document.getElementById('toasts');if(!box)return;
  while(box.childElementCount>=TOAST_MAX)box.firstChild.remove();
  const el=document.createElement('div');
  el.className='toast '+(kind||'ok');
  el.innerHTML='<span class="toast-ico">'+(kind==='err'?'✕':'✓')+'</span>'+
    '<span class="toast-msg">'+esc(msg)+'</span>';
  box.appendChild(el);
  setTimeout(function(){el.classList.add('out');setTimeout(function(){el.remove();},350);},2600);
}
// uiConfirm 替代原生 confirm()：统一风格的美化模态框，Promise 语义；Esc 与点遮罩都等于取消
function uiConfirm(msg){
  return new Promise(function(resolve){
    const wrap=document.createElement('div');
    wrap.className='modal-mask';
    wrap.innerHTML='<div class="modal"><div class="modal-msg">'+esc(msg)+'</div>'+
      '<div class="modal-btns"><button class="btn ghost" data-r="0">'+t('ui.cancel')+'</button>'+
      '<button class="btn danger" data-r="1">'+t('ui.confirm')+'</button></div></div>';
    document.body.appendChild(wrap);
    function settle(ok){
      document.removeEventListener('keydown',onKey,true);
      wrap.remove();
      resolve(ok);
    }
    function onKey(ev){
      if(ev.key==='Escape'){ev.stopPropagation();settle(false);}
    }
    wrap.addEventListener('click',function(ev){
      const b=ev.target.closest('button');
      if(b){settle(b.getAttribute('data-r')==='1');return;}
      if(ev.target===wrap)settle(false);
    });
    document.addEventListener('keydown',onKey,true);
  });
}
// 动作按钮点击后短暂禁用，防止连点重复触发（控制类请求都伴随一次 fetchStats）
document.addEventListener('click',function(ev){
  const b=ev.target.closest('button.btn');
  if(!b||b.classList.contains('busy'))return;
  b.classList.add('busy');
  setTimeout(function(){b.classList.remove('busy');},900);
},true);
// 可点击 KPI 卡：流量卡直达流量页，丢帧卡直达日志页并预置错误过滤
document.addEventListener('click',function(ev){
  const card=ev.target.closest('.kpi-card[data-goto]');
  if(!card)return;
  const pane=card.getAttribute('data-goto');
  if(!document.getElementById('pane-'+pane))return;
  showPane(pane);
  const f=card.getAttribute('data-log-filter');
  const inp=document.getElementById('log-filter');
  if(f&&inp){
    logFilter=f.toLowerCase();
    inp.value=f;
    const clr=document.getElementById('log-filter-clear');
    if(clr)clr.classList.add('show');
  }
  applyLogFilter();
});
// 窄屏收纳：顶栏三段控件折进右上角可展开菜单，点菜单外或 Esc 收起
(function(){
  const btn=document.getElementById('menu-btn'),ctl=document.getElementById('topctl');
  if(!btn||!ctl)return;
  btn.addEventListener('click',function(ev){ev.stopPropagation();ctl.classList.toggle('open');});
  document.addEventListener('click',function(ev){if(!ctl.contains(ev.target))ctl.classList.remove('open');});
  document.addEventListener('keydown',function(ev){if(ev.key==='Escape')ctl.classList.remove('open');});
})();

function passFilter(obj,f){return !f||JSON.stringify(obj).toLowerCase().includes(f);}

// nodata 用于"字段整个没下发"：服务端没这项能力或老版本不下发，不等于"确实没有"。
// 前者是能力缺失，后者是运行结果，空状态文案必须分得开，否则会把 2 个真实 MAC
// 的客户端表跟"尚未学习到 MAC"的 MAC 表并排放着。
const NO_TXT={clients:'no_clients',conns:'no_conns',macs:'no_macs',bans:'no_bans',srv:'srv_only',traffic:'tr.empty',logs:'no_logs',nodata:'ov.no_data'};
// 空状态配一个淡色图标：一整块纯空白读起来像渲染失败
const EMPTY_ICON={
  clients:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/>',
  conns:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  macs:'<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>',
  bans:'<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/>',
  srv:'<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
  traffic:'<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
  logs:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/>'
};
function emptyIcon(kind){return '<svg class="empty-ico" viewBox="0 0 24 24">'+(EMPTY_ICON[kind]||EMPTY_ICON.srv)+'</svg>';}
// msg 为可信 i18n 文案（允许内嵌 <br>），extra 放"清除过滤"按钮
function emptyRow(key,cols,msg,extra){
  return '<tr><td class="empty" colspan="'+cols+'">'+emptyIcon(key)+'<div class="empty-txt">'+msg+'</div>'+
    (extra||'')+'</td></tr>';
}
// 表格空状态：完全没有数据 vs 有数据但被过滤掉，两种提示要能区分
function emptyTableRow(key,cols,total){
  if(!total)return emptyRow(key,cols,t(NO_TXT[key]));
  return emptyRow(key,cols,t('filter_none')+'<br>','<button class="btn ghost sm" onclick="clearFilter(\''+key+'\')">'+t('filter_clear')+'</button>');
}
// 失败原因用 omitempty：报错列表为空时字段整个不下发。"没有报错"不等于"全部
// 生效"——没有连接被塑形时也给绿灯，就会读成开关=否、已生效 0/0 却"全部生效"。
function brutErrCell(b){
  if(b.errors&&b.errors.length)return '<span style="color:var(--err)">'+esc(b.errors.join('; '))+'</span>';
  if(b.total_conns>0)return '<span class="badge b-on">'+t('stt.noerr')+'</span>';
  return ntxt();
}
// ---------- 表格分页：默认 25 行/页，可切 50/100/全部；每页只重画工具条内容有变化时，
// 否则 2 秒一次的轮询会重建 DOM、打断已展开的页大小下拉框 ----------
const PAGE_SIZES=[25,50,100,0];
let pageState={};
function pageConf(key){
  if(!pageState[key])pageState[key]={page:1,size:PAGE_SIZES[0]};
  return pageState[key];
}
// size=0 表示不分页；行数变少时页码越界，收敛到最后一页而不是停在空白页
function settlePage(key,total){
  const c=pageConf(key);
  let pages=1;
  if(c.size>0)pages=Math.max(1,Math.ceil(total/c.size));
  if(c.page<1||c.page>pages)c.page=pages;
  c.pages=pages;
  return c;
}
function pageView(key,arr){
  const c=settlePage(key,arr.length);
  let rows=arr;
  if(c.size>0)rows=arr.slice((c.page-1)*c.size,(c.page-1)*c.size+c.size);
  const out={rows:rows,c:c};
  return out;
}
function renderPager(key,total){
  const el=document.getElementById('pager-'+key);
  if(!el)return;
  const c=settlePage(key,total);
  // 单页（或选"全部"后只剩一页）不占位置；空表同样不占位置
  if(c.size>0&&total<=c.size){if(el.innerHTML)el.innerHTML='';return;}
  let from=0,to=total;
  if(c.size>0){from=(c.page-1)*c.size;to=Math.min(total,from+c.size);}
  let opts='';
  PAGE_SIZES.forEach(function(n){
    let sel='';
    if(n===c.size)sel=' selected';
    // n=0 是"不分页"，显示全部而不是"0 条 / 页"
    let label=t('page.size');
    if(n>0)label=tpl(label,{n:n});
    else label=t('page.all');
    opts+='<option value="'+n+'"'+sel+'>'+label+'</option>';
  });
  // 上一页 / 下一页：chevron 图标 + i18n 悬停文案，到边界时禁用
  let prevBtn='<button class="btn ghost sm pg-btn"';
  let nextBtn='<button class="btn ghost sm pg-btn"';
  if(c.page<=1)prevBtn+=' disabled';
  if(c.page>=c.pages)nextBtn+=' disabled';
  prevBtn+=' title="'+esc(t('page.prev'))+'" onclick="goPage(\''+key+'\','+(c.page-1)+')">‹</button>';
  nextBtn+=' title="'+esc(t('page.next'))+'" onclick="goPage(\''+key+'\','+(c.page+1)+')">›</button>';
  const html='<span class="dim">'+tpl(t('page.showing'),{a:from+1,b:to,n:total})+'</span>'+
    '<span class="pager-right">'+
      '<select class="sel pg-sel" onchange="setPageSize(\''+key+'\',this.value)">'+opts+'</select>'+
      prevBtn+
      '<span class="pg-of">'+tpl(t('page.of'),{x:c.page,y:c.pages})+'</span>'+
      nextBtn+
    '</span>';
  // 工具条内容变了就整块重画；重画出来的原生 select 要重新包成自绘下拉框
  if(el.innerHTML!==html){el.innerHTML=html;syncSelects();}
}
function goPage(key,p){
  pageConf(key).page=p;
  if(key==='traffic')renderTrafficView();else rerenderTables();
}
function setPageSize(key,n){
  const c=pageConf(key);
  // 0 是"不分页"的哨兵值，不能用 || 兜底，否则"全部"会被悄悄改成默认 25
  const v=parseInt(n,10);
  if(!isNaN(v))c.size=v;
  else c.size=PAGE_SIZES[0];
  c.page=1;
  if(key==='traffic')renderTrafficView();else rerenderTables();
}
// 多占位符替换：词条里可能同时出现 {a}{b}{n}
function tpl(s,o){
  let out=String(s);
  for(const k in o)out=out.split('{'+k+'}').join(o[k]);
  return out;
}
// ---------- 自定义下拉框 ----------
// 原生 <select> 的弹层是操作系统画的，CSS 染不上去（暗色面板配一个白底黑字菜单）。
// 做法：select 留在 DOM 里继续当唯一取值来源（.dl-native 只把它缩成 1px 藏起来），
// 外面套自绘的触发按钮和菜单；选中项只写 select.value 再派发一次原生 change 事件，
// 所以各处 onchange（setLogLevel / renderTrafficView / setPageSize）和程序化写值
// （服务端每轮轮询回写 log_level）一行都不用改。
const DL=new WeakMap();
let dlCur=null;
const DL_ARROW='<svg width="10" height="6" viewBox="0 0 10 6" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';

// 包起来：外壳 + 触发按钮（当前值 + chevron）+ 菜单；原生 select 缩成 1px 藏在里面
function buildSelect(sel){
  if(DL.has(sel))return;
  const host=sel.parentNode;
  const wrap=document.createElement('div');
  wrap.className='dl';
  // select 上的内联宽度约束（如 max-width:260px）搬给外壳，否则外壳会塌成按钮内容宽
  const stStyle=sel.getAttribute('style');
  if(stStyle)wrap.setAttribute('style',stStyle);
  host.insertBefore(wrap,sel);
  wrap.appendChild(sel);
  sel.classList.add('dl-native');
  sel.tabIndex=-1;
  sel.setAttribute('aria-hidden','true');
  const btn=document.createElement('div');
  // 复用 select 上的附加类（pg-sel 等）拿到它们的尺寸规则，剥掉 .sel 与 .dl-native 本身
  let bcls='dl-btn';
  sel.classList.forEach(function(c){if(c!=='sel'&&c!=='dl-native')bcls+=' '+c;});
  btn.className=bcls;
  btn.setAttribute('role','combobox');
  btn.setAttribute('aria-haspopup','listbox');
  btn.setAttribute('aria-expanded','false');
  btn.tabIndex=0;
  const lab=document.createElement('span');
  lab.className='dl-lab';
  // sz 是占位撑子：装最宽的那条选项文本，让按钮宽度跟最宽项走、切选项时不左右抖；
  // cur 才是真正显示当前值的文本，绝对定位叠在 sz 上面
  const sz=document.createElement('span');
  sz.className='dl-sz';
  const cur=document.createElement('span');
  cur.className='dl-cur';
  lab.appendChild(sz);
  lab.appendChild(cur);
  btn.appendChild(lab);
  const ar=document.createElement('span');
  ar.className='dl-arrow';
  ar.innerHTML=DL_ARROW;
  btn.appendChild(ar);
  wrap.appendChild(btn);
  const menu=document.createElement('div');
  menu.className='dl-menu';
  menu.setAttribute('role','listbox');
  menu.setAttribute('aria-hidden','true');
  wrap.appendChild(menu);
  const st={wrap:wrap,host:host&&host.tagName==='LABEL'?host:null,btn:btn,cur:cur,sz:sz,menu:menu,items:[],active:0};
  DL.set(sel,st);
  btn.addEventListener('click',function(ev){ev.stopPropagation();dlToggle(sel);});
  btn.addEventListener('keydown',function(ev){dlKey(sel,ev);});
  menu.addEventListener('click',function(ev){
    const d=ev.target.closest('.dl-opt');
    if(d)dlPick(sel,parseInt(d.getAttribute('data-i'),10));
  });
  // 原生 change 时重建菜单与文案（含我们派发的那一次）
  sel.addEventListener('change',function(){syncSelect(sel);});
  // 外层若是 <label>，点标签文字也要能开合弹层
  if(st.host)st.host.addEventListener('click',function(ev){
    if(wrap.contains(ev.target))return;
    ev.preventDefault();
    dlToggle(sel);
    btn.focus();
  });
  syncSelect(sel);
}

// 以原生 select 为准重建菜单与触发器文案：选项列表和当前值都可能被外部改写过
function syncSelect(sel){
  const st=DL.get(sel);
  if(!st)return;
  const ops=sel.options;
  const n=ops.length;
  let cur=sel.selectedIndex;
  if(cur<0)cur=0;
  if(cur>n-1)cur=n-1;
  st.items=[];
  let html='';
  for(let i=0;i<n;i++){
    const op=ops[i];
    let c='dl-opt';
    if(i===cur)c+=' on';
    if(op.disabled)c+=' disabled';
    const asel=i===cur?'true':'false';
    html+='<div class="'+c+'" role="option" aria-selected="'+asel+'" data-i="'+i+'"><span class="dl-tx">'+esc(op.textContent||op.value||'')+'</span></div>';
    st.items.push({v:op.value,off:op.disabled});
  }
  st.menu.innerHTML=html;
  let txt='';
  if(n>0)txt=ops[cur].textContent||ops[cur].value;
  st.cur.textContent=txt||'-';
  // 撑子装最宽那一条的文本，按钮宽度因此固定，切选项时右侧控件不会跟着挪
  let wide='';
  for(let j=0;j<n;j++){
    const w=ops[j].textContent||ops[j].value||'';
    if(dlW(w)>dlW(wide))wide=w;
  }
  st.sz.textContent=wide;
  st.active=cur;
  if(dlCur===sel)dlPlace(sel);
}

// 扫一遍所有原生 select：没包的包起来，已经包的按当前选项与值重建
function syncSelects(){
  document.querySelectorAll('select.sel').forEach(function(sel){
    if(DL.has(sel))syncSelect(sel);
    else buildSelect(sel);
  });
}

// 弹层用 fixed 定位：表格容器的 overflow-x 会把 absolute 菜单裁掉；越界就翻转/右移
function dlPlace(sel){
  const st=DL.get(sel);
  if(!st)return;
  const b=st.btn.getBoundingClientRect();
  st.menu.style.minWidth=Math.round(b.width)+'px';
  const mw=st.menu.getBoundingClientRect().width;
  const mh=st.menu.getBoundingClientRect().height;
  let left=b.left;
  if(left+mw>window.innerWidth-8)left=Math.max(8,window.innerWidth-8-mw);
  let top=b.bottom+6;
  if(top+mh>window.innerHeight-8&&b.top-6-mh>8)top=Math.max(8,b.top-6-mh);
  st.menu.style.left=Math.round(left)+'px';
  st.menu.style.top=Math.round(top)+'px';
}

function dlToggle(sel){
  if(dlCur===sel)dlClose(sel);
  else dlOpen(sel);
}

function dlOpen(sel){
  if(dlCur&&dlCur!==sel)dlClose(dlCur);
  const st=DL.get(sel);
  if(!st)return;
  const it=st.active>=0?st.items[st.active]:null;
  if(!it||it.off)st.active=dlNext(st,st.active,1);
  dlPlace(sel);
  st.btn.classList.add('on');
  st.menu.classList.add('on');
  st.btn.setAttribute('aria-expanded','true');
  st.menu.setAttribute('aria-hidden','false');
  dlHot(sel,st.active);
  dlCur=sel;
}

function dlClose(sel){
  const st=DL.get(sel);
  if(st){
    st.btn.classList.remove('on');
    st.menu.classList.remove('on');
    st.btn.setAttribute('aria-expanded','false');
    st.menu.setAttribute('aria-hidden','true');
  }
  if(dlCur===sel)dlCur=null;
}

// 选中：写回原生 select.value，再派一次 change 让原有 onchange 生效
function dlPick(sel,i){
  const st=DL.get(sel);
  if(!st)return;
  dlClose(sel);
  const it=st.items[i];
  if(!it||it.off)return;
  sel.value=it.v;
  sel.dispatchEvent(new Event('change',{bubbles:true}));
  st.btn.focus();
}

// 从 i 出发按 dir 找下一个可用项（跳过 disabled），越过末端回绕
function dlNext(st,i,dir){
  const n=st.items.length;
  if(n===0)return -1;
  if(i<0)i=dir>0?n-1:0;
  for(let k=1;k<=n;k++){
    let j=(i+dir*k)%n;
    if(j<0)j+=n;
    if(!st.items[j].off)return j;
  }
  return -1;
}

// 粗估文本宽度：中日韩全角字符按两格计。只做同组比较，不出回流
function dlW(s){
  let n=0;
  for(let k=0;k<s.length;k++)n+=s.charCodeAt(k)>0xff?2:1;
  return n;
}

// 键盘高亮移动；滚出菜单可视区时把它滚进来看见
function dlHot(sel,i){
  const st=DL.get(sel);
  if(!st)return;
  const ops=st.menu.querySelectorAll('.dl-opt');
  ops.forEach(function(o,k){o.classList.toggle('hot',k===i);});
  if(i<0)return;
  const o=ops[i];
  if(!o)return;
  const r=o.getBoundingClientRect();
  const m=st.menu.getBoundingClientRect();
  if(r.top<m.top||r.bottom>m.bottom)o.scrollIntoView({block:'nearest'});
}

// 触发器上的键盘：上下/Home/End 移动，Enter/Space 展开或选中，Esc 收起，Tab 收起
function dlKey(sel,ev){
  const st=DL.get(sel);
  if(!st)return;
  const open=dlCur===sel;
  if(ev.key==='ArrowDown'||ev.key==='ArrowUp'){
    ev.preventDefault();
    if(!open){dlOpen(sel);return;}
    // 要记下这次移动，否则 Enter 还是选中原来那一项
    st.active=dlNext(st,st.active,ev.key==='ArrowUp'?-1:1);
    dlHot(sel,st.active);
    return;
  }
  if(ev.key==='Home'){
    if(open){st.active=dlNext(st,-1,1);dlHot(sel,st.active);}
    ev.preventDefault();
    return;
  }
  if(ev.key==='End'){
    if(open){st.active=dlNext(st,0,-1);dlHot(sel,st.active);}
    ev.preventDefault();
    return;
  }
  if(ev.key==='Enter'||ev.key===' '){
    ev.preventDefault();
    if(open)dlPick(sel,st.active);
    else dlOpen(sel);
    return;
  }
  if(ev.key==='Escape'&&open)ev.preventDefault();
  if(ev.key==='Tab'&&open)dlClose(sel);
}

// 点在控件外就收起；外层 <label> 的文字算控件的一部分
function dlOutside(ev){
  if(!dlCur)return;
  const sel=dlCur;
  const st=DL.get(sel);
  if(st){
    if(st.wrap.contains(ev.target))return;
    if(st.host&&st.host.contains(ev.target))return;
  }
  dlClose(sel);
}

// 页面滚动时重新计算 fixed 弹层位置；菜单自身滚动保持展开。
// 浏览器/辅助技术可能在展开后为目标选项自动滚动页面，若此处直接关闭会形成
// "已打开 -> 自动滚动 -> 点击前关闭" 的竞态，真实键盘/窄屏交互同样可能触发。
function dlScroll(ev){
  if(!dlCur)return;
  const sel=dlCur,st=DL.get(sel);
  if(!st)return;
  if(ev&&(ev.target===st.menu||st.menu.contains(ev.target)))return;
  requestAnimationFrame(function(){if(dlCur===sel)dlPlace(sel);});
}

// Esc 收起（触发器没聚焦时也要有效）；Tab 让焦点正常走
document.addEventListener('keydown',function(ev){
  if(ev.key==='Escape'&&dlCur){
    const sel=dlCur;
    const st=DL.get(sel);
    dlClose(sel);
    if(st)st.btn.focus();
  }
});
document.addEventListener('mousedown',dlOutside);
window.addEventListener('scroll',dlScroll,true);
window.addEventListener('resize',function(){if(dlCur)dlClose(dlCur);});

// ---------- 表头排序：点击 <th data-sort> 循环 降序 → 升序 → 取消 ----------
// 数值列按数值比较、其余按字符串；速率列用最近一次快照算出的差分
const SORTCOLS={
  clients:{
    id:function(r){return r.id;},v4:function(r){return r.c.ipv4||'';},tcp:function(r){return r.c.active_conns;},
    tx:function(r){return r.c.tx_bytes;},rx:function(r){return r.c.rx_bytes;},txs:function(r){return r.sx;},rxs:function(r){return r.sr;}
  },
  conns:{
    owner:function(r){return r.owner;},target:function(r){return r.target||'';},remote:function(r){return r.remote||'';},
    rtt:function(r){return r.rtt;},tx:function(r){return r.tx;},rx:function(r){return r.rx;},
    txs:function(r){return r.sx;},rxs:function(r){return r.sr;},age:function(r){return r.age;}
  },
  traffic:{
    date:function(r){return r.date;},up:function(r){return r.up;},down:function(r){return r.down;},
    total:function(r){return r.up+r.down;}
  }
};
let sortState={};
function sortRows(key,rows){
  const s=sortState[key];
  if(!s)return rows;
  const col=SORTCOLS[key][s.f];
  if(!col)return rows;
  const d=s.d;
  return rows.slice().sort(function(a,b){
    const x=col(a),y=col(b);
    if(typeof x==='number'&&typeof y==='number')return (x-y)*d;
    return String(x).localeCompare(String(y))*d;
  });
}
// 箭头由 data-arrow 属性承载，当前排序列表头高亮
function syncSortUI(key){
  const pane=document.getElementById('pane-'+key);
  if(!pane)return;
  const s=sortState[key];
  pane.querySelectorAll('th[data-sort]').forEach(function(th){
    if(s&&th.getAttribute('data-sort')===s.f){
      th.classList.add('sorted');
      th.setAttribute('data-arrow',s.d<0?'↓':'↑');
    }else{
      th.classList.remove('sorted');
      th.removeAttribute('data-arrow');
    }
  });
}
document.addEventListener('click',function(ev){
  const th=ev.target.closest('th[data-sort]');
  if(!th)return;
  const pane=th.closest('.pane');
  if(!pane)return;
  const key=pane.id.replace('pane-','');
  const f=th.getAttribute('data-sort');
  const cur=sortState[key];
  if(cur&&cur.f===f){
    if(cur.d<0)sortState[key]={f:f,d:1};
    else delete sortState[key];
  }else{
    sortState[key]={f:f,d:-1};
  }
  syncSortUI(key);
  if(key==='traffic')renderTrafficView();else rerenderTables();
});
function setCount(id,f,shown,total){
  const el=document.getElementById(id);if(!el)return;
  el.textContent=f?(shown+' / '+total):'';
}
// 过滤框：纯本地过滤——基于最近一次 /api/stats 的缓存重渲染表格，不打 API；
// 140ms 防抖，×/Esc 一键清空，命中片段 <mark> 高亮，计数徽章显示 命中/总数。
const Q={clients:'',conns:'',macs:''};
function attachSearch(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  const input=box.querySelector('.search-input');
  const clear=box.querySelector('.search-clear');
  let timer=null;
  input.addEventListener('input',function(){
    clear.classList.toggle('show',!!input.value);
    clearTimeout(timer);
    timer=setTimeout(function(){Q[key]=input.value.trim().toLowerCase();pageConf(key).page=1;rerenderTables();},140);
  });
  clear.addEventListener('click',function(){input.value='';Q[key]='';clear.classList.remove('show');rerenderTables();input.focus();});
  input.addEventListener('keydown',function(e){if(e.key==='Escape')clear.click();});
}
function clearFilter(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  box.querySelector('.search-input').value='';
  box.querySelector('.search-clear').classList.remove('show');
  Q[key]='';
  pageConf(key).page=1;
  rerenderTables();
}
// "/" 聚焦当前页签的过滤框（输入控件已聚焦时不拦截）
document.addEventListener('keydown',function(e){
  if(e.key!=='/')return;
  const tag=(document.activeElement&&document.activeElement.tagName)||'';
  if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT')return;
  const pane=document.querySelector('.pane.on');if(!pane)return;
  const key=pane.id.replace('pane-','');
  if(key!=='clients'&&key!=='conns'&&key!=='macs')return;
  const box=document.getElementById('search-'+key);
  if(box){box.querySelector('.search-input').focus();e.preventDefault();}
});

let lastStats=null,lastStatsT=0,lastSpeeds={},lastTraffic=null,lastClientTraffic=null,trClientSig='';
let prevPps={tx:0,rx:0,ok:false},prevConns={},lastConnsT=0,lastConnSpeeds={};
// 异常提醒条手动关闭后，在下一个不同的告警组合出现前不再自动弹回
let alertOff=false,alertSig='';
function applyStats(data){
  if(!data)return;
  try{
    lastStats=data;
    lastStatsT=Date.now();
    const upd=document.getElementById('updated-at');
    if(upd)upd.textContent=t('updated').replace('{n}',new Date().toLocaleTimeString());
    resetDashboardPeriod(data);
    const now=data.sample_time_ms===undefined?performance.now():Number(data.sample_time_ms);
    const dt=lastT&&now>lastT?(now-lastT)/1000:0;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    const chip=document.getElementById('mode-chip');
    if(chip)chip.classList.toggle('client',data.mode!=='server');
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    // 级别来自服务端：直接写 value 不会触发 change，要顺手刷新自绘下拉框的文案
    const lvSel=document.getElementById('loglevel');
    lvSel.value=data.log_level||'info';
    syncSelect(lvSel);
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':t('tls_http');

    // 速率/总量统计覆盖全部客户端；过滤只作用于表格行
    const speeds={};let tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]&&dt>0){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};
      speeds[id]={sx:sx,sr:sr};
      tTxS+=sx;tRxS+=sr;
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;lastSpeeds=speeds;
    if(data.global_tx_bytes!==undefined && data.global_rx_bytes!==undefined){
      tTx=Number(data.global_tx_bytes)||0;tRx=Number(data.global_rx_bytes)||0;
      tTxS=globalPrev&&dt>0?Math.max(0,(tTx-globalPrev.tx)/dt):0;
      tRxS=globalPrev&&dt>0?Math.max(0,(tRx-globalPrev.rx)/dt):0;
      globalPrev={tx:tTx,rx:tRx};
    }
    const isServer=data.mode==='server';
    const upSpeed=isServer?tRxS:tTxS,downSpeed=isServer?tTxS:tRxS;
    txHist.push(upSpeed);rxHist.push(downSpeed);txTimes.push(Date.now());
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();txTimes.shift();}
    if(chartRange==='2m'&&!trendData)drawChart(); // 冷启动兜底；拿到服务端 2 分钟缓存后由 drawTrendChart 接管

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText=t('kpi.tcp')+': '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('live-up').innerText=fmtBytes(upSpeed,true);
    document.getElementById('live-down').innerText=fmtBytes(downSpeed,true);
    renderClientsTable(data);
    if(drawerOn())renderDrawer();

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small>/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    // 包总量（服务端=各会话之和；客户端=local），PPS 与 FEC 开销都基于它
    let txPk=0,rxPk=0;
    if(data.mode==='server'){
      const vals=data.clients?Object.values(data.clients):[];
      vals.forEach(function(c){txPk+=c.tx_packets||0;rxPk+=c.rx_packets||0;});
    }else if(data.clients&&data.clients.local){
      txPk=data.clients.local.tx_packets||0;rxPk=data.clients.local.rx_packets||0;
    }
    if(data.global_tx_packets!==undefined)txPk=Number(data.global_tx_packets)||0;
    if(data.global_rx_packets!==undefined)rxPk=Number(data.global_rx_packets)||0;
    const quality=dashboardQualityStats(data);
    // Parity/DATA application-frame wire bytes, excluding cover padding.
    document.getElementById('fec-overhead').innerText=quality.fecOverheadPct===null?'-':quality.fecOverheadPct.toFixed(1)+'%';
    document.getElementById('k-dropped').innerText=data.dropped_frames||0;
	const ro=data.reorder||{};
	document.getElementById('reorder-skipped').innerText=ro.skipped_frames||0;
    document.getElementById('tap-errors').innerText=data.tap_write_errors||0;
    // 包速率 PPS：与字节速率同口径的差分
    const ppsTx=prevPps.ok&&dt>0?Math.max(0,(txPk-prevPps.tx)/dt):0;
    const ppsRx=prevPps.ok&&dt>0?Math.max(0,(rxPk-prevPps.rx)/dt):0;
    prevPps={tx:txPk,rx:rxPk,ok:true};
    document.getElementById('k-pps').innerText=Math.round(ppsTx+ppsRx).toLocaleString();
    document.getElementById('pps-up').innerText=Math.round(isServer?ppsRx:ppsTx).toLocaleString();
    document.getElementById('pps-down').innerText=Math.round(isServer?ppsTx:ppsRx).toLocaleString();
    const m=data.mem||{};
    document.getElementById('mem').innerHTML=(m.heap_alloc_mb||0).toFixed(1)+'<small> MB</small>';
    document.getElementById('goroutines').innerText=m.num_goroutine||0;

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('AES-256-GCM');else if(data.enc_algo===4)meta.push('AES-128-GCM');
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

	renderConnsTable(data,true);renderMacsTable(data);renderBansTable(data);renderTraffic(data);renderStatus(data);
  }catch(e){console.error('stats render failed',e);}
}

// 过滤输入时不重新拉取：对最近一次快照重渲染各表格
function rerenderTables(){
  if(!lastStats)return;
  renderClientsTable(lastStats);
  renderConnsTable(lastStats,false);
  renderMacsTable(lastStats);
  renderBansTable(lastStats);
}

function renderClientsTable(data){
  const f=Q.clients;
  const entries=data.mode==='server'?Object.entries(data.clients||{}):(data.clients&&data.clients.local?[['local',data.clients.local]]:[]);
  let rows=[];
  entries.forEach(function(pair){
    const sp=lastSpeeds[pair[0]]||{sx:0,sr:0};
    rows.push({id:pair[0],c:pair[1],sx:sp.sx,sr:sp.sr});
  });
  rows=sortRows('clients',rows);
  syncSortUI('clients');
  const all=entries.length;
  rows=rows.filter(function(r){return passFilter(Object.assign({id:r.id},r.c),f);});
  const total=rows.length;
  const pv=pageView('clients',rows);
  document.getElementById('clients-body').innerHTML=pv.rows.map(function(r){
    return '<tr data-open="'+esc(r.id)+'"><td class="num dim" title="'+esc(r.id)+'">'+hi(esc(shortId(r.id,10)),f)+(r.c.peer_info&&r.c.peer_info.hostname?'<br><span class="dim">'+hi(esc(r.c.peer_info.hostname),f)+'</span>':'')+(r.c.peer_info&&(r.c.peer_info.os||r.c.peer_info.arch)?'<br>'+platformIconsOnly(r.c.peer_info.os,r.c.peer_info.arch):'')+'</td>'+
      '<td class="num">'+hi(esc(r.c.ipv4||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(r.c.ipv6||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(r.c.mac||'-'),f)+'</td>'+
      '<td class="num">'+r.c.active_conns+'</td>'+
      '<td class="num">'+fmtBytes(r.c.tx_bytes)+'</td><td class="num">'+fmtBytes(r.c.rx_bytes)+'</td>'+
      '<td class="num speed">'+fmtBytes(r.sx,true)+'</td><td class="num speed dn">'+fmtBytes(r.sr,true)+'</td>'+
      '<td class="hide-sm">'+badge(r.c.fec)+'</td><td class="hide-sm">'+encBadge(r.c.enc_algo)+'</td>'+
      '<td>'+(data.mode==='server'?'<button class="btn danger sm" onclick="kickClient(\''+r.id+'\')">'+t('th.kick')+'</button>'+
        '<button class="btn ghost sm" onclick="banClient(\''+r.id+'\',0)">'+t('th.ban')+'</button>':'-')+'</td></tr>';
  }).join('')||emptyTableRow('clients',12,all);
  setCount('client-count',f,total,all);
  renderPager('clients',total);
}

// ---------- "运行状态" 页：宿主/协商/brutal/配置 四块明细 ----------
// 空值不占行：面板上留一堆空行只会让人误以为字段缺失是故障
function kv(el,rows){
  el.innerHTML=rows.length?rows.map(r=>'<tr><th>'+esc(r[0])+'</th><td>'+r[1]+'</td></tr>').join(''):'';
}
function yn(v){return v?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>';}
function mtxt(v){return '<span class="mono">'+esc(v)+'</span>';}
function ntxt(){return '<span style="color:var(--sub)">-</span>';}
function peerSummary(p){
  if(!p)return '';
  const a=[];
  if(p.hostname)a.push(p.hostname);
  const impl=[p.implementation,p.version].filter(Boolean).join(' ');if(impl)a.push(impl);
  const plat=[p.os,p.os_version,p.arch].filter(Boolean).join(' ');if(plat)a.push(plat);
  if(p.kernel)a.push('kernel '+p.kernel);
  return a.join(' · ');
}
// 证书有效期：剩余天数按远近配色，过期与自签都显式标出来
function certCell(c){
  const d=c.days_left;
  let col='var(--sub)',txt;
  if(d<=0){col='var(--err)';txt=t('ov.err_cert_bad');}
  else if(d<=7){col='var(--err)';txt=t('ov.err_cert_ok').replace('{n}',d);}
  else if(d<=30){col='var(--warn)';txt=t('ov.err_cert_ok').replace('{n}',d);}
  else txt=t('ov.err_cert_ok').replace('{n}',d);
  return '<span class="mono" style="color:'+col+'">'+esc(txt)+'</span>'
    +(c.not_after?' <span class="mono" style="color:var(--sub)">'+esc(c.not_after)+'</span>':'')
    +(c.self_signed?' <span class="badge b-dup">self-signed</span>':'');
}
function encName(a){return a===2?'AES-256-GCM':(a===4?'AES-128-GCM':(a===0?'none (TLS only)':String(a)));}
function rateRange(lo,hi2){if(!lo&&!hi2)return '-';return (lo===hi2?String(lo):lo+'~'+hi2)+' Mbps';}
function renderStatus(data){
  const sys=data.system||{},neg=data.negotiate||{},b=neg.brutal||{},tls=neg.tls||{},cfg=data.cfg||{},peer=data.peer||{};
  const rw=document.getElementById('status-restart');
  const rn=sys.needs_restart||[];
  if(rn.length){rw.style.display='';rw.innerHTML='<strong>'+t('stt.restart')+'</strong><br><span class="mono">'+esc(rn.join(', '))+'</span>';}
  else{rw.style.display='none';}
  const sysRows=[
    [t('stt.sys.os'),platformSummary(sys.os,'',sys.arch)],
    [t('stt.sys.go'),mtxt(sys.go_version||'-')],
    [t('stt.sys.cpu'),sys.num_cpu||'-'],
    [t('stt.sys.host'),mtxt(sys.host||'-')],
    [t('stt.sys.cfgpath'),mtxt(sys.cfg_path||'-')],
    [t('stt.sys.ver'),mtxt(data.version||'-')+' · '+fmtDur(data.uptime_sec||0)],
  ];
  // 系统指标尽力而为：Linux 才有负载/内存/文件描述符，缺位不占行
  if(sys.load)sysRows.push([t('stt.sys.load'),'<span class="mono">'+sys.load.one.toFixed(2)+' / '+sys.load.five.toFixed(2)+' / '+sys.load.fifteen.toFixed(2)+'</span>']);
  if(sys.mem)sysRows.push([t('stt.sys.mem'),'<span class="mono">'+fmtBytes(sys.mem.used_mb*1048576)+' / '+fmtBytes(sys.mem.total_mb*1048576)+'</span> ('+Math.round(sys.mem.used_mb/sys.mem.total_mb*100)+'%)']);
  if(sys.fd_open)sysRows.push([t('stt.sys.fd'),'<span class="mono">'+sys.fd_open+'</span>']);
  if(sys.num_gc)sysRows.push([t('stt.sys.gc'),'<span class="mono">'+sys.num_gc+'</span> / <span class="mono">'+sys.gc_pause_ms.toFixed(1)+' ms</span>']);
  // 证书有效期与进程 CPU 是"到期前就该看到"的指标，放在宿主块而不是靠翻告警
  if(data.cpu)sysRows.push([t('stt.sys.cpu_use'),'<span class="mono">'+data.cpu.percent.toFixed(1)+'%</span>']);
  if(data.cert)sysRows.push([t('stt.sys.cert'),certCell(data.cert)]);
  kv(document.getElementById('st-sys'),sysRows);
  // 密钥代际与端到端 shaping 速率是"一条会话"的概念，服务端不消费单一会话，
  // 逐连接结果看"连接明细"页，这里只在客户端模式显示。
  const nrw=[
    [t('stt.neg.proto'),neg.protocol_version?('v'+neg.protocol_version):ntxt()],
    [t('stt.neg.enc'),neg.enc_algo?encName(neg.enc_algo):ntxt()],
    [t('stt.neg.fec'),yn(!!neg.fec)],
    [t('stt.neg.grp'),neg.fec_group?String(neg.fec_group):(neg.fec?t('stats.fec_mixed'):ntxt())],
    [t('stt.neg.pad'),neg.pad_mode?mtxt(neg.pad_mode):ntxt()],
    [t('stt.neg.minenc'),neg.min_enc?mtxt(neg.min_enc):ntxt()],
    [t('stt.neg.stoken'),yn(!!neg.session_token)],
  ];
  if(data.mode==='client'){
    if(peerSummary(peer))nrw.push([t('tp.peer'),mtxt(peerSummary(peer))]);
    nrw.push([t('stt.neg.epoch'),neg.session_epoch?String(neg.session_epoch):ntxt()]);
    nrw.push([t('stt.neg.tx'),(neg.tx_rate_mbps||0)+' Mbps']);
    nrw.push([t('stt.neg.rx'),(neg.rx_rate_mbps||0)+' Mbps']);
	  nrw.push([t('stt.neg.tlsfp'),tls.fingerprint_sha256?mtxt(tls.fingerprint_kind+':'+tls.fingerprint_sha256):ntxt()]);
	  nrw.push([t('stt.neg.tlsver'),tls.version?mtxt(tls.version+' (0x'+Number(tls.version_id||0).toString(16).padStart(4,'0')+')'):ntxt()]);
	  nrw.push([t('stt.neg.tlscipher'),tls.cipher_suite?mtxt(tls.cipher_suite+' (0x'+Number(tls.cipher_suite_id||0).toString(16).padStart(4,'0')+')'):ntxt()]);
	  nrw.push([t('stt.neg.tlsalpn'),tls.alpn?mtxt(tls.alpn):ntxt()]);
	  nrw.push([t('stt.neg.tlssni'),tls.sni?mtxt(tls.sni):ntxt()]);
	  nrw.push([t('stt.neg.tlsoffer'),tls.fingerprint_sha256?mtxt((tls.offered_cipher_suites||[]).length+' cipher / '+(tls.offered_signature_schemes||[]).length+' sig / '+(tls.offered_groups||[]).length+' group / '+(tls.offered_alpn||[]).length+' ALPN'):ntxt()]);
    // 配了 fwmark 才显示：策略路由是否真的装进内核，以及失败原因。
    if(neg.policy_routing!==undefined){
      nrw.push([t('stt.neg.prroute'),neg.policy_routing_error
        ?'<span class="badge b-off">'+esc(neg.policy_routing_error)+'</span>'
        :yn(!!neg.policy_routing)]);
    }
  }
  kv(document.getElementById('st-neg'),nrw);
  // TCP Brutal 的"配置意图 + 内核实际状态"是一整份数据，整份下发或整份缺失。
  // 缺失时不能按缺省值补齐渲染：会变成开关=否、0 Mbps、已生效 0/0，
  // 和同屏连接明细里真实的 brutal 速率打架。
  kv(document.getElementById('st-brutal'),!!neg.brutal?[
    [t('stt.brut.en'),yn(!!b.enabled)],
    [t('stt.brut.up'),(b.up_mbps||0)+' Mbps'],
    [t('stt.brut.down'),(b.down_mbps||0)+' Mbps'],
    [t('stt.brut.kern'),b.kernel_supported?'<span class="badge b-on">'+t('stt.kern_yes')+'</span>':'<span class="badge b-off">'+t('stt.kern_no')+'</span>'],
    [t('stt.brut.cur'),b.kernel_current?mtxt(b.kernel_current):ntxt()],
    [t('stt.brut.avail'),(b.kernel_available&&b.kernel_available.length)?mtxt(b.kernel_available.join(', ')):ntxt()],
    [t('stt.brut.applied'),(b.applied_conns||0)+' / '+(b.total_conns||0)],
    [t('stt.brut.perconn'),'<span class="mono">'+rateRange(b.min_up_mbps,b.max_up_mbps)+' / '+rateRange(b.min_down_mbps,b.max_down_mbps)+'</span>'],
    [t('stt.brut.errs'),brutErrCell(b)],
  ]:[[t('ov.no_data'),ntxt()]]);
  kv(document.getElementById('st-cfg'),Object.keys(cfg).filter(k=>data.mode!=='server'||(k!=='fec'&&k!=='fec_group')).map(function(k){
    const v=cfg[k];let cell;
    if(typeof v==='boolean')cell=yn(v);
    else if(Array.isArray(v))cell=v.length?mtxt(v.map(function(x){
      // 对象元素（source_rules）直接 join 会变成 [object Object]，转成 JSON 展示
      return typeof x==='object'&&x!==null?JSON.stringify(x):x;
    }).join(' ; ')):ntxt();
    else if(v===undefined||v===null||v==='')cell=ntxt();
    else cell=mtxt(v);
    const lab=t('cfgk.'+k);
    return [lab==='cfgk.'+k?k:lab,cell];
  }));
  // 新增观测块：填充开销 / 防护路径 / 钩子 / 策略路由 / TAP 链路，
  // 以及顶部异常提醒条。都按"缺位不占位"处理。
  renderPadStatus(data.pad);
  renderProtectStatus(data.protect);
  renderHookStatus(data.hooks);
  renderRouteStatus(data.routes);
  renderTapStatus(data.tap_link);
  renderOverview(data);
  renderDiag(data);
  renderSec(data);
  renderTopo(data);
}

// ---------- 诊断中心：健康度环 + 分类自检清单 ----------
// 只算最近一次 /api/stats 快照就能得出的项，不发新请求、不新增端点。
// 判定字段与方向取自概览页顶部异常提醒条那批条件，只是把它的一档提醒拆成 warn/fail 两档。
// lv: ok / warn / fail / skip —— skip 是当前模式或平台缺这份数据（含老服务端不下发），
// 不计分也不报忧，免得缺数据的一片红把真正的问题淹掉。
// 图标按分类名索引。这里必须是对象而不是数组：词法守卫据「前一个有效字符」判断花括号
// 是不是对象字面量（只认 ( = , : ? ! & | + - * 与 return/yield），数组里的 {…} 会被当成
// 块作用域，属性冒号就被误读成三元冒号，整段脚本直接失效。
const DG_CATS={
  tunnel:'<path d="M3 12h4l2-6 3 12 3-9 2 3h4"/>',
  route:'<circle cx="5" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="M7 6h6a4 4 0 0 1 4 4v6"/><path d="M5 8v8a4 4 0 0 0 4 4h2"/>',
  brut:'<path d="M13 2 4 14h6l-1 8 9-12h-6z"/>',
  tls:'<rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  fec:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 17.5h7M17.5 14v7"/>',
  prot:'<path d="M12 3 4 6v6c0 5 3.5 7.5 8 9 4.5-1.5 8-4 8-9V6z"/>',
  res:'<path d="M4 14a8 8 0 0 1 16 0"/><line x1="12" y1="14" x2="16" y2="9"/>',
  cfg:'<circle cx="12" cy="12" r="3"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2"/>'
};
// 三级阈值：nonzero 是计数器（大于 0 即注意），ge 越大越坏，le 越小越坏。
// soft/hard 分别是 warn 与 fail 拐点；写成 if/else 便于加新档位。
function dgLevel(kind,v,soft,hard){
  if(kind==='skip')return 'skip';
  if(kind==='nonzero')return v>0?'warn':'ok';
  if(kind==='ge')return v>=hard?'fail':(v>=soft?'warn':'ok');
  if(kind==='le')return v<=hard?'fail':(v<=soft?'warn':'ok');
  return 'ok';
}
function dgRun(data){
  const out={};
  const add=function(cat,ch,lv,det,tip){
    if(!out[cat])out[cat]=[];
    out[cat].push({ch:ch,lv:lv,det:det||'',tip:tip||''});
  };
  const N=function(v){return fmtNum(v||0);};
  const miss=t('dg.not_set');
  const cr=data.mode==='server'?(data.server_conns||[]):(data.conns||[]);
  // FEC 开销的分母是真实承载的客户端包，填充字节不算
  let txPk=0;
  if(data.mode==='server'){
    const cl=data.clients||{};
    Object.keys(cl).forEach(function(k){txPk+=(cl[k].tx_packets||0);});
  }else{
    const lc=data.clients&&data.clients.local;
    txPk=lc?(lc.tx_packets||0):0;
  }
  const f=data.fec||{},ro=data.drop_breakdown||{},np=data.negotiate||{},
        sm=data.system||{},mm=data.mem||{},cfg=data.cfg||{},
        pf=data.protect,ho=data.hooks,ip=data.ip_pool,cpu=data.cpu,
        sysMem=sm.mem||{},load=sm.load||{};

  // ---- 隧道 ----
  add('tunnel','tap',data.tap_write_errors>0?'fail':'ok',N(data.tap_write_errors));
  const df=data.dropped_frames||0,bk=[];
  if(ro.backpressure)bk.push(t('ov.err_bp'));
  if(ro.spoofed_src)bk.push(t('ov.err_spoof'));
  if(ro.broadcast)bk.push(t('ov.err_bcast'));
  if(ro.reorder)bk.push(t('ov.err_reord'));
  add('tunnel','drop',dgLevel('nonzero',df),
      N(df)+(bk.length?'<span class="dim"> · '+bk.join(' · ')+'</span>':''));
  add('tunnel','reorder',dgLevel('nonzero',ro.skipped_frames),
      N(ro.skipped_frames)+(ro.gap_events?'<span class="dim"> · '+N(ro.gap_events)+'</span>':''));
  const sm2=data.sessions;
  if(sm2&&sm2.max){
    const sv=sm2.active/sm2.max;
    add('tunnel','sess',dgLevel('ge',sv,0.8,1),
        sm2.active+'<span class="dim"> / '+sm2.max+'</span>');
  }else add('tunnel','sess','skip',miss);
  add('tunnel','reconn',dgLevel('nonzero',data.reconnect_attempts),N(data.reconnect_attempts));
  // rttStats 吃 {rtt} 形状的连接明细；先从快照里的连接记录重排出来。
  // 不用 return {…}（带空格）：词法守卫靠 return 紧邻花括号判断对象字面量。
  const rl=[];
  cr.forEach(function(x){rl.push({rtt:x.rtt_ms||0});});
  const rts=rttStats(rl);
  if(rts){
    add('tunnel','rtt',dgLevel('ge',rts.p95,200,500),
        rts.min+'<span class="dim"> · '+Math.round(rts.avg)+' · '+Math.round(rts.p95)+' · '+rts.max+' ms</span>',
        t('dg.rtt_tip'));
  }else add('tunnel','rtt','skip',miss);
  const cerr=cr.filter(function(x){return !!x.last_error;}).length;
  add('tunnel','connerr',dgLevel('nonzero',cerr),cerr?t('dg.err_n').replace('{n}',N(cerr)):N(0));

  // ---- 路由 ----
  const prl=np.policy_routing;
  if(prl===true)add('route','polroute','ok',yn(true));
  else if(prl===false)add('route','polroute','fail',yn(false));
  else add('route','polroute','skip',miss);
  if(data.routes){
    const rn=(data.routes.rules||[]).length+(data.routes.routes||[]).length;
    add('route','routes',data.routes.error?'warn':'ok',
        N(rn)+(data.routes.error?'<span class="dim"> · '+esc(data.routes.error)+'</span>':''));
  }else add('route','routes','skip',miss);
  if(ip&&ip.v4_total){
    add('route','pool',dgLevel('ge',ip.v4_used/ip.v4_total*100,80,100),
        ip.v4_used+'<span class="dim"> / '+ip.v4_total+'</span>');
  }else add('route','pool','skip',miss);
  if(np.protocol_version!==undefined)add('route','negver','ok','v'+np.protocol_version);
  else add('route','negver','skip',miss);

  // ---- TCP Brutal ----
  const bOk=cr.filter(function(x){return x.brutal_applied===true;}).length;
  const bErr=cr.filter(function(x){return !!x.brutal_error;}).length;
  if(!cr.length)add('brut','brut','skip',miss);
  else if(bErr>0)add('brut','brut','warn',bOk+'<span class="dim"> / '+cr.length+'</span>',
      cr[0].brutal_error);
  else if(bOk>0)add('brut','brut','ok',bOk+'<span class="dim"> / '+cr.length+'</span>');
  else add('brut','brut','skip',miss);
  let uMax=0,dMax=0;
  cr.forEach(function(x){
    uMax=Math.max(uMax,x.brutal_cli_tx_mbps||x.brutal_tx_mbps||0);
    dMax=Math.max(dMax,x.brutal_srv_tx_mbps||x.brutal_rx_mbps||0);
  });
  if(!cr.length)add('brut','brutrate','skip',miss);
  else if(uMax>0||dMax>0)add('brut','brutrate','ok',
      uMax+'<span class="dim"> ↑ / '+dMax+' ↓ Mbps</span>');
  else add('brut','brutrate','skip',miss);

  // ---- TLS ----
  if(data.cert){
    add('tls','cert',dgLevel('le',data.cert.days_left,30,0),
        N(data.cert.days_left)+(data.cert.self_signed?'<span class="dim"> · self-signed</span>':''));
  }else add('tls','cert','skip',miss);
  if(pf&&pf.tls_handshake_fail!==undefined)add('tls','tlsfail',dgLevel('nonzero',pf.tls_handshake_fail),
      N(pf.tls_handshake_fail));
  else add('tls','tlsfail','skip',miss);
  const vers=[];
  cr.forEach(function(x){if(x.tls_version&&vers.indexOf(x.tls_version)<0)vers.push(x.tls_version);});
  if(!vers.length)add('tls','tlsver','skip',miss);
  else add('tls','tlsver',vers.every(function(v){return v.indexOf('1.3')>=0;} )?'ok':'warn',
      esc(vers.join(', ')));
  const encs=cr.map(function(x){return x.enc_algo;}).filter(function(v){return v!==undefined;});
  if(!encs.length){
    if(cfg.encrypt===false)add('tls','enc','fail',esc(encName(data.enc_algo)));
    else if(data.enc_algo)add('tls','enc','ok',esc(encName(data.enc_algo)));
    else add('tls','enc','skip',miss);
  }else{
    const nBad=encs.filter(function(v){return !v;}).length;
    add('tls','enc',nBad>0?'warn':'ok',
        nBad>0?N(nBad)+'<span class="dim"> / '+encs.length+'</span>':esc(encName(encs[0])));
  }

  // ---- FEC ----
  if(f.enabled===false)add('fec','fecloss','skip',miss);
  else add('fec','fecloss',dgLevel('nonzero',f.lost),
      N(f.recovered)+(f.lost?'<span class="dim"> · '+N(f.lost)+'</span>':''));
  const fecQuality=dashboardQualityStats(data);
  if(fecQuality.fecOverheadPct===null)add('fec','fecovh','skip',miss);
  else add('fec','fecovh','ok',fecQuality.fecOverheadPct.toFixed(1)+'<span class="dim">%</span>');
  // A configured redundancy ratio is an observation, not a fixed-threshold fault.
  const base=data.fec_mode||cfg.fec_mode;
  const modes=[];
  cr.forEach(function(x){if(x.fec&&modes.indexOf(x.fec)<0)modes.push(x.fec);});
  if(!base||!modes.length)add('fec','fecmode','skip',miss);
  else add('fec','fecmode',modes.every(function(m){return m===base;} )?'ok':'warn',
      esc(modes.join(', ')));

  // ---- 保护与钩子 ----
  const nRj=pf?((pf.conns_rejected||0)+(pf.fec_group_rejected||0)):0;
  if(!pf)add('prot','reject','skip',miss);
  else add('prot','reject',dgLevel('nonzero',nRj),N(nRj));
  const nFb=pf?((pf.fallback_http||0)+(pf.tarpit||0)):0;
  if(!pf)add('prot','fallback','skip',miss);
  else add('prot','fallback',dgLevel('nonzero',nFb),N(nFb));
  if(!pf)add('prot','psk','skip',miss);
  else if(!(pf.psk_fail||[]).length)add('prot','psk','ok',N(0));
  else add('prot','psk','warn',N(pf.psk_fail.length));
  if(!ho||!ho.configured)add('prot','hookup','skip',miss);
  else add('prot','hookup',ho.up_ran&&!ho.up_ok?'fail':'ok',
      ho.up_ok?N(ho.up_ms)+'<span class="dim"> ms</span>':esc(ho.up_error||'-'));
  if(!ho||!ho.configured)add('prot','hookdown','skip',miss);
  else add('prot','hookdown',ho.down_ran&&!ho.down_ok?'fail':'ok',
      ho.down_ok?N(ho.down_ms)+'<span class="dim"> ms</span>':esc(ho.down_error||'-'));

  // ---- 资源 ----
  if(!cpu)add('res','cpu','skip',miss);
  else add('res','cpu',dgLevel('ge',cpu.percent,60,80),
      cpu.percent.toFixed(1)+'<span class="dim">%</span>');
  if(sysMem.total_mb){
    add('res','mem',dgLevel('ge',sysMem.used_mb/sysMem.total_mb*100,80,90),
        sysMem.used_mb.toFixed(0)+'<span class="dim"> / '+sysMem.total_mb.toFixed(0)+' MB</span>');
  }else add('res','mem','skip',miss);
  if(mm.num_goroutine!==undefined)add('res','gor',dgLevel('ge',mm.num_goroutine,400,1000),
      N(mm.num_goroutine));
  else add('res','gor','skip',miss);
  if(sm.fd_open!==undefined)add('res','fd',dgLevel('ge',sm.fd_open,4000,8000),N(sm.fd_open));
  else add('res','fd','skip',miss);
  if(load.fifteen!==undefined&&sm.num_cpu){
    // 读数是 15 分钟负载，dim 里是核数——两相除才是每核压力
    add('res','load',dgLevel('ge',load.fifteen/sm.num_cpu,1.5,2.5),
        load.fifteen.toFixed(2)+'<span class="dim"> / '+sm.num_cpu+'</span>');
  }else add('res','load','skip',miss);
  if(sm.gc_pause_ms!==undefined)add('res','gc',dgLevel('ge',sm.gc_pause_ms,30,50),
      sm.gc_pause_ms.toFixed(1)+'<span class="dim"> ms</span>');
  else add('res','gc','skip',miss);

  // ---- 配置 ----
  // 级别在快照里是顶层 log_level；cfg.log_level 只有较新的服务端才一起下发
  const logLv=cfg.log_level||data.log_level;
  if(!logLv)add('cfg','loglvl','skip',miss);
  else add('cfg','loglvl',logLv==='debug'?'warn':'ok',esc(logLv));
  return out;
}

function renderDiag(data){
  if(!data)return;
  const grp=dgRun(data);
  const keys=Object.keys(grp);
  const cnt={ok:0,warn:0,fail:0,skip:0};
  keys.forEach(function(k){grp[k].forEach(function(x){cnt[x.lv]++;});});
  const scored=cnt.ok+cnt.warn+cnt.fail;
  const score=scored?Math.round((cnt.ok+cnt.warn/2)/scored*100):100;
  // 环半径 50 → 周长 314.16；offset 越大剩得越少
  const C=2*Math.PI*50;
  const fg=document.getElementById('dg-ring-fg');
  if(fg){
    fg.setAttribute('stroke-dasharray',C.toFixed(2));
    fg.setAttribute('stroke-dashoffset',(C*(1-score/100)).toFixed(2));
    let col='var(--up)';
    if(score<60)col='var(--err)';
    else if(score<90)col='var(--warn)';
    fg.style.stroke=col;
  }
  const sn=document.getElementById('dg-score-n');
  if(sn)sn.innerText=score;
  const chips=document.getElementById('dg-chips');
  if(chips){
    chips.innerHTML=['ok','warn','fail','skip'].map(function(lv){
      const nm='dg.lv'+lv.charAt(0).toUpperCase()+lv.slice(1);
      return '<span class="dg-chip c-'+lv+(cnt[lv]?'':' zero')+'"><i></i>'+esc(t(nm))+
        '<span class="n">'+cnt[lv]+'</span></span>';
    }).join('');
  }
  const vd=document.getElementById('dg-verdict');
  if(vd){
    if(cnt.fail===0&&cnt.warn===0){
      vd.className='dg-verdict';
      vd.innerText=t('dg.all_ok');
    }else{
      vd.className='dg-verdict '+(cnt.fail>0?'v-fail':'v-warn');
      vd.innerText=t('dg.open_fail').replace('{n}',String(cnt.fail+cnt.warn));
    }
  }
  const tot=document.getElementById('dg-total');
  if(tot)tot.innerText=t('dg.total').replace('{n}',String(scored));
  const up=document.getElementById('dg-updated');
  if(up){
    const ago=lastStatsT>0?Math.max(0,Math.round((Date.now()-lastStatsT)/1000)):0;
    up.innerText=t('dg.updated').replace('{t}',fmtDur(ago));
  }
  const grid=document.getElementById('dg-grid');
  if(grid){
    // 整个分类都取不到数据（老服务端不下发、或该模式没有）就不占位——
    // 一排"未配置"只会稀释真正的问题；单项缺数据仍然保留，好说明这项为什么没判定
    grid.innerHTML=keys.filter(function(k){
      return grp[k].some(function(x){return x.lv!=='skip';});
    }).map(function(k){
      const cs=grp[k];
      const nBad=cs.filter(function(x){return x.lv==='warn'||x.lv==='fail';}).length;
      const nSkip=cs.filter(function(x){return x.lv==='skip';}).length;
      const nOk=cs.length-nBad-nSkip;
      const ic=DG_CATS[k]||'';
      return '<div class="dg-cat"><div class="dg-cat-h">'+
        '<span class="dg-cat-ico"><svg viewBox="0 0 24 24">'+ic+'</svg></span>'+
        '<h4>'+esc(t('dg.c_'+k))+'</h4>'+
        '<span class="dg-cat-n">'+nOk+'/'+(nOk+nBad)+'</span>'+
        '</div><div class="dg-checks">'+
        cs.map(function(x){
          return '<div class="dg-chk l-'+x.lv+'"'+(x.tip?' title="'+esc(x.tip)+'"':'')+'>'+
            '<span class="dg-dot"></span>'+
            '<span class="dg-chk-t">'+esc(t('dg.'+x.ch))+'</span>'+
            '<span class="dg-chk-d mono">'+x.det+'</span>'+
          '</div>';
        }).join('')+'</div></div>';
    }).join('');
  }
}

// ---------- 新增观测面板：填充开销 / 防护路径 / 钩子 / 策略路由 / TAP 链路 ----------
function fmtNum(n){return Number(n||0).toLocaleString();}

// 填充开销：线路字节与其中填充字节的比值，回答"混淆吃了多少带宽"。
// 记账在 Write 成功之后，wire 与 tx_bytes 同源；空心跳帧不计入。
function renderPadStatus(p){
  const rows=[];
  if(!p){kv(document.getElementById('st-pad'),[[t('ov.no_data'),ntxt()]]);return;}
  const wire=p.wire_bytes||0,pad=p.pad_bytes||0;
  rows.push([t('ov.pad_wire'),mtxt(fmtBytes(wire))]);
  rows.push([t('ov.pad_bytes'),mtxt(fmtBytes(pad))]);
  // 多付带宽比：每 1 字节填充，线路上实际传了多少字节
  rows.push([t('ov.pad_ratio'),wire&&pad?mtxt('1 : '+(wire/pad).toFixed(2)):ntxt()]);
  rows.push([t('ov.pad_pct'),'<span class="mono">'+(p.overhead_pct||0).toFixed(1)+'%</span>']);
  kv(document.getElementById('st-pad'),rows);
}

// 防护路径计数 + PSK 失败排行。这些都是"过去只进日志"的拒绝，
// 面板能看见才能回答"伪装站点挡住了多少扫描"。
function renderProtectStatus(pr){
  const rows=[];
  if(!pr){kv(document.getElementById('st-protect'),[[t('ov.prot.off'),ntxt()]]);return;}
  else{
    [['conns_rejected',t('ov.prot.conns')],['tls_handshake_fail',t('ov.prot.tls')],
     ['fallback_http',t('ov.prot.fallback')],['tarpit',t('ov.prot.tarpit')],
     ['fec_group_rejected',t('ov.prot.fec')]].forEach(function(e){
      const v=pr[e[0]]||0;
      rows.push([e[1],'<span class="mono" style="color:'+(v>0?'var(--warn)':'var(--sub)')+'">'+fmtNum(v)+'</span>']);
    });
  }
  kv(document.getElementById('st-protect'),rows);
  const psk=pr&&pr.psk_fail||[];
  const out=[];
  if(!psk.length){
    out.push([t('ov.prot.psk'),'<span style="color:var(--sub)">'+t('ov.prot.psk_empty')+'</span>']);
  }else{
    out.push([t('ov.prot.psk'),'<span class="mono">'+psk.length+' / '+t('ov.prot.window')+'</span>']);
    psk.slice(0,8).forEach(function(p){
      out.push(['<span class="mono">'+esc(p.remote)+'</span>','<span class="mono">'+(p.count||0)+'</span>']);
    });
  }
  kv(document.getElementById('st-psk'),out);
}

// up/down 钩子：面板此前只知道配了什么，不知道跑成功没有
function renderHookStatus(h){
  if(!h){kv(document.getElementById('st-hooks'),[[t('ov.not_applied'),ntxt()]]);return;}
  const run=function(ok,ran,ms,err,at){
    if(!ran)return '<span style="color:var(--sub)">'+t('ov.hook.never')+'</span>';
    const when=at?'<span class="dim"> · '+esc(new Date(at).toLocaleString())+'</span>':'';
    if(ok)return '<span class="badge b-on">'+t('ov.hook.ran')+'</span> <span class="mono">'+ms+' ms</span>'+when;
    return '<span class="badge b-off">'+t('ov.hook.fail')+'</span> <span class="mono">'+ms+' ms</span>'+when;
  };
  const tail=function(info){
    const o=[];
    if(info.err)o.push([t('ov.hook.err'),'<span class="mono" style="color:var(--err)">'+esc(info.err)+'</span>']);
    else if(info.out)o.push([t('ov.hook.out'),'<span class="mono">'+esc(String(info.out).slice(0,240))+'</span>']);
    return o;
  };
  // let 而非 const：下面用 concat 追加钩子输出行，const 会在第二次追加时抛
  // "Assignment to constant variable"，把整个状态页的渲染一起打断。
  let rows=[];
  if(h.up_path)rows.push([t('ov.hook.up'),'<span class="mono">'+esc(h.up_path)+'</span>']);
  if(h.down_path)rows.push([t('ov.hook.down'),'<span class="mono">'+esc(h.down_path)+'</span>']);
  rows.push([t('ov.hook.ran')+' (up)',run(h.up_ok,h.up_ran,h.up_ms,h.up_error,h.up_at)]);
  rows=rows.concat(tail({err:h.up_error,out:h.up_out}));
  rows.push([t('ov.hook.ran')+' (down)',run(h.down_ok,h.down_ran,h.down_ms,h.down_error,h.down_at)]);
  rows=rows.concat(tail({err:h.down_error,out:h.down_out}));
  kv(document.getElementById('st-hooks'),rows);
}

// 策略路由的内核实际内容：配置值不等于内核里装上的东西
function renderRouteStatus(rt){
  const kvEl=document.getElementById('st-routes');
  if(!rt){kv(kvEl,[[t('ov.no_data'),ntxt()]]);return;}
  const age=rt.age_sec?(' · '+t('ov.age').replace('{n}',rt.age_sec)):'';
  const rules=rt.rules||[],routes=rt.routes||[];
  const rows=[];
  if(rt.error)rows.push([t('ov.hook.err'),'<span class="mono" style="color:var(--err)">'+esc(rt.error)+'</span>']);
  rows.push([t('ov.route.rules')+age,'<span class="mono">'+(rules.length?String(rules.length):'-')+'</span>']);
  rules.slice(0,12).forEach(function(l){rows.push(['',esc(l)]);});
  if(rules.length>12)rows.push(['<span style="color:var(--sub)">'+t('ov.rules_n').replace('{n}',rules.length-12)+'</span>','']);
  rows.push([t('ov.route.routes'),'<span class="mono">'+(routes.length?String(routes.length):'-')+'</span>']);
  routes.slice(0,12).forEach(function(l){rows.push(['',esc(l)]);});
  if(routes.length>12)rows.push(['<span style="color:var(--sub)">'+t('ov.routes_n2').replace('{n}',routes.length-12)+'</span>','']);
  kv(kvEl,rows);
}

// TAP 链路层统计：内核接口计数，与隧道层计数是两个口径
function renderTapStatus(lp){
  if(!lp){kv(document.getElementById('st-tap'),[[t('ov.no_data'),ntxt()]]);return;}
  kv(document.getElementById('st-tap'),[
    [t('ov.link.up'),yn(lp.up)],
    [t('ov.link.mtu'),'<span class="mono">'+(lp.mtu||'-')+'</span>'],
    [t('ov.link.rx'),'<span class="mono">'+fmtBytes(lp.rx_bytes||0)+' / '+fmtNum(lp.rx_pkts||0)+'</span>'],
    [t('ov.link.tx'),'<span class="mono">'+fmtBytes(lp.tx_bytes||0)+' / '+fmtNum(lp.tx_pkts||0)+'</span>'],
    [t('ov.link.errs'),'<span class="mono">'+fmtNum(lp.rx_errs||0)+' / '+fmtNum(lp.tx_errs||0)+'</span>'],
    [t('ov.link.drops'),'<span class="mono">'+fmtNum(lp.rx_drops||0)+' / '+fmtNum(lp.tx_drops||0)+'</span>'],
  ]);
}

// ---------- 概览派生指标与异常提醒条 ----------
// RTT 分布：连接表里只有逐连接的当前值，这里给出全量的均值与 P95
function rttStats(rows){
  const v=rows.map(function(r){return r.rtt;}).filter(function(x){return x>0&&x<100000;});
  if(!v.length)return null;
  v.sort(function(a,b){return a-b;});
  const avg=v.reduce(function(a,b){return a+b;},0)/v.length;
  const i=Math.min(v.length-1,Math.floor(v.length*0.95));
  const out={n:v.length,avg:avg,p95:v[i],max:v[v.length-1],min:v[0]};
  return out;
}

function chip(l,v,cls){
  return '<span class="statchip'+(cls?' '+cls:'')+'"><span class="lbl">'+esc(l)+'</span><b>'+v+'</b></span>';
}

// 连接页的派生指标条：RTT 分布 + 丢帧率 / 平均包大小 / FEC 效率
function renderConnQuality(data,rtt){
  const q=data.quality||{};
  const out=[];
  if(rtt)out.push(chip(t('ov.rtt'),t('ov.rtt_n').replace('{n}',rtt.n)),chip(t('ov.avg'),Math.round(rtt.avg)+' ms'),chip(t('ov.p95'),Math.round(rtt.p95)+' ms'));
  else out.push(chip(t('ov.rtt'),'-'));
  if(q.pkts)out.push(chip(t('ov.avgpkt'),fmtBytes(Math.round(q.avgpkt_size))));
  if(q.pkts&&q.total_drop>=0){
    const d=(q.total_drop/q.pkts*100);
    out.push(chip(t('ov.drop_pct'),d.toFixed(3)+'%',d>1?'bad':(d>0?'warn':'good')));
  }
  if(data.fec&&data.fec.enabled){
    const tot=q.pkts+q.parity;
    if(tot>0&&q.recovered>0)out.push(chip(t('ov.fec_eff'),(q.recovered/tot*100).toFixed(1)+'%',q.lost?'warn':'good'));
  }
  const el=document.getElementById('conn-quality');
  if(el)el.innerHTML=out.join('');
}

// 异常提醒条：把各卡片的坏消息集中到顶。人工关闭后按"组合"记忆，
// 同一组告警不会反复弹回，出现新告警才重新提示。
function renderAlerts(data,items){
  const el=document.getElementById('alertbar');
  if(!el)return;
  if(!items.length){el.style.display='none';return;}
  if(alertOff&&alertSig===items.join('|')){el.style.display='none';return;}
  alertSig=items.join('|');
  el.style.display='';
  el.className='alertbar';
  document.getElementById('alertbar-txt').innerText=items.join('  ·  ');
  document.getElementById('alertbar-cnt').innerText=t('ov.alerts_n').replace('{n}',items.length);
}

function renderOverview(data){
  // 进程 CPU 与核数
  const cpu=document.getElementById('cpu-kpi'),cores=document.getElementById('cores');
  if(data.cpu&&cpu){cpu.innerHTML=data.cpu.percent.toFixed(1)+'<small>%</small>';}
  else if(cpu)cpu.textContent='-';
  if(cores)cores.innerText=(data.system&&data.system.num_cpu)||'-';
  // 填充开销卡：后端总是下发这份快照，off 模式显示 0.0% 而不是"未启用"——
  // 后者会把"填充已正确关闭"说成"没配置"。老服务端没有该字段时才隐藏
  const pad=document.getElementById('pad-card');
  if(pad){
    if(data.pad){
      pad.style.display='';
      document.getElementById('pad-kpi').innerText=(data.pad.overhead_pct||0).toFixed(1)+'%';
      document.getElementById('pad-bytes').innerText=fmtBytes(data.pad.pad_bytes||0);
      document.getElementById('pad-mode').innerText=data.pad.mode||'-';
    }else pad.style.display='none';
  }
  // 会话水位卡：服务端对 max_sessions，客户端对本机并发连接上限
  const sc=document.getElementById('sess-card');
  if(sc){
    const s=data.sessions;
    if(s){
      sc.style.display='';
      document.getElementById('sess-kpi').innerHTML=s.active+'<small> / '+(s.max||0)+'</small>';
      document.getElementById('reconn-kpi').innerText=fmtNum(data.reconnect_attempts||0);
    }else sc.style.display='none';
  }
  // 告警条件：任一触发即在顶部集中提示
  const items=[],s=data.sessions,p=data.pad,pr=data.protect,c=data.cert,ro=data.drop_breakdown||{},h=data.hooks;
  if(c&&c.days_left<=0)items.push(t('ov.err_cert_bad'));
  else if(c&&c.days_left<=7)items.push(t('ov.err_cert_ok').replace('{n}',c.days_left));
  else if(c&&c.days_left<=30)items.push(t('ov.err_cert_ok').replace('{n}',c.days_left));
  if((data.tap_write_errors||0)>0)items.push(t('ov.err_tap').replace('{n}',fmtNum(data.tap_write_errors)));
  if((data.dropped_frames||0)>0){
    const brk=[];
    if(ro.backpressure)brk.push(t('ov.err_bp'));
    if(ro.spoofed_src)brk.push(t('ov.err_spoof'));
    if(ro.broadcast)brk.push(t('ov.err_bcast'));
    if(ro.reorder)brk.push(t('ov.err_reord'));
    items.push(t('ov.err_drop').replace('{n}',fmtNum(data.dropped_frames))+(brk.length?'（'+brk.join('、')+'）':''));
  }
  if(data.fec&&data.fec.lost>0)items.push(t('ov.err_fec').replace('{n}',fmtNum(data.fec.lost)));
  if(pr&&(pr.tls_handshake_fail||0)>0)items.push(t('ov.err_tls').replace('{n}',fmtNum(pr.tls_handshake_fail)));
  if(pr&&(pr.conns_rejected||pr.fec_group_rejected)>0)items.push(t('ov.err_prot').replace('{n}',fmtNum((pr.conns_rejected||0)+(pr.fec_group_rejected||0))));
  if(pr&&(pr.fallback_http||pr.tarpit)>0)items.push(t('ov.err_fb').replace('{n}',fmtNum((pr.fallback_http||0)+(pr.tarpit||0))));
  if(pr&&(pr.psk_fail||[]).length>0)items.push(t('ov.err_psk').replace('{n}',fmtNum(pr.psk_fail.length)));
  if(data.ip_pool&&data.ip_pool.v4_total&&data.ip_pool.v4_used>=data.ip_pool.v4_total)items.push(t('ov.err_pool').replace('{n}',data.ip_pool.v4_used+'/'+data.ip_pool.v4_total));
  if(s&&s.max&&s.active>=s.max)items.push(t('ov.err_nosess'));
  if((data.reconnect_attempts||0)>0)items.push(t('ov.err_reconn').replace('{n}',fmtNum(data.reconnect_attempts)));
  if(data.negotiate&&data.negotiate.policy_routing===false)items.push(t('ov.err_neg'));
  if(p&&p.overhead_pct>40)items.push(t('ov.err_pad').replace('{n}',p.overhead_pct.toFixed(1)+'%'));
  if(data.cpu&&data.cpu.percent>80)items.push(t('ov.err_cpu').replace('{n}',data.cpu.percent.toFixed(0)+'%'));
  if(h&&h.up_ran&&!h.up_ok)items.push(t('ov.err_hookup'));
  if(h&&h.down_ran&&!h.down_ok)items.push(t('ov.err_hookdown'));
  renderAlerts(data,items);
}

// ---------- CSV 导出：只读导出，不发任何 /api/control 请求 ----------
const QUOTE='"';
function csvCell(v){
  const s=v==null?'':String(v);
  // 只读表格文本可能含逗号/换行/双引号，按 RFC4180 加引号并双写
  if(s.indexOf(',')<0&&s.indexOf(QUOTE)<0&&s.indexOf('\n')<0)return s;
  return QUOTE+s.split(QUOTE).join(QUOTE+QUOTE)+QUOTE;
}

function csvDownload(name,rows){
  // BOM 让 Excel 直接识别 UTF-8（中文/日文列名不乱码）
  const blob=new Blob([''+rows.map(r=>r.join(',')).join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function(){URL.revokeObjectURL(a.href);},1000);
  toast(t('ov.export_done'),'ok');
}

// 读当前渲染出来的表格 DOM（已过滤、已排序、当前页），所以导出结果与屏幕所见一致
function tableRows(tableId){
  return Array.prototype.slice.call(document.querySelectorAll('#'+tableId+' tr')).map(function(tr){
    return Array.prototype.slice.call(tr.children).map(function(td){return csvCell(td.innerText.trim());});
  }).filter(function(c){return c.length>1;});
}

function exportCSV(which){
  const st=lastStats;
  if(!st){toast(t('ov.no_table'),'err');return;}
  const ts=new Date().toISOString().replace(/[:]/g,'-');
  const id=which==='conns'?'conns-body':(which==='traffic'?'traffic-body':'clients-body');
  const rows=tableRows(id);
  if(!rows.length){toast(t('ov.no_table'),'err');return;}
  csvDownload('tlsvpn-'+which+'-'+ts+'.csv',rows);
}


function fmtSchedulerEta(us){
  us=Number(us||0);
  if(!us)return '-';
  if(us<1000)return Math.round(us)+' us';
  return (us/1000).toFixed(us<10000?2:1)+' ms';
}
function schedulerCell(s){
  if(!s)return '<span class="dim">-</span>';
  const cls=s.active?'b-on':'b-off';
  const state=s.active?t('sched.active'):t('sched.standby');
  const rate=Number(s.rate_mbps||0);
  const meta=t('sched.queue')+' '+fmtBytes(s.queued_bytes||0)+' · '+
    (rate?rate.toFixed(rate<10?1:0)+' Mbps':'-')+' · ETA '+fmtSchedulerEta(s.eta_us||0)+
    (s.carry_pending?' · '+t('sched.carry'):'')+' · '+t('th.tx')+' '+fmtBytes(s.assigned_bytes||0)+' / '+Number(s.assigned_batches||0);
  return '<div class="sched-cell"><span class="badge '+cls+'">'+esc(state)+'</span><small class="dim">'+esc(meta)+'</small></div>';
}

function renderConnsTable(data,fresh){
  const tb=document.getElementById('conns-body');
  let rows=[];
  if(data.mode==='server'){
    (data.server_conns||[]).forEach(c=>rows.push({key:(c.conn_id||c.client_id+'|'+c.remote),owner:shortId(c.client_id,10),fullId:c.client_id,connid:c.conn_id||'',target:'',remote:c.remote,state:'up',rtt:c.rtt_ms,sched:c.scheduler||{},tx:c.tx_bytes,rx:c.rx_bytes,age:c.age_sec,epoch:c.session_epoch||0,err:'',enc:c.enc_algo,fec:c.fec||'',sni:c.sni||'',tlsVer:c.tls_version||'',tlsCipher:c.tls_cipher||'',tlsAlpn:c.tls_alpn||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_cli_tx_mbps||0,down:c.brutal_srv_tx_mbps||0}));
  }else{
    (data.conns||[]).forEach((c,i)=>rows.push({key:(c.conn_id||i+'|'+(c.target||'')+'|'+(c.remote||'')),owner:'local',fullId:null,connid:c.conn_id||'',target:c.target,remote:c.remote,state:c.state,rtt:c.rtt_ms,sched:c.scheduler||{},tx:c.tx_bytes,rx:c.rx_bytes,retries:c.retries,age:c.age_sec,epoch:c.session_epoch!==undefined?c.session_epoch:(data.session_epoch||0),err:c.last_error||'',enc:c.negotiated===false?null:(c.enc_algo!==undefined?c.enc_algo:data.enc_algo),fec:c.fec!==undefined?c.fec:(data.fec_mode||''),sni:c.sni||'',tlsVer:c.tls_version||'',tlsCipher:c.tls_cipher||'',tlsAlpn:c.tls_alpn||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_tx_mbps||0,down:c.brutal_rx_mbps||0}));
  }
  // 速率差分：fresh=true 仅在拿到新快照时（fetchStats），过滤重渲染沿用缓存
  const now=data.sample_time_ms===undefined?Date.now():Number(data.sample_time_ms);
  const dt=(fresh&&lastConnsT&&now>lastConnsT)?(now-lastConnsT)/1000:0;
  rows.forEach(function(r){
    if(fresh){
      const p=prevConns[r.key];
      r.sx=p&&dt>0?Math.max(0,(r.tx-p.tx)/dt):0;
      r.sr=p&&dt>0?Math.max(0,(r.rx-p.rx)/dt):0;
      prevConns[r.key]={tx:r.tx,rx:r.rx};
    }else{
      const s=lastConnSpeeds[r.key]||{sx:0,sr:0};
      r.sx=s.sx;r.sr=s.sr;
    }
  });
  if(fresh){
    const present=new Set(rows.map(r=>r.key));
    Object.keys(prevConns).forEach(k=>{if(!present.has(k))delete prevConns[k];});
    lastConnsT=now;
    lastConnSpeeds={};
    rows.forEach(function(r){lastConnSpeeds[r.key]={sx:r.sx,sr:r.sr};});
  }
  const f=Q.conns;
  const all=rows.length;
  // 质量指标基于过滤前的全量行：过滤条件不该改变统计口径。
  // 注意这里绝不能调 exportCSV —— 本函数每 2 秒跑一次，导出只能由按钮触发
  renderConnQuality(data,rttStats(rows));
  const ss=document.getElementById('scheduler-summary');
  if(ss){
    const active=rows.filter(function(r){return r.sched&&r.sched.active;}).length;
    const queued=rows.reduce(function(n,r){return n+Number((r.sched&&r.sched.queued_bytes)||0);},0);
    ss.textContent=t('sched.paths').replace('{a}',active).replace('{n}',rows.length)+' · '+t('sched.queue')+' '+fmtBytes(queued);
  }
  rows=sortRows('conns',rows);
  syncSortUI('conns');
  // 服务端模式的"目标"列恒为占位符，整列隐藏；客户端模式有真实目标地址，保持可见
  const wrap=tb.closest('.twrap');
  if(wrap)wrap.classList.toggle('srv-mode',data.mode==='server');
  if(f)rows=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(f));
  const total=rows.length;
  const pv=pageView('conns',rows);
  tb.innerHTML=pv.rows.map(r=>{
    const st=r.state==='up'?'<span class="badge b-on">'+t('st.up')+'</span>':
      r.state==='connecting'?'<span class="badge b-dup">'+t('st.connecting')+'</span>':
      '<span class="badge b-off">'+esc(r.state||'-')+'</span>';
    const rtt=r.rtt>=100000?'-':r.rtt+' ms';
    // Brutal 列同时是"为什么没生效"的入口：速率生效显示双向速率，
    // 配置了但内核/平台不支持显示"未生效"，悬停看具体原因。
    let brutTxt='-',brutCls='b-off',brutTip='brutal off';
    if(r.brutErr){brutTxt=t('st.skip');brutCls='b-dup';brutTip='brutal skipped: '+r.brutErr;}
    else if(r.brut===true){brutTxt=r.up+'↑/'+r.down+'↓';brutCls='b-on';brutTip='brutal shaping '+r.up+' Mbps upstream / '+r.down+' Mbps downstream';}
    const brut='<span class="badge '+brutCls+'">'+brutTxt+'</span>';
    const ops=(data.mode==='server'&&r.fullId)?'<button class="btn danger sm" onclick="kickClient(\''+r.fullId+'\')">'+t('th.kick')+'</button>':'';
    const sniMeta=[r.tlsVer,r.tlsCipher,r.tlsAlpn].filter(Boolean).join(' · ');
    // 没错误时不能留空格：esc(undefined) 转成空串，同行其它占位列都是 '-'，
    // 唯独这里是个看得见的洞。
    const cerr=r.err||r.brutErr;
    const errCell=cerr?'<span style="color:var(--err)" title="'+esc(cerr)+'">'+esc(String(cerr).slice(0,40))+'</span>':'<span style="color:var(--sub)">-</span>';
    return '<tr data-conn-id="'+esc(r.connid||'')+'"><td class="num dim">'+hi(esc(r.owner),f)+'</td><td class="hide-sm num dim" title="'+esc(r.connid||'')+'">'+(r.connid?hi(esc(shortId(r.connid,12)),f):'-')+'</td><td class="num hide-srv">'+hi(esc(r.target||'-'),f)+'</td><td class="num">'+hi(esc(r.remote||'-'),f)+'</td><td title="'+esc(brutTip)+'">'+st+'</td>'+
      '<td class="num">'+rtt+'</td><td class="hide-sm">'+schedulerCell(r.sched)+'</td><td class="num">'+fmtBytes(r.tx)+'</td><td class="num">'+fmtBytes(r.rx)+'</td>'+
      '<td class="hide-sm num speed">'+fmtBytes(r.sx,true)+'</td><td class="hide-sm num speed dn">'+fmtBytes(r.sr,true)+'</td>'+
      '<td class="hide-sm dim" title="'+esc(sniMeta)+'">'+(r.sni?hi(esc(r.sni),f):'<span style="color:var(--sub)">-</span>')+'</td>'+
      '<td class="hide-sm num dim">'+(r.age?fmtDur(r.age):'-')+'</td>'+
      '<td class="hide-sm num dim" title="'+esc(r.epoch?'session key epoch '+r.epoch:'no epoch yet')+'">'+(r.epoch?r.epoch:'-')+'</td>'+
      '<td class="hide-sm">'+encBadge(r.enc)+'</td><td class="hide-sm">'+badge(r.fec)+'</td>'+
      '<td class="hide-sm" title="'+esc(brutTip)+'">'+brut+'</td>'+
      '<td class="hide-sm">'+errCell+'</td><td>'+ops+'</td></tr>';
  }).join('')||emptyTableRow('conns',19,all);
  setCount('conn-count',f,total,all);
  renderPager('conns',total);
}
// ---------- 客户端详情抽屉：点客户端表任意行从右侧展开 ----------
// 身份 / 流量 / 连接 / 安全四块，数据全部取自已有的 /api/stats 快照
// （clients、server_conns、client_traffic）加本地算的速率差，不额外发请求；
// 抽屉开着时每个轮询周期跟着刷新，被踢出或掉线后自动收回。
let drawerId=null;
function drawerOn(){return !!drawerId;}
function openClient(id){
  drawerId=id;
  renderDrawer();
  const m=document.getElementById('drawer-mask');
  const d=document.getElementById('drawer');
  if(m)m.classList.add('on');
  if(d)d.classList.add('on');
}
function closeDrawer(){
  drawerId=null;
  const m=document.getElementById('drawer-mask');
  const d=document.getElementById('drawer');
  if(m)m.classList.remove('on');
  if(d)d.classList.remove('on');
}
// 连接明细来源：服务端按 client_id 过滤 server_conns；客户端模式就是自己的 conns
function drawerConns(data,id){
  if(data.mode==='server')return (data.server_conns||[]).filter(function(c){return c.client_id===id;});
  return (data.conns||[]).slice();
}
function dcSec(title,hint){
  return '<div class="dc-sec-h">'+esc(title)+(hint?' <small>'+esc(hint)+'</small>':'')+'</div>';
}
function dcKV(rows){
  if(!rows.length)return '<div class="dc-empty">'+esc(t('ov.no_data'))+'</div>';
  return '<table class="dc-rows">'+rows.map(function(r){
    return '<tr><th>'+esc(r[0])+'</th><td>'+r[1]+'</td></tr>';
  }).join('')+'</table>';
}
// TCP Brutal 是逐连接各自 setsockopt 的，所以给"生效几条/共几条"而不是单一开关。
// 值里不重复品牌名——所在的行标签本身就是 TCP Brutal，重复一次就是"TCP Brutal / Brutal"
function dcBrut(conns){
  if(!conns.length)return mtxt('-');
  const err=conns.filter(function(c){return !!c.brutal_error;}).length;
  const ok=conns.filter(function(c){return c.brutal_applied===true;}).length;
  if(ok)return '<span class="badge b-on">'+ok+'/'+conns.length+'</span>';
  if(err)return '<span class="badge b-dup" title="'+esc(conns[0].brutal_error||'')+'">'+esc(t('st.skip'))+'</span>';
  return mtxt('-');
}
function renderDrawer(){
  if(!drawerId)return;
  const data=lastStats;
  if(!data)return;
  const id=drawerId;
  const cmap=data.clients||{};
  if(data.mode==='server'&&!Object.prototype.hasOwnProperty.call(cmap,id)){closeDrawer();return;}
  const c=cmap[id]||{};
  const sp=lastSpeeds[id]||{sx:0,sr:0};
  const conns=drawerConns(data,id);
  const enc=c.enc_algo!==undefined?c.enc_algo:data.enc_algo;
  const fec=c.fec||data.fec_mode||'';
  // 连接数：快照里的 active_conns 最准；旧服务端不给时退回连接明细条数，
  // 两者都没有就留空，别把一个在线客户端显示成"0 条连接"
  const nConns=c.active_conns!==undefined?c.active_conns:(conns.length||'-');

  document.getElementById('drawer-head').innerHTML=
    '<h2 id="drawer-title" title="'+esc(id)+'">'+esc(shortId(id,26))+'</h2>'+
    '<button class="btn ghost sm" data-act="copy" title="'+esc(t('dc.copy'))+'">'+esc(t('dc.copy'))+'</button>'+
    '<div class="dc-badges">'+
      '<span class="badge b-on">'+esc(t('dc.tcp'))+' '+nConns+'</span>'+
      badge(fec)+encBadge(enc)+
    '</div>';

  const acts=[];
  if(data.mode==='server'){
    acts.push('<button class="btn danger sm" data-act="kick">'+esc(t('th.kick'))+'</button>');
    acts.push('<button class="btn danger sm" data-act="ban">'+esc(t('th.ban'))+'</button>');
  }
  acts.push('<button class="btn ghost sm" data-act="logs">'+esc(t('dc.view_logs'))+'</button>');
  acts.push('<button class="btn ghost sm" data-act="traffic">'+esc(t('dc.view_traffic'))+'</button>');
  document.getElementById('drawer-acts').innerHTML=acts.join('');

  // 身份
  const ir=[];
  ir.push([t('dc.cid'),mtxt(id)]);
  ir.push([t('dc.v4'),mtxt(c.ipv4||'-')]);
  ir.push([t('dc.v6'),mtxt(c.ipv6||'-')]);
  ir.push([t('dc.mac'),mtxt(c.mac||'-')]);
  if(conns.length){
    const remotes=conns.map(function(x){return x.remote;}).filter(Boolean).join(' · ');
    ir.push([t('dc.remote'),mtxt(remotes||'-')]);
  }
  ir.push([t('dc.tcp'),mtxt(String(nConns))]);
  // 旧服务端不下发客户端级 uptime_sec，留空而不是显示"0秒"（客户端明显在线）
  ir.push([t('dc.uptime'),c.uptime_sec!==undefined?mtxt(fmtDur(c.uptime_sec)):mtxt('-')]);

  // 流量：按日累计 + 会话累计 + 本地轮询算出的当前速率
  const ct=(data.client_traffic||[]).find(function(x){return x.id===id;});
  const daily=ct&&ct.daily?ct.daily:[];
  const d0=daily.length?daily[daily.length-1]:null;
  const sumDays=function(n){return daily.slice(-n).reduce(function(a,b){return a+(b.up||0)+(b.down||0);},0);};
  const cells=[];
  // 该客户端没有按日记录时按日累计一律留空——显示"近 7 天 0 B"会
  // 让人以为它真的没流量（刚注册、或旧服务端不给这个客户端的历史）
  if(ct){
    if(d0)cells.push([t('dc.today'),fmtBytes(d0.up||0)+' · '+fmtBytes(d0.down||0)]);
    cells.push([t('dc.d7'),fmtBytes(sumDays(7))]);
    cells.push([t('dc.d30'),fmtBytes(sumDays(30))]);
  }
  const srvDirection=data.mode==='server';
  cells.push([t('dc.sess_up'),fmtBytes((srvDirection?c.rx_bytes:c.tx_bytes)||0)]);
  cells.push([t('dc.sess_down'),fmtBytes((srvDirection?c.tx_bytes:c.rx_bytes)||0)]);
  cells.push([t('dc.pkt_up'),fmtNum((srvDirection?c.rx_packets:c.tx_packets)||0)]);
  cells.push([t('dc.pkt_dn'),fmtNum((srvDirection?c.tx_packets:c.rx_packets)||0)]);
  cells.push([t('dc.rate_up'),fmtBytes(srvDirection?sp.sr:sp.sx,true)]);
  cells.push([t('dc.rate_dn'),fmtBytes(srvDirection?sp.sx:sp.sr,true)]);

  // 每日明细：最近 10 天，条长按该窗口内最大值归一
  let daysHtml='';
  if(daily.length){
    const days=daily.slice(-10).reverse();
    let mx=0;
    days.forEach(function(d){mx=Math.max(mx,(d.up||0)+(d.down||0));});
    daysHtml='<div class="dc-days">'+days.map(function(d){
      const tot=(d.up||0)+(d.down||0);
      const p=mx>0?Math.max(2,Math.round(tot/mx*100)):0;
      return '<div class="dc-day"><span class="dc-day-d">'+esc(String(d.date).slice(5))+'</span>'+
        '<span class="dc-bar"><i style="width:'+p+'%"></i></span>'+
        '<span class="dc-day-v">'+fmtBytes(tot)+'</span></div>';
    }).join('')+'</div>';
  }

  // 连接
  let connHtml;
  if(conns.length){
    connHtml=conns.map(function(x){
      const rtt=x.rtt_ms||0;
      const xEnc=x.negotiated===false?null:(x.enc_algo!==undefined?x.enc_algo:data.enc_algo);
      const up=x.brutal_cli_tx_mbps||x.brutal_tx_mbps||0;
      const dn=x.brutal_srv_tx_mbps||x.brutal_rx_mbps||0;
      let brut;
      if(x.brutal_applied===true)brut='<span class="badge b-on">'+esc(t('th.brutal'))+' '+up+'↑/'+dn+'↓</span>';
      else if(x.brutal_error)brut='<span class="badge b-dup" title="'+esc(x.brutal_error)+'">'+esc(t('st.skip'))+'</span>';
      else brut='<span class="badge b-off">'+esc(t('th.brutal'))+'</span>';
      const pkts=(x.tx_packets!==undefined||x.rx_packets!==undefined)
        ?'<span class="dc-conn-k">'+esc(t('dc.pkt_up'))+' '+fmtNum(x.tx_packets||0)+' · '+esc(t('dc.pkt_dn'))+' '+fmtNum(x.rx_packets||0)+'</span>'
        :'';
      return '<div class="dc-conn">'+
        '<div class="dc-conn-top">'+
          '<span class="mono" title="'+esc(x.remote||'')+'">'+esc(x.remote||'-')+'</span>'+
          '<span class="dc-conn-rtt">'+(rtt>0&&rtt<100000?(rtt+' ms'):'-')+'</span>'+
          '<span class="dc-conn-rate"><span class="arr-up">↑</span> '+fmtBytes((srvDirection?x.rx_bytes:x.tx_bytes)||0)+
            '<span class="arr-down">↓</span> '+fmtBytes((srvDirection?x.tx_bytes:x.rx_bytes)||0)+'</span>'+
        '</div>'+
        '<div class="dc-conn-meta">'+
          '<span class="dc-conn-k">'+esc(t('th.age'))+' '+(x.age_sec?fmtDur(x.age_sec):'-')+'</span>'+
          '<span class="dc-conn-k">'+esc(t('th.epoch'))+' '+(x.session_epoch!==undefined?x.session_epoch:(data.session_epoch||0))+'</span>'+
          encBadge(xEnc)+badge(x.fec||fec)+brut+pkts+
        '</div>'+
        (x.sni?'<div class="dc-conn-sni">'+esc(t('dc.sec_sni'))+': '+esc(x.sni)+'</div>':'')+
        (x.last_error?'<div class="dc-conn-err">'+esc(x.last_error)+'</div>':'')+
      '</div>';
    }).join('');
  } else {
    connHtml='<div class="dc-empty">'+esc(t('dc.no_conns'))+'</div>';
  }

  // 安全：协商结果是逐连接给的，这里取最近一条为代表，标题上写明口径
  const neg=conns[0]||{};
  const sr=[];
  sr.push([t('dc.sec_enc'),encBadge(neg.enc_algo!==undefined?neg.enc_algo:data.enc_algo)]);
  sr.push([t('dc.sec_sess'),neg.session_encrypt===undefined?mtxt('-'):yn(!!neg.session_encrypt)]);
  sr.push([t('dc.sec_epoch'),mtxt(String(neg.session_epoch||data.session_epoch||0))]);
  sr.push([t('dc.sec_fec'),badge(neg.fec||fec)]);
  if(neg.tls_version||neg.tls_cipher||neg.tls_alpn||neg.sni){
    sr.push([t('dc.sec_tls'),mtxt(neg.tls_version||'-')]);
    sr.push([t('dc.sec_cipher'),mtxt(neg.tls_cipher||'-')]);
    sr.push([t('dc.sec_alpn'),mtxt(neg.tls_alpn||'-')]);
    sr.push([t('dc.sec_sni'),mtxt(neg.sni||'-')]);
  }
  sr.push([t('dc.sec_brut'),dcBrut(conns)]);

  document.getElementById('drawer-body').innerHTML=
    '<div class="dc-sec">'+dcSec(t('dc.identity'))+dcKV(ir)+'</div>'+
    '<div class="dc-sec">'+dcSec(t('dc.traffic'))+
      '<div class="dc-grid">'+cells.map(function(x){
        return '<div class="dc-cell"><span class="dc-cell-l">'+esc(x[0])+'</span><span class="dc-cell-v">'+x[1]+'</span></div>';
      }).join('')+'</div>'+daysHtml+
    '</div>'+
    '<div class="dc-sec">'+dcSec(t('dc.connections'),t('dc.conns_n').replace('{n}',String(conns.length)))+connHtml+'</div>'+
    '<div class="dc-sec">'+dcSec(t('dc.security'),t('dc.sec_hint'))+dcKV(sr)+'</div>';
}
// 交互：客户端表整行可点开；抽屉内动作按钮用 data-act 委托——
// ClientID 里可能出现引号，拼进 onclick 属性有注入风险，集中委托更稳
document.getElementById('clients-body').addEventListener('click',function(ev){
  if(ev.target.closest('button'))return;
  const tr=ev.target.closest('tr[data-open]');
  if(!tr)return;
  openClient(tr.getAttribute('data-open'));
});
// 拓扑图里服务端模式的客户端节点同样可点开抽屉（共用 data-open 约定）
document.getElementById('tpo').addEventListener('click',function(ev){
  const n=ev.target.closest('.tp-node[data-open]');
  if(!n)return;
  openClient(n.getAttribute('data-open'));
});
document.getElementById('drawer').addEventListener('click',function(ev){
  const b=ev.target.closest('button[data-act]');
  if(!b)return;
  const act=b.getAttribute('data-act');
  if(act==='close')closeDrawer();
  else if(act==='kick')kickClient(drawerId);
  else if(act==='ban')banClient(drawerId,0);
  else if(act==='logs')drawerToLogs();
  else if(act==='traffic')drawerToTraffic();
  else if(act==='copy')drawerCopy();
});
document.getElementById('drawer-mask').addEventListener('click',closeDrawer);
document.addEventListener('keydown',function(ev){
  if(ev.key==='Escape'&&drawerId)closeDrawer();
});
// 跳到日志页并预置 ClientID 过滤：日志正文带完整 ID，取前缀即可命中
function drawerToLogs(){
  const id=drawerId;
  closeDrawer();
  showPane('logs');
  logFilter=String(id).slice(0,16);
  const inp=document.getElementById('log-filter');
  if(inp)inp.value=logFilter;
  const clr=document.getElementById('log-filter-clear');
  if(clr)clr.classList.add('show');
  applyLogFilter();
}
// 跳到流量页并选中该客户端；旧服务端不下发 client_traffic 时保留"全部"
function drawerToTraffic(){
  const id=drawerId;
  closeDrawer();
  showPane('traffic');
  const sel=document.getElementById('tr-client');
  if(sel&&Array.prototype.some.call(sel.options,function(o){return o.value===id;})){
    sel.value=id;
    syncSelect(sel);
  }
  renderTrafficView();
}
// 剪贴板：优先 async API，不可用时退到 execCommand（非安全上下文没有 clipboard）
function drawerCopy(){
  if(!drawerId)return;
  const done=function(ok){toast(ok?t('dc.copied'):t('toast.fail'),ok?'ok':'err');};
  const legacy=function(){
    const ta=document.createElement('textarea');
    ta.value=drawerId;
    ta.style.position='fixed';
    ta.style.opacity='0';
    document.body.appendChild(ta);
    ta.select();
    let ok=false;
    try{ok=document.execCommand('copy');}catch(e){}
    ta.remove();
    done(ok);
  };
  const cb=navigator.clipboard;
  if(cb&&cb.writeText)cb.writeText(drawerId).then(function(){done(true);},legacy);
  else legacy();
}

function renderMacsTable(data){
  const tb=document.getElementById('macs-body');
  if(data.mode!=='server'){
    tb.innerHTML=emptyRow('srv',3,t('srv_only'));
    setCount('mac-count','',0,0);renderPager('macs',0);return;
  }
  const all=data.mac_table||[];
  const f=Q.macs;
  const list=all.filter(function(e){return passFilter(e,f);});
  const pv=pageView('macs',list);
  tb.innerHTML=pv.rows.map(function(e){
    return '<tr><td class="num">'+hi(esc(e.mac),f)+'</td><td class="num dim">'+hi(esc(e.port),f)+'</td><td class="num dim">'+e.age_sec+'s</td></tr>';
  }).join('')||emptyTableRow(data.mac_table?'macs':'nodata',3,all.length);
  setCount('mac-count',f,list.length,all.length);
  renderPager('macs',list.length);
}
function renderBansTable(data){
  const tb=document.getElementById('bans-body');
  if(data.mode!=='server'){tb.innerHTML=emptyRow('srv',3,t('srv_only'));renderPager('bans',0);return;}
  const bans=Object.entries(data.banned||{});
  const pv=pageView('bans',bans);
  tb.innerHTML=pv.rows.map(function(p){
    const id=p[0],left=p[1];
    return '<tr><td class="num dim" title="'+esc(id)+'">'+esc(shortId(id,18))+'</td>'+
      '<td>'+(left===0?'<span class="badge b-dup">'+t('perm')+'</span>':'<span class="badge b-on">'+fmtDur(left)+'</span>')+'</td>'+
      '<td><button class="btn ghost sm" onclick="unban(\''+id+'\')">'+t('th.unban')+'</button></td></tr>';
  }).join('')||emptyRow('bans',3,data.banned?t('no_bans'):t('ov.no_data'));
  renderPager('bans',bans.length);
}

// ---------- 流量页：今日汇总 + 每日柱状图 + 日表 ----------
function renderTraffic(data){
  const tr=data.traffic;if(!tr)return;
  lastTraffic=tr;
  lastClientTraffic=data.client_traffic||[];
  document.getElementById('tr-up').innerText=fmtBytes(tr.up||0);
  document.getElementById('tr-down').innerText=fmtBytes(tr.down||0);
  document.getElementById('tr-total').innerText=fmtBytes((tr.up||0)+(tr.down||0));
  syncTrafficClients();
  renderTrafficView();
}
function syncTrafficClients(){
  const sel=document.getElementById('tr-client');if(!sel)return;
  const want=sel.value;
  const ids=(lastClientTraffic||[]).map(function(c){return c.id;}).join(',');
  if(ids!==trClientSig){
    trClientSig=ids;
    let opts='<option value="">'+t('tr.all')+'</option>';
    (lastClientTraffic||[]).forEach(function(ct){opts+='<option value="'+esc(ct.id)+'">'+esc(shortId(ct.id,14))+'</option>';});
    sel.innerHTML=opts;
  }
  sel.value=want;
  syncSelect(sel);
}
function renderTrafficView(){
  if(!lastTraffic)return;
  const sel=document.getElementById('tr-client');
  const id=sel?sel.value:'';
  let daily=lastTraffic.daily||[];
  let prefix='';
  if(id&&lastClientTraffic){
    const ct=lastClientTraffic.find(function(c){return c.id===id;});
    if(ct){daily=ct.daily;prefix=shortId(id,14)+' · ';}
  }
  document.getElementById('tr-caption').innerText=prefix+t('tr.caption').replace('{n}',lastTraffic.days);
  drawTrafficChart(daily);
  const tb=document.getElementById('traffic-body');
  let days=(daily||[]).slice();
  days=sortRows('traffic',days);
  syncSortUI('traffic');
  if(!sortState.traffic)days.reverse();
  const pv=pageView('traffic',days);
  tb.innerHTML=pv.rows.map(function(d){
    return '<tr><td class="num dim">'+esc(d.date)+'</td><td class="num speed">'+fmtBytes(d.up)+'</td>'+
      '<td class="num speed dn">'+fmtBytes(d.down)+'</td><td class="num">'+fmtBytes(d.up+d.down)+'</td></tr>';
  }).join('')||emptyRow('traffic',4,t('tr.empty'));
  renderPager('traffic',days.length);
}
function drawTrafficChart(daily){
  const days=(daily||[]).slice(-60); // 点数上限：日期标签保持可读
  const pts=days.map((d,i)=>({x:days.length>1?i/(days.length-1):0,up:d.up,down:d.down,label:d.date.slice(5)}));
  let max=1;
  pts.forEach(p=>{if(p.up>max)max=p.up;if(p.down>max)max=p.down;});
  const old=chartState['traffic-chart'];
  const hover=(old&&old.hover>=0&&old.hover<pts.length)?old.hover:-1;
  renderLineChart('traffic-chart',pts,{max:max,perSec:false,hover:hover});
}

async function kickClient(id){
  if(!(await uiConfirm(t('confirm_kick'))))return;
  await control({action:'kick',client_id:id},t('toast.kick'));fetchStats();
}
async function banClient(id,minutes){
  if(!(await uiConfirm(t('confirm_ban'))))return;
  await control({action:'ban',client_id:id,ttl_minutes:minutes},t('toast.ban'));fetchStats();
}
async function addBan(){
  const id=document.getElementById('ban-id').value.trim();
  if(!id){toast(t('toast.need_id'),'err');return;}
  const m=parseInt(document.getElementById('ban-min').value,10);
  await control({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m},t('toast.ban'));
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();
}
async function unban(id){
  await control({action:'unban',client_id:id},t('toast.unban'));fetchStats();
}
// gc / reconnect 不改变连接表，只在成功时刷一次内存读数
async function doAction(action){
  const msg=action==='gc'?t('toast.gc'):t('toast.reconnect');
  if(await control({action:action},msg))fetchStats();
}
async function setLogLevel(v){
  await control({action:'loglevel',level:v},t('toast.loglevel'));
}

// ---------- 设置页：配置查看/保存/热应用 ----------
async function loadConfig(){
  const st=document.getElementById('cfg-status');
  try{
    const res=await fetch(url('/api/config'),AUTH_HDR);
    if(!res.ok){st.textContent=t('set.loaded_err')+' HTTP '+res.status;return;}
    document.getElementById('cfg-editor').value=await res.text();
    st.textContent='';
  }catch(e){st.textContent=t('set.loaded_err')+' '+e;}
}
async function saveConfig(apply){
  const st=document.getElementById('cfg-status');
  let cfg;
  try{cfg=JSON.parse(document.getElementById('cfg-editor').value);}
  catch(e){st.textContent='JSON: '+e.message;toast(t('toast.fail')+' JSON','err');return;}
  try{
    const res=await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:apply?'save_apply':'save',config:cfg})});
    const data=await res.json().catch(()=>({}));
    if(!res.ok){st.textContent=(data.error||('HTTP '+res.status));toast(t('toast.fail')+' '+st.textContent.slice(0,120),'err');return;}
    if(apply){
      st.textContent=t('set.applied')+(data.needs_restart&&data.needs_restart.length?(' · '+t('set.restart_nr')+' '+data.needs_restart.join(', ')):'');
      toast(t('toast.applied'),'ok');
      setTimeout(function(){if(window.tlsvpnStreamRestart)window.tlsvpnStreamRestart();},500);
    }else{
      st.textContent=t('set.saved');
      toast(t('toast.saved'),'ok');
    }
  }catch(e){st.textContent=String(e);toast(String(e),'err');}
}

// ---------- 事件流：SSE 长连接优先，连不上两次自动回退轮询 ----------
// 事件本体在后端内存环形缓冲（events.go）：/api/events 默认推 SSE，?stream=0 给增量 JSON。
// 浏览器 EventSource 带不了 Authorization 头，-web-auth 生效时直接走轮询；
// seq 由服务端单调编号，SSE 重连回放与轮询续传都不会重也不会丢。
let evItems=[],evSeq=0,evLvl='all',evMode='reconn';
const EV_MAX=300;
// 类型 → 图标路径。这里必须是对象而不是数组：词法守卫按「前一个有效字符」判断花括号
// 是不是对象字面量（只认 ( = , : ? ! & | + - * 与 return/yield），数组里的 {…} 会被当成
// 块作用域，属性冒号就被误读成三元冒号，整段脚本直接失效。
const EVICO={
  connect:'<path d="M12 3v10"/><path d="m7 9 5 5 5-5"/><path d="M5 19h14"/>',
  off:'<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6"/><path d="m15 9-6 6"/>',
  kick:'<path d="M13 2 4 14h6l-1 8 9-12h-6z"/>',
  ban:'<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>',
  unban:'<circle cx="12" cy="12" r="9"/><path d="m5.6 18.4 12.8-12.8"/>',
  deny:'<rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  limit:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5"/><path d="m12 12 3.5 2"/>',
  up:'<path d="M12 19V5"/><path d="m6 11 6-6 6 6"/>',
  down:'<path d="M12 5v14"/><path d="m6 13 6 6 6-6"/>',
  reconnect:'<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>',
  config:'<circle cx="12" cy="12" r="3"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2"/>',
  loglevel:'<path d="M4 6h16"/><path d="M4 12h10"/><path d="M4 18h7"/>',
  gc:'<path d="M3 12h4l2-6 4 12 2-6h6"/>',
  unknown:'<circle cx="12" cy="12" r="9"/><path d="M12 8v4"/><path d="M12 16h.01"/>'
};
// 类型文案走 i18n；服务端以后加新类型时回落到通用词，而不是在页面上露出 key 名
function evTypeLabel(type){
  const p='ev.t_'+type;
  const v=t(p);
  return v===p?t('ev.t_unknown'):v;
}
function evPaneOn(){
  const p=document.getElementById('pane-events');
  return !!p&&p.classList.contains('on');
}
function evRow(e,fresh){
  const lv=e.level==='warn'?'warn':(e.level==='error'?'error':'info');
  const ic=EVICO[e.type]||EVICO.unknown;
  const cid=e.client
    ?'<span class="ev-cl" data-cid="'+esc(e.client)+'" title="'+esc(e.client)+'">'+esc(shortId(e.client,14))+'</span>'
    :'';
  return '<div class="ev-row lv-'+lv+(fresh?' new':'')+'">'+
    '<span class="ev-ico"><svg viewBox="0 0 24 24">'+ic+'</svg></span>'+
    '<span class="ev-type">'+esc(evTypeLabel(e.type))+'</span>'+
    '<span class="ev-msg">'+cid+esc(e.msg||'')+'</span>'+
    '<span class="ev-ts mono">'+esc(e.time||'')+'</span>'+
    '</div>';
}
function evRender(fresh){
  const box=document.getElementById('evbox');
  if(!box)return;
  const f=evLvl==='all'?'':evLvl;
  const list=evItems.filter(function(x){return !f||x.level===f;});
  if(!list.length){
    box.innerHTML='<div class="empty-box"><svg viewBox="0 0 24 24">'+EVICO.unknown+'</svg>'+
      '<div>'+esc(t('ev.empty'))+'</div></div>';
  }else{
    box.innerHTML=list.map(function(x){return evRow(x,fresh&&x.seq===evSeq);}).join('');
  }
  const c=document.getElementById('ev-count');
  if(c)c.textContent=f?(list.length+' / '+evItems.length):String(evItems.length);
}
function evLive(){
  const box=document.getElementById('ev-live');
  if(!box)return;
  let cls='';
  let txt=t('ev.reconn');
  if(evMode==='sse'){cls='ok';txt=t('ev.live');}
  else{cls='warn';txt=t('ev.reconn');}
  box.className='ev-live'+(cls?' '+cls:'');
  const tx=document.getElementById('ev-live-t');
  if(tx)tx.textContent=txt;
}
// 新事件入缓冲；seq 不前进就丢弃（SSE 重连回放会重发同一条）
function evPush(e){
  if(!e||!e.seq||e.seq<=evSeq)return;
  evSeq=e.seq;
  evItems.unshift(e);
  if(evItems.length>EV_MAX)evItems.length=EV_MAX;
  // 面板不在前台时只攒着，切过去再画，省掉隐藏容器上的重排
  if(evPaneOn())evRender(true);
}
function evStreamState(mode){
  evMode=mode||'reconn';
  evLive();
}
function applyEvents(list){
  if(!Array.isArray(list))return;
  list.forEach(evPush);
}
function setEvLvl(v){
  evLvl=v;
  document.querySelectorAll('#ev-seg button').forEach(function(b){
    b.classList.toggle('on',b.dataset.evlvl===v);
  });
  evRender(false);
}
function clearEvents(){
  // 只清本地显示，不回退 evSeq：退回去会把缓冲里的历史又灌回一遍
  evItems=[];
  evRender(false);
  toast(t('ev.cleared'),'ok');
}

// ---------- 安全中心：把散在各页的安全开关与计数器聚合成一份态势清单 ----------
// 与诊断中心同源（最近一次 /api/stats 快照），取向不同：诊断问"有没有东西坏了"，
// 安全问"每一项防护现在是不是开着、有没有被试探过"。不新增端点、不发额外请求。
// lv: ok / warn / fail / skip；skip = 老服务端没下发这份字段或该模式没有，
// 不计分也不报忧，免得缺数据的一片红把真正的问题淹掉。
// 图标按分类名索引，必须是对象不是数组（同 DG_CATS 的词法守卫约束）。
const SC_CATS={
  auth:'<path d="M12 3 4 6v6c0 5 3.5 7.5 8 9 4.5-1.5 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  enc:'<rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><path d="M12 15v2"/>',
  tls:'<path d="M4 8l8-5 8 5v5c0 5-3.5 7.5-8 8-4.5-.5-8-3-8-8z"/><path d="M4 8v5"/>',
  acl:'<rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1.6"/>',
  detect:'<circle cx="12" cy="12" r="9"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
  mgmt:'<circle cx="12" cy="12" r="3.4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5 5l1.4 1.4M17.6 17.6 19 19M19 5l-1.4 1.4M6.4 17.6 5 19"/>'
};
// 布尔开关一律按三态写（true / false / 字段缺位），缺位判 skip 不判 false——
// 老服务端不下发时判成"未启用"等于把缺失当成漏洞。ch 是本块的键名后缀；
// 借用诊断/概览页已有文案时直接写完整点路径（如 dg.sess），渲染时按是否含点区分。
function scRun(data){
  const out={};
  const add=function(cat,ch,lv,det){
    if(!out[cat])out[cat]=[];
    out[cat].push({ch:ch,lv:lv,det:det||''});
  };
  const N=function(v){return fmtNum(v||0);};
  const miss=t('sc.not_set');
  const cfg=data.cfg||{},np=data.negotiate||{},tl=np.tls||{},
        ro=data.drop_breakdown||{},pf=data.protect,ci=data.cert,
        ip=data.ip_pool,se=data.sessions,sm=data.system||{},ho=data.hooks,
        cr=data.mode==='server'?(data.server_conns||[]):(data.conns||[]);
  // ---- 认证 ----
  if(cfg.encrypt_psk===true)add('auth','a_psk','ok',t('stt.yes'));
  else if(cfg.encrypt_psk===false)add('auth','a_psk','warn',t('stt.no'));
  else add('auth','a_psk','skip',miss);
  if(np.session_token===true)add('auth','a_token','ok',t('stt.yes'));
  else if(np.session_token===undefined)add('auth','a_token','skip',miss);
  else add('auth','a_token','warn',t('stt.no'));
  // 服务端看逐连接代际是否漂移，客户端看会话级代际
  const eps={};
  cr.forEach(function(x){const e=x.session_epoch||0;eps[e]=(eps[e]||0)+1;});
  const nEp=Object.keys(eps).length;
  if(data.mode==='server'){
    if(!cr.length)add('auth','a_epoch','skip',miss);
    else if(nEp<=1)add('auth','a_epoch','ok','v'+cr[0].session_epoch);
    else add('auth','a_epoch','warn',t('sc.kinds').replace('{n}',String(nEp)));
  }else if(np.session_epoch>0)add('auth','a_epoch','ok','v'+np.session_epoch);
  else add('auth','a_epoch','skip',miss);
  if(cfg.max_sessions>0)add('auth','a_maxsess','ok',N(cfg.max_sessions));
  else add('auth','a_maxsess','warn',t('sc.unlimited'));
  if(cfg.insecure===true)add('auth','a_noverify','fail',t('sc.skipped'));
  else if(cfg.insecure===false)add('auth','a_noverify','ok',t('stt.yes'));
  else add('auth','a_noverify','skip',miss);
  // ---- 加密 ----
  if(cfg.encrypt===true)add('enc','e_on','ok',t('stt.yes'));
  else if(cfg.encrypt===false)add('enc','e_on','fail',t('stt.no'));
  else add('enc','e_on','skip',miss);
  if(cfg.enc_algo)add('enc','e_algo','ok',esc(cfg.enc_algo)+(cfg.min_enc?' · '+esc(cfg.min_enc):''));
  else add('enc','e_algo','skip',miss);
  if(np.enc_algo===0&&cfg.encrypt===true)add('enc','e_algo_off','warn',t('sc.plaintext'));
  else if(np.enc_algo>0&&cfg.encrypt===true&&np.enc_algo!==cfg.enc_algo)
    add('enc','e_algo_off','warn',cfg.enc_algo+' → '+np.enc_algo);
  else if(np.enc_algo>0)add('enc','e_algo_off','ok','v'+np.enc_algo);
  else add('enc','e_algo_off','skip',miss);
  if(cfg.session_encrypt===true)add('enc','e_session','ok',t('stt.yes'));
  else if(cfg.session_encrypt===false)add('enc','e_session','warn',t('stt.no'));
  else add('enc','e_session','skip',miss);
  if(np.fec===true)add('enc','e_fec','ok',(np.fec_group?'K='+np.fec_group:t('stats.fec_mixed'))+(np.pad_mode?' · '+esc(np.pad_mode):''));
  else if(np.fec===false)add('enc','e_fec','warn',t('badge.off'));
  else add('enc','e_fec','skip',miss);
  if(np.pad_mode&&np.pad_mode!=='off')add('enc','e_pad','ok',esc(np.pad_mode));
  else if(cfg.pad_mode==='off')add('enc','e_pad','warn',esc(cfg.pad_mode));
  else if(np.pad_mode)add('enc','e_pad','warn',esc(np.pad_mode));
  else add('enc','e_pad','skip',miss);
  // ---- TLS ----
  if(!tl.version&&!ci)add('tls','t_ver','skip',miss);
  else{
    const v=tl.version||'';
    add('tls','t_ver',/^1\.3/.test(v)?'ok':'warn',v?esc(v):miss);
  }
  if(!tl.cipher_suite&&!ci)add('tls','t_suite','skip',miss);
  else add('tls','t_suite',tl.cipher_suite?'ok':'warn',tl.cipher_suite?esc(tl.cipher_suite):miss);
  if(ci&&ci.days_left!==undefined){
    const d=ci.days_left;
    // 负值即已过期，颜色已在行级标出，文案不必再解释
    add('tls','t_exp',d<0?'fail':(d<30?'warn':'ok'),
        '<span class="mono">'+d+' '+esc(t('sc.days'))+'</span>'+(ci.not_after?' · '+esc(ci.not_after):''));
  }else add('tls','t_exp','skip',miss);
  if(ci){
    if(ci.self_signed)add('tls','t_self','warn',t('sc.self_signed'));
    else if(cfg.cert_sha256)add('tls','t_self','ok',esc(cfg.cert_sha256.slice(0,16)));
    else add('tls','t_self','ok',t('stt.no'));
  }else add('tls','t_self','skip',miss);
  const sni=tl.sni||cfg.sni||'';
  if(sni)add('tls','t_sni','ok',esc(sni));
  else add('tls','t_sni','warn',t('sc.none'));
  // ---- 访问控制 ----
  const nBan=Object.keys(data.banned||{}).length;
  add('acl','c_ban',nBan?'warn':'ok',N(nBan));
  if(se&&se.max>0){
    const sv=se.active/se.max;
    add('acl','dg.sess',sv>=1?'fail':(sv>=0.8?'warn':'ok'),se.active+'<span class="dim"> / '+se.max+'</span>');
  }else add('acl','dg.sess','skip',miss);
  if(ip&&ip.v4_total){
    const p=ip.v4_used/ip.v4_total;
    add('acl','dg.pool',p>=1?'fail':(p>=0.8?'warn':'ok'),ip.v4_used+'<span class="dim"> / '+ip.v4_total+'</span>');
  }else add('acl','dg.pool','skip',miss);
  if(pf){
    const v=pf.conns_rejected||0;
    add('acl','ov.prot.conns',v>0?'warn':'ok',N(v));
  }else add('acl','ov.prot.conns','skip',miss);
  if(cfg.conns>0)add('acl','c_conns','ok',N(cfg.conns));
  else add('acl','c_conns','warn',t('sc.unlimited'));
  // ---- 检测：这些计数器只有非零才有意义，非零即说明有人试探过 ----
  add('detect','ov.err_spoof',(ro.spoofed_src||0)>0?'warn':'ok',N(ro.spoofed_src||0));
  add('detect','ov.err_bcast',(ro.broadcast||0)>0?'warn':'ok',N(ro.broadcast||0));
  if(pf){
    const tv=pf.tls_handshake_fail||0;
    add('detect','ov.prot.tls',tv>0?'warn':'ok',N(tv));
    const tp=pf.tarpit||0;
    add('detect','ov.prot.tarpit',tp>0?'warn':'ok',N(tp));
    const fr=pf.fec_group_rejected||0;
    add('detect','ov.prot.fec',fr>0?'warn':'ok',N(fr));
    const ps=(pf.psk_fail||[]).reduce(function(s,x){return s+(x.count||0);},0);
    add('detect','ov.prot.psk',ps>0?'warn':'ok',N(ps));
  }else{
    add('detect','ov.prot.tls','skip',miss);
    add('detect','ov.prot.tarpit','skip',miss);
    add('detect','ov.prot.fec','skip',miss);
    add('detect','ov.prot.psk','skip',miss);
  }
  // ---- 管理面 ----
  if(cfg.web_auth===true)add('mgmt','m_auth','ok',t('stt.yes'));
  else if(cfg.web_auth===false)add('mgmt','m_auth','warn',t('stt.no'));
  else add('mgmt','m_auth','skip',miss);
  if(cfg.web_https===true)add('mgmt','m_https','ok',t('stt.yes'));
  else if(cfg.web_https===false)add('mgmt','m_https','warn',t('stt.no'));
  else add('mgmt','m_https','skip',miss);
  if(cfg.web_bind){
    const b=cfg.web_bind;
    // 监听所有接口（0.0.0.0 / :: / :端口）时面板暴露面最大。
    // 不用正则：词法守卫的简易词法器不认正则里的字符类方括号
    const allIf=b.indexOf('0.0.0.0')>=0||b.indexOf('::')===0||b.charAt(0)===':';
    add('mgmt','m_bind',allIf?'warn':'ok',esc(b));
  }else add('mgmt','m_bind','skip',miss);
  const nr=sm.needs_restart||[];
  add('mgmt','m_restart',nr.length?'warn':'ok',nr.length?N(nr.length)+' 项':t('stt.no'));
  if(ho&&ho.up_error)add('mgmt','ov.hook.fail','warn',esc(ho.up_error.slice(0,40)));
  else add('mgmt','ov.hook.fail','skip',miss);
  add('mgmt','dg.loglvl',(data.log_level||'')==='debug'?'warn':'ok',esc(data.log_level||''));
  // 配了 Brutal 但内核不支持模块时它必然没生效，面板上要能看出来
  const bi=np.brutal||{};
  if(bi.enabled===true&&bi.kernel_supported===false)add('mgmt','sc.brutfail','warn',t('sc.brutfail'));
  else add('mgmt','sc.brutfail','skip',miss);
  return out;
}
function renderSec(data){
  if(!data)return;
  const grp=scRun(data);
  const keys=Object.keys(grp);
  const cnt={ok:0,warn:0,fail:0,skip:0};
  keys.forEach(function(k){grp[k].forEach(function(x){cnt[x.lv]++;});});
  const scored=cnt.ok+cnt.warn+cnt.fail;
  const score=scored?Math.round((cnt.ok+cnt.warn/2)/scored*100):100;
  // 环半径 50 → 周长 314.16，与诊断中心同一画法
  const C=2*Math.PI*50;
  const fg=document.getElementById('sc-ring-fg');
  if(fg){
    fg.setAttribute('stroke-dasharray',C.toFixed(2));
    fg.setAttribute('stroke-dashoffset',(C*(1-score/100)).toFixed(2));
    let col='var(--up)';
    if(score<60)col='var(--err)';
    else if(score<90)col='var(--warn)';
    fg.style.stroke=col;
  }
  const sn=document.getElementById('sc-score-n');
  if(sn)sn.innerText=score;
  const chips=document.getElementById('sc-chips');
  if(chips){
    chips.innerHTML=['ok','warn','fail','skip'].map(function(lv){
      const nm='sc.lv'+lv.charAt(0).toUpperCase()+lv.slice(1);
      return '<span class="dg-chip c-'+lv+(cnt[lv]?'':' zero')+'"><i></i>'+esc(t(nm))+
        '<span class="n">'+cnt[lv]+'</span></span>';
    }).join('');
  }
  const vd=document.getElementById('sc-verdict');
  if(vd){
    if(cnt.fail===0&&cnt.warn===0){
      vd.className='dg-verdict';
      vd.innerText=t('sc.all_ok');
    }else{
      vd.className='dg-verdict '+(cnt.fail>0?'v-fail':'v-warn');
      vd.innerText=t('sc.open').replace('{n}',String(cnt.fail+cnt.warn));
    }
  }
  const tot=document.getElementById('sc-total');
  if(tot)tot.innerText=t('sc.total').replace('{n}',String(scored));
  const up=document.getElementById('sc-updated');
  if(up){
    const ago=lastStatsT>0?Math.max(0,Math.round((Date.now()-lastStatsT)/1000)):0;
    up.innerText=t('dg.updated').replace('{t}',fmtDur(ago));
  }
  const lbl=function(ch){return t(ch.indexOf('.')>=0?ch:'sc.'+ch);};
  const grid=document.getElementById('sc-grid');
  if(grid){
    // 整个分类都取不到数据就不占位；单项缺数据保留，好说明这项为什么没判定
    grid.innerHTML=keys.filter(function(k){
      return grp[k].some(function(x){return x.lv!=='skip';});
    }).map(function(k){
      const cs=grp[k];
      const nBad=cs.filter(function(x){return x.lv==='warn'||x.lv==='fail';}).length;
      const nSkip=cs.filter(function(x){return x.lv==='skip';}).length;
      const nOk=cs.length-nBad-nSkip;
      const ic=SC_CATS[k]||'';
      return '<div class="dg-cat"><div class="dg-cat-h">'+
        '<span class="dg-cat-ico"><svg viewBox="0 0 24 24">'+ic+'</svg></span>'+
        '<h4>'+esc(t('sc.c_'+k))+'</h4>'+
        '<span class="dg-cat-n">'+nOk+'/'+(nOk+nBad)+'</span>'+
        '</div><div class="dg-checks">'+
        cs.map(function(x){
          return '<div class="dg-chk l-'+x.lv+'">'+
            '<span class="dg-dot"></span>'+
            '<span class="dg-chk-t">'+esc(lbl(x.ch))+'</span>'+
            '<span class="dg-chk-d mono">'+x.det+'</span>'+
          '</div>';
        }).join('')+'</div></div>';
    }).join('');
  }
}

// ---------- 拓扑：同一份快照画成「端点 → 核心 → 出口」的关系图 ----------
// 服务端是「客户端 → 虚拟交换机 → TAP/内核路由」，客户端是「本机 → 多后端 → 对端」。
// 节点上的安全标记逐端点显示，客户端节点可点开详情抽屉。缺位不占位。
function tpIcon(ic){
  return '<span class="tp-ico"><svg viewBox="0 0 24 24">'+(typeof ic==='string'?ic:tpIcon.SVG[ic]||'')+'</svg></span>';
}
tpIcon.SVG={
  srv:'<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
  cli:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M11 18h2"/>',
  tap:'<path d="M12 2v6"/><circle cx="12" cy="11" r="7"/><path d="M12 11v4"/>',
  net:'<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5 6.5 17M12 11.5 17.5 17"/>'
};
// openId 非空时整卡可点：走 #tpo 的点击委托调 openClient（同客户端表的 data-open
// 机制），不把 ClientID 拼进 onclick 属性，避免 ID 里出现引号。
function tpNode(cls,title,rows,openId,ico){
  return '<div class="tp-node'+(cls?' '+cls:'')+'"'+
    (openId?' data-open="'+esc(openId)+'" title="'+esc(openId)+'"':'')+
    '><div class="tp-node-h">'+
    (ico?'<span class="tp-node-ico"><svg viewBox="0 0 24 24">'+ico+'</svg></span>':'')+
    '<span class="tp-node-t">'+esc(title)+'</span></div><div class="tp-node-b">'+
    rows.map(function(r){
      return '<div class="tp-kv"><span>'+esc(r[0])+'</span><span class="tp-v">'+r[1]+'</span></div>';
    }).join('')+'</div></div>';
}
function tpColumn(title,inner,cls){
  return '<div class="tp-col'+(cls?' '+cls:'')+'"><div class="tp-col-t">'+esc(title)+'</div><div class="tp-nodes">'+inner+'</div></div>';
}
function tpFlow(left,mid,right){
  return '<div class="tp-flow">'+left+
    '<div class="tp-arrow"><span>&#8594;</span></div>'+
    mid+'<div class="tp-arrow"><span>&#8594;</span></div>'+right+'</div>';
}
// 出口列只出现在服务端模式：虚拟交换机之后是 TAP 网卡与内核路由。
// 本地变量不能叫 t（会把翻译函数顶掉）
function tpEgressNodes(data){
  const nodes=[];
  const tlk=data.tap_link;
  if(tlk){
    const rs=[];
    rs.push([t('tp.up'),tlk.up?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>']);
    rs.push([t('tp.mtu'),'<span class="mono">'+(tlk.mtu||'-')+'</span>']);
    const err=(tlk.rx_errs||0)+(tlk.tx_errs||0),dp=(tlk.rx_drops||0)+(tlk.tx_drops||0);
    rs.push([t('tp.err'),'<span class="mono'+(err?' neg':'')+'">'+fmtNum(err)+'</span>']);
    rs.push([t('tp.drop'),'<span class="mono'+(dp?' neg':'')+'">'+fmtNum(dp)+'</span>']);
    nodes.push(tpNode(tlk.up?'':' tp-bad',t('tp.tap'),rs,0,tpIcon.SVG.tap));
  }
  const rt=data.routes;
  if(rt){
    const rs=[];
    const n=(rt.rules||[]).length+(rt.routes||[]).length;
    rs.push([t('tp.rules'),'<span class="mono">'+fmtNum(n)+'</span>']);
    rs.push([t('tp.age'),'<span class="mono">'+fmtDur(Math.abs(rt.age_sec||0))+'</span>']);
    rs.push([t('tp.err'),rt.error?'<span class="neg">'+esc(rt.error)+'</span>':'<span class="mono">0</span>']);
    nodes.push(tpNode(rt.error?' tp-bad':'',t('tp.routes'),rs));
  }
  // 老服务端没有 tap_link / routes 明细块时，顶格的丢帧计数仍能代表"出口这一层"；
  // 再取不到也放个占位卡，避免出口列空着、箭头指向空白。
  if(!nodes.length&&data.tap_write_errors!==undefined){
    const er=data.tap_write_errors||0,dp=data.dropped_frames||0;
    const rs=[];
    rs.push([t('tp.err'),'<span class="mono'+(er?' neg':'')+'">'+fmtNum(er)+'</span>']);
    rs.push([t('tp.drop'),'<span class="mono'+(dp?' neg':'')+'">'+fmtNum(dp)+'</span>']);
    nodes.push(tpNode(er||dp?' tp-bad':'',t('dg.c_tunnel'),rs,0,tpIcon.SVG.tap));
  }
  if(!nodes.length)nodes.push(tpNode('tp-empty',t('dg.not_set'),[]));
  return nodes;
}
function tpCoreNodes(data){
  const np=data.negotiate||{},cfg=data.cfg||{},tl=np.tls||{},ci=data.cert;
  const nodes=[];
  if(data.mode==='server'){
    const ro=data.drop_breakdown||{},pf=data.protect,
          ip=data.ip_pool,se=data.sessions,sm=data.system||{},
          ho=data.hooks,ma=data.mac_table||[],
          bns=Object.keys(data.banned||{}).length;
    const rs=[];
    const cr=data.server_conns||[];
    rs.push([t('tp.conns'),'<span class="mono">'+fmtNum(cr.length)+'</span>']);
    rs.push([t('tp.clients'),'<span class="mono">'+fmtNum(data.active_clients)+'</span>']);
    if(se&&se.max)rs.push([t('tp.sess'),'<span class="mono">'+se.active+'/'+se.max+'</span>']);
    if(ip&&ip.v4_total)rs.push([t('tp.pool'),'<span class="mono">'+ip.v4_used+'/'+ip.v4_total+'</span>']);
    if(data.mem)rs.push([t('tp.mem'),'<span class="mono">'+data.mem.heap_alloc_mb.toFixed(1)+' MB</span>']);
    const sp=ro.spoofed_src||0;
    rs.push([t('tp.spoof'),'<span class="mono'+(sp?' neg':'')+'">'+fmtNum(sp)+'</span>']);
    if(pf)rs.push([t('tp.reject'),'<span class="mono'+((pf.conns_rejected||0)?' neg':'')+'">'+fmtNum(pf.conns_rejected||0)+'</span>']);
    if(bns)rs.push([t('tp.ban'),'<span class="mono neg">'+fmtNum(bns)+'</span>']);
    rs.push([t('tp.mac'),'<span class="mono">'+fmtNum(ma.length)+'</span>']);
    if(data.reconnect_attempts)rs.push([t('tp.reconn'),'<span class="mono">'+fmtNum(data.reconnect_attempts)+'</span>']);
    if(np.brutal){
      const ab=(np.brutal.applied_conns||0)+'/'+(np.brutal.total_conns||0);
      rs.push([t('tp.brutal'),'<span class="mono">'+esc(ab)+'</span>']);
    }
    nodes.push(tpNode(cr.length?'':' tp-empty',t('tp.vswitch'),rs,'',tpIcon.SVG.net));
  }else{
    const lc=data.clients&&data.clients.local;
    const sm=data.system||{},cfg2=data.cfg||{};
    const rs=[];
    if(lc&&lc.ipv4)rs.push([t('tp.v4'),'<span class="mono">'+esc(lc.ipv4)+'</span>']);
    if(lc&&lc.ipv6)rs.push([t('tp.v6'),'<span class="mono">'+esc(lc.ipv6)+'</span>']);
    if(cfg2.mac)rs.push([t('tp.mac2'),'<span class="mono">'+esc(cfg2.mac)+'</span>']);
    if(sm.mem)rs.push([t('tp.mem'),'<span class="mono">'+sm.mem.total_mb+'</span>']);
    if(np.policy_routing!==undefined)
      rs.push([t('tp.polroute'),np.policy_routing?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>']);
    rs.push([t('tp.sess'),'<span class="mono">'+(data.session_epoch||np.session_epoch||0)+'</span>']);
    rs.push([t('tp.byt'),'<span class="mono">'+fmtBytes(data.global_tx_bytes||0)+' / '+fmtBytes(data.global_rx_bytes||0)+'</span>']);
    nodes.push(tpNode('',t('tp.local'),rs));
  }
  return nodes;
}
function tpPeerNodes(data){
  const cfg=data.cfg||{},np=data.negotiate||{},tl=np.tls||{},ci=data.cert,peer=data.peer||{};
  const rs=[];
  if(peer.hostname)rs.push([t('tp.host'),'<span class="mono">'+esc(peer.hostname)+'</span>']);
  if(peer.implementation||peer.version)rs.push([t('kpi.version'),'<span class="mono">'+esc([peer.implementation,peer.version].filter(Boolean).join(' '))+'</span>']);
  if(peer.os||peer.os_version||peer.arch)rs.push([t('stt.sys.os'),platformSummary(peer.os,peer.os_version,peer.arch)]);
  rs.push([t('tp.addr'),'<span class="mono">'+esc(cfg.addr||'-')+'</span>']);
  rs.push([t('tp.sni'),tl.sni?'<span class="mono">'+esc(tl.sni)+'</span>':'<span class="dim">'+t('sc.none')+'</span>']);
  if(tl.version)rs.push([t('tp.tls'),'<span class="mono">'+esc(tl.version)+'</span>']);
  if(tl.cipher_suite)rs.push([t('tp.cipher'),'<span class="mono">'+esc(tl.cipher_suite)+'</span>']);
  if(ci&&ci.days_left!==undefined){
    const d=ci.days_left;
    rs.push([t('tp.exp'),'<span class="mono'+(d<0?' neg':(d<30?' warn':''))+'">'+d+' d</span>']);
  }
  return [tpNode('tp-srv',t('tp.server'),rs,'',tpIcon.SVG.srv)];
}
function tpEndpoints(data){
  const out=[];
  if(data.mode==='server'){
    const conns=data.server_conns||[];
    const by={};
    conns.forEach(function(c){
      const k=c.client_id||'-';
      if(!by[k])by[k]={n:0,tx:0,rx:0,max:0,min:1e9,brut:0,err:'',remote:'',sni:'',tls:'',alpn:'',ep:0};
      by[k].n++;by[k].tx+=(c.tx_bytes||0);by[k].rx+=(c.rx_bytes||0);
      if(c.rtt_ms>by[k].max)by[k].max=c.rtt_ms;
      if(c.rtt_ms&&c.rtt_ms<by[k].min)by[k].min=c.rtt_ms;
      if(c.remote&&!by[k].remote)by[k].remote=c.remote;
      if(c.brutal_applied)by[k].brut++;
      if(c.brutal_error&&!by[k].err)by[k].err=c.brutal_error;
      if(c.sni&&!by[k].sni)by[k].sni=c.sni;
      if(c.tls_version&&!by[k].tls)by[k].tls=c.tls_version;
      if(c.tls_alpn&&!by[k].alpn)by[k].alpn=c.tls_alpn;
      if(c.session_epoch&&!by[k].ep)by[k].ep=c.session_epoch;
    });
    Object.keys(data.clients||{}).forEach(function(id){
      const c=data.clients[id]||{},b=by[id]||{n:0,tx:0,rx:0,max:0,min:1e9,brut:0,err:'',remote:'',sni:'',tls:'',alpn:'',ep:0};
      const rs=[];
      rs.push([t('tp.remote'),'<span class="mono">'+esc(b.remote||'-')+'</span>']);
      rs.push([t('tp.conns'),'<span class="mono">'+fmtNum(b.n)+'</span>']);
      if(c.active_conns!==undefined&&b.n===0)rs.push([t('tp.live'),'<span class="mono">'+fmtNum(c.active_conns)+'</span>']);
      if(c.ipv4)rs.push([t('tp.v4'),'<span class="mono">'+esc(c.ipv4)+'</span>']);
      if(c.ipv6)rs.push([t('tp.v6'),'<span class="mono">'+esc(c.ipv6)+'</span>']);
      if(c.mac)rs.push([t('tp.mac2'),'<span class="mono">'+esc(c.mac)+'</span>']);
      const pi=c.peer_info||{};
      if(pi.hostname)rs.push([t('tp.host'),'<span class="mono">'+esc(pi.hostname)+'</span>']);
      if(pi.implementation||pi.version)rs.push([t('kpi.version'),'<span class="mono">'+esc([pi.implementation,pi.version].filter(Boolean).join(' '))+'</span>']);
      if(pi.os||pi.os_version||pi.arch)rs.push([t('stt.sys.os'),platformSummary(pi.os,pi.os_version,pi.arch)]);
      if(b.n){
        const mn=b.min===1e9?0:b.min;
        rs.push([t('tp.rtt'),'<span class="mono">'+mn+'<span class="dim"> - '+b.max+' ms</span></span>']);
        rs.push([t('tp.byt'),'<span class="mono">'+fmtBytes(b.tx)+' / '+fmtBytes(b.rx)+'</span>']);
        if(b.ep)rs.push([t('sc.a_epoch'),'<span class="mono">'+fmtNum(b.ep)+'</span>']);
        if(c.fec)rs.push([t('tp.fec'),esc(c.fec)]);
        if(c.enc_algo!==undefined&&c.enc_algo!==''&&c.enc_algo!==null)
          rs.push([t('tp.enc'),encBadge(c.enc_algo)]);
        if(b.sni)rs.push([t('tp.sni'),'<span class="mono">'+esc(b.sni)+'</span>']);
        if(b.tls)rs.push([t('tp.tls'),'<span class="mono">'+esc(b.tls)+'</span>']);
        if(b.alpn)rs.push([t('tp.alpn'),'<span class="mono">'+esc(b.alpn)+'</span>']);
        if(cfg_brut(data))rs.push([t('tp.brutal'),b.brut+'<span class="dim"> / '+b.n+'</span>']);
        if(b.err)rs.push([t('tp.err'),'<span class="neg">'+esc(b.err)+'</span>']);
      }
      out.push(tpNode(b.err?' tp-bad':'',id,rs,id));
    });
    if(!out.length)out.push(tpNode('tp-empty',t('tp.empty_srv'),[]));
  }else{
    const cr=data.conns||[];
    cr.forEach(function(c,i){
      const rs=[];
      rs.push([t('tp.target'),'<span class="mono">'+esc(c.target||'-')+'</span>']);
      rs.push([t('tp.state'),'<span class="mono">'+esc(c.state||'-')+'</span>']);
      rs.push([t('tp.rtt'),'<span class="mono">'+(c.rtt_ms||0)+' ms</span>']);
      rs.push([t('tp.age'),'<span class="mono">'+fmtDur(c.age_sec||0)+'</span>']);
      rs.push([t('tp.byt'),'<span class="mono">'+fmtBytes(c.tx_bytes||0)+' / '+fmtBytes(c.rx_bytes||0)+'</span>']);
      if(c.last_error)rs.push([t('tp.err'),'<span class="neg">'+esc(c.last_error)+'</span>']);
      out.push(tpNode(c.last_error?' tp-bad':'','conn '+(i+1),rs));
    });
    if(!out.length)out.push(tpNode('tp-empty',t('tp.empty_cli'),[]));
  }
  return out;
}
function cfg_brut(data){
  const b=data.negotiate&&data.negotiate.brutal;
  return !!(b&&b.enabled);
}
// 协议链按数据实际来源取值，缺哪个都不编造：服务端模式下逐连接的 tls_version /
// 客户端表里的 enc_algo 与 fec 才是真正的协商结果，negotiate 块只有客户端模式
// 才完整。取不到就写 '-'，不写 'off'——字段缺位和"未启用"是两回事。
function tpChain(data){
  const cfg=data.cfg||{},np=data.negotiate||{},tl=np.tls||{};
  const cr=data.mode==='server'?(data.server_conns||[]):[];
  const uniq=function(a){const s=[];a.forEach(function(v){if(v!==undefined&&v!==null&&v!==''&&s.indexOf(v)<0)s.push(v);});return s;};
  const mv=function(s,df){
    if(!s.length)return df;
    if(s.length===1)return s[0];
    if(s.length===2)return s.join('/');
    return t('sc.kinds').replace('{n}',String(s.length));
  };
  const encS=function(a){return a===2?'AES-256-GCM':(a===4?'AES-128-GCM':'off');};
  const cliArr=function(){const o=data.clients;return o&&Object.prototype.toString.call(o)==='[object Object]'?Object.keys(o):[];};
  const vals=function(k){return uniq(cliArr().map(function(x){return data.clients[x][k];}));};
  const tlsV=uniq(cr.map(function(c){return c.tls_version;}));
  const enCs=vals('enc_algo');
  const fecS=vals('fec');
  const UNK=t('sc.not_set');
  const it=[];
  it.push([t('tp.p_tls'),tl.version||mv(tlsV,UNK)]);
  it.push([t('tp.p_psk'),cfg.encrypt_psk===true?'on':(cfg.encrypt_psk===false?'off':UNK)]);
  it.push([t('tp.p_enc'),np.enc_algo!==undefined?encS(np.enc_algo)
    :mv(enCs.map(encS),cfg.encrypt===true?'on':(cfg.encrypt===false?'off':UNK))]);
  it.push([t('tp.p_fec'),np.fec?mv((np.fec_group!==undefined&&np.fec_group!==null&&np.fec_group!==0)?['K'+np.fec_group]:fecS,UNK):mv(fecS,UNK)]);
  if(data.mode==='server')it.push([t('tp.p_vsw'),'vswitch']);
  it.push([t('tp.p_pad'),np.pad_mode||cfg.pad_mode||UNK]);
  return '<div class="tp-chain">'+
    it.map(function(x){
      return '<span class="tp-chip"><i>'+esc(x[0])+'</i><b>'+esc(String(x[1]))+'</b></span>';
    }).join('<span class="tp-chain-sep">&#8594;</span>')+'</div>';
}
function renderTopo(data){
  if(!data)return;
  const host=document.getElementById('tpo');
  if(!host)return;
  const isSrv=data.mode==='server';
  const m=document.getElementById('tp-mode');
  if(m){
    m.textContent=(data.mode||'').toUpperCase();
    m.className='tp-mode '+(isSrv?'t-srv':'t-cli');
  }
  const up=document.getElementById('tp-updated');
  if(up){
    const ago=lastStatsT>0?Math.max(0,Math.round((Date.now()-lastStatsT)/1000)):0;
    up.textContent=t('dg.updated').replace('{t}',fmtDur(ago));
  }
  const sm=data.system||{};
  const meta=[];
  if(sm.host)meta.push(t('tp.host')+': '+sm.host);
  meta.push(data.version||'');
  if(data.uptime_sec)meta.push(t('kpi.uptime')+' '+fmtDur(data.uptime_sec));
  const metaEl=document.getElementById('tp-meta');
  if(metaEl)metaEl.textContent=meta.filter(Boolean).join('  ·  ');
  const ep=tpEndpoints(data);
  let left,mid,right;
  if(isSrv){
    const core=tpCoreNodes(data);
    const ex=tpEgressNodes(data);
    const cnt=ep.length;
    left=tpColumn(t('tp.endpoints_srv').replace('{n}',String(cnt)),ep.join(''));
    mid=tpColumn(t('tp.vswitch'),core.join(''));
    right=tpColumn(t('tp.egress'),ex.join(''));
  }else{
    const core=tpCoreNodes(data);
    const pe=tpPeerNodes(data);
    const cnt=data.conns&&data.conns.length||0;
    left=tpColumn(t('tp.local'),core.join(''));
    mid=tpColumn(t('tp.conns_n').replace('{n}',String(cnt)),ep.join(''));
    right=tpColumn(t('tp.peer'),pe.join(''));
  }
  host.innerHTML=tpChain(data)+tpFlow(left,mid,right);
}

let logSeq=0,logFilter='';
function applyLogs(lines){
  if(!Array.isArray(lines)||!lines.length)return;
  lines=lines.filter(function(l){return l&&l.seq>logSeq;});
  if(!lines.length)return;
  try{
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    if(box.querySelector('.empty-box'))box.innerHTML='';
    box.innerHTML+=lines.map(l=>'<div class="ln lv-'+l.level+'"><span class="ts">['+l.time+']</span><span class="lv">'+l.level+'</span><span class="msg">'+esc(l.msg)+'</span></div>').join('');
    logSeq=lines[lines.length-1].seq;
    applyLogFilter();
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){console.error('log render failed',e);}
}
// 日志过滤：本地隐藏不匹配的行，缓冲不丢，计数显示 命中/总数
function applyLogFilter(){
  const box=document.getElementById('logbox');
  if(!box)return;
  const f=logFilter.toLowerCase();
  const all=box.querySelectorAll('.ln');
  let shown=0;
  all.forEach(function(l){
    const hit=!f||l.textContent.toLowerCase().indexOf(f)>=0;
    l.style.display=hit?'':'none';
    if(hit)shown++;
  });
  const cnt=document.getElementById('log-count');
  if(cnt)cnt.textContent=f?(shown+' / '+all.length):'';
}
function logEmptyBox(){
  return '<div class="empty-box"><svg viewBox="0 0 24 24">'+EMPTY_ICON.logs+'</svg>'+
    '<div>'+esc(t('no_logs'))+'</div></div>';
}
function clearLog(){
  logFilter='';
  const inp=document.getElementById('log-filter');
  const clr=document.getElementById('log-filter-clear');
  if(inp)inp.value='';
  if(clr)clr.classList.remove('show');
  document.getElementById('logbox').innerHTML=logEmptyBox();
  applyLogFilter();
  toast(t('toast.clear'),'ok');
}
function downloadLog(){
  // innerText 跳过 display:none 的行，所以导出内容自然跟随当前过滤条件
  const blob=new Blob([document.getElementById('logbox').innerText],{type:'text/plain;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='tlsvpn-dashboard-'+new Date().toISOString().replace(/[:.]/g,'-')+'.log';a.click();
  toast(t('toast.download'),'ok');
}
// 日志过滤框：与其他表格搜索框同样的防抖/清空/Esc 交互
(function(){
  const inp=document.getElementById('log-filter');
  const clr=document.getElementById('log-filter-clear');
  if(!inp)return;
  let timer=null;
  inp.addEventListener('input',function(){
    if(clr)clr.classList.toggle('show',!!inp.value);
    clearTimeout(timer);
    timer=setTimeout(function(){logFilter=inp.value.trim();applyLogFilter();},140);
  });
  if(clr)clr.addEventListener('click',function(){inp.value='';logFilter='';clr.classList.remove('show');applyLogFilter();inp.focus();});
  inp.addEventListener('keydown',function(ev){if(ev.key==='Escape'&&clr)clr.click();});
})();

	let THEME=localStorage.getItem('tlsvpn_theme')||'system';
function cssv(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()||'#888';}
// 媒体查询必须写成带括号的形式：matchMedia 的裸 'prefers-color-scheme: dark' 会被
// 解析成 'not all'（无效查询），matches 恒为 false，于是 Auto 永远退化成浅色，
// 设备明明是深色也识别不到，change 监听也永远收不到事件。定义一处共用，isDark 和
// 下面的变更监听就不会各写一遍、各错一遍。
const PREFERS_DARK=matchMedia('(prefers-color-scheme: dark)');
function isDark(){return THEME==='dark'||(THEME==='system'&&PREFERS_DARK.matches);}
// 两张画布的颜色都取自 CSS 变量、烘焙进像素，主题一变必须各自重画；漏掉一张
// 就会有一张图继续顶着旧主题配色。收进这一处，主题同步才不会各改一处各漏一处。
function redrawCharts(){redrawChart();if(lastTraffic)drawTrafficChart(lastTraffic.daily||[]);}
function applyTheme(){
  document.documentElement.dataset.theme=isDark()?'dark':'light';
  setSeg('theme-seg',THEME);
  redrawCharts();
}
function setTheme(v){THEME=v;localStorage.setItem('tlsvpn_theme',v);applyTheme();}
// Auto 跟随系统：操作系统自己切深浅色时，面板得跟着重画，而不等下一轮轮询
PREFERS_DARK.addEventListener('change',function(){if(THEME==='system')applyTheme();});

['clients','conns','macs'].forEach(attachSearch);
bindChartHover('chart',redrawChart);
bindChartHover('traffic-chart',function(){renderTrafficView();});
let chartRange='2m',trendData=null;
// 趋势数据与统计快照共用 /api/stream SSE；切换范围时重建长连接，
// 浏览器不再定时请求 /api/trend。
function setRange(v){
  chartRange=v;setSeg('range-seg',v);
  trendData=null;
  redrawChart();
  if(window.tlsvpnStreamRestart)window.tlsvpnStreamRestart();
}
function applyTrend(d){
  if(!d)return;
  if(chartRange==='2m'&&d.step_sec!==1){trendData=null;return;}
  trendData=d;
  drawTrendChart(d.points||[]);
}
// 图表重绘统一入口：服务端数据到手就用它，冷启动还没拿到时退回本地轮询增量
function redrawChart(){
  if(trendData&&trendData.points&&trendData.points.length){drawTrendChart(trendData.points||[]);return;}
  if(txHist.length||rxHist.length)drawChart();
}
function drawTrendChart(points){
  const arr=points||[];
  // 1 秒粒度下分钟级标签会大面积重复，保留到秒
  const fine=trendData&&trendData.step_sec<=1;
  const pts=arr.map((p,i)=>({
    x:arr.length>1?i/(arr.length-1):0,up:p.up,down:p.down,rtt:p.rtt||0,label:fmtHM(p.t*1000).slice(0,fine?8:5)
  }));
  let max=1,maxRtt=0;
  pts.forEach(p=>{if(p.up>max)max=p.up;if(p.down>max)max=p.down;if(p.rtt>maxRtt)maxRtt=p.rtt;});
  const old=chartState['chart'];
  const hover=(old&&old.hover>=0&&old.hover<pts.length)?old.hover:-1;
  renderLineChart('chart',pts,{max:max,maxRtt:maxRtt,perSec:true,hover:hover});
  // RTT 图例跟随数据里是否真有 RTT，切区间时一并复位
  const lg=document.getElementById('legend-rtt');
  if(lg)lg.style.display=maxRtt>0?'':'none';
}

let prev={},lastT=0;const txHist=[],rxHist=[],txTimes=[];const MAXPTS=60;
applyI18n();
// 异常提醒条的关闭按钮：静默当前组合，出现新的告警内容时再自动弹出
(function(){const x=document.getElementById('alertbar-x');
  if(x)x.onclick=function(){alertOff=true;document.getElementById('alertbar').style.display='none';toast(t('ov.alerts_off'),'ok');};})();
document.getElementById('logbox').innerHTML=logEmptyBox();
// 事件行里的客户端 ID 可点，直接打开客户端详情抽屉
document.getElementById('evbox').addEventListener('click',function(ev){
  const el=ev.target.closest('.ev-cl');
  if(el)openClient(el.dataset.cid);
});
setRefresh(REFRESH_S);setRange(chartRange);
window.addEventListener('resize',redrawChart);


function platformAssetName(kind,value){
  const v=String(value||'').trim().toLowerCase();
  if(kind==='os'){
    if(/windows|win32|mingw|msys/.test(v))return 'os-windows.svg';
    if(/darwin|macos|mac os|osx/.test(v))return 'os-macos.svg';
    if(/android/.test(v))return 'os-android.svg';
    if(/freebsd|openbsd|netbsd|dragonfly/.test(v))return 'os-bsd.svg';
    if(/linux|openwrt|immortalwrt|debian|ubuntu|alpine|fedora|centos|rhel|rocky|arch/.test(v))return 'os-linux.svg';
    return 'os-generic.svg';
  }
  if(/amd64|x86_64|x64/.test(v))return 'arch-x86_64.svg';
  if(/(^|[^0-9])386|i[3-6]86|(^|[^a-z])x86([^_]|$)/.test(v))return 'arch-x86.svg';
  if(/arm64|aarch64/.test(v))return 'arch-arm64.svg';
  if(/(^|[^a-z])arm(v[5-9])?([^a-z]|$)/.test(v))return 'arch-arm.svg';
  if(/riscv64/.test(v))return 'arch-riscv64.svg';
  if(/mips/.test(v))return 'arch-mips.svg';
  if(/loong64|loongarch/.test(v))return 'arch-loong64.svg';
  return 'arch-generic.svg';
}
function platformBadge(kind,value,label){
  const raw=String(value||'').trim(), text=String(label===undefined?raw:label||'').trim();
  if(!raw&&!text)return '';
  return '<span class="platform-badge"><img class="platform-icon" src="icons/'+platformAssetName(kind,raw)+'" alt="" loading="lazy" decoding="async"><span class="mono">'+esc(text||raw)+'</span></span>';
}
function platformIconsOnly(os,arch){
  const parts=[];
  if(os)parts.push('<img class="platform-icon" src="icons/'+platformAssetName('os',os)+'" alt="" title="'+esc(os)+'" loading="lazy" decoding="async">');
  if(arch)parts.push('<img class="platform-icon" src="icons/'+platformAssetName('arch',arch)+'" alt="" title="'+esc(arch)+'" loading="lazy" decoding="async">');
  return parts.length?'<span class="platform-icons-only">'+parts.join('')+'</span>':'';
}
function platformSummary(os,version,arch){
  const parts=[];
  if(os)parts.push(platformBadge('os',os,os));
  if(version)parts.push('<span class="mono dim">'+esc(version)+'</span>');
  if(arch)parts.push(platformBadge('arch',arch,arch));
  return parts.length?'<span class="platform-summary">'+parts.join('')+'</span>':'<span class="mono">-</span>';
}

// An SSE reconnect may attach to a new process. Reset every lifetime baseline
// before applying its first snapshot, including log/event cursors.
let dashboardInstance=null, dashboardUptime=null, globalPrev=null;
function resetDashboardPeriod(data){
  const changed=(data.instance_id && dashboardInstance!==null && data.instance_id!==dashboardInstance) ||
    (dashboardUptime!==null && data.uptime_sec!==undefined && data.uptime_sec<dashboardUptime);
  if(changed){
    prev={};lastT=0;globalPrev=null;prevPps={ok:false};lastSpeeds={};prevConns={};lastConnsT=0;lastConnSpeeds={};
    txHist.length=0;rxHist.length=0;txTimes.length=0;trendData=null;
    logSeq=0;evSeq=0;evItems=[];
    const box=document.getElementById('logbox');if(box)box.innerHTML='';
  }
  if(data.instance_id)dashboardInstance=data.instance_id;
  if(data.uptime_sec!==undefined)dashboardUptime=data.uptime_sec;
}
