import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';

const root = path.resolve('webui');
const openStreams = new Set();
const legacyPollHits = [];
const framevizExpect = {
  'zh-CN': ['协议头 (header)', '固定 10 B 大端序头。', '最后一帧 · padLen=N'],
  'zh-TW': ['協定標頭 (header)', '固定 10 B 大端序標頭。', '最後一幀 · padLen=N'],
  en: ['Protocol header', 'Fixed 10 B big-endian header.', 'Final frame · padLen=N'],
  de: ['Protokoll-Header', 'Fester 10-B-Big-Endian-Header.', 'Letzter Frame · padLen=N'],
  fr: ['En-tête du protocole', 'En-tête big-endian fixe de 10 o.', 'Dernière trame · padLen=N'],
  ja: ['プロトコルヘッダー', '固定 10 B のビッグエンディアンヘッダーです。', '最終フレーム · padLen=N']
};

function renderedIndex(src) {
  let html = src;
  if (!html.includes('data-v="zh-TW"')) {
    html = html.replace(
      '<button data-v="zh-CN" onclick="setLang(\'zh-CN\')">中文</button>',
      '<button data-v="zh-CN" onclick="setLang(\'zh-CN\')">简中</button>\n        <button data-v="zh-TW" onclick="setLang(\'zh-TW\')">繁中</button>'
    );
  }
  for (const asset of ['frameviz.js', 'metrics.js', 'stream.js']) {
    if (!html.includes(`src="${asset}"`)) {
      html = html.replace('</body>', `<script src="${asset}"></script>\n</body>`);
    }
  }
  return html;
}

function contentType(file) {
  if (file.endsWith('.js')) return 'application/javascript; charset=utf-8';
  if (file.endsWith('.css')) return 'text/css; charset=utf-8';
  if (file.endsWith('.svg')) return 'image/svg+xml';
  if (file.endsWith('.ico')) return 'image/x-icon';
  if (file.endsWith('.html')) return 'text/html; charset=utf-8';
  return 'application/octet-stream';
}

function statsFixture(mode='client',stage=1,instance='browser-smoke') {
  const client={tx_bytes:stage*12600,rx_bytes:stage*6300,tx_packets:stage*126,rx_packets:stage*50,active_conns:2,ipv4:'10.0.0.2',fec:'xor K=4',enc_algo:2};
  const conn=(id,owner)=>({conn_id:id,client_id:owner,index:0,target:'test.example:443',remote:'127.0.0.1:443',state:'up',tx_bytes:stage*6300,rx_bytes:stage*3150,rtt_ms:20,age_sec:10,fec:'xor K=4',enc_algo:2,tls_version:'TLS 1.3',scheduler:{active:true,queued_bytes:0,rate_mbps:8,assigned_bytes:stage*1000,assigned_batches:stage,fec_assigned_bytes:0,fec_assigned_batches:0}});
  const fixture={
    mode,version:'ci-smoke',instance_id:instance,sample_time_ms:1000+stage*1000,uptime_sec:10+stage,
    accounting_scope:'application_wire_excluding_heartbeat',active_clients:1,retained_sessions:1,live_conns:2,
    clients:mode==='client'?{local:client}:{A:client},
    conns:mode==='client'?[conn('a','local'),conn('b','local')]:[],
    server_conns:mode==='server'?[conn('a','A'),conn('b','A')]:[],
    global_tx_bytes:stage*12600,global_rx_bytes:stage*6300,global_tx_packets:stage*126,global_rx_packets:stage*50,
    dropped_frames:0,tap_write_errors:0,reconnect_attempts:0,
    fec:{enabled:true,counter_domain:'written',parity_tx:stage*25,parity_attempts:stage*25,data_tx:stage*100,control_tx:stage,data_wire_bytes:stage*10000,parity_wire_bytes:stage*2500,recovered:stage,lost:0,enabled_sessions:1,tx_active_sessions:1,rx_bypass_sessions:0,group:4},
    fec_mode:'xor K=4',enc_algo:2,
    reorder:{dropped_frames:0,skipped_frames:0,gap_events:0},drop_breakdown:{backpressure:0,reorder:0},
    pad:{mode:'bucket',epoch:1,wire_bytes:stage*1000,pad_bytes:stage*20,overhead_pct:stage?2:0},
    sessions:{active:2,max:2},cfg:{fec:true,fec_mode:'xor K=4',encrypt:true,conns:2},negotiate:{fec:true,fec_group:4},
    mem:{heap_alloc_mb:1,num_goroutine:10},system:{},traffic:{daily:[]}
  };
  for(const c of [...fixture.conns,...fixture.server_conns])c.tcp={source:'linux_socket',scope:c.conn_id==='a'?'local_tcp':'local_to_proxy',sample_time_ms:fixture.sample_time_ms,peer:'127.0.0.1:443',values:{nodelay:false,keepalive:true,congestion:'cubic',cork:false,quickack:false,keepidle_sec:21,total_retrans:7,retrans_delta:1,retrans_interval_ms:2000,sndbuf_bytes:131072,rcvbuf_bytes:65536},unavailable:{delivery_rate_Bps:'unsupported_short_tcp_info'}};
  return fixture;
}

function diagnosticsFixture(instance='browser-smoke') {
  return {instance_id:instance,step_sec:2,points:[0,1,2].map(i=>({t:1700000000000+i*2000,
    metrics:{online:2,fec_data:100000,fec_parity:25000,fec_pct:25,recovered:i,lost:0,pad:2000,pad_wire:100000,pad_pct:2,reconnect:0,drop:0,tap_error:0},
    conns:[{id:'conn-a',client:'local',label:'peer-a',metrics:{up:i?32.38*1024**2:null,down:i?10*1024**2:null,rtt:i?20:null,queue:128,assigned:i?30*1024**2:null}},
      {id:'conn-b',client:'other',label:'peer-b',metrics:{up:1000,down:2000,rtt:40,queue:4096,assigned:1000}}]}))};
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.pathname === '/' || u.pathname === '/index.html') {
      const src = await fs.readFile(path.join(root, 'index.html'), 'utf8');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(renderedIndex(src));
      return;
    }
    if (u.pathname === '/api/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      const emit = (name, value) => res.write(`event: ${name}\ndata: ${JSON.stringify(value)}\n\n`);
      emit('stats', statsFixture('client',0));
      const statsTimer=setTimeout(()=>emit('stats',statsFixture()),100);
      res.on('close',()=>clearTimeout(statsTimer));
      emit('trend', { step_sec: 1, points: [] });
      const diagnosticsTimer=setTimeout(()=>emit('diagnostics',diagnosticsFixture()),150);
      res.on('close',()=>clearTimeout(diagnosticsTimer));
      emit('logs', []);
      emit('events', []);
      res.write(': browser-smoke\n\n');
      openStreams.add(res);
      res.on('close', () => openStreams.delete(res));
      return;
    }
    if (['/api/stats','/api/trend','/api/logs','/api/events','/api/diagnostics'].includes(u.pathname)) {
      legacyPollHits.push(u.pathname);
      res.writeHead(418, { 'content-type': 'application/json' });
      res.end('{"error":"legacy polling forbidden"}');
      return;
    }
    if (u.pathname === '/api/auth/status') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ enabled: false, authenticated: true }));
      return;
    }
    if (u.pathname.startsWith('/api/')) {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end('{}');
      return;
    }

    const rel = decodeURIComponent(u.pathname).replace(/^\/+/, '');
    const file = path.resolve(root, rel);
    if (!file.startsWith(root + path.sep)) {
      res.writeHead(403); res.end('forbidden'); return;
    }
    const body = await fs.readFile(file);
    res.writeHead(200, { 'content-type': contentType(file), 'cache-control': 'no-store' });
    res.end(body);
  } catch (err) {
    res.writeHead(err?.code === 'ENOENT' ? 404 : 500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(String(err));
  }
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const { port } = server.address();
const origin = `http://127.0.0.1:${port}`;
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const failures = [];
let activeLang = 'initial';

page.on('pageerror', err => failures.push(`[${activeLang}] pageerror: ${err.stack || err.message}`));
page.on('console', msg => {
  if (msg.type() === 'error') failures.push(`[${activeLang}] console.error: ${msg.text()}`);
});
page.on('response', response => {
  const url = response.url();
  if (url.startsWith(origin) && !url.includes('/api/') && response.status() >= 400) {
    failures.push(`[${activeLang}] HTTP ${response.status()}: ${url}`);
  }
});
page.on('requestfailed', request => {
  const url = request.url();
  if (url.startsWith(origin) && !url.includes('/api/stream')) {
    failures.push(`[${activeLang}] request failed: ${url} (${request.failure()?.errorText || 'unknown'})`);
  }
});

for (const lang of ['zh-CN', 'zh-TW', 'en', 'de', 'fr', 'ja']) {
  activeLang = lang;
  await page.goto(origin, { waitUntil: 'domcontentloaded' });
  await page.evaluate(v => localStorage.setItem('tlsvpn_lang', v), lang);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(400);
  const state = await page.evaluate(() => ({
    langType: typeof LANG,
    i18nType: typeof I18N,
    translateType: typeof t,
    framevizType: typeof FRAMEVIZ_I18N,
    documentLang: document.documentElement.lang,
    framevizCard: !!document.getElementById('frameviz-card'),
    framevizText: document.getElementById('frameviz-card')?.innerText || ''
  }));
  if (state.langType !== 'string') failures.push(`[${lang}] LANG is ${state.langType}`);
  if (state.i18nType !== 'object') failures.push(`[${lang}] I18N is ${state.i18nType}`);
  if (state.translateType !== 'function') failures.push(`[${lang}] t is ${state.translateType}`);
  if (state.framevizType !== 'object') failures.push(`[${lang}] FRAMEVIZ_I18N is ${state.framevizType}`);
  if (state.documentLang !== lang) failures.push(`[${lang}] document lang is ${state.documentLang}`);
  if (!state.framevizCard) failures.push(`[${lang}] frame visualizer did not render`);
  const diagnosticsState=await page.evaluate(()=>({cards:document.querySelectorAll('.diagnostic-card').length,
    sampled:document.getElementById('diag-throughput')?.diagPlot?.first,title:document.getElementById('diag-title')?.textContent}));
  if(diagnosticsState.cards!==6||diagnosticsState.sampled!==1700000000000||!diagnosticsState.title)
    failures.push('['+lang+'] diagnostic charts did not receive SSE history');
  await page.evaluate(()=>{document.getElementById('pane-conns').style.display='block';renderConnsTable(lastStats,false);});
  await page.locator('[data-tcp-id="a"]').click();
  const tcpState=await page.evaluate(()=>({open:document.getElementById('tcp-dialog').open,nodelay:document.querySelector('[data-tcp-field="nodelay"]').textContent,keepalive:document.querySelector('[data-tcp-field="keepalive"]').textContent,congestion:document.querySelector('[data-tcp-field="congestion"]').textContent,unavailable:document.querySelector('[data-tcp-field="delivery_rate_Bps"]').textContent}));
  if(!tcpState.open||tcpState.congestion!=='cubic'||tcpState.nodelay===tcpState.keepalive||!tcpState.unavailable.includes('unsupported_short_tcp_info'))failures.push('['+lang+'] TCP kernel facts were not displayed');
  await page.locator('#tcp-close').click();
  for (const expected of framevizExpect[lang]) {
    if (!state.framevizText.includes(expected)) failures.push(`[${lang}] frame visualizer missing localized text: ${expected}`);
  }
  if (lang !== 'en') {
    for (const leaked of ['Fixed 10 B big-endian header.', 'Final frame · padLen=N']) {
      if (state.framevizText.includes(leaked)) failures.push(`[${lang}] frame visualizer leaked English text: ${leaked}`);
    }
  }
}

// Exercise actual rendering with nonzero client/server counters and restart sequences.
for(const mode of ['client','server']) {
  const result=await page.evaluate(([first,next,mode])=>{
    applyStats(first);applyStats(next);
    const expectedUp=mode==='server'?6300:12600,expectedDown=mode==='server'?12600:6300;
    const errors=[];
    const check=(id,want)=>{const got=document.getElementById(id)?.textContent;if(got!==want)errors.push(id+': '+got+' != '+want);};
    check('total-tx',fmtBytes(12600));check('total-rx',fmtBytes(6300));
    check('live-up',fmtBytes(expectedUp,true));check('live-down',fmtBytes(expectedDown,true));
    check('fec-overhead','25.0%');
    const diag=dgRun(next).fec.find(x=>x.ch==='fecovh');if(!diag.det.startsWith('25.0'))errors.push('diagnostic FEC differs');
    openClient(mode==='server'?'A':'local');renderDrawer();closeDrawer();
    logSeq=1000;evSeq=1000;
    const restart=JSON.parse(JSON.stringify(next));restart.instance_id='restarted-'+mode;restart.uptime_sec=0;restart.sample_time_ms=500;
    applyStats(restart);
    check('total-tx-speed',fmtBytes(0,true));
    applyLogs([{seq:1,time:'00:00:00',level:'INFO',msg:'fresh-process-'+mode}]);
    applyEvents([{seq:1,type:'up',level:'info',time:'00:00:00',msg:'fresh-event-'+mode}]);
    if(logSeq!==1 || evSeq!==1)errors.push('restart cursors did not accept new sequence');
    if(!document.getElementById('logbox').textContent.includes('fresh-process-'+mode))errors.push('new process log missing');
    return errors;
  },[statsFixture(mode,0,'metric-'+mode),statsFixture(mode,1,'metric-'+mode),mode]);
  result.forEach(x=>failures.push('['+mode+' metrics] '+x));
  await page.evaluate(stats=>{applyStats(stats);document.getElementById('pane-conns').style.display='block';},statsFixture(mode));
  await page.locator('[data-tcp-id="b"]').click();
  if(!await page.locator('#tcp-scope').innerText().then(x=>x.includes('SOCKS5')))failures.push('['+mode+'] proxy transport scope missing');
  await page.evaluate(stats=>{stats.cfg.tcp_nodelay=true;applyStats(stats);},statsFixture(mode,2));
  const noDelay=await page.locator('[data-tcp-field="nodelay"]').innerText();
  if(!['关闭','關閉','Off','Aus','Désactivé','無効'].includes(noDelay))failures.push('TCP UI inferred NoDelay from cfg');
  await page.evaluate(stats=>{stats.conns=[];stats.server_conns=[];applyStats(stats);},statsFixture(mode,3));
  if(await page.locator('#tcp-fields').innerText())failures.push('retired socket details retained');
  await page.locator('#tcp-close').click();
}

// Check actual canvas glyph bounds at desktop/mobile widths and both pixel ratios.
for (const deviceScaleFactor of [1,2]) {
  const context=await browser.newContext({deviceScaleFactor});
  const chartPage=await context.newPage();
  await chartPage.goto(origin,{waitUntil:'domcontentloaded'});
  for (const width of [360,1100]) {
    await chartPage.setViewportSize({width,height:800});
    await chartPage.evaluate(([stats,history])=>{applyStats(stats);applyDiagnostics(history);},[statsFixture(),diagnosticsFixture()]);
    await chartPage.evaluate(()=>{document.getElementById('pane-conns').style.display='block';});
    await chartPage.locator('[data-tcp-id="a"]').click();
    const tcpFits=await chartPage.evaluate(()=>{const dialog=document.getElementById('tcp-dialog');return dialog.getBoundingClientRect().width<=innerWidth&&dialog.scrollWidth<=dialog.clientWidth;});
    if(!tcpFits)failures.push('TCP dialog overflow at viewport '+width+' DPR '+deviceScaleFactor);
    await chartPage.locator('#tcp-close').click();
    const diagBounds=await chartPage.evaluate(history=>{
      const errors=[],original=CanvasRenderingContext2D.prototype.fillText;
      CanvasRenderingContext2D.prototype.fillText=function(text,x,y,...rest){
        if(this.canvas.id.startsWith('diag-')){
          const b=this.measureText(text),scale=rest[0]?Math.min(1,rest[0]/b.width):1;
          if(x-b.actualBoundingBoxLeft*scale < -0.5 || x+b.actualBoundingBoxRight*scale > this.canvas.clientWidth+0.5)
            errors.push(this.canvas.id+' clips '+text);
        }
        return original.call(this,text,x,y,...rest);
      };
      try {setRange('24h');applyDiagnostics(history);setRange('2m');applyDiagnostics(history);} finally {CanvasRenderingContext2D.prototype.fillText=original;}
      return errors;
    },diagnosticsFixture());
    diagBounds.forEach(x=>failures.push('[diagnostic canvas] '+x));
    const throughput=chartPage.locator('#diag-throughput');
    await throughput.scrollIntoViewIfNeeded();const box=await throughput.boundingBox();
    await chartPage.mouse.move(box.x+box.width*0.6,box.y+70);
    const linked=await chartPage.evaluate(()=>[...document.querySelectorAll('.diagnostic-card canvas')].map(c=>c.dataset.diagHover));
    if(!linked[0]||linked.some(t=>t!==linked[0]))failures.push('diagnostic hover did not synchronize');
    const nativeVisible=await chartPage.evaluate(()=>[...document.querySelectorAll('select')].filter(s=>getComputedStyle(s).visibility!=='hidden').map(s=>s.id));
    if(nativeVisible.length)failures.push('native selects still visible: '+nativeVisible.join(','));
    const clientDropdown=chartPage.locator('#diag-client').locator('..');
    await clientDropdown.locator('.dl-btn').click();
    const menuBox=await clientDropdown.locator('.dl-menu').boundingBox();
    if(menuBox.x<0||menuBox.x+menuBox.width>chartPage.viewportSize().width)failures.push('dropdown exceeds viewport');
    await clientDropdown.locator('.dl-opt').filter({hasText:'other'}).click();
    await clientDropdown.locator('.dl-btn').focus();
    await chartPage.keyboard.press('ArrowDown');
    await chartPage.keyboard.press('Escape');
    if(await clientDropdown.locator('.dl-btn').getAttribute('aria-expanded')!=='false')failures.push('dropdown Escape failed');
    const filtered=await chartPage.locator('#diag-wrap-throughput .legend').innerText();
    if(filtered.includes('conn-a')||!filtered.includes('conn-b'))failures.push('diagnostic client filter failed');
    await chartPage.evaluate(()=>setRange('1h'));
    const cleared=await chartPage.evaluate(()=>document.getElementById('diag-throughput').diagPlot.first);
    if(cleared!==0)failures.push('range switch retained stale diagnostic points');
    await chartPage.evaluate(([stats,history])=>{applyStats(stats);applyDiagnostics(history);applyStats({...stats,instance_id:'after-restart'});},[statsFixture(),diagnosticsFixture()]);
    if(await chartPage.evaluate(()=>document.getElementById('diag-throughput').diagPlot.first)!==0)failures.push('restart retained diagnostic points');
    const errors=await chartPage.evaluate(()=>{
      const errors=[];
      for(const id of ['chart','traffic-chart']) {
        const canvas=document.getElementById(id);
        // History can be hidden; expose it so the mobile layout is measured too.
        if(id==='traffic-chart')document.getElementById('pane-traffic').style.display='block';
        canvas.style.display='block';canvas.style.width='100%';
        const ctx=canvas.getContext('2d'),original=ctx.fillText;
        ctx.fillText=function(text,x,y,...rest){
          const bounds=this.measureText(text);
          if(x-bounds.actualBoundingBoxLeft < -0.5 || x+bounds.actualBoundingBoxRight > canvas.clientWidth+0.5)
            errors.push(id+' clipped '+text+' at width '+canvas.clientWidth);
          return original.call(this,text,x,y,...rest);
        };
        try {
          for(const max of [32.38*1024**2,1023.99*1024**3]) {
            const pts=[0,0.5,1].map(x=>({x,up:max/4,down:max/2,rtt:20,label:'09:37:36'}));
            renderLineChart(id,pts,{max,perSec:id==='chart',maxRtt:40,hover:-1});
            const state=chartState[id];
            if(state.plot.r<=state.plot.l)errors.push(id+' has no plot area');
            const rect=canvas.getBoundingClientRect();
            if(chartIdxAt(id,rect.left+state.plot.l)!==0 || chartIdxAt(id,rect.left+state.plot.r)!==2)
              errors.push(id+' hover coordinates differ from plot');
          }
        } finally {ctx.fillText=original;}
      }
      return errors;
    });
    errors.forEach(x=>failures.push('[chart DPR '+deviceScaleFactor+'] '+x));
  }
  await context.close();
}

if (legacyPollHits.length) failures.push('legacy polling requests observed: '+legacyPollHits.join(', '));
await browser.close();
for (const stream of openStreams) stream.end();
await new Promise(resolve => server.close(resolve));

if (failures.length) {
  console.error('\nWebUI browser smoke failed:\n' + failures.map(x => ` - ${x}`).join('\n'));
  process.exit(1);
}
console.log('WebUI browser smoke passed: SSE-only transport, no browser/static-asset errors, and fully localized FrameViz rendering across all locales.');
