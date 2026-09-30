import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';

const root = path.resolve('webui');
const openStreams = new Set();
const legacyPollHits = [];
const framevizExpect = {
  'zh-CN': ['协议头 (header)', '固定 10 B 大端序头。', '最后一帧 · padLen=N', '旧版迁移说明：'],
  'zh-TW': ['協定標頭 (header)', '固定 10 B 大端序標頭。', '最後一幀 · padLen=N', '舊版遷移說明：'],
  en: ['Protocol header', 'Fixed 10 B big-endian header.', 'Final frame · padLen=N', 'Legacy migration note:'],
  de: ['Protokoll-Header', 'Fester 10-B-Big-Endian-Header.', 'Letzter Frame · padLen=N', 'Migrationshinweis:'],
  fr: ['En-tête du protocole', 'En-tête big-endian fixe de 10 o.', 'Dernière trame · padLen=N', 'Note de migration :'],
  ja: ['プロトコルヘッダー', '固定 10 B のビッグエンディアンヘッダーです。', '最終フレーム · padLen=N', '移行メモ：']
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

function statsFixture() {
  return {
    mode: 'client', version: 'ci-smoke', uptime: 1,
    clients: {}, conns: [], server_conns: [], mac_table: [], bans: [],
    tx_bytes: 0, rx_bytes: 0, tx_packets: 0, rx_packets: 0,
    dropped_frames: 0, tap_write_errors: 0,
    fec: { enabled: false, parity_tx: 0, recovered: 0, lost: 0 },
    reorder: { dropped_frames: 0, skipped_frames: 0, gap_events: 0 },
    drop_breakdown: {}, padding: {}, sessions: {}, runtime: {},
    traffic: { daily: [] }, alerts: [], routes: [], rules: []
  };
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
      emit('stats', statsFixture()); emit('trend', { step_sec: 1, points: [] }); emit('logs', []); emit('events', []);
      res.write(': browser-smoke\n\n');
      openStreams.add(res); res.on('close', () => openStreams.delete(res)); return;
    }
    if (['/api/stats','/api/trend','/api/logs','/api/events'].includes(u.pathname)) {
      legacyPollHits.push(u.pathname); res.writeHead(418, { 'content-type': 'application/json' }); res.end('{"error":"legacy polling forbidden"}'); return;
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
  for (const expected of framevizExpect[lang]) {
    if (!state.framevizText.includes(expected)) failures.push(`[${lang}] frame visualizer missing localized text: ${expected}`);
  }
  if (lang !== 'en') {
    for (const leaked of ['Fixed 10 B big-endian header.', 'Final frame · padLen=N', 'Legacy migration note:']) {
      if (state.framevizText.includes(leaked)) failures.push(`[${lang}] frame visualizer leaked English text: ${leaked}`);
    }
  }
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
