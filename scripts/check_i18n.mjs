#!/usr/bin/env node
import fs from 'node:fs';
import vm from 'node:vm';

const locales=['zh-CN','zh-TW','en','de','fr','ja'];
const failures=[];
const read=p=>fs.readFileSync(p,'utf8');

function flatten(obj,prefix='',out={}){
  for(const [k,v] of Object.entries(obj||{})){
    const key=prefix?`${prefix}.${k}`:k;
    if(v&&typeof v==='object'&&!Array.isArray(v))flatten(v,key,out);
    else out[key]=v;
  }
  return out;
}
function ph(v){return typeof v==='string'?[...v.matchAll(/\{[A-Za-z0-9_]+\}/g)].map(x=>x[0]).sort():[];}
function same(a,b){return a.length===b.length&&a.every((v,i)=>v===b[i]);}
function validate(name,dict){
  for(const l of locales)if(!dict[l])failures.push(`${name}: missing locale ${l}`);
  if(!dict.en)return;
  const base=flatten(dict.en);
  for(const l of locales){
    if(!dict[l])continue;
    const cur=flatten(dict[l]);
    for(const [k,enVal] of Object.entries(base)){
      if(!(k in cur)){failures.push(`${name}/${l}: missing key ${k}`);continue;}
      if(cur[k]===undefined||cur[k]===null||cur[k]==='')failures.push(`${name}/${l}: empty key ${k}`);
      const a=ph(enVal),b=ph(cur[k]);
      if(!same(a,b))failures.push(`${name}/${l}: placeholder mismatch ${k}: en=${a.join(',')} local=${b.join(',')}`);
    }
  }
}

const i18nSrc=read('webui/i18n.js');
const ctx={navigator:{language:'en-US'},localStorage:{getItem:()=>null,setItem:()=>{}},location:{reload:()=>{}},console};
vm.createContext(ctx);
try{
  vm.runInContext(i18nSrc,ctx,{filename:'webui/i18n.js'});
  const exported=vm.runInContext('({I18N,FRAMEVIZ_I18N})',ctx);
  validate('I18N',exported.I18N);
  validate('FRAMEVIZ_I18N',exported.FRAMEVIZ_I18N);

  const english=flatten(exported.I18N.en);
  for(const file of ['webui/app.js','webui/metrics.js','webui/stream.js']){
    const src=read(file);
    for(const m of src.matchAll(/\bt\(\s*['"]([^'"]+)['"]\s*\)/g)){
      if(!(m[1] in english))failures.push(`${file}: unknown i18n key ${m[1]}`);
    }
  }
  const html=read('webui/index.html');
  for(const m of html.matchAll(/data-i18n=['"]([^'"]+)['"]/g)){
    if(!(m[1] in english))failures.push(`webui/index.html: unknown data-i18n key ${m[1]}`);
  }
}catch(err){failures.push(`webui/i18n.js evaluation failed: ${err.stack||err}`);}

const fvSrc=read('webui/frameviz.js');
try{
  const decl='const FRAMEVIZ_DETAIL_I18N=';
  const start=fvSrc.indexOf(decl);
  const end=start<0?-1:fvSrc.indexOf('\n  };',start);
  if(start<0||end<0)throw new Error('FRAMEVIZ_DETAIL_I18N declaration not found');
  const literal=fvSrc.slice(start+decl.length,end+4).trim();
  const detail=vm.runInNewContext(`(${literal})`);
  validate('FRAMEVIZ_DETAIL_I18N',detail);

  const runtime=fvSrc.slice(0,start)+fvSrc.slice(end+5);
  const stale=[
    'Fixed 10 B big-endian header.','Inner AEAD','Data frames are aggregated first.',
    'Cover bytes are copied from the process','soft limit 12 KiB','Final frame · padLen=N',
    'Ethernet → AEAD (+16 B)','seq=0 handshake/control/heartbeat frames',
    'Legacy migration note:'
  ];
  for(const text of stale)if(runtime.includes(text))failures.push(`webui/frameviz.js: hard-coded visible text remains: ${text}`);
  for(const key of ['kpi_header','kpi_data_len','kpi_pad_len','kpi_batch','ethernet_frame','aead_tag','header_desc','inner_aead','aead_desc','tail_desc','detail_desc','batch_limits','frame','final_frame','flow','control_note']){
    if(!runtime.includes(`s.${key}`))failures.push(`webui/frameviz.js: translated key not rendered: ${key}`);
  }
}catch(err){failures.push(`webui/frameviz.js audit failed: ${err.stack||err}`);}

const login=read('webui/login.html');
for(const l of locales){
  if(!login.includes(`'${l}'`)&&!login.includes(`"${l}"`))failures.push(`webui/login.html: locale ${l} missing`);
}
for(const label of ['English','Français','Deutsch','简体中文','繁體中文','日本語']){
  if(!login.includes(label))failures.push(`webui/login.html: language label missing: ${label}`);
}

if(failures.length){
  console.error(`i18n coverage failed (${failures.length}):\n`+failures.map(x=>` - ${x}`).join('\n'));
  process.exit(1);
}
console.log('i18n coverage passed: locale keys/placeholders, references, login languages, and FrameViz visible text are complete.');
