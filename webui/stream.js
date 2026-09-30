// Single live WebUI transport. Periodic dashboard data is SSE-only: the browser never
// polls /api/stats, /api/trend, /api/logs or /api/events. EventSource reconnects itself;
// URL/basic-auth sessions use the same SSE wire format through fetch()+ReadableStream.
(function(){
  'use strict';
  let source=null,controller=null,retryTimer=null,retryMs=1000,generation=0;
  const TYPES=['stats','trend','logs','events'];
  function streamPath(){
    const q=new URLSearchParams();
    q.set('interval_ms',String(Math.max(250,Number(REFRESH)||2000)));
    q.set('range',String(chartRange||'2m'));
    q.set('log_after',String(typeof logSeq==='number'?logSeq:0));
    q.set('event_after',String(typeof evSeq==='number'?evSeq:0));
    return '/api/stream?'+q.toString();
  }
  function applyFrame(type,text){
    if(!text)return;
    try{
      const payload=JSON.parse(text);
      if(type==='stats')applyStats(payload);
      else if(type==='trend')applyTrend(payload);
      else if(type==='logs')applyLogs(payload);
      else if(type==='events')applyEvents(payload);
    }catch(err){console.error('dashboard SSE '+type+' decode failed',err);}
  }
  function setLive(mode){if(typeof evStreamState==='function')evStreamState(mode);}
  function stopTransport(){
    generation++;
    if(retryTimer){clearTimeout(retryTimer);retryTimer=null;}
    if(source){try{source.close();}catch(e){}source=null;}
    if(controller){try{controller.abort();}catch(e){}controller=null;}
  }
  function scheduleReconnect(myGen){
    if(myGen!==generation||retryTimer)return;
    setLive('reconn');
    retryTimer=setTimeout(function(){retryTimer=null;if(myGen===generation)start();},retryMs);
    retryMs=Math.min(10000,Math.round(retryMs*1.7));
  }
  function startEventSource(myGen,path){
    let es;
    try{es=new EventSource(url(path));}catch(err){scheduleReconnect(myGen);return;}
    source=es;
    TYPES.forEach(function(type){es.addEventListener(type,function(ev){if(myGen===generation)applyFrame(type,ev.data);});});
    es.onopen=function(){if(myGen!==generation)return;retryMs=1000;setLive('sse');};
    es.onerror=function(){if(myGen===generation)setLive('reconn');};
  }
  function parseBlock(block){
    let event='message',data=[];
    block.split(/\r?\n/).forEach(function(line){if(line.startsWith('event:'))event=line.slice(6).trim();else if(line.startsWith('data:'))data.push(line.slice(5).replace(/^ /,''));});
    return {event:event,data:data.join('\n')};
  }
  async function startFetchStream(myGen,path){
    controller=new AbortController();
    try{
      const headers=Object.assign({'Accept':'text/event-stream'},AUTH_HDR||{});
      const res=await fetch(url(path),{signal:controller.signal,headers:headers,cache:'no-store'});
      if(res.status===401){showUnauthorized();return;}
      if(!res.ok||!res.body)throw new Error('SSE HTTP '+res.status);
      retryMs=1000;setLive('sse');
      const reader=res.body.getReader(),dec=new TextDecoder();let buf='';
      while(myGen===generation){
        const part=await reader.read();if(part.done)break;
        buf+=dec.decode(part.value,{stream:true}).replace(/\r\n/g,'\n');
        let cut;
        while((cut=buf.indexOf('\n\n'))>=0){
          const block=buf.slice(0,cut);buf=buf.slice(cut+2);
          if(!block||block[0]===':')continue;
          const frame=parseBlock(block);if(TYPES.indexOf(frame.event)>=0)applyFrame(frame.event,frame.data);
        }
      }
      if(myGen===generation)scheduleReconnect(myGen);
    }catch(err){if(myGen===generation&&!(err&&err.name==='AbortError'))scheduleReconnect(myGen);}
  }
  function start(){
    stopTransport();const myGen=generation,path=streamPath();setLive('reconn');
    if(AUTH_HDR&&AUTH_HDR.Authorization)startFetchStream(myGen,path);else startEventSource(myGen,path);
  }
  window.tlsvpnStreamRestart=start;
  window.addEventListener('beforeunload',stopTransport);
  start();
})();
