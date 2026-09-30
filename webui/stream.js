// Unified WebUI transport: all periodically refreshed dashboard data arrives over SSE.
// The legacy JSON endpoints remain available for scripts/API compatibility, but the browser
// dashboard does not poll them. Same-origin cookie auth uses EventSource; URL/basic-auth
// sessions use fetch()+ReadableStream so the Authorization header can still be sent.
(function(){
  'use strict';

  let source=null, controller=null, retryTimer=null, retryMs=1000, generation=0;
  const STREAM_TYPES=['stats','trend','logs','events'];

  function stopLegacyTimers(){
    if(typeof statsTimer!=='undefined'&&statsTimer){clearInterval(statsTimer);statsTimer=null;}
    if(typeof trendTimer!=='undefined'&&trendTimer){clearInterval(trendTimer);trendTimer=null;}
    if(typeof logTimer!=='undefined'&&logTimer){clearInterval(logTimer);logTimer=null;}
    if(typeof evTimer!=='undefined'&&evTimer){clearInterval(evTimer);evTimer=null;}
    if(typeof evES!=='undefined'&&evES){try{evES.close();}catch(e){}evES=null;}
  }

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
      if(type==='stats')fetchStats(payload);
      else if(type==='trend')fetchTrend(payload);
      else if(type==='logs')pollLogs(payload);
      else if(type==='events'&&Array.isArray(payload))payload.forEach(evPush);
    }catch(err){
      console.error('dashboard SSE '+type+' decode failed',err);
    }
  }

  function scheduleReconnect(myGen){
    if(myGen!==generation||retryTimer)return;
    retryTimer=setTimeout(function(){
      retryTimer=null;
      if(myGen===generation)start();
    },retryMs);
    retryMs=Math.min(10000,Math.round(retryMs*1.7));
  }

  function stopTransport(){
    generation++;
    if(retryTimer){clearTimeout(retryTimer);retryTimer=null;}
    if(source){try{source.close();}catch(e){}source=null;}
    if(controller){try{controller.abort();}catch(e){}controller=null;}
  }

  function startEventSource(myGen,path){
    let es;
    try{es=new EventSource(url(path));}catch(err){scheduleReconnect(myGen);return;}
    source=es;
    STREAM_TYPES.forEach(function(type){
      es.addEventListener(type,function(ev){if(myGen===generation)applyFrame(type,ev.data);});
    });
    es.onopen=function(){if(myGen===generation)retryMs=1000;};
    es.onerror=function(){};
  }

  function parseSSEBlock(block){
    let event='message',data=[];
    block.split(/\r?\n/).forEach(function(line){
      if(line.startsWith('event:'))event=line.slice(6).trim();
      else if(line.startsWith('data:'))data.push(line.slice(5).replace(/^ /,''));
    });
    return {event:event,data:data.join('\n')};
  }

  async function startFetchStream(myGen,path){
    controller=new AbortController();
    try{
      const opts=Object.assign({},AUTH_HDR,{signal:controller.signal,headers:Object.assign({'Accept':'text/event-stream'},AUTH_HDR.headers||{})});
      const res=await fetch(url(path),opts);
      if(res.status===401){showUnauthorized();return;}
      if(!res.ok||!res.body)throw new Error('SSE HTTP '+res.status);
      retryMs=1000;
      const reader=res.body.getReader(),dec=new TextDecoder();
      let buf='';
      while(myGen===generation){
        const part=await reader.read();
        if(part.done)break;
        buf+=dec.decode(part.value,{stream:true}).replace(/\r\n/g,'\n');
        let cut;
        while((cut=buf.indexOf('\n\n'))>=0){
          const block=buf.slice(0,cut);buf=buf.slice(cut+2);
          if(!block||block[0]===':')continue;
          const frame=parseSSEBlock(block);
          if(STREAM_TYPES.indexOf(frame.event)>=0)applyFrame(frame.event,frame.data);
        }
      }
      if(myGen===generation)scheduleReconnect(myGen);
    }catch(err){
      if(myGen===generation&&!(err&&err.name==='AbortError'))scheduleReconnect(myGen);
    }
  }

  function start(){
    stopLegacyTimers();
    stopTransport();
    const myGen=generation;
    const path=streamPath();
    if(AUTH_HDR&&AUTH_HDR.Authorization)startFetchStream(myGen,path);
    else startEventSource(myGen,path);
  }

  window.tlsvpnStreamRestart=function(){start();};
  window.addEventListener('beforeunload',stopTransport);
  start();
})();
