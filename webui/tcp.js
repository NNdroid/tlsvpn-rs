/* Kernel socket observations; this renderer never infers values from cfg. */
(function(){
  'use strict';
  const words={
    'zh-CN':['TCP 实际状态','等待采样','读取失败','不支持','开启','关闭','本机 TCP','本机 → SOCKS5 代理','采样时间','关闭','当前连接已退出','来自 Linux socket API。CORK/QUICKACK 为瞬时状态；内核缓冲含记账空间，不等于 TCP 窗口。所有速率为本机发送方向。','KeepAlive 空闲','KeepAlive 间隔','KeepAlive 次数','发送缓冲','接收缓冲','用户超时','未发送阈值','拥塞控制','拥塞状态','RTT 波动','拥塞窗口（段）','未确认（段）','重传中（段）','累计重传','本次新增重传','未发送字节','发送 MSS','接收 MSS','路径 MTU','接收方窗口','窗口缩放','发送窗口缩放','接收窗口缩放','发送速率估计','应用限制速率估计','发送 pacing 速率','累计忙碌','累计接收窗口受限','累计发送缓冲受限','累计重传字节','采样已过期','无限制','本次采样间隔','系统默认'],
    'zh-TW':['TCP 實際狀態','等待採樣','讀取失敗','不支援','開啟','關閉','本機 TCP','本機 → SOCKS5 代理','採樣時間','關閉','目前連線已退出','來自 Linux socket API。CORK/QUICKACK 為瞬時狀態；核心緩衝包含記帳空間，不等於 TCP 視窗。速率為本機傳送方向。','KeepAlive 閒置','KeepAlive 間隔','KeepAlive 次數','傳送緩衝','接收緩衝','使用者逾時','未傳送閾值','壅塞控制','壅塞狀態','RTT 波動','壅塞視窗（段）','未確認（段）','重傳中（段）','累計重傳','本次新增重傳','未傳送位元組','傳送 MSS','接收 MSS','路徑 MTU','接收方視窗','視窗縮放','傳送視窗縮放','接收視窗縮放','傳送速度估計','應用限制速度估計','傳送 pacing 速度','累計忙碌','累計接收視窗受限','累計傳送緩衝受限','累計重傳位元組','採樣已過期','無限制','本次採樣間隔','系統預設'],
    en:['Observed TCP state','Waiting for sample','Read failed','Unsupported','On','Off','Local TCP','Local → SOCKS5 proxy','Sample time','Close','Connection has retired','From Linux socket APIs. CORK/QUICKACK are transient; kernel buffers include bookkeeping and are not TCP windows. Rates describe local transmission.','KeepAlive idle','KeepAlive interval','KeepAlive probes','Send buffer','Receive buffer','User timeout','Not-sent threshold','Congestion control','Congestion state','RTT variation','Congestion window (segments)','Unacked (segments)','Retransmitting (segments)','Total retransmissions','New retransmissions','Not-sent bytes','Send MSS','Receive MSS','Path MTU','Peer receive window','Window scaling','Send window scale','Receive window scale','Delivery-rate estimate','App-limited estimate','Pacing rate','Total busy time','Total receive-window limited','Total send-buffer limited','Total retransmitted bytes','Stale sample','Unlimited','Sample interval','System default'],
    de:['Beobachteter TCP-Zustand','Messung ausstehend','Lesefehler','Nicht unterstützt','An','Aus','Lokales TCP','Lokal → SOCKS5-Proxy','Messzeit','Schließen','Verbindung beendet','Aus Linux-Socket-APIs. CORK/QUICKACK sind Momentaufnahmen; Puffer enthalten Verwaltungsdaten und sind keine TCP-Fenster. Raten gelten für lokales Senden.','KeepAlive-Leerlauf','KeepAlive-Intervall','KeepAlive-Proben','Sendepuffer','Empfangspuffer','Benutzer-Timeout','Ungesendet-Schwelle','Staukontrolle','Stauzustand','RTT-Schwankung','Staufenster (Segmente)','Unbestätigt (Segmente)','Neusendung (Segmente)','Neusendungen gesamt','Neue Neusendungen','Ungesendete Bytes','Sende-MSS','Empfangs-MSS','Pfad-MTU','Empfangsfenster des Peers','Fensterskalierung','Sendefensterskalierung','Empfangsfensterskalierung','Lieferratenschätzung','App-begrenzte Schätzung','Pacing-Rate','Aktive Zeit gesamt','Empfangsfenster begrenzt','Sendepuffer begrenzt','Neu gesendete Bytes','Veraltete Messung','Unbegrenzt','Messintervall','Systemstandard'],
    fr:['État TCP observé','Mesure en attente','Échec de lecture','Non pris en charge','Activé','Désactivé','TCP local','Local → proxy SOCKS5','Heure de mesure','Fermer','Connexion terminée','API socket Linux. CORK/QUICKACK sont instantanés ; les tampons incluent la gestion interne et ne sont pas des fenêtres TCP. Débits en émission locale.','Inactivité KeepAlive','Intervalle KeepAlive','Sondes KeepAlive','Tampon émission','Tampon réception','Délai utilisateur','Seuil non envoyé','Contrôle de congestion','État de congestion','Variation RTT','Fenêtre congestion (segments)','Non acquittés (segments)','Retransmis (segments)','Retransmissions totales','Nouvelles retransmissions','Octets non envoyés','MSS émission','MSS réception','MTU du chemin','Fenêtre réception du pair','Mise à échelle fenêtre','Échelle fenêtre émission','Échelle fenêtre réception','Débit livré estimé','Estimation limitée par application','Débit pacing','Temps actif total','Limité par fenêtre réception','Limité par tampon émission','Octets retransmis totaux','Mesure périmée','Illimité','Intervalle de mesure','Valeur système'],
    ja:['TCP 実測状態','測定待ち','読取失敗','非対応','有効','無効','ローカル TCP','ローカル → SOCKS5 プロキシ','測定時刻','閉じる','接続は終了しました','Linux socket API の値。CORK/QUICKACK は瞬時状態。バッファには管理領域が含まれ、TCP ウィンドウとは異なります。速度はローカル送信方向。','KeepAlive アイドル','KeepAlive 間隔','KeepAlive 回数','送信バッファ','受信バッファ','ユーザータイムアウト','未送信しきい値','輻輳制御','輻輳状態','RTT 変動','輻輳窓（セグメント）','未確認（セグメント）','再送中（セグメント）','累積再送','新規再送','未送信バイト','送信 MSS','受信 MSS','経路 MTU','相手の受信窓','ウィンドウスケール','送信窓スケール','受信窓スケール','配信速度推定','アプリ制限推定','Pacing 速度','累積稼働時間','累積受信窓制限時間','累積送信バッファ制限時間','累積再送バイト','古い測定値','無制限','測定間隔','システム既定']
  };
  const tr=i=>(words[typeof LANG==='string'?LANG:'en']||words.en)[i];
  const fields=[['state','TCP'],['nodelay','NoDelay'],['congestion',19],['keepalive','KeepAlive'],['keepidle_sec',12,'s'],['keepintvl_sec',13,'s'],['keepcnt',14],['cork','TCP_CORK'],['quickack','TCP_QUICKACK'],['sndbuf_bytes',15,'bytes'],['rcvbuf_bytes',16,'bytes'],['mss_bytes','MSS','bytes'],['user_timeout_ms',17,'ms'],['notsent_lowat_bytes',18,'bytes'],['mark','SO_MARK'],['ca_state',20],['rtt_us','RTT','us'],['rttvar_us',21,'us'],['rto_us','RTO','us'],['snd_mss_bytes',28,'bytes'],['rcv_mss_bytes',29,'bytes'],['pmtu_bytes',30,'bytes'],['cwnd_segments',22],['unacked_segments',23],['retrans_segments',24],['total_retrans',25],['retrans_delta',26],['retrans_interval_ms',44,'ms'],['notsent_bytes',27,'bytes'],['snd_wnd_bytes',31,'bytes'],['sack','SACK'],['timestamps','Timestamps'],['ecn','ECN'],['window_scaling',32],['snd_wscale',33],['rcv_wscale',34],['delivery_rate_Bps',35,'rate'],['delivery_app_limited',36],['pacing_rate_Bps',37,'rate'],['busy_us',38,'us'],['rwnd_limited_us',39,'us'],['sndbuf_limited_us',40,'us'],['bytes_retrans',41,'bytes']];
  let selected=null,lastData=null,lastReceipt=0;
  const dialog=document.createElement('dialog');dialog.id='tcp-dialog';dialog.className='tcp-dialog';dialog.innerHTML='<div class="chart-head"><h2 id="tcp-title"></h2><button class="btn ghost sm" id="tcp-close"></button></div><p id="tcp-scope" class="dim"></p><p id="tcp-note" class="dim"></p><div id="tcp-fields" class="tcp-fields"></div>';document.body.append(dialog);
  document.getElementById('tcp-close').onclick=()=>dialog.close();dialog.addEventListener('close',()=>{selected=null;});
  function value(snapshot,key,unit){
    const values=snapshot?.values||{};
    if(!Object.prototype.hasOwnProperty.call(values,key)){
      const reason=snapshot?.unavailable?.[key]||snapshot?.unavailable?.tcp_info||snapshot?.unavailable?.socket;
      return reason?(String(reason).startsWith('unsupported')?tr(3):tr(2))+' · '+reason:tr(1);
    }
    const v=values[key];if(key==='user_timeout_ms'&&v===0)return '0 ms · '+tr(45);if(key==='mark')return '0x'+Number(v).toString(16);if(typeof v==='boolean')return tr(v?4:5);if(v==='unlimited')return tr(43);
    if(unit==='bytes')return fmtBytes(v);if(unit==='rate')return fmtBytes(v,true);if(unit==='us')return Number((Number(v)/1000).toFixed(3))+' ms';return String(v)+(unit?' '+unit:'');
  }
  function connections(data){return data?.mode==='server'?(data.server_conns||[]):(data?.conns||[]);}
  function renderDetail(){
    if(!selected)return;
    const c=connections(lastData).find(c=>c.conn_id===selected),s=c?.tcp;
    document.getElementById('tcp-title').textContent=tr(0)+' · '+selected;
    document.getElementById('tcp-close').textContent=tr(9);
    document.getElementById('tcp-note').textContent=tr(11);
    const scope=document.getElementById('tcp-scope');
    if(!c||c.state&&c.state!=='up'){scope.textContent=c?tr(1)+' · '+c.state:tr(10);document.getElementById('tcp-fields').replaceChildren();return;}
    const serverNow=Number(lastData?.sample_time_ms)||Date.now();
    scope.textContent=s?(s.scope==='local_to_proxy'?tr(7):tr(6))+' · '+(s.peer||c.remote||'')+' · '+s.source+' · '+tr(8)+' '+new Date(s.sample_time_ms).toLocaleString(LANG)+(serverNow+Date.now()-lastReceipt-s.sample_time_ms>10000?' · '+tr(42):''):tr(1);
    const content=document.getElementById('tcp-fields');content.replaceChildren();
    fields.forEach(([key,label,unit])=>{const row=document.createElement('div'),name=document.createElement('span'),data=document.createElement('strong');row.className='tcp-field';name.textContent=typeof label==='number'?tr(label):label;data.textContent=value(s,key,unit);data.dataset.tcpField=key;row.append(name,data);content.append(row);});
  }
  function augment(data){
    if(data!==lastData)lastReceipt=Date.now();lastData=data;const tbody=document.getElementById('conns-body');if(!tbody)return;
    tbody.querySelectorAll('[data-tcp-cell]').forEach(el=>el.remove());
    const items=connections(data);
    tbody.querySelectorAll('tr[data-conn-id]').forEach(row=>{const id=row.dataset.connId,c=items.find(c=>c.conn_id===id);if(!c)return;
      const cell=document.createElement('td');cell.dataset.tcpCell='';const button=document.createElement('button');button.className='btn ghost sm tcp-button';button.dataset.tcpId=id;
      button.textContent=tr(0);cell.append(button);
      const s=c.tcp;if(s){const summary=document.createElement('small');summary.className='dim';summary.textContent=(s.values?.congestion||'—')+' · NoDelay '+value(s,'nodelay');cell.append(summary);}
      row.children[4].after(cell);
    });renderDetail();
    let th=document.getElementById('tcp-heading');if(!th){th=document.createElement('th');th.id='tcp-heading';tbody.closest('table').querySelector('thead tr').children[4].after(th);}th.textContent=tr(0);
    const empty=tbody.querySelector('tr:not([data-conn-id]) td[colspan]');if(empty)empty.colSpan=20;
  }
  document.getElementById('conns-body').addEventListener('click',ev=>{const button=ev.target.closest('[data-tcp-id]');if(!button)return;selected=button.dataset.tcpId;renderDetail();if(!dialog.open)dialog.showModal();});
  const original=renderConnsTable;renderConnsTable=function(data,fresh){const result=original(data,fresh);augment(data);return result;};
})();
