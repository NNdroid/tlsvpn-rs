/* MCP connection/configuration examples for the settings page. */
(function(){
  'use strict';

  const settings=document.querySelector('.mcp-settings');
  if(!settings)return;

  const I18N={
    'zh-CN':{
      title:'MCP 配置与连接示例',
      sub:'示例会跟随上方认证方式和字段实时更新。敏感凭据始终使用占位符，不会把已保存的校验值写入示例。',
      endpoint:'MCP Endpoint',metadata:'OAuth Protected Resource Metadata',server:'服务端 JSON 示例',client:'客户端 JSON 示例',curl:'curl 连通性测试',
      serverHint:'可直接参考这一段配置 web.mcp。静态密码、Token 和 API Key 请在上方输入，示例不会显示真实值。',
      clientHint:'适用于常见 Streamable HTTP MCP 客户端；不同客户端的外层字段名可能略有不同。',
      curlHint:'用于验证认证和 MCP initialize。把占位符替换成真实凭据后执行。',
      copy:'复制',copied:'已复制',copyFail:'复制失败',
      inheritNote:'inherit_web 模式下，通用 MCP 客户端通常使用 WebUI Basic 凭据；浏览器会话 Cookie 也可被服务端接受。',
      oauthNote:'OAuth/OIDC 客户端应从授权服务器取得 access token，再以 Bearer Token 访问 /mcp。',
      noneNote:'当前为无认证模式。请只在隔离且可信的网络中使用。'
    },
    'zh-TW':{
      title:'MCP 設定與連線範例',
      sub:'範例會依上方驗證方式與欄位即時更新。敏感憑據一律使用佔位符，不會把已儲存的驗證值寫入範例。',
      endpoint:'MCP Endpoint',metadata:'OAuth Protected Resource Metadata',server:'伺服器 JSON 範例',client:'用戶端 JSON 範例',curl:'curl 連線測試',
      serverHint:'可直接參考這段 web.mcp 設定。靜態密碼、Token 與 API Key 請在上方輸入，範例不會顯示真實值。',
      clientHint:'適用於常見 Streamable HTTP MCP 用戶端；不同用戶端的外層欄位名稱可能略有差異。',
      curlHint:'用來驗證身分驗證與 MCP initialize。執行前請把佔位符換成真實憑據。',
      copy:'複製',copied:'已複製',copyFail:'複製失敗',
      inheritNote:'inherit_web 模式下，一般 MCP 用戶端通常使用 WebUI Basic 憑據；瀏覽器工作階段 Cookie 也可被伺服器接受。',
      oauthNote:'OAuth/OIDC 用戶端應先向授權伺服器取得 access token，再以 Bearer Token 存取 /mcp。',
      noneNote:'目前為無驗證模式。請只在隔離且可信任的網路中使用。'
    },
    en:{
      title:'MCP configuration and connection examples',
      sub:'Examples update with the authentication mode and fields above. Sensitive credentials always use placeholders; saved verifiers are never emitted into examples.',
      endpoint:'MCP Endpoint',metadata:'OAuth Protected Resource Metadata',server:'Server JSON example',client:'Client JSON example',curl:'curl connectivity test',
      serverHint:'Use this as a reference for web.mcp. Enter static passwords, tokens and API keys above; real secret values are never rendered here.',
      clientHint:'Suitable for common Streamable HTTP MCP clients. The outer configuration keys may differ slightly between clients.',
      curlHint:'Checks authentication and MCP initialize. Replace placeholders with real credentials before running it.',
      copy:'Copy',copied:'Copied',copyFail:'Copy failed',
      inheritNote:'With inherit_web, generic MCP clients normally use the WebUI Basic credentials; an authenticated browser session cookie is also accepted by the server.',
      oauthNote:'OAuth/OIDC clients should obtain an access token from the authorization server and call /mcp with it as a Bearer token.',
      noneNote:'Authentication is disabled. Use this only on an isolated trusted network.'
    },
    de:{
      title:'MCP-Konfigurations- und Verbindungsbeispiele',
      sub:'Die Beispiele werden anhand des Authentifizierungsmodus und der Felder oben live aktualisiert. Geheimnisse bleiben Platzhalter; gespeicherte Prüfwerte werden nie ausgegeben.',
      endpoint:'MCP-Endpunkt',metadata:'OAuth Protected Resource Metadata',server:'Server-JSON-Beispiel',client:'Client-JSON-Beispiel',curl:'curl-Verbindungstest',
      serverHint:'Diese Konfiguration dient als Vorlage für web.mcp. Statische Passwörter, Tokens und API-Keys oben eingeben; echte Geheimnisse werden hier nie angezeigt.',
      clientHint:'Geeignet für gängige Streamable-HTTP-MCP-Clients. Äußere Konfigurationsschlüssel können je nach Client leicht abweichen.',
      curlHint:'Prüft Authentifizierung und MCP initialize. Vor dem Ausführen Platzhalter durch echte Zugangsdaten ersetzen.',
      copy:'Kopieren',copied:'Kopiert',copyFail:'Kopieren fehlgeschlagen',
      inheritNote:'Bei inherit_web verwenden allgemeine MCP-Clients normalerweise die WebUI-Basic-Zugangsdaten; ein authentifiziertes Browser-Session-Cookie wird ebenfalls akzeptiert.',
      oauthNote:'OAuth/OIDC-Clients sollten beim Authorization Server ein Access Token beziehen und /mcp damit als Bearer Token aufrufen.',
      noneNote:'Die Authentifizierung ist deaktiviert. Nur in einem isolierten vertrauenswürdigen Netz verwenden.'
    },
    fr:{
      title:'Exemples de configuration et de connexion MCP',
      sub:'Les exemples suivent en temps réel le mode d’authentification et les champs ci-dessus. Les secrets restent des espaces réservés et les vérificateurs enregistrés ne sont jamais affichés.',
      endpoint:'Endpoint MCP',metadata:'OAuth Protected Resource Metadata',server:'Exemple JSON serveur',client:'Exemple JSON client',curl:'Test de connexion curl',
      serverHint:'Utilisez cet exemple comme référence pour web.mcp. Saisissez les mots de passe, tokens et clés API statiques ci-dessus ; les vraies valeurs secrètes ne sont jamais affichées ici.',
      clientHint:'Convient aux clients MCP Streamable HTTP courants. Les clés externes de configuration peuvent varier légèrement selon le client.',
      curlHint:'Vérifie l’authentification et MCP initialize. Remplacez les espaces réservés par les vrais identifiants avant exécution.',
      copy:'Copier',copied:'Copié',copyFail:'Échec de la copie',
      inheritNote:'Avec inherit_web, les clients MCP génériques utilisent normalement les identifiants Basic du WebUI ; un cookie de session navigateur authentifié est également accepté.',
      oauthNote:'Les clients OAuth/OIDC doivent obtenir un access token auprès du serveur d’autorisation puis appeler /mcp avec un Bearer token.',
      noneNote:'L’authentification est désactivée. À utiliser uniquement sur un réseau isolé et fiable.'
    },
    ja:{
      title:'MCP 設定・接続例',
      sub:'上の認証方式と入力内容に合わせて例をリアルタイム更新します。機密資格情報は常にプレースホルダーを使い、保存済み検証値は例に出力しません。',
      endpoint:'MCP Endpoint',metadata:'OAuth Protected Resource Metadata',server:'サーバー JSON 例',client:'クライアント JSON 例',curl:'curl 接続テスト',
      serverHint:'web.mcp の設定例としてそのまま参照できます。静的パスワード、Token、API Key は上で入力し、実際の秘密値はここには表示しません。',
      clientHint:'一般的な Streamable HTTP MCP クライアント向けです。外側の設定キー名はクライアントによって多少異なる場合があります。',
      curlHint:'認証と MCP initialize を確認します。実行前にプレースホルダーを実際の資格情報へ置き換えてください。',
      copy:'コピー',copied:'コピー済み',copyFail:'コピー失敗',
      inheritNote:'inherit_web では、一般的な MCP クライアントは通常 WebUI の Basic 資格情報を使います。認証済みブラウザーのセッション Cookie もサーバーで受け付けます。',
      oauthNote:'OAuth/OIDC クライアントは Authorization Server から access token を取得し、Bearer Token として /mcp に送信します。',
      noneNote:'現在は認証なしです。隔離された信頼済みネットワークでのみ使用してください。'
    }
  };

  const css=document.createElement('style');
  css.textContent=`
    .mcp-examples{margin-top:16px;padding-top:16px;border-top:1px solid var(--border)}
    .mcp-examples-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:12px}
    .mcp-examples-head h4{margin:0 0 4px;font-size:14px}.mcp-examples-head p{margin:0;color:var(--sub);font-size:11px;line-height:1.5}
    .mcp-endpoint-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}.mcp-endpoint-item{min-width:0}.mcp-endpoint-label{display:block;margin-bottom:5px;color:var(--sub);font-size:11px;font-weight:600}
    .mcp-copy-row{display:flex;gap:8px;align-items:stretch}.mcp-copy-row code{display:block;min-width:0;flex:1;overflow:auto;white-space:nowrap;padding:9px 10px;border:1px solid var(--border);border-radius:8px;background:var(--bg);font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
    .mcp-example-card{margin-top:10px;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--bg)}
    .mcp-example-card summary{display:flex;align-items:center;gap:8px;cursor:pointer;padding:10px 12px;font-size:12px;font-weight:700;list-style:none}.mcp-example-card summary::-webkit-details-marker{display:none}.mcp-example-card summary::before{content:'›';font-size:17px;line-height:1;transition:transform .15s ease}.mcp-example-card[open] summary::before{transform:rotate(90deg)}
    .mcp-example-actions{margin-left:auto}.mcp-example-body{padding:0 12px 12px}.mcp-example-body pre{margin:0;max-height:320px;overflow:auto;white-space:pre;tab-size:2;padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--card);font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.mcp-example-hint{margin:8px 0 0;color:var(--sub);font-size:11px;line-height:1.5}
    .mcp-mode-note{margin:10px 0 0;padding:9px 11px;border-radius:8px;background:var(--bg);color:var(--sub);font-size:11px;line-height:1.5}
    @media(max-width:760px){.mcp-endpoint-grid{grid-template-columns:1fr}.mcp-copy-row{align-items:flex-start}.mcp-copy-row code{white-space:normal;overflow-wrap:anywhere}}
  `;
  document.head.appendChild(css);

  const panel=document.createElement('div');
  panel.className='mcp-examples';
  panel.innerHTML=`
    <div class="mcp-examples-head"><div><h4 data-mcp-example-t="title"></h4><p data-mcp-example-t="sub"></p></div></div>
    <div class="mcp-endpoint-grid">
      <div class="mcp-endpoint-item">
        <span class="mcp-endpoint-label" data-mcp-example-t="endpoint"></span>
        <div class="mcp-copy-row"><code id="mcp-example-endpoint"></code><button type="button" class="btn ghost sm" data-copy-target="mcp-example-endpoint"></button></div>
        <span class="mcp-help" id="mcp-example-endpoint-face"></span>
      </div>
      <div class="mcp-endpoint-item" id="mcp-metadata-wrap">
        <span class="mcp-endpoint-label" data-mcp-example-t="metadata"></span>
        <div class="mcp-copy-row"><code id="mcp-example-metadata"></code><button type="button" class="btn ghost sm" data-copy-target="mcp-example-metadata"></button></div>
      </div>
    </div>
    <div class="mcp-mode-note" id="mcp-example-mode-note"></div>
    <details class="mcp-example-card" open>
      <summary><span data-mcp-example-t="client"></span><span class="mcp-example-actions"><button type="button" class="btn ghost sm" data-copy-target="mcp-example-client"></button></span></summary>
      <div class="mcp-example-body"><pre id="mcp-example-client"></pre><p class="mcp-example-hint" data-mcp-example-t="clientHint"></p></div>
    </details>
    <details class="mcp-example-card">
      <summary><span data-mcp-example-t="curl"></span><span class="mcp-example-actions"><button type="button" class="btn ghost sm" data-copy-target="mcp-example-curl"></button></span></summary>
      <div class="mcp-example-body"><pre id="mcp-example-curl"></pre><p class="mcp-example-hint" data-mcp-example-t="curlHint"></p></div>
    </details>
    <details class="mcp-example-card">
      <summary><span data-mcp-example-t="server"></span><span class="mcp-example-actions"><button type="button" class="btn ghost sm" data-copy-target="mcp-example-server"></button></span></summary>
      <div class="mcp-example-body"><pre id="mcp-example-server"></pre><p class="mcp-example-hint" data-mcp-example-t="serverHint"></p></div>
    </details>`;
  settings.appendChild(panel);

  const q=id=>document.getElementById(id);
  const field=id=>q(id);
  const mode=field('mcp-auth-mode');
  if(!mode)return;

  function locale(){const l=document.documentElement.lang||'en';return I18N[l]||I18N.en;}
  // 端点路径跟随配置：内外网面共用同一 path，绝不回落可猜的 /mcp。
  // 未配置时显示 <PATH> 占位，提示用户在设置里生成/填写。
  function endpointPath(){
    const p=value('mcp-path');
    return p||'/<PATH>';
  }
  function endpoint(){
    const base=(window.location.origin&&window.location.origin!=='null'?window.location.origin:'http://HOST:PORT');
    return base+endpointPath();
  }
  // 所在面标注：直接复用部署方式下拉的本地化文本，避免重复 i18n。
  function deployFace(){
    const el=field('mcp-deploy');
    if(!el)return '';
    const opt=el.selectedOptions&&el.selectedOptions[0];
    return opt?opt.textContent:'';
  }
  function metadataEndpoint(){return (window.location.origin&&window.location.origin!=='null'?window.location.origin:'http://HOST:PORT')+'/.well-known/oauth-protected-resource';}
  function value(id,fallback=''){const el=field(id);return el&&el.value.trim()?el.value.trim():fallback;}
  function lines(id){const el=field(id);return el?el.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean):[];}
  function scopes(){const el=field('mcp-scopes');return el?el.value.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean):[];}

  function serverObject(){
    const auth=mode.value||'inherit_web';
    const m={auth_mode:auth};
    if(auth==='basic'){
      m.username=value('mcp-username','mcp-agent');
      m.credential='<MCP_PASSWORD>';
    }else if(auth==='bearer'){
      m.credential='<MCP_BEARER_TOKEN>';
    }else if(auth==='api_key'){
      m.credential='<MCP_API_KEY>';
      m.api_key_header=value('mcp-api-header','X-API-Key');
    }else if(auth==='oauth_jwt'){
      m.oauth={
        jwks_url:value('mcp-jwks','https://idp.example.com/.well-known/jwks.json'),
        issuer:value('mcp-issuer','https://idp.example.com/'),
        audience:value('mcp-audience','tlsvpn-mcp'),
        resource:value('mcp-resource',endpoint()),
        authorization_servers:lines('mcp-servers').length?lines('mcp-servers'):['https://idp.example.com/'],
        required_scopes:scopes().length?scopes():['mcp:read']
      };
    }
    return {web:{mcp:m}};
  }

  function clientObject(){
    const auth=mode.value||'inherit_web';
    const server={type:'streamable-http',url:endpoint()};
    if(auth==='inherit_web')server.headers={Authorization:'Basic <BASE64_WEBUI_USER_PASSWORD>'};
    else if(auth==='basic')server.headers={Authorization:'Basic <BASE64_MCP_USER_PASSWORD>'};
    else if(auth==='bearer')server.headers={Authorization:'Bearer <MCP_BEARER_TOKEN>'};
    else if(auth==='api_key')server.headers={[value('mcp-api-header','X-API-Key')]:'<MCP_API_KEY>'};
    else if(auth==='oauth_jwt')server.headers={Authorization:'Bearer <OAUTH_ACCESS_TOKEN>'};
    return {mcpServers:{tlsvpn:server}};
  }

  function shellQuote(s){return "'"+String(s).replace(/'/g,"'\\''")+"'";}
  function curlExample(){
    const auth=mode.value||'inherit_web';
    const parts=['curl -i -X POST '+shellQuote(endpoint())];
    if(auth==='inherit_web')parts.push("  -u '<WEBUI_USER>:<WEBUI_PASSWORD>'");
    else if(auth==='basic')parts.push("  -u '"+value('mcp-username','mcp-agent')+":<MCP_PASSWORD>'");
    else if(auth==='bearer')parts.push("  -H 'Authorization: Bearer <MCP_BEARER_TOKEN>'");
    else if(auth==='api_key')parts.push("  -H '"+value('mcp-api-header','X-API-Key')+": <MCP_API_KEY>'");
    else if(auth==='oauth_jwt')parts.push("  -H 'Authorization: Bearer <OAUTH_ACCESS_TOKEN>'");
    parts.push("  -H 'Content-Type: application/json'");
    parts.push("  -H 'Accept: application/json, text/event-stream'");
    parts.push("  --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"tlsvpn-webui-test\",\"version\":\"1\"}}}'");
    return parts.join(' \\'+'\n');
  }

  function modeNote(){
    const c=locale();
    const auth=mode.value||'inherit_web';
    if(auth==='inherit_web')return c.inheritNote;
    if(auth==='oauth_jwt')return c.oauthNote;
    if(auth==='none')return c.noneNote;
    return '';
  }

  function renderExamples(){
    q('mcp-example-endpoint').textContent=endpoint();
    const face=deployFace();
    const faceEl=q('mcp-example-endpoint-face');
    if(faceEl){faceEl.textContent=face;faceEl.style.display=face?'':'none';}
    q('mcp-example-metadata').textContent=metadataEndpoint();
    q('mcp-metadata-wrap').style.display=mode.value==='oauth_jwt'?'':'none';
    q('mcp-example-server').textContent=JSON.stringify(serverObject(),null,2);
    q('mcp-example-client').textContent=JSON.stringify(clientObject(),null,2);
    q('mcp-example-curl').textContent=curlExample();
    const note=modeNote();q('mcp-example-mode-note').textContent=note;q('mcp-example-mode-note').style.display=note?'':'none';
  }

  function translate(){
    const c=locale();
    panel.querySelectorAll('[data-mcp-example-t]').forEach(el=>{const k=el.dataset.mcpExampleT;if(c[k]!=null)el.textContent=c[k];});
    panel.querySelectorAll('[data-copy-target]').forEach(btn=>{btn.textContent=c.copy;btn.title=c.copy;});
    renderExamples();
  }

  async function copyText(text){
    if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);return;}
    const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
    const ok=document.execCommand('copy');ta.remove();if(!ok)throw new Error('copy failed');
  }

  panel.addEventListener('click',async ev=>{
    const btn=ev.target.closest('[data-copy-target]');if(!btn)return;
    ev.preventDefault();ev.stopPropagation();
    const target=q(btn.dataset.copyTarget);if(!target)return;
    const c=locale();
    try{await copyText(target.textContent||'');btn.textContent=c.copied;}catch(_){btn.textContent=c.copyFail;}
    setTimeout(()=>{btn.textContent=locale().copy;},1400);
  });

  settings.addEventListener('input',renderExamples);
  settings.addEventListener('change',renderExamples);
  const syncButton=q('mcp-sync');
  if(syncButton)syncButton.addEventListener('click',()=>setTimeout(renderExamples,0));
  const regenButton=q('mcp-path-regen');
  if(regenButton)regenButton.addEventListener('click',()=>setTimeout(renderExamples,0));

  const previousLoad=window.loadConfig;
  if(typeof previousLoad==='function')window.loadConfig=async function(){const r=await previousLoad.apply(this,arguments);renderExamples();return r;};
  const previousSave=window.saveConfig;
  if(typeof previousSave==='function')window.saveConfig=async function(){const r=await previousSave.apply(this,arguments);setTimeout(renderExamples,0);return r;};

  new MutationObserver(translate).observe(document.documentElement,{attributes:true,attributeFilter:['lang']});
  translate();
})();
