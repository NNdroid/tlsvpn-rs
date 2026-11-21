/* MCP authentication settings UI. The JSON editor remains the source of truth. */
(function(){
  'use strict';

  const pane=document.getElementById('pane-settings');
  const editor=document.getElementById('cfg-editor');
  if(!pane||!editor)return;

  const COPY={
    'zh-CN':{
      title:'MCP 认证',sub:'与 WebUI 共用端口；认证策略可独立热更新。',mode:'认证方式',
      modes:{inherit_web:'继承 WebUI 认证',basic:'独立 Basic',bearer:'Bearer Token',api_key:'API Key Header',oauth_jwt:'OAuth / OIDC JWT',none:'无认证'},
      deploy:'部署方式',deploys:{internal:'仅内网',public:'仅公网',both:'内网+公网'},deployLocked:'客户端模式固定为仅内网（无公网 MCP 面）',path:'端点路径',pathHint:'内外网共用；留空则加载时生成随机。路径是端点密钥的一部分，泄露应立即更换。',regen:'重新随机',
      username:'用户名',credential:'新密码 / Token / API Key',credentialHint:'留空表示保留当前凭据；保存成功后状态会显示已配置（凭据本身不可回显）。',configured:'已配置静态凭据',notConfigured:'尚未配置静态凭据',
      apiHeader:'API Key Header',jwks:'JWKS URL',issuer:'Issuer',audience:'Audience',resource:'Resource URL',servers:'Authorization Servers',scopes:'Required Scopes',
      serversHint:'每行一个 URL',scopesHint:'空格或逗号分隔',sync:'从 JSON 刷新',generate:'生成随机凭据',generated:'已生成 32 字节随机凭据',
      oauthHint:'JWT access token 将校验签名、exp、issuer、audience 和所需 scope；JWKS 仅允许 HTTPS（本机回环 HTTP 除外）。',noneWarn:'警告：none 会让 /mcp 无需认证，仅适合隔离可信网络。'
    },
    'zh-TW':{
      title:'MCP 驗證',sub:'與 WebUI 共用連接埠；驗證策略可獨立熱更新。',mode:'驗證方式',
      modes:{inherit_web:'沿用 WebUI 驗證',basic:'獨立 Basic',bearer:'Bearer Token',api_key:'API Key Header',oauth_jwt:'OAuth / OIDC JWT',none:'無驗證'},
      deploy:'部署方式',deploys:{internal:'僅內網',public:'僅公網',both:'內網+公網'},deployLocked:'用戶端模式固定為僅內網（無公網 MCP 面）',path:'端點路徑',pathHint:'內外網共用；留空則載入時產生隨機。路徑是端點金鑰的一部分，洩漏應立即更換。',regen:'重新隨機',
      username:'使用者名稱',credential:'新密碼 / Token / API Key',credentialHint:'留空表示保留目前憑據；儲存成功後狀態會顯示已設定（憑據本身不可回顯）。',configured:'已設定靜態憑據',notConfigured:'尚未設定靜態憑據',
      apiHeader:'API Key Header',jwks:'JWKS URL',issuer:'Issuer',audience:'Audience',resource:'Resource URL',servers:'Authorization Servers',scopes:'Required Scopes',
      serversHint:'每行一個 URL',scopesHint:'以空格或逗號分隔',sync:'從 JSON 重新整理',generate:'產生隨機憑據',generated:'已產生 32 位元組隨機憑據',
      oauthHint:'JWT access token 會驗證簽章、exp、issuer、audience 與必要 scope；JWKS 僅允許 HTTPS（本機回環 HTTP 除外）。',noneWarn:'警告：none 會讓 /mcp 不需驗證，只適合隔離可信網路。'
    },
    en:{
      title:'MCP Authentication',sub:'Shares the WebUI port; the MCP authentication policy hot-reloads independently.',mode:'Authentication mode',
      modes:{inherit_web:'Inherit WebUI auth',basic:'Independent Basic',bearer:'Bearer Token',api_key:'API Key Header',oauth_jwt:'OAuth / OIDC JWT',none:'No authentication'},
      deploy:'Deploy scope',deploys:{internal:'Internal only',public:'Public only',both:'Internal + public'},deployLocked:'Client mode is fixed to internal-only (no public MCP face)',path:'Endpoint path',pathHint:'Shared by the internal and public faces. Leave empty to generate a random one on load. The path is part of the endpoint secret; rotate it immediately if leaked.',regen:'Randomize',
      username:'Username',credential:'New password / token / API key',credentialHint:'Leave empty to keep the current credential. Once saved, the status shows that a credential is configured (the secret itself is never echoed back).',configured:'Static credential configured',notConfigured:'No static credential configured',
      apiHeader:'API Key Header',jwks:'JWKS URL',issuer:'Issuer',audience:'Audience',resource:'Resource URL',servers:'Authorization Servers',scopes:'Required Scopes',
      serversHint:'One URL per line',scopesHint:'Space or comma separated',sync:'Reload from JSON',generate:'Generate random credential',generated:'Generated a 32-byte random credential',
      oauthHint:'JWT access tokens are checked for signature, exp, issuer, audience and required scopes. JWKS must use HTTPS except for loopback tests.',noneWarn:'Warning: none leaves /mcp unauthenticated and is only suitable for isolated trusted networks.'
    },
    de:{
      title:'MCP-Authentifizierung',sub:'Nutzt den WebUI-Port; die MCP-Authentifizierung wird unabhängig per Hot-Reload aktualisiert.',mode:'Authentifizierungsmodus',
      modes:{inherit_web:'WebUI-Authentifizierung übernehmen',basic:'Eigenes Basic',bearer:'Bearer-Token',api_key:'API-Key-Header',oauth_jwt:'OAuth / OIDC JWT',none:'Keine Authentifizierung'},
      deploy:'Bereitstellung',deploys:{internal:'Nur intern',public:'Nur öffentlich',both:'Intern + öffentlich'},deployLocked:'Im Client-Modus ist nur intern festgelegt (keine öffentliche MCP-Seite)',path:'Endpunktpfad',pathHint:'Von interner und öffentlicher Seite gemeinsam genutzt. Leer lassen, um beim Laden einen zufälligen Pfad zu erzeugen. Der Pfad ist Teil des Endpunkt-Geheimnisses; bei Leck sofort rotieren.',regen:'Neu zufällig',
      username:'Benutzername',credential:'Neues Passwort / Token / API-Key',credentialHint:'Leer lassen, um den aktuellen Wert zu behalten. Nach dem Speichern zeigt der Status eine konfigurierte Zugangsmeldung an (das Geheimnis selbst wird nie zurückgespiegelt).',configured:'Statische Zugangsdaten konfiguriert',notConfigured:'Keine statischen Zugangsdaten konfiguriert',
      apiHeader:'API-Key-Header',jwks:'JWKS-URL',issuer:'Issuer',audience:'Audience',resource:'Resource-URL',servers:'Authorization Servers',scopes:'Erforderliche Scopes',
      serversHint:'Eine URL pro Zeile',scopesHint:'Durch Leerzeichen oder Komma getrennt',sync:'Aus JSON neu laden',generate:'Zufälligen Schlüssel erzeugen',generated:'32-Byte-Zufallswert erzeugt',
      oauthHint:'JWT-Access-Tokens werden auf Signatur, exp, issuer, audience und Scopes geprüft. JWKS muss HTTPS nutzen, außer bei Loopback-Tests.',noneWarn:'Warnung: none lässt /mcp ohne Authentifizierung und ist nur für isolierte vertrauenswürdige Netze geeignet.'
    },
    fr:{
      title:'Authentification MCP',sub:'Partage le port WebUI ; la stratégie MCP est mise à jour à chaud indépendamment.',mode:"Mode d’authentification",
      modes:{inherit_web:'Hériter de WebUI',basic:'Basic indépendant',bearer:'Jeton Bearer',api_key:'En-tête API Key',oauth_jwt:'OAuth / OIDC JWT',none:'Aucune authentification'},
      deploy:'Portée de déploiement',deploys:{internal:'Interne uniquement',public:'Public uniquement',both:'Interne + public'},deployLocked:'Le mode client est fixé à interne uniquement (pas de face MCP publique)',path:'Chemin d’endpoint',pathHint:'Partagé par les faces interne et publique. Laisser vide pour générer un chemin aléatoire au chargement. Le chemin fait partie du secret d’endpoint ; à faire tourner immédiatement en cas de fuite.',regen:'Réaléatoriser',
      username:"Nom d’utilisateur",credential:'Nouveau mot de passe / token / clé API',credentialHint:'Laisser vide pour conserver la valeur actuelle. Après l’enregistrement, le statut indique qu’un secret est configuré (le secret lui-même n’est jamais renvoyé).',configured:'Secret statique configuré',notConfigured:'Aucun secret statique configuré',
      apiHeader:'En-tête API Key',jwks:'URL JWKS',issuer:'Issuer',audience:'Audience',resource:'URL Resource',servers:'Authorization Servers',scopes:'Scopes requis',
      serversHint:'Une URL par ligne',scopesHint:'Séparés par espace ou virgule',sync:'Recharger depuis JSON',generate:'Générer un secret aléatoire',generated:'Secret aléatoire de 32 octets généré',
      oauthHint:'Les JWT sont vérifiés pour la signature, exp, issuer, audience et les scopes requis. JWKS exige HTTPS sauf en boucle locale.',noneWarn:'Attention : none laisse /mcp sans authentification et ne convient qu’aux réseaux isolés de confiance.'
    },
    ja:{
      title:'MCP 認証',sub:'WebUI と同じポートを使用し、MCP 認証ポリシーは独立してホット更新できます。',mode:'認証方式',
      modes:{inherit_web:'WebUI 認証を継承',basic:'独立 Basic',bearer:'Bearer Token',api_key:'API Key Header',oauth_jwt:'OAuth / OIDC JWT',none:'認証なし'},
      deploy:'配備範囲',deploys:{internal:'内部のみ',public:'公開のみ',both:'内部＋公開'},deployLocked:'クライアントモードは内部のみに固定（公開 MCP 面なし）',path:'エンドポイントパス',pathHint:'内部・公開面で共有。空欄なら読込時にランダム生成します。パスはエンドポイントの秘密の一部であり、漏洩時は直ちに交換してください。',regen:'再ランダム',
      username:'ユーザー名',credential:'新しいパスワード / Token / API Key',credentialHint:'空欄なら現在の資格情報を維持します。保存が成功すると、状態に「設定済み」と表示されます（秘密情報自体は返されません）。',configured:'静的資格情報を設定済み',notConfigured:'静的資格情報は未設定',
      apiHeader:'API Key Header',jwks:'JWKS URL',issuer:'Issuer',audience:'Audience',resource:'Resource URL',servers:'Authorization Servers',scopes:'Required Scopes',
      serversHint:'1 行に 1 URL',scopesHint:'空白またはカンマ区切り',sync:'JSON から再読込',generate:'ランダム資格情報を生成',generated:'32 バイトのランダム資格情報を生成しました',
      oauthHint:'JWT access token の署名、exp、issuer、audience、必要な scope を検証します。JWKS はループバックテスト以外 HTTPS 必須です。',noneWarn:'警告: none では /mcp が認証なしになります。隔離された信頼済みネットワーク専用です。'
    }
  };

  const css=document.createElement('style');
  css.textContent=`
    .mcp-settings{margin:12px 0 16px;padding:16px;border:1px solid var(--border);border-radius:12px;background:var(--card)}
    .mcp-settings-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:14px}.mcp-settings-head h3{margin:0 0 4px;font-size:16px}.mcp-settings-head p{margin:0;color:var(--sub);font-size:12px}.mcp-settings-actions{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
    .mcp-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.mcp-field{display:flex;flex-direction:column;gap:6px}.mcp-field.wide{grid-column:1/-1}.mcp-field label{font-size:12px;color:var(--sub);font-weight:600}.mcp-field input,.mcp-field select,.mcp-field textarea{width:100%;box-sizing:border-box;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 10px;font:inherit}.mcp-field textarea{min-height:74px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.mcp-help{font-size:11px;color:var(--sub);line-height:1.45}.mcp-status{font-size:11px}.mcp-warn{padding:9px 11px;border:1px solid var(--warn);border-radius:8px;color:var(--warn);font-size:12px;grid-column:1/-1}.mcp-secret-row{display:flex;gap:8px}.mcp-secret-row input{flex:1}
    @media(max-width:760px){.mcp-grid{grid-template-columns:1fr}.mcp-field.wide{grid-column:auto}.mcp-settings-head{flex-direction:column}.mcp-settings-actions{margin-left:0}}
  `;
  document.head.appendChild(css);

  const root=document.createElement('div');
  root.className='mcp-settings';
  root.innerHTML=`
    <div class="mcp-settings-head">
      <div><h3 data-mcp-t="title"></h3><p data-mcp-t="sub"></p></div>
      <div class="mcp-settings-actions">
        <button type="button" class="btn ghost sm" id="mcp-sync"></button>
        <button type="button" class="btn ghost sm" id="mcp-generate"></button>
      </div>
    </div>
    <div class="mcp-grid">
      <div class="mcp-field wide"><label data-mcp-t="mode"></label><select id="mcp-auth-mode">
        <option value="inherit_web"></option><option value="basic"></option><option value="bearer"></option><option value="api_key"></option><option value="oauth_jwt"></option><option value="none"></option>
      </select></div>
      <div class="mcp-field"><label data-mcp-t="deploy"></label><select id="mcp-deploy">
        <option value="internal"></option><option value="public"></option><option value="both"></option>
      </select><div class="mcp-help" id="mcp-deploy-lock" data-mcp-t="deployLocked" style="display:none"></div></div>
      <div class="mcp-field wide"><label data-mcp-t="path"></label><div class="mcp-secret-row"><input id="mcp-path" autocomplete="off" spellcheck="false"><button type="button" class="btn ghost sm" id="mcp-path-regen"></button></div><div class="mcp-help" data-mcp-t="pathHint"></div></div>
      <div class="mcp-field" data-mcp-basic><label data-mcp-t="username"></label><input id="mcp-username" autocomplete="username"></div>
      <div class="mcp-field" data-mcp-api><label data-mcp-t="apiHeader"></label><input id="mcp-api-header" value="X-API-Key"></div>
      <div class="mcp-field wide" data-mcp-static><label data-mcp-t="credential"></label><div class="mcp-secret-row"><input id="mcp-credential" type="password" autocomplete="new-password"><button type="button" class="btn ghost sm" id="mcp-secret-show">👁</button></div><div class="mcp-status" id="mcp-credential-status"></div><div class="mcp-help" data-mcp-t="credentialHint"></div></div>
      <div class="mcp-field wide" data-mcp-oauth><div class="mcp-help" data-mcp-t="oauthHint"></div></div>
      <div class="mcp-field wide" data-mcp-oauth><label data-mcp-t="jwks"></label><input id="mcp-jwks" inputmode="url"></div>
      <div class="mcp-field" data-mcp-oauth><label data-mcp-t="issuer"></label><input id="mcp-issuer" inputmode="url"></div>
      <div class="mcp-field" data-mcp-oauth><label data-mcp-t="audience"></label><input id="mcp-audience"></div>
      <div class="mcp-field wide" data-mcp-oauth><label data-mcp-t="resource"></label><input id="mcp-resource" inputmode="url"></div>
      <div class="mcp-field" data-mcp-oauth><label data-mcp-t="servers"></label><textarea id="mcp-servers"></textarea><div class="mcp-help" data-mcp-t="serversHint"></div></div>
      <div class="mcp-field" data-mcp-oauth><label data-mcp-t="scopes"></label><textarea id="mcp-scopes"></textarea><div class="mcp-help" data-mcp-t="scopesHint"></div></div>
      <div class="mcp-warn" id="mcp-none-warn" data-mcp-t="noneWarn"></div>
    </div>`;
  editor.parentNode.insertBefore(root,editor);

  const q=id=>document.getElementById(id);
  const mode=q('mcp-auth-mode'),deploy=q('mcp-deploy'),path=q('mcp-path');
  const username=q('mcp-username'),credential=q('mcp-credential'),apiHeader=q('mcp-api-header');
  const jwks=q('mcp-jwks'),issuer=q('mcp-issuer'),audience=q('mcp-audience'),resource=q('mcp-resource'),servers=q('mcp-servers'),scopes=q('mcp-scopes');
  // credConfigured：是否已配置静态凭据（GET 回显 credential_set 派生布尔）。
  // 此前的 currentVerifier 设计（把校验器存进变量、空输入时回写 credential）
  // 在凭据语义下是危险的：校验器一旦被回写成 credential，认证直接损坏。
  // 空输入时不触碰 m.credential——编辑器里是脱敏后的 ""（后端空值=保留现有）。
  let credConfigured=false;

  function lang(){const l=document.documentElement.lang||'en';return COPY[l]||COPY.en;}
  function translate(){
    const c=lang();
    root.querySelectorAll('[data-mcp-t]').forEach(el=>{const k=el.dataset.mcpT;if(c[k]!=null)el.textContent=c[k];});
    Array.from(mode.options).forEach(o=>o.textContent=c.modes[o.value]||o.value);
    Array.from(deploy.options).forEach(o=>o.textContent=c.deploys[o.value]||o.value);
    q('mcp-sync').textContent=c.sync;q('mcp-generate').textContent=c.generate;q('mcp-path-regen').textContent=c.regen;
    q('mcp-credential-status').textContent=credConfigured?c.configured:c.notConfigured;
  }
  function updateVisibility(){
    const v=mode.value;
    root.querySelectorAll('[data-mcp-basic]').forEach(el=>el.style.display=v==='basic'?'':'none');
    root.querySelectorAll('[data-mcp-api]').forEach(el=>el.style.display=v==='api_key'?'':'none');
    root.querySelectorAll('[data-mcp-static]').forEach(el=>el.style.display=['basic','bearer','api_key'].includes(v)?'':'none');
    root.querySelectorAll('[data-mcp-oauth]').forEach(el=>el.style.display=v==='oauth_jwt'?'':'none');
    q('mcp-none-warn').style.display=v==='none'?'':'none';
  }
  function parseEditor(){try{return JSON.parse(editor.value||'{}');}catch(_){return null;}}
  // 客户端模式没有公网 MCP 面（后端 applyDefaults 强制 deploy=internal）：
  // 部署方式固定为仅内网并禁用选择，避免面板显示实际不可用的选项。
  function applyDeployLock(isClient){
    deploy.disabled=!!isClient;
    if(isClient)deploy.value='internal';
    const lock=q('mcp-deploy-lock');
    if(lock)lock.style.display=isClient?'':'none';
  }
  function fromEditor(){
    const cfg=parseEditor();if(!cfg)return false;
    const m=cfg.web?.mcp||{};
    mode.value=m.auth_mode||'inherit_web';if(!mode.value)mode.value='inherit_web';
    deploy.value=m.deploy||'internal';if(!deploy.value)deploy.value='internal';
    applyDeployLock(cfg.mode==='client');
    path.value=m.path||'';
    username.value=m.username||'';apiHeader.value=m.api_key_header||'X-API-Key';
    credConfigured=!!m.credential_set;credential.value='';
    const o=m.oauth||{};jwks.value=o.jwks_url||'';issuer.value=o.issuer||'';audience.value=o.audience||'';resource.value=o.resource||'';
    servers.value=(o.authorization_servers||[]).join('\n');scopes.value=(o.required_scopes||[]).join(' ');
    translate();updateVisibility();return true;
  }
  function toEditor(){
    const cfg=parseEditor();if(!cfg)return false;
    cfg.web=cfg.web||{};cfg.web.mcp=cfg.web.mcp||{};
    const m=cfg.web.mcp;m.auth_mode=mode.value||'inherit_web';m.deploy=deploy.disabled?'internal':(deploy.value||'internal');m.path=path.value.trim();m.username=username.value.trim();m.api_key_header=(apiHeader.value||'X-API-Key').trim();
    // 新凭据只在输入框有值时写入；空输入不触碰 m.credential——编辑器里是
    // 脱敏后的 ""（后端空值=保留现有凭据）。绝不能把任何校验器/派生量回写
    // 进 credential：那会把校验器变成真实凭据（认证损坏）。
    const fresh=credential.value;if(fresh)m.credential=fresh;
    m.oauth=m.oauth||{};m.oauth.jwks_url=jwks.value.trim();m.oauth.issuer=issuer.value.trim();m.oauth.audience=audience.value.trim();m.oauth.resource=resource.value.trim();
    m.oauth.authorization_servers=servers.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    m.oauth.required_scopes=scopes.value.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean);
    editor.value=JSON.stringify(cfg,null,2);return true;
  }

  root.addEventListener('change',ev=>{if(ev.target!==credential)toEditor();updateVisibility();});
  root.addEventListener('input',ev=>{if(ev.target!==credential&&ev.target.tagName!=='TEXTAREA')toEditor();});
  q('mcp-sync').onclick=()=>fromEditor();
  q('mcp-generate').onclick=()=>{
    const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);
    credential.value=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    credential.type='text';toEditor();
    q('mcp-credential-status').textContent=lang().generated;
    // 生成后短暂可见方便复制/核对，随后自动回到密文；用户手动点过👁则尊重
    // 手动状态，失焦也立即收起。绝不把 32 字节凭据永久明文留在屏幕上。
    clearTimeout(revealTimer);
    revealTimer=setTimeout(hideCredential,20000);
  };
  let revealTimer=null;
  function hideCredential(){
    clearTimeout(revealTimer);revealTimer=null;
    if(credential.type==='text'&&!credential.matches(':focus'))credential.type='password';
  }
  credential.addEventListener('blur',hideCredential);
  q('mcp-secret-show').onclick=()=>{clearTimeout(revealTimer);credential.type=credential.type==='password'?'text':'password';};
  q('mcp-path-regen').onclick=()=>{
    const bytes=new Uint8Array(10);crypto.getRandomValues(bytes);
    path.value='/'+Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    toEditor();
  };

  // JSON 编辑器是唯一事实来源：用户在编辑器里手动改 web.mcp.* 字段时，MCP
  // 面板输入框必须实时跟随，否则「渲染旧值、JSON 新值」分裂。programmatic 的
  // editor.value= 赋值（loadConfig / 保存回写）不触发 input，由下方包装负责；
  // 这里只覆盖用户手动键入/粘贴。fromEditor 改 DOM 值不触发 change/input
  // （programmatic set 不发事件），不会与 root 的 change→toEditor 写回循环。
  editor.addEventListener('input',fromEditor);

  const originalLoad=window.loadConfig;
  if(typeof originalLoad==='function')window.loadConfig=async function(){const r=await originalLoad.apply(this,arguments);fromEditor();return r;};
  const originalSave=window.saveConfig;
  // 保存（无论是否热应用）后都回填 fromEditor：仅保存时编辑器保留用户输入值，
  // MCP 面板输入框须与之对齐，否则「渲染旧值、JSON 新值」分裂。此前只在
  // apply=true 时回填，仅保存后 MCP 面板停在旧值。
  if(typeof originalSave==='function')window.saveConfig=async function(){toEditor();const r=await originalSave.apply(this,arguments);setTimeout(fromEditor,0);return r;};

  // 兜底：loadConfig / 保存回写对 editor.value 是 programmatic 赋值（不触发
  // input），且 window.loadConfig 被后续脚本（mcp-examples）再次包装——若链上
  // 任一包装未保存 previousLoad，fromEditor 就不会执行，MCP 面板停在旧值。
  // 轮询检测 editor 内容变化，任何来源的写入都保证 fromEditor 回填。
  let lastEditorValue=editor.value;
  setInterval(function(){if(editor.value!==lastEditorValue){lastEditorValue=editor.value;fromEditor();}},400);

  new MutationObserver(translate).observe(document.documentElement,{attributes:true,attributeFilter:['lang']});
  translate();updateVisibility();fromEditor();
})();
