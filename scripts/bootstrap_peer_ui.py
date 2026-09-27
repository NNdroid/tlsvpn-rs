from pathlib import Path
p=Path('src/api.rs')
s=p.read_text()

def rep(old,new,n=1):
    global s
    if s.count(old)<n:
        raise SystemExit(f'expected {n}, got {s.count(old)} for {old[:100]!r}')
    s=s.replace(old,new,n)

rep("function onoff(b){return b?'<span class=\"badge b-on\">开启</span>':'<span class=\"badge b-off\">关闭</span>';}",
    "function peerSummary(p){if(!p)return '';const a=[];if(p.hostname)a.push(p.hostname);const iv=[p.implementation,p.version].filter(Boolean).join(' ');if(iv)a.push(iv);const plat=[p.os,p.os_version,p.arch].filter(Boolean).join(' ');if(plat)a.push(plat);if(p.kernel)a.push('kernel '+p.kernel);return a.join(' · ');}\nfunction onoff(b){return b?'<span class=\"badge b-on\">开启</span>':'<span class=\"badge b-off\">关闭</span>';}",1)

rep("  const s=data.system||{},c=data.cfg||{},g=data.negotiate||{},b=g.brutal||{},tls=g.tls||{},bs=data.brutal_system||{},mem=data.mem||{};",
    "  const s=data.system||{},c=data.cfg||{},g=data.negotiate||{},b=g.brutal||{},tls=g.tls||{},bs=data.brutal_system||{},mem=data.mem||{},peer=data.peer||{};",1)

rep("  document.getElementById('st-neg').innerHTML=kvRows([\n    ['协议版本','v'+(g.protocol_version||'-')],",
    "  const peerLine=peerSummary(peer);\n  document.getElementById('st-neg').innerHTML=kvRows([\n    ['对端',peerLine||'-'],\n    ['协议版本','v'+(g.protocol_version||'-')],",1)

old="tbody+='<tr><td title=\"'+esc(id)+'\">'+esc(sid)+'</td><td>'+esc(c.ipv4||'-')+'</td>"
new="tbody+='<tr><td title=\"'+esc(id)+'\">'+esc(sid)+(c.peer_info&&c.peer_info.hostname?'<br><span class=\"dim\">'+esc(c.peer_info.hostname)+'</span>':'')+'</td><td>'+esc(c.ipv4||'-')+'</td>"
rep(old,new,1)

p.write_text(s)
