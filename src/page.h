#pragma once
// Dashboard HTML for the ProDuckX-DNS web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>ProDuckX-DNS</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
/* bảng client: không cho MAC/IP xuống dòng, cuộn ngang khi màn hình hẹp */
.tw{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:8px;margin-bottom:18px}
.tw table{margin-bottom:0}
#ct th,#ct td{white-space:nowrap}
#ct td:first-child{white-space:normal;word-break:break-all;min-width:130px}
#ct td:nth-child(2){font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#8b949e}
/* lịch sử: tối đa 10 dòng hiển thị, cuộn dọc khi nhiều hơn */
.hist{max-height:352px;overflow-y:auto;border-radius:8px;margin-bottom:18px}
.hist table{margin-bottom:0}
.hist thead th{position:sticky;top:0;z-index:1}
#ht td:first-child{word-break:break-all}
</style></head><body>
<header><h1>🛡️ ProDuckX-DNS <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b>Default credentials in use.</b> WEB_PASS/OTA_PASS in <code>secrets.h</code> are still the placeholder values — anyone can read them in the public repo. Set real values and reflash.
</div>
<div class=cards id=sys></div>
<h2>CLIENTS</h2><div class=tw><table id=ct><thead><tr><th>Client</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody></tbody></table></div>
<h2>CUSTOM BLOCKED DOMAINS</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom()>Block domain</button></div>
<table id=cl><tbody></tbody></table>
<h2>WHITELIST &mdash; ALWAYS ALLOWED</h2>
<div style=margin-bottom:8px><input id=wdom placeholder="analytics.example.com" size=30><button onclick=addWhite()>Allow domain</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:6px">whitelist wins over the blocklist: the domain and its subdomains are never blocked</div>
<table id=wl><tbody></tbody></table>
<h2>BLOCKLIST &mdash; UPLOAD</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Upload blocklist</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB</div>
<h2>BLOCKLIST &mdash; REMOTE AUTO-UPDATE</h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> every <input id=uiv size=2 value=24>h
<button onclick=saveUpd()>Save</button> <button onclick=fetchNow()>Fetch now</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">device pulls a prebuilt <code>blocklist.bin</code> on a schedule (e.g. a GitHub release asset). last: <span id=ustat>&mdash;</span></div>
<h2>NETWORK &mdash; STATIC IP</h2>
<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin-bottom:8px">
  <div><label style="display:block;font-size:12px;color:#8b949e;margin-bottom:3px">IP Address</label><input id=netip placeholder="192.168.1.50" size=14></div>
  <div><label style="display:block;font-size:12px;color:#8b949e;margin-bottom:3px">Gateway</label><input id=netgw placeholder="192.168.1.1" size=14></div>
  <div><label style="display:block;font-size:12px;color:#8b949e;margin-bottom:3px">Subnet Mask</label><input id=netsn placeholder="255.255.255.0" size=14></div>
  <div><label style="display:block;font-size:12px;color:#8b949e;margin-bottom:3px">DNS Server</label><input id=netdns placeholder="1.1.1.1" size=14></div>
  <div style="margin-bottom:2px"><button onclick=saveIP()>Save</button> <button onclick=setDhcp()>Use DHCP</button></div>
</div>
<div style="margin-bottom:6px"><span id=netmsg style="color:#8b949e;font-size:12px"></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">applies after a reboot. currently: <span id=netstate>&mdash;</span></div>
<h2>BLOCKED PAGE REDIRECT</h2>
<div style=margin-bottom:6px><input id=burl placeholder="0.0.0.0 (default) or https://block.mydomain.com" size=40>
<button onclick=saveBlockUrl()>Save</button> <button onclick=resetBlockUrl()>Reset (0.0.0.0)</button> <span id=bmsg style=color:#8b949e></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">default is 0.0.0.0. Enter a redirect URL (e.g. <code>https://block.mydomain.com</code>) to show when a domain is blocked.</div>
<h2>WIFI</h2>
<div style=margin-bottom:18px><button onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()">Forget WiFi</button></div>
<h2>RECENTLY BLOCKED</h2>
<div class=hist><table id=ht><thead><tr><th>Domain</th><th>Client</th><th>When</th></tr></thead><tbody></tbody></table></div>
</div><script>
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'produckx-adblock'}
async function load(){let r=await fetch('/stats.json');if(r.status==401){location.href='/login';return;}let s=await r.json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.defcreds?'block':'none';
sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['Blocklist domains',fmt(s.domains),''],
['Clients',s.clients.length,''],['CPU',(s.cpu??0)+'%',''],['RAM',(s.ram??0)+'%',''],['Uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${c.ip}">${c.banned?'Unban':'Ban'}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
wl.tBodies[0].innerHTML=s.white.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=wrm data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
ht.tBodies[0].innerHTML=s.hist.map(h=>`<tr><td>${esc(h.d)}</td><td>${h.ip}</td><td>${h.t<60?h.t+'s ago':Math.round(h.t/60)+'m ago'}</td></tr>`).join('')||'<tr><td colspan=3 style=color:#8b949e>nothing blocked yet</td></tr>';
netstate.textContent=s.staticip?'static':'DHCP';
if(!netEdited){netip.value=s.netip||'';netgw.value=s.netgw||'';netsn.value=s.netsubnet||'';netdns.value=s.netdns||'';}
if(document.activeElement!=burl)burl.value=s.blockurl||'';
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function addWhite(){let d=wdom.value.trim();if(d){fetch('/addwhite?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{wdom.value='';load()})}}
wl.addEventListener('click',e=>{if(e.target.classList.contains('wrm'))fetch('/unwhite?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
let netEdited=false;
[netip,netgw,netsn,netdns].forEach(el=>el.addEventListener('input',()=>{netEdited=true;}));
function saveIP(){let ip=netip.value.trim(),gw=netgw.value.trim(),sn=netsn.value.trim(),dns=netdns.value.trim();
if(!ip||!gw||!sn||!dns){netmsg.textContent='fill all four fields';return;}
netmsg.textContent='saving...';
netEdited=false;
fetch('/setip?ip='+encodeURIComponent(ip)+'&gw='+encodeURIComponent(gw)+'&subnet='+encodeURIComponent(sn)+'&dns='+encodeURIComponent(dns),{headers:CSRF_HDRS})
.then(async r=>{netmsg.textContent=r.ok?'✓ saved, rebooting to apply':'✗ '+await r.text()}).catch(()=>netmsg.textContent='✓ rebooting...');}
function setDhcp(){if(!confirm('Switch back to DHCP and reboot?'))return;netmsg.textContent='saving...';
fetch('/setdhcp',{headers:CSRF_HDRS}).then(async r=>{netmsg.textContent=r.ok?'✓ rebooting':'✗ '+await r.text()}).catch(()=>netmsg.textContent='✓ rebooting...');}
function saveBlockUrl(){let u=burl.value.trim();bmsg.textContent='saving...';
fetch('/setblockurl?u='+encodeURIComponent(u),{headers:CSRF_HDRS}).then(r=>{bmsg.textContent=r.ok?'✓ saved':'✗ failed';load();});}
function resetBlockUrl(){burl.value='0.0.0.0';saveBlockUrl();}
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
load();setInterval(load,3000);
</script></body></html>)HTML";
