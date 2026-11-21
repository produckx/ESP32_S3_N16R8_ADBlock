#pragma once
// Dashboard HTML for the ProDuckX-DNS web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
// Giao diện dùng CDN (Tailwind, Chart.js, DataTables, Font Awesome) — chỉ áp
// dụng cho dashboard (client ở LAN có internet). Trang setup AP dùng CSS nhúng.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang=vi><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><meta name=color-scheme content=dark>
<title>ProDuckX-DNS</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel=stylesheet href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<link rel=stylesheet href="https://cdn.datatables.net/2.0.8/css/dataTables.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/2.0.8/js/dataTables.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
body{background:radial-gradient(1200px 600px at 10% -10%,#0b2942 0,transparent 55%),radial-gradient(900px 500px at 100% 0,#1e1b4b 0,transparent 50%),#020617}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.anim{animation:fadeUp .45s ease both}
.glass{background:rgba(15,23,42,.72);backdrop-filter:blur(10px);border:1px solid #1e293b}
.dataTables_wrapper{color:#cbd5e1}
.dataTables_wrapper .dt-search input,.dataTables_wrapper select{background:#0f172a;border:1px solid #334155;border-radius:.5rem;padding:.4rem .7rem;color:#e2e8f0}
table.dataTable tbody tr{background:transparent!important}
table.dataTable tbody tr:hover{background:#1e293b!important}
table.dataTable thead th{color:#94a3b8!important;border-bottom:1px solid #334155!important;background:transparent!important}
table.dataTable td{border-bottom:1px solid #1e293b!important}
.dataTables_wrapper .dt-info,.dataTables_wrapper .dt-length{color:#64748b;font-size:12px}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#334155;border-radius:6px}
</style></head>
<body class="min-h-screen text-slate-200 antialiased">
<header class="sticky top-0 z-20 glass border-b border-slate-800">
  <div class="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
    <div class="w-10 h-10 rounded-xl bg-emerald-500/15 text-emerald-400 grid place-items-center text-xl"><i class="fa-solid fa-shield-halved"></i></div>
    <div>
      <h1 class="text-lg font-semibold leading-tight">ProDuckX-DNS <span id=host class="text-emerald-400 text-sm font-normal"></span></h1>
      <p class="text-[11px] text-slate-500">DNS sinkhole · ESP32-S3</p>
    </div>
    <div class="ml-auto flex items-center gap-2 text-xs text-slate-400">
      <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span><span>online</span>
    </div>
  </div>
</header>
<div class="max-w-7xl mx-auto px-4 py-6 space-y-6">

<div id=credwarn class="hidden rounded-xl border border-rose-600/60 bg-rose-950/40 text-rose-200 px-4 py-3 text-sm anim">
  <i class="fa-solid fa-triangle-exclamation mr-1"></i> <b>Default credentials in use.</b> WEB_PASS/OTA_PASS trong <code>secrets.h</code> vẫn là giá trị mặc định. Hãy đổi rồi nạp lại.
</div>

<div class=grid id=sys></div>

<div class="grid lg:grid-cols-3 gap-4">
  <div class="glass rounded-2xl p-4 anim">
    <h2 class="text-xs uppercase tracking-wider text-slate-400 mb-2">Blocked vs Allowed</h2>
    <div class="h-56"><canvas id=chartTotals></canvas></div>
  </div>
  <div class="glass rounded-2xl p-4 anim lg:col-span-2">
    <h2 class="text-xs uppercase tracking-wider text-slate-400 mb-2">Top clients by blocked</h2>
    <div class="h-56"><canvas id=chartClients></canvas></div>
  </div>
</div>

<section class="glass rounded-2xl p-4 anim">
  <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-users text-sky-400"></i><h2 class="font-semibold">Clients</h2></div>
  <div class="overflow-x-auto"><table id=ct class="w-full text-sm">
    <thead><tr><th>Client</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody></tbody>
  </table></div>
</section>

<div class="grid md:grid-cols-2 gap-4">
  <section class="glass rounded-2xl p-4 anim">
    <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-ban text-rose-400"></i><h2 class="font-semibold">Custom blocked</h2></div>
    <div class="flex gap-2 mb-3">
      <input id=dom placeholder="ads.example.com" class="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm">
      <button onclick=addDom() class="rounded-lg bg-rose-600 hover:bg-rose-500 px-3 py-2 text-sm font-medium text-white"><i class="fa-solid fa-plus mr-1"></i>Block</button>
    </div>
    <div class="max-h-64 overflow-y-auto"><table id=cl class="w-full text-sm"><tbody></tbody></table></div>
  </section>
  <section class="glass rounded-2xl p-4 anim">
    <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-check-double text-emerald-400"></i><h2 class="font-semibold">Whitelist</h2></div>
    <div class="flex gap-2 mb-2">
      <input id=wdom placeholder="analytics.example.com" class="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm">
      <button onclick=addWhite() class="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3 py-2 text-sm font-medium text-white"><i class="fa-solid fa-plus mr-1"></i>Allow</button>
    </div>
    <p class="text-[11px] text-slate-500 mb-2">Whitelist thắng blocklist: domain và subdomain không bao giờ bị chặn.</p>
    <div class="max-h-64 overflow-y-auto"><table id=wl class="w-full text-sm"><tbody></tbody></table></div>
  </section>
</div>

<div class="grid md:grid-cols-2 gap-4">
  <section class="glass rounded-2xl p-4 anim">
    <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-upload text-indigo-400"></i><h2 class="font-semibold">Blocklist — Upload</h2></div>
    <form id=upf class="space-y-3">
      <input type=file id=blf accept=.bin class="block w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-indigo-600 file:px-3 file:py-2 file:text-white">
      <button class="rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 text-sm font-medium text-white">Upload blocklist</button>
      <span id=upmsg class="text-slate-400 text-xs"></span>
    </form>
    <p class="text-[11px] text-slate-500 mt-3">Build bằng <code>tools/build_blocklist.py</code> rồi upload tại đây — không cần USB.</p>
  </section>
  <section class="glass rounded-2xl p-4 anim">
    <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-cloud-arrow-down text-cyan-400"></i><h2 class="font-semibold">Blocklist — Remote update</h2></div>
    <div class="space-y-2">
      <input id=uurl placeholder="https://host/blocklist.bin" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm">
      <div class="flex items-center gap-2 text-sm">
        <span class="text-slate-400">Mỗi</span><input id=uiv size=2 value=24 class="w-16 rounded-lg bg-slate-950 border border-slate-700 px-2 py-2 text-center"> <span class="text-slate-400">giờ</span>
        <button onclick=saveUpd() class="ml-auto rounded-lg bg-slate-700 hover:bg-slate-600 px-3 py-2 text-sm">Save</button>
        <button onclick=fetchNow() class="rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3 py-2 text-sm text-white">Fetch now</button>
      </div>
      <p class="text-[11px] text-slate-500">Lần cập nhật cuối: <span id=ustat>—</span></p>
    </div>
  </section>
</div>

<section class="glass rounded-2xl p-4 anim">
  <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-network-wired text-amber-400"></i><h2 class="font-semibold">Network — Static IP</h2></div>
  <div class="grid sm:grid-cols-2 lg:grid-cols-5 gap-3 items-end">
    <div><label class="block text-[11px] text-slate-400 mb-1">IP Address</label><input id=netip placeholder="192.168.1.50" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm"></div>
    <div><label class="block text-[11px] text-slate-400 mb-1">Gateway</label><input id=netgw placeholder="192.168.1.1" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm"></div>
    <div><label class="block text-[11px] text-slate-400 mb-1">Subnet Mask</label><input id=netsn placeholder="255.255.255.0" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm"></div>
    <div><label class="block text-[11px] text-slate-400 mb-1">DNS Server</label><input id=netdns placeholder="1.1.1.1" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm"></div>
    <div class="flex gap-2"><button onclick=saveIP() class="rounded-lg bg-amber-600 hover:bg-amber-500 px-3 py-2 text-sm text-white">Save</button><button onclick=setDhcp() class="rounded-lg bg-slate-700 hover:bg-slate-600 px-3 py-2 text-sm">DHCP</button></div>
  </div>
  <p class="text-[11px] text-slate-500 mt-3"><span id=netmsg></span> Áp dụng sau khi reboot. Hiện tại: <span id=netstate>—</span></p>
</section>

<div class="grid md:grid-cols-2 gap-4">
  <section class="glass rounded-2xl p-4 anim">
    <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-arrow-up-right-from-square text-fuchsia-400"></i><h2 class="font-semibold">Blocked page redirect</h2></div>
    <div class="flex gap-2 mb-2">
      <input id=burl placeholder="0.0.0.0 (default)" class="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm">
      <button onclick=saveBlockUrl() class="rounded-lg bg-fuchsia-600 hover:bg-fuchsia-500 px-3 py-2 text-sm text-white">Save</button>
      <button onclick=resetBlockUrl() class="rounded-lg bg-slate-700 hover:bg-slate-600 px-3 py-2 text-sm">Reset</button>
    </div>
    <p class="text-[11px] text-slate-500"><span id=bmsg></span> Mặc định 0.0.0.0. Nhập URL để hiển thị khi bị chặn.</p>
  </section>
  <section class="glass rounded-2xl p-4 anim">
    <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-wifi text-sky-400"></i><h2 class="font-semibold">WiFi</h2></div>
    <button onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()" class="rounded-lg border border-rose-600/60 text-rose-300 hover:bg-rose-600/10 px-3 py-2 text-sm"><i class="fa-solid fa-trash-can mr-1"></i>Forget WiFi</button>
  </section>
</div>

<section class="glass rounded-2xl p-4 anim">
  <div class="flex items-center gap-2 mb-3"><i class="fa-solid fa-clock-rotate-left text-slate-300"></i><h2 class="font-semibold">Recently blocked</h2></div>
  <div class="max-h-72 overflow-y-auto"><table id=ht class="w-full text-sm"><thead class="sticky top-0 bg-slate-900"><tr><th>Domain</th><th>Client</th><th>When</th></tr></thead><tbody></tbody></table></div>
</section>

</div>
<script>
function fmt(n){return (n??0).toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
const CSRF_HDRS={'X-Requested-With':'produckx-adblock'}
let netEdited=false,dtClients=null,chartTotals=null,chartClients=null;

// Khởi tạo DataTables + Chart.js; nếu CDN bị chặn thì tự fallback, không vỡ trang.
try{
  if(window.jQuery&&window.DataTable){
    dtClients=$('#ct').DataTable({paging:true,pageLength:10,lengthChange:false,searching:true,info:true,ordering:false,autoWidth:false});
  }
}catch(e){dtClients=null}
try{
  if(window.Chart){
    chartTotals=new Chart(document.getElementById('chartTotals'),{type:'doughnut',
      data:{labels:['Blocked','Allowed'],datasets:[{data:[0,0],backgroundColor:['#f85149','#3fb950'],borderWidth:0}]},
      options:{responsive:true,maintainAspectRatio:false,cutout:'66%',plugins:{legend:{labels:{color:'#cbd5e1',boxWidth:12}}}}});
    chartClients=new Chart(document.getElementById('chartClients'),{type:'bar',
      data:{labels:[],datasets:[{label:'Blocked',data:[],backgroundColor:'#38bdf8',borderRadius:6}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{x:{ticks:{color:'#94a3b8'},grid:{display:false}},y:{ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}}}}});
  }
}catch(e){chartTotals=null;chartClients=null}

function clientRows(arr){
  return arr.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>[
    '<div class="font-medium">'+esc(c.ip)+(c.banned?' <span class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-rose-600/20 text-rose-400">BANNED</span>':'')+'</div>',
    '<span class="font-mono text-xs text-slate-400">'+esc(c.mac)+'</span>',
    c.blocked, c.allowed,
    '<button class="ban text-xs rounded-md border px-2 py-1 '+(c.banned?'border-emerald-600 text-emerald-400':'border-rose-600 text-rose-400')+'" data-ip="'+c.ip+'">'+(c.banned?'Unban':'Ban')+'</button>'
  ]);
}
function renderClients(arr){
  let rows=clientRows(arr).map(r=>[r[0],r[1],'<span class="text-rose-400">'+fmt(r[2])+'</span>','<span class="text-emerald-400">'+fmt(r[3])+'</span>',r[4]]);
  if(dtClients){dtClients.clear();rows.forEach(r=>dtClients.row.add(r));dtClients.draw(false);}
  else{ct.tBodies[0].innerHTML=rows.map(r=>'<tr>'+r.map(h=>'<td class="px-3 py-2 border-b border-slate-800">'+h+'</td>').join('')+'</tr>').join('');}
}
// Thẻ thống kê: tạo DOM 1 lần, sau đó chỉ cập nhật text để không nháy khi refresh.
const CARDS=[
  {icon:'fa-shield-halved',color:'text-rose-400',label:'Total blocked',cls:''},
  {icon:'fa-check',color:'text-emerald-400',label:'Total allowed',cls:''},
  {icon:'fa-database',color:'text-sky-400',label:'Blocklist domains',cls:''},
  {icon:'fa-users',color:'text-indigo-400',label:'Clients',cls:''},
  {icon:'fa-microchip',color:'text-amber-400',label:'CPU',cls:''},
  {icon:'fa-memory',color:'text-fuchsia-400',label:'RAM',cls:''},
  {icon:'fa-hourglass-half',color:'text-slate-300',label:'Uptime',cls:'col-span-2 lg:col-span-4 xl:col-span-7'}
];
function buildCards(){
  sys.className='grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3';
  sys.innerHTML=CARDS.map((c,i)=>'<div class="glass rounded-2xl p-4 flex items-center gap-3 anim '+c.cls+'"><div class="w-10 h-10 rounded-xl grid place-items-center text-lg '+c.color+' bg-slate-800/60"><i class="fa-solid '+c.icon+'"></i></div><div><div id="cardv'+i+'" class="text-2xl font-semibold '+c.color+'">-</div><div class="text-[11px] text-slate-400">'+c.label+'</div></div></div>').join('');
}

async function load(){
  let r=await fetch('/stats.json');if(r.status==401){location.href='/login';return;}
  let s=await r.json();
  host.textContent='@ '+s.ip;
  credwarn.style.display=s.defcreds?'block':'none';
  const vals=[fmt(s.blocked),fmt(s.allowed),fmt(s.domains),s.clients.length,(s.cpu??0)+'%',(s.ram??0)+'%',s.uptime];
  vals.forEach((v,i)=>{const el=document.getElementById('cardv'+i);if(el)el.textContent=v;});
  renderClients(s.clients);
  cl.tBodies[0].innerHTML=s.custom.map(d=>'<tr><td class="px-3 py-2 border-b border-slate-800">'+esc(d)+'</td><td class="text-right"><button class=rmbtn data-d="'+esc(d)+'" class="text-xs text-rose-400 hover:underline">remove</button></td></tr>').join('')||'<tr><td class="px-3 py-2 text-slate-500">none yet</td></tr>';
  wl.tBodies[0].innerHTML=s.white.map(d=>'<tr><td class="px-3 py-2 border-b border-slate-800">'+esc(d)+'</td><td class="text-right"><button class=wrm data-d="'+esc(d)+'" class="text-xs text-rose-400 hover:underline">remove</button></td></tr>').join('')||'<tr><td class="px-3 py-2 text-slate-500">none yet</td></tr>';
  ht.tBodies[0].innerHTML=s.hist.map(h=>'<tr><td class="px-3 py-2 border-b border-slate-800">'+esc(h.d)+'</td><td class="px-3 py-2 border-b border-slate-800 text-slate-400">'+h.ip+'</td><td class="px-3 py-2 border-b border-slate-800 text-slate-400">'+(h.t<60?h.t+'s ago':Math.round(h.t/60)+'m ago')+'</td></tr>').join('')||'<tr><td colspan=3 class="px-3 py-2 text-slate-500">nothing blocked yet</td></tr>';
  netstate.textContent=s.staticip?'static':'DHCP';
  if(!netEdited){netip.value=s.netip||'';netgw.value=s.netgw||'';netsn.value=s.netsubnet||'';netdns.value=s.netdns||'';}
  if(document.activeElement!=burl)burl.value=s.blockurl||'';
  if(document.activeElement!=uurl)uurl.value=s.upurl||'';
  if(document.activeElement!=uiv)uiv.value=s.upiv||24;
  ustat.textContent=s.upstat||'—';
  if(chartTotals){chartTotals.data.datasets[0].data=[s.blocked,s.allowed];chartTotals.update('none');}
  if(chartClients){
    let top=s.clients.slice().sort((a,b)=>b.blocked-a.blocked).slice(0,5);
    chartClients.data.labels=top.map(c=>c.ip);
    chartClients.data.datasets[0].data=top.map(c=>c.blocked);
    chartClients.update('none');
  }
}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function addWhite(){let d=wdom.value.trim();if(d){fetch('/addwhite?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{wdom.value='';load()})}}
wl.addEventListener('click',e=>{if(e.target.classList.contains('wrm'))fetch('/unwhite?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
[netip,netgw,netsn,netdns].forEach(el=>el.addEventListener('input',()=>{netEdited=true;}));
function saveIP(){let ip=netip.value.trim(),gw=netgw.value.trim(),sn=netsn.value.trim(),dns=netdns.value.trim();
if(!ip||!gw||!sn||!dns){netmsg.textContent='fill all four fields';return;}
netmsg.textContent='saving...';netEdited=false;
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
buildCards();load();setInterval(load,3000);
</script></body></html>)HTML";
