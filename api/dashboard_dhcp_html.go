// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

// dhcpDashboardHTML is a self-contained dark UI (Chart.js from CDN for lease distribution).
const dhcpDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>dhcplane dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" crossorigin="anonymous"></script>
  <style>
    :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
           --ok:#3fb950; --warn:#d29922; --bad:#f85149; --radius:8px; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:ui-sans-serif,system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
    header { padding:1rem 1.25rem; border-bottom:1px solid var(--border); background:var(--surface); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.75rem; }
    header h1 { margin:0; font-size:1.1rem; color:var(--accent); }
    .token-row { display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap; }
    .token-row input { background:#21262d; border:1px solid var(--border); color:var(--text); padding:0.35rem 0.5rem; border-radius:var(--radius); min-width:12rem; }
    .token-row button { background:var(--accent); color:#0d1117; border:none; padding:0.4rem 0.75rem; border-radius:var(--radius); cursor:pointer; font-weight:600; }
    main { padding:1.25rem; max-width:1200px; margin:0 auto; }
    .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:0.75rem; margin-bottom:1.25rem; }
    .card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:0.85rem; }
    .card .label { font-size:0.75rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.04em; }
    .card .val { font-size:1.35rem; font-weight:700; margin-top:0.25rem; }
    .pill { display:inline-block; padding:0.2rem 0.5rem; border-radius:999px; font-size:0.75rem; font-weight:600; }
    .pill.ok { background:rgba(63,185,80,0.15); color:var(--ok); }
    .pill.bad { background:rgba(248,81,73,0.15); color:var(--bad); }
    .pill.warn { background:rgba(210,153,34,0.15); color:var(--warn); }
    h2 { font-size:0.95rem; color:var(--muted); margin:1.5rem 0 0.5rem; font-weight:600; }
    table { width:100%; border-collapse:collapse; font-size:0.85rem; }
    th, td { text-align:left; padding:0.45rem 0.5rem; border-bottom:1px solid var(--border); }
    th { color:var(--muted); font-weight:600; }
    .chart-wrap { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:1rem; margin-top:0.5rem; max-width:480px; }
    .err { color:var(--bad); font-size:0.9rem; margin-top:0.5rem; }
    .muted { color:var(--muted); font-size:0.8rem; }
  </style>
</head>
<body>
  <header>
    <h1>dhcplane</h1>
    <div class="token-row">
      <span class="muted">API token (stored in sessionStorage)</span>
      <input type="password" id="apiTok" placeholder="Bearer token" autocomplete="off">
      <button type="button" id="saveTok">Save</button>
    </div>
  </header>
  <main>
    <div id="statusLine"></div>
    <div class="grid" id="cards"></div>
    <div class="chart-wrap"><canvas id="leaseChart" height="220"></canvas></div>
    <h2>DHCP</h2>
    <div id="dhcpBlock" class="muted"></div>
    <h2>Leases (preview)</h2>
    <div style="overflow:auto"><table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Expiry</th></tr></thead><tbody id="leaseRows"></tbody></table></div>
    <div id="err" class="err"></div>
  </main>
<script>
(function(){
  var LS='dhcplane_api_token';
  function tok(){ return (sessionStorage.getItem(LS)||'').trim(); }
  document.getElementById('apiTok').value = tok();
  document.getElementById('saveTok').onclick = function(){
    sessionStorage.setItem(LS, document.getElementById('apiTok').value.trim());
    location.reload();
  };
  var chart;
  function authHeaders(){
    var h={};
    var t=tok();
    if(t) h['Authorization']='Bearer '+t;
    return h;
  }
  function setErr(m){ document.getElementById('err').textContent=m||''; }
  function render(d){
    setErr('');
    var st=d.status||{};
    var ready=!!st.ready;
    var dhcp=!!st.dhcp_up;
    document.getElementById('statusLine').innerHTML=
      '<span class="pill '+(ready?'ok':'bad')+'">'+(ready?'READY':'NOT READY')+'</span> '+
      '<span class="pill '+(dhcp?'ok':'warn')+'">'+(dhcp?'DHCP up':'DHCP down')+'</span> '+
      '<span class="muted">v '+(d.build&&d.build.version||'?')+'</span>';
    var c=d.counters||{};
    var cards=document.getElementById('cards');
    cards.innerHTML='';
    function card(lab,v){
      var el=document.createElement('div'); el.className='card';
      el.innerHTML='<div class="label">'+lab+'</div><div class="val">'+v+'</div>';
      cards.appendChild(el);
    }
    card('1m allocs', c.allocations_last_1m|0);
    card('1h allocs', c.allocations_last_1h|0);
    card('24h allocs', c.allocations_last_24h|0);
    card('current', c.leases_current|0);
    card('expiring', c.leases_expiring|0);
    card('expired', c.leases_expired|0);
    var lv=d.lease_views||{};
    var cur=lv.current||[];
    var exp=lv.expiring||[];
    var exd=lv.expired||[];
    var ctx=document.getElementById('leaseChart').getContext('2d');
    if(chart) chart.destroy();
    chart=new Chart(ctx,{type:'doughnut',data:{labels:['current','expiring','expired'],datasets:[{data:[cur.length,exp.length,exd.length],backgroundColor:['#3fb950','#d29922','#6e7681']}]},options:{plugins:{legend:{labels:{color:'#8b949e'}}}}});
    var dh=d.dhcp||{};
    document.getElementById('dhcpBlock').textContent=
      (dh.interface!==undefined?'iface '+JSON.stringify(dh.interface)+' · ':'')+
      'subnet '+(dh.subnet_cidr||'')+' · server '+(dh.server_ip||'')+' · resv '+(dh.reservations_n|0);
    var tb=document.getElementById('leaseRows');
    tb.innerHTML='';
    (d.leases_preview||[]).forEach(function(r){
      var tr=document.createElement('tr');
      var td=function(x){ var e=document.createElement('td'); e.textContent=x==null?'':String(x); return e; };
      tr.appendChild(td(r.ip)); tr.appendChild(td(r.mac)); tr.appendChild(td(r.hostname)); tr.appendChild(td(r.expiry));
      tb.appendChild(tr);
    });
  }
  function load(){
    fetch('/stats/dashboard/data',{headers:authHeaders()}).then(function(r){
      if(r.status===401){ setErr('Unauthorized — set API token above'); return null;}
      if(!r.ok){ setErr('HTTP '+r.status); return null;}
      return r.json();
    }).then(function(d){ if(d) render(d); }).catch(function(e){ setErr(String(e)); });
  }
  var ws;
  function wsUrl(){
    var u=new URL('/stats/dashboard/ws', location.href);
    u.protocol=u.protocol==='https:'?'wss:':'ws:';
    var t=tok();
    if(t) u.searchParams.set('access_token', t);
    return u.toString();
  }
  function startWs(){
    if(!window.WebSocket) return;
    try{ if(ws) ws.close(); }catch(e){}
    ws=new WebSocket(wsUrl());
    ws.onopen=function(){ try{ ws.send(JSON.stringify({op:'sub',stats:true})); }catch(e){} };
    ws.onmessage=function(ev){
      try{
        var o=JSON.parse(ev.data);
        if(o.dashboard) render(o.dashboard);
      }catch(e){}
    };
    ws.onclose=function(){ ws=null; };
    ws.onerror=function(){ try{ ws.close(); }catch(e2){} };
  }
  load();
  startWs();
  setInterval(load, 30000);
})();
</script>
</body>
</html>`
