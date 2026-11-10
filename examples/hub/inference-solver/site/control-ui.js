"use strict";
let controlTimer, controlHost='', controlWindow=3600;
const measured=(value,unit='',digits=1)=>Number.isFinite(value)?value.toFixed(digits)+unit:'Unavailable';

async function renderMembers() {
  const data=await api('/api/admin/control');
  if(currentRoute()[0]!=='admin')return;
  const area=$('#member-settings'); if(!area) return;
  area.innerHTML=data.users.map(u=>`<div class="source"><div><strong>${esc(u.email)}</strong><p>${u.admin?'Administrator':'Member'}${u.id===session.user.id?' · You':''} · ${u.web_seen>data.at-90?'Online':'Offline'}</p></div><button class="text-button" type="button" data-role-user="${esc(u.id)}" data-role-admin="${!u.admin}" ${u.admin && data.counts.admins===1?'disabled':''}>${u.admin?'Make member':'Make administrator'}</button></div>`).join('');
  area.querySelectorAll('[data-role-user]').forEach(button=>button.onclick=async()=>{
    button.disabled=true;
    try {await api('/api/admin/users/role',{id:button.dataset.roleUser,admin:button.dataset.roleAdmin==='true'});await route();}
    catch(error){notice(error.message);button.disabled=false;}
  });
}

function chart(points,key,label,unit='',ceiling=null,gap=30) {
  const values=points.filter(p=>Number.isFinite(p[key]));
  if(!values.length)return `<div class="chart-empty">${esc(label)}: no measurements yet.</div>`;
  const max=ceiling || Math.max(1,...values.map(p=>p[key]));
  const start=points[0]?.at || values[0].at,end=Math.max(start+1,points.at(-1)?.at || start+1);
  const x=p=>36+(p.at-start)/(end-start)*564,y=p=>142-Math.min(1,p[key]/max)*118;
  let paths=[],current=[];
  for(const p of points) {
    if(!Number.isFinite(p[key])){if(current.length)paths.push(current);current=[];continue;}
    if(current.length && p.at-current.at(-1).at>gap){paths.push(current);current=[];}
    current.push(p);
  }
  if(current.length)paths.push(current);
  return `<figure class="usage-chart"><figcaption>${esc(label)} <strong>${measured(values.at(-1)[key],unit)}</strong></figcaption><svg viewBox="0 0 620 166" role="img" aria-label="${esc(label)} over time"><path class="chart-grid" d="M36 24H600 M36 83H600 M36 142H600"/><text x="0" y="28">${esc(measured(max,unit,0))}</text><text x="12" y="146">0</text>${paths.map(part=>part.length===1?`<circle class="chart-dot" cx="${x(part[0])}" cy="${y(part[0])}" r="3"/>`:`<polyline class="chart-line" points="${part.map(p=>`${x(p)},${y(p)}`).join(' ')}"/>`).join('')}<text x="36" y="163">${esc(new Date(start*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}))}</text><text x="540" y="163">${esc(new Date(end*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}))}</text></svg></figure>`;
}

async function renderControlPanel() {
  clearTimeout(controlTimer);
  const area=document.createElement('section');area.id='control-panel';area.className='control-panel';
  area.innerHTML=`<div class="panel-heading"><h3>Inference control panel</h3><span class="hint" id="control-updated"></span></div><div id="control-totals" class="control-totals"></div><div class="control-filters"><label>Computer<select id="control-host"></select></label><label>Hardware history<select id="control-window"><option value="900">15 minutes</option><option value="3600">1 hour</option></select></label></div><div id="control-charts" class="resource-grid"></div><div id="control-gpus"></div><div id="control-workloads"></div><div id="control-cloud"></div><div id="control-traffic"></div><div id="control-models"></div><div id="control-routing"></div><div id="control-users"></div>`;
  $('#view').prepend(area);
  $('#control-host').onchange=event=>{controlHost=event.target.value;refreshControl().catch(()=>{});};
  $('#control-window').value=String(controlWindow);
  $('#control-window').onchange=event=>{controlWindow=Number(event.target.value);refreshControl().catch(()=>{});};
  await refreshControl();
}

async function refreshControl() {
  clearTimeout(controlTimer);
  if(currentRoute()[0]!=='usage' || !session.user?.admin || !$('#control-panel'))return;
  try {
    const data=await api('/api/admin/control');
    if(currentRoute()[0]!=='usage' || !$('#control-panel'))return;
    const selected=data.nodes.find(n=>n.id===controlHost) || data.nodes[0];controlHost=selected?.id || '';
    $('#control-host').innerHTML=data.nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.name)} · ${n.online?'Online':'Offline'}</option>`).join('');$('#control-host').value=controlHost;
    $('#control-updated').textContent='Updated '+new Date(data.at*1000).toLocaleTimeString();
    const counts=data.counts, vmCount=data.grid.vms.filter(v=>v.state==='running').length;
    const totals=[['Users',counts.users],['Online now',counts.online],['API users · 5 min',counts.api_users],['Active requests',counts.active_requests],['Connected PCs',data.nodes.filter(n=>n.online).length],['Running sandboxes',vmCount],['Queued sandboxes',data.grid.vms.filter(v=>v.state==='queued').length],['Requests · 24h',data.requests.reduce((a,r)=>a+r.requests,0)],['Revenue · 24h',dollars(data.revenue_microusd)],['Top-ups · 24h',dollars(data.deposits_microusd)]];
    $('#control-totals').innerHTML=totals.map(([label,value])=>`<div class="metric"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`).join('');
    const history=(selected?.samples || []).filter(p=>p.at>=data.at-controlWindow).map(p=>({...p,ram_percent:p.memory_total_gb?100*p.memory_used_gb/p.memory_total_gb:null,
      gpu_percent:p.gpus?.some(g=>Number.isFinite(g.utilization_percent))?Math.max(...p.gpus.map(g=>g.utilization_percent||0)):p.gpu_percent,
      temperature_c:p.gpus?.some(g=>Number.isFinite(g.temperature_c))?Math.max(...p.gpus.map(g=>g.temperature_c||0)):null}));
    $('#control-charts').innerHTML=chart(history,'cpu_percent','CPU utilization','%',100)+chart(history,'ram_percent','RAM utilization','%',100)+chart(history,'gpu_percent','GPU utilization','%',100)+chart(history,'temperature_c','GPU temperature','°C',110);
    const metrics=selected?.inventory.telemetry || {}, live=selected?.online;
    $('#control-gpus').innerHTML=panel('Hardware',`<p class="hint">${esc(selected?.name || 'No connected computer')} · ${live?'Live readings':'Offline; latest reported readings below'} · ${measured(metrics.cpu_cores,' cores',0)} · RAM ${measured(metrics.memory_used_gb,' GB')} / ${measured(metrics.memory_total_gb,' GB')} · Disk ${measured(metrics.disk_used_gb,' GB')} / ${measured(metrics.disk_total_gb,' GB')} · CPU temperature: ${measured(metrics.cpu_temperature_c,'°C')}</p><div class="table-wrap"><table><thead><tr><th>GPU</th><th>Utilization</th><th>VRAM used / total</th><th>Temperature</th><th>Power</th></tr></thead><tbody>${(metrics.gpus||[]).map(g=>`<tr><td>${esc(g.name)}</td><td>${measured(g.utilization_percent,'%')}</td><td>${measured(g.memory_used_mb,' MiB',0)} / ${measured(g.memory_total_mb,' MiB',0)}</td><td>${measured(g.temperature_c,'°C')}</td><td>${measured(g.power_w,' W')}</td></tr>`).join('') || '<tr><td colspan="5">GPU sensors unavailable on this computer.</td></tr>'}</tbody></table></div>`);
    const workloads=data.nodes.flatMap(n=>(n.inventory.telemetry?.workloads || []).map(w=>({...w,host:n.name,online:n.online})));
    $('#control-workloads').innerHTML=panel('Local and cloud workloads',`<div class="table-wrap"><table><thead><tr><th>Workload</th><th>Computer</th><th>Type / state</th><th>CPU</th><th>RAM</th><th>Network ↓ / ↑</th></tr></thead><tbody>${workloads.map(w=>`<tr><td>${esc(w.name)}</td><td>${esc(w.host)}${w.online?'':' · Offline'}</td><td>${esc(w.kind)} · ${esc(w.state)}</td><td>${measured(w.cpu_percent,'%')}</td><td>${measured(w.memory_gb,' GB')}</td><td>${measured(w.network_rx_mbps,' Mbps')} / ${measured(w.network_tx_mbps,' Mbps')}</td></tr>`).join('') || '<tr><td colspan="6">No workloads reported.</td></tr>'}</tbody></table></div>`);
    $('#control-workloads').innerHTML+=panel('Sandbox VMs',`<p class="hint">These are allocated resources, not measured consumption.</p><div class="table-wrap"><table><thead><tr><th>Sandbox</th><th>Computer</th><th>State</th><th>CPU allocation</th><th>RAM allocation</th></tr></thead><tbody>${data.grid.vms.map(v=>`<tr><td>${esc(v.name)}</td><td>${esc(data.nodes.find(n=>n.id===v.host)?.name || v.host)}</td><td>${esc(v.state)}</td><td>${v.cpu} cores</td><td>${v.memory_gb} GB</td></tr>`).join('') || '<tr><td colspan="5">No sandboxes yet.</td></tr>'}</tbody></table></div>`);
    const account=data.cloud.find(j=>['account','provider'].includes(j.kind) && j.state==='done')?.result.account;
    $('#control-cloud').innerHTML=panel('Cloud spending',`<p>RunPod balance: ${Number.isFinite(account?.balance)?'$'+account.balance.toFixed(2):'Unavailable'} · Spend: ${Number.isFinite(account?.spendPerHour)?'$'+account.spendPerHour.toFixed(3)+'/hour':'Unavailable'}</p><p class="hint">Provider values are from the latest account check in Admin. GPU temperatures require sensor readings from the contributing computer; remote providers may not expose them.</p><a href="#admin" class="text-button">Manage GPUs and cloud servers →</a>`);
    const bins=new Map(data.requests.map(r=>[r.at,r]));const traffic=[];
    for(let at=Math.floor((data.at-86400)/300)*300;at<=data.at;at+=300)traffic.push(bins.get(at)||{at,requests:0});
    $('#control-traffic').innerHTML=panel('API traffic · last 24 hours',chart(traffic,'requests','Requests per five minutes','',null,600));
    const share=(part,whole)=>whole?(Math.round(1000*part/whole)/10)+'%':'Not reported';
    $('#control-models').innerHTML=panel('Model usage · last 24 hours',`<p class="hint">Token totals include reported usage only. Missing counts are listed separately. Cached input is the share of input a model server reused from its cache, among requests whose server reports it.</p><div class="table-wrap"><table><thead><tr><th>Model</th><th>Requests</th><th>Completed</th><th>Input tokens</th><th>Cached input</th><th>Output tokens</th><th>Images</th><th>Output seconds</th><th>Missing usage</th></tr></thead><tbody>${data.models.map(m=>`<tr><td>${esc(m.model)}</td><td>${m.requests}</td><td>${m.completed}</td><td>${m.input_tokens??'Unknown'}</td><td>${share(m.cached_tokens,m.cache_input)}</td><td>${m.output_tokens??'Unknown'}</td><td>${m.images??0}</td><td>${((m.output_ms||0)/1000).toFixed(1)}</td><td>${m.unknown_usage}</td></tr>`).join('') || '<tr><td colspan="9">No requests yet.</td></tr>'}</tbody></table></div>`);
    const routes=data.routing||[];
    $('#control-routing').innerHTML=panel('Computers and model servers',`<p class="hint">Each model name is served by every computer or model server that shares it. A conversation stays on the one that served its previous turn while it has a free slot, so its prompt is already cached there. Live columns count since this website started.</p><div class="table-wrap"><table><thead><tr><th>Computer or server</th><th>Requests · 24h</th><th>Average duration</th><th>Cached input</th></tr></thead><tbody>${(data.sources||[]).map(s=>`<tr><td>${esc(s.source)}</td><td>${s.requests}</td><td>${measured((s.latency_ms||0)/1000,' s',2)}</td><td>${share(s.cached_tokens,s.cache_input)}</td></tr>`).join('') || '<tr><td colspan="4">No requests yet.</td></tr>'}</tbody></table></div><div class="table-wrap"><table><thead><tr><th>Model</th><th>Served by</th><th>In progress / slots</th><th>Requests</th><th>Same conversation</th><th>Failed</th><th>State</th></tr></thead><tbody>${routes.map(r=>`<tr><td>${esc(r.model)}</td><td>${esc(r.source)}</td><td>${r.active} / ${r.slots}</td><td>${r.requests}</td><td>${share(r.same,r.requests)}</td><td>${r.failed}</td><td>${r.cooling?'Skipped after a failure':'Serving'}</td></tr>`).join('') || '<tr><td colspan="7">No routed requests since the website started.</td></tr>'}</tbody></table></div>`);
    $('#control-users').innerHTML=panel('User activity',`<p class="hint">Online = this site visible in the last 90 seconds. API users = an authenticated model request in the last five minutes.</p><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Website</th><th>Last API use</th></tr></thead><tbody>${data.users.map(u=>`<tr><td>${esc(u.email)}</td><td>${u.admin?'Admin':'Member'}</td><td>${u.web_seen>data.at-90?'Online':'Offline'}</td><td>${u.api_seen?esc(nowLabel(u.api_seen)):'Never'}</td></tr>`).join('')}</tbody></table></div>`);
  } catch(error){if(currentRoute()[0]==='usage')notice(error.message);}
  finally{if(currentRoute()[0]==='usage' && session.user?.admin)controlTimer=setTimeout(refreshControl,5000);}
}

const reportPresence=()=>{if(session?.user && document.visibilityState==='visible')api('/api/presence',{}).catch(()=>{});};
setInterval(reportPresence,30000);
document.addEventListener('visibilitychange',reportPresence);
window.addEventListener('hashchange',reportPresence);
setTimeout(reportPresence,2000);
