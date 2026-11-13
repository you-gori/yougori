"use strict";
let sandboxTimer, sandboxRound=0, sandboxesShown=false;

// The main page's Sandboxes column. It shows when a computer offers sandboxes, or when someone already
// has one, and keeps its last answer while the page is drawn again, so the columns do not jump.
function showSandboxes() {
  clearTimeout(sandboxTimer);
  const body=$('#sandboxes-body'); if(!body) return;
  $('#sandboxes-column').hidden=!sandboxesShown;
  body.innerHTML='<div id="sandbox-computers" class="resource-grid"></div><div id="my-sandboxes"></div><div id="sandbox-events"></div>';
  refreshSandboxes(++sandboxRound);
}

// One round of updates at a time: drawing the main page again starts a new round and ends the old one.
async function refreshSandboxes(round) {
  clearTimeout(sandboxTimer);
  const current=()=>round===sandboxRound && !!$('#sandboxes-body');
  if(!current()) return;
  try {
    const catalog=await api('/api/sandboxes');
    const own=session.user ? await api('/api/grid') : {vms:[],jobs:[]};
    if(!current())return;
    sandboxesShown=(catalog.enabled && catalog.nodes.length>0) || own.vms.length>0;
    if($('#sandboxes-column').hidden===sandboxesShown) { $('#sandboxes-column').hidden=!sandboxesShown; fitColumns(); }
    const area=$('#sandbox-computers');
    // Keep an in-progress resource choice intact during live updates.
    if(!area.querySelector('input:focus,button:disabled[data-submitting]')) {
      const choices=Object.fromEntries([...area.querySelectorAll('form')].map(f=>[f.dataset.host,Object.fromEntries(new FormData(f))]));
      area.innerHTML=(!catalog.enabled?'<p class="hint">Sandboxes are currently switched off by the administrator.</p>':'')+catalog.nodes.map(n=>{
        const available=catalog.enabled && n.online && n.capacity.available!==false && n.free.slots>0 && n.free.cpu>0 && n.free.memory_gb>0;
        const canUse=session.user && (session.user.admin || catalog.admission!=='private');
        const choice=choices[n.host] || {};
        return panel(n.name,`<div class="stack"><span class="badge ${available?'ready':''}">${!n.online?'Offline':available?'Available':'Unavailable'}</span>
          <p class="resource-number">${n.capacity.cpu} CPU cores · ${n.capacity.memory_gb} GB RAM</p><p class="hint">${n.free.cpu} cores · ${n.free.memory_gb} GB RAM · ${n.free.slots} slots free</p>
          ${n.capacity.available===false?`<p class="hint">${esc(n.capacity.detail)}</p>`:''}
          ${canUse?`<form class="sandbox-start stack" data-host="${esc(n.host)}"><div class="compute-sizing"><label>CPU cores<input name="cpu" type="number" min="1" max="${Math.max(1,n.free.cpu)}" value="${esc(choice.cpu||1)}" required></label><label>RAM (GB)<input name="memory_gb" type="number" min="1" max="${Math.max(1,n.free.memory_gb)}" value="${esc(choice.memory_gb||Math.min(2,n.free.memory_gb)||1)}" required></label></div><p class="error" role="alert"></p><button class="primary" type="submit" ${available?'':'disabled'}>Create sandbox</button></form>`:session.user?'<p class="hint">This node is private. An administrator can create sandboxes.</p>':'<a href="#signin" class="secondary">Sign in to create a sandbox</a>'}</div>`);
      }).join('')+(catalog.nodes.length?'':'<p class="hint">No computers are contributing sandbox resources yet.</p>');
      area.querySelectorAll('form').forEach(form=>form.onsubmit=async event=>{
        event.preventDefault();const button=form.querySelector('button');button.disabled=true;button.dataset.submitting='true';
        try {const data=Object.fromEntries(new FormData(form));await api('/api/grid/jobs',{kind:'launch',request_id:crypto.randomUUID(),host:form.dataset.host,cpu:Number(data.cpu),memory_gb:Number(data.memory_gb),name:'Sandbox VM'});}
        catch(error){form.querySelector('.error').textContent=error.message;}
        finally{button.disabled=false;delete button.dataset.submitting;}
      });
    }
    const mine=$('#my-sandboxes');
    if(!mine.querySelector('textarea:focus,button:disabled[data-submitting]')) {
      mine.innerHTML=own.vms.length?panel(session.user?.admin?'All sandboxes':'My sandboxes',own.vms.map(v=>`<div class="source"><div><strong>${esc(v.name)}</strong><p>${v.cpu} cores · ${v.memory_gb} GB RAM · ${esc(v.state)}</p>${v.state==='running'?`<form class="sandbox-command stack" data-vm="${esc(v.id)}"><label>Command inside sandbox<textarea name="input" maxlength="16000" required placeholder="uname -a"></textarea></label><p class="error" role="alert"></p><div class="device-actions"><button class="secondary" type="submit">Run command</button><button class="text-button" type="button" data-stop-vm="${esc(v.id)}">Stop sandbox</button></div></form>`:''}</div></div>`).join('')):'';
      mine.querySelectorAll('form').forEach(form=>form.onsubmit=async event=>{
        event.preventDefault();const button=form.querySelector('button');button.disabled=true;button.dataset.submitting='true';
        try {await api('/api/grid/jobs',{kind:'exec',request_id:crypto.randomUUID(),vm:form.dataset.vm,input:form.elements.input.value});form.elements.input.value='';}
        catch(error){form.querySelector('.error').textContent=error.message;}
        finally{button.disabled=false;delete button.dataset.submitting;}
      });
      mine.querySelectorAll('[data-stop-vm]').forEach(button=>button.onclick=async()=>{
        button.disabled=true;
        try{await api('/api/grid/jobs',{kind:'stop',request_id:crypto.randomUUID(),vm:button.dataset.stopVm});}
        catch(error){notice(error.message);}finally{button.disabled=false;}
      });
    }
    $('#sandbox-events').innerHTML=own.jobs.length?panel('Sandbox activity',own.jobs.slice(0,12).map(j=>`<div class="source"><div><strong>${esc(j.kind)} · ${esc(j.state)}</strong>${j.result.output?`<pre class="code">${esc(j.result.output)}</pre>`:''}${j.result.error?`<p class="error">${esc(j.result.error)}</p>`:''}</div></div>`).join('')):'';
  } catch(error){if(current() && sandboxesShown)notice(error.message);}
  finally{if(current())sandboxTimer=setTimeout(()=>refreshSandboxes(round),3000);}
}
