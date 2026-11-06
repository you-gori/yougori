/* Admin compute controls. Uses the website backend; never a browser-to-PC API. */
"use strict";
let computeTimer, computeView, computeQuoteId = "";
const computePending = new Map();

async function computeJob(kind, extra = {}) {
  const host = computeView?.hosts.find(h => h.role === "controller" && h.online);
  if (!host) throw new Error("The website's Yougori backend is offline. Connect it on the website server first.");
  const signature = kind === "rent" ? JSON.stringify({kind, host: host.id, ...extra}) : null;
  let identity = crypto.randomUUID();
  if (signature) {
    try {
      const saved = JSON.parse(sessionStorage.getItem("compute-pending-rental") || "null");
      if(saved?.signature === signature) computePending.set(signature, saved.identity);
    } catch { /* Memory still preserves retries within this page. */ }
    identity = computePending.get(signature) || identity;
    computePending.set(signature, identity);
    try { sessionStorage.setItem("compute-pending-rental", JSON.stringify({signature, identity})); } catch { /* Optional persistence. */ }
  }
  const result = await api("/api/admin/compute/jobs", {kind, host: host.id, request_id: identity, ...extra});
  if(signature) {
    computePending.delete(signature);
    try { sessionStorage.removeItem("compute-pending-rental"); } catch { /* Optional persistence. */ }
  }
  await refreshCompute();
  return result;
}

async function showCompute() {
  if (!session?.user?.admin) return;
  clearTimeout(computeTimer);
  $("#compute-setup")?.remove();
  computeQuoteId = "";
  const area = document.createElement("section");
  area.id = "compute-setup";
  area.className = "compute-setup";
  area.setAttribute("aria-label", "Add compute");
  area.innerHTML = `<div class="compute-options">
    ${panel("Local GPUs", `<p class="hint">Use GPUs attached to this website's server, or approve computers that contribute their models. Yougori handles the connection automatically.</p>
      <p id="compute-location" class="hint" role="status">Detecting the website's computeâ€¦</p><button type="button" class="secondary" id="compute-start" hidden>Start Yougori on the website server</button><div id="compute-models"></div>
      <details><summary>Allow GPU contributions</summary><div class="stack compute-details">
      <form id="compute-password" class="stack"><p class="hint">An optional password lets signed-in contributors join with a computer code. Leave it empty to require administrator approval for every computer.</p>
      <label>Contributor password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="1024" placeholder="Optional Â· at least 12 characters"></label>
      <p id="compute-password-state" class="hint"></p><p class="error" role="alert"></p><div><button class="secondary" type="submit">Save contribution access</button></div></form>
      <p class="hint">Contributors run this on the computer whose models they want to share. Cloud rentals are managed here, on the website's backend.</p>
      <pre class="code" id="compute-install"></pre><button type="button" class="secondary" id="compute-copy">Copy contributor install</button>
      <p class="hint">Yougori connects immediately. Choose the models or VM capacity to share, then enter its code below. Keep the terminal open; Ctrl+C disconnects. Sandboxes have no fixed four-hour limit.</p>
      <a class="text-button" href="#contribute">Approve a contributor's computer</a></div></details>
      <form id="compute-load" class="stack panel-end"><label>Load a model on the website's server<input name="model" placeholder="Hugging Face owner/model" required maxlength="200"></label>
      <p class="error" role="alert"></p><div><button class="primary" type="submit">Load and connect model</button></div></form>`)}
    ${panel("Rent a cloud GPU", `<p class="hint">Choose a live NeoCloud offer and a model. This website rents the GPU, starts the model and adds it to your catalog automatically.</p>
      <p class="hint">Provider: <strong>RunPod</strong>. Uses the provider account connected to the website's Yougori backend.</p><p class="hint" id="compute-balance" role="status">Checking provider balanceâ€¦</p>
      <details><summary>Connect or change the provider account</summary><form id="compute-provider" class="stack compute-details">
      <label>RunPod account key<input name="key" type="password" autocomplete="new-password" maxlength="1024" required></label>
      <p class="hint">Saved in the website server's Yougori credential store. Model API credentials are created automatically.</p><p class="error" role="alert"></p>
      <div><button class="secondary" type="submit">Connect RunPod</button></div></form></details>
      <form id="compute-sizing" class="compute-sizing"><label>GPUs per server<select name="gpu_count">${Array.from({length:8},(_,i)=>`<option value="${i+1}">${i+1}</option>`).join("")}</select></label><label>Runtime disk (GB)<input name="disk_gb" type="number" min="5" max="4000" value="80" required></label><label>Storage type<select name="storage"><option value="temporary">Temporary runtime disk</option><option value="persistent">Persistent pod volume</option></select></label><label>Persistent volume (GB)<input name="volume_gb" type="number" min="1" max="4000" value="80" disabled></label></form>
      <form id="compute-rent" class="compute-rent"><fieldset class="compute-offers"><legend>Available GPUs</legend><div id="compute-offer-list"><p class="hint">Find GPUs to see current availability and hourly prices.</p></div></fieldset>
      <div class="stack rent-side"><label>Model to host<input name="model" placeholder="Hugging Face owner/model" required maxlength="200"></label>
      <p class="hint" id="compute-price">Select a GPU to review its price.</p><p class="hint" id="compute-quote-age"></p>
      <label class="check"><input type="checkbox" name="cost" required>I approve this rental and its ongoing provider charges.</label>
      <p class="hint small-print">Quotes use the selected GPU count and disk. Persistent volumes survive stopping a pod, but not deleting it. Storage charges are additional; stopping compute does not stop storage charges.</p>
      <p class="error" role="alert"></p><div class="panel-end"><button class="primary" type="submit">Rent GPU and host model</button></div></div></form>`,
      '<button class="text-button" id="compute-offers" type="button">Find available GPUs</button>')}
    </div>${panel("Compute activity", '<div id="compute-activity" aria-live="polite"></div>')}`;
  // The admin grid pairs these panels with the rest of the page, two of equal height per row.
  ($("#admin-grid") || $("#view")).prepend(area);
  const command = installCommand("node");
  $("#compute-install").textContent = command;
  $("#compute-copy").addEventListener("click", event => copy(command, event.currentTarget));
  $("#compute-start").addEventListener("click", async () => {
    try { await computeJob("start"); } catch(error) { notice(error.message); }
  });
  formAction("#compute-password", async (data, form) => {
    await api("/api/admin/compute/password", data); form.reset(); await refreshCompute();
  });
  formAction("#compute-provider", async (data, form) => {
    try { await computeJob("provider", data); } finally { form.reset(); }
  });
  formAction("#compute-load", async data => { await computeJob("load", data); });
  formAction("#compute-rent", async (data, form) => {
    await computeJob("rent", {model: data.model, offer: data.offer, quote_id: computeQuoteId, cost_acknowledged: data.cost === "on"});
    form.elements.cost.checked = false;
  });
  $("#compute-offers").addEventListener("click", async event => {
    const button = event.currentTarget; button.disabled = true;
    try { await computeJob("offers", computeSizing()); } catch (error) { notice(error.message); }
    finally { if(button.isConnected) button.disabled = false; }
  });
  $("#compute-sizing").addEventListener("submit", event => event.preventDefault());
  $("#compute-sizing").addEventListener("change", () => {
    const sizing = $("#compute-sizing");
    sizing.elements.volume_gb.disabled = sizing.elements.storage.value !== "persistent";
    computeQuoteId = "";
    $("#compute-rent").elements.cost.checked = false;
    $("#compute-rent").querySelector('[type="submit"]').disabled = true;
    $("#compute-quote-age").textContent = "Configuration changed. Find available GPUs for a new quote.";
  });
  $("#admin-grid").addEventListener("click", async event => {
    const button = event.target.closest("[data-share-model], [data-stop-rental], [data-disconnect-compute]");
    if (!button) return;
    button.disabled = true;
    try {
      if (button.dataset.shareModel) await computeJob("share", {environment: button.dataset.shareModel, enabled: button.dataset.enable === "true"});
      else if (button.dataset.stopRental) await computeJob("stop", {rental: button.dataset.stopRental});
      else { await api("/api/admin/compute/disconnect", {id: button.dataset.disconnectCompute}); await refreshCompute(); }
    } catch (error) { notice(error.message); }
    finally { if(button.isConnected) button.disabled = false; }
  });
  await refreshCompute();
  await showInfrastructure();
  const host = computeView?.hosts.find(h => h.role === "controller" && h.online && h.inventory.connected !== false);
  const current = computeView?.jobs.some(j => j.host === host?.id && j.kind === "offers" &&
    (["queued", "running"].includes(j.state) || (j.state === "done" && j.updated > Date.now() / 1000 - 120)));
  if(area.isConnected && host && !current) {
    try { await computeJob("offers", computeSizing()); } catch(error) { if(area.isConnected) notice(error.message); }
  }
  if(host) { try { await computeJob("account"); } catch(error) { if(area.isConnected) notice(error.message); } }
}

function computeSizing() {
  const form = $("#compute-sizing");
  return {gpu_count:Number(form.elements.gpu_count.value), disk_gb:Number(form.elements.disk_gb.value),
    storage:form.elements.storage.value, volume_gb:form.elements.storage.value === "persistent" ? Number(form.elements.volume_gb.value) : 0};
}

async function refreshCompute() {
  clearTimeout(computeTimer);
  const area = $("#compute-setup");
  if (!area || !session?.user?.admin) return;
  try {
    const value = await api("/api/admin/compute");
    if (!area.isConnected || currentRoute()[0] !== "admin") return;
    computeView = value;
    const account = value.jobs.find(j => ["account","provider"].includes(j.kind) && j.state === "done" && j.result.account)?.result.account;
    $("#compute-balance").textContent = account?.connected ? `RunPod balance: ${Number.isFinite(account.balance) ? "$" + account.balance.toFixed(2) : "not reported"}${Number.isFinite(account.spendPerHour) ? " Â· Current spend $" + account.spendPerHour.toFixed(3) + "/hour" : ""}` : "Connect RunPod to see your account balance.";
    const host = value.hosts.find(h => h.role === "controller");
    const connected = host?.online && host.inventory.connected !== false;
    $("#compute-start").hidden = !host?.online || connected;
    $("#compute-start").disabled = value.jobs.some(j => j.kind === "start" && ["queued", "running"].includes(j.state));
    $("#compute-location").textContent = host ? `${host.name} Â· ${connected ? "Connected to this website" : "Compute offline"}. ${host.inventory.detail || ""}` : "The website server has no Yougori backend connected. Install and start Yougori on the server hosting this website; no visitor-side installation is required for rentals.";
    $("#compute-password-state").textContent = value.password_set ? "A contributor password is set. Save a new one to replace it, or save empty to require administrator approval." : "Administrator approval is required for contributors.";
    $("#compute-models").innerHTML = value.hosts.map(node => `<div class="compute-node"><strong>${esc(node.name)}</strong><span class="badge ${node.online ? "ready" : ""}">${node.online ? "Online" : "Offline"}</span>${node.inventory.models?.length ? node.inventory.models.map(model => `<div class="source"><div><strong>${esc(model.name)}</strong><p>${esc(model.state)}${model.shared ? " Â· In your catalog" : ""}</p></div>${node.role === "controller" ? `<button type="button" class="text-button" data-share-model="${esc(model.id)}" data-enable="${!model.shared}" ${node.online ? "" : "disabled"}>${model.shared ? "Remove from inference" : "Add to inference"}</button>${model.shared && model.state !== "ready" ? `<button type="button" class="text-button" data-share-model="${esc(model.id)}" data-enable="true" ${node.online ? "" : "disabled"}>Retry model start</button>` : ""}` : ""}</div>`).join("") : '<p class="hint">No models reported yet.</p>'}${node.role === "contributor" ? `<button class="text-button" type="button" data-disconnect-compute="${esc(node.id)}">Disconnect contributor</button>` : ""}</div>`).join("");
    for (const id of ["#compute-load", "#compute-provider", "#compute-rent"]) $(id).querySelector('[type="submit"]').disabled = !connected;
    $("#compute-offers").disabled = !connected || value.jobs.some(j => j.kind === "offers" && ["queued", "running"].includes(j.state));
    const quote = value.jobs.find(j => j.host === host?.id && j.kind === "offers" && j.state === "done");
    const matches = quote && JSON.stringify(quote.result.offers?.[0]?.options || {gpu_count:1,disk_gb:80,storage:"temporary",volume_gb:0}) === JSON.stringify(computeSizing());
    const fresh = quote && matches && quote.updated > Date.now() / 1000 - 120;
    $("#compute-rent").querySelector('[type="submit"]').disabled = !connected || !fresh;
    $("#compute-quote-age").textContent = quote ? (fresh ? "Live offers. Prices will be rechecked before rental." : "These offers have expired. Find available GPUs again before renting.") : "";
    if(!fresh) $("#compute-rent").elements.cost.checked = false;
    if (quote && matches && quote.id !== computeQuoteId) {
      computeQuoteId = quote.id;
      $("#compute-offer-list").innerHTML = quote.result.offers?.length ? quote.result.offers.map(offer => `<label class="compute-offer"><input type="radio" name="offer" required value="${esc(offer.id)}"><span><strong>${esc(offer.options?.gpu_count || 1)} Ã— ${esc(offer.name)}</strong><span>${esc(offer.vram_gb ?? "â€”")} GB VRAM each Â· ${esc(offer.cloud)} Â· $${Number(offer.hourly_usd).toFixed(3)}/hour</span></span></label>`).join("") : '<p class="hint">No available GPUs returned. Refresh to check again.</p>';
      $("#compute-offer-list").onchange = event => {
        const selected = quote.result.offers.find(o => o.id === event.target.value);
        if (selected) $("#compute-price").textContent = `${selected.name}: maximum compute price $${Number(selected.hourly_usd).toFixed(3)}/hour. Availability and price are checked again before renting.`;
        $("#compute-rent").elements.cost.checked = false;
      };
    }
    $("#compute-activity").innerHTML = value.jobs.length ? value.jobs.map(job => `<div class="source"><div><strong>${esc({rent:"Cloud GPU rental",load:"Load model",share:"Model connection",offers:"GPU offers",provider:"Provider account",stop:"Stop cloud GPU",start:"Start website compute"}[job.kind] || job.kind)}</strong><span class="badge ${job.state === "done" ? "ready" : ""}">${esc(job.state)}</span><p>${esc(job.detail)}</p>${job.result.environment ? `<p class="hint">${esc(job.result.environment)}</p>` : ""}</div>${job.kind === "rent" && job.result.environment ? `<button type="button" class="text-button" data-stop-rental="${esc(job.id)}">Stop rented GPU</button>` : ""}</div>`).join("") : '<p class="hint">Rentals and model connections appear here as soon as you start them.</p>';
    const [discovered, overview] = await Promise.all([api("/api/models"), api("/api/admin/overview")]);
    if(!area.isConnected) return;
    models = discovered.models;
    const list = $("#refresh-models")?.previousElementSibling;
    if(list) {
      list.innerHTML = overview.endpoints.length ? overview.endpoints.map(e => `<div class="source"><div><strong>${esc(e.name)}</strong><p>${esc(e.url.startsWith("compute://") ? "Connected by Yougori" : e.url)}</p><span class="badge ${e.state === "ready" ? "ready" : ""}">${esc(e.state)}</span><p>${esc(e.detail)}</p></div>${e.url.startsWith("compute://") ? "" : `<button type="button" class="text-button" data-remove-source="${esc(e.id)}">Disconnect</button>`}</div>`).join("") : '<p class="hint">Choose a local model or rent a GPU above. Its models appear here automatically.</p>';
      list.querySelectorAll("[data-remove-source]").forEach(button => button.addEventListener("click", async () => {
        button.disabled = true;
        try { await api("/api/admin/endpoints/remove", {id: button.dataset.removeSource}); await refreshCompute(); }
        catch(error) { notice(error.message); button.disabled = false; }
      }));
    }
    const counter = $("#view .metrics .metric:nth-child(2) strong");
    if(counter) counter.textContent = models.length;
  } catch (error) { if(area.isConnected) notice(error.message); }
  finally { if(area.isConnected) computeTimer = setTimeout(refreshCompute, 3000); }
}

function renderContributor() {
  header("Connect a contributing computer", "Approve only a computer you recognize. Inference requests may be sent to this computer. It cannot manage the website or rent cloud GPUs.");
  $("#view").innerHTML = panel("Computer code", `<form id="contributor-inspect" class="stack"><label>Code from the contributor<input name="code" required maxlength="8" autocomplete="off"></label><p class="error" role="alert"></p><div><button class="primary" type="submit">Check computer</button></div></form><div id="contributor-review"></div>`);
  formAction("#contributor-inspect", async data => {
    const info = await api("/api/compute/pair/inspect", data);
    $("#contributor-review").innerHTML = `<form id="contributor-approve" class="stack"><p>Connect <strong>${esc(info.name)}</strong> as a GPU contributor?</p>${session.user.admin ? "" : '<label>Contributor password<input name="password" type="password" autocomplete="off"></label>'}<p class="error" role="alert"></p><div><button class="primary" type="submit">Approve this computer</button></div></form>`;
    formAction("#contributor-approve", async values => {
      const result = await api("/api/compute/pair/approve", {code: data.code, password: values.password || ""});
      $("#contributor-review").textContent = `${result.name} is connected. Its shared models will appear automatically.`;
    });
  });
}
