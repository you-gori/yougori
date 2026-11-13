/* Admin compute controls. Uses the website backend; never a browser-to-PC API. */
"use strict";
let computeTimer, computeView, computeQuoteId = "";
const computePending = new Map();
// What the model fields take, above both whose models run in Yougori (on a computer, or on the
// website's server). People paste references from other tools, such as owner/model-GGUF:UD-Q4_K_M,
// which the field refuses; Yougori reads a UD-Q4_K_M file as Q4_K_M (preflight.rs quant_label).
const MODEL_HINT = '<p class="hint model-hint">Type the Hugging Face repository as owner/model, such as Qwen/Qwen3-8B or unsloth/Qwen3-8B-GGUF. For a GGUF repository, Yougori picks the file: Q4_K_M when the repository has one, and a UD-Q4_K_M file counts as Q4_K_M. So leave out endings such as :Q4_K_M. The model must fit the GPU that runs it. A GGUF file needs about its own size in GPU memory; a full model needs about 2 GB for each billion parameters. Both need a little more for the conversation.</p>';
// Installs Yougori, or updates it (the desktop app too) to the newest release, and starts it: the
// commands yougori.com shows under Install the CLI. Releases are unsigned previews for now, so
// these name the preview installer; once a signed release ships, use yougori.com's own
// install.ps1 and install.sh commands here.
const YOUGORI_INSTALL = [
  ["Windows", 'powershell -c "Set-Item Env:YOUGORI_ALLOW_UNSIGNED 1; irm https://yougori.com/install-preview.ps1 | iex"'],
  ["Linux", "curl -fsSL https://yougori.com/install-preview.sh | YOUGORI_ALLOW_UNSIGNED=1 bash"],
];
// Every command a computer runs to serve this website's models, in order, each with its own Copy.
// The connector needs Yougori already running: it never starts it.
function connectSteps() {
  const connect = installCommand("node");
  const steps = [
    ...YOUGORI_INSTALL.map(([system, command]) => [`Install or update <small>${esc(system)}</small>`, command]),
    ["Start Yougori", "yougori app start"],
    ["Connect this computer", connect, "compute-install"],
  ];
  // Copy all, one per system: only the commands, one per line, with only that system's install
  // command.
  const copyAll = YOUGORI_INSTALL.map(([system, command]) =>
    `<button type="button" class="secondary" id="compute-copy-all-${system.toLowerCase()}" data-copy="${esc([command, "yougori app start", connect].join("\n"))}">Copy all for ${esc(system)}</button>`).join("");
  // Post on X, one post for both systems: each install command under its system's name, then the
  // start and connect commands once, under "Both:" (each system's full list would be 312 of X's
  // 280). X counts each link as 23 characters, so the post is 249 for any website address. X opens
  // it ready to post; the person presses Post, as X never lets a website post on someone's behalf.
  const post = [...YOUGORI_INSTALL.map(([system, command]) => `${system}:\n${command}`), `Both:\nyougori app start\n${connect}`].join("\n\n");
  return `<ol class="command-steps">${steps.map(([label, command, id]) => `<li><span class="command-label">${label}</span><div class="admin-command"><pre class="code"${id ? ` id="${id}"` : ""}>${esc(command)}</pre><button type="button" class="secondary" data-copy="${esc(command)}"${id ? ' id="compute-copy"' : ""}>Copy</button></div></li>`).join("")}</ol>
    <div class="admin-row" id="compute-share">${copyAll}<a class="secondary" id="compute-post-x" href="${esc("https://x.com/intent/post?text=" + encodeURIComponent(post))}" target="_blank" rel="noopener noreferrer">Post on X ↗</a></div>`;
}

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
  $("#admin-activity")?.remove();
  computeQuoteId = "";
  const area = document.createElement("section");
  area.id = "compute-setup";
  area.className = "compute-setup";
  area.setAttribute("aria-label", "Add compute");
  // Local GPUs leads with the commands that connect a computer, the only way on a hosted inference.
  // The website server's own controls, and renting from here, show only when this website has
  // Yougori of its own (refreshCompute); otherwise Rent a cloud GPU points to the Yougori app.
  area.innerHTML = `<div class="compute-options">
    ${adminSection("admin-local", "Local GPUs", "Your own computers with GPUs serve the models.", `<div class="stack" id="compute-offered"><p class="hint">The models computers run for this website. Each computer that connects chooses 1 to 3 of them; Yougori installs them there and loads each on its GPU while it is used. With none listed, computers can lend only Sandbox VMs.</p>
      <div id="compute-offered-list"></div>
      <form id="compute-offered-add" class="stack">${MODEL_HINT}<div class="admin-row"><label>Model for computers to run<input name="model" placeholder="Hugging Face owner/model" required maxlength="200"></label><button class="secondary" type="submit">Add model</button></div><p class="error" role="alert"></p></form></div>
      <p class="hint" id="compute-run-hint">Run these on each computer with a GPU, in order, and choose what it shares. Approve the code it shows, and keep its terminal open.</p>
      ${connectSteps()}
      <p class="hint">After a first install, open a new terminal. On a computer with the Yougori desktop app, the same command updates the app.</p>
      <form id="compute-admission" class="stack"><label class="check"><input type="checkbox" name="code" checked>Ask each computer for its code</label><p class="hint" id="compute-admission-state"></p><p class="error" role="alert"></p></form>
      ${contributorForm()}
      <div id="compute-models"></div>
      <div id="compute-website" class="stack" hidden><p id="compute-location" class="hint" role="status">Detecting the website's compute…</p><div><button type="button" class="secondary" id="compute-start" hidden>Start Yougori on the website server</button></div>
      <form id="compute-load" class="stack">${MODEL_HINT}<div class="admin-row"><label>Load a model on the website's server<input name="model" placeholder="Hugging Face owner/model" required maxlength="200"></label><button class="primary" type="submit">Load and connect model</button></div><p class="error" role="alert"></p></form></div>
      <form id="compute-password" class="stack"><div class="admin-row"><label class="check"><input type="checkbox" name="protected">Let people connect with a password</label><label>Contributor password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="1024" placeholder="At least 12 characters" disabled></label><button class="secondary" type="submit">Save contribution access</button></div>
      <p id="compute-password-state" class="hint"></p><p class="error" role="alert"></p></form>`)}
    ${adminSection("admin-rent", "Rent a cloud GPU", "A GPU by the hour when you need more.", `${rentalForms()}
      <div class="stack" id="rent-here"><p class="hint" id="compute-balance" role="status">Checking provider balance…</p>
      <form id="compute-provider" class="stack"><div class="admin-row"><label>RunPod account key<input name="key" type="password" autocomplete="new-password" maxlength="1024" required></label><button class="secondary" type="submit">Connect RunPod</button></div><p class="hint">Saved in the website server's Yougori credential store. Model API credentials are created automatically.</p><p class="error" role="alert"></p></form>
      <form id="compute-sizing" class="admin-row"><label>GPUs per server<select name="gpu_count">${Array.from({length:8},(_,i)=>`<option value="${i+1}">${i+1}</option>`).join("")}</select></label><label>Runtime disk (GB)<input name="disk_gb" type="number" min="5" max="4000" value="80" required></label><label>Storage type<select name="storage"><option value="temporary">Temporary runtime disk</option><option value="persistent">Persistent pod volume</option></select></label><label>Persistent volume (GB)<input name="volume_gb" type="number" min="1" max="4000" value="80" disabled></label><button class="secondary" id="compute-offers" type="button">Find available GPUs</button></form>
      <form id="compute-rent" class="stack"><fieldset class="compute-offers"><legend>Available GPUs</legend><div id="compute-offer-list"><p class="hint">Find GPUs to see current availability and hourly prices.</p></div></fieldset><p class="hint" id="compute-quote-age"></p>
      <label>Model to host<input name="model" placeholder="Hugging Face owner/model" required maxlength="200"></label>
      <p class="hint" id="compute-price">Select a GPU to review its price.</p>
      <label class="check"><input type="checkbox" name="cost" required>I approve this rental and its ongoing provider charges.</label>
      <p class="error" role="alert"></p>
      <div class="admin-row"><button class="primary" type="submit">Rent GPU and host model</button><p class="hint small-print">Prices use the GPU count and disk above. A persistent volume survives stopping the pod but not deleting it, and is charged until deleted.</p></div></form>
      </div>`)}
    </div>`;
  placeAdmin("#slot-compute", area);
  const activity = adminElement("admin-activity", "Compute activity", "Rentals, model loads and connections, newest first.", '<div id="compute-activity" aria-live="polite"></div>');
  activity.classList.add("activity-bottom");
  placeAdmin("#slot-activity", activity);
  bindContributor(refreshCompute);
  bindRentals();
  bindCopies(area.querySelector(".command-steps"));
  bindCopies(area.querySelector("#compute-share"));
  $("#compute-start").addEventListener("click", async () => {
    try { await computeJob("start"); } catch(error) { notice(error.message); }
  });
  // Codes are optional: unticked, a computer that runs the commands joins at once.
  $("#compute-admission").elements.code.addEventListener("change", async event => {
    const box = event.target, ask = box.checked;
    box.disabled = true;
    try {
      await api("/api/admin/compute/admission", {open: !ask});
      await refreshCompute();
      notice(ask ? "Each computer now shows a code for you to approve." : "Computers now join without a code.");
    } catch (error) { box.checked = !ask; notice(error.message); }
    finally { box.disabled = false; }
  });
  // The box decides: ticked keeps or replaces the password, unticked removes it so you approve every computer.
  const access = $("#compute-password");
  access.elements.protected.addEventListener("change", event => {
    access.elements.password.disabled = !event.target.checked;
    if (event.target.checked) access.elements.password.focus();
  });
  formAction("#compute-password", async (data, form) => {
    const use = form.elements.protected.checked, password = form.elements.password.value;
    if (use && !password && !computeView?.password_set) throw new Error("Type a password of at least 12 characters, or untick the box.");
    if (use && !password) return notice("The contributor password stays as it is.");
    await api("/api/admin/compute/password", {password: use ? password : ""});
    form.elements.password.value = ""; await refreshCompute();
    notice(use ? "Contributor password saved." : "You now approve every computer yourself.");
  });
  formAction("#compute-offered-add", async (data, form) => {
    const name = data.model.trim();
    await api("/api/admin/compute/models", {models: [...(computeView?.offered || []), name]});
    form.reset(); await refreshCompute();
    notice(`${name} added. Computers that connect can choose it.`);
  });
  $("#compute-offered-list").addEventListener("click", async event => {
    const button = event.target.closest("[data-remove-offered]");
    if (!button) return;
    button.disabled = true;
    try {
      await api("/api/admin/compute/models", {models: (computeView?.offered || []).filter(name => name !== button.dataset.removeOffered)});
      await refreshCompute();
    } catch (error) { notice(error.message); }
    finally { if(button.isConnected) button.disabled = false; }
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
  if(computeView && access.isConnected) { access.elements.protected.checked = !!computeView.password_set; access.elements.password.disabled = !computeView.password_set; }
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
    $("#compute-balance").textContent = account?.connected ? `RunPod balance: ${Number.isFinite(account.balance) ? "$" + account.balance.toFixed(2) : "not reported"}${Number.isFinite(account.spendPerHour) ? " · Current spend $" + account.spendPerHour.toFixed(3) + "/hour" : ""}` : "Connect RunPod to see your account balance.";
    const host = value.hosts.find(h => h.role === "controller");
    const connected = host?.online && host.inventory.connected !== false;
    // Without Yougori on this website's server (every hosted inference), computers connect instead.
    $("#compute-website").hidden = !host; $("#rent-here").hidden = !host; $("#rent-direct").hidden = !!host;
    // The rented GPUs load beside the rest, never holding Local GPUs up.
    if(!host) refreshRentals().catch(error => { if(area.isConnected) notice(error.message); });
    $("#compute-start").hidden = !host?.online || connected;
    $("#compute-start").disabled = value.jobs.some(j => j.kind === "start" && ["queued", "running"].includes(j.state));
    $("#compute-location").textContent = host ? `${host.name} · ${connected ? "Connected to this website" : "Compute offline"}. ${host.inventory.detail || ""}` : "The website server has no Yougori backend connected. Install and start Yougori on the server hosting this website; no visitor-side installation is required for rentals.";
    $("#compute-password-state").textContent = value.password_set ? "A password is set: signed-in people who know it connect a computer without your approval. Type a new one to replace it." : "You approve every computer yourself.";
    // Without codes the code box and the password are not needed, and the steps say so.
    const admission = $("#compute-admission").elements.code;
    if (!admission.disabled) admission.checked = !value.open;
    for (const id of ["#contributor-inspect", "#contributor-review", "#compute-password"]) $(id).hidden = !!value.open;
    $("#compute-admission-state").textContent = value.open
      ? "Any computer that runs these commands joins at once, without a code, and serves only the models you list. It sees the requests it serves."
      : "Each computer shows a code: approve it here, or let people approve their own computers with a password.";
    $("#compute-run-hint").textContent = value.open
      ? "Run these on each computer with a GPU, in order, and choose what it shares. It joins at once; keep its terminal open."
      : "Run these on each computer with a GPU, in order, and choose what it shares. Approve the code it shows, and keep its terminal open.";
    // Each listed model with how many connected computers serve it now.
    const offeredKey = name => name.replace(/^hf\.co\//, "").toLowerCase();
    const serving = name => value.hosts.filter(node => node.online && node.role === "contributor" &&
      node.inventory.models?.some(model => model.shared && model.offered && offeredKey(model.name) === offeredKey(name))).length;
    $("#compute-offered-list").innerHTML = value.offered?.length ? value.offered.map(name => {
      const count = serving(name);
      // What it needs from a GPU (checked when it was added), and which computers have such a GPU.
      const need = value.needs?.[name];
      const gpus = need?.computers && !need.problem ? ` · ${need.fits} of your ${need.computers} connected ${need.computers === 1 ? "computer has" : "computers have"} a GPU for it` : "";
      // A model listed before models were checked, which Yougori cannot run, says why.
      const said = !need ? '<p class="hint">Checking what it needs…</p>' : need.problem ? `<p class="error">${esc(need.problem)} Remove it.</p>` : `<p class="hint">${esc(need.summary + gpus)}</p>`;
      return `<div class="source"><div><strong>${esc(name)}</strong><p>${count ? `${count} ${count === 1 ? "computer runs" : "computers run"} it now` : "No computer runs it yet"}</p>${said}</div><button type="button" class="text-button" data-remove-offered="${esc(name)}">Remove</button></div>`;
    }).join("") : '<p class="hint">No models yet: add at least one for computers to run models for this website.</p>';
    // GPUs this website rented are listed under Rent a cloud GPU, not here.
    const computers = value.hosts.filter(node => node.role !== "rental");
    $("#compute-models").innerHTML = !computers.length ? '<p class="hint">No computer connected yet.</p>' : computers.map(node => `<div class="compute-node"><strong>${esc(node.name)}</strong><span class="badge ${node.online ? "ready" : ""}">${node.online ? "Online" : "Offline"}</span>${node.inventory.models?.length ? node.inventory.models.map(model => `<div class="source"><div><strong>${esc(model.name)}</strong><p>${esc(model.detail || model.state)}${model.shared ? (model.offered === false ? " · Not on your list of models for computers, so not in your catalog" : " · In your catalog") : ""}</p></div>${node.role === "controller" ? `<button type="button" class="text-button" data-share-model="${esc(model.id)}" data-enable="${!model.shared}" ${node.online ? "" : "disabled"}>${model.shared ? "Remove from inference" : "Add to inference"}</button>${model.shared && !["ready", "loading"].includes(model.state) ? `<button type="button" class="text-button" data-share-model="${esc(model.id)}" data-enable="true" ${node.online ? "" : "disabled"}>Retry model start</button>` : ""}` : ""}</div>`).join("") : '<p class="hint">No models reported yet.</p>'}${node.role === "contributor" ? `<button class="text-button" type="button" data-disconnect-compute="${esc(node.id)}">Disconnect contributor</button>` : ""}</div>`).join("");
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
      $("#compute-offer-list").innerHTML = quote.result.offers?.length ? quote.result.offers.map(offer => `<label class="compute-offer"><input type="radio" name="offer" required value="${esc(offer.id)}"><span><strong>${esc(offer.options?.gpu_count || 1)} × ${esc(offer.name)}</strong><span>${esc(offer.vram_gb ?? "—")} GB VRAM each · ${esc(offer.cloud)} · $${Number(offer.hourly_usd).toFixed(3)}/hour</span></span></label>`).join("") : '<p class="hint">No available GPUs returned. Refresh to check again.</p>';
      $("#compute-offer-list").onchange = event => {
        const selected = quote.result.offers.find(o => o.id === event.target.value);
        if (selected) $("#compute-price").textContent = `${selected.name}: maximum compute price $${Number(selected.hourly_usd).toFixed(3)}/hour. Availability and price are checked again before renting.`;
        $("#compute-rent").elements.cost.checked = false;
      };
    }
    $("#compute-activity").innerHTML = value.jobs.length ? value.jobs.map(job => `<div class="source"><div><strong>${esc({rent:"Cloud GPU rental",load:"Load model",share:"Model connection",offers:"GPU offers",provider:"Provider account",account:"Provider balance",stop:"Stop cloud GPU",start:"Start website compute"}[job.kind] || job.kind)}</strong><span class="badge ${job.state === "done" ? "ready" : ""}">${esc(job.state)}</span><p>${esc(job.detail)}</p>${job.result.environment ? `<p class="hint">${esc(job.result.environment)}</p>` : ""}</div>${job.kind === "rent" && job.result.environment ? `<button type="button" class="text-button" data-stop-rental="${esc(job.id)}">Stop rented GPU</button>` : ""}</div>`).join("") : '<p class="hint">Rentals and model connections appear here as soon as you start them.</p>';
    const [discovered, overview] = await Promise.all([api("/api/models"), api("/api/admin/overview")]);
    if(!area.isConnected) return;
    models = discovered.models;
    const list = $("#model-servers");
    if(list) list.innerHTML = serverRows(overview.endpoints);
    adminSummary();
  } catch (error) { if(area.isConnected) notice(error.message); }
  finally { if(area.isConnected) computeTimer = setTimeout(refreshCompute, 3000); }
}

// A connecting computer shows a code: administrators approve it in Admin's Local GPUs, under the
// command; a signed-in contributor with the contributor password uses its own page (#contribute,
// which the connector names). Approve only a computer you recognize.
function contributorForm() {
  return `<form id="contributor-inspect" class="stack"><div class="admin-row"><label>Code from the contributor<input name="code" required maxlength="8" autocomplete="off" spellcheck="false" placeholder="The code its terminal shows"></label><button class="secondary" type="submit">Check computer</button></div><p class="error" role="alert"></p></form><div id="contributor-review"></div>`;
}
function bindContributor(done) {
  formAction("#contributor-inspect", async data => {
    const info = await api("/api/compute/pair/inspect", data);
    $("#contributor-review").innerHTML = `<form id="contributor-approve" class="stack"><p>Connect <strong>${esc(info.name)}</strong> as a GPU contributor? Inference requests may be sent to it; it cannot manage this website or rent GPUs.</p>${session.user.admin ? "" : '<label>Contributor password<input name="password" type="password" autocomplete="off"></label>'}<p class="error" role="alert"></p><div><button class="primary" type="submit">Approve this computer</button></div></form>`;
    formAction("#contributor-approve", async values => {
      const result = await api("/api/compute/pair/approve", {code: data.code, password: values.password || ""});
      $("#contributor-review").textContent = `${result.name} is connected. Its shared models will appear automatically.`;
      $("#contributor-inspect").reset();
      await done?.();
    });
  });
}
function renderContributor() {
  header("Connect a contributing computer", "Approve only a computer you recognize. Inference requests may be sent to this computer. It cannot manage the website or rent cloud GPUs.");
  $("#view").innerHTML = panel("Computer code", contributorForm());
  bindContributor();
}

// Renting with the administrator's own neocloud accounts, right here: the website rents the GPU
// and starts the model on it, and the GPU connects back by itself (rentals.py). No computer of
// the administrator's is needed. Shown when the website's server has no Yougori of its own.
const RENTAL_PROVIDERS = [["runpod", "RunPod", "runpod.io: Settings, API Keys"], ["vast", "Vast.ai", "cloud.vast.ai: Account, Keys"]];
const RENTAL_STATES = {creating: "Renting", starting: "Starting", loading: "Loading the model", ready: "Ready", attention: "Needs attention", failed: "Failed", stopped: "Stopped"};
let rentalQuote = null, rentalPending = null, rentalFinding = null, rentalAuto = 0, rentalModel = null, rentalChecking = 0;
function rentalForms() {
  return `<div class="stack" id="rent-direct" hidden><p class="hint">Rent GPUs from RunPod or Vast.ai with your own account. This website starts your model on the GPU, and the model joins your catalog when it is ready. No computer of yours is needed.</p>
    ${RENTAL_PROVIDERS.map(([id, name, where]) => `<form class="stack rental-account" data-provider="${id}"><div class="admin-row"><label>${esc(name)} API key<input name="key" type="password" autocomplete="new-password" maxlength="512" required placeholder="From ${esc(where)}"></label><button class="secondary" type="submit">Save ${esc(name)} key</button><button class="text-button" type="button" data-forget-provider="${id}" hidden>Forget key</button></div><p class="hint" data-provider-state="${id}">Not connected.</p><p class="error" role="alert"></p></form>`).join("")}
    <p class="hint">Keys stay on this website's server and are never shown again.</p>
    <form id="rental-search" class="stack"><div class="admin-row"><label>GPUs per server<select name="gpu_count">${Array.from({length: 8}, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("")}</select></label><label>Disk (GB)<input name="disk_gb" type="number" min="40" max="2000" value="80" required></label><button class="secondary" type="submit">Find available GPUs</button></div><p class="error" role="alert"></p></form>
    <form id="rental-rent" class="stack"><fieldset class="compute-offers"><legend>Available GPUs</legend><div id="rental-offer-list"><p class="hint">Checking RunPod and Vast.ai for available GPUs…</p></div></fieldset><p class="hint" id="rental-quote-age"></p>
      <label>Model to host<input name="model" placeholder="Hugging Face owner/model" required maxlength="200"></label>
      <p class="hint" id="rental-model-check" role="status">A public Hugging Face chat model, such as Qwen/Qwen3-8B. Yougori checks what it needs, and marks the GPUs that cannot run it.</p>
      <label class="check"><input type="checkbox" name="cost" required>I approve this rental and its ongoing provider charges.</label>
      <p class="error" role="alert"></p>
      <div class="admin-row"><button class="primary" type="submit" disabled>Rent GPU and host model</button></div></form>
    <div id="rental-list" aria-live="polite"></div></div>`;
}
function bindRentals() {
  for (const [id, name] of RENTAL_PROVIDERS) {
    formAction(`.rental-account[data-provider="${id}"]`, async (data, form) => {
      showRentals(await api("/api/admin/rentals/account", {provider: id, key: data.key}));
      form.reset(); notice(`${name} key saved. Its GPUs can be rented now.`);
      findGpus().catch(error => notice(error.message));
    });
  }
  $("#rent-direct").addEventListener("click", event => {
    const forget = event.target.closest("[data-forget-provider]"), stop = event.target.closest("[data-stop-rental-gpu]");
    if (forget) confirmAction("Forget this key?", "This website can no longer rent or stop GPUs with it until you save it again.", async () => {
      showRentals(await api("/api/admin/rentals/forget", {provider: forget.dataset.forgetProvider}));
      findGpus().catch(error => notice(error.message));
    });
    if (stop) confirmAction("Stop and delete this GPU?", "Its charges end and its model leaves your catalog. Renting again downloads the model again.",
      async () => showRentals(await api("/api/admin/rentals/stop", {id: stop.dataset.stopRentalGpu})));
  });
  formAction("#rental-search", async () => { await findGpus(); });
  // The model is checked as it is typed: what it needs, and which of the GPUs listed can run it.
  let typing;
  $("#rental-rent").elements.model.addEventListener("input", event => {
    clearTimeout(typing);
    const model = event.target.value.trim(), turn = ++rentalChecking, line = $("#rental-model-check");
    rentalModel = null;
    if (rentalQuote) showOffers();
    if (!/^[^/\s]+\/[^/\s]+$/.test(model)) { line.textContent = "A public Hugging Face chat model, such as Qwen/Qwen3-8B. Yougori checks what it needs, and marks the GPUs that cannot run it."; return; }
    line.textContent = `Checking ${model}…`;
    typing = setTimeout(async () => {
      try {
        const facts = await api("/api/admin/rentals/check", {model});
        if (turn !== rentalChecking || !$("#rental-rent")) return;
        rentalModel = facts;
        line.textContent = [facts.summary, ...facts.notes].join(" ");
        if (rentalQuote) showOffers();
      } catch (error) { if (turn === rentalChecking && line.isConnected) line.textContent = error.message; }
    }, 700);
  });
  formAction("#rental-rent", async (data, form) => {
    if (!rentalQuote || !data.offer) throw new Error("Choose an available GPU.");
    // A retried press rents nothing twice: the same choice keeps its request identity.
    const signature = JSON.stringify([rentalQuote.id, data.offer, data.model.trim()]);
    if (rentalPending?.signature !== signature) rentalPending = {signature, identity: crypto.randomUUID()};
    showRentals(await api("/api/admin/rentals/rent", {request_id: rentalPending.identity, quote_id: rentalQuote.id, offer: data.offer,
      model: data.model.trim(), cost_acknowledged: data.cost === "on"}));
    rentalPending = null; form.elements.cost.checked = false;
    notice("Renting the GPU. Its model joins your catalog when it is ready.");
  });
}
// Both providers list their GPUs without a key: the list shows as soon as the section does, and
// its prices stay current. One lookup at a time; the chosen GPU stays chosen while offered.
function findGpus() {
  if (rentalFinding) return rentalFinding;
  const form = $("#rental-search");
  rentalFinding = api("/api/admin/rentals/offers", {gpu_count: Number(form.elements.gpu_count.value), disk_gb: Number(form.elements.disk_gb.value)})
    .then(quote => { rentalQuote = quote; if ($("#rent-direct")) showOffers(); })
    .finally(() => { rentalFinding = null; });
  return rentalFinding;
}
function showOffers() {
  const names = Object.fromEntries(RENTAL_PROVIDERS), quote = rentalQuote, chosen = new FormData($("#rental-rent")).get("offer");
  // With a model checked, a GPU that cannot run it says why and cannot be chosen.
  const need = rentalModel, unfit = offer => !need ? "" : !need.rent ? "this model does not run on rented GPUs"
    : (offer.vram_gb || 0) * offer.gpu_count < need.gpu_gb ? `too little GPU memory for this model (it needs about ${need.gpu_gb} GB)`
    : offer.compute && offer.compute < need.compute ? "too old a GPU for this model" : "";
  const usable = offer => offer.connected && !unfit(offer);
  $("#rental-offer-list").dataset.quote = quote.id;
  $("#rental-offer-list").innerHTML = (quote.offers.length ? quote.offers.map(offer => `<label class="compute-offer"><input type="radio" name="offer" required value="${esc(offer.id)}"${usable(offer) ? "" : " disabled"}${usable(offer) && offer.id === chosen ? " checked" : ""}><span><strong>${offer.gpu_count > 1 ? esc(offer.gpu_count) + " × " : ""}${esc(offer.name)}</strong><span>${offer.vram_gb ? esc(offer.vram_gb) + " GB" + (offer.gpu_count > 1 ? " each" : "") + " · " : ""}${esc(names[offer.provider])} · ${esc(offer.where)} · $${Number(offer.hourly_usd).toFixed(3)}/hour${offer.connected ? "" : ` · save your ${esc(names[offer.provider])} key to rent it`}${unfit(offer) ? " · " + esc(unfit(offer)) : ""}</span></span></label>`).join("")
    : '<p class="hint">No GPUs are available with these choices now. Try another count or disk size.</p>')
    + quote.issues.map(issue => `<p class="hint">${esc(names[issue.provider])}: ${esc(issue.detail)}</p>`).join("");
  $("#rental-rent").querySelector('[type="submit"]').disabled = !quote.offers.some(usable);
  $("#rental-quote-age").textContent = quote.offers.length ? "Live prices, updated every two minutes." : "";
}
async function refreshRentals() {
  showRentals(await api("/api/admin/rentals"));
  const stale = !rentalQuote || rentalQuote.created < Date.now() / 1000 - 100;
  // Admin opened again: the GPUs found a moment ago show at once.
  if (!stale && $("#rental-offer-list").dataset.quote !== rentalQuote.id) showOffers();
  if (stale && !rentalFinding && Date.now() - rentalAuto > 100000 && $("#rental-search").checkValidity()) {
    rentalAuto = Date.now();
    findGpus().catch(error => { const alert = $("#rental-search [role=alert]"); if (alert) alert.textContent = error.message; });
  }
}
function showRentals(view) {
  if (!$("#rent-direct")) return;
  for (const account of view.accounts) {
    const state = $(`[data-provider-state="${account.provider}"]`), balance = account.account?.balance;
    if (!state) continue;
    state.textContent = account.connected ? `Connected${Number.isFinite(balance) ? ` · balance $${balance.toFixed(2)}` : ""}.` : "Not connected.";
    $(`[data-forget-provider="${account.provider}"]`).hidden = !account.connected;
  }
  $("#rental-list").innerHTML = view.rentals.length ? '<p><strong>Your rented GPUs</strong></p>' + view.rentals.map(rental => `<div class="source"><div><strong>${rental.gpu_count > 1 ? esc(rental.gpu_count) + " × " : ""}${esc(rental.gpu)} · ${esc(rental.provider)}</strong><span class="badge ${rental.state === "ready" ? "ready" : ""}">${esc(RENTAL_STATES[rental.state] || rental.state)}</span><p>${esc(rental.model)} · $${Number(rental.hourly_usd).toFixed(3)}/hour${rental.where ? " · " + esc(rental.where) : ""}</p><p class="hint">${esc(rental.detail)}</p></div>${["stopped", "failed"].includes(rental.state) ? "" : `<button type="button" class="text-button" data-stop-rental-gpu="${esc(rental.id)}">Stop and delete</button>`}</div>`).join("") : "";
}
