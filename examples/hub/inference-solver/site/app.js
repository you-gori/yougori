/* No framework, build step, third-party scripts, or template-supplied HTML. */
"use strict";
const $ = selector => document.querySelector(selector);
let session, harnesses = [], categories = [], models = [], authMode = "signin", viewGeneration = 0, returnTo = "", shownPage = "";
const AUTH_ROUTES = ["signin", "signup", "join"];
// The administrator picks which of the three main pages people open first, and which harnesses are offered.
const MAIN = ["harnesses", "models", "sandboxes"];
const PAGES = [...MAIN, "contribute", "connect", "keys", "usage", "admin"];
const home = () => session?.choices?.home || "harnesses";
const offeredHarnesses = () => harnesses.filter(h => h.offered !== false);
// Until an administrator has chosen, the main pages show them the choice instead.
const choosing = name => !!session?.user?.admin && !session.choices?.chosen && MAIN.includes(name);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ready = model => model.state === "ready";
const friendly = model => model.upstream.split("/").pop();
const nowLabel = value => value ? new Date(value * 1000).toLocaleString() : "Not checked";
function installCommand(name, address = location) {
  if (!/^[a-z][a-z0-9-]*$/.test(name) || !/^https?:\/\/[A-Za-z0-9.\-:\[\]]+$/.test(address.origin)) {
    throw new Error("This installation address is invalid.");
  }
  return name === "node" ? `yougori inference connect "${address.origin}"`
    : `yougori inference run ${name} --server "${address.origin}"`;
}
const PROTOCOLS = {chat_completions: "Chat Completions", responses: "Responses", messages: "Messages", google: "Gemini", mcp: "MCP", custom: "Custom adapter", jobs: "Jobs", images: "Images", speech: "Speech", videos: "Videos"};
// A media model generates images, video, speech or sound: it takes jobs, not chat.
const TASKS = {"text-to-image": "Image generation", "image-to-image": "Image to image", "text-to-video": "Video generation", "image-to-video": "Image to video", "text-to-audio": "Sound generation", "text-to-speech": "Speech"};
const isMedia = m => Object.hasOwn(TASKS, m.task);
const SAMPLE_INPUTS = {"text-to-image": {prompt: "a red bicycle leaning on a white wall, morning light", width: 512, height: 512, steps: 4}, "image-to-image": {prompt: "the same scene in winter", image: "data:image/png;base64,...", strength: 0.6}, "text-to-video": {prompt: "a paper boat drifting down a stream", seconds: 2}, "image-to-video": {prompt: "a slow push in", image: "data:image/png;base64,...", seconds: 2}, "text-to-audio": {prompt: "rain on a tin roof", seconds: 5}, "text-to-speech": {text: "Hello from this inference service."}};
const mediaPriced = m => m.media_price && (m.media_price.image_microusd || m.media_price.second_microusd);
const mediaPrice = m => !mediaPriced(m) ? "Free" : [m.media_price.image_microusd ? dollars(m.media_price.image_microusd) + " per image" : "", m.media_price.second_microusd ? dollars(m.media_price.second_microusd) + " per second of output" : ""].filter(Boolean).join(" / ");
const CATEGORIES = {};
const STATES = {ready: "Available", stale: "Stale", unavailable: "Unavailable", checking: "Checking"};
const PLACES = {local: "Local host", neocloud: "Rented cloud GPU", mixed: "Local hosts and rented cloud GPUs"};
// A model is published once; each connected computer or model server serving it is a replica.
const servedBy = m => m.replicas?.length ? `${m.replicas.length} ${m.replicas.length === 1 ? "server" : "servers"}` : "";
const cacheHits = m => Number.isFinite(m.cache?.hit_rate) ? `${Math.round(m.cache.hit_rate * 1000) / 10}% cached input` : "";
const CENSORSHIP = {censored: "Censored", uncensored: "Uncensored"};
const named = (names, value) => Object.hasOwn(names || {}, value) ? names[value] : String(value);
const byName = name => (a, b) => name(a).localeCompare(name(b), undefined, {sensitivity: "base", numeric: true});
const catalogState = {};
let redrawModels = null;
// Earlier designs saved their own default blues as the accent; they now show as this design's blue.
// The colour styles an administrator can choose for every visitor (style.css has each one's colours).
const PALETTES = [["navy", "Navy"], ["nord", "Nord"], ["solarized", "Solarized"], ["catppuccin", "Catppuccin"], ["rose-pine", "Rosé Pine"], ["gruvbox", "Gruvbox"]];

function closeMenu() {
  $("#menu").classList.remove("open"); $("#menu-toggle").setAttribute("aria-expanded", "false"); $("#nav-panel").inert = true;
}
function currentRoute() {
  const hash = location.hash.slice(1), slash = hash.indexOf("/");
  if (slash < 0) return [hash || home(), ""];
  try { return [hash.slice(0, slash), decodeURIComponent(hash.slice(slash + 1))]; }
  catch { return [hash.slice(0, slash), ""]; }
}
function paintNavigation() {
  const signedIn = !!session?.user, [current] = currentRoute();
  const links = [...document.querySelectorAll("#nav a, #signin-link, #signup-link")].filter(a => !a.hidden);
  $("#menu-links").replaceChildren(...links.map(link => {
    const copy = link.cloneNode(true); copy.removeAttribute("id"); copy.className = "nav-link";
    copy.addEventListener("click", event => {
      event.preventDefault(); const next = copy.hash; closeMenu();
      if(location.hash === next) route(); else location.hash = next;
    }); return copy;
  }));
  $("#menu-signout").hidden = !signedIn;
  $("#account-email").textContent = session?.user?.email || (session?.mode === "public" ? "Public inference" : "Private inference");
  const gated = !signedIn && ["signin", "join", "connect", "keys", "usage", "admin"].includes(current);
  const active = links.find(a => a.hash === "#" + (gated ? "signin" : current)) || links[0];
  document.querySelectorAll('#nav a, #signin-link, #signup-link, #menu-links a').forEach(a => {
    if (a.hash === active?.hash) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}
const darkQuery = matchMedia("(prefers-color-scheme: dark)");
function themeLabel() {
  const dark = (document.documentElement.dataset.theme || (darkQuery.matches ? "dark" : "light")) === "dark";
  document.querySelectorAll("[data-theme-toggle]").forEach(button => {
    button.textContent = dark ? "Light mode" : "Dark mode";
    button.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  });
}
document.querySelectorAll("[data-theme-toggle]").forEach(button => button.addEventListener("click", () => {
  const dark = (document.documentElement.dataset.theme || (darkQuery.matches ? "dark" : "light")) === "dark";
  const theme = dark ? "light" : "dark"; document.documentElement.dataset.theme = theme;
  try { localStorage.setItem("theme", theme); } catch { /* This visit still uses the chosen theme. */ }
  themeLabel();
}));
darkQuery.addEventListener("change", themeLabel); themeLabel();
$("#menu-toggle").addEventListener("click", () => {
  const open = $("#menu").classList.toggle("open"); $("#menu-toggle").setAttribute("aria-expanded", String(open)); $("#nav-panel").inert = !open;
});
document.addEventListener("keydown", event => { if(event.key === "Escape" && $("#menu").classList.contains("open")) { closeMenu(); $("#menu-toggle").focus(); } });
document.addEventListener("click", event => { if (!$("#menu").contains(event.target)) closeMenu(); });
document.addEventListener("keydown", event => {
  if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || $("#dialog").open || event.target.closest?.("input, textarea, select, [contenteditable]")) return;
  const search = $("#catalog-search");
  if (search && !search.closest("[hidden]")) { event.preventDefault(); search.focus(); }
});
$("#menu-signout").addEventListener("click", () => $("#signout").click());
// Main buttons end in an arrow inside a circle. The full label stays the accessible name.
function pill(button) {
  if (button.querySelector(":scope > .pill-arrow")) return;
  const label = button.textContent.trim();
  button.setAttribute("aria-label", label);
  button.innerHTML = `<span>${esc(label.replace(/\s*[↗→]$/, ""))}</span><i class="pill-arrow" aria-hidden="true">→</i>`;
}
const pills = () => document.querySelectorAll(".primary").forEach(pill);
new MutationObserver(pills).observe(document.body, {childList: true, subtree: true});
pills();

async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? "GET" : "POST", credentials: "same-origin",
    headers: {"Content-Type":"application/json", ...(body !== undefined && session?.user ? {"X-CSRF-Token":session.user.csrf} : {})},
    ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message || "The request could not be completed.");
  return data;
}
function notice(message) { $("#notice").textContent = message; }
async function copy(text, button) {
  try { await navigator.clipboard.writeText(text); button.textContent = "Copied"; }
  catch { notice("Select the text and copy it. Clipboard access is unavailable in this browser."); }
}
function modal(title, html, kicker = "Inference Solver") {
  $("#dialog-title").textContent = title; $("#dialog-kicker").textContent = kicker;
  $("#dialog-body").innerHTML = html; $("#dialog").showModal();
}
function formAction(selector, action) {
  $(selector).addEventListener("submit", async event => {
    event.preventDefault(); const form = event.currentTarget, button = form.querySelector('[type="submit"]');
    const error = form.querySelector('[role="alert"]'); if(error) error.textContent = "";
    button.disabled = true;
    try { await action(Object.fromEntries(new FormData(form)), form); }
    catch (problem) { if(error) error.textContent = problem.message; else notice(problem.message); }
    finally { button.disabled = false; }
  });
}
function empty(title, text, button = "") {
  return `<div class="empty"><h3>${esc(title)}</h3><p>${esc(text)}</p>${button}</div>`;
}
function bindCopies(root = document) {
  root.querySelectorAll("[data-copy]").forEach(button => button.addEventListener("click", () => copy(button.dataset.copy, button)));
}
function header(title, description, actions = "") {
  $("#section-title").textContent = title; $("#section-description").textContent = description;
  $("#section-actions").innerHTML = actions;
}
function panel(title, body, side = "") {
  return `<section class="panel"><div class="panel-heading"><h2>${esc(title)}</h2>${side}</div><div class="panel-body">${body}</div></section>`;
}
function facts(rows) {
  return `<dl class="facts">${rows.filter(([, value]) => value).map(([name, value]) => `<div><dt>${esc(name)}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl>`;
}

async function loadSession() {
  session = await api("/api/session"); document.title = session.site.name;
  $("#brand").textContent = session.site.name; $("#footer-name").textContent = session.site.name; $("#tagline").textContent = session.site.tagline;
  // CSSOM assignment of a validated six-digit color, never an inline HTML fragment.
  document.documentElement.dataset.palette = PALETTES.some(([id]) => id === session.site.palette) ? session.site.palette : "navy";
  const signedIn = !!session.user;
  document.querySelectorAll("[data-member-only]").forEach(link => { link.hidden = !signedIn; });
  $("#signin-link").hidden = signedIn;
  $("#signup-link").hidden = signedIn || session.mode !== "public";
  $("#signout").hidden = !signedIn;
  $("#admin-link").hidden = !session.user?.admin;
  closeMenu(); paintNavigation();
  const [catalog, discovered] = await Promise.all([api("/api/harnesses"), api("/api/models")]);
  harnesses = catalog.harnesses; models = discovered.models;
  categories = catalog.categories || [];
  for (const category of categories) CATEGORIES[category.id] = category.label;
  // The main page leads the menu and the site name links to it; Harnesses goes when none are offered.
  const mains = MAIN.map(id => $(`#nav a[href="#${id}"]`));
  $("#nav").prepend(...mains.filter(a => a.hash === "#" + home()), ...mains.filter(a => a.hash !== "#" + home()));
  mains[0].hidden = !offeredHarnesses().length;
  $("#brand").setAttribute("href", "#" + home());
  await route();
}

// Tools and models share one catalog: optional filters, search and sort above a list with one row per entry.
// Each row links to its own page. Search, sort and filter survive refreshes and navigation.
// With `menu`, the filters become one dropdown of checkboxes and any number can be chosen; otherwise
// they are pill buttons and one at a time can be chosen.
function catalog({key, one, noun, items, filters = [], menu = null, sorts, text, row, grid = false, note = ""}) {
  const state = catalogState[key] ||= {search: "", sort: sorts[0][0], filter: "", chosen: [], scroll: 0};
  const dot = f => `<i class="filter-dot" data-color="${esc(f.color || "")}" aria-hidden="true"></i>`;
  const picker = !filters.length ? "" : menu
    ? `<div class="filter" id="${key}-filter"><button type="button" class="filter-button" id="${key}-filter-button" aria-expanded="false" aria-controls="${key}-filter-menu"><span class="filter-dots"></span><span class="filter-summary"></span><svg viewBox="0 0 12 12" aria-hidden="true"><path d="m3 4.5 3 3 3-3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></button><div class="filter-menu" id="${key}-filter-menu" role="group" aria-label="${esc(menu.label)}" hidden>${filters.map(f => `<label class="filter-option" data-color="${esc(f.color || "")}"><input type="checkbox" value="${esc(f.id)}">${dot(f)}<span class="filter-name">${esc(f.label)}</span><span class="filter-count"></span></label>`).join("")}<button type="button" class="text-button filter-clear">Show all</button></div></div>`
    : `<div class="toggles" role="group" aria-label="Filter ${noun}">${filters.map(f => `<button type="button" class="toggle" data-filter="${f.id}" aria-pressed="false">${esc(f.label)} <span class="toggle-count"></span></button>`).join("")}</div>`;
  $("#view").innerHTML = `<div class="catalog"><div class="toolbar">${picker}<div class="search-box"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m11 11 3.5 3.5" stroke="currentColor" stroke-width="1.6"/></svg><input type="search" id="catalog-search" aria-label="Search ${noun}" placeholder="Search ${noun}" autocomplete="off"><kbd aria-hidden="true">/</kbd></div><label class="sort">Sort<select id="catalog-sort" aria-label="Sort ${noun}">${sorts.map(([value, name]) => `<option value="${value}">${esc(name)}</option>`).join("")}</select></label></div><p class="count" id="catalog-count" aria-live="polite"></p><div class="${grid ? "entries grid" : "entries list"}" id="${key}-list"></div>${note}</div>`;
  const search = $("#catalog-search"), sort = $("#catalog-sort"), list = $(`#${key}-list`), count = $("#catalog-count");
  const toggles = [...document.querySelectorAll("#view [data-filter]")];
  const paint = root => root.querySelectorAll("[data-color]").forEach(node => {
    if (/^#[0-9a-f]{6}$/i.test(node.dataset.color)) node.style.setProperty("--category-blue", node.dataset.color);
  });
  paint($("#view .toolbar"));
  const amount = n => `${n} ${n === 1 ? one : noun}`;
  search.value = state.search; sort.value = state.sort;
  const draw = () => {
    const all = items(), words = state.search.trim().toLowerCase();
    const chosen = filters.filter(f => menu ? state.chosen.includes(f.id) : f.id === state.filter);
    for (const button of toggles) {
      const filter = filters.find(f => f.id === button.dataset.filter);
      button.setAttribute("aria-pressed", String(chosen.includes(filter)));
      button.querySelector(".toggle-count").textContent = all.filter(filter.test).length;
    }
    if (menu) {
      for (const box of document.querySelectorAll(`#${key}-filter-menu input`)) {
        const filter = filters.find(f => f.id === box.value);
        box.checked = chosen.includes(filter);
        box.closest("label").querySelector(".filter-count").textContent = all.filter(filter.test).length;
      }
      const summary = !chosen.length ? menu.all : chosen.length === 1 ? chosen[0].label : `${chosen.length} selected`;
      $(`#${key}-filter .filter-summary`).textContent = summary;
      $(`#${key}-filter-button`).setAttribute("aria-label", `${menu.label}: ${summary}`);
      $(`#${key}-filter .filter-dots`).innerHTML = chosen.map(dot).join("");
      paint($(`#${key}-filter .filter-dots`));
      $(`#${key}-filter .filter-clear`).hidden = !chosen.length;
    }
    const shown = all.filter(item => (!chosen.length || chosen.some(f => f.test(item))) && (!words || text(item).toLowerCase().includes(words)));
    shown.sort(sorts.find(([value]) => value === state.sort)[2]);
    count.textContent = shown.length === all.length ? amount(all.length) : `${shown.length} of ${amount(all.length)}`;
    list.innerHTML = shown.map(row).join("") || empty(`No ${noun} found`, "Try another name or filter.");
    list.querySelectorAll("[data-category]").forEach(card => {
      const color = categories.find(c => c.id === card.dataset.category)?.color;
      if (/^#[0-9a-f]{6}$/i.test(color || "")) card.style.setProperty("--category-blue", color);
    });
    bindCopies(list);
    return list.isConnected;
  };
  // A second press on the chosen filter shows everything again.
  for (const button of toggles) button.addEventListener("click", () => { state.filter = state.filter === button.dataset.filter ? "" : button.dataset.filter; draw(); });
  if (menu) {
    // The list stays open while boxes are ticked; a click elsewhere, Tab away or Escape closes it.
    const wrap = $(`#${key}-filter`), button = $(`#${key}-filter-button`), panel = $(`#${key}-filter-menu`);
    const show = open => { panel.hidden = !open; button.setAttribute("aria-expanded", String(open)); };
    button.addEventListener("click", () => show(panel.hidden));
    panel.addEventListener("change", () => { state.chosen = [...panel.querySelectorAll("input:checked")].map(box => box.value); draw(); });
    panel.querySelector(".filter-clear").addEventListener("click", () => { state.chosen = []; draw(); show(false); button.focus(); });
    wrap.addEventListener("keydown", event => { if (event.key === "Escape" && !panel.hidden) { event.stopPropagation(); show(false); button.focus(); } });
    wrap.addEventListener("focusout", event => { if (event.relatedTarget && !wrap.contains(event.relatedTarget)) show(false); });
    const outside = event => {
      if (!wrap.isConnected) document.removeEventListener("pointerdown", outside);
      else if (!wrap.contains(event.target)) show(false);
    };
    document.addEventListener("pointerdown", outside);
  }
  search.addEventListener("input", () => { state.search = search.value; draw(); });
  sort.addEventListener("change", () => { state.sort = sort.value; draw(); });
  // Coming back from an entry's page returns to the same place in the list.
  list.addEventListener("click", event => { if (event.target.closest(".entry-open")) state.scroll = scrollY; });
  draw();
  if (state.scroll) { scrollTo(0, state.scroll); state.scroll = 0; }
  return draw;
}
const pageLink = (key, id) => `#${key}/${encodeURIComponent(id)}`;
function missing(key, text) {
  const tools = key === "harnesses";
  header("Not found", text, `<a class="secondary" href="#${key}">← ${tools ? "All tools" : "All models"}</a>`);
  $("#view").innerHTML = empty("Not found", text);
}
// Tools show as cards: the mark and state, the name and description, then the pinned version and the action.
function harnessRow(h) {
  const available = !!h.setup?.available;
  const facts = [["Category", named(CATEGORIES, h.category)], ["Interface", h.interface], ["API format", named(PROTOCOLS, h.protocol)]];
  return `<article class="entry"><div class="entry-head"><h3 class="entry-name"><a class="entry-open" href="${esc(pageLink("harnesses", h.id))}" data-harness="${esc(h.id)}">${esc(h.name)}</a></h3><span class="tag${available ? " ready" : ""}">${available ? "Ready" : "In preparation"}</span></div><p class="entry-text">${esc(h.description)}</p><dl class="entry-facts">${facts.map(([name, value]) => `<div><dt>${esc(name)}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl><p class="entry-meta"><span>${available ? `Pinned <span class="mono">${esc(h.setup.version)}</span>` : "Setup not available yet"}</span><span class="entry-more" aria-hidden="true">${available ? "Install" : "Learn more"}</span></p></article>`;
}
function renderHarnesses() {
  header("Tools for your models", "Connect the tools you know to the models you control.");
  const offered = offeredHarnesses();
  catalog({key: "harnesses", one: "tool", noun: "tools", items: () => offered, grid: true,
    filters: categories.filter(c => offered.some(h => h.category === c.id)).map(c => ({id: c.id, label: c.label, color: c.color, test: h => h.category === c.id})),
    menu: {label: "Category", all: "All categories"},
    sorts: [
      ["ready", "Ready first", (a, b) => Number(!!b.setup?.available) - Number(!!a.setup?.available)],
      ["name", "Name A–Z", byName(h => h.name)],
      ["name-desc", "Name Z–A", (a, b) => byName(h => h.name)(b, a)],
    ],
    text: h => [h.name, h.description, h.interface, h.category].join(" "),
    row: harnessRow,
    note: '<p class="hint catalog-note">Blue terminals. Your models. Isolated setups connect only to this server; browsing, external APIs, and package downloads are blocked while a tool runs.</p>',
  });
  $("#harnesses-list").addEventListener("click", event => {
    const card = event.target.closest("[data-harness]");
    if(card) { event.preventDefault(); renderHarness(card.dataset.harness); }
  });
}
function renderHarness(id) {
  const h = offeredHarnesses().find(h => h.id === id);
  if (!h) return missing("harnesses", "This tool is not offered on this inference.");
  const available = !!h.setup?.available, listed = models.filter(ready).length;
  let main;
  if (available) {
    const install = installCommand(h.id);
    main = panel("Install and start", `<ol class="setup-steps install-steps"><li><strong>Install Yougori.</strong> ${esc(h.name)} runs in a Yougori Sandbox VM on your computer. <a class="text-button" id="get-yougori" href="https://yougori.com/#download" target="_blank" rel="noopener noreferrer">Download Yougori ↗</a> Already installed? Go to step 2.</li><li><strong>Run this command</strong> in a new terminal. Before the VM starts, Yougori asks what ${esc(h.name)} may use: a project folder (copied in; changes come back only after your review), what it can reach (only this inference, sites you choose, or the whole internet as well), and CPU and memory. <strong>${esc(h.name)} starts automatically after installation.</strong> Keep the terminal open.<pre class="code" id="guide-code">${esc(install)}</pre><button class="primary" id="guide-copy" data-copy="${esc(install)}">Copy install command</button><p class="hint" id="not-recognized">If the terminal says <code>yougori</code> is not recognized, do step 1, then open a new terminal.</p></li><li><strong>Approve the code.</strong> On first use the terminal shows a link and a code: sign in here, enter the code and approve. The terminal then continues by itself. <a class="text-button" href="#connect" id="setup-account">Enter your connection code →</a></li></ol><p class="hint">No API key to create or copy.${h.id==='shannon'?' Shannon opens its command prompt. Type check to verify the model connection, help for commands, or exit to close it.':''}</p>${listed?'':'<p class="error">No models are ready. The administrator must connect a model before you can use this harness.</p>'}`)
      + panel("Open it again", `<p>Run the same Yougori command next time:</p><div class="install-command"><pre class="code" id="launch-code">${esc(install)}</pre><button class="secondary" data-copy="${esc(install)}">Copy start command</button></div><p class="hint">Yougori asks its questions again each time: add <code>--yes</code> to keep the defaults, or <code>--workspace "C:\\path\\to\\project"</code> to name the project folder. The VM works on a copy; review and promote changes in Yougori. It runs until you exit or stop it.</p>`)
        + `<details class="install-details"><summary>Requirements and source</summary><p class="hint">Yougori manages the private runtime on Windows. By default the VM reaches only this server; when you start it, Yougori asks whether it may also reach sites you choose or the whole internet. Linux source requires Python and a supported Yougori VM backend. macOS is not supported yet.</p><a class="text-button" id="harness-download" href="/api/harness-download/${encodeURIComponent(h.id)}" download>Download source setup ↓</a></details>`;
  } else {
    main = panel("In preparation", `<div class="small-banner">${esc(h.setup?.reason || "This tool needs an isolated launch adapter before it can be used here.")}</div><p class="hint">There is no unrestricted fallback. This setup will become available when it can run inside the same server-only boundary.</p>`);
  }
  const about = facts([["Status", available ? "Ready to install" : "In preparation"], ["Category", named(CATEGORIES, h.category)], ["Interface", h.interface], ["API format", named(PROTOCOLS, h.protocol)], ["Pinned version", h.setup?.version], ["Connected server", location.host]])
    + (available ? `<div class="small-banner">Blue terminal, connected to ${esc(location.host)}. External runtime network access is blocked.</div>` : "")
    + `<a class="text-button" href="${esc(h.source)}" target="_blank" rel="noopener noreferrer">Official project ↗</a>`;
  $("#harness-install-inline")?.remove();
  const installation = document.createElement("section");
  installation.id = "harness-install-inline";
  installation.className = "stack harness-install";
  installation.innerHTML = `<div class="install-heading"><div><h2>${esc(h.name)}</h2><p>${esc(h.description)}</p></div><button type="button" class="text-button" id="close-installation">Close</button></div>${main}<details class="install-details"><summary>About ${esc(h.name)}</summary>${about}</details>`;
  $("#view").append(installation);
  $("#close-installation").addEventListener("click", () => installation.remove());
  bindCopies(installation);
  installation.scrollIntoView({block: "start"});
}

function renderDeviceConnect() {
  header("Connect your harness", "Enter the code displayed in your terminal.");
  $("#view").innerHTML = `<form id="device-code-form" class="box stack device-connect"><label>Connection code<input name="user_code" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="20" placeholder="ABCD-EFGH" required></label><p class="hint">Only enter a code from a harness you just started yourself.</p><p class="error" role="alert"></p><button class="primary" type="submit">Continue</button></form>`;
  formAction("#device-code-form", async data => {
    const request = await api("/api/device/inspect", data);
    $("#view").innerHTML = `<form id="device-approve-form" class="box stack device-connect"><h2>Connect ${esc(request.name)}?</h2><p>This connects the CLI to your account, <strong>${esc(session.user.email)}</strong>, for inference with this server's models. It does not grant administrator access.</p><p class="hint">Code: <strong>${esc(data.user_code.toUpperCase())}</strong>. You can revoke the connection in API keys.</p><p class="error" role="alert"></p><div class="device-actions"><button class="primary" type="submit">Allow connection</button><button class="secondary" id="device-deny" type="button">Deny</button></div></form>`;
    const decide = async approve => {
      await api("/api/device/decide", {...data, approve});
      $("#view").innerHTML = empty(approve ? "You're connected" : "Connection denied", approve ? "Return to your terminal. It will continue automatically; you can close this browser tab." : "No access was granted. You can close this tab.");
    };
    formAction("#device-approve-form", () => decide(true));
    $("#device-deny").addEventListener("click", async event => {
      const button = event.currentTarget; button.disabled = true;
      try { await decide(false); } catch(error) { $("#device-approve-form .error").textContent = error.message; }
      finally { button.disabled = false; }
    });
  });
}
function modelRow(m) {
  const meta = [isMedia(m) ? esc(named(TASKS, m.task)) : esc(named(CENSORSHIP, m.censorship)), `<span class="model-id">${esc(m.id)}</span>`, esc((m.protocols || []).map(p => named(PROTOCOLS, p)).join(", ")), m.features?.json ? "JSON output" : "", esc(servedBy(m)), esc(cacheHits(m))].filter(Boolean).join(" · ");
  return `<article class="entry"><div class="entry-head"><h3 class="entry-name"><a class="entry-open" href="${esc(pageLink("models", m.id))}" data-model="${esc(m.id)}">${esc(friendly(m))}</a></h3><span class="tag${ready(m) ? " ready" : ""}">${esc(named(STATES, m.state))}</span><button type="button" class="text-button entry-action" data-copy="${esc(m.id)}" aria-label="Copy model ID ${esc(m.id)}">Copy ID</button></div><p class="entry-text mono">${esc(m.upstream)}</p><p class="entry-meta">${meta}</p></article>`;
}
function renderModels() {
  header("One API for every model", "Models appear automatically when their connected server reports them.", session.user?.admin ? '<button class="primary" id="connect-model">Connect a model server ↗</button>' : "");
  $("#connect-model")?.addEventListener("click",connectDialog);
  redrawModels = null;
  if (!models.length) {
    $("#view").innerHTML = empty("Your first model starts here.",session.user?.admin ? "Connect an existing Yougori, vLLM, or llama.cpp model server. Its models will appear here without renting hardware or downloading weights again." : "Your administrator has not connected a model server yet.");
    return;
  }
  redrawModels = catalog({key: "models", one: "model", noun: "models", items: () => models,
    filters: [
      {id: "censored", label: "Censored", test: m => m.censorship !== "uncensored"},
      {id: "uncensored", label: "Uncensored", test: m => m.censorship === "uncensored"},
    ],
    sorts: [
      ["ready", "Available first", (a, b) => Number(ready(b)) - Number(ready(a)) || byName(friendly)(a, b)],
      ["name", "Name A–Z", byName(friendly)],
      ["name-desc", "Name Z–A", (a, b) => byName(friendly)(b, a)],
    ],
    text: m => [m.id, m.upstream, m.source].join(" "),
    row: modelRow,
    note: `<p class="hint catalog-note">Availability confirms the server's catalog, not that weights are resident or a GPU is healthy. Inference uses the server's own loading and queue behavior.</p>`,
  });
}
function renderModel(id) {
  const m = models.find(m => m.id === id);
  if (!m) return missing("models", "This model is not connected.");
  header(friendly(m), m.upstream, '<a class="secondary" href="#models">← All models</a>');
  const request = isMedia(m)
    ? `POST ${location.origin}/v1/jobs\nAuthorization: Bearer YOUR_API_KEY\nContent-Type: application/json\n\n` + JSON.stringify({model: m.id, input: SAMPLE_INPUTS[m.task] || {prompt: "..."}}, null, 2) + `\n\nGET ${location.origin}/v1/jobs/JOB_ID?wait=30\n→ status, progress, output.files[].url\nGET ${location.origin}/v1/files/JOB_ID.1\n→ the file`
    : `POST ${location.origin}/v1/chat/completions\nAuthorization: Bearer YOUR_API_KEY\nContent-Type: application/json\n\n` + JSON.stringify({model: m.id, messages: [{role: "user", content: "Hello"}]}, null, 2);
  const labelled = m.censorship_source === "administrator";
  const priced = m.price?.input_microusd_per_million || m.price?.output_microusd_per_million;
  const cachedPrice = priced && m.price.cached_microusd_per_million !== m.price.input_microusd_per_million ? " / " + dollars(m.price.cached_microusd_per_million) + " cached input" : "";
  const replicas = (m.replicas || []).map(r => `${r.name} (${named(STATES, r.state)})`).join(", ");
  const about = facts([["Model ID", m.id], ["Kind", isMedia(m) ? named(TASKS, m.task) + ": asynchronous jobs" + (m.protocols.includes("images") ? ", and OpenAI's images endpoint" : m.protocols.includes("speech") ? ", and OpenAI's speech endpoint" : m.protocols.includes("videos") ? ", and OpenAI's videos endpoint" : "") : ""], ["Price", isMedia(m) ? mediaPrice(m) : priced ? dollars(m.price.input_microusd_per_million) + " input" + cachedPrice + " / " + dollars(m.price.output_microusd_per_million) + " output per 1M tokens" : "Free"], ["Status", named(STATES, m.state)], ["JSON output", m.features?.json ? "Enforced by the server: send response_format with a json_schema" : m.features?.json === false ? "Not enforced by its servers" : ""], ["Cache · 24 hours", cacheHits(m) ? cacheHits(m) + ", " + m.cache.requests + " requests" : ""], ["Content", isMedia(m) ? "" : `${named(CENSORSHIP, m.censorship)}, ${labelled ? "set by the administrator" : "detected from the name"}`], ["Served by", replicas], ["Runs on", m.place && named(PLACES, m.place)], ["Last checked", m.checked && nowLabel(m.checked)]]);
  const label = session.user?.admin && !isMedia(m) ? panel("Content label", `<form id="censorship-form" class="stack"><p class="hint">Automatic marks a model uncensored when its name says so, for example “uncensored” or “abliterated”.</p><label>Label<select name="censorship"><option value="automatic">Automatic, from the name</option><option value="censored">Censored</option><option value="uncensored">Uncensored</option></select></label><p class="error" role="alert"></p><div><button class="primary" type="submit">Save label ↗</button></div></form>`) : "";
  const keys = session.user ? '<a class="text-button" href="#keys">Create a personal API key</a>' : '<a class="text-button" href="#signin">Sign in to create a personal API key</a>';
  const tryIt = isMedia(m) && session.user ? tryPanel(m) : isMedia(m) ? panel("Try it", `<p class="hint"><a class="text-button" href="#signin">Sign in</a> to generate with this model from this page.</p>`) : "";
  $("#view").innerHTML = `<div class="detail"><div class="detail-main">${panel("Request", `<pre class="code">${esc(request)}</pre><button class="primary" data-copy="${esc(m.id)}">Copy model ID</button><p class="hint">${keys} and use it in place of YOUR_API_KEY. Availability confirms the server's catalog, not that weights are resident or a GPU is healthy.</p>`)}${tryIt}</div><div class="detail-side">${panel("About", about)}${label}</div></div>`;
  bindCopies($("#view"));
  if (isMedia(m) && session.user) bindTry(m);
  if (label) {
    $("#censorship-form select").value = labelled ? m.censorship : "automatic";
    formAction("#censorship-form", async data => { await api("/api/admin/models/censorship", {id: m.id, censorship: data.censorship}); models = (await api("/api/models")).models; notice("Content label saved."); await route(); });
  }
  scrollTo(0, 0);
}
// The model page's Try it box: one job at a time through the session's own routes, shown as it runs.
let tryJob = null;
function tryPanel(m) {
  const image = ["image-to-image", "image-to-video"].includes(m.task), speech = m.task === "text-to-speech", timed = ["text-to-video", "image-to-video", "text-to-audio"].includes(m.task);
  return panel("Try it", `<form id="try-form" class="stack"><label>${speech ? "Text to speak" : "Prompt"}<textarea name="prompt" rows="3" maxlength="8000" required placeholder="${esc(speech ? SAMPLE_INPUTS[m.task].text : SAMPLE_INPUTS[m.task]?.prompt || "")}"></textarea></label>${image ? '<label>Image<input name="image" type="file" accept="image/png,image/jpeg,image/webp" required></label>' : ""}${timed ? `<label>Seconds<input name="seconds" type="number" min="0.5" max="60" step="0.5" value="${m.task === "text-to-audio" ? 5 : 2}"></label>` : ""}<p class="hint">${mediaPriced(m) ? "Charged to your balance at " + esc(mediaPrice(m)) + "." : "Free on this service."} Outputs stay for the administrator's retention period and count in your usage.</p><p class="error" role="alert"></p><div class="device-actions"><button class="primary" type="submit">Generate ↗</button><button class="secondary" type="button" id="try-cancel" hidden>Cancel</button></div></form><p id="try-status" class="hint" role="status"></p><div id="try-output" class="try-output"></div>`);
}
function bindTry(m) {
  formAction("#try-form", async (data, form) => {
    const input = {};
    if (m.task === "text-to-speech") input.text = data.prompt; else input.prompt = data.prompt;
    if (data.seconds) input.seconds = Number(data.seconds);
    const file = form.elements.image?.files?.[0];
    if (file) {
      if (file.size > 16 * 1024 * 1024) throw new Error("Choose an image of at most 16 MiB.");
      input.image = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = () => reject(new Error("The image could not be read.")); reader.readAsDataURL(file); });
    }
    $("#try-output").replaceChildren(); $("#try-status").textContent = "Submitting…";
    const job = await api("/api/media/jobs", {model: m.id, input});
    tryJob = job.id; $("#try-cancel").hidden = false;
    await followTry(job.id);
  });
  $("#try-cancel").addEventListener("click", async () => { if (tryJob) try { await api(`/api/media/jobs/${tryJob}/cancel`, {}); } catch (problem) { notice(problem.message); } });
}
async function followTry(id) {
  while (tryJob === id) {
    const job = await api(`/api/media/jobs/${id}?wait=20`);
    if (tryJob !== id || !$("#try-status")) return;
    $("#try-status").textContent = job.status === "queued" ? `Queued${job.position ? ", position " + job.position : ""}` : job.status === "running" ? `Generating, ${Math.round((job.progress || 0) * 100)}%` : job.status === "succeeded" ? "Done" : `${job.status[0].toUpperCase() + job.status.slice(1)}${job.error ? ": " + job.error : ""}`;
    if (["succeeded", "failed", "cancelled"].includes(job.status)) { $("#try-cancel").hidden = true; tryJob = null; if (job.status === "succeeded") showTryOutput(job); return; }
  }
}
function showTryOutput(job) {
  const out = $("#try-output"); out.replaceChildren();
  for (const file of job.output?.files || []) {
    const src = "/api/media/files/" + encodeURIComponent(file.file);
    const node = file.content_type.startsWith("image/") ? Object.assign(document.createElement("img"), {src, alt: job.input?.prompt || "Generated image"})
      : file.content_type.startsWith("video/") ? Object.assign(document.createElement("video"), {src, controls: true})
      : Object.assign(document.createElement("audio"), {src, controls: true});
    const link = Object.assign(document.createElement("a"), {href: src, download: file.name, textContent: `Download ${file.name} (${Math.max(1, Math.round(file.bytes / 1024))} KB)`, className: "text-button"});
    out.append(node, link);
  }
}
async function renderKeys(generation) {
  const result = await api("/api/keys"); if(generation !== viewGeneration) return;
  header("API keys", "Create individual keys for your tools. Keys are shown once and can be revoked at any time.", '<button class="primary" id="new-key">Create API key ↗</button>');
  $("#new-key").addEventListener("click",keyDialog);
  $("#view").innerHTML = result.keys.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Models</th><th>Created</th><th>Status</th><th></th></tr></thead><tbody>${result.keys.map(k=>`<tr><td>${esc(k.label)}</td><td>${esc(k.scopes.includes("*")?"All current and future models":k.scopes.length+" selected")}</td><td>${esc(nowLabel(k.created))}</td><td>${k.revoked?"Revoked":"Active"}</td><td>${k.revoked?"":`<button class="text-button" data-revoke="${esc(k.id)}">Revoke</button>`}</td></tr>`).join("")}</tbody></table></div>` : empty("Connect your first tool.", "Create an API key to use this service from a harness or your own application.");
  document.querySelectorAll("[data-revoke]").forEach(b=>b.addEventListener("click",()=>confirmAction("Revoke this key?","Tools using it will lose access immediately.",async()=>{await api("/api/keys/revoke",{id:b.dataset.revoke});await route();})));
}
function reveal(title, value, explanation) {
  modal(title,`<div class="stack"><p class="hint">${esc(explanation)}</p><pre class="code secret">${esc(value)}</pre><button class="primary" id="copy-secret">Copy ↗</button></div>`);
  $("#copy-secret").addEventListener("click",e=>copy(value,e.currentTarget));
}
function keyDialog() {
  modal("Create an API key",`<form id="key-form" class="stack"><label>Key name<input name="label" placeholder="My coding tool" required maxlength="60"></label><label>Access<select name="access" id="key-access"><option value="all">All current and future models</option><option value="selected">Selected models only</option></select></label><div id="scope-list" class="scope-list" hidden>${models.map(m=>`<label class="check"><input type="checkbox" name="model" value="${esc(m.id)}">${esc(friendly(m))}</label>`).join("")}</div><p class="error" role="alert"></p><button class="primary" type="submit">Create key ↗</button></form>`);
  $("#key-access").addEventListener("change",e=>{$("#scope-list").hidden=e.target.value==="all";});
  formAction("#key-form",async(data,form)=>{const r=await api("/api/keys",{label:data.label,scopes:data.access==="all"?["*"]:new FormData(form).getAll("model")});$("#dialog").close();await route();reveal("Save your API key",r.key,"This is the only time the full key is shown. Store it privately; only its hash is retained by the service.");});
}
async function renderUsage(generation) {
  const r = await api("/api/usage"); if(generation !== viewGeneration) return;
  header("Usage", "Your last 100 requests. Token counts come from the model server; missing counts stay unknown. Cached input is the part of the prompt the model server reused from earlier turns. A media job counts its images, or its seconds of video or sound.");
  const made = x => Number.isInteger(x.images) ? (x.images ? `${x.images} image${x.images === 1 ? "" : "s"}` : `${((x.output_ms || 0) / 1000).toFixed(1)} s of output`) : `${x.input_tokens??"—"}${Number.isInteger(x.cached_tokens) ? ` (${x.cached_tokens})` : ""} / ${x.output_tokens??"—"} tokens`;
  $("#view").innerHTML = r.requests.length ? `<div class="table-wrap"><table><thead><tr><th>Model</th><th>Time</th><th>Duration</th><th>Input (cached) / output tokens, or output made</th><th>Cost (USD)</th><th>Status</th></tr></thead><tbody>${r.requests.map(x=>`<tr><td>${esc(x.model)}</td><td>${esc(nowLabel(x.started))}</td><td>${(x.duration_ms/1000).toFixed(2)} s</td><td>${made(x)}</td><td>${dollars(x.cost_microusd)}${x.billing_state === "unbilled" ? " · Unbilled" : ""}</td><td>${esc(x.status)}</td></tr>`).join("")}</tbody></table></div>` : empty("A clear view of every request.", "Requests made with your API keys will appear here. Prompts and generated content are not stored.");
  await renderCredits();
  if(session.user?.admin) await renderControlPanel();
}
function confirmAction(title, text, action) {
  modal(title,`<form id="confirm-form" class="stack"><p class="hint">${esc(text)}</p><p class="error" role="alert"></p><button type="submit" class="primary">Confirm</button></form>`);
  formAction("#confirm-form",async()=>{await action();$("#dialog").close();});
}
function connectDialog() {
  if(!$("#compute-setup")) { location.hash = "admin"; return; }
  $("#compute-setup .panel")?.scrollIntoView({behavior: "smooth", block: "start"});
}

// The administrator's choices: the page people open first and the harnesses offered here. The same
// form opens after the administrator's first sign-in and stays in Admin.
const HOMES = [["harnesses", "Harnesses", "Coding and security tools that run in Sandbox VMs."],
  ["models", "Models", "The models this inference serves, with the request for each."],
  ["sandboxes", "Sandboxes", "Sandbox VMs on computers people contribute."]];
function choicesForm(submit, compact = false) {
  const groups = categories.map(c => [c, harnesses.filter(h => h.category === c.id).sort(byName(h => h.name))]).filter(([, list]) => list.length);
  if (compact) {
    // Admin's version: the main page as one row of options and the harnesses by name.
    const box = (type, name, value, checked, title) => `<label class="check"><input type="${type}" name="${name}" value="${esc(value)}"${checked ? " checked" : ""}>${esc(title)}</label>`;
    return `<form id="choices-form" class="stack"><div class="choice-home" role="radiogroup" aria-labelledby="choice-home"><span class="choice-label" id="choice-home">Main page</span>${HOMES.map(([id, title]) => box("radio", "home", id, id === home(), title)).join("")}</div><p class="hint" id="choice-sandboxes" hidden>Sandboxes are switched off. Switch them on under Sandboxes.</p>`
      + `<div class="choice-tools"><span class="choice-label">Harnesses</span><p class="hint" id="choice-count" aria-live="polite"></p><button type="button" class="text-button" data-choose="all">Select all</button><button type="button" class="text-button" data-choose="none">Clear</button></div>${groups.map(([c, list]) => `<div class="choice-names" role="group" aria-label="${esc(c.label)}"><p class="choice-category">${esc(c.label)}</p>${list.map(h => box("checkbox", "harness", h.id, h.offered !== false, h.name)).join("")}</div>`).join("")}`
      + `<p class="error" role="alert"></p><div><button class="primary" type="submit">${esc(submit)}</button></div></form>`;
  }
  const option = (type, name, value, checked, title, text) => `<label class="choice"><input type="${type}" name="${name}" value="${esc(value)}"${checked ? " checked" : ""}><span><strong>${esc(title)}</strong><span>${esc(text)}</span></span></label>`;
  return `<form id="choices-form" class="choices"><fieldset class="choice-group"><legend>Main page</legend><div class="choice-list">${HOMES.map(([id, title, text]) => option("radio", "home", id, id === home(), title, text)).join("")}</div><p class="hint" id="choice-sandboxes" hidden>Sandboxes are switched off. Switch them on in Admin, under Sandboxes.</p></fieldset>`
    + `<fieldset class="choice-group"><legend>Harnesses</legend><div class="choice-tools"><p class="hint" id="choice-count" aria-live="polite"></p><button type="button" class="text-button" data-choose="all">Select all</button><button type="button" class="text-button" data-choose="none">Clear</button></div>${groups.map(([c, list]) => `<p class="choice-category">${esc(c.label)}</p><div class="choice-list">${list.map(h => option("checkbox", "harness", h.id, h.offered !== false, h.name, h.description)).join("")}</div>`).join("")}</fieldset>`
    + `<p class="error" role="alert"></p><div><button class="primary" type="submit">${esc(submit)}</button></div></form>`;
}
function bindChoices(saved) {
  const form = $("#choices-form"), boxes = [...form.querySelectorAll('[name="harness"]')];
  const count = () => { $("#choice-count").textContent = `${boxes.filter(b => b.checked).length} of ${boxes.length} harnesses offered`; };
  form.querySelectorAll("[data-choose]").forEach(button => button.addEventListener("click", () => {
    for (const box of boxes) box.checked = button.dataset.choose === "all";
    count();
  }));
  form.addEventListener("change", count); count();
  api("/api/sandboxes").then(grid => { if (form.isConnected) $("#choice-sandboxes").hidden = grid.enabled; }).catch(() => { /* The hint is optional. */ });
  formAction("#choices-form", async (data, element) => {
    const chosen = new FormData(element).getAll("harness");
    if (data.home === "harnesses" && !chosen.length) throw new Error("Offer at least one harness, or choose another main page.");
    await api("/api/admin/choices", {home: data.home, harnesses: chosen});
    await saved(data.home);
  });
}
function renderSetup() {
  header("Set up your inference", "Choose the page people see first and the harnesses you offer. You can change both later in Admin.");
  $("#view").innerHTML = panel("Main page and harnesses", choicesForm("Save and continue ↗"));
  bindChoices(async chosen => { history.replaceState(null, "", "#" + chosen); await loadSession(); });
}

// Admin is one column of sections: each shows its name and one line about it, then its controls.
// The sections come from several scripts, so the page lays out empty slots in order and each
// script fills its own; the reading and keyboard order is the order on screen.
function adminSection(id, title, about, body) {
  return `<section class="panel admin-section" id="${id}"><div class="panel-heading"><h3>${esc(title)}</h3><p class="hint">${esc(about)}</p></div><div class="panel-body">${body}</div></section>`;
}
function adminElement(...parts) {
  const holder = document.createElement("div"); holder.innerHTML = adminSection(...parts); return holder.firstElementChild;
}
function placeAdmin(slot, element) {
  const target = $(slot);
  if (target) target.replaceWith(element); else $("#admin-grid")?.append(element);
}
let adminCounts = null, adminFocus = "";
// The left edge of Admin as a camera-style ruler, as in the owner's PrompX harness: fine tick lines,
// a mark for each section (the current one highlighted) and a thumb where the page is. Drag along it
// to scroll fast (its top is the top of the page, its bottom the end), click a mark to go to that
// section, hover for the names. It replaces the page's scrollbar on desktop; phones keep theirs.
let rail = null;
function removeRail() { rail?.stop(); rail = null; }
function sectionRail(sections) {
  removeRail();
  if (!sections.length) return;
  const GAP = 22, EDGE = 12, el = document.createElement("div");
  el.className = "rail";
  el.innerHTML = `<div class="rail-ticks" aria-hidden="true"></div><div class="rail-thumb" aria-hidden="true"></div><nav aria-label="Sections of this page">${sections.map(s => `<button type="button" class="rail-mark" data-section="${esc(s.id)}"><i aria-hidden="true"></i><span>${esc(s.label)}</span></button>`).join("")}</nav>`;
  document.body.append(el);
  document.documentElement.classList.add("with-rail");
  const header = () => $(".site-header")?.offsetHeight || 0;
  const place = target => Math.max(0, target.getBoundingClientRect().top + scrollY - header() - 16);
  // A clicked mark stays current until the person scrolls by hand: a section near the end cannot
  // reach the top of the view, and the last one would otherwise take over.
  let frame = 0, dragging = false, pinned = "";
  const measure = () => {
    frame = 0;
    el.style.top = header() + "px";
    const height = el.clientHeight, max = Math.max(1, document.documentElement.scrollHeight - innerHeight), y = scrollY;
    const marks = [];
    for (const button of el.querySelectorAll(".rail-mark")) {
      const target = document.getElementById(button.dataset.section);
      button.hidden = !target;
      if (target) { const top = place(target); marks.push({button, top, at: Math.min(1, top / max) * (height - 2 * EDGE) + EDGE}); }
    }
    // Marks never sit on each other: pushed apart downwards, then back up from the bottom.
    for (let i = 1; i < marks.length; i++) marks[i].at = Math.max(marks[i].at, marks[i - 1].at + GAP);
    for (let i = marks.length - 1; i >= 0; i--) marks[i].at = Math.min(marks[i].at, i === marks.length - 1 ? height - EDGE : marks[i + 1].at - GAP);
    let current = marks[0];
    for (const m of marks) if (m.top <= y + 40) current = m;
    if (y >= max - 2 && marks.length) current = marks.at(-1);
    if (pinned) current = marks.find(m => m.button.dataset.section === pinned) || current;
    for (const m of marks) {
      m.button.style.top = m.at + "px";
      if (m === current) m.button.setAttribute("aria-current", "true"); else m.button.removeAttribute("aria-current");
    }
    el.querySelector(".rail-thumb").style.top = (Math.min(1, y / max) * (height - 2 * EDGE) + EDGE) + "px";
  };
  const soon = () => { if (!frame) frame = requestAnimationFrame(measure); };
  // The ruler maps to the whole page: where the pointer is on it, the page is.
  const scrub = clientY => {
    const r = el.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (clientY - r.top - EDGE) / Math.max(1, r.height - 2 * EDGE)));
    scrollTo({top: f * (document.documentElement.scrollHeight - innerHeight)});
  };
  el.addEventListener("pointerdown", event => {
    if (event.target.closest(".rail-mark")) return;
    event.preventDefault(); el.setPointerCapture(event.pointerId); dragging = true; pinned = ""; el.classList.add("rail-held"); scrub(event.clientY);
  });
  el.addEventListener("pointermove", event => { if (dragging) scrub(event.clientY); });
  const release = event => { dragging = false; el.classList.remove("rail-held"); if (el.hasPointerCapture(event.pointerId)) el.releasePointerCapture(event.pointerId); };
  el.addEventListener("pointerup", release); el.addEventListener("pointercancel", release);
  el.addEventListener("click", event => {
    const target = document.getElementById(event.target.closest(".rail-mark")?.dataset.section || "");
    if (target) { pinned = target.id; scrollTo({top: place(target), behavior: "smooth"}); soon(); }
  });
  const unpin = () => { if (pinned) { pinned = ""; soon(); } };
  addEventListener("scroll", soon, {passive: true}); addEventListener("resize", soon);
  for (const kind of ["wheel", "touchstart", "keydown"]) addEventListener(kind, unpin, {passive: true});
  const seen = new ResizeObserver(soon); seen.observe(document.body);
  rail = {stop() {
    removeEventListener("scroll", soon); removeEventListener("resize", soon); seen.disconnect();
    for (const kind of ["wheel", "touchstart", "keydown"]) removeEventListener(kind, unpin);
    if (frame) cancelAnimationFrame(frame);
    el.remove(); document.documentElement.classList.remove("with-rail");
  }};
  measure();
}
// The description under Admin counts people, models and completed requests; the model count stays live.
function adminSummary() {
  if (!adminCounts || currentRoute()[0] !== "admin") return;
  const count = (n, one) => `${n} ${one}${n === 1 ? "" : "s"}`;
  $("#section-description").textContent = [count(adminCounts.users, "team member"), count(models.length, "model"), count(adminCounts.completed, "completed request")].join(" · ");
}
function serverRows(endpoints) {
  return endpoints.length ? endpoints.map(e => `<div class="source"><div><strong>${esc(e.name)}</strong> <span class="badge ${e.state === "ready" ? "ready" : ""}">${esc(e.state)}</span><p>${esc(e.url.startsWith("compute://") ? "Connected by Yougori" : e.url)} · ${esc(e.detail)}</p></div>${e.url.startsWith("compute://") ? "" : `<button type="button" class="text-button" data-remove-source="${esc(e.id)}">Disconnect</button>`}</div>`).join("")
    : '<p class="hint">Nothing yet. Connect a computer or rent a GPU above, and its models appear here.</p>';
}

async function renderAdmin(generation) {
  if(!session.user.admin){location.hash=home();return;}
  const data=await api("/api/admin/overview"); if(generation !== viewGeneration) return;
  adminCounts = data.counts;
  header("Admin", "");
  adminSummary();
  const access = session.mode === "public" ? "Anyone can sign up; invitations are optional." : "Only people you invite can sign in.";
  $("#view").innerHTML = `<div class="admin-grid" id="admin-grid"><div id="slot-compute"></div>`
    + adminSection("admin-servers", "Model servers", "What serves each model in your catalog.", `<div id="model-servers">${serverRows(data.endpoints)}</div><div class="admin-row"><button class="secondary" type="button" id="refresh-models">Refresh catalog</button><button class="text-button" type="button" id="add-endpoint">Connect a computer</button></div>`)
    + `<div id="slot-sandboxes"></div>`
    + adminSection("admin-choices", "Main page and harnesses", "What people see first, and the harnesses you offer.", choicesForm("Save choices ↗", true))
    + adminSection("admin-identity", "Website identity", "The name, tagline and colour style everyone sees.", `<form id="branding-form" class="stack"><div class="admin-row"><label>Website name<input name="name" maxlength="80" required value="${esc(session.site.name)}"></label><label>Tagline<input name="tagline" maxlength="200" value="${esc(session.site.tagline)}"></label></div><fieldset class="palette-group"><legend>Color style</legend><div class="palette-options">${PALETTES.map(([id, title]) => `<label class="palette-option"><input type="radio" name="palette" value="${id}"${id === document.documentElement.dataset.palette ? " checked" : ""}><span class="palette-swatch" data-palette="${id}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>${esc(title)}</label>`).join("")}</div></fieldset><p class="hint">Every visitor sees this style, and each person can still switch between light and dark.</p><p class="error" role="alert"></p><div><button class="primary" type="submit">Save identity ↗</button></div></form>`)
    + adminSection("admin-people", "People", "Who can sign in, and who manages this inference.", `<form id="invite-form" class="stack"><div class="admin-row"><label>Email address<input name="email" type="email" required></label><label class="check"><input name="admin" type="checkbox">Invite as administrator</label><button class="primary" type="submit">Create invitation ↗</button></div><p class="hint">${esc(access)} An invitation is for one email address and expires after 24 hours.</p><p class="error" role="alert"></p></form><div id="member-settings" class="member-list"></div><p class="hint">Administrators manage compute, prices, wallets and people. At least one must remain.</p>`)
    + `<div id="slot-prices"></div><div id="slot-media"></div><div id="slot-payments"></div><div id="slot-activity"></div></div>`;
  await showCompute();
  if(!$("#branding-form")) return;
  sectionRail([...document.querySelectorAll("#admin-grid .admin-section")].map(section => ({id: section.id, label: section.querySelector("h3").textContent})));
  if(adminFocus === "contributor") { adminFocus = ""; $("#admin-local").scrollIntoView({block: "start"}); $("#contributor-inspect input[name=code]").focus({preventScroll: true}); }
  $("#add-endpoint").addEventListener("click",connectDialog);
  $("#refresh-models").addEventListener("click",async e=>{e.currentTarget.disabled=true;try{await api("/api/admin/refresh",{});models=(await api("/api/models")).models;await route();}catch(problem){notice(problem.message);e.currentTarget.disabled=false;}});
  $("#model-servers").addEventListener("click",event=>{
    const button=event.target.closest("[data-remove-source]");
    if(button) confirmAction("Disconnect this server?","This removes its models from the service. The server keeps running and its infrastructure billing is unchanged.",async()=>{await api("/api/admin/endpoints/remove",{id:button.dataset.removeSource});models=(await api("/api/models")).models;await refreshCompute();});
  });
  formAction("#invite-form",async d=>{const r=await api("/api/admin/invitations",{...d,admin:d.admin === "on"});$('#invitation-result')?.remove();const result=document.createElement('div');result.id='invitation-result';result.className='stack';result.innerHTML=`<p class="hint">Invitation for ${esc(r.email)}. Expires in 24 hours. Share this code privately.</p><pre class="code secret">${esc(r.invitation)}</pre><button class="secondary" type="button" data-copy="${esc(r.invitation)}">Copy invitation</button>`;$('#invite-form').append(result);bindCopies(result);});
  formAction("#branding-form",async d=>{await api("/api/admin/site",d);await loadSession();notice("Website identity saved.");});
  bindChoices(async () => { await loadSession(); notice("Main page and harnesses saved."); });
}
async function route() {
  if(!session) return;
  if($("#dialog").open) $("#dialog").close();
  if(AUTH_ROUTES.includes(currentRoute()[0]) && session.user) history.replaceState(null, "", "#" + (returnTo || home()));
  let [name, item] = currentRoute(); const generation = ++viewGeneration;
  removeRail();
  // Administrators approve a computer's code in Admin's Local GPUs, even from the connector's link.
  if(name === "contribute" && session.user?.admin) { history.replaceState(null, "", "#admin"); name = "admin"; adminFocus = "contributor"; }
  const needsLogin = !session.user && [...AUTH_ROUTES, "connect", "contribute", "keys", "usage", "admin"].includes(name);
  $("#auth").hidden = !needsLogin; $("#workspace").hidden = needsLogin;
  paintNavigation();
  if(needsLogin) {
    if(!AUTH_ROUTES.includes(name)) returnTo = location.hash.slice(1);
    renderAuth(AUTH_ROUTES.includes(name) ? name : "signin");
    return;
  }
  // Unknown addresses, and Harnesses when none are offered, open the main page.
  if(!PAGES.includes(name) || (name === "harnesses" && !offeredHarnesses().length && home() !== "harnesses")) { name = home(); item = ""; }
  if(MAIN.includes(name)) returnTo = location.hash.slice(1);
  // Another page opens at its top; the same page drawn again (after a save) keeps its place.
  if(name !== shownPage) { shownPage = name; scrollTo(0, 0); }
  if(choosing(name)) { renderSetup(); return; }
  try {
    if(name==="sandboxes")await renderSandboxes();else if(name==="contribute")renderContributor();else if(name==="connect")renderDeviceConnect();else if(name==="models")item?renderModel(item):renderModels();else if(name==="keys")await renderKeys(generation);else if(name==="usage")await renderUsage(generation);else if(name==="admin")await renderAdmin(generation);else {renderHarnesses();if(item){history.replaceState(null,"","#harnesses");renderHarness(item);}}
  } catch(problem){notice(problem.message);}
}
$("#dialog-close").addEventListener("click",()=>$("#dialog").close());
$("#dialog").addEventListener("close",()=>{if(!$("#dialog").open)$("#dialog-body").replaceChildren();});
function renderAuth(mode) {
  if(mode === "signup" && session.mode !== "public") mode = "join";
  authMode = mode;
  const creating = mode !== "signin", invited = mode === "join";
  $("#invitation-field").hidden = !invited;
  $("#invitation-field input").required = invited;
  $("#invitation-field input").disabled = !invited;
  $("#auth-title").textContent = creating ? "Create your account" : "Welcome back";
  $("#auth-window-title").textContent = invited ? "Accept your invitation" : creating ? "Sign up with your email and password." : session.mode === "private" ? "Invitation-only inference. Sign in to continue." : "Sign in";
  $("#auth-submit").textContent = creating ? "Create account ↗" : "Sign in ↗";
  $("#auth-toggle").textContent = creating ? "Already have an account? Sign in" : "Don't have an account? Sign up";
  $("#auth-toggle").hidden = !creating && session.mode !== "public";
  $("#auth-invitation").hidden = invited;
  $("#password-hint").hidden = !creating;
  const password = $("#login-form input[name=password]");
  password.autocomplete = creating ? "new-password" : "current-password";
  password.minLength = creating ? 12 : 1;
  password.setAttribute("aria-describedby", "password-hint");
  $("#auth-error").textContent = "";
}
$("#auth-toggle").addEventListener("click",()=>{location.hash = authMode === "signin" ? "signup" : "signin";});
$("#auth-invitation").addEventListener("click",()=>{location.hash = "join";});
formAction("#login-form",async data=>{await api(authMode === "signin" ? "/api/login" : authMode === "join" ? "/api/join" : "/api/signup",data);$("#login-form").reset();await loadSession();});
$("#signout").addEventListener("click",async()=>{try{await api("/api/logout",{});viewGeneration++;Object.keys(catalogState).forEach(key=>delete catalogState[key]);$("#dialog").close();$("#view").replaceChildren();notice("");history.replaceState(null,"",location.pathname+location.search);await loadSession();}catch(problem){notice(problem.message);}});
window.addEventListener("hashchange",route);
loadSession().catch(problem=>notice(problem.message));
setInterval(async()=>{if(!session||document.hidden||$("#dialog").open)return;try{models=(await api("/api/models")).models;const [name,item]=currentRoute();if(name==="models"&&!item&&!choosing(name)&&!(models.length&&redrawModels?.()))renderModels();}catch{/* Keep the last view; never mark stale data as newly observed. */}},15000);
