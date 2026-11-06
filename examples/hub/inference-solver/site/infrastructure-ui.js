/* Inline website administration; all compute stays on enrolled servers. */
"use strict";
let gridRefreshTimer;

async function showInfrastructure() {
  clearTimeout(gridRefreshTimer);
  $("#infrastructure-setup")?.remove();
  const [grid, payments] = await Promise.all([api("/api/grid"), api("/api/payments")]);
  if(currentRoute()[0] !== "admin") return;
  const area = document.createElement("section");
  area.id = "infrastructure-setup"; area.className = "compute-setup";
  const local = grid.nodes.find(n => n.host === "website-host")?.capacity;
  area.innerHTML = `<div class="compute-options">${panel("Sandboxes", `<form id="grid-policy" class="stack">
    <label class="check"><input name="enabled" type="checkbox" role="switch" ${grid.policy.enabled ? "checked" : ""}>Enable sandboxes</label>
    <p class="hint">People choose an available computer and start their sandbox from the Sandboxes page.</p>
    <label class="check"><input name="local" type="checkbox" ${local?.slots ? "checked" : ""}>Contribute this website server</label>
    <div class="compute-sizing"><label>CPU cores<input name="cpu" type="number" min="1" max="64" value="${local?.cpu || 4}"></label><label>RAM (GB)<input name="memory_gb" type="number" min="1" max="256" value="${local?.memory_gb || 8}"></label><label>Sandbox slots<input name="slots" type="number" min="1" max="16" value="${local?.slots || 2}"></label></div>
    <details><summary>Contribution access</summary><div class="stack compute-details"><label>Who may contribute<select name="admission"><option value="private">Private · admin approval</option><option value="open">Public · no join password</option><option value="password">Public · join password required</option></select></label><label>Join password<input name="password" type="password" minlength="12" autocomplete="new-password" placeholder="Leave blank to keep current password"></label></div></details>
    <p class="error" role="alert"></p><button class="secondary" type="submit">Save resource limits</button><a href="#sandboxes" class="text-button">Open sandboxes →</a></form>`)}
    ${panel("Crypto payments", `<form id="payment-wallet" class="stack"><label>Payment network<select name="network">${Object.entries(payments.networks).map(([id,name])=>`<option value="${esc(id)}">${esc(name)}</option>`).join("")}</select></label>
    <label>Receiving wallet address<input name="address" maxlength="128" autocomplete="off" placeholder="Public wallet address"></label><button type="button" class="secondary" id="wallet-connect">Use connected wallet</button>
    <p class="hint">Payments go directly to your wallet. Finalized invoices add dollar balance automatically.</p><p class="error" role="alert"></p><button class="primary" type="submit">Save receiving wallet</button></form><div id="payment-wallets"></div>`)}</div>`;
  $("#compute-setup").after(area);
  $("#grid-policy").elements.admission.value = grid.policy.admission;
  formAction("#grid-policy", async data => {
    await api("/api/admin/grid", {enabled:data.enabled === "on",admission:data.admission,password:data.password,
      local:data.local === "on" ? {cpu:Number(data.cpu),memory_gb:Number(data.memory_gb),slots:Number(data.slots)} : {}});
    $("#grid-policy").elements.password.value = ""; notice('Sandbox resource limits saved.');
  });
  $("#grid-policy").elements.enabled.onchange = async event => {
    const form=$("#grid-policy");
    try {
      await api('/api/admin/grid',{enabled:event.target.checked,admission:form.elements.admission.value,password:form.elements.password.value});
      form.elements.password.value=''; notice(event.target.checked ? 'Sandboxes enabled.' : 'New sandboxes disabled. Running sandboxes are preserved.');
    } catch(error) {event.target.checked=!event.target.checked;form.querySelector('.error').textContent=error.message;}
  };
  let walletState = payments;
  const renderWallets = value => {
    walletState = value;
    $("#payment-wallets").innerHTML = value.wallets.map(w=>`<div class="source"><div><strong>${esc(value.networks[w.network])}</strong><p class="wallet-address">${esc(w.address)}</p></div></div>`).join("");
    $("#payment-wallet").elements.address.value = value.wallets.find(w=>w.network === $("#payment-wallet").elements.network.value)?.address || "";
  };
  renderWallets(payments);
  await renderPriceAdmin();
  $("#payment-wallet").elements.network.onchange = () => renderWallets(walletState);
  formAction("#payment-wallet", async data => renderWallets(await api("/api/admin/wallet",data)));
  $("#wallet-connect").onclick = async () => {
    try {
      const form = $("#payment-wallet"), network = form.elements.network.value;
      const chains = {ethereum:"0x1",base:"0x2105",arbitrum:"0xa4b1",polygon:"0x89",bsc:"0x38"};
      if(chains[network] && window.ethereum?.request) {
        await window.ethereum.request({method:"wallet_switchEthereumChain",params:[{chainId:chains[network]}]});
        const addresses = await window.ethereum.request({method:"eth_requestAccounts"}); form.elements.address.value = addresses[0] || "";
      } else if(network === "solana" && window.solana?.connect) {
        const connected = await window.solana.connect(); form.elements.address.value = connected.publicKey.toString();
      } else throw new Error("No compatible wallet found. Paste your public receiving address above.");
    } catch(error) { $("#payment-wallet .error").textContent = error.message; }
  };
  await renderMembers();
  const activity=$('#compute-activity')?.closest('.panel');
  if(activity) {activity.classList.add('activity-bottom');$('#admin-grid').append(activity);}
}
