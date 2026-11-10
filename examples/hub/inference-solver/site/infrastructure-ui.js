/* Inline website administration; all compute stays on enrolled servers. */
"use strict";
let gridRefreshTimer;

async function showInfrastructure() {
  clearTimeout(gridRefreshTimer);
  $("#admin-sandboxes")?.remove(); $("#admin-payments")?.remove();
  const [grid, payments] = await Promise.all([api("/api/grid"), api("/api/payments")]);
  if(currentRoute()[0] !== "admin") return;
  const local = grid.nodes.find(n => n.host === "website-host")?.capacity;
  // Only a website with Yougori of its own can run sandboxes itself; hosted inferences use contributors.
  const website = !!local?.slots || !!computeView?.hosts.some(h => h.role === "controller");
  placeAdmin("#slot-sandboxes", adminElement("admin-sandboxes", "Sandboxes", "Sandbox VMs people start on contributed computers.", `<form id="grid-policy" class="stack">
    <label class="check"><input name="enabled" type="checkbox" role="switch" ${grid.policy.enabled ? "checked" : ""}>Enable sandboxes</label>
    <div class="admin-row"${website ? "" : " hidden"}><label class="check"><input name="local" type="checkbox" ${local?.slots ? "checked" : ""}>Contribute this website server</label><label>CPU cores<input name="cpu" type="number" min="1" max="64" value="${local?.cpu || 4}"></label><label>RAM (GB)<input name="memory_gb" type="number" min="1" max="256" value="${local?.memory_gb || 8}"></label><label>Sandbox slots<input name="slots" type="number" min="1" max="16" value="${local?.slots || 2}"></label></div>
    <div class="admin-row"><label>Who may contribute<select name="admission"><option value="private">Private · admin approval</option><option value="open">Public · no join password</option><option value="password">Public · join password required</option></select></label><label>Join password<input name="password" type="password" minlength="12" autocomplete="new-password" placeholder="Leave blank to keep the current one"></label></div>
    <p class="error" role="alert"></p><div class="admin-row"><button class="secondary" type="submit">Save resource limits</button><a href="#sandboxes" class="text-button">Open sandboxes</a></div></form>`));
  placeAdmin("#slot-payments", adminElement("admin-payments", "Crypto payments", "People top up their balance with crypto, paid straight to your wallet.", `<form id="payment-wallet" class="stack"><div class="admin-row"><label>Payment network<select name="network">${Object.entries(payments.networks).map(([id,name])=>`<option value="${esc(id)}">${esc(name)}</option>`).join("")}</select></label>
    <label>Receiving wallet address<input name="address" maxlength="128" autocomplete="off" placeholder="Public wallet address"></label><button type="button" class="secondary" id="wallet-connect">Use connected wallet</button><button class="primary" type="submit">Save receiving wallet</button></div>
    <p class="hint">Finalized invoices add dollar balance automatically.</p><p class="error" role="alert"></p></form><div id="payment-wallets"></div>`));
  $("#grid-policy").elements.admission.value = grid.policy.admission;
  // Nothing is folded away: a setting's fields work once its box is ticked or its mode is chosen.
  const policy = $("#grid-policy");
  const sync = () => {
    for (const name of ["cpu", "memory_gb", "slots"]) policy.elements[name].disabled = !policy.elements.local.checked;
    policy.elements.password.disabled = policy.elements.admission.value !== "password";
  };
  policy.elements.local.addEventListener("change", sync); policy.elements.admission.addEventListener("change", sync); sync();
  formAction("#grid-policy", async data => {
    await api("/api/admin/grid", {enabled:data.enabled === "on",admission:data.admission,password:data.password,
      ...(website ? {local:data.local === "on" ? {cpu:Number(data.cpu),memory_gb:Number(data.memory_gb),slots:Number(data.slots)} : {}} : {})});
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
}
