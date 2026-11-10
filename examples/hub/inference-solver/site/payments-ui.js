/* Inline checkout. Every transfer is explicitly approved in the user's wallet. */
"use strict";
let paymentRefreshTimer;
const creditAmount = value => (value / 1000000).toLocaleString(undefined, {maximumFractionDigits: 6});
const dollars = value => '$'+creditAmount(value || 0);

async function renderCredits() {
  clearTimeout(paymentRefreshTimer);
  const state = await api('/api/payments');
  if(currentRoute()[0] !== 'usage') return;
  const area = document.createElement('section'); area.id = 'credits';
  area.innerHTML = panel('Balance', `<div class="stack"><p><strong id="credit-balance">${dollars(state.balance_microusd)}</strong> USD available</p>
    <p class="hint">Top up your dollar balance with USDC or USDT at $1 per token; network fees are extra. Models charge separately for measured input and output tokens. A temporary maximum reservation is released after each request. Failed requests and responses without valid token counts are not charged.</p>
    ${state.wallets.length ? `<form id="credit-invoice" class="stack"><div class="compute-sizing"><label>Payment network<select name="network">${state.wallets.map(w=>`<option value="${esc(w.network)}">${esc(state.networks[w.network])} · ${esc(state.assets[w.network].symbol)}</option>`).join('')}</select></label><label>Amount (USD)<input name="amount" type="number" min="1" max="1000" step="0.000001" value="10" required></label></div><p class="error" role="alert"></p><button class="primary" type="submit">Create payment invoice</button></form>` : '<p class="hint">The administrator has not connected a receiving wallet yet.</p>'}
    <div id="payment-invoices"></div></div>`);
  $('#view').prepend(area);
  if(state.wallets.length) formAction('#credit-invoice',async data => {
    await api('/api/payments/invoice',data); await refreshPayments();
  });
  showInvoices(state);
  area.addEventListener('click', async event => {
    const button = event.target.closest('[data-pay],[data-cancel-payment]'); if(!button) return;
    button.disabled = true;
    const row = button.closest('[data-invoice]'), error = row.querySelector('.error'); error.textContent = '';
    try {
      const id = row.dataset.invoice;
      if(button.hasAttribute('data-cancel-payment')) { await api('/api/payments/cancel',{id}); return await refreshPayments(); }
      const invoice = (await api('/api/payments')).invoices.find(i=>i.id === id);
      if(!invoice || invoice.state === 'settled') return await refreshPayments();
      if(!window.ethereum?.request) throw new Error('Open this page with an EVM wallet extension to approve the payment.');
      await window.ethereum.request({method:'wallet_switchEthereumChain',params:[{chainId:'0x'+invoice.chain_id.toString(16)}]});
      const accounts = await window.ethereum.request({method:'eth_requestAccounts'});
      const txid = await window.ethereum.request({method:'eth_sendTransaction',params:[{from:accounts[0],to:invoice.token,data:invoice.data,value:'0x0'}]});
      // Preserve the hash on screen even if submitting it to this website fails.
      row.querySelector('[name="txid"]').value = txid;
      await api('/api/payments/submit',{id,txid}); await refreshPayments();
    } catch(e) { error.textContent = e.message || 'Payment was not submitted.'; }
    finally { button.disabled = false; }
  });
  paymentRefreshTimer = setTimeout(refreshPayments,5000);
}

function showInvoices(state) {
  $('#credit-balance').textContent = dollars(state.balance_microusd);
  const list = $('#payment-invoices');
  // Preserve a typed transaction ID while polling.
  const drafts = Object.fromEntries([...list.querySelectorAll('[data-invoice]')].map(r=>[r.dataset.invoice,r.querySelector('[name="txid"]')?.value || '']));
  list.innerHTML = state.invoices.map(i=>{
    const active = !['settled','cancelled'].includes(i.state);
    const solana = 'solana:'+i.recipient+'?amount='+encodeURIComponent(String(i.credits/1000000))+'&spl-token='+i.token+'&memo='+encodeURIComponent(i.memo);
    return `<div class="panel-body stack" data-invoice="${esc(i.id)}"><strong>${dollars(i.credits)} USD · ${esc(state.networks[i.network])} · ${esc(i.state)}</strong>
      <p class="hint">${esc(i.detail || 'Pay this invoice once, using the exact network, token and reference below.')}</p>
      ${active ? `<p class="wallet-address">Receive: ${esc(i.recipient)}<br>Token: ${esc(i.symbol)} · ${esc(i.token)}</p>
      ${i.state === 'created' ? (i.chain_id ? '<button class="primary" type="button" data-pay>Approve payment in wallet</button>' : i.network === 'solana' ? `<a class="primary" href="${esc(solana)}">Open in Solana Pay wallet</a><p class="hint">Use a wallet that includes the memo. Submit the resulting transaction signature below.</p>` : '<p class="hint">Send TRC-20 USDT on Tron mainnet using a wallet that supports a transaction memo. Include the exact memo below, then submit the transaction ID.</p>') : ''}
      <details><summary>Payment reference and transaction details</summary><p class="hint">A plain transfer without this reference cannot be credited automatically. Do not send directly from an exchange.</p><pre class="code">${esc(i.chain_id ? i.data : i.memo)}</pre></details>
      <form class="payment-submit stack"><input type="hidden" name="id" value="${esc(i.id)}"><label>Transaction ID<input name="txid" required maxlength="100" value="${esc(drafts[i.id] || i.txid || '')}" autocomplete="off"></label><p class="error" role="alert"></p><button class="secondary" type="submit">Verify payment automatically</button></form>
      ${i.state === 'created' ? '<button type="button" class="text-button" data-cancel-payment>Cancel unused invoice</button>' : ''}` : ''}</div>`;
  }).join('');
  list.querySelectorAll('.payment-submit').forEach(form=>form.addEventListener('submit',async event=>{
    event.preventDefault(); const button = form.querySelector('button'); button.disabled = true;
    try { await api('/api/payments/submit',Object.fromEntries(new FormData(form))); await refreshPayments(); }
    catch(e) { form.querySelector('.error').textContent = e.message; }
    finally { button.disabled = false; }
  }));
}

async function refreshPayments() {
  clearTimeout(paymentRefreshTimer);
  if(currentRoute()[0] !== 'usage' || !$('#credits')) return;
  try {
    const state = await api('/api/payments');
    if(currentRoute()[0] === 'usage' && $('#credits')) {
      // Do not replace the checkout while its wallet approval or form submit is pending.
      if(!$('#payment-invoices button:disabled') && !$('#payment-invoices input:focus')) showInvoices(state);
      $('#credit-balance').textContent = dollars(state.balance_microusd);
    }
  } finally {
    if(currentRoute()[0] === 'usage') paymentRefreshTimer = setTimeout(()=>refreshPayments().catch(()=>{}),5000);
  }
}

function renderPriceAdmin() {
  placeAdmin('#slot-prices', adminElement('admin-prices', 'Model pricing', 'USD per million tokens. Zero is free.', `<form id="model-price" class="stack"><div class="admin-row"${models.length ? '' : ' hidden'}><label>Model<select name="model">${models.map(m=>`<option value="${esc(m.id)}">${esc(friendly(m))}</option>`).join('')}</select></label><label>Input / 1M tokens ($)<input name="input_usd" type="number" min="0" max="1000" step="0.000001" required value="0"></label><label>Cached input / 1M tokens ($)<input name="cached_usd" type="number" min="0" max="1000" step="0.000001" required value="0"></label><label>Output / 1M tokens ($)<input name="output_usd" type="number" min="0" max="1000" step="0.000001" required value="0"></label><button class="primary" type="submit">Save model price</button></div><p class="hint">${models.length ? "Billed from the model server's measured tokens. Cached input is the part of a prompt the server reused from earlier turns; in agent conversations it is most of the input." : 'No model is connected yet. Its prices are set here once it is.'}</p><p class="error" role="alert"></p></form>`));
  const form = $('#model-price');
  // Cached input follows the input price until it is changed by hand, so a new input price never
  // leaves cached input at an old, lower price unnoticed.
  let cachedEdited = false;
  const selected = () => { const price=models.find(m=>m.id === form.elements.model.value)?.price || {};
    form.elements.input_usd.value = String((price.input_microusd_per_million || 0)/1000000);
    form.elements.cached_usd.value = String((price.cached_microusd_per_million ?? price.input_microusd_per_million ?? 0)/1000000);
    form.elements.output_usd.value = String((price.output_microusd_per_million || 0)/1000000);
    cachedEdited = form.elements.cached_usd.value !== form.elements.input_usd.value;
  };
  form.elements.cached_usd.oninput = () => { cachedEdited = true; };
  form.elements.input_usd.oninput = () => { if(!cachedEdited) form.elements.cached_usd.value = form.elements.input_usd.value; };
  form.elements.model.onchange = selected; selected(); form.querySelector('button').disabled = !models.length;
  formAction('#model-price',async data=>{
    await api('/api/admin/prices',data);
    const micro = value => Math.round(Number(value)*1000000);
    const model = models.find(m=>m.id === data.model); if(model) model.price = {input_microusd_per_million:micro(data.input_usd),cached_microusd_per_million:micro(data.cached_usd),output_microusd_per_million:micro(data.output_usd)};
    notice('Model token prices saved.');
  });
  renderMediaAdmin();
}

// Media models are priced by what a job makes; their outputs are kept on this website for a while.
function renderMediaAdmin() {
  const media = models.filter(isMedia);
  placeAdmin('#slot-media', adminElement('admin-media', 'Media pricing and storage', 'USD per image or second of output, and how long outputs stay.', `<form id="media-price" class="stack"><div class="admin-row"${media.length ? '' : ' hidden'}><label>Model<select name="model">${media.map(m=>`<option value="${esc(m.id)}">${esc(friendly(m))} · ${esc(named(TASKS, m.task))}</option>`).join('')}</select></label><label>Per image ($)<input name="image_usd" type="number" min="0" max="1000" step="0.000001" required value="0"></label><label>Per second of output ($)<input name="second_usd" type="number" min="0" max="1000" step="0.000001" required value="0"></label><button class="primary" type="submit"${media.length ? '' : ' disabled'}>Save media price</button></div><p class="hint">${media.length ? "Billed from the model server's measured output. A job reserves the most it may cost until it ends; a failed or cancelled job is not charged." : 'No media model is connected yet. Run an image, video, speech or sound model with Yougori and share it.'}</p><p class="error" role="alert"></p></form><form id="media-storage" class="stack"><div class="admin-row"><label>Keep outputs (hours)<input name="keep_hours" type="number" min="1" max="720" step="1" required value="24"></label><label>Storage cap (GB)<input name="cap_gb" type="number" min="1" max="10000" step="1" required value="20"></label><button class="secondary" type="submit">Save retention</button></div><p class="hint" id="media-storage-state">Outputs stay on this website, so a result outlives the computer that made it.</p><p class="error" role="alert"></p></form>`));
  const form = $('#media-price');
  const selected = () => { const price = models.find(m=>m.id === form.elements.model.value)?.media_price || {};
    form.elements.image_usd.value = String((price.image_microusd || 0)/1000000);
    form.elements.second_usd.value = String((price.second_microusd || 0)/1000000);
  };
  form.elements.model.onchange = selected; selected();
  formAction('#media-price', async data => {
    await api('/api/admin/media/prices', data);
    const micro = value => Math.round(Number(value)*1000000);
    const model = models.find(m=>m.id === data.model); if(model) model.media_price = {image_microusd: micro(data.image_usd), second_microusd: micro(data.second_usd)};
    notice('Media prices saved.');
  });
  const showStorage = state => {
    $('#media-storage').elements.keep_hours.value = state.keep_hours; $('#media-storage').elements.cap_gb.value = state.cap_gb;
    $('#media-storage-state').textContent = `${state.jobs} stored job${state.jobs === 1 ? '' : 's'}, ${(state.bytes/1024/1024).toFixed(1)} MB · ${state.open} in progress (${state.open_limit} at most). Outputs stay on this website, so a result outlives the computer that made it.`;
  };
  api('/api/admin/media').then(showStorage).catch(()=>{});
  formAction('#media-storage', async data => { showStorage(await api('/api/admin/media', {keep_hours: Number(data.keep_hours), cap_gb: Number(data.cap_gb)})); notice('Media retention saved.'); });
}
