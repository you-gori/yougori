// Real-browser DOM and layout checks. No engine, accounts, inference or screenshots.
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const path = require('node:path');
const {chromium} = require('@playwright/test');

(async () => {
  const site = path.resolve(__dirname, '../site');
  const result = spawnSync('python', ['-B', '-c', 'import sys,json;sys.path.insert(0,sys.argv[1]);import pages;print(json.dumps({"html":pages.shell("Fixture"),"js":pages.SCRIPT,"css":pages.CSS,"theme":pages.THEME_SCRIPT}))', site], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const assets = JSON.parse(result.stdout);
  const browser = await chromium.launch({headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chromium'});
  try {
    const page = await browser.newPage({viewport: {width: 1400, height: 900}});
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    let phase = 0;
    let requests = 0;
    let paymentChecks = 0;
    let paid = false;
    // What a buyer receives: a model's name, maker and price, nothing about where it runs.
    const model = (name, maker, priceIn, priceOut) => ({name, maker, available: true, discovered: true, priceIn, priceOut});
    const catalogue = () => [
      model('openai/gpt-6-astra', 'openai', 10, 50), model('openai/gpt-6-luna', 'openai', 0.1, 0.5),
      model('anthropic/claude-opus-5-5', 'anthropic', 4, 20), model('google/models/gemini-4-argon', 'google', 2, 10),
      model('llama3.3:70b', 'meta', 0.1, 0.32), model(phase === 1 ? 'minimax-m2' : 'minimax-m3', 'minimax', 0.3, 1.2),
      model('anthropic/claude-haiku-5-5', 'anthropic', 0.1, 0.5), model('google/models/gemini-2.5-flash', 'google', 0.3, 2.5),
      model('openai/gpt-5.4-mini', 'openai', 0.75, 4.5)];
    await page.route('http://fixture.invalid/**', async route => {
      const url = new URL(route.request().url());
      let data = {};
      if (url.pathname === '/app.js') return route.fulfill({body: assets.js, contentType: 'text/javascript'});
      if (url.pathname === '/app.css') return route.fulfill({body: assets.css, contentType: 'text/css'});
      if (url.pathname === '/theme.js') return route.fulfill({body: assets.theme, contentType: 'text/javascript'});
      if (url.pathname === '/api/me') data = {signedIn: true, admin: false, anyAdmin: true, walletSet: true, email: 'buyer@example.invalid', credits: paid ? 25 : 0, siteName: 'Fixture'};
      else if (url.pathname === '/api/models') {
        requests++;
        data = {models: phase ? catalogue() : [], updatedAt: phase, refreshSeconds: 30};
      } else if (url.pathname === '/api/keys') data = {keys: []};
      else if (url.pathname === '/api/usage') data = {usage: []};
      else if (url.pathname === '/api/wallet') data = {set: true, network: 'tron', label: 'Tron (TRC-20)', coin: 'USDT', address: 'TFixtureAddressFixtureAddressFixtur', networks: []};
      else if (url.pathname === '/api/payments') {
        paymentChecks++;
        data = {payments: [{reference: 'pay_fixture', dollars: 25, network: 'tron', label: 'Tron (TRC-20)', state: paid ? 'paid' : 'waiting', created_at: 1}]};
      } else if (!url.pathname.startsWith('/api/') && !url.pathname.includes('.')) return route.fulfill({body: assets.html, contentType: 'text/html'});
      else if (url.pathname.includes('.')) return route.fulfill({status: 404, body: ''});
      return route.fulfill({json: data});
    });
    await page.goto('http://fixture.invalid/');
    await page.getByText('No models are ready yet', {exact: true}).waitFor();
    phase = 1;
    await page.getByText('minimax-m2', {exact: true}).waitFor({timeout: 10000});
    assert.equal(await page.locator('.mcard').count(), 9);

    // Four models to a row on a wide screen, fewer as the window narrows.
    const perRow = async () => page.$$eval('.mcard', cards => {
      const top = cards[0].getBoundingClientRect().top;
      return cards.filter(card => Math.abs(card.getBoundingClientRect().top - top) < 2).length;
    });
    assert.equal(await perRow(), 4, 'four cards per row at 1400px');
    const widths = await page.$$eval('.mcard', cards => cards.slice(0, 4).map(card => Math.round(card.getBoundingClientRect().width)));
    assert.ok(Math.max(...widths) - Math.min(...widths) <= 1, `equal card widths: ${widths}`);
    for (const [width, expected] of [[1100, 3], [800, 2], [480, 1]]) {
      await page.setViewportSize({width, height: 900});
      await page.waitForTimeout(150);
      assert.equal(await perRow(), expected, `${expected} per row at ${width}px`);
    }
    await page.setViewportSize({width: 1400, height: 900});

    // Models are named, never their sources; nothing says free unless a price is 0 and 0.
    const text = await page.locator('body').innerText();
    assert.doesNotMatch(text, /subscription|coding tool|claude code|codex|kilo|opencode|ollama|gateway|self-hosted|providers|free/i);
    assert.match(text, /USDT \/1M input/i);
    const filters = await page.locator('.toolbar .toggle').allInnerTexts();
    assert.deepEqual(filters.map(label => label.toLowerCase()), ['all', 'openai', 'anthropic', 'google', 'meta', 'minimax']);
    await page.locator('.toolbar .toggle', {hasText: 'Meta'}).click();
    assert.deepEqual(await page.locator('.mcard-name').allInnerTexts(), ['llama3.3:70b']);
    await page.locator('.toolbar .toggle', {hasText: 'All'}).click();

    // The footer's API box is readable: dark text on its light window.
    const ink = await page.locator('.foot-wins .foot-links span').first().evaluate(node => getComputedStyle(node).color);
    assert.notEqual(ink, 'rgb(255, 255, 255)', 'footer API text is visible');

    // A refresh keeps the search, and replaced models disappear.
    await page.getByRole('searchbox').fill('minimax');
    phase = 2;
    await page.getByText('minimax-m3', {exact: true}).waitFor({timeout: 10000});
    assert.equal(await page.getByRole('searchbox').inputValue(), 'minimax');
    assert.equal(await page.getByText('minimax-m2', {exact: true}).count(), 0);
    await page.getByRole('searchbox').fill('');

    // The hero's Create API key opens the keys page, where USDT is added and a payment
    // that is confirmed raises the balance without a reload.
    await page.locator('.hero-cta .bubble', {hasText: 'Create API key'}).click();
    await page.getByRole('heading', {name: 'API keys', exact: true}).waitFor();
    await page.getByText('Waiting for payment', {exact: true}).waitFor();
    assert.ok(await page.locator('.win-title', {hasText: 'Add USDT'}).count(), 'top-up lives on the keys page');
    paid = true;
    await page.getByText('Payment received. 25.00 USDT added to your balance.', {exact: true}).waitFor({timeout: 10000});
    await page.locator('.stat', {hasText: '25.00 USDT'}).first().waitFor();
    const checks = paymentChecks;
    await page.waitForTimeout(5500);
    assert.equal(paymentChecks, checks, 'payment checks stop once nothing is waiting');

    // Pixel titles really draw on a canvas, at the screen's own resolution.
    const title = page.locator('.page-title canvas');
    await title.waitFor();
    const drawn = await title.evaluate(canvas => ({width: canvas.width, css: parseFloat(canvas.style.width),
      inked: canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data.some((value, index) => index % 4 === 3 && value === 255)}));
    assert.ok(drawn.width > 0 && drawn.css > 0 && drawn.inked, `pixel title drawn: ${JSON.stringify(drawn)}`);

    const stoppedAt = requests;
    await page.waitForTimeout(5500);
    assert.equal(requests, stoppedAt, 'Model polling stopped on navigation');
    assert.deepEqual(errors, []);
    console.log('Models UI passed: four per row (3, 2, 1 as it narrows), names and makers only, USDT, maker filters, readable footer, live updates, preserved search, live payment confirmation, pixel titles, polling cleanup.');
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
