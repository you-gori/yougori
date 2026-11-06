// Light and dark mode in a real browser: every visible text keeps WCAG contrast against what is
// actually behind it, on every page, and the switch remembers a choice that then applies before
// the page paints. No engine, accounts, inference or screenshots.
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const path = require('node:path');
const {chromium} = require('@playwright/test');

// Runs in the page: each element with text, its colour composited over every background and
// opacity behind it, against the WCAG minimum (4.5:1, or 3:1 for large text).
function audit() {
  const parse = value => {
    const match = /rgba?\(([^)]+)\)/.exec(value || '');
    if (!match) return null;
    const parts = match[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return {r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1};
  };
  const over = (top, bottom) => ({r: top.r * top.a + bottom.r * (1 - top.a), g: top.g * top.a + bottom.g * (1 - top.a), b: top.b * top.a + bottom.b * (1 - top.a), a: 1});
  const light = ({r, g, b}) => [r, g, b].map(v => (v /= 255) <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
  const ratio = (one, two) => {
    const [high, low] = [light(one), light(two)].sort((x, y) => y - x);
    return (high + 0.05) / (low + 0.05);
  };
  const failures = [];
  let checked = 0;
  const seen = new Set();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const element = walker.currentNode.parentElement;
    if (!walker.currentNode.textContent.trim() || !element || seen.has(element)) continue;
    seen.add(element);
    if (element.closest('svg, canvas, noscript, option, .sr-only, .veil-text, [disabled]')) continue;
    const style = getComputedStyle(element);
    const box = element.getBoundingClientRect();
    if (!box.width || !box.height || style.visibility === 'hidden') continue;
    let background = {r: 255, g: 255, b: 255, a: 1};
    let opacity = 1;
    const chain = [];
    for (let node = element; node; node = node.parentElement) chain.unshift(node);
    for (const node of chain) {
      const look = getComputedStyle(node);
      const fill = parse(look.backgroundColor);
      if (fill && fill.a > 0) background = over(fill, background);
      opacity *= Number(look.opacity);
    }
    const colour = parse(style.color);
    const shown = over({...colour, a: colour.a * opacity}, background);
    const value = ratio(shown, background);
    const size = parseFloat(style.fontSize);
    const needed = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700) ? 3 : 4.5;
    checked += 1;
    if (value < needed) failures.push(`${element.tagName.toLowerCase()}.${[...element.classList].join('.')} "${walker.currentNode.textContent.trim().slice(0, 32)}" ${value.toFixed(2)} < ${needed}`);
  }
  return {checked, failures};
}

(async () => {
  const site = path.resolve(__dirname, '../site');
  const result = spawnSync('python', ['-B', '-c', 'import sys,json;sys.path.insert(0,sys.argv[1]);import pages;print(json.dumps({"html":pages.shell("Fixture"),"js":pages.SCRIPT,"css":pages.CSS,"theme":pages.THEME_SCRIPT}))', site], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const assets = JSON.parse(result.stdout);
  const browser = await chromium.launch({headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chromium'});
  try {
    // Reduced motion: no curtain or entrance animation half-way through when the audit runs.
    const context = await browser.newContext({viewport: {width: 1400, height: 900}, colorScheme: 'light', reducedMotion: 'reduce'});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    let viewer = 'visitor';
    const model = (name, maker, priceIn, priceOut, more = {}) => ({name, maker, available: true, discovered: true, priceIn, priceOut, ...more});
    const catalogue = () => {
      const admin = viewer === 'admin';
      const extra = (source, cost) => admin ? {provider: 'openai', sandbox: 'paid', priceSource: source, note: '', costIn: cost, costOut: cost && cost * 5,
        marketIn: cost, marketOut: cost && cost * 5, defaultIn: cost, defaultOut: cost && cost * 5, defaultSource: source} : {};
      const list = [
        model('openai/gpt-6-astra', 'openai', 10, 50, extra('list', 10)), model('anthropic/claude-opus-5-5', 'anthropic', 4, 20, extra('market', 4)),
        model('google/models/gemini-4-argon', 'google', 2, 10, extra('list', 2)), model('llama3.3:70b', 'meta', 0.1, 0.32, extra('market', null)),
        model('minimax-m2', 'minimax', 0.3, 1.2, extra('estimate', 0)), model('Qwen/Qwen3-8B', 'qwen', 0, 0, extra('admin', null)),
      ];
      if (admin) list.push(model('google/models/gemini-embedding-2', 'google', 0, 0, {available: false, provider: 'google', sandbox: 'paid', priceSource: ''}));
      return list;
    };
    await page.route('http://fixture.invalid/**', async route => {
      const url = new URL(route.request().url());
      const signedIn = viewer !== 'visitor';
      let data = {};
      if (url.pathname === '/app.js') return route.fulfill({body: assets.js, contentType: 'text/javascript'});
      if (url.pathname === '/app.css') return route.fulfill({body: assets.css, contentType: 'text/css'});
      if (url.pathname === '/theme.js') return route.fulfill({body: assets.theme, contentType: 'text/javascript'});
      if (url.pathname === '/api/me') data = {signedIn, admin: viewer === 'admin', anyAdmin: true, walletSet: true, email: `${viewer}@example.invalid`, credits: 42.5, siteName: 'Fixture'};
      else if (url.pathname === '/api/models') data = {models: catalogue(), updatedAt: 1, refreshSeconds: 30, markup: 0, pricesAsOf: '2026-10-24',
        priceSources: {openai: 'https://openai.com/api/pricing', market: 'https://openrouter.ai/models'}};
      else if (url.pathname === '/api/keys') data = {keys: [{id: 1, name: 'Production', prefix: 'yg-abc1234', model: null, created_at: 1, last_used_at: 2, exhausted_note: null}]};
      else if (url.pathname === '/api/usage') data = {usage: [{model: 'openai/gpt-6-astra', tokensIn: 1200, tokensOut: 300, cost: 0.0324, at: 3}]};
      else if (url.pathname === '/api/wallet') data = {set: true, network: 'tron', label: 'Tron (TRC-20)', coin: 'USDT', hint: 'A Tron address, T and 33 more characters.',
        address: 'TFixtureAddressFixtureAddressFixtur', networks: [{value: 'tron', label: 'Tron (TRC-20)', coin: 'USDT', hint: 'A Tron address.'},
          {value: 'ethereum', label: 'Ethereum (ERC-20)', coin: 'USDT', hint: 'An Ethereum-style address.'}]};
      else if (url.pathname === '/api/payments') data = {payments: [
        {reference: 'pay_waiting', dollars: 25, network: 'tron', label: 'Tron (TRC-20)', state: 'waiting', created_at: 1},
        {reference: 'pay_received', dollars: 50, network: 'tron', label: 'Tron (TRC-20)', state: 'paid', created_at: 1}]};
      else if (url.pathname === '/api/admin/overview') data = {users: 3, paid: 125, spent: 1.25, waiting: [
        {reference: 'pay_waiting', dollars: 25, network: 'tron', label: 'Tron (TRC-20)', address: 'TFixtureAddressFixtureAddressFixtur', created_at: 1, user_id: 2}],
        providers: {paid: {openai: 'Connected', anthropic: 'API key not configured'}, local: {local: 'Connected'}, free: {kilo: 'Provider authorization failed.'}}};
      else if (!url.pathname.startsWith('/api/') && !url.pathname.includes('.')) return route.fulfill({body: assets.html, contentType: 'text/html'});
      else if (url.pathname.includes('.')) return route.fulfill({status: 404, body: ''});
      return route.fulfill({json: data});
    });

    const views = [
      ['visitor', '/', () => page.locator('.mcard').first().waitFor()],
      ['buyer', '/', () => page.locator('.mcard').first().waitFor()],
      ['buyer', '/keys', () => page.getByText('Waiting for payment', {exact: true}).waitFor()],
      ['admin', '/admin', () => page.getByText('Mark as received', {exact: true}).waitFor()],
    ];
    const problems = [];
    let audited = 0;
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({colorScheme: scheme});
      for (const [who, address, ready] of views) {
        viewer = who;
        await page.goto('http://fixture.invalid' + address);
        await ready();
        await page.waitForTimeout(250);
        const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
        assert.equal(background, scheme === 'dark' ? 'rgb(15, 16, 20)' : 'rgb(235, 237, 245)', `${scheme} ${who} ${address} page colour`);
        const {checked, failures} = await page.evaluate(audit);
        audited += checked;
        problems.push(...failures.map(failure => `${scheme} ${who} ${address}: ${failure}`));
      }
      // Pixel titles drawn in ink are turned light in dark mode, and only those.
      const filter = await page.locator('.px.ink.page-title canvas').first().evaluate(canvas => getComputedStyle(canvas).filter);
      assert.ok(filter.startsWith(scheme === 'dark' ? 'invert(1)' : 'invert(0)'), filter);
    }
    assert.deepEqual(problems, [], `Text below the contrast minimum:\n${problems.join('\n')}`);
    assert.ok(audited > 400, `audited ${audited} texts`);

    // The switch: a choice is remembered, applies before the page paints, and following the
    // device again is the same as picking what it shows.
    await page.emulateMedia({colorScheme: 'light'});
    viewer = 'buyer';
    await page.goto('http://fixture.invalid/');
    await page.locator('.quick .bracket', {hasText: 'dark mode'}).click();
    assert.equal(await page.evaluate(() => [document.documentElement.dataset.theme, localStorage.getItem('theme')].join()), 'dark,dark');
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(15, 16, 20)');
    assert.equal(await page.evaluate(() => document.querySelector('meta[name="theme-color"]').content), '#0f1014');
    await page.goto('http://fixture.invalid/keys');
    // theme.js ran in <head>: the page was dark before the app's script.
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'dark');
    await page.locator('.quick .bracket', {hasText: 'light mode'}).click();
    assert.equal(await page.evaluate(() => [String(document.documentElement.dataset.theme), String(localStorage.getItem('theme'))].join()), 'undefined,null');
    // A device in dark mode: the page follows it, and picking light is remembered.
    await page.emulateMedia({colorScheme: 'dark'});
    await page.goto('http://fixture.invalid/');
    await page.locator('.quick .bracket', {hasText: 'light mode'}).click();
    assert.equal(await page.evaluate(() => [document.documentElement.dataset.theme, localStorage.getItem('theme')].join()), 'light,light');
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(235, 237, 245)');
    // On a phone the switch is in the menu.
    await page.setViewportSize({width: 420, height: 860});
    await page.locator('.nav-toggle').click();
    await page.locator('.nav-small .bracket', {hasText: 'dark mode'}).click();
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(15, 16, 20)');
    assert.deepEqual(errors, []);
    console.log(`Theme UI passed: ${audited} texts on 4 pages meet WCAG contrast in light and dark, pixel titles follow the theme, the switch remembers and applies before paint.`);
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
