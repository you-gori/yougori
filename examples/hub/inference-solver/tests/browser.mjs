// Uses a real local website and upstream fixture. No route interception or screenshots.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';

const child = spawn('python', ['-I', '-B', fileURLToPath(new URL('./browser_fixture.py', import.meta.url))], { stdio: ['pipe', 'pipe', 'inherit'] });
const stopped = new Promise(resolve => child.once('exit', resolve));
let browser;
try {
  const lines = createInterface({ input: child.stdout });
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Preview startup timed out')), 20000);
    lines.once('line', line => { clearTimeout(timer); resolve(line); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Preview exited ${code}`)); });
  });
  assert.match(url, /^http:\/\/127\.0\.0\.1:\d+$/);
  browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', chromiumSandbox: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text() + ' ' + message.location().url); });
  await page.goto(url);
  await page.locator('#harnesses-list .entry').last().waitFor();
  assert.equal(await page.locator('#auth').isVisible(), false);
  assert.equal(await page.locator('#signup-link').isVisible(), true);
  assert.equal(await page.locator('#harnesses-list .entry').count(), 21);
  // Categories are one dropdown of checkboxes; any number can be ticked, each with its own blue.
  const categoryMenu = page.getByRole('button', { name: 'Category: All categories' });
  await categoryMenu.click();
  const coding = page.getByRole('checkbox', { name: /^Coding/ });
  const cyber = page.getByRole('checkbox', { name: /^Cyber Coding/ });
  await cyber.check();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 5);
  const dotColor = name => page.locator('.filter-option', { hasText: name }).locator('.filter-dot').evaluate(el => getComputedStyle(el).backgroundColor);
  assert.notEqual(await dotColor(/^Coding/), await dotColor(/^Cyber Coding/));
  await coding.check();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 21);
  assert.equal(await page.locator('#harnesses-filter-button').getAttribute('aria-label'), 'Category: 2 selected');
  await cyber.uncheck();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 16);
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#harnesses-filter-menu').isVisible(), false);
  await page.getByRole('button', { name: 'Category: Coding' }).click();
  await page.getByRole('button', { name: 'Show all', exact: true }).click();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 21);
  assert.equal(await page.locator('#harnesses-filter-menu').isVisible(), false);
  await page.locator('[data-harness="pi"]').click();
  // Installation and later starts are the same Yougori command (installCommand in app.js).
  assert.equal(await page.locator('#guide-code').textContent(), `yougori inference run pi --server "${url}"`);
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run pi --server "${url}"`);
  assert.ok((await page.locator('#guide-copy').textContent()).includes('Copy install command'));
  const install = await page.request.get(url + '/install/pi.ps1');
  assert.equal(install.status(), 200);
  assert.ok((await install.text()).includes('FromBase64String'));
  assert.equal(await page.locator('#setup-account').getAttribute('href'), '#connect');
  // Step 1 sends people without Yougori to its official download, not to a script from this server.
  assert.equal(await page.locator('#get-yougori').getAttribute('href'), 'https://yougori.com/#download');
  assert.ok((await page.locator('#not-recognized').textContent()).includes('not recognized'));
  assert.equal(await page.locator('#harness-install-inline .install-steps > li').count(), 3);
  const download = await page.request.get(new URL(await page.locator('#harness-download').getAttribute('href'), url).href);
  assert.equal(download.status(), 200);
  assert.equal(download.headers()['content-type'], 'application/zip');
  assert.ok((await download.body()).subarray(0, 2).equals(Buffer.from('PK')));
  assert.equal(await page.locator('dialog[open]').count(), 0);
  assert.equal(new URL(page.url()).hash.includes('/pi'), false);
  assert.equal(await page.locator('#harnesses-list .entry').first().evaluate(el => getComputedStyle(el).borderTopWidth), '0px');
  assert.ok((await page.locator('#harness-install-inline').textContent()).includes('starts automatically after installation'));
  await page.getByRole('button', { name: 'Copy start command', exact:true }).waitFor();
  await page.locator('#close-installation').click();
  await page.locator('#harnesses-list .entry').last().waitFor();
  await page.locator('[data-harness="pentagi"]').click();
  await page.locator('#harness-install-inline').waitFor();
  assert.equal(await page.locator('dialog[open]').count(), 0);
  assert.equal(await page.locator('#harness-download').count(), 1);
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run pentagi --server "${url}"`);
  await page.keyboard.press('Escape');
  await page.locator('#harnesses-list .entry').last().waitFor();
  await page.locator('.quick').getByRole('button', { name: 'Switch to dark mode' }).click();
  await page.reload();
  await page.locator('.quick').getByRole('button', { name: 'Switch to light mode' }).waitFor();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.locator('.quick').getByRole('button', { name: 'Switch to light mode' }).click();
  await page.locator('#nav a[href="#models"]').click();
  await page.locator('#view .model-id').last().waitFor();
  assert.equal(await page.locator('#view .entry').count(), 2);
  await page.reload();
  await page.locator('#view .model-id').last().waitFor();
  assert.equal(await page.locator('#auth').isVisible(), false);
  await page.setViewportSize({ width: 390, height: 900 });
  await page.locator('#menu-toggle').click();
  await page.locator('#menu-links a[href="#harnesses"]').click();
  await page.locator('#harnesses-list .entry').last().waitFor();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 21);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(url + '/#keys');
  await page.locator('#auth-title').waitFor();
  assert.equal(await page.locator('#workspace').isVisible(), false);
  await page.locator('#nav a[href="#harnesses"]').click();
  await page.locator('#harnesses-list').waitFor();
  await page.locator('#signin-link').click();
  await page.getByLabel('Email', { exact: true }).fill('admin@example.invalid');
  await page.getByLabel('Password', { exact: true }).fill('disposable-test-password');
  await page.locator('#auth-submit').click();
  // The administrator's first sign-in asks for the main page and the harnesses offered, all ticked.
  await page.getByRole('heading', { name: 'Set up your inference', exact: true }).waitFor();
  assert.equal(await page.locator('#choices-form [name="home"]:checked').getAttribute('value'), 'harnesses');
  assert.equal(await page.locator('#choice-count').textContent(), '21 of 21 harnesses offered');
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await page.getByRole('button', { name: 'Save and continue ↗' }).click();
  await page.getByText('Offer at least one harness, or choose another main page.', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Select all', exact: true }).click();
  await page.getByLabel(/^Aider/).uncheck();
  assert.equal(await page.locator('#choice-count').textContent(), '20 of 21 harnesses offered');
  await page.getByRole('button', { name: 'Save and continue ↗' }).click();
  await page.locator('#harnesses-list .entry').last().waitFor();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 20);
  assert.equal(await page.locator('[data-harness="aider"]').count(), 0);
  assert.equal((await page.request.get(url + '/install/aider.ps1')).status(), 404);
  await page.getByRole('searchbox').fill('Codex');
  assert.equal(await page.locator('#harnesses-list .entry').count(), 1);
  await page.locator('[data-harness="codex"]').click();
  await page.getByText('Requirements and source',{exact:true}).click();
  await page.locator('#harness-download').waitFor();
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run codex --server "${url}"`);
  await page.keyboard.press('Escape');
  await page.locator('#nav a[href="#models"]').click();
  await page.locator('#view .model-id').last().waitFor();
  assert.equal(await page.locator('#view .entry').count(), 2);
  await page.getByRole('button', { name: /^Uncensored/ }).click();
  assert.equal(await page.locator('#view .entry').count(), 0);
  await page.getByRole('button', { name: /^Uncensored/ }).click();
  await page.locator('[data-model]').first().click();
  await page.locator('#censorship-form select').selectOption('uncensored');
  await page.getByRole('button', { name: 'Save label ↗' }).click();
  await page.getByText('Uncensored, set by the administrator').waitFor();
  const labelled = (await (await fetch(url + '/api/models')).json()).models.filter(m => m.censorship === 'uncensored');
  assert.equal(labelled.length, 1);
  assert.equal(labelled[0].censorship_source, 'administrator');
  await page.locator('#section-actions a[href="#models"]').click();
  await page.getByRole('button', { name: /^Uncensored/ }).click();
  assert.equal(await page.locator('#view .entry').count(), 1);
  await page.getByRole('button', { name: /^Censored/ }).click();
  assert.equal(await page.locator('#view .entry').count(), 1);
  await page.getByRole('button', { name: /^Censored/ }).click();
  assert.equal(await page.locator('#view .entry').count(), 2);
  await page.locator('#nav a[href="#keys"]').click();
  await page.getByRole('button', { name: 'Create API key ↗' }).click();
  await page.getByLabel('Key name').fill('Browser tool');
  await page.locator('#key-access').selectOption('selected');
  await page.locator('#scope-list input').first().check();
  await page.getByRole('button', { name: 'Create key ↗' }).click();
  await page.getByRole('heading', { name: 'Save your API key' }).waitFor();
  const key = await page.locator('.secret').textContent();
  assert.match(key, /^is_/);
  const catalog = await (await fetch(url + '/v1/models', { headers: { Authorization: 'Bearer ' + key } })).json();
  assert.equal(catalog.data.length, 1);
  await page.getByRole('button', { name: 'Close dialog' }).click();
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
  await page.getByRole('cell', { name: 'Revoked', exact: true }).waitFor();
  assert.equal((await fetch(url + '/v1/models', { headers: { Authorization: 'Bearer ' + key } })).status, 401);
  await page.locator('#nav a[href="#admin"]').click();
  await page.getByRole('heading', { name: 'Rent a cloud GPU', exact: true }).waitFor();
  await page.getByRole('heading', { name: 'Local GPUs', exact: true }).waitFor();
  assert.equal(await page.locator('#compute-setup input[name="url"], #compute-setup select[name="place"]').count(), 0);
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.getByRole('heading', {name:'Sandboxes', exact:true}).waitFor();
  await page.getByRole('heading', {name:'Crypto payments', exact:true}).waitFor();
  await page.getByRole('heading', {name:'Media pricing and storage', exact:true}).waitFor();
  // Admin is one column, in this order, with nothing folded away.
  const sections = await page.locator('#admin-grid .admin-section').evaluateAll(nodes => nodes.map(node => {
    const r = node.getBoundingClientRect(); return {id: node.id, x: r.x, y: r.y};
  }));
  assert.deepEqual(sections.map(s => s.id), ['admin-local', 'admin-rent', 'admin-servers', 'admin-sandboxes', 'admin-choices', 'admin-identity', 'admin-people', 'admin-prices', 'admin-media', 'admin-payments', 'admin-activity']);
  assert.ok(sections.every((s, i) => s.x === sections[0].x && (i === 0 || s.y > sections[i - 1].y)));
  assert.equal(await page.locator('#admin-grid details').count(), 0);
  // The left edge is the PrompX harness's ruler, one mark per section, in place of the scrollbar.
  assert.equal(await page.locator('.rail .rail-mark').count(), 11);
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).scrollbarWidth), 'none');
  // The ruler is 48 px wide and never covers the page: the sections and the footer start after it.
  const edges = await page.evaluate(() => ({rail: document.querySelector('.rail').getBoundingClientRect(), grid: document.querySelector('#admin-grid').getBoundingClientRect().left, foot: document.querySelector('.foot-inner').getBoundingClientRect().left}));
  assert.equal(edges.rail.width, 48);
  assert.ok(edges.rail.right + 16 <= edges.grid && edges.rail.right + 16 <= edges.foot, JSON.stringify(edges));
  await page.locator('.rail').hover();
  await page.locator('.rail-mark', { hasText: 'Crypto payments' }).click();
  await page.waitForFunction(() => document.querySelector('.rail-mark[aria-current="true"]')?.textContent === 'Crypto payments');
  await page.locator('.rail').click({ position: { x: 4, y: 20 } });
  await page.waitForFunction(() => scrollY < 50);
  // A computer's code is approved right in Local GPUs.
  await page.locator('#contributor-inspect input[name="code"]').fill('ZZZZ9999');
  await page.getByRole('button', { name: 'Check computer', exact: true }).click();
  await page.locator('#contributor-inspect .error').filter({ hasText: /./ }).waitFor();
  // Without Yougori on the website's server, as on every hosted inference, computers connect with the
  // command shown first, and renting points to the Yougori app instead of controls that cannot work.
  assert.equal(await page.locator('#compute-install').textContent(), `yougori inference connect "${url}"`);
  // Every command a computer runs, in order: install or update Yougori (Windows or Linux), start it
  // (the connector never does), then connect. Each Copy button copies its own command.
  const steps = await page.locator('#admin-local .command-steps li').evaluateAll(rows => rows.map(row => [
    row.querySelector('.command-label').textContent, row.querySelector('pre').textContent, row.querySelector('button').dataset.copy]));
  assert.deepEqual(steps.map(([label]) => label), ['Install or update Windows', 'Install or update Linux', 'Start Yougori', 'Connect this computer']);
  assert.deepEqual(steps.map(([, command]) => command), [
    'powershell -c "Set-Item Env:YOUGORI_ALLOW_UNSIGNED 1; irm https://yougori.com/install-preview.ps1 | iex"',
    'curl -fsSL https://yougori.com/install-preview.sh | YOUGORI_ALLOW_UNSIGNED=1 bash',
    'yougori app start',
    `yougori inference connect "${url}"`,
  ]);
  assert.ok(steps.every(([, command, copied]) => command === copied));
  await page.locator('#admin-local .command-steps li', { hasText: 'Start Yougori' }).getByRole('button', { name: 'Copy' }).click();
  await page.locator('#admin-local .command-steps li', { hasText: 'Start Yougori' }).getByRole('button', { name: 'Copied' }).waitFor();
  // Copy all copies the whole set as one message; Post on X opens X with a short post ready to send.
  const siteName = await page.locator('#brand').textContent();
  const all = await page.locator('#compute-copy-all').getAttribute('data-copy');
  assert.equal(all, [`Connect a computer with a GPU to ${siteName}. Run these in a terminal, in order:`, '',
    '1. Install or update Yougori; this updates the desktop app too (after a first install, open a new terminal)',
    `   Windows: ${steps[0][1]}`, `   Linux: ${steps[1][1]}`,
    '2. Start Yougori', '   yougori app start',
    '3. Connect this computer, and choose what it shares', `   yougori inference connect "${url}"`, '',
    'It shows a code for the administrator to approve. Keep its terminal open.'].join('\n'));
  await page.locator('#compute-copy-all').click();
  await page.waitForFunction(() => document.querySelector('#compute-copy-all').textContent === 'Copied');
  const xPost = page.locator('#compute-post-x');
  const intent = new URL(await xPost.getAttribute('href'));
  assert.equal(intent.origin + intent.pathname, 'https://x.com/intent/post');
  assert.equal(intent.searchParams.get('text'), `Connect your GPU to ${siteName}:\n\n1. Install Yougori: yougori.com\n2. yougori app start\n3. yougori inference connect "${url}"`);
  assert.ok(intent.searchParams.get('text').length <= 280);
  assert.equal(await xPost.getAttribute('target'), '_blank');
  assert.match(await xPost.getAttribute('rel'), /noopener/);
  assert.equal(await page.locator('#rent-elsewhere').isVisible(), true);
  assert.equal(await page.locator('#rent-here').isHidden(), true);
  assert.equal(await page.locator('#compute-website').isHidden(), true);
  // Optional settings are tick boxes that switch their fields on.
  const contributor = page.locator('#compute-password');
  assert.equal(await contributor.locator('[name="password"]').isDisabled(), true);
  await contributor.getByLabel('Let people connect with a password').check();
  await contributor.locator('[name="password"]').fill('contributor-password-1');
  await contributor.getByRole('button', { name: 'Save contribution access' }).click();
  await page.getByText('Contributor password saved.', { exact: true }).waitFor();
  await page.locator('#compute-password-state', { hasText: 'A password is set' }).waitFor();
  await contributor.getByLabel('Let people connect with a password').uncheck();
  assert.equal(await contributor.locator('[name="password"]').isDisabled(), true);
  await contributor.getByRole('button', { name: 'Save contribution access' }).click();
  await page.getByText('You now approve every computer yourself.', { exact: true }).waitFor();
  const policy = page.locator('#grid-policy');
  assert.equal(await policy.locator('[name="password"]').isDisabled(), true);
  await policy.locator('[name="admission"]').selectOption('password');
  assert.equal(await policy.locator('[name="password"]').isEnabled(), true);
  await policy.locator('[name="admission"]').selectOption('private');
  await page.locator('#payment-wallet select').selectOption('base');
  await page.locator('#payment-wallet input[name="address"]').fill('0x' + '1'.repeat(40));
  await page.getByRole('button', {name:'Save receiving wallet',exact:true}).click();
  await page.locator('#payment-wallets .wallet-address').waitFor();
  await page.getByRole('heading', {name:'Model pricing',exact:true}).waitFor();
  await page.locator('#nav a[href="#usage"], #menu-links a[href="#usage"]').first().click();
  await page.getByRole('heading', {name:'Balance',exact:true}).waitFor();
  await page.locator('#credit-invoice input[name="amount"]').fill('3');
  await page.getByRole('button', {name:'Create payment invoice',exact:true}).click();
  await page.locator('[data-invoice]').waitFor();
  assert.ok((await page.locator('[data-invoice]').innerText()).includes('$3 USD'));
  assert.equal(await page.locator('dialog[open]').count(),0);
  // User-rejected wallet approval never submits a transaction or creates credits.
  await page.evaluate(()=>{window.ethereum={request:async ({method})=>{
    if(method==='wallet_switchEthereumChain') return null;
    if(method==='eth_requestAccounts') return ['0x'+'2'.repeat(40)];
    throw new Error('User rejected the payment');
  }};});
  await page.getByRole('button',{name:'Approve payment in wallet',exact:true}).click();
  await page.getByText('User rejected the payment',{exact:true}).waitFor();
  assert.equal(await page.locator('#credit-balance').textContent(),'$0');
  await page.getByRole('button',{name:'Cancel unused invoice',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('[data-invoice]')?.textContent.includes('cancelled'));
  await page.locator('a[href="#admin"]').first().click();
  await page.locator('#admin-sandboxes').waitFor();
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.locator('#add-endpoint').click();
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.getByLabel('Website name').fill('My inference team');
  assert.equal(await page.locator('.palette-option input').count(), 6);
  await page.getByLabel('Rosé Pine').check();
  await page.getByRole('button', { name: 'Save identity ↗' }).click();
  await page.getByText('Website identity saved.', { exact: true }).waitFor();
  await page.locator('#brand', { hasText: 'My inference team' }).waitFor();
  // The colour style is the whole site's: it arrives with the page itself, for every visitor.
  assert.equal(await page.evaluate(() => document.documentElement.dataset.palette), 'rose-pine');
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--pill').trim()), '#286983');
  assert.match(await (await fetch(url + '/')).text(), /<html lang="en" data-palette="rose-pine">/);
  // Admin keeps the same choices: the main page leads the menu and opens at the site's own address.
  const choices = page.locator('#admin-choices');
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 20);
  await choices.getByLabel(/^Models/).check();
  await choices.getByLabel(/^Aider/).check();
  await choices.getByRole('button', { name: 'Save choices ↗' }).click();
  await page.getByText('Main page and harnesses saved.', { exact: true }).waitFor();
  assert.equal(await page.locator('#nav a').first().textContent(), 'Models');
  assert.equal(await page.locator('#brand').getAttribute('href'), '#models');
  await page.goto(url);
  await page.locator('#view .model-id').last().waitFor();
  assert.equal(await page.locator('#nav a[aria-current="page"]').textContent(), 'Models');
  await page.goto(url + '/#admin');
  await choices.waitFor();
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 21);
  await choices.getByLabel(/^Harnesses/).check();
  await choices.getByRole('button', { name: 'Save choices ↗' }).click();
  await page.getByText('Main page and harnesses saved.', { exact: true }).waitFor();
  assert.equal(await page.locator('#nav a').first().textContent(), 'Harnesses');
  await page.getByLabel('Email address').fill('new-member@example.invalid');
  await page.getByRole('button', { name: 'Create invitation ↗' }).click();
  await page.locator('.secret').waitFor();
  const invitation = await page.locator('.secret').textContent();
  await page.keyboard.press('Escape');
  for (const width of [768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Admin overflows at ${width}px`);
    await page.getByRole('button', { name: 'Menu', exact: true }).click();
    await page.locator('#menu-links a[href="#models"]').click();
    await page.locator('#view .model-id').last().waitFor();
    assert.equal(await page.locator('#menu-toggle').getAttribute('aria-expanded'), 'false');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Models overflow at ${width}px`);
    await page.getByRole('button', { name: 'Menu', exact: true }).click();
    await page.locator('#menu-links a[href="#admin"]').click();
    await page.locator('#branding-form').waitFor();
  }
  await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#menu-toggle').getAttribute('aria-expanded'), 'false');
  await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await page.locator('#menu-signout').click();
  // The old list stays on screen until sign-out finishes, so wait for the signed-out header.
  await page.waitForFunction(() => !document.querySelector('#signin-link').hidden);
  await page.locator('#harnesses-list').waitFor();
  assert.equal(await page.locator('#auth').isVisible(), false);
  await page.locator('#menu-toggle').click();
  await page.locator('#menu-links a[href="#signin"]').click();
  await page.locator('#auth-invitation').click();
  await page.getByLabel('Email', { exact: true }).fill('new-member@example.invalid');
  await page.getByLabel('Password', { exact: true }).fill('disposable-test-password');
  await page.getByLabel('Invitation code').fill(invitation);
  await page.locator('#auth-submit').click();
  await page.locator('#harnesses-list').waitFor();
  assert.equal(await page.locator('#admin-link').isVisible(), false);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Harness grid overflows on mobile');
  await page.locator('#menu-toggle').click();
  await page.locator('#menu-signout').click();
  // The old list stays on screen until sign-out finishes, so wait for the signed-out header.
  await page.waitForFunction(() => !document.querySelector('#signin-link').hidden);
  await page.locator('#harnesses-list').waitFor();
  await page.locator('#menu-toggle').click();
  await page.locator('#menu-links a[href="#signup"]').click();
  await page.getByRole('heading', { name: 'Create your account' }).waitFor();
  assert.equal(await page.locator('#invitation-field').isVisible(), false);
  assert.equal(await page.locator('#login-form input[name=password]').getAttribute('minlength'), '12');
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Signup overflows on mobile');
  // The signup route survives refresh, and the form reports a duplicate without switching modes.
  await page.reload();
  await page.getByRole('heading', { name: 'Create your account' }).waitFor();
  await page.getByLabel('Email', { exact: true }).fill('admin@example.invalid');
  await page.getByLabel('Password', { exact: true }).fill('disposable-test-password');
  const duplicateResponse = page.waitForResponse(response => response.url() === url + '/api/signup');
  await page.locator('#auth-submit').click();
  assert.equal((await duplicateResponse).status(), 400);
  await page.locator('#auth-error').filter({ hasText: 'already exists' }).waitFor();
  await page.getByLabel('Email', { exact: true }).fill('public-member@example.invalid');
  await page.locator('#auth-submit').click();
  await page.locator('#harnesses-list').waitFor();
  const newSession = await (await page.request.get(url + '/api/session')).json();
  assert.equal(newSession.user.email, 'public-member@example.invalid');
  assert.equal(newSession.user.admin, 0);
  assert.equal(await page.locator('#signup-link').isVisible(), false);
  assert.equal(await page.locator('#admin-link').isVisible(), false);
  assert.equal((await page.request.get(url + '/api/admin/overview')).status(), 403);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.locator('#signout').click();
  // The old list stays on screen until sign-out finishes, so wait for the signed-out header.
  await page.waitForFunction(() => !document.querySelector('#signin-link').hidden);
  await page.locator('#harnesses-list').waitFor();
  await page.locator('#signup-link').click();
  await page.getByRole('heading', { name: 'Create your account' }).waitFor();
  await page.locator('#auth-toggle').click();
  await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
  await page.getByLabel('Email', { exact: true }).fill('public-member@example.invalid');
  await page.getByLabel('Password', { exact: true }).fill('disposable-test-password');
  await page.locator('#auth-submit').click();
  await page.locator('#harnesses-list').waitFor();
  await page.locator('#nav a[href="#keys"]').click();
  await page.getByRole('button', { name: 'Create API key ↗' }).waitFor();
  // A deliberately rejected duplicate signup and a deliberately wrong computer code produce Chrome's normal HTTP error log.
  assert.deepEqual(errors.filter(error => !(error.includes('400') && (error.endsWith(url + '/api/signup') || error.endsWith(url + '/api/compute/pair/inspect')))), []);
  console.log('Browser flow passed: public signup/login on desktop and mobile, member/admin boundaries, guest-first catalogs, scoped key/revoke, branding, invitations, themes and responsive layouts.');
} finally {
  await browser?.close();
  child.stdin.end('\n');
  await stopped;
}
