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
  // The fixture's own commands (browser_fixture.py), each answered with one line.
  const fixture = command => new Promise(resolve => { lines.once('line', resolve); child.stdin.write(command + '\n'); });
  browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', chromiumSandbox: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text() + ' ' + message.location().url); });
  await page.goto(url);
  await page.locator('#harnesses-list .entry').last().waitFor();
  assert.equal(await page.locator('#auth').isVisible(), false);
  assert.equal(await page.locator('#signup-link').isVisible(), true);
  // The Harnesses column lists one item, Yougori, saying how many harnesses it holds.
  assert.equal(await page.locator('#harnesses-list .entry').count(), 1);
  assert.equal(await page.locator('#harnesses-list .entry-name').textContent(), 'Yougori');
  assert.equal(await page.locator('#harnesses-list [data-harness]').getAttribute('data-harness'), 'yougori');
  assert.equal(await page.locator('#harnesses-list .entry-meta').textContent(), '21 harnesses inside · 16 Coding · 5 Cyber Coding');
  // The note under it says what each kind reaches: a coding harness may be given more, a security harness
  // only ever its target and this server.
  assert.equal(await page.locator('#harnesses-column .catalog-note').textContent(), 'Blue terminals. Your models. Each harness runs in an isolated Sandbox VM. A coding harness reaches only this server unless you choose more. A security harness reaches only its target and this server.');
  // Harnesses, models and sandboxes share one page, side by side, with no tabs; sandboxes join only when
  // a computer offers them, and the page keeps room on both sides.
  assert.equal(await page.locator('#nav a[href="#harnesses"], #nav a[href="#models"], #nav a[href="#sandboxes"]').count(), 0);
  await page.locator('#models-list .entry').last().waitFor();
  const tools = await page.locator('#harnesses-column').boundingBox(), modelsBox = await page.locator('#models-column').boundingBox();
  assert.equal(modelsBox.y, tools.y);
  assert.ok(modelsBox.x > tools.x + tools.width && Math.abs(tools.width - modelsBox.width) < 1, 'The tools and models columns are side by side');
  assert.ok(tools.x >= 40, 'The page keeps room on its left');
  // Yougori's card starts on the line of the models' search.
  assert.equal((await page.locator('#harnesses-list').boundingBox()).y, (await page.locator('#models-column .search-box').boundingBox()).y);
  assert.equal(await page.locator('#sandboxes-column').isVisible(), false);
  // API keys are a dropdown at the right of the main page's title; visitors are asked to sign in first.
  const title = await page.locator('#section-title').boundingBox(), keysButton = await page.locator('#keys-button').boundingBox();
  assert.ok(keysButton.x > title.x + title.width, 'The API keys button is right of the title');
  await page.locator('#keys-button').click();
  await page.locator('#keys-panel').getByRole('link', { name: 'Sign in ↗' }).waitFor();
  assert.equal(await page.locator('#keys-panel').getByRole('link', { name: 'Sign in ↗' }).getAttribute('href'), '#keys');
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#keys-panel').isVisible(), false);
  // Yougori's card opens its page, at its own address.
  await page.locator('[data-harness="yougori"]').click();
  await page.locator('#harness-install-inline').waitFor();
  assert.equal(new URL(page.url()).hash, '#harnesses/yougori');
  assert.equal(await page.locator('#section-title').textContent(), 'Yougori');
  // Installation and later starts are the same Yougori command (installCommand in app.js): it asks which
  // harness, then which model, then that harness's own questions.
  assert.equal(await page.locator('#guide-code').textContent(), `yougori inference run yougori --server "${url}"`);
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run yougori --server "${url}"`);
  assert.ok((await page.locator('#guide-copy').textContent()).includes('Copy install command'));
  assert.equal(await page.locator('#setup-account').getAttribute('href'), '#connect');
  // Step 1 sends people without Yougori to its official download, not to a script from this server, and
  // people with an older Yougori to its update: an older CLI knows no harness named yougori.
  assert.equal(await page.locator('#get-yougori').getAttribute('href'), 'https://yougori.com/#download');
  assert.ok((await page.locator('#harness-install-inline .install-steps > li').first().textContent()).includes('Already installed? Update it with yougori update, then go to step 2.'));
  const notRecognized = await page.locator('#not-recognized').textContent();
  assert.ok(notRecognized.includes('not recognized') && notRecognized.includes('If it says Unknown harness, update Yougori with yougori update.'), notRecognized);
  assert.equal(await page.locator('#harness-install-inline .install-steps > li').count(), 3);
  const startSteps = await page.locator('#harness-install-inline .install-steps').textContent();
  // The fixture publishes the Yougori harness's base, so its own agent is ready with the others.
  assert.ok(startSteps.includes('Yougori asks which harness, its own agent or one of the ready ones below, then which model'), startSteps);
  assert.ok(startSteps.includes('starts automatically after installation'), startSteps);
  // A coding harness is asked what its VM may reach; a security harness is not, and its About banner says
  // the same: it reaches only its target and this inference.
  assert.ok(startSteps.includes('Before the VM starts, it asks what a coding harness may use: a project folder (copied in; changes come back only after your review), what it can reach (only this inference, sites you choose, or the whole internet as well), and CPU and memory. A security harness is not asked what it can reach: it reaches only its target and this inference.'), startSteps);
  assert.equal(await page.locator('.detail-side .small-banner').textContent(), `Blue terminal, connected to ${new URL(url).host}. A coding harness reaches only this inference unless you choose more. A security harness reaches only its target and this inference.`);
  // So do its requirements, which cover both kinds (app.js REQUIREMENTS); a coding harness's own page says
  // only what its VM reaches (REQUIREMENTS_CODING, on Pi's and Codex's pages below).
  const requirements = 'Yougori manages the private runtime on Windows. A coding harness reaches only this server unless you choose more: when you start it, Yougori asks whether it may also reach sites you choose or the whole internet. A security harness reaches only its target and this server, and Yougori does not ask. Linux source requires Python and a supported Yougori VM backend. macOS is not supported yet.';
  const codingRequirements = 'Yougori manages the private runtime on Windows. The VM reaches only this server unless you choose more: when you start it, Yougori asks whether it may also reach sites you choose or the whole internet. Linux source requires Python and a supported Yougori VM backend. macOS is not supported yet.';
  assert.equal(await page.locator('#harness-install-inline .install-details .hint').textContent(), `${requirements} Each harness's page, linked from its name below, has its source setup.`);
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.getByRole('button', { name: 'Copy start command', exact:true }).waitFor();
  // A harness's own command starts the list on it; --yes asks nothing, so it needs the model when there are
  // several and the answers the harness's page names.
  const againYougori = await page.locator('#again-hint').textContent();
  for (const words of ["Each harness's Copy command below copies its own command, which starts the list on that harness.", 'To ask nothing, add --yes to it, with --model ID when there is more than one model and the answers its page names.']) assert.ok(againYougori.includes(words), againYougori);
  // Inside: the harnesses offered here, coding then security as the command lists them, one row each with
  // what it asks and a copy of its own command, under the steps, Open it again and the requirements. The page
  // shows the command itself only at the top. Yougori's own agent is not listed inside itself.
  assert.deepEqual(await page.locator('#harness-install-inline .panel-heading h2').allTextContents(), ['Install and start', 'Open it again', 'Coding', 'Cyber Coding']);
  assert.deepEqual(await page.locator('#harness-install-inline > *').evaluateAll(parts => parts.map(part => part.id || part.className)), ['panel', 'panel', 'install-details', 'group-coding', 'group-security']);
  assert.equal(await page.locator('#harness-install-inline pre').count(), 2);
  const inside = await page.locator('[data-inside]').evaluateAll(links => links.map(link => link.dataset.inside));
  assert.equal(inside.length, 21);
  assert.deepEqual(inside.slice(16), ['strix', 'shannon', 'pentagi', 'pentestgpt', 'hexstrike']);
  assert.equal(inside.includes('yougori'), false);
  const pi = page.locator('#inside-pi');
  assert.equal(await pi.locator('.tag').textContent(), 'Ready');
  assert.equal(await pi.locator('.entry-text').textContent(), (await (await page.request.get(url + '/api/harnesses')).json()).harnesses.find(h => h.id === 'pi').description);
  // A harness that asks nothing of its own says nothing about it.
  assert.equal(await pi.locator('.entry-meta').count(), 0);
  assert.equal(await page.locator('#inside-swe .entry-meta').textContent(), 'Asks for: the issue to fix.');
  assert.equal(await page.locator('#inside-strix .entry-meta').textContent(), 'Asks for: target, permission, how far it may go. Optional: what is off limits, a test login, source code, focus.');
  assert.equal(await page.locator('#inside-shannon .entry-meta').textContent(), 'Asks for: target, permission, how far it may go, source code. Optional: what is off limits, a test login, focus.');
  const copyPi = pi.getByRole('button', { name: 'Copy command for Pi', exact: true });
  assert.equal(await copyPi.textContent(), 'Copy command');
  assert.equal(await copyPi.getAttribute('data-copy'), `yougori inference run pi --server "${url}"`);
  assert.equal(await page.locator('#inside-strix [data-copy]').getAttribute('data-copy'), `yougori inference run strix --server "${url}"`);
  await copyPi.click();
  await page.waitForFunction(() => document.querySelector('#inside-pi [data-copy]').textContent === 'Copied');
  // Security harnesses: permission before anything starts, the target's reach with nothing more offered,
  // the practice app, the report.
  const security = await page.locator('#group-security .panel-body > .hint').textContent();
  for (const words of ['without a yes, nothing starts', 'The VM reaches only the target and this inference. Yougori does not offer other sites or the whole internet.', 'the practice app', 'The report comes back to your folder']) assert.ok(security.includes(words), words);
  assert.equal(security.includes('unless you choose more'), false, security);
  // ← Main page returns to the main page where Yougori was opened, with its card focused.
  await page.getByRole('button', { name: '← Main page' }).click();
  await page.locator('#harness-install-inline').waitFor({ state: 'detached' });
  assert.equal(new URL(page.url()).hash, '');
  assert.equal(await page.evaluate(() => document.activeElement?.dataset.harness), 'yougori');
  assert.equal(await page.locator('#harnesses-list .entry').first().evaluate(el => getComputedStyle(el).borderTopWidth), '0px');
  // Each harness inside keeps its own page and address, which old links open: its own command, the
  // install script and the source setup. ← Yougori, as the browser's Back, returns to it on Yougori's page.
  await page.locator('[data-harness="yougori"]').click();
  await page.locator('[data-inside="pi"]').scrollIntoViewIfNeeded();
  const piPlace = await page.evaluate(() => scrollY);
  await page.locator('[data-inside="pi"]').click();
  await page.locator('#section-title', { hasText: /^Pi$/ }).waitFor();
  assert.equal(new URL(page.url()).hash, '#harnesses/pi');
  assert.equal(await page.locator('#guide-code').textContent(), `yougori inference run pi --server "${url}"`);
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run pi --server "${url}"`);
  assert.ok((await page.locator('#harness-install-inline').textContent()).includes('Pi starts automatically after installation'));
  assert.equal(await page.locator('#harness-install-inline .install-steps > li').count(), 3);
  // Its command starts the list of harnesses on Pi. With --yes it keeps the defaults, given the model when
  // there are several.
  const piSteps = await page.locator('#harness-install-inline .install-steps').textContent();
  assert.ok(piSteps.includes('Yougori asks which harness, with Pi already selected, then which model. Before the VM starts, it asks what Pi may use: a project folder'), piSteps);
  // A coding harness is still asked what its VM may reach.
  assert.ok(piSteps.includes('what it can reach (only this inference, sites you choose, or the whole internet as well), and CPU and memory.'), piSteps);
  assert.equal(await page.locator('.detail-side .small-banner').textContent(), `Blue terminal, connected to ${new URL(url).host}. The VM reaches only this inference unless you choose more.`);
  // Its requirements speak of its own VM only, never of security harnesses.
  assert.equal(await page.locator('#harness-install-inline .install-details .hint').textContent(), codingRequirements);
  assert.equal(await page.locator('#again-hint').textContent(), 'Yougori asks its questions again each time. To ask nothing, add --yes to keep the defaults, with --model ID when there is more than one model. Add --workspace "C:\\path\\to\\project" to name the project folder. The VM works on a copy; review and promote changes in Yougori. It runs until you exit or stop it.');
  assert.ok((await page.locator('.detail-side .facts').textContent()).includes('No questions of its own.'));
  const install = await page.request.get(url + '/install/pi.ps1');
  assert.equal(install.status(), 200);
  assert.ok((await install.text()).includes('FromBase64String'));
  const download = await page.request.get(new URL(await page.locator('#harness-download').getAttribute('href'), url).href);
  assert.equal(download.status(), 200);
  assert.equal(download.headers()['content-type'], 'application/zip');
  assert.ok((await download.body()).subarray(0, 2).equals(Buffer.from('PK')));
  await page.getByRole('button', { name: '← Yougori' }).click();
  await page.locator('#section-title', { hasText: 'Yougori' }).waitFor();
  assert.equal(new URL(page.url()).hash, '#harnesses/yougori');
  assert.equal(await page.evaluate(() => scrollY), piPlace);
  assert.equal(await page.evaluate(() => document.activeElement?.dataset.inside), 'pi');
  await page.locator('[data-inside="pentagi"]').scrollIntoViewIfNeeded();
  const pentagiPlace = await page.evaluate(() => scrollY);
  assert.ok(pentagiPlace > piPlace, 'PentAGI is further down the page');
  await page.locator('[data-inside="pentagi"]').click();
  await page.locator('#section-title', { hasText: 'PentAGI' }).waitFor();
  assert.equal(new URL(page.url()).hash, '#harnesses/pentagi');
  // A security harness's own page says what happens around its run. Its report comes back to the folder
  // Yougori asks for, or to the source code's when that is given. --yes needs the target, and an address
  // needs the permission yes.
  assert.ok((await page.locator('#harness-install-inline').textContent()).includes('without a yes, nothing starts'));
  const pentagiSteps = await page.locator('#harness-install-inline .install-steps').textContent();
  for (const words of ["Yougori asks which harness, with PentAGI already selected, then which model, then PentAGI's own questions.", 'it asks what PentAGI may use: a folder for the report (copied in; the report comes back only after your review), and CPU and memory. If you give the source code, the report comes back to its folder instead.']) assert.ok(pentagiSteps.includes(words), pentagiSteps);
  // Yougori asks a security harness nothing about what its VM may reach: only the target and this
  // inference, as its note, its About panel and its requirements say. The requirements sit beside the
  // source setup, which holds the VM to the target as the Yougori command does (solver.py, held_to_target).
  const pentagiPage = await page.locator('#view').textContent();
  assert.ok(pentagiPage.includes('The VM reaches only the target and this inference. Yougori does not offer other sites or the whole internet.'), pentagiPage);
  for (const words of ['what it can reach', 'sites you choose', 'unless you choose more', 'may also reach', 'With the Yougori command']) assert.equal(pentagiPage.includes(words), false, words);
  assert.equal(await page.locator('.detail-side .small-banner').textContent(), `Blue terminal, connected to ${new URL(url).host}. The VM reaches only the target and this inference.`);
  assert.equal(await page.locator('#harness-install-inline .install-details .hint').textContent(), 'Yougori manages the private runtime on Windows. The VM reaches only the target and this server. Linux source requires Python and a supported Yougori VM backend. macOS is not supported yet.');
  const againPentagi = await page.locator('#again-hint').textContent();
  for (const words of ["PentAGI's own answer: --set target=practice (the practice app) or --set target=URL --set permission=yes (a target you may test).", 'Add --workspace "C:\\path\\to\\project" for the source code.']) assert.ok(againPentagi.includes(words), againPentagi);
  // The browser's Back returns to PentAGI on Yougori's page; Forward opens it again.
  await page.goBack();
  await page.locator('#section-title', { hasText: 'Yougori' }).waitFor();
  assert.equal(await page.evaluate(() => scrollY), pentagiPlace);
  assert.equal(await page.evaluate(() => document.activeElement?.dataset.inside), 'pentagi');
  await page.goForward();
  await page.locator('#section-title', { hasText: 'PentAGI' }).waitFor();
  // A shared link to a harness opens its page; ← Yougori opens Yougori's page with that harness in view,
  // and there ← Main page opens the main page at its top.
  const shared = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  await shared.goto(url + '/#harnesses/pentagi');
  await shared.locator('#harness-install-inline').waitFor();
  assert.equal(await shared.locator('#launch-code').textContent(), `yougori inference run pentagi --server "${url}"`);
  await shared.getByRole('button', { name: '← Yougori' }).click();
  await shared.locator('#section-title', { hasText: 'Yougori' }).waitFor();
  assert.equal(new URL(shared.url()).hash, '#harnesses/yougori');
  assert.equal(await shared.evaluate(() => document.activeElement?.dataset.inside), 'pentagi');
  const inView = await shared.locator('[data-inside="pentagi"]').boundingBox();
  assert.ok(inView.y > 0 && inView.y + inView.height < 1000, 'PentAGI is in view');
  await shared.getByRole('button', { name: '← Main page' }).click();
  await shared.locator('#harnesses-list').waitFor();
  assert.equal(new URL(shared.url()).hash, '#harnesses');
  assert.equal(await shared.evaluate(() => scrollY), 0);
  await shared.close();
  // Shannon needs its source code: Yougori then asks for no other folder, and the report comes back to the
  // source code's. SWE-agent needs the issue to fix.
  const other = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
  await other.goto(url + '/#harnesses/shannon');
  await other.locator('#again-hint').waitFor();
  const shannonSteps = await other.locator('#harness-install-inline .install-steps').textContent();
  assert.ok(shannonSteps.includes('it asks what Shannon may use: CPU and memory. The source code is copied in, and the report comes back to its folder only after your review.'), shannonSteps);
  assert.equal(shannonSteps.includes('a folder for the report'), false);
  assert.equal(shannonSteps.includes('what it can reach'), false, shannonSteps);
  const againShannon = await other.locator('#again-hint').textContent();
  assert.ok(againShannon.includes(`Shannon's own answers: --set target=practice (the practice app) or --set target=URL --set permission=yes (a target you may test), and --workspace "C:\\path\\to\\project" (source code). The VM works on a copy`), againShannon);
  await other.goto(url + '/#harnesses/swe');
  await other.locator('#section-title', { hasText: 'SWE-agent' }).waitFor();
  const againSwe = await other.locator('#again-hint').textContent();
  assert.ok(againSwe.includes(`SWE-agent's own answer: --set issue="..." (the issue to fix). Add --workspace "C:\\path\\to\\project" to name the project folder.`), againSwe);
  // A harness whose VM image is not published yet is in preparation: its row says why and copies no
  // command, its own page says so, and Yougori stays ready with the others.
  assert.equal(await fixture('unpublish strix aider'), 'unpublished');
  await other.goto(url + '/');
  await other.locator('#harnesses-list .entry').waitFor();
  assert.equal(await other.locator('#harnesses-list .tag').textContent(), 'Ready');
  await other.locator('[data-harness="yougori"]').click();
  await other.locator('#inside-strix').waitFor();
  for (const id of ['strix', 'aider']) {
    const row = other.locator('#inside-' + id);
    assert.equal(await row.locator('.tag').textContent(), 'In preparation');
    assert.equal(await row.locator('.entry-meta').textContent(), "The administrator has not published this harness's Sandbox VM image yet.");
    assert.equal(await row.locator('[data-copy]').count(), 0);
  }
  assert.equal(await other.locator('#inside-pi .tag').textContent(), 'Ready');
  assert.equal(await other.locator('#inside-pi [data-copy]').count(), 1);
  assert.equal(await other.locator('#guide-code').count(), 1);
  await other.locator('[data-inside="strix"]').click();
  await other.locator('#section-title', { hasText: 'Strix' }).waitFor();
  assert.deepEqual(await other.locator('#harness-install-inline .panel-heading h2').allTextContents(), ['In preparation']);
  assert.equal(await other.locator('#harness-install-inline .small-banner').textContent(), "The administrator has not published this harness's Sandbox VM image yet.");
  assert.equal(await other.locator('#guide-code, #launch-code, [data-copy]').count(), 0);
  // With no image published, nothing here can start: Yougori is in preparation too, and its page says why
  // for each harness inside it.
  assert.equal(await fixture('unpublish'), 'unpublished');
  await other.goto(url + '/');
  await other.locator('#harnesses-list .entry').waitFor();
  assert.equal(await other.locator('#harnesses-list .tag').textContent(), 'In preparation');
  await other.locator('[data-harness="yougori"]').click();
  await other.locator('#inside-pi').waitFor();
  assert.deepEqual(await other.locator('#harness-install-inline .panel-heading h2').allTextContents(), ['In preparation', 'Coding', 'Cyber Coding']);
  assert.equal(await other.locator('#harness-install-inline .tag.ready, #harness-install-inline [data-copy], #guide-code, #launch-code').count(), 0);
  assert.equal(await other.locator('#harness-install-inline .entry-meta', { hasText: "has not published this harness's Sandbox VM image" }).count(), 21);
  assert.ok((await other.locator('.detail-side .facts').textContent()).includes('In preparation'));
  assert.equal(await fixture('publish'), 'published');
  await other.close();
  assert.equal(await page.locator('dialog[open]').count(), 0);
  assert.equal(await page.locator('#harness-download').count(), 1);
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run pentagi --server "${url}"`);
  // Back to Yougori's page, then to the main page.
  await page.goBack();
  await page.locator('#section-title', { hasText: 'Yougori' }).waitFor();
  await page.goBack();
  await page.locator('#harnesses-list .entry').last().waitFor();
  await page.locator('.quick').getByRole('button', { name: 'Switch to dark mode' }).click();
  await page.reload();
  await page.locator('.quick').getByRole('button', { name: 'Switch to light mode' }).waitFor();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.locator('.quick').getByRole('button', { name: 'Switch to light mode' }).click();
  // An old link to Models opens the same main page.
  await page.goto(url + '/#models');
  await page.locator('#models-list .model-id').last().waitFor();
  assert.equal(await page.locator('#models-list .entry').count(), 2);
  assert.equal(await page.locator('#harnesses-list .entry').count(), 1);
  assert.equal(await page.locator('#auth').isVisible(), false);
  // Phones stack the columns at full width, the tools first.
  await page.setViewportSize({ width: 390, height: 900 });
  const phoneTools = await page.locator('#harnesses-list').boundingBox(), phoneModels = await page.locator('#models-list').boundingBox();
  assert.ok(phoneModels.y > phoneTools.y + phoneTools.height && phoneModels.width === phoneTools.width && phoneTools.width > 340, 'Phones stack the columns');
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'The main page overflows on phones');
  // Yougori's page and a harness's own page fit phones too.
  for (const harness of ['yougori', 'strix']) {
    await page.goto(url + '/#harnesses/' + harness);
    await page.locator('#launch-code').waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `The page of ${harness} overflows on phones`);
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(url + '/#keys');
  await page.locator('#auth-title').waitFor();
  assert.equal(await page.locator('#workspace').isVisible(), false);
  await page.locator('#brand').click();
  await page.locator('#harnesses-list').waitFor();
  await page.locator('#signin-link').click();
  await page.getByLabel('Email', { exact: true }).fill('admin@example.invalid');
  await page.getByLabel('Password', { exact: true }).fill('disposable-test-password');
  await page.locator('#auth-submit').click();
  // The administrator's first sign-in asks for the main page and the harnesses offered, all ticked: the
  // harnesses inside Yougori, with no box for Yougori itself.
  await page.getByRole('heading', { name: 'Set up your inference', exact: true }).waitFor();
  assert.equal(await page.locator('#choices-form [name="home"]:checked').getAttribute('value'), 'harnesses');
  assert.equal(await page.locator('#choice-count').textContent(), '21 of 21 harnesses offered');
  assert.equal(await page.locator('#choices-form [name="harness"][value="yougori"]').count(), 0);
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await page.getByRole('button', { name: 'Save and continue ↗' }).click();
  await page.getByText('Offer at least one harness, or choose another main page.', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Select all', exact: true }).click();
  await page.getByLabel(/^Aider/).uncheck();
  assert.equal(await page.locator('#choice-count').textContent(), '20 of 21 harnesses offered');
  // Yougori is offered with the harnesses inside it.
  const saving = page.waitForRequest(request => request.url() === url + '/api/admin/choices');
  await page.getByRole('button', { name: 'Save and continue ↗' }).click();
  const sent = JSON.parse((await saving).postData());
  assert.equal(sent.harnesses.length, 21);
  assert.ok(sent.harnesses.includes('yougori') && !sent.harnesses.includes('aider'), JSON.stringify(sent));
  await page.locator('#harnesses-list .entry').last().waitFor();
  assert.equal(await page.locator('#harnesses-list .entry').count(), 1);
  assert.equal(await page.locator('#harnesses-list .entry-meta').textContent(), '20 harnesses inside · 15 Coding · 5 Cyber Coding');
  const offered = Object.fromEntries((await (await page.request.get(url + '/api/harnesses')).json()).harnesses.map(h => [h.id, h.offered]));
  assert.deepEqual([offered.yougori, offered.aider, offered.codex], [true, false, true]);
  assert.equal((await page.request.get(url + '/install/aider.ps1')).status(), 404);
  // Yougori's page lists only the harnesses offered; an old link to another says it is not offered.
  await page.locator('[data-harness="yougori"]').click();
  await page.locator('[data-inside]').first().waitFor();
  assert.equal(await page.locator('[data-inside]').count(), 20);
  assert.equal(await page.locator('[data-inside="aider"]').count(), 0);
  await page.locator('[data-inside="codex"]').click();
  await page.getByText('Requirements and source',{exact:true}).click();
  await page.locator('#harness-download').waitFor();
  assert.equal(await page.locator('#harness-install-inline .install-details .hint').textContent(), codingRequirements);
  assert.equal(await page.locator('#launch-code').textContent(), `yougori inference run codex --server "${url}"`);
  await page.goto(url + '/#harnesses/aider');
  await page.locator('#view').getByText('This tool is not offered on this inference.', { exact: true }).waitFor();
  await page.getByRole('link', { name: '← Main page' }).click();
  await page.locator('#models-list .model-id').last().waitFor();
  assert.equal(await page.locator('#models-list .entry').count(), 2);
  // Administrators connect a model server from the Models column.
  assert.equal(await page.locator('#models-column #connect-model').textContent(), 'Connect a model server →');
  await page.getByRole('button', { name: /^Uncensored/ }).click();
  assert.equal(await page.locator('#models-list .entry').count(), 0);
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
  assert.equal(await page.locator('#models-list .entry').count(), 1);
  await page.getByRole('button', { name: /^Censored/ }).click();
  assert.equal(await page.locator('#models-list .entry').count(), 1);
  await page.getByRole('button', { name: /^Censored/ }).click();
  assert.equal(await page.locator('#models-list .entry').count(), 2);
  // API keys open as a dropdown beside the title, not as a page of their own.
  assert.equal(await page.locator('#nav a[href="#keys"]').count(), 0);
  await page.locator('#keys-button').click();
  await page.getByLabel('Key name').fill('Browser tool');
  await page.locator('#key-access').selectOption('selected');
  await page.locator('#scope-list input').first().check();
  await page.getByRole('button', { name: 'Create key ↗' }).click();
  await page.getByRole('heading', { name: 'Save your API key' }).waitFor();
  const key = await page.locator('#keys-panel .secret').textContent();
  assert.match(key, /^is_/);
  const catalog = await (await fetch(url + '/v1/models', { headers: { Authorization: 'Bearer ' + key } })).json();
  assert.equal(catalog.data.length, 1);
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.getByRole('button', { name: 'Done', exact: true }).click();
  await page.locator('#keys-panel').getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
  await page.locator('#keys-panel .key-list', { hasText: 'Revoked' }).waitFor();
  // Confirming in the dialog leaves the dropdown open; Escape then closes it.
  assert.equal(await page.locator('#keys-panel').isVisible(), true);
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#keys-panel').isVisible(), false);
  assert.equal((await fetch(url + '/v1/models', { headers: { Authorization: 'Bearer ' + key } })).status, 401);
  await page.locator('#nav a[href="#admin"]').click();
  await page.getByRole('heading', { name: 'Rent a cloud GPU', exact: true }).waitFor();
  await page.getByRole('heading', { name: 'Local GPUs', exact: true }).waitFor();
  assert.equal(await page.locator('#compute-setup input[name="url"], #compute-setup select[name="place"]').count(), 0);
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.getByRole('heading', {name:'Sandboxes', exact:true}).waitFor();
  await page.getByRole('heading', {name:'Crypto payments', exact:true}).waitFor();
  await page.getByRole('heading', {name:'Media pricing and storage', exact:true}).waitFor();
  await page.getByRole('heading', {name:'Subscriptions', exact:true}).waitFor();
  // Admin is one column, in this order, with nothing folded away.
  const sections = await page.locator('#admin-grid .admin-section').evaluateAll(nodes => nodes.map(node => {
    const r = node.getBoundingClientRect(); return {id: node.id, x: r.x, y: r.y};
  }));
  assert.deepEqual(sections.map(s => s.id), ['admin-local', 'admin-rent', 'admin-servers', 'admin-sandboxes', 'admin-choices', 'admin-identity', 'admin-people', 'admin-prices', 'admin-subscriptions', 'admin-media', 'admin-payments', 'admin-activity']);
  assert.ok(sections.every((s, i) => s.x === sections[0].x && (i === 0 || s.y > sections[i - 1].y)));
  assert.equal(await page.locator('#admin-grid details').count(), 0);
  // The left edge is the PrompX harness's ruler, one mark per section, in place of the scrollbar
  // (built once every section has loaded).
  await page.waitForFunction(() => document.querySelectorAll('.rail .rail-mark').length === 12);
  // Subscriptions: switched on, the administrator offers plans with their models and a limit that
  // resets every 5 hours or every week.
  assert.equal(await page.locator('#subscriptions-on').isChecked(), true);
  const offer = page.locator('#admin-subscriptions form:not([data-plan])');
  await offer.getByLabel('Name').fill('Starter');
  await offer.getByLabel('USD per 30 days').fill('0');
  await offer.getByLabel('Tokens per window, millions').fill('1');
  await offer.getByLabel('Limit resets').selectOption('week');
  await offer.getByRole('checkbox', {name:'two', exact:true}).uncheck();
  await offer.getByRole('button', {name:'Add subscription', exact:true}).click();
  await page.getByText('Subscription saved.', {exact:true}).waitFor();
  assert.equal(await page.locator('#admin-subscriptions form[data-plan] input[name="name"]').inputValue(), 'Starter');
  assert.equal(await page.locator('#admin-subscriptions form[data-plan] select[name="resets"]').inputValue(), 'week');
  assert.deepEqual(await page.locator('#admin-subscriptions form[data-plan] input[name="model"]:checked').evaluateAll(boxes => boxes.map(b => b.value)), ['test/one']);
  await page.locator('#admin-subscriptions').getByText('No one is subscribed yet.', {exact:true}).waitFor();
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
  // Local GPUs starts with the models computers may run: none yet, then one added and removed.
  await page.locator('#compute-offered-list', { hasText: 'No models yet' }).waitFor();
  await page.locator('#compute-offered-add input[name="model"]').fill('not a model');
  await page.getByRole('button', { name: 'Add model', exact: true }).click();
  await page.locator('#compute-offered-add .error').filter({ hasText: 'Hugging Face model repository' }).waitFor();
  // Above the field: what it takes, and that Yougori picks a GGUF repository's file itself.
  const hint = page.locator('#compute-offered-add .model-hint');
  await hint.filter({ hasText: 'a UD-Q4_K_M file counts as Q4_K_M' }).waitFor();
  const placed = await page.evaluate(() => [document.querySelector('#compute-offered-add .model-hint').getBoundingClientRect().bottom,
    document.querySelector('#compute-offered-add input[name="model"]').getBoundingClientRect().top]);
  assert.ok(placed[0] <= placed[1], JSON.stringify(placed));
  // A reference pasted from another tool is told what to change.
  await page.locator('#compute-offered-add input[name="model"]').fill('unsloth/gemma-4-26B-A4B-it-GGUF:UD-Q4_K_M');
  await page.getByRole('button', { name: 'Add model', exact: true }).click();
  await page.locator('#compute-offered-add .error').filter({ hasText: "without the ending after ':'" }).waitFor();
  await page.locator('#compute-offered-add input[name="model"]').fill('Qwen/Qwen3-8B');
  await page.getByRole('button', { name: 'Add model', exact: true }).click();
  await page.locator('#compute-offered-list .source', { hasText: 'Qwen/Qwen3-8B' }).filter({ hasText: 'No computer runs it yet' }).waitFor();
  // Checked when added: what it needs from a GPU shows under it, and connecting computers get it too.
  await page.locator('#compute-offered-list .source', { hasText: 'Chat model · about 4 GB of GPU memory · Ampere (RTX 30, A100, A40) or newer' }).waitFor();
  const summary = 'Chat model · about 4 GB of GPU memory · Ampere (RTX 30, A100, A40) or newer';
  assert.deepEqual(await (await fetch(url + '/api/compute/models')).json(), { models: ['Qwen/Qwen3-8B'], most: 3, needs: { 'Qwen/Qwen3-8B': { gpu_gb: 4, compute: 8, summary } } });
  await page.locator('#compute-offered-list [data-remove-offered="Qwen/Qwen3-8B"]').click();
  await page.locator('#compute-offered-list', { hasText: 'No models yet' }).waitFor();
  assert.deepEqual((await (await fetch(url + '/api/compute/models')).json()).models, []);
  // Codes are optional: unticked, computers join at once, and the code box and password go away.
  const admission = page.locator('#compute-admission input[name="code"]');
  assert.equal(await admission.isChecked(), true);
  await admission.uncheck();
  await page.locator('#compute-admission-state', { hasText: 'joins at once, without a code' }).waitFor();
  await page.locator('#contributor-inspect').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#compute-password').isHidden(), true);
  assert.match(await page.locator('#compute-run-hint').textContent(), /It joins at once/);
  await admission.check();
  await page.locator('#contributor-inspect').waitFor();
  await page.locator('#compute-admission-state', { hasText: 'Each computer shows a code' }).waitFor();
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
  // Copy all, one per system, copies only the commands, with only that system's install command;
  // Post on X is one post for both: each install command under its system's name, then the start
  // and connect commands under "Both:".
  assert.deepEqual(await page.locator('#compute-share button').allTextContents(), ['Copy all for Windows', 'Copy all for Linux']);
  for (const [system, install] of [['Windows', steps[0][1]], ['Linux', steps[1][1]]]) {
    assert.equal(await page.locator(`#compute-copy-all-${system.toLowerCase()}`).getAttribute('data-copy'),
      [install, 'yougori app start', `yougori inference connect "${url}"`].join('\n'));
  }
  await page.locator('#compute-copy-all-linux').click();
  await page.waitForFunction(() => document.querySelector('#compute-copy-all-linux').textContent === 'Copied');
  assert.equal(await page.locator('#compute-copy-all-windows').textContent(), 'Copy all for Windows');
  assert.deepEqual(await page.locator('#compute-share a').allTextContents(), ['Post on X ↗']);
  const xPost = page.locator('#compute-post-x');
  const intent = new URL(await xPost.getAttribute('href'));
  assert.equal(intent.origin + intent.pathname, 'https://x.com/intent/post');
  assert.equal(intent.searchParams.get('text'), [`Windows:\n${steps[0][1]}`, `Linux:\n${steps[1][1]}`,
    `Both:\nyougori app start\nyougori inference connect "${url}"`].join('\n\n'));
  // X counts each link as 23 characters.
  assert.ok(intent.searchParams.get('text').replace(/https?:\/\/[^\s"]+/g, 'x'.repeat(23)).length <= 280);
  assert.equal(await xPost.getAttribute('target'), '_blank');
  assert.match(await xPost.getAttribute('rel'), /noopener/);
  // Renting happens right here, with the administrator's own RunPod or Vast.ai key: no computer
  // in between, and no Yougori on the website's server.
  await page.locator('#rent-direct').waitFor();
  assert.equal(await page.locator('#rent-here').isHidden(), true);
  assert.equal(await page.locator('#compute-website').isHidden(), true);
  assert.deepEqual(await page.locator('#rent-direct .rental-account button[type="submit"]').allTextContents(), ['Save RunPod key', 'Save Vast.ai key']);
  assert.deepEqual(await page.locator('#rent-direct [data-provider-state]').allTextContents(), ['Not connected.', 'Not connected.']);
  // The GPUs are looked up as soon as the section shows, before any key; this fixture's providers
  // answer nothing, so the page says so, and nothing can be rented.
  await page.locator('#rental-offer-list', { hasText: 'RunPod: The provider did not answer.' }).waitFor();
  await page.locator('#rental-offer-list', { hasText: 'Vast.ai: The provider did not answer.' }).waitFor();
  assert.equal(await page.locator('#rental-rent button[type="submit"]').isDisabled(), true);
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
  // Usage offers the plans with their models, never their tokens; subscribing pays from the balance
  // (nothing for this free plan).
  await page.locator('#subscriptions').getByText('$0 per 30 days · limit resets every week', {exact:true}).waitFor();
  await page.locator('#subscriptions').getByText('Models: one', {exact:true}).waitFor();
  assert.equal((await page.locator('#subscriptions').textContent()).includes('1M'), false);
  await page.locator('#subscriptions').getByRole('button', {name:'Subscribe', exact:true}).click();
  await page.getByRole('button', {name:'Confirm', exact:true}).click();
  await page.locator('#subscription-window').waitFor();
  assert.equal(await page.locator('#subscription-window').textContent(), "0% of this window's limit used. The limit resets every week; the window opens with your next request. Included: one.");
  assert.equal(await page.locator('#subscriptions [role="meter"]').getAttribute('aria-valuenow'), '0');
  assert.equal(await page.locator('#subscriptions').getByRole('button', {name:'Add 30 days', exact:true}).count(), 1);
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
  // Admin lists who is subscribed and can give them a fresh window.
  await page.locator('#admin-subscriptions').getByRole('button', {name:'Reset limit', exact:true}).click();
  await page.getByText('Limit reset: a fresh window starts with the next request.', {exact:true}).waitFor();
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
  // Admin keeps the same choices: the chosen main page is the first column, and the site's name opens it.
  const choices = page.locator('#admin-choices');
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 20);
  assert.equal(await choices.locator('[name="harness"][value="yougori"]').count(), 0);
  await choices.getByLabel(/^Models/).check();
  await choices.getByLabel(/^Aider/).check();
  await choices.getByRole('button', { name: 'Save choices ↗' }).click();
  await page.getByText('Main page and harnesses saved.', { exact: true }).waitFor();
  assert.equal(await page.locator('#brand').getAttribute('href'), '#models');
  await page.goto(url);
  await page.locator('#models-list .model-id').last().waitFor();
  assert.equal(await page.locator('.overview > .column').first().getAttribute('id'), 'models-column');
  assert.equal(await page.locator('#nav a[aria-current="page"]').count(), 0);
  await page.goto(url + '/#admin');
  await choices.waitFor();
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 21);
  // With no harness offered, Yougori is not offered either, and the main page has no Harnesses column.
  await choices.getByRole('button', { name: 'Clear', exact: true }).click();
  const cleared = page.waitForResponse(response => response.url() === url + '/api/admin/choices');
  await choices.getByRole('button', { name: 'Save choices ↗' }).click();
  assert.equal((await cleared).status(), 200);
  assert.deepEqual(JSON.parse((await cleared).request().postData()).harnesses, []);
  assert.equal((await (await page.request.get(url + '/api/harnesses')).json()).harnesses.some(h => h.offered), false);
  await page.goto(url);
  await page.locator('#models-list .model-id').last().waitFor();
  assert.equal(await page.locator('#harnesses-column').isHidden(), true);
  await page.goto(url + '/#admin');
  await choices.waitFor();
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 0);
  // With one harness offered, Yougori holds it alone, in one group.
  await choices.getByLabel(/^Strix/).check();
  const single = page.waitForResponse(response => response.url() === url + '/api/admin/choices');
  await choices.getByRole('button', { name: 'Save choices ↗' }).click();
  assert.equal((await single).status(), 200);
  assert.deepEqual(JSON.parse((await single).request().postData()).harnesses, ['yougori', 'strix']);
  await page.goto(url);
  await page.locator('#harnesses-list .entry').waitFor();
  assert.equal(await page.locator('#harnesses-list .entry-meta').textContent(), '1 harness inside · 1 Cyber Coding');
  await page.locator('[data-harness="yougori"]').click();
  await page.locator('#inside-strix').waitFor();
  assert.deepEqual(await page.locator('#harness-install-inline .panel-heading h2').allTextContents(), ['Install and start', 'Open it again', 'Cyber Coding']);
  assert.equal(await page.locator('#group-security .panel-heading .hint').textContent(), '1 harness');
  assert.deepEqual(await page.locator('[data-inside]').evaluateAll(links => links.map(link => link.dataset.inside)), ['strix']);
  await page.goto(url + '/#admin');
  await choices.waitFor();
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 1);
  await choices.getByRole('button', { name: 'Select all', exact: true }).click();
  assert.equal(await choices.locator('[name="harness"]:checked').count(), 21);
  await choices.getByLabel(/^Harnesses/).check();
  await choices.getByRole('button', { name: 'Save choices ↗' }).click();
  await page.getByText('Main page and harnesses saved.', { exact: true }).waitFor();
  assert.equal(await page.locator('#brand').getAttribute('href'), '#harnesses');
  await page.getByLabel('Email address').fill('new-member@example.invalid');
  await page.getByRole('button', { name: 'Create invitation ↗' }).click();
  await page.locator('.secret').waitFor();
  const invitation = await page.locator('.secret').textContent();
  await page.keyboard.press('Escape');
  for (const width of [768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Admin overflows at ${width}px`);
    await page.locator('#brand').click();
    await page.locator('#models-list .model-id').last().waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `The main page overflows at ${width}px`);
    await page.getByRole('button', { name: 'Menu', exact: true }).click();
    await page.locator('#menu-links a[href="#admin"]').click();
    await page.locator('#branding-form').waitFor();
    assert.equal(await page.locator('#menu-toggle').getAttribute('aria-expanded'), 'false');
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
  // An old link to API keys opens the main page with the dropdown open.
  await page.goto(url + '/#keys');
  await page.getByRole('button', { name: 'Create key ↗' }).waitFor();
  assert.equal(await page.locator('#keys-button').getAttribute('aria-expanded'), 'true');
  // A deliberately rejected duplicate signup and a deliberately wrong computer code produce Chrome's normal HTTP error log.
  assert.deepEqual(errors.filter(error => !(error.includes('400') && (error.endsWith(url + '/api/signup') || error.endsWith(url + '/api/compute/pair/inspect') || error.endsWith(url + '/api/admin/compute/models') || error.endsWith(url + '/api/admin/rentals/offers')))), []);
  console.log('Browser flow passed: public signup/login on desktop and mobile, member/admin boundaries, guest-first catalogs, scoped key/revoke, branding, invitations, themes and responsive layouts.');
} finally {
  await browser?.close();
  child.stdin.end('\n');
  await stopped;
}
