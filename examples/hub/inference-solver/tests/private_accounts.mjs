// Real private-mode HTTP/UI check; no screenshots or route interception.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';

const child = spawn('python', ['-I', '-B', fileURLToPath(new URL('./browser_fixture.py', import.meta.url)), 'private'], { stdio: ['pipe', 'pipe', 'inherit'] });
const stopped = new Promise(resolve => child.once('exit', resolve));
let browser;
try {
  const lines = createInterface({ input: child.stdout });
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Private preview startup timed out')), 20000);
    lines.once('line', line => { clearTimeout(timer); resolve(line); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Preview exited ${code}`)); });
  });
  browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', chromiumSandbox: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(url);
  await page.locator('#harnesses-list .entry').last().waitFor();
  assert.equal(await page.locator('#signup-link').isVisible(), false);
  await page.locator('#signin-link').click();
  await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
  assert.equal(await page.locator('#auth-toggle').isVisible(), false);
  assert.equal(await page.locator('#auth-invitation').isVisible(), true);
  const denied = await page.request.post(url + '/api/signup', {
    headers: { Origin: url }, data: { email: 'uninvited@example.invalid', password: 'disposable-test-password' },
  });
  assert.equal(denied.status(), 403);
  assert.match((await denied.json()).error.message, /invitation-only/);
  // A manually typed signup route offers only the invitation form.
  await page.goto(url + '/#signup');
  await page.getByLabel('Invitation code').waitFor();
  assert.equal(await page.getByLabel('Invitation code').getAttribute('required'), '');
  await page.setViewportSize({ width: 390, height: 900 });
  await page.locator('#menu-toggle').click();
  assert.equal(await page.locator('#menu-links a[href="#signup"]').count(), 0);
  await page.keyboard.press('Escape');
  await page.locator('#auth-toggle').click();
  await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
  await page.getByLabel('Email', { exact: true }).fill('admin@example.invalid');
  await page.getByLabel('Password', { exact: true }).fill('disposable-test-password');
  await page.locator('#auth-submit').click();
  await page.getByRole('heading', { name: 'Set up your inference', exact: true }).waitFor();
  assert.equal((await (await page.request.get(url + '/api/session')).json()).user.admin, 1);
  assert.deepEqual(errors, []);
  console.log('Private mode passed: no open signup on desktop/mobile, direct signup refused, invitations required, admin login preserved.');
} finally {
  await browser?.close();
  child.stdin.end('\n');
  await stopped;
}
