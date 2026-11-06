// Browser approval against real HTTP/SQLite, without a manually created API key.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
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
  const post = async (path, body) => {
    const response = await fetch(url + path, {method:'POST', headers:{Origin:url, 'Content-Type':'application/json'}, body:JSON.stringify(body)});
    assert.ok(response.ok, path);
    return response.json();
  };
  const key = 'is_' + randomBytes(32).toString('base64url');
  const state = await post('/api/device/start', {harness:'pi', credential_hash:createHash('sha256').update(key).digest('hex')});
  browser = await chromium.launch({headless:true, channel:process.env.PLAYWRIGHT_CHANNEL || 'chrome', chromiumSandbox:true});
  const page = await browser.newPage({viewport:{width:390,height:900}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(url + '/#connect');
  await page.getByRole('heading', {name:'Welcome back'}).waitFor();
  await page.locator('#auth-toggle').click();
  await page.getByLabel('Email', {exact:true}).fill('device-user@example.invalid');
  await page.getByLabel('Password', {exact:true}).fill('disposable-test-password');
  await page.locator('#auth-submit').click();
  await page.getByLabel('Connection code').waitFor();
  await page.getByLabel('Connection code').fill(state.user_code.toLowerCase());
  await page.getByRole('button', {name:'Continue', exact:true}).click();
  await page.getByRole('heading', {name:'Connect Pi?'}).waitFor();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  assert.equal((await fetch(url + '/v1/models', {headers:{Authorization:'Bearer ' + key}})).status, 401);
  await page.getByRole('button', {name:'Allow connection'}).click();
  await page.getByRole('heading', {name:"You're connected"}).waitFor();
  assert.equal((await post('/api/device/poll', {device_code:state.device_code})).status, 'approved');
  assert.equal((await fetch(url + '/v1/models', {headers:{Authorization:'Bearer ' + key}})).status, 200);
  const keys = await (await page.request.get(url + '/api/keys')).json();
  assert.equal(keys.keys.length, 1);
  assert.equal(keys.keys[0].label, 'Harness: pi');
  assert.ok(!(await page.locator('body').textContent()).includes(key));
  assert.equal((await page.request.get(url + '/api/admin/overview')).status(), 403);
  const denied = await post('/api/device/start', {harness:'pi', credential_hash:randomBytes(32).toString('hex')});
  await page.reload();
  await page.getByLabel('Connection code').fill(denied.user_code);
  await page.getByRole('button', {name:'Continue', exact:true}).click();
  await page.getByRole('button', {name:'Deny',exact:true}).click();
  await page.getByRole('heading', {name:'Connection denied'}).waitFor();
  assert.equal((await post('/api/device/poll', {device_code:denied.device_code})).status, 'denied');
  assert.deepEqual(errors, []);
  console.log('Device browser flow passed: signup resumes approval, consent required, automatic member key, denial and mobile layout.');
} finally {
  await browser?.close();
  child.stdin.end('\n');
  await stopped;
}
