import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
const child=spawn('python',['-I','-B',fileURLToPath(new URL('./control_browser_fixture.py',import.meta.url))],{stdio:['pipe','pipe','inherit']});
const stopped=new Promise(resolve=>child.once('exit',resolve));
let browser;
try {
  const lines=createInterface({input:child.stdout});
  const url=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Fixture timeout')),20000);lines.once('line',line=>{clearTimeout(timer);resolve(line);});});
  browser=await chromium.launch({headless:true,channel:process.env.PLAYWRIGHT_CHANNEL||'chrome',chromiumSandbox:true});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(url+'/#sandboxes');
  await page.getByText('4 CPU cores · 8 GB RAM',{exact:true}).waitFor();
  assert.equal(await page.locator('dialog[open]').count(),0);
  const order=await page.locator('#nav a').evaluateAll(nodes=>nodes.map(n=>n.textContent));
  assert.equal(order[order.indexOf('Models')+1],'Sandboxes');
  await page.getByRole('link',{name:'Sign in to create a sandbox',exact:true}).click();
  await page.getByLabel('Email',{exact:true}).fill('admin@example.invalid');await page.getByLabel('Password',{exact:true}).fill('disposable-test-password');
  await page.locator('#auth-submit').click();
  await page.goto(url+'/#admin');await page.getByRole('heading',{name:'Model pricing',exact:true}).waitFor();
  await page.locator('#model-price [name="input_usd"]').fill('0.25');await page.locator('#model-price [name="output_usd"]').fill('0.5');
  // Cached input follows the input price until it is set by hand.
  assert.equal(await page.locator('#model-price [name="cached_usd"]').inputValue(),'0.25');
  await page.locator('#model-price [name="cached_usd"]').fill('0.025');await page.locator('#model-price [name="input_usd"]').fill('0.3');
  assert.equal(await page.locator('#model-price [name="cached_usd"]').inputValue(),'0.025');
  await page.getByRole('button',{name:'Save model price',exact:true}).click();await page.getByText('Model token prices saved.',{exact:true}).waitFor();
  const priced=(await (await page.request.get(url+'/api/models')).json()).models.find(m=>m.price.input_microusd_per_million===300000);
  assert.deepEqual(priced.price,{input_microusd_per_million:300000,output_microusd_per_million:500000,cached_microusd_per_million:25000});
  await page.getByLabel('Invite as administrator').check();assert.equal(await page.getByLabel('Invite as administrator').isChecked(),true);
  const member=page.locator('#member-settings .source').filter({hasText:'operator@example.invalid'});
  await member.getByRole('button',{name:'Make administrator',exact:true}).click();
  await page.locator('#member-settings .source').filter({hasText:'operator@example.invalid'}).getByText('Administrator · Offline',{exact:true}).waitFor();
  const placement=await page.locator('#admin-grid').evaluate(root=>{
    const activity=root.querySelector('.activity-bottom').getBoundingClientRect();
    return [...root.querySelectorAll('.panel')].filter(p=>!p.classList.contains('activity-bottom')).every(p=>p.getBoundingClientRect().bottom<=activity.top+1);
  });assert.equal(placement,true,'Compute activity must follow all management panels');
  await page.goto(url+'/#usage');await page.getByRole('heading',{name:'Inference control panel',exact:true}).waitFor();
  await page.getByText('Fixture NVIDIA GPU',{exact:true}).waitFor();assert.ok(await page.locator('.usage-chart polyline').count()>=4);
  assert.ok((await page.locator('#control-gpus').textContent()).includes('65.0°C'));
  await page.getByRole('heading',{name:'Computers and model servers',exact:true}).waitFor();
  await page.getByRole('columnheader',{name:'Cached input',exact:true}).first().waitFor();
  assert.equal(await page.locator('dialog[open]').count(),0);
  for(const width of [768,390]) {
    await page.setViewportSize({width,height:900});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Control panel must fit narrow screens');
  }
  await page.goto(url+'/#sandboxes');await page.getByText('4 CPU cores · 8 GB RAM',{exact:true}).waitFor();
  await page.locator('.sandbox-start [name="cpu"]').fill('2');await page.locator('.sandbox-start [name="memory_gb"]').fill('4');
  await page.getByRole('button',{name:'Create sandbox',exact:true}).click();
  await page.getByText('2 cores · 4 GB RAM · queued',{exact:true}).waitFor();
  await page.getByText('2 cores · 4 GB RAM · 1 slots free',{exact:true}).waitFor();
  await page.goto(url+'/#usage');await page.getByRole('heading',{name:'Sandbox VMs',exact:true}).waitFor();
  await page.getByRole('cell',{name:'2 cores',exact:true}).waitFor();
  await page.getByRole('cell',{name:'4 GB',exact:true}).waitFor();
  assert.equal(await page.locator('#control-totals .metric').filter({hasText:'Queued sandboxes'}).locator('strong').textContent(),'1');
  assert.equal(await page.locator('#control-totals .metric').filter({hasText:'Running sandboxes'}).locator('strong').textContent(),'0');
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  assert.deepEqual(errors,[]);
  console.log('CONTROL_BROWSER_OK: contributed capacity, queued VM, token prices, admin promotion, charts, compact layout and mobile. Hardware and VM execution are fixtures.');
} finally {await browser?.close();child.stdin.end();await stopped;}
