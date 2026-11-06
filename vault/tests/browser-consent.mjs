// Run: node --test vault/tests/browser-consent.mjs
// Isolated browser fixture: no actual vault, account, tunnel, or native approval.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { test } from 'node:test'
import { chromium } from 'playwright'

test('OAuth consent POST returns to the registered callback without leaking cookies or referrers', async () => {
  const source = readFileSync(new URL('../src/broker/oauth.rs', import.meta.url), 'utf8')
  const policy = source.match(/\("referrer-policy","([^"]+)"\)/)?.[1]
  assert.ok(policy, 'Use the actual broker response policy')
  const requests = []
  const callback = createServer((request, response) => {
    if (request.url.startsWith('/callback')) requests.push(request.headers)
    response.end('Returned')
  })
  await new Promise(resolve => callback.listen(0, '127.0.0.1', resolve))
  const callbackOrigin = `http://127.0.0.1:${callback.address().port}`
  const callbackUrl = `${callbackOrigin}/callback?code=fixture&state=private-fixture`
  const csp = source.match(/let policy = format!\("([^"]+)"\)/)?.[1]?.replace('{callback_origin}', callbackOrigin)
  assert.ok(csp, 'Use the actual consent redirect policy')
  const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_BROWSER_CHANNEL || 'msedge', chromiumSandbox: true })
  try {
    const context = await browser.newContext()
    const page = await context.newPage()
    await page.route('https://vault.example/**', async route => {
      if (route.request().method() === 'POST') {
        requests.push(await route.request().allHeaders())
        await route.fulfill({ status: 303, headers: { 'referrer-policy': policy, 'content-security-policy': csp, location: callbackUrl } })
      } else {
        await route.fulfill({ contentType: 'text/html', headers: {
          'referrer-policy': policy,
          'content-security-policy': csp,
          'set-cookie': '__Host-yougori-oauth=fixture; Path=/; Secure; HttpOnly; SameSite=Lax',
        }, body: '<form method="post" action="/oauth/authorize"><input type="hidden" name="ticket" value="fixture"><button>Continue on my PC</button></form>' })
      }
    })
    await page.goto('https://vault.example/oauth/authorize?state=private-fixture')
    await Promise.all([page.waitForURL(callbackUrl), page.getByRole('button').click()])
    assert.equal(requests[0].origin, 'https://vault.example')
    assert.equal(requests[0].cookie, '__Host-yougori-oauth=fixture')
    assert.equal(requests[1].referer, undefined)
    assert.equal(requests[1].cookie, undefined)
  } finally {
    await browser.close()
    await new Promise(resolve => callback.close(resolve))
  }
})
