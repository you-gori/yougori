// A disposable, in-memory copy of the website's Hub for runtime acceptance (scripts/acceptance/README.md),
// started as scripts/test-hub-contract.mjs starts one: nothing is published anywhere real. It
// publishes one tool with the review the CLI wrote for it, prints READY, and serves until stopped.
// Usage: node scripts/acceptance/hub-fixture.mjs WEBSITE_CHECKOUT PORT TOOL_FOLDER TOOL_REVIEW_JSON
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

const [website, port, folder, reviewFile] = process.argv.slice(2)
const { createMarket } = await import(pathToFileURL(join(resolve(website), 'server/market/index.mjs')))
const hex = bytes => createHash('sha256').update(bytes).digest('hex')
const market = createMarket({ file: ':memory:', env: { NODE_ENV: 'test' }, log: { error() {} } })
const now = market.ctx.sec()
const token = 'ygs_acceptance_publisher_token_only_in_memory'
market.ctx.db.run('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)', 'owner', 'owner@example.test', 'unused', now)
market.ctx.db.run('INSERT INTO sessions (id, token_hash, user_id, kind, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 's1', hex(token), 'owner', 'client', now, now, now + 86400)
market.ctx.db.meta('swarm.admin_user_id', 'owner')
const server = createServer((req, res) => {
  void market.handle(req, res).then(handled => { if (!handled) { res.writeHead(404); res.end() } })
    .catch(error => { console.error(error.message); if (!res.headersSent) res.writeHead(500); res.end() })
})
server.listen(Number(port), '127.0.0.1')
await once(server, 'listening')
const base = `http://127.0.0.1:${port}`
const call = async (path, body) => {
  const response = await fetch(base + path, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const value = await response.json()
  if (!response.ok) throw new Error(`${path}: ${value.error}`)
  return value
}
const files = []
const walk = directory => {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) walk(path)
    else files.push([relative(folder, path).split(sep).join('/'), readFileSync(path)])
  }
}
walk(folder)
const marker = files.find(([path]) => path === 'yougori-tool.yaml')[1].toString()
const field = name => new RegExp(`^${name}:\s*(.+)$`, "m").exec(marker)[1].trim()
const manifest = { kind: 'tool', name: field('name'), version: field('version'), license: field('license'), summary: field('summary') }
const review = JSON.parse(readFileSync(reviewFile, 'utf8'))
const upload = await call('/api/hub/uploads', {
  publisher: 'yougori', ...manifest, manifest, title: field('title'), topics: ['test'], review,
  files: files.map(([path, bytes]) => ({ path, bytes: bytes.length, sha256: hex(bytes) })),
})
await call(`/api/hub/uploads/${upload.upload.id}/files`, { files: files.map(([path, bytes]) => ({ path, content: bytes.toString('base64') })) })
await call(`/api/hub/uploads/${upload.upload.id}/finish`, {})
console.log(`READY ${base} yougori/${manifest.name}@${manifest.version}`)
process.on('SIGTERM', () => { server.close(); market.close(); process.exit(0) })
