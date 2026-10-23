// Runs the CLI contract test against the website's actual Hub server with disposable data.
// Usage from any directory: node scripts/test-hub-contract.mjs PATH/TO/YougoriWebsite
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawn } from 'node:child_process'

const website = process.argv[2]
if (!website) throw new Error('Usage: node scripts/test-hub-contract.mjs PATH/TO/YougoriWebsite')
const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const folder = join(repository, 'examples/hub/hello-site')
const { createMarket } = await import(pathToFileURL(join(resolve(website), 'server/market/index.mjs')))
const hex = bytes => createHash('sha256').update(bytes).digest('hex')
const market = createMarket({ file: ':memory:', env: { NODE_ENV: 'test' }, log: { error() {} } })
const now = market.ctx.sec()
// This token exists only in the in-memory fixture, never in a real account or credential store.
const token = 'ygs_contract_publisher_token'
market.ctx.db.run('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)', 'owner', 'owner@example.test', 'unused', now)
market.ctx.db.run('INSERT INTO sessions (id, token_hash, user_id, kind, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 's1', hex(token), 'owner', 'client', now, now, now + 86400)
market.ctx.db.meta('swarm.admin_user_id', 'owner')
const server = createServer((req, res) => {
  void market.handle(req, res).then(handled => {
    if (!handled) { res.writeHead(404); res.end() }
  }).catch(error => {
    console.error(error.message)
    if (!res.headersSent) res.writeHead(500)
    res.end()
  })
})

try {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const base = `http://127.0.0.1:${server.address().port}`
  const files = []
  const walk = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.isFile()) files.push([relative(folder, path).split(sep).join('/'), readFileSync(path)])
      else throw new Error(`The fixture must contain only ordinary files: ${path}`)
    }
  }
  walk(folder)
  const call = async (path, body) => {
    const response = await fetch(base + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    const value = await response.json()
    if (!response.ok) throw new Error(`${path}: ${value.error}`)
    return value
  }
  // The example uses plain top-level metadata. The CLI validates its entire YAML on download.
  const marker = files.find(([path]) => path === 'yougori-template.yaml')[1].toString()
  const field = name => {
    const match = new RegExp(`^${name}:\\s*(.+)$`, 'm').exec(marker)
    if (!match) throw new Error(`The fixture is missing ${name}`)
    return match[1].trim()
  }
  const manifest = { kind: 'template', name: field('name'), version: field('version'), license: field('license'), summary: field('summary') }
  const upload = await call('/api/hub/uploads', {
    publisher: 'yougori', ...manifest, manifest, title: field('title'), topics: ['website', 'starter'],
    review: { environments: [{ name: 'web' }] },
    files: files.map(([path, bytes]) => ({ path, bytes: bytes.length, sha256: hex(bytes) })),
  })
  await call(`/api/hub/uploads/${upload.upload.id}/files`, { files: files.map(([path, bytes]) => ({ path, content: bytes.toString('base64') })) })
  await call(`/api/hub/uploads/${upload.upload.id}/finish`, {})
  const child = spawn('cargo', ['test', '--manifest-path', 'cli/Cargo.toml', '--test', 'hub_contract', '--', '--ignored'], {
    cwd: repository, env: { ...process.env, YOUGORI_HUB_CONTRACT_URL: base }, stdio: 'inherit', windowsHide: true,
  })
  const [code, signal] = await once(child, 'exit')
  if (signal) console.error(`The contract test stopped with ${signal}`)
  process.exitCode = code ?? 1
} finally {
  server.closeAllConnections()
  await new Promise(resolve => server.close(resolve))
  market.close()
}
