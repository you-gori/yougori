// Serve built frontend bytes to disposable native WebView2 tests. No screenshots.
import { createServer } from 'node:http'
import { readFile, stat } from 'node:fs/promises'
import { resolve, relative, isAbsolute, extname, sep } from 'node:path'

const [directory, requestedPort] = process.argv.slice(2)
if (!directory || !/^\d+$/.test(requestedPort ?? '') || Number(requestedPort) < 1 || Number(requestedPort) > 65535)
  throw new Error('Usage: node scripts/serve-native-test-frontend.mjs BUILT_DIRECTORY PORT')
const root = resolve(directory)
await stat(resolve(root, 'index.html'))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.wasm': 'application/wasm' }
const server = createServer(async (request, response) => {
  try {
    if (request.method !== 'GET') { response.writeHead(405); response.end(); return }
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname)
    const path = resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`)
    const inside = relative(root, path)
    if (!inside || isAbsolute(inside) || inside === '..' || inside.startsWith(`..${sep}`)) { response.writeHead(404); response.end(); return }
    const bytes = await readFile(path)
    response.writeHead(200, { 'Content-Type': mime[extname(path)] ?? 'application/octet-stream', 'Cache-Control': 'no-store', 'Content-Length': bytes.length })
    response.end(bytes)
  } catch { response.writeHead(404); response.end() }
})
server.listen(Number(requestedPort), '127.0.0.1', () => console.log(`Native test frontend: http://127.0.0.1:${requestedPort}`))
process.once('SIGTERM', () => server.close())
process.once('SIGINT', () => server.close())
