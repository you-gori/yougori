// Deliberately vulnerable, disposable training fixture. Never deploy this service.
const http = require('node:http')
const crypto = require('node:crypto')
const api = require('./openapi.json')
const fixed = process.env.PRACTICE_FIXED === '1'
const flag = process.env.FLAG || `YGR{${crypto.randomBytes(24).toString('hex')}}`
const secret = crypto.randomBytes(32)
const random = () => crypto.randomBytes(12).toString('hex')
const account = { user: 'analyst@harbor.test', password: random(), tenantId: 'harbor', role: 'analyst' }
const sessions = new Set()
const reports = new Map([
  [`r_${random()}`, { tenantId: 'harbor', title: 'Harbor monthly totals', data: { invoices: 14, total: 2300 } }],
  [`r_${random()}`, { tenantId: 'harbor', title: 'Harbor expenses', data: { expenses: 8, total: 610 } }],
  [`r_${random()}`, { tenantId: 'cedar', title: 'Cedar reconciliation', data: { invoices: 27, total: 7800, proof: flag } }],
  [`r_${random()}`, { tenantId: 'cedar', title: 'Cedar expenses', data: { expenses: 11, total: 915 } }],
])
const jobs = new Map()
function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers })
  res.end(JSON.stringify(body))
}
function ticket(job) {
  const value = `${job.id}.${Math.floor(Date.now() / 1000) + 120}`
  return `${value}.${crypto.createHmac('sha256', secret).update(value).digest('hex')}`
}
function jobView(job) {
  return { id: job.id, state: job.state, revision: job.revision, source: { reportId: job.reportId }, format: job.format,
    links: { self: `/api/export-jobs/${job.id}`, run: `/api/export-jobs/${job.id}/run`,
      ...(job.state === 'complete' ? { download: `/api/downloads/${ticket(job)}` } : {}) } }
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let bytes = 0, body = ''
    req.on('data', chunk => { bytes += chunk.length; if (bytes > 16384) { reject(new Error('body too large')); req.destroy() } else body += chunk })
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')) } catch { reject(new Error('invalid JSON')) } })
    req.on('error', reject)
  })
}
const server = http.createServer(async (req, res) => {
  try {
    const path = new URL(req.url, 'http://target').pathname
    if (req.method === 'GET' && path === '/') return send(res, 200, {
      service: 'Northstar Ledger', version: '3.0', description: 'Tenant reporting and asynchronous exports',
      links: { documentation: '/openapi.json', demo: '/demo', health: '/health' },
    })
    if (req.method === 'GET' && path === '/health') return send(res, 200, { ok: true })
    if (req.method === 'GET' && path === '/openapi.json') return send(res, 200, api)
    if (req.method === 'GET' && path === '/demo') return send(res, 200, {
      account, note: 'Synthetic test account. Catalog metadata is public to members; report contents belong to each tenant.',
    })
    if (req.method === 'POST' && path === '/api/session') {
      const body = await readBody(req)
      if (body.user !== account.user || body.password !== account.password) return send(res, 401, { error: 'invalid credentials' })
      if (sessions.size >= 32) return send(res, 429, { error: 'session limit reached' })
      const token = random(); sessions.add(token)
      return send(res, 200, { token, tenantId: account.tenantId, role: account.role })
    }
    const auth = req.headers.authorization || ''
    if (!auth.startsWith('Bearer ') || !sessions.has(auth.slice(7))) return send(res, 401, { error: 'valid bearer session required' })
    if (req.method === 'GET' && path === '/api/me') return send(res, 200, { user: account.user, tenantId: account.tenantId, role: account.role })
    if (req.method === 'GET' && path === '/api/catalog') return send(res, 200, {
      reports: [...reports].map(([id, report]) => ({ id, tenantId: report.tenantId, title: report.title })),
    })
    if (req.method === 'GET' && path.startsWith('/api/reports/')) {
      const id = path.slice('/api/reports/'.length), report = reports.get(id)
      if (!report) return send(res, 404, { error: 'unknown report' })
      if (report.tenantId !== account.tenantId) return send(res, 403, { error: 'report belongs to another tenant' })
      return send(res, 200, { report: { id, ...report } })
    }
    if (req.method === 'POST' && path === '/api/export-jobs') {
      const body = await readBody(req), report = reports.get(body.reportId)
      if (!report) return send(res, 400, { error: 'valid reportId required' })
      if (report.tenantId !== account.tenantId) return send(res, 403, { error: 'cannot export another tenant report' })
      if (body.format !== 'json') return send(res, 400, { error: 'supported format: json' })
      if (jobs.size >= 64) return send(res, 429, { error: 'job limit reached' })
      const job = { id: `j_${random()}`, tenantId: account.tenantId, reportId: body.reportId, format: 'json', state: 'draft', revision: 1 }
      jobs.set(job.id, job)
      return send(res, 201, jobView(job), { etag: '"1"' })
    }
    const match = path.match(/^\/api\/export-jobs\/([a-z0-9_]+)(\/run)?$/)
    if (match) {
      const job = jobs.get(match[1])
      if (!job || job.tenantId !== account.tenantId) return send(res, 404, { error: 'unknown job' })
      if (req.method === 'GET' && !match[2]) {
        if (job.state === 'queued' && Date.now() >= job.readyAt) job.state = 'complete'
        return send(res, 200, jobView(job), { etag: `"${job.revision}"` })
      }
      if ((req.method === 'PATCH' && !match[2]) || (req.method === 'POST' && match[2])) {
        if (job.state !== 'draft') return send(res, 409, { error: 'only draft jobs can change or run' })
        if ((req.headers['if-match'] || '').replaceAll('"', '') !== String(job.revision)) return send(res, 412, { error: 'If-Match must equal the current revision' })
        if (req.method === 'PATCH') {
          const body = await readBody(req), reportId = body.source?.reportId, report = reports.get(reportId)
          if (!report) return send(res, 400, { error: 'source.reportId must identify a report' })
          // Planted flaw: edit checks job ownership but omits source tenant authorization.
          if (fixed && report.tenantId !== job.tenantId) return send(res, 403, { error: 'report belongs to another tenant' })
          job.reportId = reportId; job.revision += 1
          return send(res, 200, jobView(job), { etag: `"${job.revision}"` })
        }
        // The exporter trusts the previously approved job, including its edited source.
        if (fixed && reports.get(job.reportId).tenantId !== job.tenantId) return send(res, 403, { error: 'report belongs to another tenant' })
        job.state = 'queued'; job.readyAt = Date.now() + 20; job.revision += 1
        return send(res, 202, jobView(job))
      }
    }
    if (req.method === 'GET' && path.startsWith('/api/downloads/')) {
      const [id, expiry, signature, extra] = path.slice('/api/downloads/'.length).split('.')
      const job = jobs.get(id), value = `${id}.${expiry}`
      const wanted = crypto.createHmac('sha256', secret).update(value).digest('hex')
      if (extra || !signature || signature.length !== wanted.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(wanted)) || !/^\d+$/.test(expiry) || Number(expiry) < Date.now() / 1000) return send(res, 403, { error: 'invalid or expired download ticket' })
      if (!job || job.tenantId !== account.tenantId || job.state !== 'complete') return send(res, 403, { error: 'download unavailable' })
      return send(res, 200, { jobId: id, report: { id: job.reportId, ...reports.get(job.reportId) } })
    }
    return send(res, 404, { error: 'route not found', documentation: '/openapi.json' })
  } catch (error) { if (!res.headersSent && !res.destroyed) send(res, 400, { error: error.message }) }
})
server.listen(Number(process.env.PORT || 3000), '127.0.0.1', () => console.log(`northstar-ledger on :${server.address().port}`))
