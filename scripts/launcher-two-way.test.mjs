import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, symlinkSync, statSync, lstatSync, renameSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
const require = createRequire(import.meta.url)
const create = require('../cli/src/launcher/assets/two-way.cjs')
const digest = data => createHash('sha256').update(data).digest('hex')
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'yougori-two-way-'))
  const remote = create(root)
  t.after(() => { remote.abort(); rmSync(root, { recursive: true, force: true }) })
  return { root, call: r => remote.request(r) }
}

test('prototype-named files keep their checksums and directory failure diagnostics', t => {
  const { root, call } = fixture(t)
  for (const name of ['__proto__', 'constructor', 'toString']) writeFileSync(join(root, name), `contents of ${name}`)
  const reply = JSON.parse(JSON.stringify(call({ op: 'hashes', paths: ['__proto__', 'constructor', 'toString', 'missing'], skipLinks: true })))
  for (const name of ['__proto__', 'constructor', 'toString']) assert.equal(reply.hashes[name], digest(`contents of ${name}`))
  assert.equal(reply.hashes.missing, null)
  rmSync(join(root, '__proto__'))
  mkdirSync(join(root, '__proto__'))
  writeFileSync(join(root, '__proto__', 'keep.txt'), 'keep this concurrent addition')
  const removal = JSON.parse(JSON.stringify(call({ op: 'directories', create: false, paths: ['__proto__'] })))
  assert.equal(typeof removal.errors.__proto__, 'string')
  assert.equal(readFileSync(join(root, '__proto__', 'keep.txt'), 'utf8'), 'keep this concurrent addition')
})

test('replacing an upload directory with a link cannot redirect chunks or staging cleanup', t => {
  const { root, call } = fixture(t)
  const outside = mkdtempSync(join(tmpdir(), 'yougori-upload-outside-'))
  t.after(() => rmSync(outside, { recursive: true, force: true }))
  mkdirSync(join(root, 'nested'))
  call({ op: 'begin', path: 'nested/file.bin', expected: null })
  const temporary = readdirSync(join(root, 'nested'))[0]
  rmSync(join(root, 'nested'), { recursive: true })
  symlinkSync(outside, join(root, 'nested'), process.platform === 'win32' ? 'junction' : 'dir')
  writeFileSync(join(outside, temporary), 'unrelated private file')
  assert.throws(() => call({ op: 'chunk', data: Buffer.from('incoming').toString('base64') }), /Symlink/)
  call({ op: 'abort' })
  assert.equal(readFileSync(join(outside, temporary), 'utf8'), 'unrelated private file')
})

test('SQLite batch cancellation cannot remove a file through a replaced parent directory', t => {
  const { root, call } = fixture(t)
  const outside = mkdtempSync(join(tmpdir(), 'yougori-sqlite-outside-'))
  t.after(() => rmSync(outside, { recursive: true, force: true }))
  mkdirSync(join(root, 'nested'))
  call({ op: 'sqlite-create', path: 'nested/data.db', schema: [{ sql: 'CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT)' }] })
  call({ op: 'sqlite-stage-batch', path: 'nested/data.db', operations: [{ key: JSON.stringify(['records', ['new']]), expected: null, row: ['new', 'pending'] }] })
  const temporary = readdirSync(join(root, 'nested')).find(name => name.startsWith('.yougori-sync-sqlite-'))
  assert.ok(temporary)
  try { renameSync(join(root, 'nested'), join(root, 'moved')) }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) { t.skip('Windows SQLite handle prevents parent rename; Linux exercises the replacement'); return }
    throw error
  }
  symlinkSync(outside, join(root, 'nested'), process.platform === 'win32' ? 'junction' : 'dir')
  writeFileSync(join(outside, temporary), 'unrelated private file')
  call({ op: 'sqlite-abort' })
  assert.equal(readFileSync(join(outside, temporary), 'utf8'), 'unrelated private file')
})
test('listing an open WAL database preserves SQLite locks and commits stay visible to fresh app connections', t => {
  const {root,call} = fixture(t)
  const file=join(root,'records.sqlite')
  const db=new DatabaseSync(file)
  db.exec("PRAGMA journal_mode=WAL; CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT); INSERT INTO records VALUES ('base','old')")
  db.close()
  const app = sql => {
    const result=spawnSync(process.execPath,['--no-warnings','-e',"const d=new(require('node:sqlite').DatabaseSync)(process.argv[1]); const q=process.argv[2]; if(q.startsWith('SELECT')) console.log(JSON.stringify(d.prepare(q).all())); else d.exec(q); d.close()",file,sql],{encoding:'utf8',windowsHide:true})
    assert.equal(result.status,0,result.stderr)
    return result.stdout.trim()
  }
  call({op:'sqlite-info',path:'records.sqlite'})
  app("UPDATE records SET value='from app' WHERE id='base'")
  const inventory=call({op:'sqlite-scan',path:'records.sqlite',offset:0})
  assert.ok(existsSync(file+'-wal'))
  // Header probes must not open/close DB or SHM descriptors in the SQL process.
  const listing=call({op:'tree',cursor:null,offset:0,prune:[]})
  assert.equal(listing.entries.find(e=>e.path==='records.sqlite').kind,'sqlite')
  assert.ok(app("SELECT value FROM records WHERE id='base'").includes('from app'))
  assert.ok(existsSync(file+'-wal'),'another app unlinked the sync helper’s open WAL')
  const [key,expected]=inventory.entries[0]
  call({op:'sqlite-stage-batch',path:'records.sqlite',operations:[{key,expected,row:['base','synced commit']}]})
  assert.equal(call({op:'sqlite-apply',path:'records.sqlite'}).count,1)
  assert.ok(app("SELECT value FROM records WHERE id='base'").includes('synced commit'))
})

test('ordinary directory replacement preserves unrelated files during upload and cancellation', t => {
  const { root, call } = fixture(t)
  mkdirSync(join(root, 'nested'))
  call({ op: 'begin', path: 'nested/file.bin', expected: null })
  call({ op: 'chunk', data: Buffer.from('original staging').toString('base64') })
  const temporary = readdirSync(join(root, 'nested'))[0]
  try { renameSync(join(root, 'nested'), join(root, 'moved')) }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) { t.skip('Windows upload handle prevents directory replacement'); return }
    throw error
  }
  mkdirSync(join(root, 'nested'))
  writeFileSync(join(root, 'nested', temporary), 'unrelated private file')
  assert.throws(() => call({ op: 'chunk', data: Buffer.from('incoming').toString('base64') }), /staging location changed/)
  assert.throws(() => call({ op: 'commit', hash: digest('unrelated private file') }), /staging location changed/)
  call({ op: 'abort' })
  assert.equal(readFileSync(join(root, 'nested', temporary), 'utf8'), 'unrelated private file')
  assert.equal(readFileSync(join(root, 'moved', temporary), 'utf8'), 'original staging')
  assert.equal(existsSync(join(root, 'nested', 'file.bin')), false)
})

test('replacing just the staging file cannot redirect an upload or its cleanup', t => {
  const { root, call } = fixture(t)
  call({ op: 'begin', path: 'file.bin', expected: null })
  call({ op: 'chunk', data: Buffer.from('original staging').toString('base64') })
  const temporary = readdirSync(root)[0]
  try { renameSync(join(root, temporary), join(root, 'moved')) }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) { t.skip('Windows upload handle prevents staging replacement'); return }
    throw error
  }
  writeFileSync(join(root, temporary), 'unrelated private file')
  assert.throws(() => call({ op: 'chunk', data: Buffer.from('incoming').toString('base64') }), /staging location changed/)
  assert.throws(() => call({ op: 'commit', hash: digest('unrelated private file') }), /staging location changed/)
  call({ op: 'abort' })
  assert.equal(readFileSync(join(root, temporary), 'utf8'), 'unrelated private file')
  assert.equal(readFileSync(join(root, 'moved'), 'utf8'), 'original staging')
})

test('ordinary parent replacement cannot redirect SQLite cancellation', t => {
  const { root, call } = fixture(t)
  mkdirSync(join(root, 'nested'))
  call({ op: 'sqlite-create', path: 'nested/data.db', schema: [{ sql: 'CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT)' }] })
  call({ op: 'sqlite-stage-batch', path: 'nested/data.db', operations: [{ key: JSON.stringify(['records', ['new']]), expected: null, row: ['new', 'pending'] }] })
  const temporary = readdirSync(join(root, 'nested')).find(name => name.startsWith('.yougori-sync-sqlite-'))
  try { renameSync(join(root, 'nested'), join(root, 'moved')) }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) { t.skip('Windows SQLite handle prevents parent replacement'); return }
    throw error
  }
  mkdirSync(join(root, 'nested'))
  writeFileSync(join(root, 'nested', temporary), 'unrelated private file')
  call({ op: 'sqlite-abort' })
  assert.equal(readFileSync(join(root, 'nested', temporary), 'utf8'), 'unrelated private file')
  assert.ok(existsSync(join(root, 'moved', temporary)))
})

test('SQLite staging replacement cannot alter an unrelated file or commit substituted records', t => {
  const { root, call } = fixture(t)
  call({ op: 'sqlite-create', path: 'data.db', schema: [{ sql: 'CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT)' }] })
  const operation = { key: JSON.stringify(['records', ['new']]), expected: null, row: ['new', 'pending'] }
  call({ op: 'sqlite-stage-batch', path: 'data.db', operations: [operation] })
  const temporary = readdirSync(root).find(name => name.startsWith('.yougori-sync-sqlite-'))
  try { renameSync(join(root, temporary), join(root, 'moved')) }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) { t.skip('Windows staging handle prevents replacement'); return }
    throw error
  }
  writeFileSync(join(root, temporary), 'unrelated private file')
  assert.throws(() => call({ op: 'sqlite-apply', path: 'data.db' }), /staging location changed/)
  assert.throws(() => call({ op: 'sqlite-stage-batch', path: 'data.db', operations: [operation] }), /staging location changed/)
  call({ op: 'sqlite-abort' })
  assert.equal(readFileSync(join(root, temporary), 'utf8'), 'unrelated private file')
  assert.deepEqual(call({ op: 'sqlite-scan', path: 'data.db' }).entries, [])
})
test('two-way transfers binary files in bounded chunks and preserves the old file until commit', t => {
  const {root, call} = fixture(t)
  const data = Buffer.alloc(70000, 173)
  writeFileSync(join(root, 'file.bin'), 'old')
  call({op:'begin', path:'file.bin', expected:digest('old')})
  for (let offset=0; offset<data.length; offset+=24*1024) call({op:'chunk', data:data.subarray(offset,offset+24*1024).toString('base64')})
  assert.equal(readFileSync(join(root, 'file.bin'), 'utf8'), 'old')
  call({op:'commit', hash:digest(data)})
  const received = []
  for (let offset=0;;) {
    const reply = call({op:'read', path:'file.bin', offset})
    const chunk = Buffer.from(reply.data,'base64')
    assert.ok(chunk.length <= 24*1024)
    received.push(chunk); offset += chunk.length
    if (reply.done) break
  }
  assert.deepEqual(Buffer.concat(received), data)
  assert.deepEqual(call({op:'hashes', paths:['file.bin']}), {'file.bin':digest(data)})
  assert.deepEqual(readdirSync(root), ['file.bin'])
})
test('edits made during upload and delete are kept, and interrupted uploads clean up', t => {
  const {root, call} = fixture(t)
  writeFileSync(join(root,'file.txt'),'base')
  call({op:'begin', path:'file.txt', expected:digest('base')})
  call({op:'chunk', data:Buffer.from('laptop').toString('base64')})
  writeFileSync(join(root,'file.txt'),'terminal edit')
  assert.throws(() => call({op:'commit', hash:digest('laptop')}), /changed/)
  assert.throws(() => call({op:'delete', path:'file.txt', expected:digest('base')}), /changed/)
  assert.equal(readFileSync(join(root,'file.txt'),'utf8'),'terminal edit')
  call({op:'abort'})
  assert.deepEqual(readdirSync(root), ['file.txt'])
  call({op:'delete', path:'file.txt', expected:digest('terminal edit')})
  assert.equal(existsSync(join(root,'file.txt')), false)
})
test('files above 256 MiB upload, hash and read without loading the whole file into memory', t => {
  const { root, call } = fixture(t)
  const chunk = Buffer.alloc(24 * 1024, 173)
  const encoded = chunk.toString('base64')
  const digest = createHash('sha256')
  const count = Math.ceil(257 * 1024 * 1024 / chunk.length)
  writeFileSync(join(root, 'large.db'), 'original')
  const original = call({ op: 'hash', path: 'large.db' }).hash
  call({ op: 'begin', path: 'large.db', expected: original })
  for (let i = 0; i < count; i++) {
    call({ op: 'chunk', data: encoded })
    digest.update(chunk)
  }
  assert.equal(readFileSync(join(root, 'large.db'), 'utf8'), 'original')
  const hash = digest.digest('hex')
  call({ op: 'commit', hash })
  assert.equal(statSync(join(root, 'large.db')).size, count * chunk.length)
  assert.equal(call({ op: 'hash', path: 'large.db' }).hash, hash)
  const last = call({ op: 'read', path: 'large.db', offset: (count - 1) * chunk.length })
  assert.equal(last.done, true)
  assert.deepEqual(Buffer.from(last.data, 'base64'), chunk)
})
test('invalid paths, changed file types, oversized chunks and wrong checksums are rejected', t => {
  const {root, call} = fixture(t)
  const invalid = ['../escape','/absolute','a/../../b','a\\b','a/./b','a//b','nul\0byte','line\nbreak','.yougori-sync-temp','x'.repeat(4097)]
  // Linux containers store ':' in names (the PC decides whether it can); on
  // Windows it would address an NTFS stream.
  if (process.platform === 'win32') invalid.push('a:stream')
  for (const path of invalid) {
    for (const r of [{op:'begin',path,expected:null},{op:'hash',path},{op:'read',path,offset:0},{op:'delete',path,expected:null},{op:'hashes',paths:[path]}]) {
      assert.throws(() => call(r), /path/, `${r.op} ${JSON.stringify(path)}`)
    }
  }
  if (process.platform !== 'win32') {
    call({op:'begin',path:'app-12:00.log',expected:null})
    call({op:'chunk',data:Buffer.from('log').toString('base64')})
    call({op:'commit',hash:digest('log')})
    assert.equal(call({op:'hash',path:'app-12:00.log'}).hash, digest('log'))
  }
  mkdirSync(join(root,'folder'))
  assert.throws(() => call({op:'delete',path:'folder',expected:null}), /regular file/)
  call({op:'begin',path:'file',expected:null})
  assert.throws(() => call({op:'chunk',data:Buffer.alloc(24*1024+1).toString('base64')}), /limit/)
  call({op:'chunk',data:Buffer.from('data').toString('base64')})
  assert.throws(() => call({op:'commit',hash:digest('wrong')}), /checksum/)
  call({op:'abort'})
  assert.equal(existsSync(join(root,'file')), false)
})
function inventory(call, prune = []) {
  const entries = []
  let cursor = null, offset = 0, pages = 0
  for (;;) {
    const page = call({op:'tree',cursor,offset,prune})
    // Each reply stays well inside the PC's 256 KiB frame limit once base64-encoded.
    assert.ok(Buffer.byteLength(JSON.stringify(page)) * 4 / 3 < 256 * 1024)
    entries.push(...page.entries); cursor = page.cursor; pages += 1
    if (page.next === null) return { entries, pages }
    assert.ok(page.next > offset)
    offset = page.next
  }
}

test('workspace inventory is paged, new files are discovered, and internal staging files stay hidden', t => {
  const {root,call} = fixture(t)
  mkdirSync(join(root,'many'))
  const name = i => `${'f'.repeat(160)}-${i}`
  for (let i=0; i<1200; i++) writeFileSync(join(root,'many',name(i)),'')
  writeFileSync(join(root,'.yougori-sync-temp'),'hidden')
  writeFileSync(join(root,'many','.yougori-sync-upload'),'hidden')
  const first = inventory(call)
  assert.ok(first.pages > 1, 'large inventories span several replies')
  const paths = first.entries.map(e => e.path)
  assert.equal(new Set(paths).size, paths.length)
  assert.deepEqual(paths.filter(p => p.startsWith('many/')).length, 1200)
  assert.ok(!paths.some(p => p.split('/').some(part => part.startsWith('.yougori-sync-'))))
  // Parents come before their contents, and every file carries a change stamp.
  assert.ok(paths.indexOf('many') < paths.indexOf(`many/${name(0)}`))
  assert.ok(first.entries.filter(e => e.kind === 'file').every(e => /^\d+:\d+:\d+:\d+$/.test(e.stamp)))
  // A page from an earlier or unknown inventory is refused rather than mixed in.
  assert.throws(() => call({op:'tree',cursor:'stale',offset:5,prune:[]}), /expired/)
  writeFileSync(join(root,'many','added-later'),'new')
  assert.ok(inventory(call).entries.some(e => e.path === 'many/added-later'))
  const before = first.entries.find(e => e.path === `many/${name(0)}`).stamp
  writeFileSync(join(root,'many',name(0)),'edited')
  assert.notEqual(inventory(call).entries.find(e => e.path === `many/${name(0)}`).stamp, before)
})

test('workspace inventory reports host-only folders and links without entering them', t => {
  const {root,call} = fixture(t)
  const outside = mkdtempSync(join(tmpdir(),'yougori-inventory-outside-'))
  t.after(() => rmSync(outside,{recursive:true,force:true}))
  writeFileSync(join(outside,'private'),'outside the workspace')
  for (const folder of ['node_modules/pkg','.git/hooks','app/node_modules/.bin','src/.GIT','src/.g\u200cit','.venv/bin','lib/__pycache__']) mkdirSync(join(root,folder),{recursive:true})
  for (const file of ['node_modules/pkg/index.js','.git/hooks/pre-commit','app/node_modules/.bin/tool','src/.GIT/config','src/.g\u200cit/HEAD','.venv/bin/python','lib/__pycache__/a.pyc','src/app.js','app/package.json']) writeFileSync(join(root,file),'x')
  symlinkSync(outside,join(root,'linked'),process.platform === 'win32' ? 'junction' : 'dir')
  const prune = ['.git','.hg','.svn','node_modules','.venv','venv','__pycache__']
  const { entries } = inventory(call, prune)
  const byPath = Object.fromEntries(entries.map(e => [e.path, e]))
  for (const folder of ['node_modules','.git','app/node_modules','src/.GIT','src/.g\u200cit','.venv','lib/__pycache__']) {
    assert.deepEqual(byPath[folder], {path:folder,kind:'dir',pruned:true}, folder)
    assert.ok(!entries.some(e => e.path.startsWith(`${folder}/`)), `${folder} was entered`)
  }
  assert.equal(byPath.linked.kind, 'link')
  assert.ok(!entries.some(e => e.path.startsWith('linked/')))
  for (const file of ['src/app.js','app/package.json']) assert.equal(byPath[file].kind, 'file')
  assert.equal(readFileSync(join(outside,'private'),'utf8'),'outside the workspace')
  // Without a prune list the same folders are inventoried normally.
  assert.ok(inventory(call).entries.some(e => e.path === 'node_modules/pkg/index.js'))
  assert.throws(() => call({op:'tree',cursor:null,offset:0,prune:'node_modules'}), /Invalid/)
})
test('directory symlinks and Windows junctions cannot redirect reads or writes', t => {
  const {root,call} = fixture(t)
  const outside = mkdtempSync(join(tmpdir(),'yougori-outside-'))
  t.after(() => rmSync(outside,{recursive:true,force:true}))
  writeFileSync(join(outside,'keep'),'private')
  symlinkSync(outside,join(root,'link'),process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => call({op:'hash',path:'link/keep'}), /Symlink/)
  assert.throws(() => call({op:'begin',path:'link/new',expected:null}), /Symlink/)
  writeFileSync(join(root,'ordinary'),'project code')
  const paths=['ordinary','link/keep','link/missing','missing']
  assert.deepEqual(call({op:'hashes',paths,skipLinks:true}), {
    hashes:{ordinary:digest('project code'),missing:null},
    skipped:['link/keep','link/missing']
  })
  assert.deepEqual(call({op:'links',paths}), {skipped:['link/keep','link/missing']})
  assert.throws(() => call({op:'hashes',paths}), /Symlink/)
  assert.throws(() => call({op:'links',paths:['../keep']}), /Invalid/)
  assert.throws(() => call({op:'hashes',paths:['../keep'],skipLinks:true}), /Invalid/)
  assert.ok(lstatSync(join(root,'link')).isSymbolicLink())
  assert.equal(readFileSync(join(outside,'keep'),'utf8'),'private')
})

test('resume checks distinguish Linux npm links from missing files without following targets', t => {
  const {root,call}=fixture(t)
  mkdirSync(join(root,'node_modules','.bin'),{recursive:true})
  writeFileSync(join(root,'dependency.js'),'Linux dependency')
  try { symlinkSync('../../dependency.js',join(root,'node_modules','.bin','tool'),'file') }
  catch(e) { if(process.platform === 'win32' && e.code === 'EPERM') { t.skip('File symlink privilege unavailable; directory links are tested separately'); return } throw e }
  symlinkSync('../../missing.js',join(root,'node_modules','.bin','broken'),'file')
  const paths=['node_modules/.bin/tool','node_modules/.bin/broken','dependency.js','missing.js']
  assert.deepEqual(call({op:'hashes',paths,skipLinks:true}), {
    hashes:{'dependency.js':digest('Linux dependency'),'missing.js':null},
    skipped:['node_modules/.bin/tool','node_modules/.bin/broken']
  })
  assert.deepEqual(call({op:'links',paths}), {skipped:['node_modules/.bin/tool','node_modules/.bin/broken']})
  assert.throws(() => call({op:'delete',path:'node_modules/.bin/tool',expected:null}), /Symlink/)
  assert.equal(readFileSync(join(root,'dependency.js'),'utf8'),'Linux dependency')
  assert.ok(lstatSync(join(root,'node_modules','.bin','tool')).isSymbolicLink())
})
test('actual sync receiver frames large replies and keeps the one-way protocol working', t => {
  const root = mkdtempSync(join(tmpdir(), 'yougori-sync-protocol-'))
  t.after(()=>rmSync(root,{recursive:true,force:true}))
  const workspace=join(root,'project'), state=join(root,'state'), imported=join(root,'imported')
  mkdirSync(imported); mkdirSync(state)
  // Local launch points /workspace at the imported project. Chunked one-way
  // operations must accept this launcher-owned alias while rejecting child links.
  symlinkSync(imported, workspace, process.platform === 'win32' ? 'junction' : 'dir')
  const asset = new URL('../cli/src/launcher/assets/',import.meta.url)
  const script=readFileSync(new URL('sync.cjs',asset),'utf8')
    .replace("const root = '/workspace';",`const root = ${JSON.stringify(workspace)};`)
    .replace("const state = '/yougori/launch';",`const state = ${JSON.stringify(state)};`)
  writeFileSync(join(root,'sync.cjs'),script)
  writeFileSync(join(root,'two-way.cjs'),readFileSync(new URL('two-way.cjs',asset)))
  writeFileSync(join(root,'sqlite.cjs'),readFileSync(new URL('sqlite.cjs',asset)))
  const data=Buffer.alloc(24000,123)
  const request=Buffer.from(JSON.stringify({op:'read',path:'file',offset:0})).toString('base64')
  const input=`W ${Buffer.from('file').toString('base64')} ${data.toString('base64')}\nB before\nX request ${request}\n`
  const result=spawnSync(process.execPath,[join(root,'sync.cjs'),'test'],{input,encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  assert.match(result.stdout,/ack:before/)
  const frames=[...result.stdout.matchAll(/\[yougori-test:rpc:request:([^\]]+)\]/g)].map(m=>m[1])
  assert.ok(frames.length>1)
  assert.ok(frames.every(f=>f.length<=8192))
  const reply=JSON.parse(Buffer.from(frames.join(''),'base64'))
  assert.deepEqual(Buffer.from(reply.result.data,'base64'),data)
  assert.match(result.stdout,/end:request/)
})
