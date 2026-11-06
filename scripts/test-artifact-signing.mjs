// Explicit native smoke test. No production keys, engine or live runtime.
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { invokeSigning } from './sign-artifacts.mjs'

const [toolFlag, toolPath, scratchFlag, scratchPath, ...extra] = process.argv.slice(2)
if (toolFlag !== '--tool' || !toolPath || scratchFlag !== '--scratch' || !scratchPath || extra.length) {
  throw new Error('Usage: node scripts/test-artifact-signing.mjs --tool EXECUTABLE --scratch EXISTING_DIRECTORY')
}
const tool = resolve(toolPath)
const directory = mkdtempSync(join(resolve(scratchPath), 'signing-smoke-'))
const files = []
const passed = []
function file(name, bytes) {
  const path = join(directory, name)
  if (!files.includes(path)) files.push(path)
  writeFileSync(path, bytes, { mode: 0o600 })
  return path
}
const requestPath = join(directory, 'request.json')
function request(value) { file('request.json', JSON.stringify(value)); return ['--tool', tool, '--request', requestPath] }
function verify(value) { return JSON.parse(invokeSigning(request(value), { verifyOnly: true })) }

let privateDer
try {
  privateDer = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' })
  const keyPath = file('disposable-test-key.der', privateDer)
  const sign = (value) => JSON.parse(invokeSigning([...request(value), '--key-file', keyPath]))
  const publicKey = sign({ operation: 'public_key' })
  assert.equal(publicKey.algorithm, 'ed25519')
  assert.equal(publicKey.publisher, publicKey.metadata_key_id)
  passed.push('real binary accepts generated PKCS8 and emits public identity')
  const roots = sign({ operation: 'trust_roots', id: 'disposable-smoke', classes: ['model_helper', 'guest_image'],
    valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' })
  file('artifact', 'release artifact')
  const attestation = sign({ operation: 'sign_artifact', class: 'model_helper', artifact: 'artifact' })
  const valid = { operation: 'verify_artifact', class: 'model_helper', artifact: 'artifact', attestation,
    trust_roots: roots, at: '2026-06-01T00:00:00Z' }
  assert.equal(verify(valid).verification, 'artifact_signature')
  passed.push('native file signing and public-only verification round trip')
  file('roots.json', JSON.stringify(roots))
  file('artifact.sig', JSON.stringify(attestation))
  file('runner', 'disposable runner bytes')
  const identifyBuild = { operation: 'identify_build', trust_roots_file: 'roots.json',
    build: { plan: '00'.repeat(32), runner_build_file: 'runner', runner_version: 'native-smoke' },
    components: [{ class: 'model_helper', publisher: publicKey.publisher, artifact: 'artifact', signature_file: 'artifact.sig' }] }
  const record = verify(identifyBuild)
  assert.equal(record.build.runner_build, createHash('sha256').update('disposable runner bytes').digest('hex'))
  assert.equal(record.components[0].verification.outcome, 'verified')
  file('build.json', JSON.stringify(record))
  const verifyBuild = { operation: 'verify_build', trust_roots_file: 'roots.json', record_file: 'build.json',
    artifact_files: ['artifact'], signature_files: ['artifact.sig'] }
  const rechecked = verify(verifyBuild)
  assert.equal(rechecked.all_verified, true)
  assert.equal(rechecked.artifact_files_checked, true)
  assert.equal(rechecked.build_authenticated, false)
  passed.push('native build record hashes runner and rechecks current artifact bytes')
  const relabelled = structuredClone(record)
  relabelled.components[0].class = 'guest_image'
  file('build.json', JSON.stringify(relabelled))
  assert.throws(() => verify(verifyBuild))
  file('build.json', JSON.stringify(record))
  passed.push('record cannot relabel a signature even under a key trusted for both classes')
  assert.throws(() => verify({ ...valid, class: 'guest_image' }))
  passed.push('cross-class signature refused')
  assert.throws(() => verify({ ...valid, at: '2027-01-01T00:00:00Z' }))
  passed.push('expired artifact root refused')
  const revoked = structuredClone(roots)
  revoked.keys[0].revoked = { reason: 'smoke-revocation' }
  assert.throws(() => verify({ ...valid, trust_roots: revoked }))
  passed.push('revoked key refused')
  file('roots.json', JSON.stringify(revoked))
  const nowRevoked = verify(verifyBuild)
  assert.equal(nowRevoked.all_verified, false)
  assert.equal(nowRevoked.components[0].reverified.outcome, 'revoked')
  file('roots.json', JSON.stringify(roots))
  passed.push('saved build recheck reports current revocation instead of trusting saved success')
  file('artifact', 'RELEASE artifact')
  assert.throws(() => verify(valid))
  assert.throws(() => verify(verifyBuild))
  passed.push('same-length artifact tampering refused')
  file('request.json', '{"operation":"public_key","operation":"public_key"}')
  const malformed = spawnSync(tool, ['--request', requestPath], { input: privateDer, encoding: 'utf8', windowsHide: true })
  assert.equal(malformed.status, 1)
  assert.equal(malformed.stdout, '')
  assert.ok(!malformed.stderr.includes(privateDer.toString('hex')))
  passed.push('malformed request exits nonzero with no public output or private key')
  request({ operation: 'public_key' })
  const corrupt = spawnSync(tool, ['--request', requestPath], { input: privateDer.subarray(0, 10), encoding: 'utf8', windowsHide: true })
  assert.equal(corrupt.status, 1)
  assert.equal(corrupt.stdout, '')
  passed.push('truncated private key refused')
  process.stdout.write(JSON.stringify({ tool, passed: passed.length, checks: passed }, null, 2) + '\n')
} finally {
  privateDer?.fill(0)
  // Only these exact disposable files; no recursive or computed tree deletion.
  for (const path of files) unlinkSync(path)
  rmdirSync(directory)
}
