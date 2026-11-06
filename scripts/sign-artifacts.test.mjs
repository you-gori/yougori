import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { invokeSigning } from './sign-artifacts.mjs'

test('private bytes travel only through stdin and are cleared afterward', () => {
  const root = mkdtempSync(join(tmpdir(), 'yougori-sign-test-'))
  try {
    const key = join(root, 'key.der')
    writeFileSync(key, Buffer.from('disposable-test-key'))
    let held
    const output = invokeSigning(['--tool', 'tool.exe', '--request', 'public.json', '--key-file', key], {
      spawn(tool, args, options) {
        assert.equal(tool, 'tool.exe')
        assert.deepEqual(args, ['--request', 'public.json'])
        assert.equal(options.shell, false)
        assert.equal(options.windowsHide, true)
        assert.equal(options.input.toString(), 'disposable-test-key')
        held = options.input
        return { status: 0, stdout: '{"public_key":"public"}' }
      },
    })
    assert.equal(output, '{"public_key":"public"}\n')
    assert.ok(held.every(byte => byte === 0))
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('oversized keys and duplicate/unknown flags never launch a child', () => {
  const root = mkdtempSync(join(tmpdir(), 'yougori-sign-test-'))
  try {
    const key = join(root, 'large.der')
    writeFileSync(key, Buffer.alloc(4097, 42))
    const args = ['--tool', 'tool', '--request', 'public.json', '--key-file', key]
    const spawn = () => assert.fail('must not launch')
    assert.throws(() => invokeSigning(args, { spawn }))
    assert.throws(() => invokeSigning([...args, '--tool', 'second'], { spawn }))
    assert.throws(() => invokeSigning(['--secret', 'do-not-print'], { spawn }))
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('verification supplies no private input and requires a verification result', () => {
  const args = ['--tool', 'tool', '--request', 'verify.json']
  const invoke = stdout => invokeSigning(args, { verifyOnly: true, spawn(tool, forwarded, options) {
    assert.equal(options.input.length, 0)
    return { status: 0, stdout }
  } })
  assert.equal(invoke('{"verification":"artifact_signature"}'), '{"verification":"artifact_signature"}\n')
  assert.throws(() => invoke('{"publisher":"key","signature":"sig"}'))
  assert.throws(() => invokeSigning([...args, '--key-file', 'key'], { verifyOnly: true }))
})

test('child errors and malformed results cannot be mistaken for success', () => {
  const args = ['--tool', 'tool', '--request', 'verify.json']
  for (const result of [{ status: 1, stderr: 'private input' }, { error: new Error('private input') },
    { status: 0, stdout: '[]' }, { status: 0, stdout: '{}' }]) {
    assert.throws(() => invokeSigning(args, { verifyOnly: true, spawn: () => result }), error => !error.message.includes('private input'))
  }
})

test('build identity records and their re-verification pass the verification wrapper only', () => {
  const args = ['--tool', 'tool', '--request', 'build.json']
  const invoke = stdout => invokeSigning(args, { verifyOnly: true, spawn(tool, forwarded, options) {
    assert.deepEqual(forwarded, ['--request', 'build.json'])
    assert.equal(options.input.length, 0)
    return { status: 0, stdout }
  } })
  const record = '{"schema_version":3,"build":{"plan":"p","runner_build":"r","runner_version":"v"},"components":[]}'
  assert.equal(invoke(record), record + '\n')
  const reverified = '{"verification":"signed_build_reverified","all_verified":false,"components":[]}'
  assert.equal(invoke(reverified), reverified + '\n')
  for (const stdout of ['{"schema_version":3,"build":{}}', '{"schema_version":"3","build":{},"components":[]}',
    '{"schema_version":3,"build":[],"components":[]}', '{"verification":"signed_build","schema_version":3,"build":{},"components":[]}']) {
    assert.throws(() => invoke(stdout), stdout)
  }
})
