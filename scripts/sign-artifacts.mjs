// Maintainer bridge for binary PKCS#8 stdin, including Windows shells.
import { openSync, readSync, closeSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

// Public results the verification wrapper passes on: a verification report, or the
// signed build identity record `identify_build` writes, which carries no report tag so
// that `SignedBuildIdentity::from_json` reads it back unchanged.
const VERIFICATIONS = ['artifact_signature', 'metadata_threshold_only', 'signed_build_reverified']
const isBuildIdentity = value => !('verification' in value) && Number.isInteger(value.schema_version) &&
  value.build !== null && typeof value.build === 'object' && !Array.isArray(value.build) &&
  Array.isArray(value.components)

export function invokeSigning(args, { verifyOnly = false, spawn = spawnSync } = {}) {
  const options = new Map()
  const allowed = new Set(verifyOnly ? ['--tool', '--request'] : ['--tool', '--request', '--key-file'])
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || options.has(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) {
      throw new Error('Expected unique --tool, --request and (for signing) --key-file paths')
    }
    options.set(args[i], args[i + 1])
  }
  if (!options.has('--tool') || !options.has('--request') || (!verifyOnly && !options.has('--key-file'))) {
    throw new Error('Missing tool, public request or signing key file')
  }
  let secret = Buffer.alloc(0)
  try {
    if (!verifyOnly) {
      // One extra byte detects an oversized key; never read an unbounded private file.
      secret = Buffer.alloc(4097)
      const fd = openSync(options.get('--key-file'), 'r')
      let used = 0
      try {
        while (used < secret.length) {
          const read = readSync(fd, secret, used, secret.length - used, null)
          if (!read) break
          used += read
        }
      } finally { closeSync(fd) }
      if (!used || used > 4096) throw new Error('Signing key must be bounded PKCS#8 DER')
      secret = secret.subarray(0, used)
    }
    const child = spawn(options.get('--tool'), ['--request', options.get('--request')], {
      input: secret, encoding: 'utf8', shell: false, windowsHide: true,
      maxBuffer: 2 * 1024 * 1024 + 4096,
    })
    // Do not forward arbitrary child output on error (it could contain input bytes).
    if (child.error || child.status !== 0) throw new Error('Signing utility refused the request or could not run')
    const value = JSON.parse(child.stdout)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid public utility result')
    if (verifyOnly && !VERIFICATIONS.includes(value.verification) && !isBuildIdentity(value)) {
      throw new Error('Request did not produce a verification result')
    }
    return JSON.stringify(value) + '\n'
  } finally { secret.fill(0) }
}

export function main(args = process.argv.slice(2), verifyOnly = false) {
  try { process.stdout.write(invokeSigning(args, { verifyOnly })) }
  catch { process.stderr.write('Artifact signing/verification failed; check the public request, key format and tool path.\n'); process.exitCode = 1 }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()
