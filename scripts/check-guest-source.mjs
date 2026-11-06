// Match the build record to the source used for this app. Checksums alone can
// authenticate an old, incompatible guest just as successfully as a current one.
import { createHash } from 'node:crypto'
import { readFile, readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

export async function verifyGuestSource(root, recordPath = join(root, 'src-tauri/resources/runtime/sandbox-guest/artifacts.json')) {
  const record = JSON.parse(await readFile(recordPath, 'utf8'))
  const agent = join(root, 'appliance/agent'), paths = []
  async function collect(relative) {
    for (const entry of await readdir(join(agent, relative), { withFileTypes: true })) {
      const name = relative + '/' + entry.name
      if (entry.isDirectory()) await collect(name)
      else if (entry.isFile()) paths.push(name)
      else throw new Error('Guest sources must not contain links: ' + name)
    }
  }
  await collect('link'); await collect('cmd/yougori-sandbox-agent'); await collect('gridkit'); await collect('setupkit')
  const hash = createHash('sha256')
  for (const name of paths.sort()) {
    const content = await readFile(join(agent, name))
    hash.update(name + '\0' + content.length + '\0'); hash.update(content)
  }
  const source = record.inputs.find(input => input.path === 'appliance/agent/{link,cmd/yougori-sandbox-agent,gridkit,setupkit}')
  if (!source || source.sha256 !== hash.digest('hex') || source.files !== paths.length) {
    throw new Error('Sandbox guest is stale. Rebuild with scripts/build-guest.sh and package the matching guest before distributing this app.')
  }
  for (const name of ['go.mod', 'go.sum']) {
    const digest = createHash('sha256').update(await readFile(join(agent, name))).digest('hex')
    if (record.inputs.find(input => input.path === 'appliance/agent/' + name)?.sha256 !== digest) {
      throw new Error('Sandbox guest dependencies are stale: ' + name)
    }
  }
  return record.agent_build
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { console.log('Guest source verified: ' + await verifyGuestSource(resolve('.'), process.argv[2])) }
  catch (error) { console.error(error.message); process.exitCode = 1 }
}
