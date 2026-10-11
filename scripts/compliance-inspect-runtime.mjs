import { createHash } from "node:crypto"
import { readFile, readdir, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { windowsPeImports } from "./release-preflight.mjs"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const records = []
for (const part of ["qemu", "qemu-secure"]) {
  const folder = resolve(root, "src-tauri/resources/runtime", part)
  const files = new Map()
  for (const name of await readdir(folder)) {
    if (!/\.(exe|dll)$/i.test(name)) continue
    const bytes = await readFile(resolve(folder, name))
    const record = { file: `src-tauri/resources/runtime/${part}/${name}`, sha256: createHash("sha256").update(bytes).digest("hex"), imports: windowsPeImports(bytes) }
    records.push(record)
    files.set(name.toLowerCase(), record)
  }
  const reachable = new Set()
  const pending = ["qemu-system-x86_64.exe", "libegl.dll", "libegl_angle.dll", "libglesv2.dll"]
  while (pending.length) {
    const name = pending.pop().toLowerCase()
    if (reachable.has(name)) continue
    reachable.add(name)
    for (const dependency of files.get(name)?.imports ?? []) pending.push(dependency)
  }
  for (const name of ["libdb-6.2.dll", "libjack64.dll", "libcrypto-3-x64.dll", "yougori-tpm.dll"]) {
    if (reachable.has(name)) throw new Error(`${part}: unexpected QEMU linkage to ${name}`)
  }
  console.log(`${part}: ${files.size} PE files inspected; QEMU has no JACK/Berkeley DB/TPM/OpenSSL import chain.`)
}
await writeFile(resolve(root, "compliance/evidence/windows-pe-imports.json"), JSON.stringify(records, null, 2) + "\n")
