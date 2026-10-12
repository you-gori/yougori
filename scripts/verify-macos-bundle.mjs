import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { readFile, readdir } from "node:fs/promises"
import { basename, join, relative, resolve } from "node:path"
import { assertMacCli } from "./release-preflight.mjs"

// Checks a built Yougori.app: native binaries, the bundled QEMU runtime and every signature.
// With --distribution it also requires Developer ID signatures, the hardened runtime and an
// accepted, notarized and stapled app, as a public download needs.
if (process.platform !== "darwin") throw new Error("Inspect the built .app on macOS")
const args = process.argv.slice(2)
const distribution = args.includes("--distribution")
const app = resolve(args.find(arg => !arg.startsWith("--")) || "src-tauri/target/release/bundle/macos/Yougori.app")
const contents = join(app, "Contents")
const runtime = join(contents, "Resources/runtime/qemu")

function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { encoding: "utf8" })
  if (result.error || result.status !== 0) throw new Error(`${command} ${commandArgs.join(" ")}: ${result.error?.message || result.stderr || result.stdout}`)
  return `${result.stdout}${result.stderr}`
}

async function files(directory) {
  const found = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isSymbolicLink()) throw new Error(`Unexpected symlink in application resources: ${path}`)
    if (entry.isDirectory()) found.push(...await files(path))
    else found.push(path)
  }
  return found
}

const executables = ["MacOS/yougori", "Resources/cli/yougori", "Resources/cli/yougori-cli",
  "Resources/runtime/qemu/qemu-system-x86_64", "Resources/runtime/qemu/qemu-img",
  "Resources/runtime/llama/llama-server", "Resources/runtime/llama/yougori-supervise"].map(file => join(contents, file))
for (const file of executables) assertMacCli(await readFile(file), process.arch)
for (const file of await files(join(contents, "Resources"))) {
  if (/\.(exe|dll)$/i.test(file)) throw new Error(`Windows binary leaked into macOS package: ${file}`)
}

// The runtime holds exactly what its SHA256SUMS lists, which the app verifies before use.
async function verifyRuntime(directory) {
  const listed = new Map()
  for (const line of (await readFile(join(directory, "SHA256SUMS"), "utf8")).split("\n").filter(line => line.trim())) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+?)\s*$/i)
    if (!match || listed.has(match[2])) throw new Error(`Invalid or duplicate runtime checksum: ${directory}`)
    listed.set(match[2], match[1].toLowerCase())
  }
  const present = (await files(directory)).map(file => relative(directory, file).split("\\").join("/")).filter(file => file !== "SHA256SUMS")
  for (const file of present) {
    const hash = createHash("sha256").update(await readFile(join(directory, file))).digest("hex")
    if (listed.get(file) !== hash) throw new Error(`Runtime file is not listed with its checksum: ${join(directory, file)}`)
  }
  for (const file of listed.keys()) if (!present.includes(file)) throw new Error(`Runtime file listed but missing: ${join(directory, file)}`)
  return present
}
const present = await verifyRuntime(runtime)
const nativeModel = join(contents, "Resources/runtime/llama")
await verifyRuntime(nativeModel)

// Libraries load only from macOS itself or from the runtime's own lib folder.
const libraries = present.filter(file => file.startsWith("lib/") && file.endsWith(".dylib")).map(file => join(runtime, file))
for (const binary of [join(runtime, "qemu-system-x86_64"), join(runtime, "qemu-img"), ...libraries,
  join(nativeModel, "llama-server"), join(nativeModel, "yougori-supervise")]) {
  for (const line of run("/usr/bin/otool", ["-L", binary]).split("\n").slice(1)) {
    const reference = line.trim().split(" (compatibility")[0]
    if (!reference) continue
    const name = basename(reference)
    const own = reference === `@rpath/${basename(binary)}`
    const bundled = !binary.startsWith(nativeModel) && [`@executable_path/lib/${name}`, `@loader_path/${name}`].includes(reference) && present.includes(`lib/${name}`)
    if (!(own || bundled || reference.startsWith("/usr/lib/") || reference.startsWith("/System/Library/"))) {
      throw new Error(`${relative(contents, binary)} loads ${reference} from outside macOS and the app`)
    }
  }
}

// Every executable and library is signed; QEMU carries its hypervisor and JIT entitlements.
for (const binary of [...executables, ...libraries]) run("/usr/bin/codesign", ["--verify", "--strict", binary])
const entitlements = run("/usr/bin/codesign", ["-d", "--entitlements", "-", "--xml", join(runtime, "qemu-system-x86_64")])
for (const key of ["com.apple.security.hypervisor", "com.apple.security.cs.allow-jit"]) {
  if (!entitlements.includes(key)) throw new Error(`QEMU is missing the ${key} entitlement`)
}
run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app])
if (distribution) {
  for (const binary of [app, ...executables, ...libraries]) {
    const details = run("/usr/bin/codesign", ["-dv", "--verbose=2", binary])
    if (!details.includes("Authority=Developer ID Application:")) throw new Error(`${relative(contents, binary) || "Yougori.app"} is not signed with a Developer ID`)
    if (!/flags=0x[0-9a-f]*\(.*runtime.*\)/.test(details)) throw new Error(`${relative(contents, binary) || "Yougori.app"} lacks the hardened runtime`)
  }
  const assessment = run("/usr/sbin/spctl", ["--assess", "--type", "execute", "-vv", app])
  if (!/accepted/.test(assessment) || !/Notarized Developer ID/.test(assessment)) throw new Error(`Gatekeeper did not accept the notarized app: ${assessment}`)
  run("/usr/bin/xcrun", ["stapler", "validate", app])
}
run("/usr/bin/plutil", ["-lint", join(contents, "Info.plist")])
console.log(`macOS bundle verified (${process.arch}): native binaries, QEMU and model runtimes, and signatures${distribution ? ", Developer ID, notarization and Gatekeeper" : ""}: ${app}`)
if (!distribution) console.log("Not a distribution check: run with --distribution on the signed, notarized build.")
