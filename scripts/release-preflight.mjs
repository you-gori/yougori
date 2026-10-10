import { createHash } from "node:crypto"
import { createReadStream } from "node:fs"
import { lstat, readFile, readdir, realpath } from "node:fs/promises"
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

export const windowsTarget = "x86_64-pc-windows-msvc"
export const linuxTarget = "x86_64-unknown-linux-gnu"
export const linuxArmTarget = "aarch64-unknown-linux-gnu"
export const macIntelTarget = "x86_64-apple-darwin"
export const macArmTarget = "aarch64-apple-darwin"

export function nativeTarget(platform = process.platform, arch = process.arch) {
  if (platform === "darwin" && arch === "arm64") return macArmTarget
  if (platform === "darwin" && arch === "x64") return macIntelTarget
  if (platform === "linux" && arch === "x64") return linuxTarget
  if (platform === "linux" && arch === "arm64") return linuxArmTarget
  if (platform === "win32" && arch === "x64") return windowsTarget
  throw new Error("Supported desktop builds: Windows x64, Linux x64/arm64, macOS Intel x64 or Apple Silicon arm64.")
}

// Cross builds must explicitly select the Linux payload architecture. All
// binaries are checked against it before they can enter an engine archive.
export function releaseArchitecture(env = process.env, platform = process.platform, arch = process.arch) {
  const selected = env.YOUGORI_RELEASE_ARCH || arch
  if (selected !== arch && platform !== "linux") throw new Error("Cross packaging is supported for Linux only")
  nativeTarget(platform, selected)
  return selected
}

export function assertLinuxCli(buffer, arch, label = "CLI") {
  const machine = { x64: 62, arm64: 183 }[arch]
  if (!machine || buffer.length < 64 || buffer.toString("hex", 0, 4) !== "7f454c46"
    || buffer[4] !== 2 || buffer[5] !== 1 || ![2, 3].includes(buffer.readUInt16LE(16))
    || buffer.readUInt16LE(18) !== machine) {
    throw new Error(`Expected a ${arch} Linux ELF ${label}`)
  }
}

export function assertMacCli(buffer, arch) {
  const cpu = arch === "arm64" ? 0x0100000c : arch === "x64" ? 0x01000007 : null
  if (!cpu || buffer.length < 32 || buffer.readUInt32LE(0) !== 0xfeedfacf
    || buffer.readUInt32LE(4) !== cpu || buffer.readUInt32LE(12) !== 2) {
    throw new Error(`Expected a native ${arch} macOS Mach-O CLI executable, not an ELF, PE or universal binary`)
  }
}

// The CLI is built separately from Tauri, so it does not inherit Tauri's
// default static Visual C++ runtime setting. Retain caller flags and append
// the portability requirement using whichever Cargo flag encoding they use.
export function portableCliBuildEnv(env = process.env, platform = process.platform) {
  if (platform !== "win32") return { ...env }
  if (env.CARGO_ENCODED_RUSTFLAGS !== undefined) {
    const flags = env.CARGO_ENCODED_RUSTFLAGS ? [env.CARGO_ENCODED_RUSTFLAGS] : []
    return { ...env, CARGO_ENCODED_RUSTFLAGS: [...flags, "-C", "target-feature=+crt-static"].join("\u001f") }
  }
  return { ...env, RUSTFLAGS: `${env.RUSTFLAGS || ""} -C target-feature=+crt-static`.trim() }
}

export function windowsPeImports(buffer) {
  try {
    if (buffer.toString("ascii", 0, 2) !== "MZ") throw new Error("Missing DOS header")
    const pe = buffer.readUInt32LE(60)
    if (buffer.readUInt32LE(pe) !== 0x4550 || buffer.readUInt16LE(pe + 4) !== 0x8664) throw new Error("Expected an x64 PE executable")
    const count = buffer.readUInt16LE(pe + 6)
    const optional = pe + 24
    if (buffer.readUInt16LE(optional) !== 0x20b) throw new Error("Expected PE32+")
    const sections = optional + buffer.readUInt16LE(pe + 20)
    const offset = rva => {
      for (let index = 0; index < count; index++) {
        const section = sections + index * 40
        const va = buffer.readUInt32LE(section + 12)
        const length = buffer.readUInt32LE(section + 16)
        if (rva >= va && rva < va + length) {
          const result = buffer.readUInt32LE(section + 20) + rva - va
          if (result < buffer.length) return result
        }
      }
      throw new Error("PE import points outside file data")
    }
    const directory = optional + 112
    const importRva = buffer.readUInt32LE(directory + 8)
    const importSize = buffer.readUInt32LE(directory + 12)
    if (!importRva || importSize < 20) throw new Error("Missing import directory")
    const imports = []
    let table = offset(importRva)
    for (let index = 0; index < Math.min(Math.floor(importSize / 20), 4096); index++, table += 20) {
      const nameRva = buffer.readUInt32LE(table + 12)
      if (!nameRva) return imports
      const start = offset(nameRva)
      const end = buffer.indexOf(0, start)
      if (end < start || end - start > 260) throw new Error("Invalid PE DLL name")
      imports.push(buffer.toString("ascii", start, end))
    }
    throw new Error("Unterminated PE import directory")
  } catch (error) {
    throw new Error(`Cannot verify Windows binary imports: ${error.message}`)
  }
}

export function assertPortableCli(buffer, label = "CLI") {
  const imports = windowsPeImports(buffer)
  const externalCrt = imports.filter(name => /^(?:vcruntime|msvcp|concrt)\d.*\.dll$/i.test(name))
  if (externalCrt.length) throw new Error(`${label} requires an unbundled Visual C++ runtime (${externalCrt.join(", ")}). Rebuild with +crt-static before packaging.`)
  return imports
}

export function releaseTarget(env = process.env, platform = process.platform, arch = process.arch) {
  const target = nativeTarget(platform, arch)
  for (const value of [env.TAURI_ENV_TARGET_TRIPLE, env.CARGO_BUILD_TARGET]) {
    if (value && value !== target) throw new Error(`Unsupported desktop release target: ${value}. Use ${target}.`)
  }
  if (env.VITE_YOUGORI_TEST_ADAPTER === "1") {
    throw new Error("Refusing to package the test adapter. Unset VITE_YOUGORI_TEST_ADAPTER before building a release.")
  }
  return env.TAURI_ENV_TARGET_TRIPLE || env.CARGO_BUILD_TARGET || null
}

export function parseManifest(source) {
  const entries = new Map()
  const identities = new Set()
  for (const line of source.trim().split(/\r?\n/)) {
    const match = /^([a-fA-F0-9]{64}) {2}(.+)$/.exec(line)
    if (!match) throw new Error("Malformed runtime SHA256SUMS entry")
    const [, checksum, name] = match
    if (name.includes("\\") || name.includes(":") || name.includes("\0") || name.startsWith("/")
      || name.split("/").some(part => !part || part === "." || part === ".." || /[. ]$/.test(part))) {
      throw new Error(`Unsafe runtime manifest path: ${name}`)
    }
    const identity = name.toLowerCase()
    if (identity === "sha256sums" || identities.has(identity)) throw new Error(`Duplicate or self-referencing manifest entry: ${name}`)
    identities.add(identity)
    entries.set(name, checksum.toLowerCase())
  }
  return entries
}

async function insideFile(root, name) {
  const path = join(root, name)
  const resolved = await realpath(path)
  const tail = relative(root, resolved)
  if (!tail || tail === ".." || tail.startsWith(`..${sep}`) || isAbsolute(tail)) throw new Error(`Runtime path escapes its directory: ${name}`)
  let current = root
  for (const part of name.split("/")) {
    current = join(current, part)
    if ((await lstat(current)).isSymbolicLink()) throw new Error(`Runtime links cannot be packaged: ${name}`)
  }
  if (!(await lstat(path)).isFile()) throw new Error(`Runtime payload is not a regular file: ${name}`)
  return path
}

export async function verifyRuntimeDirectory(directory, allowedNotices = [], required = []) {
  if ((await lstat(directory)).isSymbolicLink()) throw new Error("Runtime directory cannot be a symbolic link")
  const root = await realpath(directory)
  const manifestPath = await insideFile(root, "SHA256SUMS")
  const entries = parseManifest(await readFile(manifestPath, "utf8"))
  for (const name of required) {
    if (!entries.has(name)) throw new Error(`Required runtime payload missing from manifest: ${name}`)
  }
  let bytes = 0
  for (const [name, expected] of entries) {
    const path = await insideFile(root, name)
    const hash = createHash("sha256")
    for await (const chunk of createReadStream(path)) { hash.update(chunk); bytes += chunk.length }
    if (hash.digest("hex") !== expected) throw new Error(`Runtime checksum mismatch: ${directory}/${name}. Rebuild the payload; do not bypass verification.`)
  }
  async function checkFiles(path, prefix = "") {
    for (const item of await readdir(path, { withFileTypes: true })) {
      const name = prefix + item.name
      if (item.isSymbolicLink()) throw new Error(`Runtime links cannot be packaged: ${name}`)
      if (item.isDirectory()) await checkFiles(join(path, item.name), name + "/")
      else if (!item.isFile() || (name !== "SHA256SUMS" && !entries.has(name) && !allowedNotices.includes(name))) {
        throw new Error(`Unverified runtime payload: ${directory}/${name}`)
      }
    }
  }
  await checkFiles(root)
  return { files: entries.size, bytes }
}

export async function verifyVersions(root) {
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"))
  const config = JSON.parse(await readFile(join(root, "src-tauri/tauri.conf.json"), "utf8"))
  if (config.version !== pkg.version) throw new Error("Desktop and npm versions must match before packaging")
  for (const component of ["src-tauri", "cli", "engine", "vault"]) {
    const cargo = await readFile(join(root, component, "Cargo.toml"), "utf8")
    const cargoVersion = /^version\s*=\s*"([^"]+)"/m.exec(cargo.split(/\r?\n\[/)[0])?.[1]
    if (cargoVersion !== pkg.version) throw new Error(`${component} version must match ${pkg.version} before packaging`)
  }
  return config
}

export async function preflight(root, env = process.env) {
  releaseTarget(env, process.platform, releaseArchitecture(env))
  const config = await verifyVersions(root)
  if (config.bundle?.windows?.allowDowngrades !== false) throw new Error("Windows release installers must reject downgrades to older state handlers")
  const runtime = join(root, "src-tauri/resources/runtime")
  const totals = { files: 0, bytes: 0 }
  const required = {
    qemu: ["qemu-system-x86_64.exe", "qemu-img.exe", "share/edk2-x86_64-code.fd", "share/edk2-i386-vars.fd"],
    "qemu-secure": ["qemu-system-x86_64.exe", "opendock-tpm.dll", "opendock-tpm-init.exe", "opendock-tpm-worker.exe", "OVMF.qemuvars.fd", "secure-vars.json"],
    appliance: ["appliance-base.qcow2", "vmlinuz-virt", "initramfs-virt"],
    cuda: ["opendock-agent", "opendock-mount-helper", "opendock-cuda-probe", "yougori-oci-runtime-linux-amd64.tar.gz", "yougori-oci-runtime-linux-amd64.manifest.json", "yougori-nvidia-cdi-linux-amd64.tar.gz", "yougori-nvidia-cdi-linux-amd64.manifest.json"],
  }
  for (const part of process.platform !== "win32" ? ["appliance"] : ["qemu", "qemu-secure", "appliance", "cuda"]) {
    const allowed = part === "appliance" ? ["storage-notices/SOURCES.md", "storage-notices/musl-COPYRIGHT.txt", "storage-notices/e2fsprogs-NOTICE.txt", "storage-notices/BUILD-PACKAGES.txt"] : []
    const result = await verifyRuntimeDirectory(join(runtime, part), allowed, required[part])
    totals.files += result.files
    totals.bytes += result.bytes
  }
  return totals
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
    const result = await preflight(root)
    console.log(`Release payload verified: ${result.files} files, ${(result.bytes / 1e6).toFixed(1)} MB; ${process.platform} ${process.arch}. Installer, upgrade, guest lifecycle and signing checks on each supported platform are still required before distribution.`)
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
