// Packages the standalone engine (no desktop app) for CLI-only installs:
//   yougori-engine[.exe], cli/yougori[.exe], runtime/, vault/ and the licence files,
// with exactly the resources the desktop bundle maps for this platform, laid out beside the
// engine (it looks for them there). Writes artifacts/engine/yougori-engine-VERSION-PLATFORM.zip
// (Windows) or .tar.gz and prints its SHA-256 for the release manifest.
// Run `npm run cli:bundle` first so resources/cli holds the current CLI.
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { signWindowsPayload } from "./windows-payload-signing.mjs"
import { signMacPayload } from "./macos-payload-signing.mjs"
import { assertMacCli, assertPortableCli, assertLinuxCli, nativeTarget, portableCliBuildEnv, preflight, releaseTarget, releaseArchitecture } from "./release-preflight.mjs"
import { checkCompliance } from "./compliance-check.mjs"
import { checkInstalledLicenses } from "./check-installed-licenses.mjs"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const tauri = join(root, "src-tauri")

export function enginePlatform(platform = process.platform, arch = releaseArchitecture()) {
  nativeTarget(platform, arch)
  const os = { win32: "windows", darwin: "macos", linux: "linux" }[platform]
  const cpu = { x64: "x86_64", arm64: "aarch64" }[arch]
  if (!os || !cpu) throw new Error(`Unsupported platform ${platform}/${arch}`)
  return `${os}-${cpu}-engine`
}

/** The desktop bundle's resource map for this platform: source (relative to src-tauri) -> destination. */
export function resourceMap(platform = process.platform) {
  const file = { win32: "tauri.windows.conf.json", darwin: "tauri.macos.conf.json", linux: "tauri.linux.conf.json" }[platform]
  const resources = JSON.parse(readFileSync(join(tauri, file), "utf8")).bundle?.resources
  if (!resources || Array.isArray(resources)) throw new Error(`${file} must map bundle.resources as source -> destination`)
  return resources
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", cwd: root, windowsHide: true, ...options })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed`)
}

export function buildEngine({ projectRoot = root, platform = process.platform, arch = releaseArchitecture(), env = process.env, execute = spawnSync } = {}) {
  const target = releaseTarget(env, platform, arch) || nativeTarget(platform, arch)
  const buildEnv = portableCliBuildEnv(env, platform)
  const manifest = join(projectRoot, "engine/Cargo.toml")
  const options = { cwd: projectRoot, env: buildEnv, windowsHide: true }
  const built = execute("cargo", ["build", "--locked", "--release", "--target", target, "--manifest-path", manifest], { ...options, stdio: "inherit" })
  if (built.error || built.status !== 0) throw new Error(built.error?.message || "Engine build failed")
  const metadata = execute("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", manifest], { ...options, encoding: "utf8" })
  if (metadata.error || metadata.status !== 0) throw new Error(metadata.error?.message || metadata.stderr || "Cannot resolve engine Cargo target directory")
  const binary = join(JSON.parse(metadata.stdout).target_directory, target, "release", platform === "win32" ? "yougori-engine.exe" : "yougori-engine")
  const bytes = readFileSync(binary)
  if (platform === "win32") assertPortableCli(bytes, "Engine")
  else if (platform === "darwin") assertMacCli(bytes, arch)
  else assertLinuxCli(bytes, arch, "engine")
  return binary
}

async function main() {
  const args = process.argv.slice(2)
  if (args.some(arg => arg !== "--preview")) throw new Error("Usage: node scripts/package-engine.mjs [--preview]")
  const preview = args.includes("--preview")
  await preflight(root)
  await checkCompliance(root, { packaging: !preview, preview })
  const version = JSON.parse(readFileSync(join(tauri, "tauri.conf.json"), "utf8")).version
  const platform = enginePlatform()
  const exe = process.platform === "win32" ? "yougori-engine.exe" : "yougori-engine"
  const binary = buildEngine()
  const name = `yougori-engine-${version}-${platform.replace(/-engine$/, "")}${preview ? "-preview" : ""}`
  const out = join(root, "artifacts/engine")
  const stage = join(out, name)
  rmSync(stage, { recursive: true, force: true })
  mkdirSync(stage, { recursive: true })
  for (const [source, destination] of Object.entries(resourceMap())) {
    const from = resolve(tauri, source)
    if (!existsSync(from)) throw new Error(`Missing bundle resource ${source}; build it before packaging`)
    const to = join(stage, destination)
    mkdirSync(statSync(from).isDirectory() ? to : dirname(to), { recursive: true })
    cpSync(from, to, { recursive: true })
  }
  cpSync(binary, join(stage, exe))
  if (process.platform === "win32") signWindowsPayload(root, join(stage, exe))
  else chmodSync(join(stage, exe), 0o755)
  if (process.platform === "darwin") signMacPayload(join(stage, exe))
  await checkInstalledLicenses(root, stage, { win32: "windows", darwin: "macos", linux: "linux" }[process.platform])
  const archive = join(out, process.platform === "win32" ? `${name}.zip` : `${name}.tar.gz`)
  rmSync(archive, { force: true })
  // Windows' own bsdtar writes zip (Git's GNU tar on PATH would read C: as a remote host).
  const tar = process.platform === "win32" ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe") : "tar"
  run(tar, process.platform === "win32" ? ["-a", "-cf", archive, "-C", stage, "."] : ["-czf", archive, "-C", stage, "."])
  rmSync(stage, { recursive: true, force: true })
  const sha256 = createHash("sha256").update(readFileSync(archive)).digest("hex")
  console.log(JSON.stringify({ platform, archive, sha256, bytes: statSync(archive).size }))
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1 })
}
