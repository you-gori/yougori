import { spawnSync } from "node:child_process"
import { chmodSync, copyFileSync, mkdirSync, readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { signWindowsPayload } from "./windows-payload-signing.mjs"
import { signMacPayload } from "./macos-payload-signing.mjs"
import { assertPortableCli, assertMacCli, assertLinuxCli, portableCliBuildEnv, releaseTarget, nativeTarget, releaseArchitecture } from "./release-preflight.mjs"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
export function bundleCli(development = false, io = { spawnSync, readFileSync, copyFileSync, mkdirSync, chmodSync }) {
  const arch = releaseArchitecture()
  const target = development ? process.env.CARGO_BUILD_TARGET || null : releaseTarget(process.env, process.platform, arch) || nativeTarget(process.platform, arch)
  // The desktop and CLI both have a `yougori` target in the shared Cargo directory.
  // Build the identical compatibility entry point under its distinct name, then
  // install it as `yougori`; a desktop build can no longer replace our source file.
  const args = ["build", "--locked", "--bin", "yougori-cli", ...(development ? [] : ["--release"]), "--manifest-path", join(root, "cli/Cargo.toml")]
  if (target) args.push("--target", target)
  const result = io.spawnSync("cargo", args, { stdio: "inherit", cwd: root, windowsHide: true, env: development ? process.env : portableCliBuildEnv() })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`CLI build failed (${result.status ?? "signal"})`)
  const name = process.platform === "win32" ? "yougori.exe" : "yougori"
  const compatibilityName = process.platform === "win32" ? "yougori-cli.exe" : "yougori-cli"
  // Cargo config can override target-dir independently of CARGO_TARGET_DIR.
  const metadata = io.spawnSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", join(root, "cli/Cargo.toml")], { encoding: "utf8", cwd: root, windowsHide: true })
  if (metadata.error) throw metadata.error
  if (metadata.status !== 0) throw new Error(metadata.stderr || "Cannot resolve Cargo target directory")
  const targetRoot = JSON.parse(metadata.stdout).target_directory
  const destination = join(root, "src-tauri/resources/cli")
  const binary = development
    ? target ? join(targetRoot, target, "debug", compatibilityName) : join(targetRoot, "debug", compatibilityName)
    : join(targetRoot, target, "release", compatibilityName)
  if (development) {
    if (!io.readFileSync(binary).length) throw new Error("The development CLI is empty")
    const probe = io.spawnSync(binary, ["--version"], { encoding: "utf8", cwd: root, windowsHide: true, timeout: 10_000 })
    const version = JSON.parse(io.readFileSync(join(root, "package.json"), "utf8")).version
    const reported = /^yougori (\S+) \(protocol \d+\)$/.exec(probe.stdout?.trim() ?? "")
    if (!version || probe.error || probe.status !== 0 || reported?.[1] !== version) {
      throw new Error("The development bundle is not the expected Yougori CLI. Nothing was installed.")
    }
  } else if (process.platform === "win32") assertPortableCli(io.readFileSync(binary))
  else if (process.platform === "darwin") assertMacCli(io.readFileSync(binary), process.arch)
  else assertLinuxCli(io.readFileSync(binary), arch)
  io.mkdirSync(destination, { recursive: true })
  io.copyFileSync(binary, join(destination, name))
  if (process.platform === "win32" && !development) signWindowsPayload(root, join(destination, name))
  // The compatibility copy below keeps this signature.
  if (process.platform === "darwin" && !development) signMacPayload(join(destination, name))
  io.copyFileSync(join(destination, name), join(destination, compatibilityName))
  if (process.platform !== "win32") for (const file of [name, compatibilityName]) io.chmodSync(join(destination, file), 0o755)
  console.log(`Bundled ${development ? "development " : ""}${name} (no Node.js dependency at runtime)`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { bundleCli(process.argv.includes("--dev")) } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
