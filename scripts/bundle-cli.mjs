import { spawnSync } from "node:child_process"
import { chmodSync, copyFileSync, mkdirSync, readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { signWindowsPayload } from "./windows-payload-signing.mjs"
import { signMacPayload } from "./macos-payload-signing.mjs"
import { assertPortableCli, assertMacCli, assertLinuxCli, portableCliBuildEnv, releaseTarget, nativeTarget, releaseArchitecture } from "./release-preflight.mjs"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const development = process.argv.includes("--dev")
const arch = releaseArchitecture()
const target = development ? process.env.CARGO_BUILD_TARGET || null : releaseTarget(process.env, process.platform, arch) || nativeTarget(process.platform, arch)
const args = ["build", "--locked", ...(development ? [] : ["--release"]), "--manifest-path", join(root, "cli/Cargo.toml")]
if (target) args.push("--target", target)
const result = spawnSync("cargo", args, { stdio: "inherit", cwd: root, windowsHide: true, env: development ? process.env : portableCliBuildEnv() })
if (result.error) throw result.error
if (result.status !== 0) process.exit(result.status ?? 1)
const name = process.platform === "win32" ? "yougori.exe" : "yougori"
// Cargo config can override target-dir independently of CARGO_TARGET_DIR.
const metadata = spawnSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", join(root, "cli/Cargo.toml")], { encoding: "utf8", cwd: root, windowsHide: true })
if (metadata.error) throw metadata.error
if (metadata.status !== 0) throw new Error(metadata.stderr || "Cannot resolve Cargo target directory")
const targetRoot = JSON.parse(metadata.stdout).target_directory
const destination = join(root, "src-tauri/resources/cli")
mkdirSync(destination, { recursive: true })
const binary = development
  ? target ? join(targetRoot, target, "debug", name) : join(targetRoot, "debug", name)
  : join(targetRoot, target, "release", name)
if (development) {
  if (!readFileSync(binary).length) throw new Error("The development CLI is empty")
} else if (process.platform === "win32") assertPortableCli(readFileSync(binary))
else if (process.platform === "darwin") assertMacCli(readFileSync(binary), process.arch)
else assertLinuxCli(readFileSync(binary), arch)
copyFileSync(binary, join(destination, name))
if (process.platform === "win32" && !development) signWindowsPayload(root, join(destination, name))
// The compatibility copy below keeps this signature.
if (process.platform === "darwin" && !development) signMacPayload(join(destination, name))
const compatibilityName = process.platform === "win32" ? "yougori-cli.exe" : "yougori-cli"
copyFileSync(join(destination, name), join(destination, compatibilityName))
if (process.platform !== "win32") for (const file of [name, compatibilityName]) chmodSync(join(destination, file), 0o755)
console.log(`Bundled ${development ? "development " : ""}${name} (no Node.js dependency at runtime)`)
