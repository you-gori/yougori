import { spawnSync } from "node:child_process"
import { accessSync, constants } from "node:fs"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { nativeTarget } from "./release-preflight.mjs"

// Homebrew QEMU paths, used only by development builds that have no runtime from
// `npm run macos:runtime`. The app itself ships its own QEMU.
export function macosPaths(arch) {
  nativeTarget("darwin", arch)
  const prefix = arch === "arm64" ? "/opt/homebrew" : "/usr/local"
  const qemu = `${prefix}/opt/qemu`
  return { brew: `${prefix}/bin/brew`, qemu: `${qemu}/bin/qemu-system-x86_64`, image: `${qemu}/bin/qemu-img`,
    code: `${qemu}/share/qemu/edk2-x86_64-code.fd`, vars: `${qemu}/share/qemu/edk2-i386-vars.fd` }
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000, maxBuffer: 2 * 1024 * 1024 })
  if (result.error || result.status !== 0) throw new Error(`${command}: ${result.error?.message || result.stderr || "failed"}`)
  return result.stdout.trim()
}

// Checks, and with --install installs, what building the macOS app needs on a native Mac:
// Xcode command-line tools, plus Homebrew's meson, ninja and pkgconf to build the bundled QEMU
// runtime from its pinned sources. People who install the app need none of this.
export function checkMacos({ install = false } = {}) {
  if (process.platform !== "darwin") throw new Error("Run this step on a Mac (or the macOS GitHub workflow), not Windows or WSL.")
  if (process.getuid?.() === 0) throw new Error("Run Yougori setup/build as your normal Mac user, never sudo.")
  const paths = macosPaths(process.arch)
  const version = run("/usr/bin/sw_vers", ["-productVersion"])
  if (Number(version.split(".")[0]) < 14) throw new Error("Building Yougori for macOS needs macOS 14 or newer.")
  const translated = spawnSync("/usr/sbin/sysctl", ["-in", "sysctl.proc_translated"], { encoding: "utf8", timeout: 5000 })
  if (translated.stdout?.trim() === "1") throw new Error("This terminal/Node is running under Rosetta. Use native Apple Silicon Terminal, Node, Rust and Homebrew.")
  run("/usr/bin/xcode-select", ["-p"])
  try { accessSync(paths.brew, constants.X_OK) } catch {
    throw new Error(`Native Homebrew is missing at ${paths.brew}. Install it from https://brew.sh, then retry. This script does not download/execute an installer or request sudo.`)
  }
  if (install) {
    console.log("Installing build tools for the bundled QEMU runtime: meson, ninja and pkgconf. Nothing from Homebrew is shipped in the app.")
    const result = spawnSync(paths.brew, ["install", "meson", "ninja", "pkgconf"], { stdio: "inherit" })
    if (result.error || result.status !== 0) throw new Error(result.error?.message || "Homebrew installation failed")
  }
  const versions = []
  for (const tool of ["meson", "ninja", "pkg-config"]) {
    const found = spawnSync("/bin/sh", ["-c", `command -v ${tool}`], { encoding: "utf8" })
    if (found.status !== 0) throw new Error(`Missing build tool: ${tool}. Run npm run macos:setup (or brew install meson ninja pkgconf).`)
    versions.push(`${tool} ${run(tool, ["--version"]).split("\n")[0]}`)
  }
  console.log(`macOS ${version} · ${nativeTarget()}\n${versions.join("\n")}`)
  console.log(process.arch === "arm64"
    ? "Apple Silicon: x86-64 guests use QEMU's software CPU (slower). GPU/CUDA guests are not available on macOS."
    : "Intel: containers and full VMs use Apple's Hypervisor framework; microVMs use software emulation. GPU/CUDA is unavailable.")
  console.log("Build tools checked. Next: npm run macos:runtime builds the bundled QEMU; see docs/macos.md.")
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.slice(2).some(arg => arg !== "--install")) throw new Error("Usage: node scripts/macos-setup.mjs [--install]")
    checkMacos({ install: process.argv.includes("--install") })
  } catch (error) { console.error(error.message); process.exitCode = 1 }
}
