// Build a native release candidate from current source, without commits or CI.
// The developer's index, installed binaries and running environments are untouched.
import { spawn, spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { createReadStream, createWriteStream } from "node:fs"
import { copyFile, cp, mkdir, readFile, stat, writeFile } from "node:fs/promises"
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { finished } from "node:stream/promises"
import { nativeTarget } from "./release-preflight.mjs"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const npmCli = join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js")

export function options(argv, sourceRoot = root) {
  let output
  let runtimeTests = false
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--output" && argv[i + 1] && !argv[i + 1].startsWith("--")) output = resolve(argv[++i])
    else if (argv[i] === "--runtime-tests") runtimeTests = true
    else throw new Error("Usage: npm run release:local -- --output NEW_DIRECTORY [--runtime-tests]")
  }
  if (!output) output = join(sourceRoot, "artifacts", `local-release-${new Date().toISOString().replace(/[:.]/g, "-")}`)
  const tail = relative(output, sourceRoot)
  if (!tail || (!isAbsolute(tail) && tail !== ".." && !tail.startsWith(`..${sep}`))) {
    throw new Error("Release output must not contain the developer checkout")
  }
  return { output, runtimeTests }
}

export async function checksum(path) {
  const hash = createHash("sha256")
  for await (const chunk of createReadStream(path)) hash.update(chunk)
  return hash.digest("hex")
}

// Explicit versioned names prevent an old package in Cargo's bundle directory
// from being silently selected. Missing packages stop the candidate build.
export function packageNames(version, platform = process.platform, arch = process.arch) {
  nativeTarget(platform, arch)
  if (!/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(version)) throw new Error("Invalid release version")
  if (platform === "win32") return [
    `nsis/Yougori_${version}_x64-setup.exe`, `msi/Yougori_${version}_x64_en-US.msi`,
  ]
  if (platform === "linux") return [`deb/Yougori_${version}_${arch === "arm64" ? "arm64" : "amd64"}.deb`]
  return [`dmg/Yougori_${version}_${arch === "arm64" ? "aarch64" : "x64"}.dmg`]
}

export async function recordArtifact(source, output, name) {
  if (name !== name.replaceAll("\\", "/").split("/").at(-1) || !name || name === "." || name === "..") {
    throw new Error("Artifact name must be a file name")
  }
  const destination = join(output, name)
  const expected = await checksum(source)
  await copyFile(source, destination, 1) // COPYFILE_EXCL: never overwrite an earlier candidate
  const actual = await checksum(destination)
  if (actual !== expected) throw new Error(`Artifact changed while copying: ${name}`)
  return { file: name, sha256: actual, bytes: (await stat(destination)).size }
}

export async function runStep(name, command, args, { cwd, env, logs, timeoutMs = 3_600_000 }) {
  const logName = `${name}.log`
  const log = createWriteStream(join(logs, logName), { flags: "wx" })
  const started = Date.now()
  console.log(`RUN ${name} (log: ${join(logs, logName)})`)
  const child = spawn(command, args, { cwd, env, windowsHide: true, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] })
  child.stdout.pipe(log, { end: false })
  child.stderr.pipe(log, { end: false })
  let timedOut = false
  const terminate = () => {
    if (!child.pid) return
    if (process.platform === "win32") {
      spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" })
    } else {
      try { process.kill(-child.pid, "SIGKILL") } catch (failure) { if (failure.code !== "ESRCH") throw failure }
    }
  }
  const timer = setTimeout(() => { timedOut = true; terminate() }, timeoutMs)
  const interrupt = () => { timedOut = true; terminate() }
  process.once("SIGINT", interrupt)
  process.once("SIGTERM", interrupt)
  let code
  let error
  try {
    code = await new Promise((accept, reject) => {
      child.once("error", reject)
      child.once("close", accept)
    })
  } catch (failure) { error = failure.message }
  finally {
    clearTimeout(timer)
    process.removeListener("SIGINT", interrupt)
    process.removeListener("SIGTERM", interrupt)
    log.end()
    await finished(log)
  }
  const result = { name, exitCode: code ?? null, seconds: Math.round((Date.now() - started) / 1000), log: `logs/${logName}`, timedOut, ...(error ? { error } : {}) }
  console.log(`${!error && !timedOut && code === 0 ? "PASS" : "FAIL"} ${name} (${result.seconds}s)`)
  return result
}

async function main() {
  const target = nativeTarget()
  const { output, runtimeTests } = options(process.argv.slice(2))
  const cudaTestDistro = process.env.YOUGORI_CUDA_WSL_TEST_DISTRO
  if (process.platform === "win32" && runtimeTests && !cudaTestDistro) {
    throw new Error("Windows runtime release requires explicit YOUGORI_CUDA_WSL_TEST_DISTRO for the owned inert CUDA preflight fixture")
  }
  if (cudaTestDistro && !/^[A-Za-z0-9][A-Za-z0-9-]{0,100}$/.test(cudaTestDistro)) {
    throw new Error("YOUGORI_CUDA_WSL_TEST_DISTRO must be a literal owned test distribution name")
  }
  await mkdir(output) // A candidate is immutable: existing directories are rejected.
  const logs = join(output, "logs")
  await mkdir(logs)
  const candidate = join(output, "checkout")
  const python = process.platform === "win32" ? "python" : "python3"
  const report = { schemaVersion: 1, status: "building", productionReady: false, target, startedAt: new Date().toISOString(), source: {}, checks: [], artifacts: [], outstanding: [
    "Trusted platform signing and timestamp/notarization verification",
    "Clean-machine installation, real version upgrade, uninstall and retained-data validation",
    "Release-specific engineering review and verified public matching-source delivery",
    "Native macOS builds and runtime acceptance on both architectures",
    "Account-backed model/cloud acceptance with a defined resource budget",
  ] }
  const save = () => writeFile(join(output, "release-report.json"), JSON.stringify(report, null, 2) + "\n")
  const baseEnv = { ...process.env }
  // Candidate source metadata must not inherit a different checkout's Git index.
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete baseEnv[key]
  const unitEnv = { ...baseEnv }
  // Native WSL is exercised explicitly below, not implicitly by the wildcard
  // unit suite. Default/unsupported runs report the five native cases skipped.
  delete unitEnv.YOUGORI_CUDA_WSL_TEST_DISTRO
  const step = async (name, command, args, cwd = candidate, env = baseEnv) => {
    const result = await runStep(name, command, args, { cwd, env, logs })
    report.checks.push(result)
    await save()
    if (result.error || result.timedOut || result.exitCode !== 0) throw new Error(`${name} failed. See ${join(output, result.log)}`)
  }
  // Test fixtures create their own repositories. Never expose the candidate's
  // Git overrides to tests: git -C alone does not override GIT_WORK_TREE/index.
  const npm = (name, args, env = baseEnv) => process.platform === "win32"
    ? step(name, process.execPath, [process.env.npm_execpath || npmCli, ...args], candidate, env)
    : step(name, "npm", args, candidate, env)
  let candidateEnv
  try {
    await save()
    await step("runtime-integrity", process.execPath, ["scripts/release-preflight.mjs"], root)
    await step("snapshot", python, ["scripts/prepare-release-checkout.py", candidate, "--runtime", join(root, "src-tauri/resources/runtime")], root)
    const gitEnv = JSON.parse(await readFile(join(output, "checkout.environment.json"), "utf8"))
    candidateEnv = { ...baseEnv, ...gitEnv }
    // Only verified corresponding-source archives and collector records are
    // copied; build caches, extracted upstream trees and credentials stay out.
    await cp(join(root, "build/compliance/bundle"), join(candidate, "build/compliance/bundle"), { recursive: true })
    const oldReport = JSON.parse(await readFile(join(candidate, "compliance/release.json"), "utf8"))
    for (const name of ["local", "application", "alpine", "msys", "go", "go-main", "debian"]) {
      const source = join(root, `build/compliance/${name}-sources.json`)
      await copyFile(source, join(candidate, `build/compliance/${name}-sources.json`))
    }
    report.source.baseCommit = oldReport.sourceCommit
    report.tools = { node: process.version }
    for (const [tool, command, args] of [["cargo", "cargo", ["--version"]], ["rustc", "rustc", ["--version"]], ["python", python, ["--version"]], ["npm", process.platform === "win32" ? process.execPath : "npm", process.platform === "win32" ? [process.env.npm_execpath || npmCli, "--version"] : ["--version"]]]) {
      const result = spawnSync(command, args, { env: candidateEnv, encoding: "utf8", windowsHide: true })
      if (result.status !== 0) throw new Error(`Cannot identify ${tool} toolchain`)
      report.tools[tool] = result.stdout.trim()
    }
    await npm("locked-dependencies", ["ci"])
    await step("frontend-inventory", python, ["-c", 'import runpy; g=runpy.run_path("scripts/collect-compliance.py",run_name="library"); g["write_json"](g["EVIDENCE"] / "frontend-dependencies.json", g["frontend_inventory"]())'], candidate, candidateEnv)
    // Generated dependency notices are application source inputs. Refresh them
    // before archiving the exact source, then record the completed archive set.
    await step("source-notices", python, ["scripts/collect-compliance.py", "report"], candidate, candidateEnv)
    await step("source-material", python, ["scripts/collect-compliance.py", "material"], candidate, candidateEnv)
    await step("source-report", python, ["scripts/collect-compliance.py", "report"], candidate, candidateEnv)
    report.source.applicationManifestSha256 = await checksum(join(candidate, "compliance/evidence/application-source.json"))
    report.source.meaning = "Exact uncommitted source is identified by the application manifest, not the base commit."
    await step("compliance", process.execPath, ["scripts/compliance-check.mjs", "--preview"], candidate, candidateEnv)
    if (process.platform === "win32") await step("test-prerequisites", "pwsh", ["-NoProfile", "-File", "scripts/check-windows-test-prerequisites.ps1"], candidate, candidateEnv)
    await npm("dependency-audit", ["audit", "--audit-level=moderate"])
    await npm("lint", ["run", "lint"])
    await npm("unit-tests", ["test"], unitEnv)
    await npm("cuda-setup-tests", ["run", "test:cuda-setup"], unitEnv)
    await npm("source-collector-tests", ["run", "test:compliance"])
    await step("snapshot-tests", python, ["scripts/prepare-release-checkout.test.py"], candidate, candidateEnv)
    await step("cuda-payload-tests", python, ["runtime/cuda/test_install_oci.py"], candidate, candidateEnv)
    if (process.platform === "win32" && cudaTestDistro) {
      await step("cuda-wsl-preflight-native", process.execPath,
        ["--test", "--test-reporter=tap", "scripts/cuda-wsl-preflight-native.test.mjs"], candidate, baseEnv)
      const summary = await readFile(join(logs, "cuda-wsl-preflight-native.log"), "utf8")
      for (const [name, value] of [["tests", 5], ["pass", 5], ["fail", 0], ["skipped", 0]]) {
        if (!new RegExp(`^# ${name} ${value}\\s*$`, "m").test(summary)) {
          throw new Error("Native CUDA preflight must report exactly five passing tests and zero skips")
        }
      }
      report.cudaWslPreflight = { distribution: cudaTestDistro, tests: 5, passed: 5, skipped: 0 }
      await save()
    }
    if (process.platform === "linux") await step("mount-helper-tests", python, ["appliance/test_mount_helper.py"], candidate, candidateEnv)
    await npm("frontend-build", ["run", "build"])
    await npm("browser-install", ["exec", "--", "playwright", "install", "chromium", "--no-shell"])
    await npm("browser-tests", ["run", "test:e2e"])
    if (process.platform === "win32") await npm("bounded-test-harness", ["run", "test:harness"])
    // Sequential checks also keep cache-cleanup regressions independent from
    // concurrent Cargo processes and avoid competing native builds.
    for (const [name, action, manifest, extra] of [
      ["cli-tests", "test", "cli/Cargo.toml", []],
      ["cuda-host-tests", "test", "runtime/cuda/host/Cargo.toml", []],
      ["vault-tests", "test", "vault/Cargo.toml", []],
      ["desktop-check", "check", "src-tauri/Cargo.toml", ["--all-targets"]],
      ["desktop-tests", "test", "src-tauri/Cargo.toml", ["--lib"]],
      ["engine-check", "check", "engine/Cargo.toml", ["--all-targets"]],
    ]) await step(name, "cargo", [action, "--locked", "--manifest-path", manifest, ...extra], candidate, baseEnv)
    if (runtimeTests) {
      if (process.platform !== "win32") throw new Error("--runtime-tests uses the Windows disposable runtime gate; use the platform runtime script on Linux/macOS")
      await step("native-runtime", "pwsh", ["-NoProfile", "-File", "scripts/test-production-runtime.ps1"], candidate, candidateEnv)
    }
    await npm("desktop-package", ["run", "desktop:build", "--", "--config", "src-tauri/tauri.preview.conf.json"], candidateEnv)
    await npm("engine-package", ["run", "engine:package", "--", "--preview"], candidateEnv)
    await step("matching-sources", python, ["scripts/package-compliance.py"], candidate, candidateEnv)
    await step("final-source-integrity", process.execPath, ["scripts/compliance-check.mjs", "--preview"], candidate, candidateEnv)
    report.source.applicationManifestSha256 = await checksum(join(candidate, "compliance/evidence/application-source.json"))
    const metadata = spawnSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", "src-tauri/Cargo.toml"], { cwd: candidate, env: candidateEnv, encoding: "utf8", windowsHide: true })
    if (metadata.status !== 0) throw new Error("Cannot locate the built desktop packages")
    const cargoTarget = JSON.parse(metadata.stdout).target_directory
    const bundle = join(cargoTarget, baseEnv.CARGO_BUILD_TARGET || "", "release/bundle")
    const version = JSON.parse(await readFile(join(candidate, "package.json"), "utf8")).version
    const assets = join(output, "packages")
    await mkdir(assets)
    const { readdir } = await import("node:fs/promises")
    const os = { win32: "windows", linux: "linux", darwin: "macos" }[process.platform]
    const cpu = process.arch === "arm64" ? "aarch64" : "x86_64"
    const engineName = `yougori-engine-${version}-${os}-${cpu}-preview.${process.platform === "win32" ? "zip" : "tar.gz"}`
    const paths = packageNames(version).map(name => join(bundle, name))
    paths.push(join(candidate, "artifacts/engine", engineName))
    for (const name of await readdir(join(candidate, "build/compliance/dist"))) {
      if (name.endsWith(".zip")) paths.push(join(candidate, "build/compliance/dist", name))
    }
    const cli = process.platform === "win32" ? "yougori.exe" : "yougori"
    paths.push(join(candidate, "src-tauri/resources/cli", cli))
    for (const path of paths) report.artifacts.push(await recordArtifact(path, assets, path.replaceAll("\\", "/").split("/").at(-1)))
    await writeFile(join(assets, "SHA256SUMS"), report.artifacts.map(item => `${item.sha256}  ${item.file}\n`).join(""))
    await copyFile(join(candidate, "compliance/release.json"), join(output, "compliance-release.json"))
    await copyFile(join(candidate, "compliance/evidence/application-source.json"), join(output, "application-source.json"))
    report.status = "candidate-ready"
    await writeFile(join(output, "README.txt"), `Yougori ${version} — local ${target} candidate\n\nPackages and matching sources: packages/\nExact hashes: packages/SHA256SUMS\nChecks and remaining release requirements: release-report.json\n\nNo commit, publishing, installation or live runtime replacement was performed.\nThese unsigned candidates are for validation; productionReady remains false\nuntil signing, native installation and release acceptance requirements pass.\n`)
    console.log(`Candidate ready: ${output}`)
  } catch (error) {
    report.status = "failed"
    report.error = error.message
    throw error
  } finally {
    report.finishedAt = new Date().toISOString()
    await save()
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1 })
}
