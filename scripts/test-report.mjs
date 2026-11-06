// Agreed unit/contract/mocked suites only. No app, live engine, runtime workload or publication.
import { spawn, spawnSync } from "node:child_process"
import { writeFileSync } from "node:fs"
import { arch, cpus, homedir, platform, totalmem } from "node:os"
import path from "node:path"
import { performance } from "node:perf_hooks"
import { fileURLToPath, pathToFileURL } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const TARGET = "D:/tmp/codex-target"
const REPORT = "docs/template-platform/test-report"
const MAX_OUTPUT = 4 * 1024 * 1024
const SUITE_TIMEOUT_MS = 45 * 60 * 1_000

export const SUITES = [
  { id: "setup", command: "cargo", args: ["test", "--manifest-path", "setup/Cargo.toml"], evidence: "pure unit/contract test", fixture: "In-memory synthetic packages, temporary files and planner fixtures.", skips: [] },
  { id: "cli", command: "cargo", args: ["test", "--manifest-path", "cli/Cargo.toml", "--", "--skip", "swarm", "--skip", "bounty"], evidence: "mocked integration", fixture: "CLI unit/contract tests, temporary configuration and mocked services; no live engine.", skips: ["swarm", "bounty"] },
  { id: "grid", command: "cargo", args: ["test", "--manifest-path", "grid/Cargo.toml", "--", "--skip", "bounty"], evidence: "mocked integration", fixture: "Grid unit tests and synthetic/local mock-server fixtures; no live grid or bounty.", skips: ["bounty"] },
  { id: "engine", command: "cargo", args: ["test", "--manifest-path", "src-tauri/Cargo.toml", "--lib", "--", "--skip", "swarm::", "--skip", "bounty"], evidence: "mocked integration", fixture: "Native library unit tests and disposable/mock integration fixtures; real runtime tests remain ignored.", skips: ["swarm::", "bounty"] },
  { id: "desktop", command: "npx", args: ["vitest", "run", "--dir", "src"], evidence: "mocked integration", fixture: "Frontend unit/component tests with mocked engine calls and DOM fixtures; no desktop app.", skips: [] },
]

export function withoutAnsi(text) {
  // Terminal control sequences, without importing another package.
  return text.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
}

export function parseCounts(text, kind = "cargo") {
  const clean = withoutAnsi(text)
  if (kind === "cargo") {
    const matches = [...clean.matchAll(/test result: (ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;\s+(\d+) measured;\s+(\d+) filtered out;/g)]
    if (!matches.length) return null
    return matches.reduce((sum, match) => ({
      passed: sum.passed + Number(match[2]), failed: sum.failed + Number(match[3]),
      ignored: sum.ignored + Number(match[4]), measured: sum.measured + Number(match[5]),
      filtered: sum.filtered + Number(match[6]), targets: sum.targets + 1,
    }), { passed: 0, failed: 0, ignored: 0, measured: 0, filtered: 0, targets: 0 })
  }
  const line = /^\s*Tests\s+(.+)$/m.exec(clean)?.[1]
  if (!line) return null
  const counts = { passed: 0, failed: 0, ignored: 0, measured: 0, filtered: 0, targets: 0 }
  for (const match of line.matchAll(/(\d+)\s+(passed|failed|skipped|todo)\b/g)) {
    const key = match[2] === "skipped" || match[2] === "todo" ? "ignored" : match[2]
    counts[key] += Number(match[1])
  }
  const files = /^\s*Test Files\s+(.+)$/m.exec(clean)?.[1]
  for (const match of files?.matchAll(/(\d+)\s+(?:passed|failed|skipped)\b/g) ?? []) counts.targets += Number(match[1])
  return counts
}

export function resultStatus(exitCode, counts, timedOut = false) {
  if (timedOut) return "timed out"
  if (exitCode !== 0 || (counts?.failed ?? 0) > 0) return "failed"
  return counts ? "passed" : "incomplete: no test summary"
}

export function sanitise(text, root = ROOT, user = homedir()) {
  let safe = withoutAnsi(text)
  for (const [prefix, replacement] of [[root, "<repository>"], [TARGET, "<isolated-target>"], [user, "<user>"]]) {
    for (const variant of new Set([prefix, prefix.replaceAll("\\", "/"), prefix.replaceAll("/", "\\")])) {
      safe = safe.replaceAll(variant, replacement)
    }
  }
  return safe
}

export function invocation(suite, os = platform()) {
  // npx.cmd needs the Windows command interpreter. Every word is from SUITES, never user input.
  if (os === "win32" && suite.command === "npx") return { command: process.env.ComSpec || "cmd.exe", args: ["/d", "/s", "/c", [suite.command, ...suite.args].join(" ")] }
  return { command: suite.command, args: suite.args }
}

function sourceIdentity() {
  const git = args => {
    const got = spawnSync("git", args, { cwd: ROOT, encoding: "utf8", windowsHide: true })
    if (got.status !== 0) throw new Error("Read-only source identity lookup failed")
    return got.stdout.trim()
  }
  const status = git(["status", "--porcelain"])
  return { commit: git(["rev-parse", "HEAD"]), dirty: Boolean(status), changedPaths: status ? status.split(/\r?\n/).length : 0 }
}

export function runSuite(suite) {
  const launch = invocation(suite)
  const startedAt = new Date().toISOString()
  const began = performance.now()
  return new Promise(resolve => {
    let output = ""
    let timedOut = false
    let spawnError = ""
    const child = spawn(launch.command, launch.args, {
      cwd: ROOT, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env, CARGO_TARGET_DIR: TARGET, CARGO_NET_OFFLINE: "true", CARGO_INCREMENTAL: "0",
        CARGO_BUILD_JOBS: "4", CARGO_PROFILE_DEV_DEBUG: "0", CARGO_PROFILE_TEST_DEBUG: "0",
        npm_config_offline: "true", npm_config_yes: "false", NO_COLOR: "1", FORCE_COLOR: "0",
      },
    })
    const collect = chunk => { output = (output + chunk.toString()).slice(-MAX_OUTPUT) }
    child.stdout.on("data", collect)
    child.stderr.on("data", collect)
    child.on("error", error => { spawnError = sanitise(error.message) })
    const timeout = setTimeout(() => {
      timedOut = true
      // Only the test process tree we own, never the app or another build.
      if (platform() === "win32" && child.pid) spawnSync("taskkill", ["/pid", String(child.pid), "/t", "/f"], { windowsHide: true, stdio: "ignore" })
      else child.kill("SIGTERM")
    }, SUITE_TIMEOUT_MS)
    child.on("close", code => {
      clearTimeout(timeout)
      const counts = parseCounts(output, suite.command === "cargo" ? "cargo" : "vitest")
      const status = resultStatus(code, counts, timedOut)
      resolve({
        id: suite.id, command: [suite.command, ...suite.args].join(" "), evidence: suite.evidence,
        fixture: suite.fixture, skippedByPolicy: suite.skips, startedAt, finishedAt: new Date().toISOString(),
        durationSeconds: Math.round((performance.now() - began) / 10) / 100,
        exitCode: code, status, counts,
        diagnostic: status === "passed" ? null : spawnError || sanitise(output.split(/\r?\n/).slice(-55).join("\n")),
      })
    })
  })
}

const cell = value => String(value).replaceAll("|", "\\|").replaceAll("\n", " ")

export function markdown(report) {
  const lines = [
    "# Template platform test report", "",
    `Started ${report.startedAt}; finished ${report.finishedAt ?? "pending"}. Times are UTC.`, "",
    `Source: \`${report.source.commit}\`${report.source.dirty ? " **with uncommitted changes**" : " (clean tree)"}.`,
    `Machine: ${report.machine.os} ${report.machine.arch}; ${report.machine.logicalProcessors} logical processors; ${report.machine.memoryGiB} GiB RAM.`,
    "Evidence is assigned per suite: mocked integration suites also contain unit/contract tests. No row proves real-runtime acceptance or publication/download verification.", "",
    "The working tree is mutable while other agents work. This is not a frozen-source release acceptance report. Source identities are recorded before and after the run.", "",
    "| Suite | Exact command | Evidence level | Result | Seconds | Passed | Failed | Ignored/skipped | Filtered |",
    "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
  ]
  for (const suite of report.suites) lines.push(`| ${suite.id} | \`${cell(suite.command)}\` | ${suite.evidence} | ${suite.status} | ${suite.durationSeconds} | ${suite.counts?.passed ?? "unknown"} | ${suite.counts?.failed ?? "unknown"} | ${suite.counts?.ignored ?? "unknown"} | ${suite.counts?.filtered ?? "unknown"} |`)
  lines.push("", "## Policy and interpretation", "",
    "- Swarm Mining/bounty execution is excluded under `.claude/codex-board.md`. The exact Rust skip filters are in each command and in JSON. Pure setup-format fixtures do not run workers.",
    "- Ignored tests are not passes. The suites retain their own runtime/hardware prerequisites; this runner never enables ignored tests.",
    "- Filtered counts are Rust's aggregate counts; they do not identify individual skipped tests. No unexecuted test is reported as verified.",
    "- A successful command without a recognizable test summary is incomplete, not passed. Compilation failure can leave counts unknown or partial.",
    "- Cargo runs offline in `D:/tmp/codex-target` with four build jobs, incremental compilation off, and dev/test debug information disabled. It never uses the app's target directory. npm also runs offline.",
    "- Duration includes compilation for Cargo suites. The first run in the isolated cache can take much longer than warm-cache tests.", "", "## Fixture types", "")
  for (const suite of report.suites) lines.push(`- **${suite.id}:** ${suite.fixture}`)
  for (const suite of report.suites.filter(row => row.diagnostic)) lines.push("", `## ${suite.id} diagnostic`, "", "```text", suite.diagnostic.replaceAll("```", "'''"), "```")
  lines.push("", "## Source at completion", "", report.sourceAfter ? `\`${report.sourceAfter.commit}\`${report.sourceAfter.dirty ? " with uncommitted changes" : " (clean tree)"}; ${report.sourceAfter.changedPaths} changed paths.` : "Pending.", "")
  return lines.join("\n")
}

export async function runReport() {
  const report = {
    schema: 1, startedAt: new Date().toISOString(), finishedAt: null,
    source: sourceIdentity(), sourceAfter: null,
    machine: { os: platform(), arch: arch(), logicalProcessors: cpus().length, memoryGiB: Math.round(totalmem() / 1024 ** 3 * 100) / 100 },
    environment: { cargoTarget: TARGET, cargoOffline: true, cargoBuildJobs: 4, incremental: false, debugInfo: false, npmOffline: true },
    suites: [],
  }
  const write = () => {
    writeFileSync(path.join(ROOT, `${REPORT}.json`), `${JSON.stringify(report, null, 2)}\n`, "utf8")
    writeFileSync(path.join(ROOT, `${REPORT}.md`), markdown(report), "utf8")
  }
  write()
  for (const suite of SUITES) {
    process.stdout.write(`Running ${suite.id}: ${[suite.command, ...suite.args].join(" ")}\n`)
    const result = await runSuite(suite)
    report.suites.push(result)
    write()
    process.stdout.write(`${suite.id}: ${result.status}; ${result.durationSeconds}s; ${result.counts?.passed ?? "unknown"} passed\n`)
  }
  report.finishedAt = new Date().toISOString()
  report.sourceAfter = sourceIdentity()
  write()
  process.stdout.write(`Reports: ${REPORT}.md and .json\n`)
  return report.suites.every(suite => suite.status === "passed")
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length !== 2) {
    process.stderr.write("Usage: node scripts/test-report.mjs\n")
    process.exitCode = 1
  } else {
    try { if (!await runReport()) process.exitCode = 1 }
    catch (error) { process.stderr.write(`${sanitise(error.message)}\n`); process.exitCode = 1 }
  }
}
