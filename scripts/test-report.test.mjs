import assert from "node:assert/strict"
import test from "node:test"
import { invocation, markdown, parseCounts, resultStatus, sanitise, SUITES } from "./test-report.mjs"

test("Rust counts include every completed target and preserve ignored and filtered counts", () => {
  const text = 'test result: ok. 70 passed; 0 failed; 2 ignored; 0 measured; 3 filtered out; finished in 0.1s\n' +
    'test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.1s\n'
  assert.deepEqual(parseCounts(text), { passed: 74, failed: 1, ignored: 2, measured: 0, filtered: 12, targets: 2 })
})

test("Vitest counts parse mixed failures and skips after removing ANSI colors", () => {
  assert.deepEqual(parseCounts('\u001b[32m Test Files  1 failed | 5 passed (6)\u001b[0m\n Tests  2 failed | 40 passed | 3 skipped (45)\n', "vitest"), { passed: 40, failed: 2, ignored: 3, filtered: 0, measured: 0, targets: 6 })
  assert.equal(parseCounts("Compilation failed."), null)
})

test("zero exit without test evidence is incomplete and compilation failures cannot pass", () => {
  assert.equal(resultStatus(0, null), "incomplete: no test summary")
  assert.equal(resultStatus(1, null), "failed")
  assert.equal(resultStatus(0, { failed: 1 }), "failed")
  assert.equal(resultStatus(0, { failed: 0 }), "passed")
  assert.equal(resultStatus(0, { failed: 0 }, true), "timed out")
})

test("suite commands retain the coordinator's exclusions and never opt into ignored tests", () => {
  assert.equal(SUITES.length, 5)
  assert.deepEqual(SUITES.find(suite => suite.id === "cli").skips, ["swarm", "bounty"])
  assert.deepEqual(SUITES.find(suite => suite.id === "grid").skips, ["bounty"])
  assert.deepEqual(SUITES.find(suite => suite.id === "engine").skips, ["swarm::", "bounty"])
  assert.ok(SUITES.every(suite => !suite.args.includes("--ignored") && !suite.args.includes("run" + "time")))
})

test("Windows npx uses a fixed command while Cargo is launched directly", () => {
  const desktop = SUITES.find(suite => suite.id === "desktop")
  assert.deepEqual(invocation(desktop, "win32").args, ["/d", "/s", "/c", "npx vitest run --dir src"])
  assert.equal(invocation(SUITES[0], "win32").command, "cargo")
  assert.equal(invocation(desktop, "linux").command, "npx")
})

test("diagnostics redact repository, isolated-target and personal prefixes", () => {
  assert.equal(sanitise("/fixture/repo/src/a.rs /fixture/user/.cargo/file D:/tmp/codex-target/debug", "/fixture/repo", "/fixture/user"), "<repository>/src/a.rs <user>/.cargo/file <isolated-target>/debug")
})

test("Markdown distinguishes dirty source, evidence, unknown counts and policy skips", () => {
  const output = markdown({
    startedAt: "2026-10-26T00:00:00Z", finishedAt: null,
    source: { commit: "a".repeat(40), dirty: true }, sourceAfter: null,
    machine: { os: "win32", arch: "x64", logicalProcessors: 24, memoryGiB: 64 },
    suites: [{ id: "engine", command: "cargo test -- --skip swarm::", evidence: "mocked integration", status: "failed", durationSeconds: 1, counts: null, fixture: "Disposable fake.", diagnostic: "Compile failed." }],
  })
  assert.match(output, /with uncommitted changes/)
  assert.match(output, /mocked integration/)
  assert.match(output, /unknown/)
  assert.match(output, /Ignored tests are not passes/)
  assert.match(output, /Compile failed/)
})
