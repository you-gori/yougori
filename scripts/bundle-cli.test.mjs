import assert from "node:assert/strict"
import test from "node:test"
import { basename, join } from "node:path"
import { bundleCli } from "./bundle-cli.mjs"

function harness(probe = { status: 0, stdout: "yougori 1.2.0 (protocol 2)\n" }) {
  const calls = [], copies = []
  const targetRoot = join(process.cwd(), "unused-test-target")
  return {
    calls, copies, targetRoot,
    io: {
      spawnSync(command, args, options) {
        calls.push({ command, args, options })
        if (args[0] === "metadata") return { status: 0, stdout: JSON.stringify({ target_directory: targetRoot }) }
        if (args[0] === "build") return { status: 0 }
        assert.deepEqual(args, ["--version"])
        return probe
      },
      readFileSync: path => basename(path) === "package.json" ? '{"version":"1.2.0"}' : Buffer.from("binary"),
      copyFileSync: (from, to) => copies.push({ from, to }),
      mkdirSync() {}, chmodSync() {},
    },
  }
}

test("bundling uses the CLI's distinct Cargo target, never the desktop's yougori binary", () => {
  const h = harness()
  bundleCli(true, h.io)
  const build = h.calls.find(call => call.args[0] === "build")
  assert.equal(build.args[build.args.indexOf("--bin") + 1], "yougori-cli")
  const executable = process.platform === "win32" ? "yougori-cli.exe" : "yougori-cli"
  const binary = process.env.CARGO_BUILD_TARGET
    ? join(h.targetRoot, process.env.CARGO_BUILD_TARGET, "debug", executable)
    : join(h.targetRoot, "debug", executable)
  assert.equal(h.copies[0].from, binary)
  assert.equal(basename(h.copies[0].to), process.platform === "win32" ? "yougori.exe" : "yougori")
  assert.equal(h.copies[1].from, h.copies[0].to)
  const probe = h.calls.find(call => call.args[0] === "--version")
  assert.equal(probe.command, binary)
  assert.equal(probe.options.windowsHide, true)
  assert.equal(probe.options.timeout, 10_000)
})

test("wrong, stale or nonresponsive binaries cannot replace the bundled CLI", () => {
  for (const probe of [
    { status: 0, stdout: "" }, // A desktop instance can exit successfully without CLI output.
    { status: 0, stdout: "yougori 1.1.1 (protocol 2)" },
    { status: 1, stdout: "yougori 1.2.0 (protocol 2)" },
    { status: null, error: new Error("timeout") },
  ]) {
    const h = harness(probe)
    assert.throws(() => bundleCli(true, h.io), /not the expected Yougori CLI/)
    assert.deepEqual(h.copies, [])
  }
})

test("a failed Cargo build leaves the previous bundle untouched", () => {
  const h = harness()
  h.io.spawnSync = () => ({ status: 1 })
  assert.throws(() => bundleCli(true, h.io), /CLI build failed/)
  assert.deepEqual(h.copies, [])
})
