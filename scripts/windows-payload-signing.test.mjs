import { test } from "node:test"
import assert from "node:assert/strict"
import { signWindowsPayload } from "./windows-payload-signing.mjs"

const mustNotRun = () => { throw new Error("must not run") }

test("development bundling does not request a signing identity but reports unsigned output", () => {
  const warnings = []
  assert.equal(signWindowsPayload("C:/repo", "C:/repo/cli.exe", {}, mustNotRun, message => warnings.push(message)), false)
  assert.match(warnings.join("\n"), /cli\.exe is unsigned/)
  const acknowledged = []
  assert.equal(signWindowsPayload("C:/repo", "C:/repo/cli.exe", { YOUGORI_ALLOW_UNSIGNED: "1" }, mustNotRun, message => acknowledged.push(message)), false)
  assert.deepEqual(acknowledged, [])
})
test("a signed release build fails instead of producing unsigned payloads", () => {
  assert.throws(() => signWindowsPayload("C:/repo", "C:/repo/cli.exe", { YOUGORI_REQUIRE_SIGNING: "1", YOUGORI_ALLOW_UNSIGNED: "1" }, mustNotRun),
    /requires signed Yougori executables/)
})
test("signed bundling passes paths as arguments and propagates signing failure", () => {
  const env = { YOUGORI_SIGN_CERT_SHA1: "a".repeat(40) }
  assert.throws(() => signWindowsPayload("C:/source with spaces", "C:/output/app.exe", env, (command, args, options) => {
    assert.equal(command, "powershell.exe")
    assert.equal(args.at(-1), "C:/output/app.exe")
    assert.equal(options.env, env)
    assert.equal(options.windowsHide, true)
    return { status: 1 }
  }), /signing failed/)
})
test("a successfully signed payload may proceed to packaging", () => {
  assert.equal(signWindowsPayload("C:/repo", "C:/repo/cli.exe", { YOUGORI_SIGN_CERT_SHA1: "a".repeat(40) }, () => ({ status: 0 })), true)
})
