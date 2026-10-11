import assert from "node:assert/strict"
import test from "node:test"
import { signMacPayload } from "./macos-payload-signing.mjs"

test("mac payloads are signed for notarization only with an explicit identity", () => {
  const calls = []
  const run = (command, args) => { calls.push([command, ...args]); return { status: 0 } }
  assert.equal(signMacPayload("/stage/cli/yougori", { YOUGORI_MAC_SIGNING_IDENTITY: "Developer ID Application: Yougori (TEAM123456)" }, run), true)
  assert.deepEqual(calls, [
    ["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp", "--sign", "Developer ID Application: Yougori (TEAM123456)", "/stage/cli/yougori"],
    ["/usr/bin/codesign", "--verify", "--strict", "/stage/cli/yougori"],
  ])
  const warnings = []
  assert.equal(signMacPayload("/stage/cli/yougori", {}, () => assert.fail("must not sign"), message => warnings.push(message)), false)
  assert.equal(warnings.length, 1)
  assert.equal(signMacPayload("/stage/cli/yougori", { YOUGORI_ALLOW_UNSIGNED: "1" }, () => assert.fail("must not sign"), () => assert.fail("acknowledged")), false)
  assert.throws(() => signMacPayload("/stage/cli/yougori", { YOUGORI_REQUIRE_SIGNING: "1", YOUGORI_ALLOW_UNSIGNED: "1" }), /YOUGORI_MAC_SIGNING_IDENTITY/)
  assert.throws(() => signMacPayload("/stage/cli/yougori", { YOUGORI_MAC_SIGNING_IDENTITY: "id" }, () => ({ status: 1 })), /packaging was stopped/)
})
