import { spawnSync } from "node:child_process"

// macOS release payloads (CLI, standalone engine) are signed with the "Developer ID Application"
// identity named by YOUGORI_MAC_SIGNING_IDENTITY: hardened runtime and a secure timestamp, as
// notarization requires. Without it they keep the linker's ad-hoc signature, which is reported and
// fatal when YOUGORI_REQUIRE_SIGNING=1. Local test builds may set YOUGORI_ALLOW_UNSIGNED=1.
export function signMacPayload(path, env = process.env, run = spawnSync, warn = message => process.stderr.write(`${message}\n`)) {
  const identity = env.YOUGORI_MAC_SIGNING_IDENTITY
  if (!identity) {
    if (env.YOUGORI_REQUIRE_SIGNING === "1") throw new Error(`Set YOUGORI_MAC_SIGNING_IDENTITY to sign ${path}; this release build requires signed Yougori executables`)
    if (env.YOUGORI_ALLOW_UNSIGNED !== "1") warn(`Warning: ${path} has only an ad-hoc signature. Release payloads need YOUGORI_MAC_SIGNING_IDENTITY; set YOUGORI_ALLOW_UNSIGNED=1 to acknowledge a local test build.`)
    return false
  }
  for (const args of [["--force", "--options", "runtime", "--timestamp", "--sign", identity, path], ["--verify", "--strict", path]]) {
    const result = run("/usr/bin/codesign", args, { env, stdio: "inherit" })
    if (result.error) throw result.error
    if (result.status !== 0) throw new Error(`Signing ${path} failed; packaging was stopped`)
  }
  return true
}
