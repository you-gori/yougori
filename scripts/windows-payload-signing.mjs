import { spawnSync } from "node:child_process"
import { join } from "node:path"

// Release payloads are signed with YOUGORI_SIGN_CERT_SHA1. Without it the payload stays unsigned:
// that is reported, and fatal when YOUGORI_REQUIRE_SIGNING=1 (scripts/build-signed-windows.ps1).
// Local test builds may set YOUGORI_ALLOW_UNSIGNED=1 to acknowledge unsigned output.
// release-manifest.mjs refuses to publish unsigned Windows executables either way.
export function signWindowsPayload(root, path, env = process.env, run = spawnSync, warn = message => process.stderr.write(`${message}\n`)) {
  if (!env.YOUGORI_SIGN_CERT_SHA1) {
    if (env.YOUGORI_REQUIRE_SIGNING === "1") throw new Error(`Set YOUGORI_SIGN_CERT_SHA1 to sign ${path}; this release build requires signed Yougori executables`)
    if (env.YOUGORI_ALLOW_UNSIGNED !== "1") warn(`Warning: ${path} is unsigned. Release payloads need YOUGORI_SIGN_CERT_SHA1; set YOUGORI_ALLOW_UNSIGNED=1 to acknowledge a local test build.`)
    return false
  }
  const result = run("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", join(root, "scripts/sign-windows-release.ps1"), "-Action", "Sign", "-Path", path],
  { env, stdio: "inherit", windowsHide: true })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error("Release payload signing failed; packaging was stopped")
  return true
}
