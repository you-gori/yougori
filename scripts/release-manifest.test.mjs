import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { basename, dirname, join, relative } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"
import { engineArchiveSigner, manifest, parseArgs, pinAppleTeam, pinPublisher, signedPayloads, sourceMetadata, windowsSigner } from "./release-manifest.mjs"
import { enginePlatform, resourceMap } from "./package-engine.mjs"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")

test("release arguments need an HTTPS base and known platform keys", () => {
  const options = parseArgs(["--base-url", "https://yougori.com/releases/1.2.0/", "--notes", "n", "windows-x86_64=a.exe", "linux-x86_64-engine=b.tar.gz"])
  assert.equal(options.baseUrl, "https://yougori.com/releases/1.2.0")
  assert.deepEqual(options.assets, { "windows-x86_64": "a.exe", "linux-x86_64-engine": "b.tar.gz" })
  assert.throws(() => parseArgs(["--base-url", "http://x", "windows-x86_64=a.exe"]), /HTTPS/)
  assert.throws(() => parseArgs(["--base-url", "https://x", "windows=a.exe"]), /PLATFORM=PATH/)
  assert.throws(() => parseArgs(["--base-url", "https://x"]), /at least one/)
})

test("the manifest lists each asset's URL and hash in the shape the CLI and installers read", () => {
  const source = { url: "https://y.com/source.zip", sha256: "a".repeat(64), commit: "b".repeat(40) }
  const value = manifest("1.2.0", "notes", "https://y.com/r", { "windows-x86_64-engine": { name: "yougori engine.zip", sha256: "ab" } }, source)
  assert.deepEqual(value, { version: "1.2.0", notes: "notes", assets: { "windows-x86_64-engine": { url: "https://y.com/r/yougori%20engine.zip", sha256: "ab" } }, source })
  assert.throws(() => manifest("1", "", "https://y.com", {}), /requires matching source/)
})

test("release source links require completed publication and pinned source identity", () => {
  const report = { sourceCommit: "b".repeat(40), publication: { status: "verified", bundleUrl: "https://y.com/source.zip", bundleSha256: "a".repeat(64) } }
  assert.equal(sourceMetadata(report).commit, report.sourceCommit)
  assert.throws(() => sourceMetadata({ ...report, publication: { ...report.publication, status: "not-published" } }), /verified matching source/)
  assert.throws(() => sourceMetadata({ ...report, publication: { ...report.publication, bundleSha256: "" } }), /verified matching source/)
})

test("install.ps1 is pinned to the exact release signer and refuses to run unpinned", () => {
  const script = readFileSync(join(root, "scripts/install/install.ps1"), "utf8")
  const pinned = pinPublisher(script, "CN=Yougori O'Brien, O=Yougori, C=US")
  assert.match(pinned, /\$ExpectedPublisher = 'CN=Yougori O''Brien, O=Yougori, C=US'/)
  assert.match(pinned, /-eq \('__YOUGORI_' \+ 'PUBLISHER__'\)/)
  assert.match(pinned, /SignerCertificate\.Subject -eq \$ExpectedPublisher/)
  assert.throws(() => pinPublisher(pinned, "CN=Other"), /placeholder/)
})

test("install.sh is pinned to the release's Apple Developer ID team", () => {
  const script = readFileSync(join(root, "scripts/install/install.sh"), "utf8")
  const pinned = pinAppleTeam(script, "AB12CD34EF")
  assert.match(pinned, /^apple_team='AB12CD34EF'$/m)
  assert.match(pinned, /"__YOUGORI_APPLE_""TEAM_ID__"/)
  for (const team of ["", "ab12cd34ef", "AB12CD34E", "AB12CD34EF'"]) assert.throws(() => pinAppleTeam(script, team), /Apple Developer ID team/)
  assert.throws(() => pinAppleTeam(pinned, "AB12CD34EF"), /placeholder/)
  assert.equal(parseArgs(["--base-url", "https://y.com", "--apple-team-id", "AB12CD34EF", "macos-aarch64=a.dmg"]).appleTeamId, "AB12CD34EF")
})

function engineFolder(t, names) {
  const folder = mkdtempSync(join(tmpdir(), "yougori-engine-fixture-"))
  t.after(() => rmSync(folder, { recursive: true, force: true }))
  for (const name of names) {
    mkdirSync(join(folder, name, ".."), { recursive: true })
    writeFileSync(join(folder, name), name)
  }
  return folder
}
const payloads = ["yougori-engine.exe", "cli/yougori.exe", "cli/yougori-cli.exe", "vault/yougori-vault.exe"]

test("every Yougori executable in an engine archive is a signed payload, except the runtime", t => {
  const folder = engineFolder(t, [...payloads, "runtime/qemu/qemu-system-x86_64.exe", "runtime/qemu/libglib.DLL", "LICENSE"])
  assert.deepEqual(signedPayloads(folder).map(path => relative(folder, path).replaceAll("\\", "/")).sort(), [...payloads].sort())
  symlinkSync(join(folder, "cli"), join(folder, "vault/linked"), "junction")
  assert.throws(() => signedPayloads(folder), /must not contain links/)
})

test("Windows engine archives need one publisher for every executable", { skip: process.platform !== "win32" }, t => {
  const archive = folder => {
    const path = join(folder, "..", `${basename(folder)}.zip`)
    t.after(() => rmSync(path, { force: true }))
    const tar = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe")
    assert.equal(spawnSync(tar, ["-a", "-cf", path, "-C", folder, "."], { windowsHide: true }).status, 0)
    return path
  }
  const signed = []
  const signer = path => { signed.push(basename(path)); return basename(path) === "yougori-vault.exe" ? "CN=Other" : "CN=Yougori" }
  const complete = archive(engineFolder(t, [...payloads, "runtime/qemu/qemu-img.exe"]))
  assert.throws(() => engineArchiveSigner(complete, signer), /2 publishers/)
  assert.deepEqual(signed.sort(), ["yougori-cli.exe", "yougori-engine.exe", "yougori-vault.exe", "yougori.exe"])
  assert.equal(engineArchiveSigner(complete, () => "CN=Yougori"), "CN=Yougori")
  assert.throws(() => engineArchiveSigner(archive(engineFolder(t, ["yougori-engine.exe"])), () => "CN=Yougori"), /no cli\/yougori\.exe/)
})

test("engine packages use the desktop bundle's own resource map", () => {
  assert.equal(enginePlatform("win32", "x64"), "windows-x86_64-engine")
  assert.equal(enginePlatform("darwin", "arm64"), "macos-aarch64-engine")
  assert.equal(enginePlatform("linux", "arm64"), "linux-aarch64-engine")
  assert.throws(() => enginePlatform("sunos", "x64"))
  const windows = resourceMap("win32")
  assert.equal(windows["resources/runtime/"], "runtime/")
  assert.equal(windows["resources/cli/yougori.exe"], "cli/yougori.exe")
  assert.equal(windows["resources/vault/yougori-vault.exe"], "vault/yougori-vault.exe")
  assert.equal(resourceMap("linux")["resources/cli/yougori"], "cli/yougori")
})

test("Windows release verification handles paths with spaces and refuses unsigned payloads", { skip: process.platform !== "win32" }, () => {
  const folder = mkdtempSync(join(tmpdir(), "yougori-release-signature-"))
  try {
    const signed = join(folder, "signed executable with spaces.exe")
    copyFileSync(join(process.env.SystemRoot ?? "C:\\Windows", "System32/cmd.exe"), signed)
    assert.match(windowsSigner(signed), /O=Microsoft Corporation/)
    const unsigned = join(folder, "unsigned executable with spaces.exe")
    writeFileSync(unsigned, "Unsigned test fixture")
    assert.throws(() => windowsSigner(unsigned), /trusted, timestamped signature/)
  } finally { rmSync(folder, { recursive: true, force: true }) }
})
