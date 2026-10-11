import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"
import { pinAppleTeam } from "./release-manifest.mjs"

const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "bash"
const unix = path => path.replaceAll("\\", "/").replace(/^([A-Za-z]):/, (_, drive) => `/${drive.toLowerCase()}`)
const unpinned = readFileSync(new URL("./install/install.sh", import.meta.url), "utf8").replaceAll("\r\n", "\n")
const script = pinAppleTeam(unpinned, "AB12CD34EF")

function install(t, { extension = "deb", assetQuery = "", assetUrl = null, manifestUrl = "https://fixture.invalid/latest.json", badHash = false, aptExit = "0", skillExit = "0", engineOnly = "0", os = "Linux", arch = "x86_64", assetKey = "linux-x86_64", shell = "/bin/bash", startEngine = "1", shadowCli = false, profiles = {}, source = script, allowUnsigned = "", codesignExit = "0" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "yougori-installer-"))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const bin = join(root, "bin")
  mkdirSync(bin)
  const stubs = {
    uname: 'if [ "$1" = "-s" ]; then echo "$FIXTURE_OS"; else echo "$FIXTURE_ARCH"; fi',
    id: 'echo 1000',
    curl: 'printf "%s\\n" "$@" >> "$FIXTURE_CURL_LOG"; case "$*" in *latest.json*) printf "%s" "$FIXTURE_MANIFEST" ;; *) while [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then shift; printf "package" > "$1"; exit 0; fi; shift; done; exit 1 ;; esac',
    sudo: 'exec "$@"',
    "apt-get": 'printf "%s\\n" "$@" > "$FIXTURE_APT_LOG"; exit "$FIXTURE_APT_EXIT"',
    ln: '[ "$1" = "-sf" ] && { [ "$2" = "/usr/bin/yougori" ] || [ "$2" = "$HOME/.local/opt/yougori-engine/cli/yougori" ]; } && [ "$3" = "$HOME/.local/bin/yougori" ] && cp "$FIXTURE_BIN/yougori" "$3" && chmod 755 "$3"',
    tar: 'while [ "$#" -gt 0 ]; do if [ "$1" = "-C" ]; then shift; mkdir -p "$1/cli"; printf "fixture engine" > "$1/yougori-engine"; printf "fixture cli" > "$1/cli/yougori"; exit 0; fi; shift; done; exit 1',
    codesign: 'printf "%s\\n" "$*" >> "$FIXTURE_CODESIGN_LOG"; exit "$FIXTURE_CODESIGN_EXIT"',
    yougori: 'printf "%s\\n" "$*" >> "$FIXTURE_CLI_LOG"; if [ "$1" = "skills" ] && [ "$FIXTURE_SKILL_EXIT" != 0 ]; then echo "Existing custom skill left unchanged" >&2; exit "$FIXTURE_SKILL_EXIT"; fi; exit 0',
    "qemu-system-x86_64": 'exit 0',
    "qemu-img": 'exit 0',
    ldconfig: 'echo "libgtk-3.so.0"',
  }
  for (const [name, body] of Object.entries(stubs)) {
    const path = join(bin, name)
    writeFileSync(path, `#!/bin/sh\n${body}\n`)
    chmodSync(path, 0o755)
  }
  const sha = createHash("sha256").update("package").digest("hex")
  const log = join(root, "apt.log")
  const home = join(root, "home")
  mkdirSync(home)
  for (const [name, text] of Object.entries(profiles)) writeFileSync(join(home, name), text)
  const cliLog = join(root, "cli.log")
  const codesignLog = join(root, "codesign.log")
  const curlLog = join(root, "curl.log")
  const shadow = join(root, "shadow")
  if (shadowCli) {
    mkdirSync(shadow)
    writeFileSync(join(shadow, "yougori"), '#!/bin/sh\necho "An older Yougori command ran" >&2\nexit 41\n')
    chmodSync(join(shadow, "yougori"), 0o755)
  }
  const env = { ...process.env, HOME: unix(home), SHELL: shell, YOUGORI_START_ENGINE: startEngine, FIXTURE_CLI_LOG: unix(cliLog), FIXTURE_BIN: unix(bin), FIXTURE_OS: os,
      FIXTURE_ARCH: arch, FIXTURE_SKILL_EXIT: skillExit, YOUGORI_ENGINE_ONLY: engineOnly, YOUGORI_AUTOSTART: "", YOUGORI_RELEASES_URL: manifestUrl,
      FIXTURE_APT_LOG: unix(log), FIXTURE_APT_EXIT: aptExit, FIXTURE_CODESIGN_LOG: unix(codesignLog), FIXTURE_CODESIGN_EXIT: codesignExit, YOUGORI_ALLOW_UNSIGNED: allowUnsigned, FIXTURE_CURL_LOG: unix(curlLog), FIXTURE_SHADOW: shadowCli ? unix(shadow) : "", FIXTURE_HOME_BIN: shadowCli ? unix(join(home, ".local/bin")) : "",
      FIXTURE_MANIFEST: JSON.stringify({ version: "1.0.0", assets: { [assetKey]: { url: assetUrl ?? `https://fixture.invalid/Yougori.${extension}${assetQuery}`, sha256: badHash ? "0".repeat(64) : sha } } }),
  }
  if (engineOnly === null) delete env.YOUGORI_ENGINE_ONLY
  const rerun = () => spawnSync(bash, ["--noprofile", "--norc", "-c", 'export PATH="${FIXTURE_SHADOW:+$FIXTURE_SHADOW:}$FIXTURE_BIN:${FIXTURE_HOME_BIN:+$FIXTURE_HOME_BIN:}$PATH"; /bin/sh -s'], {
    input: source, encoding: "utf8", timeout: 15000, env,
  })
  const result = rerun()
  if (result.error) throw result.error
  return { result, rerun, home, codesign: existsSync(codesignLog) ? readFileSync(codesignLog, "utf8") : "", curl: existsSync(curlLog) ? readFileSync(curlLog, "utf8") : "", cli: existsSync(cliLog) ? readFileSync(cliLog, "utf8") : "", apt: existsSync(log) ? readFileSync(log, "utf8") : null, engineInstalled: existsSync(join(root, "home/.local/opt/yougori-engine/yougori-engine")), cliInstalled: existsSync(join(root, "home/.local/opt/yougori-engine/cli/yougori")) }
}

test("Unix installer refuses unsafe manifest and download URLs before installing", t => {
  for (const url of ['http://fixture.invalid/latest.json', 'https://user:private@fixture.invalid/latest.json', 'https://']) {
    const manifest = install(t, { manifestUrl: url })
    assert.notEqual(manifest.result.status, 0)
    assert.equal(manifest.curl, "")
    assert.match(manifest.result.stderr, /HTTPS without credentials/)
    assert.doesNotMatch(manifest.result.stdout + manifest.result.stderr, /user:private/)
    const download = install(t, { assetUrl: url })
    assert.notEqual(download.result.status, 0)
    assert.equal(download.apt, null)
    assert.match(download.result.stderr, /HTTPS without credentials/)
    assert.doesNotMatch(download.curl, /user:private/)
  }
})

test("command downloads are attributed without changing the package filename or existing query", t => {
  const plain = install(t)
  assert.equal(plain.result.status, 0, plain.result.stderr)
  assert.match(plain.curl, /https:\/\/fixture.invalid\/Yougori\.deb\?source=command\n/)
  const query = install(t, { assetQuery: "?download=1#fragment" })
  assert.equal(query.result.status, 0, query.result.stderr)
  assert.match(query.curl, /https:\/\/fixture.invalid\/Yougori\.deb\?download=1&source=command\n/)
  assert.match(query.apt, /Yougori\.deb\n$/)
})

test("piped install preserves Bash profiles and saves PATH exactly once", t => {
  const original = 'export USER_SETTING="keep me"\n'
  const fixture = install(t, { profiles: { ".profile": original, ".bashrc": original, ".bash_profile": original } })
  assert.equal(fixture.result.status, 0, fixture.result.stderr)
  assert.match(fixture.result.stdout, /In this terminal, run:\nexport PATH=/)
  assert.match(fixture.cli, /^skills install\napp start\ndoctor --format table\n$/)
  assert.equal(fixture.rerun().status, 0)
  for (const name of [".profile", ".bashrc", ".bash_profile"]) {
    const content = readFileSync(join(fixture.home, name), "utf8")
    assert.ok(content.startsWith(original))
    assert.equal(content.match(/# Yougori CLI PATH/g).length, 1)
    const result = spawnSync(bash, ["--noprofile", "--norc", "-c", '. "$HOME/$PROFILE"; . "$HOME/$PROFILE"; printf "%s" "$PATH"'], {
      encoding: "utf8", env: { ...process.env, HOME: unix(fixture.home), PROFILE: name },
    })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.split(":").filter(entry => entry === unix(join(fixture.home, ".local/bin"))).length, 1)
  }
})

test("Zsh installs configure both login and interactive shells", t => {
  const { result, home } = install(t, { shell: "/bin/zsh" })
  assert.equal(result.status, 0, result.stderr)
  for (const name of [".zprofile", ".zshrc"]) assert.match(readFileSync(join(home, name), "utf8"), /# Yougori CLI PATH/)
})

test("automation can skip engine startup without reporting an expected failure", t => {
  const { result, cli } = install(t, { startEngine: "0" })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(cli, "skills install\n")
  assert.match(result.stdout, /Engine startup skipped/)
  assert.doesNotMatch(result.stdout, /FAIL/)
})

test("startup and diagnostics use this installation when an older CLI shadows PATH", t => {
  const { result, cli } = install(t, { shadowCli: true })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(cli, "skills install\napp start\ndoctor --format table\n")
  assert.doesNotMatch(result.stderr, /older Yougori command/)
})

test("a custom skill conflict does not interrupt installing or starting Yougori", t => {
  const { result, cli } = install(t, { skillExit: "1" })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(cli, "skills install\napp start\ndoctor --format table\n")
  assert.match(result.stderr, /Existing custom skill left unchanged/)
  assert.match(result.stdout, /Yougori 1\.0\.0 is installed/)
})

for (const arch of ["aarch64", "arm64"]) test(`Linux ${arch} installs the ARM64 CLI and engine`, t => {
  const { result, apt, engineInstalled, cliInstalled } = install(t, { arch, engineOnly: null, assetKey: "linux-aarch64-engine", extension: "tar.gz" })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(apt, null)
  assert.equal(engineInstalled && cliInstalled, true)
})

for (const [os, platform] of [["Linux", "linux"], ["Darwin", "macos"]]) {
  for (const engineOnly of [null, "", "1"]) test(`${os} command installs CLI and engine without the desktop (override ${engineOnly ?? "unset"})`, t => {
    const { result, apt, engineInstalled, cliInstalled } = install(t, { os, engineOnly, assetKey: `${platform}-x86_64-engine`, extension: "tar.gz" })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(apt, null)
    assert.equal(engineInstalled, true)
    assert.equal(cliInstalled, true)
    assert.match(result.stdout, /engine only, no desktop app/)
  })
}

test("macOS engine installs verify the engine and CLI against the pinned Developer ID team", t => {
  const options = { os: "Darwin", engineOnly: "1", assetKey: "macos-x86_64-engine", extension: "tar.gz" }
  const pinned = install(t, options)
  assert.equal(pinned.result.status, 0, pinned.result.stderr)
  const checks = pinned.codesign.trim().split("\n")
  assert.equal(checks.length, 2)
  for (const [check, binary] of [[checks[0], "/yougori-engine"], [checks[1], "/cli/yougori"]]) {
    assert.match(check, /^--verify --strict -R=anchor apple generic and certificate leaf\[subject\.OU\] = "AB12CD34EF" /)
    assert.ok(check.endsWith(binary), check)
  }
  const rejected = install(t, { ...options, codesignExit: "1" })
  assert.notEqual(rejected.result.status, 0)
  assert.match(rejected.result.stderr, /signature is not valid/)
  assert.equal(rejected.engineInstalled, false)
  const unprepared = install(t, { ...options, source: unpinned })
  assert.notEqual(unprepared.result.status, 0)
  assert.match(unprepared.result.stderr, /not prepared for a macOS release/)
  assert.equal(unprepared.engineInstalled, false)
  const allowed = install(t, { ...options, source: unpinned, allowUnsigned: "1" })
  assert.equal(allowed.result.status, 0, allowed.result.stderr)
  assert.doesNotMatch(allowed.codesign, /-R=/)
})

test("default CLI install never falls back to a desktop-only release", t => {
  const { result, apt, engineInstalled } = install(t, { engineOnly: null })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /no download for linux-x86_64-engine/)
  assert.equal(apt, null)
  assert.equal(engineInstalled, false)
})

test("Linux download installer installs the verified Debian package with its dependencies", t => {
  const { result, apt } = install(t)
  assert.equal(result.status, 0, result.stderr)
  assert.match(apt, /^install\n-y\n.*Yougori\.deb\n$/)
  assert.match(result.stdout, /1\.0\.0 is installed/)
})

test("Linux download installer stops before installation on a hash or package format mismatch", t => {
  for (const options of [{ badHash: true }, { extension: "AppImage" }]) {
    const { result, apt } = install(t, options)
    assert.notEqual(result.status, 0)
    assert.equal(apt, null)
    assert.match(result.stderr, /SHA-256|expected a \.deb/)
  }
})

test("Linux download installer reports package manager failures", t => {
  const { result } = install(t, { aptExit: "42" })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /package installation failed/)
  assert.doesNotMatch(result.stdout, /is installed/)
})
