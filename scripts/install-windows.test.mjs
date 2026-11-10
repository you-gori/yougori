import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"
import { pinPublisher } from "./release-manifest.mjs"

// Execute only platform selection, before any network, files, PATH or installs.
const script = pinPublisher(readFileSync(new URL("./install/install.ps1", import.meta.url), "utf8"), "CN=Installer Test")
const boundary = script.indexOf("Write-Host 'Finding the latest Yougori release...'")
assert.ok(boundary > 0)
// The desktop app's uninstall entry, read from FIXTURE_APP instead of this computer's registry.
const appEntry = `function Get-ItemProperty { if ($env:FIXTURE_APP) { [PSCustomObject]@{ InstallLocation = '"' + $env:FIXTURE_APP + '"'; DisplayVersion = $env:FIXTURE_APP_VERSION } } }\n`
const selection = appEntry + script.slice(0, boundary) + '\nWrite-Output $platform\n'
// A whole installer is longer than a command line may be: it runs from a file.
function powershellFile(t, code, env = {}) {
  const folder = mkdtempSync(join(tmpdir(), 'yougori script '))
  t.after(() => rmSync(folder, { recursive: true, force: true }))
  const file = join(folder, 'fixture.ps1')
  writeFileSync(file, '\ufeff' + code)
  return spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file], {
    encoding: 'utf8', windowsHide: true, timeout: 30000, env: { ...process.env, ...env },
  })
}
const powershell = (code, env = {}) => spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(code, 'utf16le').toString('base64')], {
  encoding: 'utf8', windowsHide: true, timeout: 30000, env: { ...process.env, ...env },
})
// A desktop app folder as its installer leaves it; `without` leaves files out.
function desktopApp(t, without = []) {
  const folder = mkdtempSync(join(tmpdir(), 'yougori app '))
  t.after(() => rmSync(folder, { recursive: true, force: true }))
  for (const name of ['yougori.exe', 'cli/yougori.exe', 'uninstall.exe'].filter(name => !without.includes(name))) {
    mkdirSync(join(folder, name, '..'), { recursive: true })
    writeFileSync(join(folder, name), 'fixture')
  }
  return folder
}

test("Windows installer refuses unsafe manifest URLs before network or installation", { skip: process.platform !== "win32" }, () => {
  for (const url of ['http://fixture.invalid/latest.json', 'https://user:private@fixture.invalid/latest.json', 'https://', 'not a URL']) {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(selection, 'utf16le').toString('base64')], {
      encoding: 'utf8', windowsHide: true, timeout: 15000,
      env: { ...process.env, YOUGORI_RELEASES_URL: url },
    })
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stdout, /YOUGORI_RELEASES_URL must use HTTPS without credentials/)
    assert.doesNotMatch(result.stdout + result.stderr, /user:private/)
  }
})

test("Windows installer requires valid signatures from its exact publisher", { skip: process.platform !== "win32" }, () => {
  const start = script.indexOf('function Assert-Signed')
  const end = script.indexOf('function Stop-InstalledEngine', start)
  for (const [status, publisher, expected] of [['Valid', 'CN=Installer Test', 0], ['NotSigned', 'CN=Installer Test', 7], ['Valid', 'CN=Other Publisher', 7]]) {
    const fixture = `$ErrorActionPreference='Stop'; $allowUnsigned=$false; $ExpectedPublisher='CN=Installer Test'; function Fail($message) { throw $message }; function Remove-Item {}; function Get-AuthenticodeSignature { param($LiteralPath); [PSCustomObject]@{ Status='${status}'; SignerCertificate=[PSCustomObject]@{ Subject='${publisher}' } } };\n${script.slice(start, end)}\ntry { Assert-Signed 'fixture.exe'; Write-Output 'VERIFIED' } catch { Write-Output $_.Exception.Message; exit 7 }`
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixture, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 15000 })
    assert.equal(result.status, expected, result.stderr)
    assert.match(result.stdout, expected ? /Nothing was installed/ : /VERIFIED/)
  }
})

test("Windows engine installs check every Yougori executable except the hash-checked runtime", { skip: process.platform !== "win32" }, t => {
  const root = mkdtempSync(join(tmpdir(), 'yougori payloads '))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  for (const name of ['yougori-engine.exe', 'cli/yougori.exe', 'cli/yougori-cli.exe', 'vault/yougori-vault.exe', 'vault/helper.DLL', 'runtime/qemu/qemu-system-x86_64.exe', 'runtime/qemu/libglib.dll', 'LICENSE']) {
    mkdirSync(join(root, name, '..'), { recursive: true })
    writeFileSync(join(root, name), 'fixture')
  }
  const start = script.indexOf('function Get-SignedPayloads')
  const fragment = script.slice(start, script.indexOf('function Stop-InstalledEngine', start))
  const run = extra => spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(`$ErrorActionPreference='Stop'; function Fail($message) { [Console]::Out.WriteLine("FAILED: $message"); exit 7 };\n${fragment}\n${extra}\nGet-SignedPayloads $env:FIXTURE_ROOT | ForEach-Object { $_.Substring($env:FIXTURE_ROOT.Length + 1) }`, 'utf16le').toString('base64')], {
    encoding: 'utf8', windowsHide: true, timeout: 15000, env: { ...process.env, FIXTURE_ROOT: root },
  })
  const result = run('')
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.stdout.trim().split(/\r?\n/).sort(), ['cli\\yougori-cli.exe', 'cli\\yougori.exe', 'vault\\helper.DLL', 'vault\\yougori-vault.exe', 'yougori-engine.exe'])
  const linked = run(`New-Item -ItemType Junction -Path (Join-Path $env:FIXTURE_ROOT 'cli\\linked') -Target $env:TEMP | Out-Null`)
  assert.equal(linked.status, 7, linked.stderr)
  assert.match(linked.stdout, /contains links\. Nothing was installed/)
})

for (const mode of ['offline', 'stops', 'refuses', 'timeout']) test(`Windows reinstall handles an engine that ${mode}`, { skip: process.platform !== "win32" }, t => {
  const root = mkdtempSync(join(tmpdir(), 'yougori reinstall '))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const cli = join(root, 'engine.cmd')
  const log = join(root, 'arguments.txt')
  const stopped = join(root, 'stopped.txt')
  writeFileSync(cli, `@echo off\n@echo %*>>"%FIXTURE_CLI_LOG%"\n@if "%2"=="quit" goto quit\n@if "%FIXTURE_MODE%"=="offline" goto offline\n@if exist "%FIXTURE_STOPPED%" goto offline\n@exit /b 0\n:quit\n@if "%FIXTURE_MODE%"=="refuses" exit /b 4\n@if "%FIXTURE_MODE%"=="stops" echo stopped>"%FIXTURE_STOPPED%"\n@exit /b 0\n:offline\n@echo engine offline 1>&2\n@exit /b 1\n`)
  const start = script.indexOf('function Stop-InstalledEngine')
  const fragment = script.slice(start, script.indexOf('function Start-InstalledEngine', start))
  const fixture = `$ErrorActionPreference='Stop'; function Fail($message) { throw $message }; function Start-Sleep { param($Seconds) };\n${fragment}\ntry { Stop-InstalledEngine $env:FIXTURE_CLI; Write-Output 'COPY_MAY_CONTINUE' } catch { Write-Output $_.Exception.Message; exit 7 }`
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixture, 'utf16le').toString('base64')], {
    encoding: 'utf8', windowsHide: true, timeout: 15000,
    env: { ...process.env, FIXTURE_MODE: mode, FIXTURE_CLI: cli, FIXTURE_CLI_LOG: log, FIXTURE_STOPPED: stopped },
  })
  assert.equal(result.status, ['refuses', 'timeout'].includes(mode) ? 7 : 0, result.stderr)
  const calls = readFileSync(log, 'utf8').trim().split(/\r?\n/)
  if (mode === 'offline') assert.deepEqual(calls, ['app status'])
  if (mode === 'stops') assert.deepEqual(calls, ['app status', 'app quit --yes', 'app status'])
  assert.match(result.stdout, ['refuses', 'timeout'].includes(mode) ? /Existing files were left untouched/ : /COPY_MAY_CONTINUE/)
})

for (const exit of [0, 1]) test(`Windows installer starts the installed engine and reports startup failure (exit ${exit})`, { skip: process.platform !== "win32" }, t => {
  const root = mkdtempSync(join(tmpdir(), 'yougori startup '))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const cli = join(root, 'engine.cmd')
  const log = join(root, 'arguments.txt')
  writeFileSync(cli, `@echo off\n@echo %*>>"%FIXTURE_CLI_LOG%"\n@if "%2"=="start" exit /b ${exit}\n@exit /b 0\n`)
  const start = script.indexOf('function Start-InstalledEngine')
  const fixture = `$ErrorActionPreference='Stop';\n${script.slice(start, boundary)}\nStart-InstalledEngine $env:FIXTURE_CLI; Write-Output 'INSTALL_COMPLETED'`
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixture, 'utf16le').toString('base64')], {
    encoding: 'utf8', windowsHide: true, timeout: 15000,
    env: { ...process.env, FIXTURE_CLI: cli, FIXTURE_CLI_LOG: log },
  })
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(readFileSync(log, 'utf8').trim().split(/\r?\n/), exit === 0 ? ['app start', 'doctor --format table'] : ['app start'])
  assert.match(result.stdout, /INSTALL_COMPLETED/)
  if (exit) assert.match(result.stdout + result.stderr, /files are installed, but engine startup failed/)
})

for (const exit of [0, 1]) test(`Windows skill setup uses the installed CLI and tolerates a conflict (exit ${exit})`, { skip: process.platform !== "win32" }, t => {
  const root = mkdtempSync(join(tmpdir(), "yougori skill setup "))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const cli = join(root, 'installed cli.ps1')
  const log = join(root, 'arguments.txt')
  writeFileSync(cli, `param($group, $verb)\n[IO.File]::WriteAllText($env:FIXTURE_SKILL_LOG, "$group $verb")\nWrite-Output '{"ok":true,"result":{"path":"fixture skill"}}'\nexit ${exit}\n`)
  const start = script.indexOf("Write-Host 'Setting up the Yougori skill...'")
  const end = script.indexOf("if ($env:YOUGORI_AUTOSTART", start)
  assert.ok(start > 0 && end > start)
  const fixture = `$ErrorActionPreference = 'Stop'; $cli = [PSCustomObject]@{ Source = $env:FIXTURE_SKILL_CLI };\n${script.slice(start,end)}\nWrite-Output 'INSTALL_COMPLETED'`
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixture,'utf16le').toString('base64')], {
    encoding:'utf8', windowsHide:true, timeout:15000,
    env:{...process.env, FIXTURE_SKILL_CLI:cli, FIXTURE_SKILL_LOG:log},
  })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(readFileSync(log,'utf8'), 'skills install')
  assert.match(result.stdout, /INSTALL_COMPLETED/)
  assert.match(result.stdout + result.stderr, exit === 0 ? /Yougori skill ready: fixture skill/ : /existing custom skills were preserved/)
})

test("Windows command downloads preserve the URL query and add command attribution", { skip: process.platform !== "win32" }, () => {
  const start = script.indexOf('# The server saves aggregate command/app totals')
  const end = script.indexOf('$hash =', start)
  assert.ok(start > 0 && end > start)
  const fragment = script.slice(start, end)
  for (const [url, expected] of [
    ['https://fixture.invalid/setup.exe', 'https://fixture.invalid/setup.exe?source=command'],
    ['https://fixture.invalid/setup.exe?download=1#fragment', 'https://fixture.invalid/setup.exe?download=1&source=command'],
  ]) {
    const fixture = `$asset = [PSCustomObject]@{ url = '${url}' }; $download = 'unused'; function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing); Write-Output $Uri }; function Fail($message) { throw $message };\n${fragment}`
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixture, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 15000 })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), expected)
  }
})

for (const [arch, platform] of [["AMD64", "x86_64"], ["ARM64", "aarch64"]]) {
  for (const override of [null, "", "1", "0"]) {
    test(`Windows ${arch} selects the engine by default (override ${override ?? "unset"})`, { skip: process.platform !== "win32" }, () => {
      const env = { ...process.env, PROCESSOR_ARCHITECTURE: arch, YOUGORI_ENGINE_ONLY: override, YOUGORI_ALLOW_UNSIGNED: "", FIXTURE_APP: "" }
      if (override === null) delete env.YOUGORI_ENGINE_ONLY
      const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(selection, "utf16le").toString("base64")], {
        encoding: "utf8", windowsHide: true, timeout: 15000, env,
      })
      if (result.error) throw result.error
      assert.equal(result.status, 0, result.stderr)
      assert.equal(result.stdout.trim(), `windows-${platform}${override === "0" ? "" : "-engine"}`)
    })
  }
}

for (const override of [null, "", "1", "0"]) test(`Windows with the desktop app installed updates the app unless asked otherwise (override ${override ?? "unset"})`, { skip: process.platform !== "win32" }, t => {
  const env = { PROCESSOR_ARCHITECTURE: "AMD64", YOUGORI_ENGINE_ONLY: override ?? "", YOUGORI_ALLOW_UNSIGNED: "", FIXTURE_APP: desktopApp(t), FIXTURE_APP_VERSION: "1.0.0" }
  const result = powershell(selection, env)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), override === "1" ? "windows-x86_64-engine" : "windows-x86_64")
})

test("Windows takes only a complete per-user app install for the desktop app", { skip: process.platform !== "win32" }, t => {
  // An MSI install has no uninstall.exe: the per-user installer cannot update it.
  for (const without of ['uninstall.exe', 'cli/yougori.exe', 'yougori.exe']) {
    const result = powershell(selection, { PROCESSOR_ARCHITECTURE: "AMD64", YOUGORI_ENGINE_ONLY: "", YOUGORI_ALLOW_UNSIGNED: "", FIXTURE_APP: desktopApp(t, [without]), FIXTURE_APP_VERSION: "1.0.0" })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), "windows-x86_64-engine", without)
  }
})

test("Windows compares the installed app with the release by version", { skip: process.platform !== "win32" }, () => {
  const start = script.indexOf('function Test-Current')
  const fragment = script.slice(start, script.indexOf('function Start-InstalledEngine', start))
  const cases = [['1.2.3', '1.2.3', true], ['1.2.4', '1.2.3', true], ['1.10.0', '1.9.0', true], ['1.2.0', '1.2.3', false], ['', '1.2.3', false], ['1.2.3-beta', '1.2.3', false]]
  const result = powershell(`${fragment}\n${cases.map(([have, offered]) => `Write-Output (Test-Current '${have}' '${offered}')`).join('\n')}`)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.stdout.trim().split(/\r?\n/), cases.map(([, , current]) => current ? 'True' : 'False'))
})

for (const [label, installed, standalone, exit] of [['an update', true, true, 0], ['a first install', false, false, 0], ['a failed install', true, false, 3]]) test(`Windows desktop app install stops Yougori before the installer runs (${label})`, { skip: process.platform !== "win32" }, t => {
  const app = desktopApp(t)
  const local = mkdtempSync(join(tmpdir(), 'yougori local '))
  t.after(() => rmSync(local, { recursive: true, force: true }))
  const engineCli = join(local, 'Yougori Engine', 'cli', 'yougori.exe')
  if (standalone) {
    mkdirSync(join(engineCli, '..'), { recursive: true })
    writeFileSync(engineCli, 'fixture')
  }
  const start = script.indexOf('function Install-DesktopApp')
  const fragment = script.slice(start, script.indexOf('function Test-Current', start))
  // Write-Host keeps the stubs' lines out of the function's result.
  const fixture = `$ErrorActionPreference = 'Stop'
function Fail($message) { Write-Host "FAILED: $message"; exit 7 }
function Assert-Signed($path) { Write-Host "signature $([IO.Path]::GetFileName($path))" }
function Stop-InstalledEngine($running) { Write-Host "stop $running" }
function Start-Process { param($FilePath, $ArgumentList, $WindowStyle, [switch]$Wait, [switch]$PassThru) Write-Host "installer $($ArgumentList -join ' ')"; [PSCustomObject]@{ ExitCode = [int]$env:FIXTURE_EXIT } }
function Find-DesktopApp { [PSCustomObject]@{ Folder = $env:FIXTURE_APP; Version = '2.0.0' } }
${fragment}
$installed = if ($env:FIXTURE_INSTALLED -eq '1') { [PSCustomObject]@{ Folder = $env:FIXTURE_APP; Version = '1.0.0' } } else { $null }
$app = Install-DesktopApp 'C:\\fixture\\Yougori_2.0.0_x64-setup.exe' $installed
Write-Host "installed $($app.Version)"`
  const result = powershell(fixture, { LOCALAPPDATA: local, FIXTURE_APP: app, FIXTURE_INSTALLED: installed ? '1' : '0', FIXTURE_EXIT: String(exit) })
  const lines = result.stdout.trim().split(/\r?\n/)
  const stops = [...(installed ? [`stop ${join(app, 'cli', 'yougori.exe')}`] : []), ...(standalone ? [`stop ${engineCli}`] : [])]
  if (exit) {
    assert.equal(result.status, 7, result.stdout + result.stderr)
    assert.deepEqual(lines, ['signature Yougori_2.0.0_x64-setup.exe', ...stops, 'Installing (this takes a minute)...', 'installer /S /UPDATE', 'FAILED: the installer exited with code 3.'])
    return
  }
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.deepEqual(lines, ['signature Yougori_2.0.0_x64-setup.exe', ...stops, 'Installing (this takes a minute)...', `installer ${installed ? '/S /UPDATE' : '/S'}`, 'installed 2.0.0'])
})

test("Windows skips the download when the desktop app is already this release", { skip: process.platform !== "win32" }, t => {
  const manifest = JSON.stringify({ version: '1.0.0', assets: { 'windows-x86_64': { url: 'https://fixture.invalid/Yougori_1.0.0_x64-setup.exe', sha256: 'a'.repeat(64), bytes: 1 } } })
  const fixture = `${appEntry}
function Invoke-RestMethod { param($Uri, [switch]$UseBasicParsing) $env:FIXTURE_MANIFEST | ConvertFrom-Json }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing) Write-Host "download $Uri"; throw 'offline' }
${script}`
  const result = powershellFile(t, fixture, { PROCESSOR_ARCHITECTURE: 'AMD64', YOUGORI_ENGINE_ONLY: '', YOUGORI_ALLOW_UNSIGNED: '1', YOUGORI_START_ENGINE: '0', YOUGORI_AUTOSTART: '',
    YOUGORI_RELEASES_URL: 'https://fixture.invalid/latest.json', FIXTURE_MANIFEST: manifest, FIXTURE_APP: desktopApp(t), FIXTURE_APP_VERSION: '1.0.0' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.doesNotMatch(result.stdout, /download /)
  assert.match(result.stdout, /The Yougori desktop app 1\.0\.0 is up to date\./)
  assert.match(result.stdout, /Yougori 1\.0\.0 is up to date\. Try: yougori status/)
})

test("Windows downloads the desktop app's installer when the installed app is older", { skip: process.platform !== "win32" }, t => {
  const manifest = JSON.stringify({ version: '1.1.0', assets: { 'windows-x86_64': { url: 'https://fixture.invalid/Yougori_1.1.0_x64-setup.exe', sha256: 'a'.repeat(64), bytes: 1 }, 'windows-x86_64-engine': { url: 'https://fixture.invalid/engine.zip', sha256: 'b'.repeat(64), bytes: 1 } } })
  const temp = mkdtempSync(join(tmpdir(), 'yougori download '))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  const fixture = `${appEntry}
function Invoke-RestMethod { param($Uri, [switch]$UseBasicParsing) $env:FIXTURE_MANIFEST | ConvertFrom-Json }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing) Write-Host "download $Uri"; throw 'offline' }
${script}`
  const result = powershellFile(t, fixture, { PROCESSOR_ARCHITECTURE: 'AMD64', YOUGORI_ENGINE_ONLY: '', YOUGORI_ALLOW_UNSIGNED: '1', TEMP: temp, TMP: temp,
    YOUGORI_RELEASES_URL: 'https://fixture.invalid/latest.json', FIXTURE_MANIFEST: manifest, FIXTURE_APP: desktopApp(t), FIXTURE_APP_VERSION: '1.0.0' })
  assert.equal(result.status, 1, result.stdout + result.stderr)
  assert.match(result.stdout, /Downloading Yougori 1\.1\.0 to update the desktop app \(now 1\.0\.0\)\.\.\./)
  assert.match(result.stdout, /download https:\/\/fixture\.invalid\/Yougori_1\.1\.0_x64-setup\.exe\?source=command/)
})
