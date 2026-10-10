import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { cp, mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import test from "node:test"

const windows = { skip: process.platform !== "win32" }
const runtime = resolve("runtime/cuda")
// Cold Windows PowerShell startup includes two .NET processes in the pipe tests.
// Keep the timeout bounded while allowing hosted runners to initialize them.
const powershellTimeoutMs = 30_000
const extended = path => `\\\\?\\${path}`

test("Windows PowerShell 5 transfers CUDA archive bytes without a UTF-8 BOM", windows, async () => {
  const root = await mkdtemp(join(tmpdir(), "yougori-cuda-pipe-"))
  try {
    const source = join(root, "payload.bin")
    const target = join(root, "received.bin")
    const receiver = join(root, "receive.ps1")
    const harness = join(root, "transfer.ps1")
    const bytes = Buffer.from(Array.from({ length: 1024 }, (_, i) => i % 256))
    await writeFile(source, bytes)
    await writeFile(receiver, String.raw`param([string]$Destination)
$outputFile = [IO.File]::Create($Destination)
try { [Console]::OpenStandardInput().CopyTo($outputFile) } finally { $outputFile.Dispose() }
`)
    await writeFile(harness, String.raw`param([string]$Installer, [string]$Source, [string]$Receiver, [string]$Destination)
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Send-CudaPayload' }, $true)
. ([scriptblock]::Create($function.Extent.Text))
[Console]::InputEncoding = [Text.UTF8Encoding]::new($true)
$command = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Receiver + '" -Destination "' + $Destination + '"'
Send-CudaPayload ([Diagnostics.ProcessStartInfo]::new('powershell.exe', $command)) $Source
if ([Console]::InputEncoding.GetPreamble().Length -ne 3) { throw 'The caller encoding was not restored' }
`)
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness, join(runtime, "install.ps1"), source, receiver, target], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
    assert.ifError(result.error)
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(await readFile(target), bytes)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test("CUDA payload transfer reports the WSL failure when the receiver closes its pipe", windows, async () => {
  const root = await mkdtemp(join(tmpdir(), "yougori-cuda-closed-pipe-"))
  try {
    const source = join(root, "payload.bin")
    const receiver = join(root, "reject.ps1")
    const harness = join(root, "transfer.ps1")
    // Exceed a pipe buffer so the receiver exits during the actual binary copy.
    await writeFile(source, Buffer.alloc(8 * 1024 * 1024, 7))
    await writeFile(receiver, String.raw`
$message = [Text.Encoding]::Unicode.GetBytes('Failed to attach CUDA disk. The system cannot find the path specified.')
$outputStream = [Console]::OpenStandardOutput()
$outputStream.Write($message, 0, $message.Length)
$outputStream.Flush()
[Console]::Error.WriteLine('Wsl/Service/CreateInstance/MountDisk/HCS/ERROR_PATH_NOT_FOUND')
exit 57
`)
    await writeFile(harness, String.raw`param([string]$Installer, [string]$Source, [string]$Receiver)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ast = [Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Send-CudaPayload' }, $true)
. ([scriptblock]::Create($function.Extent.Text))
[Console]::InputEncoding = [Text.UTF8Encoding]::new($true)
$command = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Receiver + '"'
try {
    Send-CudaPayload ([Diagnostics.ProcessStartInfo]::new('powershell.exe', $command)) $Source
} catch {
    if ([Console]::InputEncoding.GetPreamble().Length -ne 3) { throw 'The caller encoding was not restored after failure' }
    Write-Output ('TRANSFER_ERROR: ' + $_.Exception.Message)
    exit 29
}
throw 'An incomplete transfer must fail'
`)
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness, join(runtime, "install.ps1"), source, receiver], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
    assert.ifError(result.error)
    assert.equal(result.status, 29, result.stderr)
    assert.match(result.stdout, /TRANSFER_ERROR: Installing the CUDA runtime payload failed \(exit 57\): Failed to attach CUDA disk\..*ERROR_PATH_NOT_FOUND/)
    assert.doesNotMatch(result.stdout, /TRANSFER_ERROR: .*CopyTo/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test("Windows PowerShell 5 accepts canonical CUDA paths, spaces, brackets and UNC paths", windows, async () => {
  const root = await mkdtemp(join(tmpdir(), "yougori-cuda-paths-"))
  try {
    const harness = join(root, "check.ps1")
    await writeFile(harness, String.raw`param([string]$Helper, [string]$Candidate)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
. $Helper
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Expected the Windows PowerShell used by packaged setup' }
$normalized = Get-CudaWindowsPath $Candidate
$sibling = Join-Path ([IO.Path]::GetDirectoryName($normalized)) 'opendock-mount-helper'
@{ path = $normalized; sibling = $sibling } | ConvertTo-Json -Compress
`)
    // GitHub's Windows TEMP can contain an 8.3 alias such as RUNNER~1.
    // Keep that spelling as input; .NET Framework expands it to the long path.
    const canonicalRoot = await realpath(root)
    const unc = "\\\\server\\share\\CUDA files\\opendock-agent"
    for (const [candidate, expected] of [
      [join(root, "CUDA [files] & spaces", "opendock-agent"), join(canonicalRoot, "CUDA [files] & spaces", "opendock-agent")],
      [unc, unc],
    ]) {
      const prefixed = candidate.startsWith("\\\\") ? `\\\\?\\UNC\\${candidate.slice(2)}` : extended(candidate)
      for (const value of [candidate, prefixed]) {
        const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness, join(runtime, "paths.ps1"), value], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
        assert.ifError(result.error)
        assert.equal(result.status, 0, result.stderr)
        const output = JSON.parse(result.stdout.trim())
        assert.equal(output.path, expected)
        assert.equal(output.sibling, expected.replace(/opendock-agent$/, "opendock-mount-helper"))
      }
    }
    for (const candidate of ["relative\\agent", "C:agent", "\\agent"]) {
      const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", harness, join(runtime, "paths.ps1"), candidate], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
      assert.ifError(result.error)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /absolute Windows filesystem paths/)
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test("packaged CUDA update stages every helper from canonical paths and reports the real failure", windows, async () => {
  const root = await mkdtemp(join(tmpdir(), "yougori-cuda-setup-"))
  try {
    const data = join(root, "Data [owned] & spaces")
    const assets = join(root, "Setup assets")
    const payload = join(root, "Bundled payload")
    await Promise.all([mkdir(data), mkdir(assets), mkdir(payload)])
    for (const name of ["install.ps1", "paths.ps1", "wsl.conf", "setup.sh", "start.sh", "install-oci.py"]) await cp(join(runtime, name), join(assets, name))
    const payloadNames = ["opendock-agent", "opendock-mount-helper", "opendock-cuda-probe", "yougori-oci-runtime-linux-amd64.tar.gz", "yougori-oci-runtime-linux-amd64.manifest.json", "yougori-nvidia-cdi-linux-amd64.tar.gz", "yougori-nvidia-cdi-linux-amd64.manifest.json"]
    for (const name of payloadNames) await writeFile(join(payload, name), name)
    await writeFile(join(payload, "SHA256SUMS"), payloadNames.map(name => `${createHash("sha256").update(name).digest("hex")}  ${name}\n`).join(""))
    await writeFile(join(data, "installed.json"), "existing manifest must survive")
    await writeFile(join(data, "saved-container-marker"), "saved container data")
    await mkdir(join(data, "distribution"))
    await writeFile(join(data, "distribution/ext4.vhdx"), "existing CUDA disk")
    // The installer derives ownership after expanding short path components.
    const digest = createHash("sha256").update((await realpath(data)).toLowerCase()).digest("hex")
    const distro = `OpenDock-CUDA-${digest.slice(0, 12)}`
    const harness = join(root, "stage.ps1")
    // Stub external WSL, registry and download calls. The real install script
    // stages real files and must stop before launching a distribution.
    await writeFile(harness, String.raw`param([string]$Script, [string]$DataPath, [string]$Agent, [string]$Assets, [string]$Distro, [switch]$AllowRecovery)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$global:FixtureData = $DataPath.Substring(4)
$global:FixtureDistro = $Distro
$global:RecoveryDone = $false
function global:wsl.exe {
    if (($args -join ' ') -eq ('--unregister ' + $global:FixtureDistro) -and $AllowRecovery) {
        $global:RecoveryDone = $true
        [IO.File]::WriteAllText((Join-Path $global:FixtureData 'unregistered-empty-fixture'), 'yes')
    } elseif (($args -join ' ') -notin @('--status', '--list --running --quiet')) { throw ('Unexpected WSL mutation: ' + ($args -join ' ')) }
    $global:LASTEXITCODE = 0
}
function global:curl.exe { throw 'Unexpected CUDA runtime download' }
function global:Get-ChildItem {
    if ($args[0] -ne 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss') { throw 'Unexpected registry query' }
    if (!$global:RecoveryDone) { [pscustomobject]@{ DistributionName = $global:FixtureDistro; BasePath = (Join-Path $global:FixtureData 'distribution'); Version = 2 } }
}
function global:Get-ItemProperty {
    param([Parameter(ValueFromPipeline=$true)]$Entry)
    process { $Entry }
}
function global:tar.exe {
    $staging = $args[3]
    foreach ($name in @('opendock-agent', 'opendock-mount-helper', 'opendock-cuda-probe')) {
        if ([IO.File]::ReadAllText((Join-Path $staging ('usr/local/sbin/' + $name))) -cne $name) { throw ('Incorrect staged helper: ' + $name) }
    }
    foreach ($name in @('yougori-oci-runtime-linux-amd64.tar.gz', 'yougori-oci-runtime-linux-amd64.manifest.json', 'yougori-nvidia-cdi-linux-amd64.tar.gz', 'yougori-nvidia-cdi-linux-amd64.manifest.json')) {
        if ([IO.File]::ReadAllText((Join-Path $staging ('usr/local/share/yougori-oci-runtime/' + $name))) -cne $name) { throw ('Incorrect staged vendor payload: ' + $name) }
    }
    if (!(Test-Path -LiteralPath (Join-Path $staging 'usr/local/sbin/opendock-cuda-install-oci.py'))) { throw 'Missing verified vendor installer' }
    if (!(Test-Path -LiteralPath (Join-Path $staging 'etc/opendock-cuda-runtime'))) { throw 'Missing ownership marker' }
    [IO.File]::WriteAllText((Join-Path $global:FixtureData 'staging-passed'), 'all helpers staged')
    throw 'STAGING_COMPLETE: simulated archive failure'
}
& $Script -DataDirectory $DataPath -AgentPath $Agent -AssetsDirectory $Assets
exit $LASTEXITCODE
`)
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
      join(assets, "install.ps1"), extended(data), extended(join(payload, "opendock-agent")), extended(assets), distro], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
    assert.ifError(result.error)
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stdout, /YOUGORI_CUDA_SETUP_ERROR: STAGING_COMPLETE: simulated archive failure/)
    assert.equal(await readFile(join(data, "staging-passed"), "utf8"), "all helpers staged")
    assert.equal(await readFile(join(data, "installed.json"), "utf8"), "existing manifest must survive")
    assert.equal(await readFile(join(data, "saved-container-marker"), "utf8"), "saved container data")
    assert.equal(await readFile(join(data, "distribution/ext4.vhdx"), "utf8"), "existing CUDA disk")
    assert.equal((await readdir(data)).some(name => name.startsWith("setup-")), false)

    await writeFile(join(payload, "yougori-oci-runtime-linux-amd64.tar.gz"), "tampered")
    const tampered = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
      join(assets, "install.ps1"), extended(data), extended(join(payload, "opendock-agent")), extended(assets), distro], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
    assert.ifError(tampered.error)
    assert.equal(tampered.status, 1)
    assert.match(tampered.stdout, /YOUGORI_CUDA_SETUP_ERROR: CUDA payload checksum mismatch/)
    assert.equal(await readFile(join(data, "distribution/ext4.vhdx"), "utf8"), "existing CUDA disk")
    await writeFile(join(payload, "yougori-oci-runtime-linux-amd64.tar.gz"), "yougori-oci-runtime-linux-amd64.tar.gz")

    await rm(join(payload, "opendock-mount-helper"))
    const missing = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
      join(assets, "install.ps1"), extended(data), extended(join(payload, "opendock-agent")), extended(assets), distro], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
    assert.ifError(missing.error)
    assert.equal(missing.status, 1)
    assert.match(missing.stdout, /YOUGORI_CUDA_SETUP_ERROR: CUDA setup file is missing: .*opendock-mount-helper/)
    assert.equal(await readFile(join(data, "installed.json"), "utf8"), "existing manifest must survive")

    await writeFile(join(payload, "opendock-mount-helper"), "opendock-mount-helper")
    await rm(join(data, "distribution/ext4.vhdx"))
    for (const removeDirectory of [false, true]) {
      if (removeDirectory) await rm(join(data, "distribution"), { recursive: true })
      const missingDisk = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
        join(assets, "install.ps1"), extended(data), extended(join(payload, "opendock-agent")), extended(assets), distro], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
      assert.ifError(missingDisk.error)
      assert.equal(missingDisk.status, 1, missingDisk.stderr)
      assert.match(missingDisk.stdout, /YOUGORI_CUDA_SETUP_ERROR: WSL still lists .* but its CUDA disk is missing: .*ext4.vhdx/)
      assert.doesNotMatch(missingDisk.stdout, /STAGING_COMPLETE|Unexpected WSL mutation|Unexpected CUDA runtime download/)
      assert.equal(await readFile(join(data, "installed.json"), "utf8"), "existing manifest must survive")
      assert.equal(await readFile(join(data, "saved-container-marker"), "utf8"), "saved container data")
      assert.equal((await readdir(data)).some(name => name.startsWith("setup-")), false)
    }
    await rm(join(data, "installed.json"))
    await rm(join(data, "saved-container-marker"))
    const emptyRegistration = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
      join(assets, "install.ps1"), extended(data), extended(join(payload, "opendock-agent")), extended(assets), distro, "-AllowRecovery"], { encoding: "utf8", windowsHide: true, timeout: powershellTimeoutMs })
    assert.ifError(emptyRegistration.error)
    assert.equal(emptyRegistration.status, 1, emptyRegistration.stderr)
    assert.match(emptyRegistration.stdout, /YOUGORI_CUDA_SETUP_ERROR: Unexpected CUDA runtime download/)
    assert.equal(await readFile(join(data, "unregistered-empty-fixture"), "utf8"), "yes")
    assert.equal((await readdir(data)).some(name => name.startsWith("setup-")), false)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
