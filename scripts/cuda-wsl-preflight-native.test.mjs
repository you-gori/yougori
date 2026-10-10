import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import test from "node:test"

// Explicit opt-in: this suite executes only inert commands in the selected
// owned test distro. It never imports, updates, terminates or unregisters WSL.
const distro = process.env.YOUGORI_CUDA_WSL_TEST_DISTRO
const enabled = process.platform === "win32" && Boolean(distro)
if (enabled && !/^[A-Za-z0-9][A-Za-z0-9-]{0,100}$/.test(distro)) throw new Error("Use a literal owned WSL test distribution name")
const native = { skip: !enabled }
const installer = resolve("runtime/cuda/install.ps1")
const harnessText = String.raw`param([string]$Installer,[string]$Staging,[string]$Distro,[string]$Mode,[string]$ScriptFile)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($PSVersionTable.PSVersion.Major -ne 5){throw 'Expected stock Windows PowerShell5.1'}
$ast=[Management.Automation.Language.Parser]::ParseFile($Installer,[ref]$null,[ref]$null)
$sender=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Send-CudaPayload'},$true)
. ([scriptblock]::Create($sender.Extent.Text))
$script:OriginalSender=(Get-Item Function:Send-CudaPayload).ScriptBlock
$script:Calls=0;$script:Diagnostics='';$script:Endpoint=$null
$script:TestDistro=$Distro;$script:Mode=$Mode
$distro='OpenDock-CUDA-123456abcdef'
$script:ProductionDistro=$distro
if($Mode -eq 'guard'){$distro='bad distro "quoted"'}
function Send-CudaPayload([Diagnostics.ProcessStartInfo]$StartInfo,[string]$Archive){
 $script:Calls++
 $expected="--distribution $script:ProductionDistro --user root --exec /bin/sh -s"
 if($StartInfo.FileName -cne 'wsl.exe' -or $StartInfo.Arguments -cne $expected){throw 'Production endpoint/constant argv changed'}
 $script:Endpoint=@{file=$StartInfo.FileName;arguments=$StartInfo.Arguments}
 $program=switch($script:Mode){'syntax'{'/bin/sh -n -s'} 'hash'{'/usr/bin/sha256sum'} default{'/bin/sh -s'}}
 # Replace only the endpoint with an explicitly selected owned inert fixture.
 $StartInfo.Arguments="--distribution $script:TestDistro --user root --exec $program"
 $output=@(& $script:OriginalSender $StartInfo $Archive)
 $script:Diagnostics=(@($output|Where-Object{$_ -is [string]}) -join ([string][char]10))
}
$assignment=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$preflight'},$true)
$preflight=Invoke-Expression $assignment.Right.Extent.Text
if($ScriptFile){$preflight=[IO.File]::ReadAllText($ScriptFile)}
$staging=$Staging
$guard=$ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.Contains("distro -cnotmatch '^OpenDock-CUDA-")},$true)
$path=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$preflightPath'},$true)
$write=$ast.Find({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Extent.Text.StartsWith('[IO.File]::WriteAllText($preflightPath,')},$true)
$send=$ast.Find({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Send-CudaPayload' -and $node.Extent.Text.Contains('/bin/sh -s')},$true)
if(!$guard -or !$path -or !$write -or !$send){throw 'Actual new preflight transport statements missing'}
[Console]::InputEncoding=[Text.UTF8Encoding]::new($true)
$failure=$null
try{
 Invoke-Expression $guard.Extent.Text
 Invoke-Expression $path.Extent.Text
 Invoke-Expression $write.Extent.Text
 Invoke-Expression $send.Extent.Text
}catch{$failure=$_.Exception.Message}
$result=@{version=$PSVersionTable.PSVersion.ToString();calls=$script:Calls;endpoint=$script:Endpoint;
 diagnostics=$script:Diagnostics;failure=$failure;inputEncodingRestored=([Console]::InputEncoding.GetPreamble().Length -eq 3);
 mutatingGuestCommands=0;registrationOperations=0}
if($preflightPath -and [IO.File]::Exists($preflightPath)){
 $bytes=[IO.File]::ReadAllBytes($preflightPath);$hasher=[Security.Cryptography.SHA256]::Create()
 try{$result.scriptBytes=$bytes.Length;$result.scriptSha256=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}
 finally{$hasher.Dispose()}
 $result.utf8Bom=($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
}
$result|ConvertTo-Json -Depth 4 -Compress
`

async function run(mode, script) {
  const root = await mkdtemp(join(tmpdir(), "yougori-cuda-wsl-inert-"))
  try {
    const harness = join(root, "harness.ps1")
    const input = script === undefined ? "" : join(root, "fixture-script.sh")
    await writeFile(harness, harnessText)
    if (input) await writeFile(input, script)
    const exe = join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe")
    const result = spawnSync(exe, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
      installer, root, distro, mode, input], { encoding: "utf8", windowsHide: true, timeout: 90_000 })
    assert.ifError(result.error)
    assert.equal(result.status, 0, result.stderr)
    const record = JSON.parse(result.stdout.trim())
    assert.match(record.version, /^5\.1\./)
    assert.equal(record.inputEncodingRestored, true)
    assert.equal(record.mutatingGuestCommands, 0)
    assert.equal(record.registrationOperations, 0)
    return record
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

test("actual CUDA preflight parses through stock PowerShell5.1 and real WSL stdin", native, async () => {
  const record = await run("syntax")
  assert.equal(record.failure, null)
  assert.equal(record.calls, 1)
  assert.equal(record.utf8Bom, false)
  assert.equal(record.diagnostics, "")
})

test("actual preflight transport preserves normalized UTF8 quotes substitutions and Unicode bytes", native, async () => {
  const script = "set -eu\r\nlabel='café 猩 quoted \"value\"'\r\nvalue=\"$(printf '%s' \"$label\")\"\r\nprintf '%s\\n' \"$value\"\r\n"
  const expected = Buffer.from(script.replace(/\r\n/g, "\n") + "\n", "utf8")
  const record = await run("hash", script)
  const hash = createHash("sha256").update(expected).digest("hex")
  assert.equal(record.failure, null)
  assert.equal(record.scriptSha256, hash)
  assert.equal(record.scriptBytes, expected.length)
  assert.equal(record.utf8Bom, false)
  assert.match(record.diagnostics, new RegExp(`^${hash}\\s+-`))
  assert.doesNotMatch(record.endpoint.arguments, /café|printf|\$\(|quoted/)
  const executed = await run("script", script)
  assert.equal(executed.failure, null)
  assert.equal(executed.diagnostics, 'café 猩 quoted "value"')
})

test("invalid CUDA distribution is rejected before any native child", native, async () => {
  const record = await run("guard")
  assert.equal(record.calls, 0)
  assert.match(record.failure, /Invalid owned CUDA distribution name/)
})

test("real WSL nonzero shell exit fails closed and preserves diagnostic", native, async () => {
  const record = await run("script", "printf 'INERT_EXIT_MARKER\\n' >&2\nexit 19\n")
  assert.match(record.failure, /Installing the CUDA runtime payload failed \(exit 19\): INERT_EXIT_MARKER/)
})

test("real WSL early shell exit closes a partial stdin transfer without deadlock", native, async () => {
  const record = await run("script", "printf 'INERT_PARTIAL_PIPE\\n' >&2\nexit 23\n" + "# unused inert padding\n".repeat(400_000))
  assert.match(record.failure, /Installing the CUDA runtime payload failed \(exit 23\): INERT_PARTIAL_PIPE/)
  assert.doesNotMatch(record.failure, /CopyTo/)
})
