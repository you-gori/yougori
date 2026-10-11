param([Parameter(Mandatory=$true)][string]$DataDirectory)
$ErrorActionPreference = 'Stop'
$resolvedTestPath = [IO.Path]::GetFullPath($DataDirectory).TrimEnd('\')
$expectedTestPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../build/cuda/integration-runtime')).TrimEnd('\')
if ($resolvedTestPath -ine $expectedTestPath) { throw 'This test only accepts build/cuda/integration-runtime. User CUDA storage will not be touched.' }
$runtimeOwner = [IO.File]::Open((Join-Path $resolvedTestPath 'runtime-owner.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$installed = Get-Content -LiteralPath (Join-Path $DataDirectory 'installed.json') -Raw | ConvertFrom-Json
$distro = $installed.distribution
if ($distro -notmatch '^Yougori-CUDA-[a-f0-9]{12}$') { throw 'Invalid test distribution.' }
& (Join-Path $PSScriptRoot 'verify-owned.ps1') -DataDirectory $resolvedTestPath -Distribution $distro
$token = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$process = [Diagnostics.Process]::new()
$process.StartInfo = [Diagnostics.ProcessStartInfo]::new('wsl.exe', "-d $distro -u root --exec /bin/bash /usr/local/sbin/yougori-cuda-start")
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardInput = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
[void]$process.Start()
$process.StandardInput.NewLine = "`n"
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$process.StandardInput.WriteLine($token)
$process.StandardInput.WriteLine($port)
$process.StandardInput.Close()
$base = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token" }
function Request([string]$Path, $Body) {
    Invoke-RestMethod -Uri "$base$Path" -Method Post -Headers $headers -ContentType 'application/json' -Body (ConvertTo-Json -Depth 20 $Body) -TimeoutSec 480
}
$id = 'cuda-test-' + [Guid]::NewGuid().ToString('N')
$denied = $id + '-denied'
$snapshot = $id + '-snapshot'
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($process.HasExited) { throw "Runtime exited: $($stderr.Result)" }
        try { $health = Invoke-RestMethod -Uri "$base/v1/health" -Headers $headers -TimeoutSec 2; $ready = $true; break } catch { Start-Sleep -Milliseconds 200 }
    }
    if (!$ready) { throw 'CUDA agent did not become ready.' }
    try { Invoke-RestMethod -Uri "$base/v1/health" -TimeoutSec 2 | Out-Null; throw 'Unauthenticated agent access succeeded.' } catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw } }
    Write-Output 'Authenticated loopback agent ready.'
    Request '/v1/containers/provision' @{ id=$id; image='docker.io/library/python:3.12-slim'; command='sleep 2147483647'; cpus=2; memoryBytes=1073741824; networkAccess=$false; gpuAccess=$true } | Out-Null
    Request '/v1/containers/action' @{ id=$id; action='start'; networkAccess=$false } | Out-Null
    $probe = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'kernel-probe.py')).Replace("`r`n", "`n")
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
    $result = Request '/v1/containers/exec' @{ id=$id; command="printf '%s' '$encoded' | base64 -d | python3 -" }
    if ($result.exitCode -ne 0 -or $result.stdout -notmatch 'CUDA KERNEL PASS') { throw (ConvertTo-Json $result) }
    Write-Output $result.stdout
    Request '/v1/containers/action' @{ id=$id; action='stop'; networkAccess=$false } | Out-Null
    Request '/v1/containers/action' @{ id=$id; action='start'; networkAccess=$false } | Out-Null
    $result = Request '/v1/containers/exec' @{ id=$id; command="printf '%s' '$encoded' | base64 -d | python3 -" }
    if ($result.exitCode -ne 0) { throw (ConvertTo-Json $result) }
    Write-Output 'CUDA kernel passed again after stop/start.'
    $result = Request '/v1/containers/exec' @{id=$id; command='printf persistent-data > /root/yougori-persistence'}
    if ($result.exitCode -ne 0) { throw 'Could not create persistence fixture.' }
    $saved = Request '/v1/snapshots/create' @{id=$id; snapshotId=$snapshot; image='docker.io/library/python:3.12-slim'; command='sleep 2147483647'; networkAccess=$false; gpuAccess=$true}
    if ($saved.sizeBytes -le 0 -or $saved.checksumSha256.Length -ne 64) { throw 'Invalid CUDA snapshot artifact.' }
    Request '/v1/containers/action' @{id=$id; action='stop'; networkAccess=$false} | Out-Null
    Request '/v1/containers/configuration' @{id=$id; command='sleep 2147483647'; networkAccess=$false; gpuAccess=$false; previousNetworkAccess=$false; previousGpuAccess=$true; cpus=1; memoryBytes=536870912} | Out-Null
    Request '/v1/containers/action' @{id=$id; action='start'; networkAccess=$false} | Out-Null
    $result = Request '/v1/containers/exec' @{id=$id; command='test ! -e /dev/dxg && test -f /root/yougori-persistence'}
    if ($result.exitCode -ne 0) { throw 'GPU disconnect or persistence failed.' }
    Request '/v1/containers/action' @{id=$id; action='stop'; networkAccess=$false} | Out-Null
    Request '/v1/snapshots/restore' @{id=$id; snapshotId=$snapshot; image='docker.io/library/python:3.12-slim'; command='sleep 2147483647'; networkAccess=$false; gpuAccess=$true} | Out-Null
    Request '/v1/containers/resources' @{id=$id; cpus=1; memoryBytes=536870912} | Out-Null
    Request '/v1/containers/action' @{id=$id; action='start'; networkAccess=$false} | Out-Null
    $result = Request '/v1/containers/exec' @{id=$id; command="test -f /root/yougori-persistence && printf '%s' '$encoded' | base64 -d | python3 -"}
    if ($result.exitCode -ne 0) { throw (ConvertTo-Json $result) }
    Write-Output 'Snapshot restore preserved files and restored working CUDA.'
    $result = Request '/v1/containers/exec' @{id=$id; command='test "$(cat /sys/fs/cgroup/memory.max)" = 536870912 && test "$(cut -d " " -f 1 /sys/fs/cgroup/cpu.max)" = 100000'}
    if ($result.exitCode -ne 0) { throw 'Container CPU or memory hard limit was not enforced.' }
    Write-Output 'Container CPU and memory hard limits verified.'
    $terminal = Request '/v1/terminal/create' @{id=$id; sessionId=($id + '-terminal'); cols=80; rows=24}
    if (!$terminal.sessionId) { throw 'Container terminal did not open.' }
    Request '/v1/terminal/close' @{id=$id; sessionId=$terminal.sessionId} | Out-Null
    Request '/v1/containers/internet' @{id=$id; action='internet'; networkAccess=$true} | Out-Null
    $result = Request '/v1/containers/exec' @{id=$id; command="python3 -c 'import urllib.request; print(urllib.request.urlopen(""https://example.com"", timeout=15).status)'"}
    if ($result.exitCode -ne 0 -or $result.stdout -notmatch '200') { throw (ConvertTo-Json $result) }
    Request '/v1/containers/internet' @{id=$id; action='internet'; networkAccess=$false} | Out-Null
    Write-Output 'Terminal and live internet connect/disconnect passed.'
    Request '/v1/containers/provision' @{ id=$denied; image='docker.io/library/python:3.12-slim'; command='sleep 2147483647'; cpus=1; memoryBytes=536870912; networkAccess=$false; gpuAccess=$false } | Out-Null
    Request '/v1/containers/action' @{ id=$denied; action='start'; networkAccess=$false } | Out-Null
    $result = Request '/v1/containers/exec' @{ id=$denied; command='test ! -e /dev/dxg && test ! -e /mnt/c && test ! -e /usr/lib/wsl/lib/libcuda.so.1' }
    if ($result.exitCode -ne 0) { throw 'A disconnected container has unintended device or filesystem access.' }
    Write-Output 'GPU-disconnected container has no GPU bridge or host drive.'
} finally {
    foreach ($container in @($id, $denied)) {
        try { Request '/v1/containers/delete' @{id=$container; action='delete'; networkAccess=$false} | Out-Null } catch { Write-Warning "Test container cleanup: $_" }
    }
    try { Request '/v1/snapshots/delete' @{id=$id; snapshotId=$snapshot} | Out-Null } catch { Write-Warning "Test snapshot cleanup: $_" }
    try { Request '/v1/system/shutdown' @{} | Out-Null } catch { Write-Warning "Agent shutdown: $_" }
    if (!$process.WaitForExit(15000)) { Write-Warning 'Test runtime remains active; it was not force-killed.' }
    else { & wsl.exe --terminate $distro | Out-Null }
}
