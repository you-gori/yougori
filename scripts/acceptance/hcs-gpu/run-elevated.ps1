[CmdletBinding()]
param(
    [string]$Bundle = 'D:\YougoriBuildCache\scratch\hcs-gpu-probe\bundle',
    [string]$Output = 'D:\YougoriBuildCache\scratch\hcs-gpu-probe\elevated-result.json'
)
$ErrorActionPreference = 'Stop'
$probeScript = Join-Path $PSScriptRoot 'probe.py'
$pythonPath = (& python -I -c 'import sys; print(sys.executable)').Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Python is unavailable.'
}
$Bundle = (Resolve-Path -LiteralPath $Bundle).Path
$Output = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $Output) {
    throw 'A result already exists. Choose a new -Output path so an old pass cannot be mistaken for this run.'
}
foreach ($value in @($pythonPath, $probeScript, $Bundle, $Output)) {
    if ($value.Contains('"') -or $value.Contains("`n") -or $value.Contains("`r")) {
        throw 'Invalid path.'
    }
}
# Check the image hashes before the UAC prompt, then check them again in the
# privileged process. This script installs no service or persistent privilege.
& $pythonPath -I -B $probeScript --bundle $Bundle --output ([IO.Path]::ChangeExtension($Output, 'preflight.json'))
$preflight = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($Output, 'preflight.json')) -Raw | ConvertFrom-Json
if (-not $preflight.bundle -or ($preflight.error -and $preflight.error -notlike 'HCS access: 0x8037011B*')) {
    throw "Bundle/preflight failed: $($preflight.error)"
}
# Access denied is expected under the normal app identity. Do not use its
# result as GPU evidence; the actual CUDA tests must run and pass below.
$arguments = '-I -B "{0}" --bundle "{1}" --output "{2}" --run' -f $probeScript, $Bundle, $Output
Write-Output 'Requesting a one-time administrator launch for two disposable GPU test VMs.'
$process = Start-Process -FilePath $pythonPath -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait
if (Test-Path -LiteralPath $Output) {
    $report = Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json
    [PSCustomObject]@{ Report = $Output; ExitCode = $process.ExitCode; GPUValidated = $report.gpuValidated; Error = $report.error } | ConvertTo-Json
}
if ($process.ExitCode -ne 0) { throw "GPU VM test did not pass. Read $Output" }
