param(
    [Parameter(Mandatory)][string]$Iso,
    [ValidateRange(1,24)][int]$Cpus = 12,
    [ValidateRange(4,32)][double]$MemoryGb = 4,
    [switch]$Restart,
    [switch]$Gpu,
    [string]$TestBinary
)
# Opt-in developer test. Uses the real RuntimeManager, disposable disks, and
# an observer inside WinPE. Does not take screenshots or install Windows.
$ErrorActionPreference = 'Stop'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("yougori-setup-probe-" + [guid]::NewGuid())
$names = @('YOUGORI_TEST_WINDOWS_ISO','YOUGORI_TEST_WINDOWS_PROBE','YOUGORI_TEST_WINDOWS_CPUS','YOUGORI_TEST_WINDOWS_MEMORY_GB','YOUGORI_TEST_WINDOWS_RESTART','YOUGORI_TEST_WINDOWS_GPU')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    & "$PSScriptRoot/build-windows-setup-probe.ps1" -OutputDirectory $scratch
    $env:YOUGORI_TEST_WINDOWS_ISO = (Resolve-Path -LiteralPath $Iso).Path
    $env:YOUGORI_TEST_WINDOWS_PROBE = "$scratch/probe.img"
    $env:YOUGORI_TEST_WINDOWS_CPUS = [string]$Cpus
    $env:YOUGORI_TEST_WINDOWS_MEMORY_GB = $MemoryGb.ToString([Globalization.CultureInfo]::InvariantCulture)
    $env:YOUGORI_TEST_WINDOWS_RESTART = if ($Restart) { '1' } else { $null }
    $env:YOUGORI_TEST_WINDOWS_GPU = if ($Gpu) { '1' } else { $null }
    if ($TestBinary) {
        & "$PSScriptRoot/test-production-runtime.ps1" -Group windows -TestBinary $TestBinary -TimeoutSeconds 900
    } else {
        & cargo test --manifest-path "$PSScriptRoot/../src-tauri/Cargo.toml" --lib windows_setup_reaches_visible_installer -- --ignored --nocapture --test-threads=1
    }
    if ($LASTEXITCODE) { throw 'Windows Setup verification failed' }
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    $resolved = [IO.Path]::GetFullPath($scratch)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path $resolved -Leaf).StartsWith('yougori-setup-probe-') -and (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
