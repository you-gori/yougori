#requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Clean,
    [string[]]$CacheRoot = @(),
    [string]$WorkspaceRoot = (Split-Path $PSScriptRoot -Parent)
)
$ErrorActionPreference = 'Stop'

# Resolve every component: target/debug can be a junction even when target isn't.
function Resolve-PhysicalPath([string]$Path) {
    $absolute = [IO.Path]::GetFullPath($Path)
    $current = [IO.Path]::GetPathRoot($absolute)
    foreach ($part in $absolute.Substring($current.Length).Split([char[]]'\/', [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $current = $item.ResolveLinkTarget($true).FullName
        }
    }
    return [IO.Path]::TrimEndingDirectorySeparator($current)
}

function Test-Within([string]$Path, [string]$Root) {
    return $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

# Do not traverse a link hidden inside a compiler directory during deletion.
function Measure-Cache([string]$Path) {
    [long]$bytes = 0
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing linked content inside compiler cache: $($item.FullName)"
        }
        if ($item.PSIsContainer) { $bytes += Measure-Cache $item.FullName }
        else { $bytes += $item.Length }
    }
    return $bytes
}

$workspace = Resolve-PhysicalPath $WorkspaceRoot
if (!(Test-Path -LiteralPath (Join-Path $workspace 'src-tauri/Cargo.toml'))) {
    throw 'WorkspaceRoot must be a Yougori source checkout.'
}
$allowed = @($workspace) + @($CacheRoot | ForEach-Object { Resolve-PhysicalPath $_ })
$targets = @('src-tauri/target', 'cli/target', 'vault/target', 'engine/target', 'runtime/cuda/host/target', 'build/gpu-bridge/vm-memory-check/target') |
    ForEach-Object { Join-Path $workspace $_ }
$crates = Join-Path $workspace 'crates'
if (Test-Path -LiteralPath $crates) {
    $targets += @(Get-ChildItem -LiteralPath $crates -Directory | ForEach-Object { Join-Path $_.FullName 'target' })
}
$targets += $CacheRoot
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$profiles = [Collections.Generic.List[string]]::new()
function Find-Profiles([string]$Path, [int]$Depth = 0) {
    if (!(Test-Path -LiteralPath $Path -PathType Container)) { return }
    $physical = Resolve-PhysicalPath $Path
    # Test-Path sees a junction to a deleted folder as present; its target is not.
    if (!(Test-Path -LiteralPath $physical -PathType Container)) { return }
    if (!($allowed | Where-Object { Test-Within $physical $_ })) {
        Write-Warning "Skipped external cache $physical. Include its parent with -CacheRoot to inspect or clean it."
        return
    }
    if (!$seen.Add($physical)) { return }
    if ((Test-Path -LiteralPath (Join-Path $physical '.cargo-lock')) -and
        (Test-Path -LiteralPath (Join-Path $physical '.fingerprint') -PathType Container)) {
        $profiles.Add($physical)
        return
    }
    if ($Depth -ge 3) { return }
    foreach ($child in Get-ChildItem -LiteralPath $physical -Directory -Force) {
        Find-Profiles $child.FullName ($Depth + 1)
    }
}
foreach ($target in $targets) { Find-Profiles $target }

if ($Clean -and (Get-Process -Name cargo,rustc -ErrorAction SilentlyContinue)) {
    throw 'A Rust build is running. Finish it before cleaning compiler caches.'
}
[long]$total = 0
foreach ($profile in $profiles) {
    $lock = $null
    try {
        if ($Clean) {
            # Cargo uses this same lock. Fail rather than clean an active build.
            $lock = [IO.File]::Open((Join-Path $profile '.cargo-lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        }
        # Preserve executables, bundled runtime, releases, models, disks and logs.
        foreach ($name in @('incremental', 'deps', 'build', '.fingerprint')) {
            $path = Join-Path $profile $name
            if (!(Test-Path -LiteralPath $path -PathType Container)) { continue }
            $physical = Resolve-PhysicalPath $path
            if ($physical -ne $path -or !(Test-Within $physical $profile)) {
                throw "Refusing redirected compiler cache: $path"
            }
            $bytes = Measure-Cache $physical
            Write-Output ('{0,9:N2} GiB  {1}' -f ($bytes / 1GB), $physical)
            if ($Clean) { Remove-Item -LiteralPath $physical -Recurse -Force }
            $total += $bytes
        }
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
}
$verb = if ($Clean) { 'Removed' } else { 'Reclaimable' }
Write-Output ('{0}: {1:N2} GiB of compiler artifacts.' -f $verb, ($total / 1GB))
if (!$Clean) { Write-Output 'To remove these artifacts, repeat with -Clean. The next Rust build will recompile them.' }
