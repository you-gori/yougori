#requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Compact,
    [int]$KeepReleases = 2,
    [string]$ReleaseRoot = 'D:\',
    [string[]]$ScratchRoot = @('C:\tmp'),
    [string]$BuildDistro = 'Yougori-Release-Build',
    [string]$TempRoot = [IO.Path]::GetTempPath(),
    [string]$WorkspaceRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$LogPath,
    [switch]$SkipWsl
)
$ErrorActionPreference = 'Stop'
if ($KeepReleases -lt 1) { throw 'KeepReleases must be at least 1.' }
if ($LogPath) { Start-Transcript -LiteralPath $LogPath -Append | Out-Null }
$env:WSL_UTF8 = '1'
[long]$total = 0
$verb = if ($Clean) { 'Removed' } else { 'Reclaimable' }

function Write-Size([long]$Bytes, [string]$What) {
    Write-Output ('{0,9:N2} GiB  {1}' -f ($Bytes / 1GB), $What)
}

# Sizes never follow links, so a junction cannot pull outside data into a deletion.
function Measure-Tree([string]$Path) {
    [long]$bytes = 0
    foreach ($file in Get-ChildItem -LiteralPath $Path -Recurse -Force -File -Attributes !ReparsePoint -ErrorAction SilentlyContinue) {
        $bytes += $file.Length
    }
    return $bytes
}

function Test-Link($Item) { [bool]($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) }

# Keep the newest releases by semantic version, not by name or date.
function Select-OldVersions([string[]]$Versions) {
    return @($Versions | Sort-Object { [version]$_ } -Descending -Unique | Select-Object -Skip $KeepReleases)
}

function Get-YougoriDistros {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (!(Test-Path $key)) { return @() }
    return @(Get-ChildItem $key | ForEach-Object { Get-ItemProperty $_.PSPath } |
        Where-Object { $_.DistributionName -like 'Yougori-*' -and $_.BasePath } |
        ForEach-Object {
            $disk = Join-Path ($_.BasePath -replace '^\\\\\?\\', '') 'ext4.vhdx'
            [pscustomobject]@{ Name = $_.DistributionName; Disk = $disk }
        } | Where-Object { Test-Path -LiteralPath $_.Disk })
}

function Invoke-Distro([string]$Name, [string[]]$Arguments) {
    $output = & wsl.exe -d $Name -u root --exec @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "wsl -d $Name $($Arguments -join ' ') failed: $output" }
    return $output
}

try {
    $distros = if ($SkipWsl) { @() } else { Get-YougoriDistros }
    # Read before this script starts any distribution: compaction needs WSL idle.
    # Names have no spaces; this drops wsl.exe's "no running distributions" message.
    $running = if ($SkipWsl) { @() } else { @(& wsl.exe --list --running --quiet 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '\s' }) }

    Write-Output "Release workspaces in $ReleaseRoot (keeping the newest $KeepReleases)"
    if (Test-Path -LiteralPath $ReleaseRoot -PathType Container) {
        $releases = @(Get-ChildItem -LiteralPath $ReleaseRoot -Directory -Force |
            Where-Object { $_.Name -match '^yougori-(\d+\.\d+\.\d+)$' -and !(Test-Link $_) })
        $old = Select-OldVersions @($releases | ForEach-Object { $_.Name.Substring(8) })
        foreach ($release in $releases | Where-Object { $old -contains $_.Name.Substring(8) }) {
            $bytes = Measure-Tree $release.FullName
            Write-Size $bytes $release.FullName
            if ($Clean) { Remove-Item -LiteralPath $release.FullName -Recurse -Force }
            $total += $bytes
        }
    }

    if ($distros.Name -contains $BuildDistro) {
        Write-Output "Release builds inside $BuildDistro (keeping the newest $KeepReleases)"
        $entries = @(Invoke-Distro $BuildDistro @('ls', '-1', '/build'))
        $built = @($entries | Where-Object { $_ -match '^(out-linux|out-arm64|yougori)-(\d+\.\d+\.\d+)$' })
        $old = Select-OldVersions @($built | ForEach-Object { ($_ -split '-')[-1] })
        $paths = @($built | Where-Object { $old -contains ($_ -split '-')[-1] } | ForEach-Object { "/build/$_" })
        $cache = Invoke-Distro $BuildDistro @('sh', '-c', 'test -d /root/.npm/_cacache && echo yes || true')
        if ($cache -eq 'yes') { $paths += '/root/.npm/_cacache' }
        if ($paths) {
            foreach ($line in Invoke-Distro $BuildDistro (@('du', '-sk', '--') + $paths)) {
                $kib, $path = $line -split "`t", 2
                Write-Size ([long]$kib * 1KB) "${BuildDistro}:$path"
                $total += [long]$kib * 1KB
            }
            if ($Clean) { Invoke-Distro $BuildDistro (@('rm', '-rf', '--one-file-system', '--') + $paths) | Out-Null }
        }
    }

    # Agents put Cargo targets in D:\YougoriBuildCache or ad hoc *-target folders on D:\ and C:\tmp.
    $roots = @()
    foreach ($parent in @($ReleaseRoot) + $ScratchRoot) {
        if (!(Test-Path -LiteralPath $parent -PathType Container)) { continue }
        $roots += @(Get-ChildItem -LiteralPath $parent -Directory -Force |
            Where-Object { ($_.Name -eq 'YougoriBuildCache' -or $_.Name -match '(^|-)target(-|$)') -and !(Test-Link $_) } |
            ForEach-Object FullName)
    }
    if ($roots) {
        Write-Output 'Rust compiler caches'
        $arguments = @{ WorkspaceRoot = $WorkspaceRoot; CacheRoot = $roots; Clean = [bool]$Clean }
        try {
            $lines = & (Join-Path $PSScriptRoot 'build-cache.ps1') @arguments 3>$null
            foreach ($line in $lines) {
                if ($line -match '^(Removed|Reclaimable): ([\d.,]+) GiB') {
                    $total += [long]([double]($Matches[2] -replace ',', '') * 1GB)
                } elseif ($line -notmatch '^To remove') { Write-Output $line }
            }
        } catch {
            Write-Warning "Skipped compiler caches: $($_.Exception.Message)"
        }
    }

    # Grid tests leave realm.db/minting.db folders behind when Windows cannot delete open databases.
    Write-Output "Leaked test databases in $TempRoot (older than one day)"
    $cutoff = (Get-Date).AddDays(-1)
    foreach ($folder in Get-ChildItem -LiteralPath $TempRoot -Directory -Force -ErrorAction SilentlyContinue) {
        if ((Test-Link $folder) -or $folder.LastWriteTime -gt $cutoff) { continue }
        if (!(Test-Path -LiteralPath (Join-Path $folder.FullName 'realm.db')) -and
            !(Test-Path -LiteralPath (Join-Path $folder.FullName 'minting.db'))) { continue }
        $bytes = Measure-Tree $folder.FullName
        if ($Clean) { Remove-Item -LiteralPath $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        if (!$Clean -or !(Test-Path -LiteralPath $folder.FullName)) { $total += $bytes }
    }

    # Git LFS leaves a full temp copy of a modified LFS file whenever a git diff or
    # status that runs its filter is killed, as tools polling the repository do.
    $lfsTemp = Join-Path $WorkspaceRoot '.git\lfs\tmp'
    if (Test-Path -LiteralPath $lfsTemp -PathType Container) {
        Write-Output "Interrupted Git LFS copies in $lfsTemp (older than one hour)"
        $cutoff = (Get-Date).AddHours(-1)
        [long]$bytes = 0
        foreach ($file in Get-ChildItem -LiteralPath $lfsTemp -File -Force | Where-Object { $_.LastWriteTime -lt $cutoff }) {
            if ($Clean) { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue }
            if (!$Clean -or !(Test-Path -LiteralPath $file.FullName)) { $bytes += $file.Length }
        }
        if ($bytes) { Write-Size $bytes $lfsTemp }
        $total += $bytes
    }

    if ($Compact -and $distros) {
        Write-Output 'Yougori WSL disks'
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
        foreach ($distro in $distros) { Write-Size (Get-Item -LiteralPath $distro.Disk).Length "$($distro.Name)  $($distro.Disk)" }
        if (!$Clean) {
            Write-Output 'Compaction returns free space inside these disks to Windows; it runs with -Clean.'
        } elseif ($running) {
            Write-Warning "Skipped compaction: WSL is in use ($($running -join ', ')). It runs next time WSL is idle."
        } elseif (!$admin) {
            Write-Warning 'Skipped compaction: it needs an administrator PowerShell.'
        } else {
            # Trimming marks deleted Linux files as free so compaction can return them.
            foreach ($distro in $distros) {
                # --exec does not search sbin, where distributions install fstrim.
                try { Invoke-Distro $distro.Name @('sh', '-c', 'PATH="/usr/sbin:/sbin:$PATH" fstrim /') | Out-Null }
                catch { Write-Warning "Could not trim $($distro.Name): $($_.Exception.Message)" }
            }
            & wsl.exe --shutdown
            $script = [IO.Path]::GetTempFileName()
            try {
                Set-Content -LiteralPath $script -Value ($distros | ForEach-Object {
                    "select vdisk file=`"$($_.Disk)`"", 'attach vdisk readonly', 'compact vdisk', 'detach vdisk'
                })
                $before = ($distros | ForEach-Object { (Get-Item -LiteralPath $_.Disk).Length } | Measure-Object -Sum).Sum
                $output = & diskpart.exe /s $script
                if ($LASTEXITCODE -ne 0) { throw "diskpart failed: $($output -join "`n")" }
                $after = ($distros | ForEach-Object { (Get-Item -LiteralPath $_.Disk).Length } | Measure-Object -Sum).Sum
                Write-Size ($before - $after) 'returned to Windows by compaction'
                $total += $before - $after
            } finally { Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue }
        }
    }

    Write-Output ('{0}: {1:N2} GiB.' -f $verb, ($total / 1GB))
    if (!$Clean) { Write-Output 'To remove these files, repeat with -Clean (add -Compact to shrink WSL disks).' }
} finally {
    if ($LogPath) { Stop-Transcript | Out-Null }
}
