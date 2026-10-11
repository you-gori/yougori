# Renames this storage's WSL distribution from the name an earlier release gave it to
# the current Yougori name. Only the WSL registration name changes: the disk and its
# data are not moved or copied, and only the distribution stored in this exact data
# directory is renamed.
param(
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][string]$From
)
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, 'paths.ps1'))
$dataPath = (Get-CudaWindowsPath $DataDirectory).TrimEnd('\')
if ([IO.Path]::GetPathRoot($dataPath).TrimEnd('\') -eq $dataPath) { throw 'A dedicated CUDA data directory is required.' }
$sha = [Security.Cryptography.SHA256]::Create()
$digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($dataPath.ToLowerInvariant()))).Replace('-', '').ToLowerInvariant()
$suffix = '-CUDA-' + $digest.Substring(0, 12)
$to = 'Yougori' + $suffix
if ($From -cnotmatch '^[A-Za-z]+-CUDA-[a-f0-9]{12}$' -or !$From.EndsWith($suffix, [StringComparison]::Ordinal) -or $From -ceq $to) {
    throw 'CUDA runtime identity mismatch.'
}
$distributions = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction Stop)
if (@($distributions | Get-ItemProperty | Where-Object { $_.DistributionName -ceq $to }).Count -ne 0) {
    throw 'A distribution already uses the current CUDA name. Nothing was renamed.'
}
$registered = @($distributions | Where-Object { (Get-ItemProperty $_.PSPath).DistributionName -ceq $From })
if ($registered.Count -ne 1) { throw 'The CUDA distribution to rename is missing.' }
$properties = Get-ItemProperty $registered[0].PSPath
if ($properties.Version -ne 2) { throw 'The CUDA distribution to rename is not WSL 2.' }
$basePath = (Get-CudaWindowsPath $properties.BasePath).TrimEnd('\')
$expectedPath = Join-Path $dataPath 'distribution'
if ($basePath -ine $expectedPath) { throw 'This WSL distribution belongs to different storage. It was not touched.' }
if (!(Test-Path -LiteralPath (Join-Path $expectedPath 'ext4.vhdx') -PathType Leaf)) { throw 'The CUDA disk is missing. Nothing was renamed.' }
# Stopping an idle distribution is harmless; a running one is never renamed.
& wsl.exe --terminate $From | Out-Null
$running = ((& wsl.exe --list --running --quiet) -join "`n").Replace([string][char]0, '')
if ($LASTEXITCODE -ne 0 -or (($running -split "`r?`n" | ForEach-Object { $_.Trim() }) -contains $From)) {
    throw 'The CUDA distribution is still running. Nothing was renamed.'
}
Set-ItemProperty -LiteralPath $registered[0].PSPath -Name DistributionName -Value $to
