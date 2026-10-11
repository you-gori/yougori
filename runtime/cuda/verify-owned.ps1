param(
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][string]$Distribution,
    [switch]$Terminate,
    [switch]$RequireStopped
)
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, 'paths.ps1'))
$dataPath = (Get-CudaWindowsPath $DataDirectory).TrimEnd('\')
if ([IO.Path]::GetPathRoot($dataPath).TrimEnd('\') -eq $dataPath) { throw 'A dedicated CUDA data directory is required.' }
$sha = [Security.Cryptography.SHA256]::Create()
$digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($dataPath.ToLowerInvariant()))).Replace('-', '').ToLowerInvariant()
if ($Distribution -cne ('Yougori-CUDA-' + $digest.Substring(0, 12))) { throw 'CUDA runtime identity mismatch.' }
$registered = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction Stop | Get-ItemProperty | Where-Object { $_.DistributionName -ceq $Distribution })
if ($registered.Count -ne 1 -or $registered[0].Version -ne 2) { throw 'The owned WSL 2 distribution is missing.' }
$basePath = (Get-CudaWindowsPath $registered[0].BasePath).TrimEnd('\')
$expectedPath = Join-Path $dataPath 'distribution'
if ($basePath -ine $expectedPath) { throw 'This WSL distribution belongs to different storage. It was not touched.' }
if (!(Test-Path -LiteralPath (Join-Path $expectedPath 'ext4.vhdx') -PathType Leaf)) { throw 'The CUDA disk is missing. No distribution was changed.' }
if ($RequireStopped) {
    $running = ((& wsl.exe --list --running --quiet) -join "`n").Replace([string][char]0, '')
    if ($LASTEXITCODE -ne 0) { throw 'Could not verify that the CUDA distribution is stopped. Its disk was not changed.' }
    if (($running -split "`r?`n" | ForEach-Object { $_.Trim() }) -contains $Distribution) {
        throw 'The CUDA distribution is still running. Stop its containers and close its WSL sessions normally, then retry Reclaim space.'
    }
}
if ($Terminate) {
    & wsl.exe --terminate $Distribution
    if ($LASTEXITCODE -ne 0) { throw 'Could not stop the owned CUDA distribution. Its disk was preserved.' }
}
