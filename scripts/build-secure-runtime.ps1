[CmdletBinding()]
param(
  [string]$WslDistribution = 'Ubuntu-22.04',
  [switch]$SkipFirmware,
  [switch]$QemuOnly,
  [switch]$WithTools,
  [string]$QemuBuildDirectory = '',
  [switch]$Install
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath "$PSScriptRoot/..").Path
$build = "$repo/build/secure-runtime"
$cache = "$repo/build/runtime-cache"
$bash = "$build/toolchain/msys64/usr/bin/bash.exe"
if (-not (Test-Path -LiteralPath $bash)) {
  throw 'Prepare a workspace-only MSYS2 UCRT64 toolchain at build/secure-runtime/toolchain/msys64 (see docs/rebuilding-third-party.txt). End users use the bundled binaries; only source builds need this toolchain.'
}
function Check([string]$Step) { if ($LASTEXITCODE) { throw "$Step failed ($LASTEXITCODE)" } }
function WslPath([string]$Path) {
  $full = [IO.Path]::GetFullPath($Path)
  if ($full -notmatch '^([A-Za-z]):\\(.*)$') { throw "Expected local drive path: $full" }
  '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\','/')
}
function Source([string]$Name, [string]$Url, [string]$Revision, [string]$Patch = '') {
  $path = "$cache/$Name"
  if (-not (Test-Path -LiteralPath $path)) {
    New-Item -ItemType Directory -Path $path | Out-Null
    & git -C $path init; Check "Initialize $Name"
    & git -C $path config core.longpaths true; Check "Configure $Name"
    & git -C $path remote add origin $Url; Check "Set source for $Name"
    & git -C $path fetch --depth 1 origin $Revision; Check "Fetch $Name"
    & git -C $path checkout --detach FETCH_HEAD; Check "Select $Name revision"
  }
  $actual = (& git -C $path rev-parse HEAD).Trim(); Check "Check $Name revision"
  if ($actual -ne $Revision) { throw "Unexpected cached $Name revision; preserve it and move it aside before rebuilding." }
  if ($Patch) {
    $patchPath = "$repo/runtime/security/$Patch"
    & git -C $path apply --ignore-whitespace --reverse --check $patchPath 2>$null
    if ($LASTEXITCODE) {
      & git -C $path apply --ignore-whitespace --check $patchPath; Check "Validate $Name patch"
      & git -C $path apply --ignore-whitespace $patchPath; Check "Apply $Name patch"
    }
  }
}
New-Item -ItemType Directory -Force -Path $cache | Out-Null
Source 'qemu-secure-src' 'https://github.com/qemu/qemu' '84f07211cc5b4fc6a371559bf8a5de4fb068e648' 'qemu-windows-tpm.patch'
Source 'qemu-secure-src' 'https://github.com/qemu/qemu' '84f07211cc5b4fc6a371559bf8a5de4fb068e648' 'qemu-whpx-tpm-ppi.patch'
Source 'qemu-secure-src' 'https://github.com/qemu/qemu' '84f07211cc5b4fc6a371559bf8a5de4fb068e648' 'qemu-whpx-reboot.patch'
Source 'qemu-secure-src' 'https://github.com/qemu/qemu' '84f07211cc5b4fc6a371559bf8a5de4fb068e648' 'qemu-license-notices.patch'
if ($QemuOnly) {
  Copy-Item -LiteralPath "$repo/runtime/security/tpm-qemu.c", "$repo/runtime/security/tpm-api.h" -Destination "$cache/qemu-secure-src/backends/tpm"
  $savedEnvironment = @{}
  foreach ($name in @('MSYSTEM', 'CHERE_INVOKING', 'YOUGORI_QEMU_BUILD_TOOLS', 'YOUGORI_QEMU_BUILD_DIRECTORY')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
  }
  try {
    $env:MSYSTEM = 'UCRT64'
    $env:CHERE_INVOKING = '1'
    $env:YOUGORI_QEMU_BUILD_TOOLS = $(if ($WithTools) { '1' } else { '0' })
    if ($QemuBuildDirectory) { $env:YOUGORI_QEMU_BUILD_DIRECTORY = [IO.Path]::GetFullPath($QemuBuildDirectory).Replace('\', '/') }
    & $bash --login "$PSScriptRoot/build-secure-qemu.sh"; Check 'Build source-backed Windows QEMU'
  } finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
  }
  Write-Output 'Pinned Windows QEMU source build completed.'
  return
}
Source 'ms-tpm-20-ref' 'https://github.com/microsoft/ms-tpm-20-ref' 'ee21db0a941decd3cac67925ea3310873af60ab3' 'ms-tpm-openssl3.patch'
Source 'edk2-secure-src' 'https://github.com/tianocore/edk2' '2970e5699ba6267f3384ffab20f96647578aebc8' 'edk2-svsm-probe.patch'
Source 'secureboot-objects' 'https://github.com/microsoft/secureboot_objects' '9a2bbf82e86b62694e44aba3a4068d8dd0c943d7'
& git -C "$cache/edk2-secure-src" submodule update --init --depth 1 -- `
  CryptoPkg/Library/OpensslLib/openssl MdeModulePkg/Library/BrotliCustomDecompressLib/brotli `
  BaseTools/Source/C/BrotliCompress/brotli MdePkg/Library/BaseFdtLib/libfdt `
  MdePkg/Library/MipiSysTLib/mipisyst CryptoPkg/Library/MbedTlsLib/mbedtls `
  SecurityPkg/DeviceSecurity/SpdmLib/libspdm
Check 'Fetch firmware dependencies'
Copy-Item -LiteralPath "$repo/runtime/security/tpm-qemu.c", "$repo/runtime/security/tpm-api.h" -Destination "$cache/qemu-secure-src/backends/tpm"
$oldSystem = $env:MSYSTEM
$oldHere = $env:CHERE_INVOKING
try {
  $env:MSYSTEM = 'UCRT64'
  $env:CHERE_INVOKING = '1'
  & $bash --login "$PSScriptRoot/build-tpm-library.sh"; Check 'Build TPM library'
  & $bash --login "$PSScriptRoot/build-secure-qemu.sh"; Check 'Build secure QEMU'
} finally { $env:MSYSTEM = $oldSystem; $env:CHERE_INVOKING = $oldHere }
if (-not $SkipFirmware) {
  & wsl -d $WslDistribution -- bash (WslPath "$PSScriptRoot/build-secure-firmware.sh"); Check 'Build Secure Boot firmware'
}
& wsl -d $WslDistribution -- bash (WslPath "$PSScriptRoot/build-secure-vars.sh"); Check 'Build enrolled public trust database'
$staged = "$build/staged-$([guid]::NewGuid().ToString('N'))"
& "$PSScriptRoot/stage-secure-runtime.ps1" -OutputDirectory $staged
if ($Install) {
  $destination = [IO.Path]::GetFullPath("$repo/src-tauri/resources/runtime/qemu-secure")
  $preserved = [IO.Path]::GetFullPath("$build/previous-runtime-$([guid]::NewGuid().ToString('N'))")
  foreach ($path in @($destination, $preserved)) {
    if (-not $path.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "Unsafe runtime target: $path" }
  }
  $running = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq 'yougori.exe' -or ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($destination + '\', [StringComparison]::OrdinalIgnoreCase))
  }
  if ($running) { throw 'Close Yougori and its secure VMs before installing the staged runtime. The completed build was preserved.' }
  if (Test-Path -LiteralPath $destination) { Move-Item -LiteralPath $destination -Destination $preserved }
  Copy-Item -LiteralPath $staged -Destination $destination -Recurse
  Write-Output "Installed secure runtime. Any previous runtime is preserved at $preserved (existing VMs pin their firmware version)."
}
Write-Output "Secure runtime built: $staged"
