[CmdletBinding()]
param(
  [string]$OutputDirectory = "$PSScriptRoot/../build/secure-runtime/staged",
  [string]$QemuBuildDirectory = "$PSScriptRoot/../build/secure-runtime/qemu-build",
  [string]$AngleDirectory = "$PSScriptRoot/../build/angle-runtime/angle/out/Yougori-D3D11"
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path "$PSScriptRoot/..").Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$angle = & "$PSScriptRoot/check-angle-build.ps1" -AngleDirectory $AngleDirectory
if (Test-Path -LiteralPath $output) { throw 'Use a new staging directory; never replace a mapped runtime.' }
New-Item -ItemType Directory -Path $output | Out-Null
$ucrt = "$repo/build/secure-runtime/toolchain/msys64/ucrt64/bin"
$dump = "$ucrt/objdump.exe"
$queue = [Collections.Generic.Queue[string]]::new()
foreach ($file in @(
  "$QemuBuildDirectory/qemu-system-x86_64.exe",
  "$repo/build/secure-runtime/tpm/yougori-tpm.dll",
  "$repo/build/secure-runtime/tpm/yougori-tpm-init.exe",
  "$repo/build/secure-runtime/tpm/yougori-tpm-worker.exe",
  "$angle/libEGL.dll", "$angle/libGLESv2.dll"
)) { $queue.Enqueue($file) }
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
while ($queue.Count) {
  $file = $queue.Dequeue()
  $name = [IO.Path]::GetFileName($file)
  if (-not $seen.Add($name)) { continue }
  if (-not (Test-Path -LiteralPath $file)) { throw "Missing runtime dependency: $file" }
  Copy-Item -LiteralPath $file -Destination (Join-Path $output $name)
  $imports = & $dump -p $file
  if ($LASTEXITCODE) { throw "Cannot inspect PE imports: $file" }
  foreach ($line in $imports) {
    if ($line -match 'DLL Name:\s*(\S+)') {
      $dll = $Matches[1]
      if (Test-Path -LiteralPath "$ucrt/$dll") { $queue.Enqueue("$ucrt/$dll") }
      elseif (-not (Test-Path -LiteralPath "$env:SystemRoot/System32/$dll") -and $dll -notmatch '^api-ms-') {
        throw "Unresolved PE dependency: $dll"
      }
    }
  }
}
& "$ucrt/strip.exe" "$output/qemu-system-x86_64.exe"
if ($LASTEXITCODE) { throw 'Cannot strip QEMU build symbols' }
Copy-Item -LiteralPath "$repo/build/secure-runtime/firmware/OVMF.qemuvars.fd" -Destination $output
# Keep installed firmware available to VMs/backups which pin its measured-boot
# identity. Only new VMs use the new default; never rewrite existing profiles.
$installed = "$repo/src-tauri/resources/runtime/qemu-secure"
$firmwareArchive = Join-Path $output 'firmware'
New-Item -ItemType Directory -Path $firmwareArchive | Out-Null
$previousFirmware = @()
if (Test-Path -LiteralPath "$installed/OVMF.qemuvars.fd") { $previousFirmware += Get-Item -LiteralPath "$installed/OVMF.qemuvars.fd" }
if (Test-Path -LiteralPath "$installed/firmware") { $previousFirmware += Get-ChildItem -LiteralPath "$installed/firmware" -File -Filter '*.fd' }
foreach ($firmwareFile in $previousFirmware) {
  if ($firmwareFile.Length -gt 8MB -or ($firmwareFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid retained firmware image' }
  $firmwareHash = (Get-FileHash -LiteralPath $firmwareFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  Copy-Item -LiteralPath $firmwareFile.FullName -Destination (Join-Path $firmwareArchive "$firmwareHash.fd")
}
Copy-Item -LiteralPath "$repo/build/secure-runtime/firmware/secure-vars.json" -Destination $output
Copy-Item -LiteralPath "$repo/build/runtime-cache/qemu-secure-src/COPYING" -Destination "$output/QEMU-LICENSE.txt"
Copy-Item -LiteralPath "$repo/build/runtime-cache/ms-tpm-20-ref/LICENSE" -Destination "$output/TPM-LICENSE.txt"
Copy-Item -LiteralPath "$repo/build/runtime-cache/edk2-secure-src/License.txt" -Destination "$output/EDK2-LICENSE.txt"
# Preserve the app's explicit physical-GPU selection in the secure runtime too.
& "$PSScriptRoot/build-gpu-bridge.ps1" -QemuDirectory $output
Copy-Item -LiteralPath "$angle/ANGLE_BUILD.json", "$angle/ANGLE-NOTICES.txt" -Destination $output
Copy-Item -LiteralPath "$repo/build/runtime-cache/secureboot-objects/License.txt" -Destination "$output/SECUREBOOT-OBJECTS-LICENSE.txt"
Copy-Item -LiteralPath "$repo/runtime/security/SOURCES.txt" -Destination $output
Copy-Item -LiteralPath "$repo/runtime/security/LICENSE" -Destination "$output/YOUGORI-TPM-LICENSE.txt"
$sourceRecord = [ordered]@{
  schemaVersion = 1
  source = 'https://github.com/qemu/qemu'
  revision = '84f07211cc5b4fc6a371559bf8a5de4fb068e648'
  buildScript = 'scripts/build-secure-qemu.sh'
  buildScriptSha256 = (Get-FileHash -LiteralPath "$repo/scripts/build-secure-qemu.sh" -Algorithm SHA256).Hash.ToLowerInvariant()
  tpmTransport = 'Private process with anonymous pipes; OpenSSL is loaded only inside the BSD TPM worker'
  patches = @(@('qemu-windows-tpm.patch', 'qemu-whpx-tpm-ppi.patch', 'qemu-whpx-reboot.patch', 'qemu-license-notices.patch', 'tpm-qemu.c', 'tpm-api.h', 'tpm-worker.c') | ForEach-Object {
    [ordered]@{ path = "runtime/security/$_"; sha256 = (Get-FileHash -LiteralPath "$repo/runtime/security/$_" -Algorithm SHA256).Hash.ToLowerInvariant() }
  })
  dependencyProvenance = 'PACKAGES.txt for package DLLs; ANGLE_BUILD.json and ANGLE-NOTICES.txt for source-built D3D11 ANGLE'
  firmware = 'SOURCES.md and retained content-addressed firmware; existing VM identities are preserved'
}
[IO.File]::WriteAllText("$output/SOURCE_BUILD.json", ($sourceRecord | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
$licenses = "$output/licenses"
Copy-Item -LiteralPath "$ucrt/../share/licenses" -Destination $licenses -Recurse
Copy-Item -LiteralPath "$repo/runtime/security/licenses" -Destination "$licenses/extra" -Recurse
Copy-Item -LiteralPath "$repo/build/runtime-cache/qemu-secure-src/COPYING.LIB" -Destination "$licenses/LGPL-2.1.txt"
Copy-Item -LiteralPath "$repo/build/runtime-cache/edk2-secure-src/CryptoPkg/Library/OpensslLib/openssl/LICENSE.txt" -Destination "$licenses/firmware-openssl.txt"
Copy-Item -LiteralPath "$repo/build/runtime-cache/edk2-secure-src/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli/LICENSE" -Destination "$licenses/firmware-brotli.txt"
$pacman = "$repo/build/secure-runtime/toolchain/msys64/usr/bin/pacman.exe"
$dlls = @($seen | Where-Object { $_ -notin @('libEGL.dll', 'libGLESv2.dll') -and (Test-Path -LiteralPath "$ucrt/$_") } | ForEach-Object { "/ucrt64/bin/$_" })
$owners = @(& $pacman -Qoq @dlls | Sort-Object -Unique)
if ($LASTEXITCODE) { throw 'Cannot identify runtime package provenance' }
$packages = & $pacman -Qi @owners
if ($LASTEXITCODE) { throw 'Cannot record runtime package provenance' }
[IO.File]::WriteAllLines("$output/PACKAGES.txt", $packages, [Text.UTF8Encoding]::new($false))
$lines = Get-ChildItem -LiteralPath $output -File -Recurse | Where-Object Name -ne SHA256SUMS | Sort-Object FullName | ForEach-Object {
  $relative = [IO.Path]::GetRelativePath($output, $_.FullName).Replace('\','/')
  "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
}
[IO.File]::WriteAllLines("$output/SHA256SUMS", $lines, [Text.UTF8Encoding]::new($false))
Write-Output "Staged secure runtime: $output"
