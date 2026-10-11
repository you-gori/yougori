[CmdletBinding()]
param([string]$QemuDirectory = "$PSScriptRoot/../src-tauri/resources/runtime/qemu")
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$qemu = (Resolve-Path -LiteralPath $QemuDirectory).Path
$build = Join-Path $repo 'build\gpu-bridge'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'MSVC C++ Build Tools are required to rebuild the graphics bridge' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$egl = Join-Path $qemu 'libEGL.dll'
$original = Join-Path $qemu 'libEGL_angle.dll'
$source = Join-Path $repo 'runtime\gpu\egl-bridge.c'
$exports = & $env:ComSpec /d /c "call `"$vcvars`" >nul && dumpbin /nologo /exports `"$(if (Test-Path -LiteralPath $original) { $original } else { $egl })`""
if ($LASTEXITCODE) { throw 'Could not inspect the bundled EGL exports' }
$intercept = @('eglGetDisplay', 'eglGetProcAddress', 'eglInitialize', 'eglGetPlatformDisplay', 'eglGetPlatformDisplayEXT')
$names = @($exports | ForEach-Object { if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(egl\w+)\s*$') { $Matches[1] } })
if ($names.Count -lt 40) { throw 'Unexpected EGL export table; refusing to generate a partial proxy' }
$definition = Join-Path $build 'egl-exports.rsp'
$lines = @($names | ForEach-Object { if ($intercept -contains $_) { "/EXPORT:$_" } else { "/EXPORT:$_=libEGL_angle.$_" } })
[IO.File]::WriteAllLines($definition, $lines, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllLines((Join-Path $build 'angle-imports.def'), (@('LIBRARY libEGL_angle', 'EXPORTS') + $names), [Text.UTF8Encoding]::new($false))
Push-Location $build
try {
  & $env:ComSpec /d /c "call `"$vcvars`" >nul && lib /nologo /def:angle-imports.def /machine:x64 /out:angle-imports.lib && cl /nologo /O1 /MT /c /W3 `"$source`" && link /nologo /DLL /NOIMPLIB /NOEXP @egl-exports.rsp egl-bridge.obj angle-imports.lib /OUT:libEGL.dll dxgi.lib dxguid.lib"
  if ($LASTEXITCODE) { throw 'EGL bridge compilation failed' }
  & $env:ComSpec /d /c "call `"$vcvars`" >nul && cl /nologo /O1 /MT /W3 /DYOUGORI_GPU_PROBE `"$source`" /Fe:yougori-gpu-probe.exe /link dxgi.lib dxguid.lib"
  if ($LASTEXITCODE) { throw 'GPU probe compilation failed' }
} finally { Pop-Location }
# Preserve the complete upstream library; never replace it with a previous proxy.
if (-not (Test-Path -LiteralPath $original)) { Copy-Item -LiteralPath $egl -Destination $original }
Copy-Item -LiteralPath (Join-Path $build 'libEGL.dll') -Destination $egl -Force
Copy-Item -LiteralPath (Join-Path $build 'yougori-gpu-probe.exe') -Destination $qemu -Force
Copy-Item -LiteralPath (Join-Path $repo 'runtime/gpu/LICENSE') -Destination (Join-Path $qemu 'GPU-BRIDGE-LICENSE.txt')
$manifest = Join-Path $qemu 'SHA256SUMS'
$checksums = Get-ChildItem -LiteralPath $qemu -File -Recurse | Where-Object FullName -ne $manifest | Sort-Object FullName | ForEach-Object {
  '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.FullName.Substring($qemu.Length + 1).Replace('\', '/')
}
[IO.File]::WriteAllLines($manifest, $checksums, [Text.UTF8Encoding]::new($false))
Write-Output 'Verified GPU selection bridge built; the original ANGLE library is preserved.'
