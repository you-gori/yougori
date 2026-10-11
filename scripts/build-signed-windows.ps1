param([string]$Thumbprint = $env:YOUGORI_SIGN_CERT_SHA1)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
& "$PSScriptRoot/sign-windows-release.ps1" -Action Preflight -Thumbprint $Thumbprint
if ($LASTEXITCODE) { throw 'Signing preflight failed.' }
$previousSigner = $env:YOUGORI_SIGN_CERT_SHA1
$previousRequirement = $env:YOUGORI_REQUIRE_SIGNING
$env:YOUGORI_SIGN_CERT_SHA1 = $Thumbprint
# Bundled CLI and vault payloads must be signed too; a missing identity stops the build.
$env:YOUGORI_REQUIRE_SIGNING = '1'
# Keep the generated Tauri signing configuration outside the checkout: a dirty tree blocks
# release metadata, and the file must never be committed.
$configDirectory = Join-Path ([IO.Path]::GetTempPath()) ("yougori-release-signing-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $configDirectory | Out-Null
$configPath = Join-Path $configDirectory 'tauri.signing.json'
$config = @{ bundle = @{ windows = @{ signCommand = @{ cmd = 'powershell.exe'; args = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$PSScriptRoot/sign-windows-release.ps1",'-Action','Sign','-Path','%1') } } } }
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
try {
    Push-Location $repoRoot
    npm run tauri -- build --config src-tauri/tauri.windows.conf.json --config $configPath --bundles nsis,msi
    if ($LASTEXITCODE) { throw 'Signed Windows packaging failed.' }
    # Every Yougori executable in the packages must carry this signer's timestamped signature.
    $metadata = cargo metadata --locked --no-deps --format-version 1 --manifest-path src-tauri/Cargo.toml | ConvertFrom-Json
    if ($LASTEXITCODE) { throw 'Cannot locate the built Windows packages.' }
    $release = Join-Path $metadata.target_directory 'release'
    $version = (Get-Content -Raw src-tauri/tauri.conf.json | ConvertFrom-Json).version
    $payloads = @(
        (Join-Path $release 'yougori.exe'),
        (Join-Path $release "bundle/nsis/Yougori_${version}_x64-setup.exe"),
        (Join-Path $release "bundle/msi/Yougori_${version}_x64_en-US.msi"),
        'src-tauri/resources/vault/yougori-vault.exe',
        'src-tauri/resources/cli/yougori.exe',
        'src-tauri/resources/cli/yougori-cli.exe'
    )
    foreach ($payload in $payloads) {
        & "$PSScriptRoot/sign-windows-release.ps1" -Action Verify -Path $payload -Thumbprint $Thumbprint
        if ($LASTEXITCODE) { throw "Unsigned release payload: $payload" }
    }
} finally {
    Pop-Location
    $env:YOUGORI_SIGN_CERT_SHA1 = $previousSigner
    $env:YOUGORI_REQUIRE_SIGNING = $previousRequirement
    Remove-Item -LiteralPath $configDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
