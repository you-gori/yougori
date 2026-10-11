param(
    [Parameter(Mandatory)][string]$Installer,
    [string]$UpgradeInstaller,
    [Parameter(Mandatory)][string]$Report,
    [switch]$DisposableMachine,
    [switch]$AllowUnsignedPreview
)
# Only run in a disposable Windows VM/CI machine. Never erase existing app data.
$ErrorActionPreference = 'Stop'
if (-not $DisposableMachine) { throw 'This installs and uninstalls Yougori. Run only in a disposable Windows machine with -DisposableMachine.' }
foreach ($existing in @("$env:APPDATA\com.yougori.desktop", "$env:USERPROFILE\Yougori")) {
    if (Test-Path -LiteralPath $existing) { throw "This is not a clean test profile: $existing" }
}
if (Get-Command yougori -ErrorAction SilentlyContinue) { throw 'An existing Yougori CLI was found. Use a clean VM.' }
if (Get-Process yougori,yougori-vault -ErrorAction SilentlyContinue) { throw 'Yougori is already running. Use a clean VM.' }
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
if ([IO.Path]::GetExtension($installerPath) -ne '.exe') { throw 'Use the NSIS .exe installer for this smoke test.' }
if ($UpgradeInstaller) {
    $UpgradeInstaller = (Resolve-Path -LiteralPath $UpgradeInstaller).Path
    $currentVersion = (Get-Item -LiteralPath $installerPath).VersionInfo.ProductVersion
    $upgradeVersion = (Get-Item -LiteralPath $UpgradeInstaller).VersionInfo.ProductVersion
    if ($currentVersion -notmatch '^\d+\.\d+\.\d+$' -or $upgradeVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw 'Upgrade validation requires installers with explicit numeric product versions.'
    }
    if ([version]$upgradeVersion -le [version]$currentVersion) {
        throw 'UpgradeInstaller must be a newer version. Same-version reinstall is not an upgrade test.'
    }
}
if (-not $AllowUnsignedPreview) { & "$PSScriptRoot/sign-windows-release.ps1" -Action Verify -Path $installerPath }
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('yougori-installer-test-' + [guid]::NewGuid())
$installRoot = Join-Path $testRoot 'app'
New-Item -ItemType Directory -Path $testRoot | Out-Null
$result = [ordered]@{ schemaVersion = 1; installerSha256 = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash; signed = -not $AllowUnsignedPreview; install = $false; cli = $false; reinstallPreservesData = $false; upgrade = 'not-tested'; uninstall = $false; uiAndRuntime = 'not-tested'; status = 'failed' }
function Install-Candidate([string]$candidate) {
    # NSIS requires /D last, with an unquoted absolute path.
    if ($installRoot.Contains('"')) { throw 'Invalid test installation path.' }
    $process = Start-Process -FilePath $candidate -ArgumentList "/S /D=$installRoot" -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(180000)) { throw 'Installer did not finish within three minutes.' }
    if ($process.ExitCode -ne 0) { throw "Installer failed: $($process.ExitCode)" }
}
try {
    Install-Candidate $installerPath
    if (-not (Test-Path -LiteralPath "$installRoot\yougori.exe")) { throw 'Desktop executable missing after installation.' }
    foreach ($binary in @('yougori.exe','cli\yougori.exe','vault\yougori-vault.exe')) {
        if (-not (Test-Path -LiteralPath "$installRoot\$binary")) { throw "Required binary missing: $binary" }
        if (-not $AllowUnsignedPreview) { & "$PSScriptRoot/sign-windows-release.ps1" -Action Verify -Path "$installRoot\$binary" }
    }
    $result.install = $true
    $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    $env:Path = "$machinePath;$userPath"
    $resolvedCli = (Get-Command yougori -ErrorAction Stop).Source
    if ([IO.Path]::GetFullPath($resolvedCli) -ne [IO.Path]::GetFullPath("$installRoot\cli\yougori.exe")) { throw 'Fresh-shell PATH resolves to a different CLI.' }
    $help = & powershell.exe -NoLogo -NoProfile -NonInteractive -Command 'yougori --help' 2>&1
    if ($LASTEXITCODE -ne 0 -or ($help -join "`n") -notmatch 'run') { throw 'CLI help failed without development tools.' }
    $result.cli = $true
    $dataRoot = "$env:APPDATA\com.yougori.desktop"
    New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
    $sentinel = Join-Path $dataRoot 'installer-data-preservation.txt'
    [IO.File]::WriteAllText($sentinel, 'keep-existing-user-data')
    $nextInstaller = if ($UpgradeInstaller) { (Resolve-Path -LiteralPath $UpgradeInstaller).Path } else { $installerPath }
    if (-not $AllowUnsignedPreview) { & "$PSScriptRoot/sign-windows-release.ps1" -Action Verify -Path $nextInstaller }
    Install-Candidate $nextInstaller
    if ([IO.File]::ReadAllText($sentinel) -ne 'keep-existing-user-data') { throw 'Installation did not preserve existing app data.' }
    $result.reinstallPreservesData = $true
    if ($UpgradeInstaller) { $result.upgrade = 'passed'; $result.upgradeInstallerSha256 = (Get-FileHash -LiteralPath $nextInstaller -Algorithm SHA256).Hash }
    $uninstaller = Get-ChildItem -LiteralPath $installRoot -File | Where-Object Name -Match '^uninstall.*\.exe$' | Select-Object -First 1
    if (-not $uninstaller) { throw 'Uninstaller missing.' }
    $process = Start-Process -FilePath $uninstaller.FullName -ArgumentList '/S' -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(120000)) { throw 'Uninstaller did not finish.' }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Test-Path -LiteralPath "$installRoot\yougori.exe") -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (Test-Path -LiteralPath "$installRoot\yougori.exe") { throw 'Desktop executable remains after uninstall.' }
    if ([Environment]::GetEnvironmentVariable('Path','User').Split(';') -contains "$installRoot\cli") { throw 'CLI PATH entry remains after uninstall.' }
    if ([IO.File]::ReadAllText($sentinel) -ne 'keep-existing-user-data') { throw 'Uninstall removed app data.' }
    $result.uninstall = $true
    $result.status = 'passed-smoke-only'
} catch {
    $result.error = $_.Exception.Message
    throw
} finally {
    $reportPath = [IO.Path]::GetFullPath($Report)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($reportPath)) | Out-Null
    [IO.File]::WriteAllText($reportPath, ($result | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
}
