# Yougori CLI and engine installer for Windows. Download the desktop app separately.
#   powershell -c "irm https://yougori.com/install.ps1 | iex"
# Downloads the current signed release, checks its SHA-256 and the publisher signature of every
# Yougori executable in it (the third-party runtime is checked against its SHA256SUMS), installs it for
# this user (no administrator rights), puts `yougori` on PATH and runs `yougori doctor`.
# Environment overrides: YOUGORI_ENGINE_ONLY=0 (opt into the desktop bundle),
# YOUGORI_RELEASES_URL (HTTPS manifest), YOUGORI_AUTOSTART=1 (start the engine in the background
# at login), YOUGORI_START_ENGINE=0 (skip startup), YOUGORI_ALLOW_UNSIGNED=1 (test builds only).

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Exact certificate subject of the release signer. scripts/release-manifest.mjs fills this in from
# the signed installer when it prepares the copy served by yougori.com.
$ExpectedPublisher = '__YOUGORI_PUBLISHER__'

function Fail($message) { Write-Host "Yougori install failed: $message" -ForegroundColor Red; exit 1 }

function Assert-HttpsUri($value, $label) {
  $uri = $null
  if (-not [Uri]::TryCreate([string]$value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo) {
    Fail "$label must use HTTPS without credentials."
  }
  return $uri.AbsoluteUri
}

$engineOnly = $env:YOUGORI_ENGINE_ONLY -ne '0'
$allowUnsigned = $env:YOUGORI_ALLOW_UNSIGNED -eq '1'
$startEngine = if ($env:YOUGORI_START_ENGINE) { $env:YOUGORI_START_ENGINE } else { '1' }
if ($startEngine -notin @('0', '1')) { Fail 'YOUGORI_START_ENGINE must be 0 or 1.' }
if ($ExpectedPublisher -eq ('__YOUGORI_' + 'PUBLISHER__') -and -not $allowUnsigned) { Fail 'this copy of the installer was not prepared for a release (no publisher pin). Use the one from https://yougori.com/install.ps1.' }
$manifestUrl = if ($env:YOUGORI_RELEASES_URL) { Assert-HttpsUri $env:YOUGORI_RELEASES_URL 'YOUGORI_RELEASES_URL' } else { 'https://yougori.com/releases/latest.json' }
$platform = switch ($env:PROCESSOR_ARCHITECTURE) { 'ARM64' { 'windows-aarch64' } 'AMD64' { 'windows-x86_64' } default { Fail "unsupported processor $($env:PROCESSOR_ARCHITECTURE)" } }
if ($engineOnly) { $platform = "$platform-engine" }
if ([Environment]::OSVersion.Version.Build -lt 19041) { Fail 'Windows 10 version 2004 (build 19041) or newer is required.' }

function Assert-Signed($path) {
  $signature = Get-AuthenticodeSignature -LiteralPath $path
  if ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -eq $ExpectedPublisher) { return }
  if ($allowUnsigned) { Write-Host "Warning: $([IO.Path]::GetFileName($path)) is not signed by the Yougori publisher ($($signature.Status)); installing a test build." -ForegroundColor Yellow; return }
  Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
  Fail "$([IO.Path]::GetFileName($path)) is not signed by the Yougori publisher ($($signature.Status)). Nothing was installed."
}

# The release signs every Yougori-built executable in an engine archive. Only the third-party
# runtime folder is exempt: the engine checks it against its own SHA256SUMS before use.
function Get-SignedPayloads($root) {
  # TEMP may be a short 8.3 path; Get-ChildItem reports long names.
  $root = (Get-Item -LiteralPath $root).FullName
  $items = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
  if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
    Fail 'the engine archive contains links. Nothing was installed.'
  }
  $runtime = (Join-Path $root 'runtime') + '\'
  @($items | Where-Object {
    -not $_.PSIsContainer -and $_.Extension -in @('.exe', '.dll', '.sys', '.msi') -and
    -not $_.FullName.StartsWith($runtime, [StringComparison]::OrdinalIgnoreCase)
  } | ForEach-Object { $_.FullName } | Sort-Object)
}

function Stop-InstalledEngine($running) {
  # An offline engine writes its status error to stderr. That is expected during
  # reinstall, and Windows PowerShell otherwise turns it into a terminating error.
  $ErrorActionPreference = 'Continue'
  & $running app status 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { return }
  & $running app quit --yes 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail 'the running engine refused to stop. Existing files were left untouched.' }
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    & $running app status 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { return }
    Start-Sleep -Seconds 1
  }
  Fail 'the running engine did not stop. Existing files were left untouched.'
}

function Start-InstalledEngine($cliPath) {
  $ErrorActionPreference = 'Continue'
  Write-Host 'Starting the Yougori engine...'
  & $cliPath app start
  if ($LASTEXITCODE -ne 0) {
    Write-Warning 'The files are installed, but engine startup failed. Check: yougori doctor --format table'
    return
  }
  & $cliPath doctor --format table
}

Write-Host 'Finding the latest Yougori release...'
try { $manifest = Invoke-RestMethod -Uri $manifestUrl -UseBasicParsing } catch { Fail "cannot read $manifestUrl ($($_.Exception.Message))" }
$asset = $manifest.assets.$platform
if (-not $asset -or -not $asset.url -or -not $asset.sha256) { Fail "release $($manifest.version) has no download for $platform yet." }
$asset.url = Assert-HttpsUri $asset.url 'The release download'
if ($asset.sha256 -isnot [string] -or $asset.sha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'the release SHA-256 is invalid.' }

$folder = Join-Path $env:TEMP ("yougori-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder | Out-Null
$download = Join-Path $folder ([IO.Path]::GetFileName(([Uri]$asset.url).AbsolutePath))
Write-Host "Downloading Yougori $($manifest.version)$(if ($engineOnly) { ' (engine only)' })..."
# The server saves aggregate command/app totals, without visitor identifiers.
$downloadUri = [UriBuilder]$asset.url
$downloadUri.Fragment = ''
$downloadUri.Query = if ($downloadUri.Query) { "$($downloadUri.Query.TrimStart('?'))&source=command" } else { 'source=command' }
try { Invoke-WebRequest -Uri $downloadUri.Uri.AbsoluteUri -OutFile $download -UseBasicParsing } catch { Fail "download failed ($($_.Exception.Message))" }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash
if ($hash -ne $asset.sha256.ToUpperInvariant()) { Remove-Item -Recurse -Force $folder; Fail 'the download does not match the published SHA-256. Nothing was installed.' }

if ($engineOnly) {
  # The engine and CLI without the desktop app: unpack, check every signature, then move into place.
  $staged = Join-Path $folder 'unpacked'
  New-Item -ItemType Directory -Path $staged | Out-Null
  & (Join-Path $env:SystemRoot 'System32\tar.exe') -xf $download -C $staged
  if ($LASTEXITCODE) { Fail 'cannot unpack the engine archive. Nothing was installed.' }
  foreach ($binary in @('yougori-engine.exe', 'cli\yougori.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $staged $binary))) { Fail "the engine archive has no $binary. Nothing was installed." }
  }
  foreach ($path in Get-SignedPayloads $staged) { Assert-Signed $path }
  $target = Join-Path $env:LOCALAPPDATA 'Yougori Engine'
  $running = Join-Path $target 'cli\yougori.exe'
  if (Test-Path -LiteralPath $running) { Stop-InstalledEngine $running }
  Write-Host 'Installing...'
  New-Item -ItemType Directory -Force -Path $target | Out-Null
  Copy-Item -Path (Join-Path $staged '*') -Destination $target -Recurse -Force
  $cliFolder = Join-Path $target 'cli'
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not (($userPath -split ';') -contains $cliFolder)) {
    [Environment]::SetEnvironmentVariable('Path', ((@($userPath, $cliFolder) | Where-Object { $_ }) -join ';'), 'User')
  }
} else {
  Assert-Signed $download
  Write-Host 'Installing (this takes a minute)...'
  $process = Start-Process -FilePath $download -ArgumentList '/S' -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -ne 0) { Fail "the installer exited with code $($process.ExitCode)." }
}
Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue

# The installer adds the CLI to the user PATH; make it available in this window too.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:Path = "$userPath;$([Environment]::GetEnvironmentVariable('Path', 'Machine'))"
$cli = if ($engineOnly) { [PSCustomObject]@{ Source = (Join-Path $cliFolder 'yougori.exe') } } else { Get-Command yougori -ErrorAction SilentlyContinue }
if (-not $cli) { Fail 'Yougori installed, but `yougori` is not on PATH. Open a new terminal, or add the Yougori cli folder to PATH.' }

Write-Host 'Setting up the Yougori skill...'
try {
  $skillOutput = & $cli.Source skills install 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Yougori is installed. Automatic skill setup could not finish; existing custom skills were preserved. Retry with: yougori skills install. $($skillOutput -join ' ')"
  } else {
    $skillResult = ($skillOutput -join "`n") | ConvertFrom-Json
    Write-Host "Yougori skill ready: $($skillResult.result.path)"
  }
} catch {
  Write-Warning "Yougori is installed. Skill setup could not finish: $($_.Exception.Message). Retry with: yougori skills install"
}

if ($env:YOUGORI_AUTOSTART -eq '1') { & $cli.Source app autostart on | Out-Null }
if ($startEngine -eq '1') { Start-InstalledEngine $cli.Source } else { Write-Host 'Engine startup skipped. Start it with: yougori app start' }
Write-Host ''
Write-Host "Yougori $($manifest.version) is installed$(if ($engineOnly) { ' (engine only, no desktop app)' }). Try: yougori status" -ForegroundColor Green
if ($env:YOUGORI_AUTOSTART -ne '1') { Write-Host 'Keep the engine ready at login with: yougori app autostart on' }
