param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('runpod', 'vast', 'crusoe', 'nebius', 'prime', 'jarvis', 'thunder', 'latitude', 'civo', 'e2e')]
    [string]$Provider
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Join-Path $env:LOCALAPPDATA 'Yougori\neocloud\cli'
$programs = @{ runpod = 'runpodctl'; vast = 'vastai'; crusoe = 'crusoe'; nebius = 'nebius'; prime = 'prime'; jarvis = 'jl'; thunder = 'tnr'; latitude = 'lsh'; civo = 'civo'; e2e = 'e2e_cli' }

function Add-UserPath([string]$directory) {
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($current -split ';' | Where-Object { $_ })
    if ($entries -notcontains $directory) {
        [Environment]::SetEnvironmentVariable('Path', (($entries + $directory) -join ';'), 'User')
    }
    $env:Path = "$directory;$env:Path"
}

function Install-Release([string]$repository) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repository/releases/latest" -Headers @{ 'User-Agent' = 'Yougori/1.0' }
    $version = [string]$release.tag_name -replace '^v', ''
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw 'This processor is not supported by the provider CLI.' } }
    $assetName = switch ($Provider) {
        'runpod' { "runpodctl-windows-$arch.zip" }
        'crusoe' { 'crusoe_Windows_' + $(if ($arch -eq 'amd64') { 'x86_64' } else { 'arm64' }) + '.tar.gz' }
        'civo' { "civo-$version-windows-$arch.zip" }
        'thunder' { "tnr_${version}_windows_$arch.zip" }
    }
    $asset = @($release.assets | Where-Object { $_.name -eq $assetName })[0]
    if (-not $asset) { throw "The latest $Provider release has no Windows archive for this computer." }
    if ($asset.browser_download_url -notlike "https://github.com/$repository/releases/download/*") { throw 'The provider release URL is invalid.' }
    if ($asset.digest -notmatch '^sha256:[0-9a-fA-F]{64}$') { throw 'The provider release has no SHA-256 digest.' }
    if ($asset.size -gt 80MB) { throw 'The provider release archive is too large.' }
    $directory = Join-Path $root $Provider
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $staging = Join-Path $directory ('.install-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        $archive = Join-Path $staging $assetName
        Write-Host "Downloading $Provider CLI from $repository..."
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archive
        if ((Get-Item -LiteralPath $archive).Length -gt 80MB) { throw 'The provider release archive is too large.' }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
        if ($actual -ine $asset.digest.Substring(7)) { throw 'The provider CLI failed SHA-256 verification.' }
        $executable = $programs[$Provider] + '.exe'
        # Windows' own bsdtar reads zip (Git's GNU tar earlier on PATH would read C: as a remote host).
        $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
        $members = @(& $tar -tf $archive)
        if ($LASTEXITCODE -ne 0) { throw 'The provider release archive cannot be read.' }
        $member = @($members | Where-Object { ($_.TrimStart('./') -eq $executable) -or ($_.EndsWith('/' + $executable)) })[0]
        if (-not $member -or $member -match '(^/|(^|/)\.\.(/|$)|^[a-zA-Z]:)') { throw 'The provider release has no safe CLI executable.' }
        & $tar -xf $archive -C $staging -- $member
        if ($LASTEXITCODE -ne 0) { throw 'The provider CLI could not be extracted.' }
        $extracted = Join-Path $staging ($member -replace '/', '\')
        if (-not (Test-Path -LiteralPath $extracted -PathType Leaf)) { throw 'The provider CLI executable is missing from the archive.' }
        $target = Join-Path $directory $executable
        Move-Item -LiteralPath $extracted -Destination $target -Force
        Add-UserPath $directory
        & $target --help | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$executable was installed but did not start." }
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-Python([string]$package) {
    $venv = Join-Path (Join-Path $root $Provider) 'venv'
    $launcher = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } elseif (Get-Command python -ErrorAction SilentlyContinue) { 'python' } else { throw 'Python 3 is required. Install Python 3, then press Install CLI again.' }
    $pythonArgs = if ($launcher -eq 'py') { @('-3', '-m', 'venv', $venv) } else { @('-m', 'venv', $venv) }
    & $launcher @pythonArgs
    if ($LASTEXITCODE -ne 0) { throw 'Python 3 could not create the isolated CLI environment.' }
    $scripts = Join-Path $venv 'Scripts'
    & (Join-Path $scripts 'python.exe') -m pip install --disable-pip-version-check --no-input --upgrade $package
    if ($LASTEXITCODE -ne 0) { throw "$package could not be installed." }
    $executable = Join-Path $scripts ($programs[$Provider] + '.exe')
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "$package did not provide the expected CLI command." }
    Add-UserPath $scripts
    & $executable --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$package was installed but did not start." }
}

if ($Provider -in @('runpod', 'crusoe', 'civo', 'thunder')) {
    $repository = @{ runpod = 'runpod/runpodctl'; crusoe = 'crusoecloud/cli'; civo = 'civo/cli'; thunder = 'Thunder-Compute/thunder-cli' }[$Provider]
    Install-Release $repository
} elseif ($Provider -in @('vast', 'prime', 'jarvis', 'e2e')) {
    $package = @{ vast = 'vastai'; prime = 'prime'; jarvis = 'jarvislabs'; e2e = 'e2e-cli' }[$Provider]
    Install-Python $package
} else {
    $script = if ($Provider -eq 'nebius') { 'set -euo pipefail; curl -fsSL https://storage.eu-north1.nebius.cloud/cli/install.sh | bash' } else { 'set -euo pipefail; curl -fsSL https://cli.latitude.sh/install.sh | sh' }
    & wsl.exe --exec bash -lc $script
    if ($LASTEXITCODE -ne 0) { throw 'Set up a WSL Linux distribution, then press Install CLI again.' }
}

Write-Host "$($programs[$Provider]) is installed. Open CLI setup to sign in. Restart Yougori before checking the connection in the app."
