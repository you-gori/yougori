param(
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][string]$AgentPath,
    [Parameter(Mandatory=$true)][string]$AssetsDirectory
)
$ErrorActionPreference = 'Stop'
try {
. ([IO.Path]::Combine($PSScriptRoot, 'paths.ps1'))
$DataDirectory = Get-CudaWindowsPath $DataDirectory
$AgentPath = Get-CudaWindowsPath $AgentPath
$AssetsDirectory = Get-CudaWindowsPath $AssetsDirectory
$payloadDirectory = [IO.Path]::GetDirectoryName($AgentPath)
$payloadNames = @('opendock-agent', 'opendock-mount-helper', 'opendock-cuda-probe', 'yougori-oci-runtime-linux-amd64.tar.gz', 'yougori-oci-runtime-linux-amd64.manifest.json', 'yougori-nvidia-cdi-linux-amd64.tar.gz', 'yougori-nvidia-cdi-linux-amd64.manifest.json')
# Validate the complete payload before importing or starting a distribution.
foreach ($file in @($payloadNames | ForEach-Object { Join-Path $payloadDirectory $_ }) + @((Join-Path $payloadDirectory 'SHA256SUMS'), (Join-Path $AssetsDirectory 'wsl.conf'), (Join-Path $AssetsDirectory 'setup.sh'), (Join-Path $AssetsDirectory 'start.sh'), (Join-Path $AssetsDirectory 'install-oci.py'))) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "CUDA setup file is missing: $file. Reinstall Yougori and retry." }
}
if (!(Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw 'WSL 2 is not installed. Install WSL and restart Windows, then retry CUDA setup.' }
& wsl.exe --status | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'WSL is not ready. Install/update WSL 2 and enable hardware virtualization before CUDA setup.' }
$dataPath = [IO.Path]::GetFullPath($DataDirectory).TrimEnd('\')
if ([IO.Path]::GetPathRoot($dataPath).TrimEnd('\') -eq $dataPath) { throw 'A dedicated CUDA data directory is required.' }
$sha = [Security.Cryptography.SHA256]::Create()
$digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($dataPath.ToLowerInvariant()))).Replace('-', '').ToLowerInvariant()
$distro = 'OpenDock-CUDA-' + $digest.Substring(0, 12)
$distributionPath = Join-Path $dataPath 'distribution'
New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
$installLock = [IO.File]::Open((Join-Path $dataPath 'setup.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)

# Use .NET directly: a PowerShell 7 parent can pass a module search path that
# hides Windows PowerShell 5's Get-FileHash command in a packaged desktop app.
function Get-CudaSha256([string]$LiteralPath) {
    $stream = [IO.File]::OpenRead($LiteralPath)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hasher.Dispose() }
}

$verifiedPayload = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $payloadDirectory 'SHA256SUMS'))) {
    if ($line -notmatch '^([a-f0-9]{64})\s+([a-zA-Z0-9_.-]+)$' -or !($payloadNames -ccontains $Matches[2])) { throw 'Unexpected CUDA checksum record; setup was not started.' }
    $name = $Matches[2]; $expected = $Matches[1]
    if ($verifiedPayload.ContainsKey($name) -or (Get-CudaSha256 (Join-Path $payloadDirectory $name)) -cne $expected) { throw 'CUDA payload checksum mismatch; setup was not started.' }
    $verifiedPayload[$name] = $true
}
if ($verifiedPayload.Count -ne $payloadNames.Count) { throw 'CUDA payload checksum records are incomplete; setup was not started.' }

function Invoke-Wsl([string[]]$WslArguments) {
    & wsl.exe @WslArguments
    if ($LASTEXITCODE -ne 0) { throw "WSL operation failed (exit $LASTEXITCODE). No existing distribution was removed." }
}

function Send-CudaPayload([Diagnostics.ProcessStartInfo]$StartInfo, [string]$Archive) {
    # .NET Framework creates the child's stdin writer with Console.InputEncoding.
    # UTF-8 with a BOM prepends three bytes even when using BaseStream, corrupting
    # tar's first header. Change it only while this binary transfer is running.
    $previousEncoding = [Console]::InputEncoding
    $process = [Diagnostics.Process]::new()
    $outputBuffer = [IO.MemoryStream]::new()
    $errorBuffer = [IO.MemoryStream]::new()
    function Read-CudaProcessOutput([IO.MemoryStream]$Buffer) {
        $bytes = $Buffer.ToArray()
        # WSL's own startup errors use UTF-16LE, while guest tools use UTF-8.
        if ($bytes.Length -ge 2 -and (($bytes[0] -eq 255 -and $bytes[1] -eq 254) -or $bytes[1] -eq 0)) {
            $text = [Text.Encoding]::Unicode.GetString($bytes)
        } else {
            $text = [Text.Encoding]::UTF8.GetString($bytes)
        }
        return $text.TrimStart([char]0xfeff).Replace([string][char]0, '').Trim()
    }
    try {
        [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
        $process.StartInfo = $StartInfo
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardInput = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        [void]$process.Start()
        # Drain both pipes while sending bytes so a child error cannot deadlock
        # the transfer. Save CopyTo's error until WSL has reported why it exited.
        $outputRead = $process.StandardOutput.BaseStream.CopyToAsync($outputBuffer)
        $errorRead = $process.StandardError.BaseStream.CopyToAsync($errorBuffer)
        $transferFailure = $null
        try {
            $inputFile = [IO.File]::OpenRead($Archive)
            try { $inputFile.CopyTo($process.StandardInput.BaseStream) } finally { $inputFile.Dispose() }
        } catch { $transferFailure = $_.Exception.Message }
        try { $process.StandardInput.Close() } catch {
            if (!$transferFailure) { $transferFailure = $_.Exception.Message }
        }
        if ($transferFailure -and !$process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'The CUDA payload receiver did not exit after its input pipe closed. Setup stopped.'
        }
        $process.WaitForExit()
        $outputRead.GetAwaiter().GetResult()
        $errorRead.GetAwaiter().GetResult()
        $diagnostics = ((Read-CudaProcessOutput $outputBuffer) + "`n" + (Read-CudaProcessOutput $errorBuffer)).Trim()
        if ($diagnostics) { Write-Output $diagnostics }
        if ($process.ExitCode -ne 0 -or $transferFailure) {
            $detail = if ($diagnostics) { $diagnostics } else { $transferFailure }
            $detail = ($detail -replace '\s+', ' ').Trim()
            if ($detail.Length -gt 1500) { $detail = $detail.Substring(0, 1500) }
            throw "Installing the CUDA runtime payload failed (exit $($process.ExitCode)): $detail"
        }
    } finally {
        $process.Dispose()
        $outputBuffer.Dispose()
        $errorBuffer.Dispose()
        [Console]::InputEncoding = $previousEncoding
    }
}

# Never adopt a similarly named distribution or touch any other WSL instance.
$registered = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DistributionName -eq $distro })
if ($registered.Count -gt 1) { throw 'Multiple CUDA distributions have the same name. No distribution was changed.' }
if ($registered.Count -gt 0) {
    $registeredPath = (Get-CudaWindowsPath $registered[0].BasePath).TrimEnd('\')
    if ($registeredPath -ine $distributionPath) { throw 'CUDA distribution name is already owned by another directory.' }
    if ($registered[0].Version -ne 2) { throw 'The CUDA distribution must use WSL 2.' }
    $running = ((& wsl.exe --list --running --quiet) -join "`n").Replace([string][char]0, '')
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect running WSL distributions.' }
    if (($running -split "`r?`n" | ForEach-Object { $_.Trim() }) -contains $distro) {
        throw 'Stop the Yougori CUDA runtime before installing or updating it. No running containers were interrupted.'
    }
    $diskPath = Join-Path $distributionPath 'ext4.vhdx'
    if (!(Test-Path -LiteralPath $diskPath -PathType Leaf)) {
        # A failed first import can leave a WSL registration without creating a
        # disk or an installation manifest. Only that empty state is recoverable.
        # Any saved state or existing directory may belong to a moved disk.
        if ((Test-Path -LiteralPath (Join-Path $dataPath 'installed.json')) -or
            (Test-Path -LiteralPath $distributionPath)) {
            throw "WSL still lists $distro but its CUDA disk is missing: $diskPath. Restore the disk if it was moved. Setup did not recreate or reset this distribution."
        }
        & wsl.exe --unregister $distro | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not clear the empty CUDA registration $distro. No runtime disk was changed." }
        $remaining = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DistributionName -eq $distro })
        if ($remaining.Count -ne 0) { throw 'WSL still lists the empty CUDA registration after unregistering it. Setup stopped.' }
        $registered = @()
    }
}
if ($registered.Count -eq 0) {
    if (Test-Path -LiteralPath $distributionPath) { throw 'Unregistered CUDA storage already exists. It was preserved; recover it before installing again.' }
    $archive = Join-Path $dataPath 'ubuntu-base-24.04.4-base-amd64.tar.gz'
    $expected = 'c1e67ef7b17a6300e136118bd1dc04725009cb376c1aad10abcf8cd453628d58'
    if (!(Test-Path -LiteralPath $archive)) {
        Write-Output 'Downloading the optional CUDA runtime base...'
        & curl.exe --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$archive.part" 'https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.4-base-amd64.tar.gz'
        if ($LASTEXITCODE -ne 0) { throw 'CUDA runtime base download failed.' }
        if ((Get-CudaSha256 "$archive.part") -ne $expected) { throw 'Ubuntu base checksum mismatch. Installation stopped.' }
        Move-Item -LiteralPath "$archive.part" -Destination $archive
    }
    if ((Get-CudaSha256 $archive) -ne $expected) { throw 'Ubuntu base checksum mismatch.' }
    Invoke-Wsl @('--import', $distro, $distributionPath, $archive, '--version', '2')
}

$staging = Join-Path $dataPath ('setup-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $staging 'etc'), (Join-Path $staging 'usr/local/sbin'), (Join-Path $staging 'usr/local/share/yougori-oci-runtime') -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $AssetsDirectory 'wsl.conf') -Destination (Join-Path $staging 'etc/wsl.conf')
    [IO.File]::WriteAllText((Join-Path $staging 'etc/opendock-cuda-runtime'), $digest, [Text.Encoding]::ASCII)
    Copy-Item -LiteralPath $AgentPath -Destination (Join-Path $staging 'usr/local/sbin/opendock-agent')
    Copy-Item -LiteralPath (Join-Path $payloadDirectory 'opendock-mount-helper') -Destination (Join-Path $staging 'usr/local/sbin/opendock-mount-helper')
    Copy-Item -LiteralPath (Join-Path $payloadDirectory 'opendock-cuda-probe') -Destination (Join-Path $staging 'usr/local/sbin/opendock-cuda-probe')
    foreach ($vendorFile in @('yougori-oci-runtime-linux-amd64.tar.gz', 'yougori-oci-runtime-linux-amd64.manifest.json', 'yougori-nvidia-cdi-linux-amd64.tar.gz', 'yougori-nvidia-cdi-linux-amd64.manifest.json')) {
        Copy-Item -LiteralPath (Join-Path $payloadDirectory $vendorFile) -Destination (Join-Path $staging 'usr/local/share/yougori-oci-runtime')
    }
    $installer = [IO.File]::ReadAllText((Join-Path $AssetsDirectory 'install-oci.py')).Replace("`r`n", "`n")
    [IO.File]::WriteAllText((Join-Path $staging 'usr/local/sbin/opendock-cuda-install-oci.py'), $installer, [Text.UTF8Encoding]::new($false))
    foreach ($script in @('setup', 'start')) {
        $contents = [IO.File]::ReadAllText((Join-Path $AssetsDirectory "$script.sh")).Replace("`r`n", "`n")
        [IO.File]::WriteAllText((Join-Path $staging "usr/local/sbin/opendock-cuda-$script"), $contents, [Text.UTF8Encoding]::new($false))
    }
    $bundle = Join-Path $staging 'payload.tar'
    & tar.exe -cf $bundle -C $staging etc usr
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare CUDA runtime payload.' }
    # Binary stdin avoids mounting the Windows drive or interpreting its paths in a shell.
    # Refuse redirected ancestors and aliased existing leaves before tar can
    # overwrite anything. The registered owned distro is stopped before setup.
    $preflight = @'
set -eu
for directory in /etc /usr /usr/local /usr/local/sbin /usr/local/share /usr/local/share/yougori-oci-runtime; do
  test ! -L "$directory" || { echo 'Redirected CUDA payload directory; files were kept.' >&2; exit 1; }
  test ! -e "$directory" || test -d "$directory" || exit 1
done
for file in /etc/wsl.conf /etc/opendock-cuda-runtime /usr/local/sbin/opendock-agent /usr/local/sbin/opendock-mount-helper /usr/local/sbin/opendock-cuda-probe /usr/local/sbin/opendock-cuda-setup /usr/local/sbin/opendock-cuda-start /usr/local/sbin/opendock-cuda-install-oci.py /usr/local/share/yougori-oci-runtime/yougori-oci-runtime-linux-amd64.tar.gz /usr/local/share/yougori-oci-runtime/yougori-oci-runtime-linux-amd64.manifest.json /usr/local/share/yougori-oci-runtime/yougori-nvidia-cdi-linux-amd64.tar.gz /usr/local/share/yougori-oci-runtime/yougori-nvidia-cdi-linux-amd64.manifest.json; do
  test ! -L "$file" || { echo 'Redirected CUDA payload file; files were kept.' >&2; exit 1; }
  if test -e "$file"; then test -f "$file" && test "$(stat -c %h "$file")" = 1 || { echo 'Aliased CUDA payload file; files were kept.' >&2; exit 1; }; fi
done
'@
    # Windows PowerShell 5 rewrites embedded quotes in native argv. Keep shell
    # source out of argv and use the existing binary/BOM-safe stdin sender.
    if ($distro -cnotmatch '^OpenDock-CUDA-[a-f0-9]{12}$') { throw 'Invalid owned CUDA distribution name. Setup stopped.' }
    $preflightPath = Join-Path $staging 'preflight.sh'
    [IO.File]::WriteAllText($preflightPath, ($preflight.Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    Send-CudaPayload ([Diagnostics.ProcessStartInfo]::new('wsl.exe', "--distribution $distro --user root --exec /bin/sh -s")) $preflightPath
    Send-CudaPayload ([Diagnostics.ProcessStartInfo]::new('wsl.exe', "--distribution $distro --user root --exec tar -xf - -C /")) $bundle
    Invoke-Wsl @('-d', $distro, '-u', 'root', '--exec', 'chmod', '0755', '/usr/local/sbin/opendock-agent', '/usr/local/sbin/opendock-mount-helper', '/usr/local/sbin/opendock-cuda-probe', '/usr/local/sbin/opendock-cuda-start', '/usr/local/sbin/opendock-cuda-setup')
    # Apply only this owned distribution's no-automount/no-interop configuration.
    Invoke-Wsl @('--terminate', $distro)
    Invoke-Wsl @('-d', $distro, '-u', 'root', '--exec', '/bin/bash', '/usr/local/sbin/opendock-cuda-setup')
    Invoke-Wsl @('-d', $distro, '-u', 'root', '--exec', '/usr/local/sbin/opendock-agent', '--prepare-container-storage')
    Invoke-Wsl @('--terminate', $distro)
    $payloadChecksum = Get-CudaSha256 (Join-Path $payloadDirectory 'SHA256SUMS')
    [IO.File]::WriteAllText((Join-Path $dataPath 'installed.json'), (ConvertTo-Json @{ version = 1; distribution = $distro; identity = $digest; payloadChecksum = $payloadChecksum }), [Text.UTF8Encoding]::new($false))
    Write-Output "CUDA backend ready: $distro"
} finally {
    $resolvedStaging = [IO.Path]::GetFullPath($staging)
    if ([IO.Path]::GetDirectoryName($resolvedStaging) -ieq $dataPath -and [IO.Path]::GetFileName($resolvedStaging).StartsWith('setup-')) {
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
    $installLock.Dispose()
}
} catch {
    # A stable, plain-text marker lets the app show the actual setup failure.
    Write-Output ('YOUGORI_CUDA_SETUP_ERROR: ' + ($_.Exception.Message -replace '[\r\n]+', ' '))
    Write-Error $_ -ErrorAction Continue
    exit 1
}
