# Inference Solver: per-user CLI installer, compatible with Windows PowerShell 5.1.
# Served with a server-bound configuration. No keys, admin rights or global Python.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOLVER_CONFIG_BASE64__')) | ConvertFrom-Json
    if ($env:OS -ne 'Windows_NT') { throw 'This installer is for Windows.' }
    if ($config.harness -notmatch '^[a-z][a-z0-9-]*$' -or $config.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Invalid installer configuration.' }
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $arch = switch ($architecture) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw 'A 64-bit Windows installation is required.' } }
    $runtime = $config.python.$arch
    $root = if ($env:INFERENCE_SOLVER_HOME) { $env:INFERENCE_SOLVER_HOME } else { Join-Path $env:LOCALAPPDATA 'InferenceSolver\cli' }
    $root = [IO.Path]::GetFullPath($root).TrimEnd('\')
    if ($root.Length -lt 5 -or $root -match '[\r\n]') { throw 'Choose a normal installation folder.' }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    function Child-Path([string]$path) {
        $full = [IO.Path]::GetFullPath($path)
        if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installation path escaped its folder.' }
        return $full
    }
    function Folder([string]$path) {
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'An installation folder is redirected or is not a directory.' }
        } else { [void][IO.Directory]::CreateDirectory($path) }
    }
    function Write-Atomic([string]$path, [string]$text, [Text.Encoding]$encoding) {
        $path = Child-Path $path
        $temp = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            [IO.File]::WriteAllText($temp, $text, $encoding)
            if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp, $path, [NullString]::Value) }
            else { [IO.File]::Move($temp, $path) }
        } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
    }
    function File-Hash([string]$path) {
        $hash = [Security.Cryptography.SHA256]::Create()
        $stream = [IO.File]::OpenRead($path)
        try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
        finally { $stream.Dispose(); $hash.Dispose() }
    }
    function Artifact([string]$url, [string]$sha) {
        if ($sha -notmatch '^[a-f0-9]{64}$') { throw 'Invalid download checksum.' }
        $uri = [Uri]$url
        $isolated = $uri.Scheme -eq 'http' -and $uri.Host -cmatch '^[a-z0-9]+\.localhost$'
        if (-not $uri.IsAbsoluteUri -or $uri.UserInfo -or $uri.Fragment -or ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and ($uri.Host -in @('127.0.0.1','localhost','[::1]') -or $isolated)))) { throw 'Downloads require HTTPS; HTTP is allowed only for localhost previews.' }
        $path = Child-Path (Join-Path $root ('cache\' + $sha + '.zip'))
        if ((Test-Path -LiteralPath $path -PathType Leaf) -and (File-Hash $path) -ceq $sha) { return $path }
        $temp = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        $response = $null; $stream = $null; $file = $null
        try {
            $target = $uri
            if ($isolated) { $target = [Uri]('http://127.0.0.1:' + $uri.Port + $uri.PathAndQuery) }
            $request = [Net.HttpWebRequest]::Create($target)
            if ($isolated) { $request.Host = $uri.Authority; $request.Proxy = $null }
            $request.AllowAutoRedirect = $false
            $request.Timeout = 60000; $request.ReadWriteTimeout = 60000
            $response = $request.GetResponse()
            if ([int]$response.StatusCode -ne 200) { throw 'Download was refused or redirected.' }
            if ($response.ContentLength -gt 67108864) { throw 'Download is too large.' }
            $stream = $response.GetResponseStream()
            $file = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $buffer = New-Object byte[] 65536
            $total = 0
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $count
                if ($total -gt 67108864) { throw 'Download is too large.' }
                $file.Write($buffer, 0, $count)
            }
            $file.Dispose(); $file = $null
            if ((File-Hash $temp) -cne $sha) { throw 'Download checksum mismatch. Re-run the install command to get the current release.' }
            if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp, $path, [NullString]::Value) }
            else { [IO.File]::Move($temp, $path) }
            return $path
        } finally {
            if ($file) { $file.Dispose() }; if ($stream) { $stream.Dispose() }; if ($response) { $response.Dispose() }
            if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
        }
    }
    function Expand-Safe([string]$zip, [string]$destination) {
        $destination = Child-Path $destination
        Folder $destination
        $archive = [IO.Compression.ZipFile]::OpenRead($zip)
        try {
            if ($archive.Entries.Count -gt 2048) { throw 'Too many archive entries.' }
            $total = 0
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $archive.Entries) {
                $name = $entry.FullName
                if ($name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/') -or (($entry.ExternalAttributes -shr 16) -band 61440) -eq 40960) { throw 'Unsafe archive entry.' }
                $target = [IO.Path]::GetFullPath((Join-Path $destination $name))
                if (-not $target.StartsWith($destination + '\', [StringComparison]::OrdinalIgnoreCase) -or -not $seen.Add($target)) { throw 'Archive entry escaped its folder or is duplicated.' }
                $total += $entry.Length
                if ($total -gt 268435456) { throw 'Expanded archive is too large.' }
                if ($name.EndsWith('/')) { Folder $target; continue }
                Folder ([IO.Path]::GetDirectoryName($target))
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)
            }
        } finally { $archive.Dispose() }
    }

    Folder $root
    foreach ($part in @('cache','releases','runtimes','bin')) { Folder (Join-Path $root $part) }
    $lock = $null; $stages = @()
    try {
        try { $lock = [IO.File]::Open((Join-Path $root 'install.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch { throw 'Another Inference Solver installation is running. Try again when it finishes.' }
        if (-not $config.runtime_only) { Write-Host ('Installing solver-' + $config.harness + ' for ' + $config.server) -ForegroundColor Cyan }
        $runtimeName = 'python-' + $config.python_version + '-' + $arch
        $runtimeFolder = Child-Path (Join-Path $root ('runtimes\' + $runtimeName))
        if (-not (Test-Path -LiteralPath $runtimeFolder)) {
            Write-Host 'Downloading the private Python runtime...' -ForegroundColor Cyan
            $archive = Artifact $runtime.url $runtime.sha256
            $stage = Child-Path (Join-Path $root ('.stage-' + [Guid]::NewGuid().ToString('N'))); $stages += $stage
            Expand-Safe $archive $stage
            [IO.Directory]::Move($stage, $runtimeFolder)
        }
        Folder $runtimeFolder
        $python = Join-Path $runtimeFolder 'python.exe'
        $version = & $python -I -B --version
        if ($LASTEXITCODE -ne 0 -or $version -ne ('Python ' + $config.python_version)) { throw 'The private Python runtime did not start correctly.' }
        if ($config.runtime_only) { return }
        $release = Child-Path (Join-Path $root ('releases\' + $config.sha256))
        if (-not (Test-Path -LiteralPath $release)) {
            $archive = Artifact $config.bundle $config.sha256
            $stage = Child-Path (Join-Path $root ('.stage-' + [Guid]::NewGuid().ToString('N'))); $stages += $stage
            Expand-Safe $archive $stage
            $connection = Get-Content -LiteralPath (Join-Path $stage 'inference-solver\connection.json') -Raw | ConvertFrom-Json
            if ($connection.server -cne $config.server -or $connection.harness -cne $config.harness) { throw 'The downloaded setup belongs to a different server or harness.' }
            & $python -I -B (Join-Path $stage 'inference-solver\cli_entry.py') ('solver-' + $config.harness) --help | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'The downloaded CLI failed its startup check.' }
            [IO.Directory]::Move($stage, $release)
        }
        Folder $release
        $command = 'solver-' + $config.harness
        $bin = Join-Path $root 'bin'
        $ownerPath = Join-Path $bin ($command + '.owner.json')
        if (Test-Path -LiteralPath $ownerPath) {
            $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
            if ($owner.schema -ne 1 -or $owner.harness -cne $config.harness) { throw 'An existing command is not owned by this installer.' }
            if ($owner.server -cne $config.server) {
                $hash = [Security.Cryptography.SHA256]::Create()
                try { $suffix = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($config.server)))).Replace('-','').Substring(0,8).ToLowerInvariant() } finally { $hash.Dispose() }
                $command += '-' + $suffix
                $ownerPath = Join-Path $bin ($command + '.owner.json')
            }
        }
        $shim = Join-Path $bin ($command + '.cmd')
        if ((Test-Path -LiteralPath $shim) -and -not (Test-Path -LiteralPath $ownerPath)) { throw 'An existing command has no ownership record. It was left untouched.' }
        if (Test-Path -LiteralPath $ownerPath) {
            $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
            if ($owner.schema -ne 1 -or $owner.server -cne $config.server -or $owner.harness -cne $config.harness) { throw 'An existing command belongs to another setup. It was left untouched.' }
        }
        # Only relative, fixed-alphabet paths are embedded in batch code. The user's
        # folder name (spaces, Unicode, %, &, etc.) is expanded once through %~dp0.
        $batch = "@echo off`r`nsetlocal DisableDelayedExpansion`r`n" +
            '"%~dp0..\runtimes\' + $runtimeName + '\python.exe" -I -B "%~dp0..\releases\' + $config.sha256 + '\inference-solver\cli_entry.py" ' + $command + ' %*' + "`r`nexit /b %errorlevel%`r`n"
        $ownership = @{schema=1;server=$config.server;harness=$config.harness;release=$config.sha256} | ConvertTo-Json
        Write-Atomic $ownerPath $ownership (New-Object Text.UTF8Encoding $false)
        Write-Atomic $shim $batch ([Text.Encoding]::ASCII)
        if ($env:INFERENCE_SOLVER_NO_PATH -ne '1') {
            $registry = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
            try {
                $old = [string]$registry.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if (-not @($old -split ';' | Where-Object { $_.Trim().Trim('"').TrimEnd('\') -ieq $bin }).Count) {
                    $updated = ($old.TrimEnd(';') + ';' + $bin).TrimStart(';')
                    if ($updated.Length -ge 32760) { throw 'PATH is too long. The CLI is installed; use its full path.' }
                    $registry.SetValue('Path', $updated, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                }
            } finally { $registry.Dispose() }
            $env:PATH = $bin + ';' + $env:PATH
            if (-not ('InferenceSolver.EnvironmentNotice' -as [type])) {
                Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace InferenceSolver { public static class EnvironmentNotice {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr wparam, string lparam, uint flags, uint timeout, out IntPtr result);
} }
'@
            }
            $result = [IntPtr]::Zero
            [void][InferenceSolver.EnvironmentNotice]::SendMessageTimeout([IntPtr]0xffff, 0x001a, [IntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
        }
        Write-Host ''
        Write-Host ('Installed ' + $command) -ForegroundColor Cyan
        Write-Host ('Next time, run: ' + $command)
        if ($config.harness -eq 'node') {
            Write-Host 'Choose the models to contribute, then approve the computer code on the website.'
            Write-Host 'This connector shares selected Yougori models. Cloud rentals run on the website backend.'
        } else {
            Write-Host 'Sign in with the code shown below. No API key needs to be copied.'
            Write-Host 'First launch prepares your Sandbox VM. Keep this terminal open.'
        }
    } finally {
        if ($lock) { $lock.Dispose() }
        foreach ($stage in $stages) {
            $safe = Child-Path $stage
            if ((Test-Path -LiteralPath $safe) -and -not ((Get-Item -LiteralPath $safe -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($safe, $true) }
        }
    }
    # Release the installer lock before the interactive session. The default
    # command opens immediately; the opt-out is for unattended packaging/tests.
    if ($config.harness -ne 'node' -and $env:INFERENCE_SOLVER_NO_LAUNCH -ne '1') {
        Write-Host ''
        Write-Host ('Starting ' + $command + '...') -ForegroundColor Cyan
        & $shim
        $launchCode = $LASTEXITCODE
        Write-Host ''
        Write-Host ('To open it again, run: ' + $command) -ForegroundColor Cyan
        if ($launchCode -ne 0 -and $launchCode -ne 130) {
            throw ('Installation succeeded, but the harness stopped (exit ' + $launchCode + '). Fix the error above, then run ' + $command + ' again.')
        }
    }
}
