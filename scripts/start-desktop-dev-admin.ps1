$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Set-Location -LiteralPath $workspace
    & npm.cmd run desktop:dev
    exit $LASTEXITCODE
}

$escapedWorkspace = $workspace.Replace("'", "''")
$command = "Set-Location -LiteralPath '$escapedWorkspace'; & npm.cmd run desktop:dev; `$yougoriExitCode = `$LASTEXITCODE; if (`$yougoriExitCode -ne 0) { Write-Host ''; Write-Host 'Yougori development exited with an error.' -ForegroundColor Red; Read-Host 'Press Enter to close this window' }; exit `$yougoriExitCode"
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

Write-Host 'Requesting administrator access for Yougori development...'
$child = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -WorkingDirectory $workspace `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
exit $child.ExitCode
