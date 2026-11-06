#requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Unregister,
    [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
    [string]$Day = 'Sunday',
    [string]$At = '04:00',
    [int]$KeepReleases = 2
)
$ErrorActionPreference = 'Stop'
$name = 'Yougori disk cleanup'

# Compaction needs administrator rights, so the task is registered elevated once.
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$admin) {
    $forward = @('-NoProfile', '-File', $PSCommandPath, '-Day', $Day, '-At', $At, '-KeepReleases', $KeepReleases)
    if ($Unregister) { $forward += '-Unregister' }
    $process = Start-Process pwsh -ArgumentList $forward -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
}

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Removed the scheduled task '$name'."
    exit 0
}

$script = Join-Path $PSScriptRoot 'disk-cleanup.ps1'
$log = Join-Path $env:LOCALAPPDATA 'Yougori\disk-cleanup.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
$pwsh = (Get-Command pwsh).Source
$action = New-ScheduledTaskAction -Execute $pwsh -WorkingDirectory (Split-Path $PSScriptRoot -Parent) `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$script`" -Clean -Compact -KeepReleases $KeepReleases -LogPath `"$log`""
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $At
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 3)
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Output "Registered '$name': every $Day at $At, keeping the newest $KeepReleases releases. Log: $log"
