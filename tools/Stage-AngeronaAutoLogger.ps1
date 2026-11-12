<#
.SYNOPSIS
  Stage (or remove) a Windows ETW AutoLogger session that records process
  start/stop events while Angerona is not running.

.DESCRIPTION
  Angerona's own sensors stop when its process stops, so a restart leaves an
  unobserved interval. An AutoLogger session is owned by Windows: it starts at
  boot, before any user-mode security tool, and keeps running whatever happens
  to Angerona. This script registers one bounded, circular session:

    Session   AngeronaBoot
    Provider  Microsoft-Windows-Kernel-Process (process start/stop only)
    File      %ProgramData%\Angerona\etw\AngeronaBoot.etl  (circular, 64 MB)

  Default is a DRY RUN that only prints what would change. Nothing is written
  without -Apply, and -Apply/-Remove require an elevated PowerShell.
  The session becomes active at the next boot.

  LIMITS (read before relying on it)
    * Angerona does not yet read this file automatically. Review it with
      `tracerpt` or Event Viewer (Open Saved Log) until replay-on-start exists.
    * An administrator can stop or remove the session; it is not tamper-proof.
    * Process events only: no network, file or registry telemetry.

.PARAMETER Apply
  Create or update the AutoLogger registration.
.PARAMETER Remove
  Delete the AutoLogger registration. The .etl file is left in place.
#>
[CmdletBinding()]
param([switch]$Apply, [switch]$Remove)

$ErrorActionPreference = 'Stop'
$SessionName  = 'AngeronaBoot'
$SessionGuid  = '{6F1B7C52-3A0E-4D5B-9C41-7E2A9D8B4F10}'
$ProviderGuid = '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}'   # Microsoft-Windows-Kernel-Process
$ProcessKeyword = 0x10                                      # WINEVENT_KEYWORD_PROCESS
$Root   = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
$Key    = Join-Path $Root $SessionName
$EtlDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Angerona\etw'
$Etl    = Join-Path $EtlDir "$SessionName.etl"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($Apply -and $Remove) { throw 'Choose either -Apply or -Remove.' }

# Test-Path answers True for any name here when the key is unreadable
# (unelevated), so read the key itself and report "unknown" on access denial.
$present = $false
$state = 'not registered'
try {
    [void](Get-ItemProperty -Path $Key -Name 'Start' -ErrorAction Stop)
    $present = $true
    $state = 'registered'
} catch [System.Security.SecurityException] {
    $state = 'unknown: run elevated to read this key'
} catch {
    $state = 'not registered'
}
Write-Output "AutoLogger session : $SessionName ($state)"
Write-Output "Registry key       : $Key"
Write-Output "Trace file         : $Etl (circular, 64 MB)"
Write-Output "Provider           : Microsoft-Windows-Kernel-Process, process start/stop"

if (-not $Apply -and -not $Remove) {
    Write-Output ''
    Write-Output 'DRY RUN: nothing was changed. Re-run elevated with -Apply to register, or -Remove to delete.'
    exit 0
}
if (-not (Test-Admin)) { throw 'This change requires an elevated (administrator) PowerShell.' }

if ($Remove) {
    if (Test-Path $Key) { Remove-Item -Path $Key -Recurse -Force }
    Write-Output 'Removed. The session will not start at the next boot. Existing .etl files were kept.'
    exit 0
}

New-Item -ItemType Directory -Path $EtlDir -Force | Out-Null
New-Item -Path $Key -Force | Out-Null
Set-ItemProperty -Path $Key -Name 'Start'        -Type DWord  -Value 1
Set-ItemProperty -Path $Key -Name 'Guid'         -Type String -Value $SessionGuid
Set-ItemProperty -Path $Key -Name 'FileName'     -Type String -Value $Etl
Set-ItemProperty -Path $Key -Name 'LogFileMode'  -Type DWord  -Value 0x2      # EVENT_TRACE_FILE_MODE_CIRCULAR
Set-ItemProperty -Path $Key -Name 'MaxFileSize'  -Type DWord  -Value 64       # MB
Set-ItemProperty -Path $Key -Name 'BufferSize'   -Type DWord  -Value 64       # KB
Set-ItemProperty -Path $Key -Name 'MinimumBuffers' -Type DWord -Value 8
Set-ItemProperty -Path $Key -Name 'MaximumBuffers' -Type DWord -Value 32
Set-ItemProperty -Path $Key -Name 'ClockType'    -Type DWord  -Value 2        # system time

$ProviderKey = Join-Path $Key $ProviderGuid
New-Item -Path $ProviderKey -Force | Out-Null
Set-ItemProperty -Path $ProviderKey -Name 'Enabled'         -Type DWord -Value 1
Set-ItemProperty -Path $ProviderKey -Name 'EnableLevel'     -Type DWord -Value 4   # informational
Set-ItemProperty -Path $ProviderKey -Name 'MatchAnyKeyword' -Type QWord -Value $ProcessKeyword

# Readback: report exactly what is now registered.
$check = Get-ItemProperty -Path $Key
$provider = Get-ItemProperty -Path $ProviderKey
if ($check.Start -ne 1 -or $check.FileName -ne $Etl -or $provider.Enabled -ne 1) {
    throw 'Readback did not match the requested registration.'
}
Write-Output 'Registered and verified. The session starts at the next boot.'
Write-Output "Undo: .\Stage-AngeronaAutoLogger.ps1 -Remove"
