<#
Creates the supported Angerona Desktop shortcut.

The Black Box recorder is launched as a child of the elevated suite. A separate
unelevated recorder shortcut is intentionally not created because packaged
runtime evidence is protected for Administrators and SYSTEM only.
#>
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$launcher = Join-Path $root 'start-angerona.bat'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw "Supported launcher not found: $launcher"
}

$desktops = @()
try { $desktops += [Environment]::GetFolderPath('Desktop') } catch {}
if ($env:USERPROFILE) { $desktops += (Join-Path $env:USERPROFILE 'Desktop') }
if ($env:OneDrive) { $desktops += (Join-Path $env:OneDrive 'Desktop') }
$desktops = $desktops |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
    Select-Object -Unique

$wsh = New-Object -ComObject WScript.Shell
$icon = Join-Path $root 'assets\icons\angerona.ico'
$made = 0
foreach ($desktop in $desktops) {
    $link = Join-Path $desktop 'Angerona.lnk'
    $shortcut = $wsh.CreateShortcut($link)
    $shortcut.TargetPath = $launcher
    $shortcut.WorkingDirectory = $root
    if (Test-Path -LiteralPath $icon -PathType Leaf) {
        $shortcut.IconLocation = $icon
    }
    $shortcut.Description = 'Angerona local-first endpoint security suite'
    $shortcut.Save()
    if (Test-Path -LiteralPath $link -PathType Leaf) { $made++ }
}

if ($made -eq 0) { throw 'No writable Desktop location was found.' }
Write-Host "Created $made Angerona Desktop shortcut(s)." -ForegroundColor Green
