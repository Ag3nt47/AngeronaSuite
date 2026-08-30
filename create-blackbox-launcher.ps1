<#
Creates the supported Angerona Desktop shortcut.

For a source checkout this creates an unelevated Observe/development shortcut.
Full protected recorder custody is available only from the signed installed
build, not from this mutable source helper.
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
    $shortcut.Description = 'Angerona source Observe/development profile (unelevated)'
    $shortcut.Save()
    if (Test-Path -LiteralPath $link -PathType Leaf) { $made++ }
}

if ($made -eq 0) { throw 'No writable Desktop location was found.' }
Write-Host "Created $made Angerona Desktop shortcut(s)." -ForegroundColor Green
