# Creates a Desktop shortcut "Angerona - Push to GitHub" that runs
# push-to-github.bat in this folder. Run via create-push-shortcut.bat.
$ErrorActionPreference = 'Stop'
$ws      = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$target  = Join-Path $PSScriptRoot 'push-to-github.bat'
$lnkPath = Join-Path $desktop 'Angerona - Push to GitHub.lnk'

if (-not (Test-Path $target)) {
    Write-Host "[ERROR] push-to-github.bat not found next to this script." -ForegroundColor Red
    exit 1
}

$lnk = $ws.CreateShortcut($lnkPath)
$lnk.TargetPath        = $target
$lnk.WorkingDirectory  = $PSScriptRoot
$lnk.IconLocation      = "$env:SystemRoot\System32\shell32.dll,45"   # upload/cloud-ish icon
$lnk.Description        = 'Commit and push AngeronaSuite to GitHub'
$lnk.Save()

Write-Host "[OK] Desktop shortcut created:" -ForegroundColor Green
Write-Host "     $lnkPath"
