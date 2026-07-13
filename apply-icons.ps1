<#
  apply-icons.ps1 — give the Kill-All-Angerona and Backup-to-F batch files
  custom icons.

  A raw .bat file always shows the generic batch icon in Explorer; a custom
  icon has to live on a SHORTCUT (.lnk). So this script creates/updates:
    - "Kill All Angerona.lnk"  (project folder + Desktop)  -> skull.ico
    - "Backup to F.lnk"        (Desktop)                    -> backup_f.ico
  pointing at the real .bat files, with the icons in assets\icons\.

  Safe + idempotent: re-running just refreshes the icons. Nothing is deleted.
#>

$ErrorActionPreference = 'Stop'
$proj    = Split-Path -Parent $MyInvocation.MyCommand.Path
$icons   = Join-Path $proj 'assets\icons'
$skull   = Join-Path $icons 'skull.ico'
$fico    = Join-Path $icons 'backup_f.ico'

# Resolve the Desktop (handles OneDrive-redirected Desktops too)
$desktop = [Environment]::GetFolderPath('Desktop')

function New-IconShortcut {
    param([string]$LinkPath, [string]$Target, [string]$Icon, [string]$WorkDir)
    if (-not (Test-Path $Target)) {
        Write-Host "  ! target not found, skipping: $Target" -ForegroundColor Yellow
        return
    }
    if (-not (Test-Path $Icon)) {
        Write-Host "  ! icon not found, skipping: $Icon" -ForegroundColor Yellow
        return
    }
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($LinkPath)
    $lnk.TargetPath       = $Target
    $lnk.WorkingDirectory = $WorkDir
    $lnk.IconLocation     = "$Icon,0"
    $lnk.WindowStyle      = 1
    $lnk.Description       = "Angerona helper"
    $lnk.Save()
    Write-Host "  + $LinkPath  ->  $(Split-Path $Icon -Leaf)" -ForegroundColor Green
}

Write-Host "`nApplying Angerona batch-file icons..." -ForegroundColor Cyan

# 1) Kill-All — project folder shortcut (next to the .bat)
$killBat = Join-Path $proj 'kill-all-angerona.bat'
New-IconShortcut -LinkPath (Join-Path $proj 'Kill All Angerona.lnk') `
                 -Target $killBat -Icon $skull -WorkDir $proj

# 2) Kill-All — Desktop shortcut (prefer a desktop .bat if present, else project bat)
$killDeskBat = Join-Path $desktop 'kill-all-angerona.bat'
$killTarget  = if (Test-Path $killDeskBat) { $killDeskBat } else { $killBat }
New-IconShortcut -LinkPath (Join-Path $desktop 'Kill All Angerona.lnk') `
                 -Target $killTarget -Icon $skull -WorkDir (Split-Path $killTarget)

# 3) Backup-to-F — Desktop shortcut targeting the PROJECT copy of backup_to_F.bat
#    (so the raw .bat can be removed from the Desktop and just the icon shortcut kept)
$backupBat = Join-Path $proj 'backup_to_F.bat'
New-IconShortcut -LinkPath (Join-Path $desktop 'Backup to F.lnk') `
                 -Target $backupBat -Icon $fico -WorkDir $proj

# Nudge Explorer to refresh its icon cache
try {
    ie4uinit.exe -show 2>$null
} catch {}

Write-Host "`nDone. If an icon still looks stale, press F5 on the Desktop or sign out/in.`n" -ForegroundColor Cyan
