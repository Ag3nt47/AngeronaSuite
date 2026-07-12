<#
================================================================================
  finalize-and-deploy.ps1
  Moves the new Angerona Suite to its clean home and makes the backup copy.

    1. Copies  D:\local-security-ai\AngeronaSuite  ->  D:\Angerona   (clean repo)
    2. Initializes a git repo there (ready to push to GitHub) if git is present
    3. Mirrors  D:\Angerona  ->  F:\Angerona-Backups\Angerona  (passive copy)

  Safe + re-runnable: uses robocopy mirroring; excludes venv/__pycache__/.git
  from the backup. Nothing here auto-launches.

  RUN (no admin needed):
    powershell -NoProfile -ExecutionPolicy Bypass -File "D:\local-security-ai\AngeronaSuite\finalize-and-deploy.ps1"
================================================================================
#>

$ErrorActionPreference = 'Stop'
$stage = 'D:\local-security-ai\AngeronaSuite'
$home_ = 'D:\Angerona'
$fbak  = 'F:\Angerona-Backups\Angerona'

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
Say "=== Finalize & deploy Angerona Suite ===" Cyan

if (-not (Test-Path $stage)) { Say "Staging folder not found: $stage" Red; exit 1 }

# 1) Stage -> D:\Angerona ------------------------------------------------------
Say "`n[1] Copying to $home_ ..." Cyan
$rc = robocopy "$stage" "$home_" /MIR /XD __pycache__ venv .git /NFL /NDL /NP /NJH
if ($LASTEXITCODE -ge 8) { Say "robocopy error ($LASTEXITCODE)" Red; exit $LASTEXITCODE }
Say "    done -> $home_" Green

# 2) git init (ready for GitHub) ----------------------------------------------
Say "`n[2] Git repository ..." Cyan
if (Get-Command git -ErrorAction SilentlyContinue) {
    Push-Location $home_
    if (-not (Test-Path (Join-Path $home_ '.git'))) {
        git init -b main | Out-Null
        git add . | Out-Null
        git -c user.email="you@example.com" -c user.name="Angerona" commit -m "Initial commit: Angerona Security Suite v1.0.0" | Out-Null
        Say "    initialized git repo + first commit" Green
        Say "    next:  git remote add origin https://github.com/<you>/Angerona.git ; git push -u origin main" DarkGray
    } else {
        Say "    git repo already exists (left as-is)" DarkGray
    }
    Pop-Location
} else {
    Say "    git not installed - skipped. Install Git, then run 'git init' in $home_" Yellow
}

# 3) Mirror copy to F: --------------------------------------------------------
Say "`n[3] Backup copy to My Passport (F:) ..." Cyan
if (Test-Path 'F:\') {
    $rc2 = robocopy "$home_" "$fbak" /MIR /XD __pycache__ venv .git /NFL /NDL /NP /NJH
    if ($LASTEXITCODE -ge 8) { Say "    backup robocopy error ($LASTEXITCODE)" Red }
    else { Say "    backup done -> $fbak" Green }
} else {
    Say "    F: not connected - skipped. Plug in My Passport and re-run to back up." Yellow
}

Say "`n================ DONE ================" Green
Say "Clean repo : $home_"
Say "Backup     : $fbak  (if F: was connected)"
Say "Run it     : cd $home_ ; .\install.bat ; .\run.bat"
Say "You can delete the staging copy at $stage once you've confirmed $home_ works."
