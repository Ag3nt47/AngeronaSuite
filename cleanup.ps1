<#
================================================================================
  cleanup.ps1 — purge local build/runtime artifacts for a pristine, reproducible
  checkout (the state you want before committing / pushing to GitHub).

  Removes: venv, __pycache__, *.egg-info, build/dist, *.pyc, runtime databases
  and logs, diagnostics artifacts, and Posture-Hardening remediation output.

  Does NOT touch: source code, docs, your local .env (secrets), or git history.
  Everything it removes is either rebuildable (venv via install.bat) or runtime
  state the app regenerates — and all of it is already in .gitignore.
================================================================================
#>
$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "[*] Cleaning Angerona working tree: $root" -ForegroundColor Cyan

# Whole directories that are rebuildable / runtime-only.
foreach ($d in @('venv', 'build', 'dist', 'src\angerona.egg-info', 'logs', 'remediations')) {
    $p = Join-Path $root $d
    if (Test-Path $p) { Write-Host "  - $d"; Remove-Item $p -Recurse -Force }
}

# __pycache__ anywhere in the tree, plus compiled files.
Get-ChildItem $root -Recurse -Directory -Filter '__pycache__' |
    ForEach-Object { Remove-Item $_.FullName -Recurse -Force }
Get-ChildItem $root -Recurse -File -Include '*.pyc', '*.pyo' | Remove-Item -Force

# Runtime databases + logs anywhere.
Get-ChildItem $root -Recurse -File -Include '*.db', '*.sqlite', '*.sqlite3', '*.log' |
    Remove-Item -Force

# Diagnostics artifacts (keep the folder so the app can write to it again).
$diag = Join-Path $root 'diagnostics'
if (Test-Path $diag) { Get-ChildItem $diag -File | Remove-Item -Force }
Remove-Item (Join-Path $root 'custom_user_patch.ps1') -Force -ErrorAction SilentlyContinue

Write-Host "[+] Clean. Rebuild with: install.bat  (recreates venv + installs deps)" -ForegroundColor Green
Write-Host "    Your local .env (secrets) was left untouched." -ForegroundColor DarkGray
