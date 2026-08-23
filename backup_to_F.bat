@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Angerona - Backup to F:

REM One-click default used by the desktop shortcut. An explicit destination is
REM accepted only beneath F:\Angerona-Backups. The optional second argument is
REM a non-destructive guard check used by release validation:
REM   backup_to_F.bat "F:\Angerona-Backups\Angerona" --validate-only
set "SRC=%~dp0"
set "DST=%~1"
set "VALIDATE_ONLY=0"
set "RC=16"
set "LAUNCHER=%~f0"
if /I "%~2"=="--validate-only" set "VALIDATE_ONLY=1"
if not defined DST (
  set "DST=F:\Angerona-Backups\Angerona"
  set "PAUSE_ON_EXIT=1"
)
set "DST_VALIDATION=%DST%"
for %%S in ("%SRC%") do set "SRC=%%~fS"
for %%D in ("%DST%") do set "DST=%%~fD"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"
if "%DST:~-1%"=="\" set "DST=%DST:~0,-1%"
set "SAFETY=%SRC%\tools\backup_to_f_safety.ps1"

echo(
echo ============================================
echo   Angerona - Safe Backup to F:
echo ============================================
echo(

if not exist "%SAFETY%" (
  echo [ERROR] Backup safety component is missing. Nothing was copied.
  goto finish
)

call :validate_boundary
if errorlevel 1 (
  echo [ERROR] Backup location failed the safety check. Nothing was copied.
  goto finish
)
if "%VALIDATE_ONLY%"=="1" (
  echo [PASS] Backup boundary is safe. Validation only; nothing was copied.
  set "RC=0"
  goto finish
)

if defined PAUSE_ON_EXIT (
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "$v=Get-Volume -DriveLetter F -ErrorAction SilentlyContinue; if ($v -and $v.HealthStatus -eq 'Healthy' -and $v.OperationalStatus -contains 'OK') {exit 0}; exit 1" >nul 2>&1
  if errorlevel 1 (
    echo [WARNING] Windows reports that F: needs repair.
    echo           Backing up to an unhealthy filesystem can damage the backup.
    "%SystemRoot%\System32\choice.exe" /C YN /N /M "Continue anyway? [Y/N] "
    if errorlevel 2 goto finish
  )
)

if not exist "F:\Angerona-Backups" mkdir "F:\Angerona-Backups" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Could not create the protected backup root. Nothing was copied.
  set "RC=17"
  goto finish
)
if not exist "%DST%" mkdir "%DST%" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Could not create the backup folder. Nothing was copied.
  set "RC=17"
  goto finish
)

REM Re-check after directory creation to close junction/reparse substitution gaps.
call :validate_boundary
if errorlevel 1 (
  echo [ERROR] Backup location changed during validation. Nothing was copied.
  goto finish
)

REM /MIR leaves excluded destination items untouched, so remove only the
REM validator's strict private/runtime allowlist before and after the mirror.
call :scrub_private_state
if errorlevel 1 (
  echo [ERROR] Existing private backup state could not be removed safely.
  set "RC=18"
  goto finish
)

echo Mirroring public project files. Private settings, credentials, runtime data,
echo local models, reports, caches, environments, and generated builds are excluded.
echo(
"%SystemRoot%\System32\robocopy.exe" "%SRC%" "%DST%" /MIR /XJ /SL /XD "%SRC%\.venv" "%SRC%\venv" "%SRC%\env" "%SRC%\.tmp" "%SRC%\node_modules" "%SRC%\runtime-data" "%SRC%\diagnostics" "%SRC%\shared_logs" "%SRC%\quarantine" "%SRC%\flight-recorder" "%SRC%\baselines" "%SRC%\remediations" "%SRC%\heartbeats" "%SRC%\ipc" "%SRC%\models" "%SRC%\secrets" "%SRC%\drill-sandbox" "%SRC%\staged_patches" "%SRC%\shadow_cache" "%SRC%\forensics" "%SRC%\build" "%SRC%\dist" "%SRC%\.dev-tools" "%SRC%\.pytest_cache" "%SRC%\.mypy_cache" "%SRC%\.ruff_cache" "%SRC%\.hypothesis" "%SRC%\htmlcov" "%SRC%\.tox" "%SRC%\pip-wheel-metadata" "%SRC%\.eggs" "%SRC%\logs" "%SRC%\analysis\manual_build" __pycache__ .venv venv venv.incompatible.* env .tmp node_modules runtime-data diagnostics shared_logs quarantine flight-recorder baselines remediations heartbeats ipc models secrets drill-sandbox staged_patches shadow_cache forensics build dist .dev-tools .pytest_cache .mypy_cache .ruff_cache .hypothesis htmlcov .tox pip-wheel-metadata .eggs LibreOffice_* /XF *.pyc .env .env.* settings.json *.settings.json user_config.json credentials.json credentials.yaml credentials.yml secrets.json secrets.yaml secrets.yml tokens.json api_keys.json auth.json client_secret*.json client_secret*.yaml client_secret*.yml client_secret*.txt id_rsa id_ed25519 .npmrc .pypirc .netrc *.key *.pem *.pfx *.p12 *.token *.secret *.secrets ANGERONA_WATCHDOG_TOKEN* bus.key *.db *.sqlite *.sqlite3 *.log *.gguf *.hb *.ring *.bak *.tmp *.lnk *.test *.spec .coverage custom_user_patch.ps1 standdown.cmd selfcheck_report*.txt angerona_watchdog.exe frz_watchdog.exe /R:1 /W:1 /NP /NFL /NDL /NJH /NJS /NC /NS >nul 2>&1
set "ROBOCOPY_RC=%ERRORLEVEL%"
set "RC=%ROBOCOPY_RC%"
if %ROBOCOPY_RC% GEQ 8 (
  echo [ERROR] Backup was incomplete. Robocopy returned code %ROBOCOPY_RC%.
  goto finish
)

call :scrub_private_state
if errorlevel 1 (
  echo [ERROR] Post-backup privacy validation failed.
  set "RC=18"
  goto finish
)

echo [DONE] Backup complete. Robocopy status %ROBOCOPY_RC% is successful.
set "RC=0"
goto finish

:validate_boundary
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SAFETY%" -Mode Validate -Source "%SRC%" -Destination "%DST_VALIDATION%" -LauncherPath "%LAUNCHER%" >nul 2>&1
exit /b %ERRORLEVEL%

:scrub_private_state
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SAFETY%" -Mode Scrub -Source "%SRC%" -Destination "%DST_VALIDATION%" -LauncherPath "%LAUNCHER%" >nul 2>&1
exit /b %ERRORLEVEL%

:finish
echo(
if defined PAUSE_ON_EXIT pause
exit /b %RC%
