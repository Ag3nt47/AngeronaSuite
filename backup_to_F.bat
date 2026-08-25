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
    echo           Recommended: choose N, close apps using F:, then run:
    echo             chkdsk F: /f
    "%SystemRoot%\System32\choice.exe" /C YN /N /M "Continue anyway? [Y/N] "
    if errorlevel 2 goto finish
  )
)

REM CHOICE returns errorlevel 1 for Y. Do not treat that stale value as a
REM directory-creation failure: verify the requested directory itself instead.
call :ensure_directory "F:\Angerona-Backups" "protected backup root"
if errorlevel 1 (
  set "RC=17"
  goto finish
)
call :ensure_directory "%DST%" "backup folder"
if errorlevel 1 (
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

REM The broad .env.* exclusion also matches the tracked public template. Sync
REM only this exact file after private state is gone; never relax the wildcard.
call :sync_public_env_example
if errorlevel 1 (
  echo [ERROR] The public environment template could not be synchronized.
  set "RC=19"
  goto finish
)

echo [DONE] Backup complete. Robocopy status %ROBOCOPY_RC% is successful.
set "RC=0"
goto finish

:ensure_directory
if exist "%~1\" exit /b 0
REM Keep stderr visible so a genuine read-only/corrupt/permission failure is
REM actionable instead of collapsing into a generic message.
mkdir "%~1" >nul
if exist "%~1\" exit /b 0
echo [ERROR] Could not create the %~2. Nothing was copied.
echo         Review the Windows error above and the health of F:.
exit /b 1

:validate_boundary
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SAFETY%" -Mode Validate -Source "%SRC%" -Destination "%DST_VALIDATION%" -LauncherPath "%LAUNCHER%" >nul 2>&1
exit /b %ERRORLEVEL%

:scrub_private_state
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SAFETY%" -Mode Scrub -Source "%SRC%" -Destination "%DST_VALIDATION%" -LauncherPath "%LAUNCHER%" >nul 2>&1
exit /b %ERRORLEVEL%

:sync_public_env_example
if exist "%SRC%\.env.example" (
  copy /B /Y "%SRC%\.env.example" "%DST%\.env.example" >nul 2>&1
  exit /b %ERRORLEVEL%
)
if exist "%DST%\.env.example" del /F /Q "%DST%\.env.example" >nul 2>&1
if exist "%DST%\.env.example" exit /b 1
exit /b 0

:finish
echo(
if defined PAUSE_ON_EXIT pause
exit /b %RC%
