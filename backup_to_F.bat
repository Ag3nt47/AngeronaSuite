@echo off
setlocal
title Angerona - Backup to F:

REM One-click default used by the desktop shortcut. An explicit destination is
REM still accepted for maintenance/testing: backup_to_F.bat "X:\path\Angerona"
set "SRC=%~dp0"
set "DST=%~1"
if not defined DST (
  set "DST=F:\Angerona-Backups\Angerona"
  set "PAUSE_ON_EXIT=1"
)
for %%S in ("%SRC%") do set "SRC=%%~fS"
for %%D in ("%DST%") do set "DST=%%~fD"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"

echo(
echo ============================================
echo   Angerona - Backup to F:
echo ============================================
echo   Source : %SRC%
echo   Target : %DST%
echo(

if /I "%SRC%"=="%DST%" (
  echo [ERROR] Source and destination must be different.
  set "RC=2"
  goto finish
)
if not exist "%SRC%" (
  echo [ERROR] Source folder not found.
  set "RC=2"
  goto finish
)
if /I "%DST:~0,2%"=="F:" if not exist "F:\" (
  echo [ERROR] The F: backup drive is not connected.
  echo         Connect the My Passport drive and try again.
  set "RC=2"
  goto finish
)
if not exist "%DST%" (
  mkdir "%DST%"
  if errorlevel 1 (
    echo [ERROR] Could not create the backup folder.
    set "RC=1"
    goto finish
  )
)

echo Mirroring the project. Rebuildable environments, runtime data, diagnostics,
echo caches, and the private .env file are excluded.
echo(
"%SystemRoot%\System32\robocopy.exe" "%SRC%" "%DST%" /MIR /XD __pycache__ venv .venv node_modules runtime-data diagnostics /XF *.pyc .env /R:1 /W:1 /NP /NFL /NDL /NJH
set "RC=%ERRORLEVEL%"

if %RC% GEQ 8 (
  echo [ERROR] Backup was incomplete. Robocopy returned code %RC%.
) else (
  echo [DONE] Backup complete: %DST%
  echo        Robocopy status %RC% is successful.
)

:finish
echo(
if defined PAUSE_ON_EXIT pause
exit /b %RC%
