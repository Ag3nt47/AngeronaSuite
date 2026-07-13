@echo off
setlocal
REM ============================================================================
REM  backup_to_F.bat  -  Mirror the Angerona project to the F: backup drive.
REM    Source : D:\local-security-ai\AngeronaSuite
REM    Target : F:\Angerona-Backups\Angerona
REM  Keeps .git history and .env (your own external drive); skips rebuildable
REM  junk (venv, __pycache__, *.pyc, node_modules). Safe + re-runnable.
REM ============================================================================
title Angerona - Backup to F:

set "SRC=D:\local-security-ai\AngeronaSuite"
set "DST=F:\Angerona-Backups\Angerona"

echo(
echo ============================================
echo   Angerona  -  Backup to F:
echo ============================================
echo   Source : %SRC%
echo   Target : %DST%
echo(

if not exist "%SRC%\" (
  echo [ERROR] Source folder not found:
  echo         %SRC%
  echo Nothing was backed up.
  goto :end
)

if not exist "F:\" (
  echo [SKIPPED] The F: drive is not connected.
  echo Plug in the My Passport ^(F:^) drive and run this again.
  goto :end
)

if not exist "%DST%\" mkdir "%DST%"

echo Mirroring... the first run can take a minute.
echo(
robocopy "%SRC%" "%DST%" /MIR /XD __pycache__ venv .venv node_modules /XF *.pyc /R:1 /W:1 /NP /NFL /NDL /NJH
set "RC=%ERRORLEVEL%"

echo(
if %RC% GEQ 8 (
  echo [ERROR] robocopy reported errors ^(code %RC%^). Backup may be incomplete.
) else (
  echo [DONE] Backup complete  -^>  %DST%
  echo        ^(robocopy status code %RC% = success^)
)

:end
echo(
pause
endlocal
