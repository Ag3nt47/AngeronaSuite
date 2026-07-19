@echo off
setlocal
REM Generic, re-runnable Angerona backup. Pass an explicit destination:
REM   backup_to_F.bat "E:\Backups\Angerona"
set "SRC=%~dp0"
set "DST=%~1"
if not defined DST (
  echo Usage: %~nx0 "X:\path\to\Angerona-backup"
  exit /b 2
)
for %%S in ("%SRC%") do set "SRC=%%~fS"
for %%D in ("%DST%") do set "DST=%%~fD"
if /I "%SRC%"=="%DST%" (
  echo [ERROR] Source and destination must be different.
  exit /b 2
)
if not exist "%SRC%" exit /b 2
if not exist "%DST%" mkdir "%DST%" || exit /b 1
"%SystemRoot%\System32\robocopy.exe" "%SRC%" "%DST%" /MIR /XD __pycache__ venv .venv node_modules runtime-data diagnostics /XF *.pyc .env /R:1 /W:1 /NP /NFL /NDL /NJH
set "RC=%ERRORLEVEL%"
if %RC% GEQ 8 exit /b %RC%
echo [DONE] Backup complete: %DST%
exit /b 0
