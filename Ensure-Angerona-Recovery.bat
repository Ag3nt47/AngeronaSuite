@echo off
setlocal DisableDelayedExpansion
set "ERRORLEVEL="
if not exist "%~dp0venv\Scripts\python.exe" (
    echo [!] Recovery inspection needs the existing runtime. Use the normal Angerona launcher for verified setup or repair.
    exit /b 2
)
if "%~1"=="" goto ensure
if /i "%~1"=="--check-only" if "%~2"=="" goto check
echo [!] Supported option: --check-only
exit /b 1
:check
"%~dp0venv\Scripts\python.exe" -I -B "%~dp0tools\ensure_mutual_recovery.py" --check-only
exit /b %errorlevel%
:ensure
"%~dp0venv\Scripts\python.exe" -I -B "%~dp0tools\ensure_mutual_recovery.py"
exit /b %errorlevel%
