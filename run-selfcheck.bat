@echo off
REM ============================================================================
REM  Angerona - headless self-check. Builds the whole app + dashboard dialogs
REM  offscreen and runs every module self_test. No admin, no window, no clicks.
REM  All output is written to selfcheck_report.txt (console optional).
REM ============================================================================
cd /d "%~dp0"
set "QT_QPA_PLATFORM=offscreen"
set "REPORT=%~dp0selfcheck_report.txt"

if not exist "venv\Scripts\python.exe" (
    echo [!] venv not found. Run install.bat first. > "%REPORT%"
    exit /b 1
)

echo Running Angerona self-check... > "%REPORT%"
"venv\Scripts\python.exe" -u -X utf8 tools\selfcheck.py >> "%REPORT%" 2>&1
echo. >> "%REPORT%"
echo (exit code %errorlevel%) >> "%REPORT%"
