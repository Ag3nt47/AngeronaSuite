@echo off
REM ============================================================================
REM  Angerona launcher. Self-elevates to Administrator (needed for full-system
REM  telemetry), then starts the GUI.
REM ============================================================================
cd /d "%~dp0"

REM ── Re-launch elevated if not already admin ─────────────────────────────────
net session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "VENV_PY=%~dp0venv\Scripts\pythonw.exe"
if not exist "%VENV_PY%" (
    echo [!] venv not found. Run start-angerona.bat (or install.bat) first.
    pause
    exit /b 1
)

REM pythonw = no console window for the GUI
start "" "%VENV_PY%" -m angerona
