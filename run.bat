@echo off
REM ============================================================================
REM  Angerona launcher. Self-elevates to Administrator (needed for full-system
REM  telemetry), then starts the GUI.
REM ============================================================================
cd /d "%~dp0"

REM Keep every persistent/runtime write on the D: installation drive.
set "ANGERONA_DATA=%~dp0runtime-data"
set "ANGERONA_DIAG_DIR=%~dp0diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=1"
set "TEMP=%~dp0runtime-data\tmp"
set "TMP=%TEMP%"
if not exist "%ANGERONA_DATA%" mkdir "%ANGERONA_DATA%"
if not exist "%TEMP%" mkdir "%TEMP%"

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
