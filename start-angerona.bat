@echo off
REM ============================================================================
REM  Angerona - one-click start.
REM  First run: self-elevates, creates a venv, installs the app + dependencies
REM  (downloads PySide6, ~1-2 min). Every run after: just launches the GUI.
REM
REM  Finds a REAL Python even when the Microsoft Store "python.exe" stub is on
REM  PATH (the #1 cause of "Python was not found" on a fresh Windows machine).
REM ============================================================================
cd /d "%~dp0"
title Angerona launcher

REM Keep every persistent/runtime write on the D: installation drive.
set "ANGERONA_DATA=%~dp0runtime-data"
set "ANGERONA_DIAG_DIR=%~dp0diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=1"
set "TEMP=%~dp0runtime-data\tmp"
set "TMP=%TEMP%"
if not exist "%ANGERONA_DATA%" mkdir "%ANGERONA_DATA%"
if not exist "%TEMP%" mkdir "%TEMP%"

REM ── Self-elevate (full-system telemetry needs Administrator) ────────────────
net session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM ── First-run install (skip straight to launch if the venv already exists) ──
if exist "venv\Scripts\pythonw.exe" goto launch

echo [*] First run - setting up. This downloads PySide6, ~1-2 minutes...
call :find_python
if not defined PYCMD (
    echo [!] No real Python 3.10+ found.
    echo     Install it from https://www.python.org/downloads/ ^(tick "Add python.exe to PATH"^),
    echo     or turn OFF the Microsoft Store stub under
    echo     Settings ^> Apps ^> Advanced app settings ^> App execution aliases, then re-run.
    pause
    exit /b 1
)
echo [*] Using Python: %PYCMD%
%PYCMD% -m venv venv || (echo [!] venv creation failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --upgrade pip
"venv\Scripts\python.exe" -m pip install -e .[windows] || (echo [!] Install failed. & pause & exit /b 1)

:launch
REM ── Launch (pythonw = no console window) ─────────────────────────────────────
echo [*] Launching Angerona...
start "" "venv\Scripts\pythonw.exe" -m angerona

REM ── Black Box out-of-band recorder ─────────────────────────────────────────
REM Detached, independent process (pythonw = no console window). --show opens
REM the window immediately. Strictly read-only: it only tails diagnostic files
REM and queries psutil, never touches the suite, so it survives even a fatal
REM deadlock of the main Angerona process.
start "AngeronaBlackBox" "venv\Scripts\pythonw.exe" "%~dp0blackbox_recorder.py" --show
exit /b

REM ── Locate a real Python interpreter, skipping the Microsoft Store stub ──────
:find_python
set "PYCMD="
py -3 --version >nul 2>&1 && set "PYCMD=py -3" && goto :eof
for %%P in (
    "%LocalAppData%\Programs\Python\Python314\python.exe"
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%LocalAppData%\Programs\Python\Python310\python.exe"
    "%LocalAppData%\Python\bin\python.exe"
) do if not defined PYCMD if exist "%%~P" set PYCMD="%%~P"
goto :eof
