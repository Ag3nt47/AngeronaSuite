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
set "ANGERONA_INSTALL_ROOT=%~dp0"

REM ── Self-elevate (full-system telemetry needs Administrator) ────────────────
"%SystemRoot%\System32\net.exe" session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    set "ANGERONA_ELEVATE_PATH=%~f0"
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath $env:ANGERONA_ELEVATE_PATH -Verb RunAs"
    exit /b
)

REM This source/developer launcher must not recursively rewrite the checkout ACLs.
REM The release installer establishes the protected installed-program trust root.
if not exist "%TEMP%" mkdir "%TEMP%"
if not exist "%ANGERONA_DATA%\logs" mkdir "%ANGERONA_DATA%\logs"

REM ── First-run install (skip straight to launch if the venv already exists) ──
if exist "venv\Scripts\python.exe" if exist "venv\Scripts\pythonw.exe" goto validate

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
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --upgrade "pip==26.1.2"
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --build-constraint constraints-release.txt -c constraints-release.txt -e .[windows,voice] || (echo [!] Install failed. & pause & exit /b 1)
"venv\Scripts\python.exe" "tools\build_srt_compat_wheel.py" --out "%TEMP%\wheels" || (echo [!] Speech compatibility wheel build failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: "%TEMP%\wheels\srt-0.0.0+angerona.1-py3-none-any.whl" || (echo [!] Speech compatibility wheel install failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --no-deps "vosk==0.3.45" || (echo [!] Offline speech engine install failed. & pause & exit /b 1)
echo [*] Installing the verified offline speech model to the D-drive data folder...
"venv\Scripts\python.exe" -c "from angerona.connectors.voice import install_offline_model; print(install_offline_model())" || echo [!] Speech model setup failed; retry from Settings ^> ARIA.

:validate
REM Fail visibly before using pythonw, which intentionally has no console output.
set "ANGERONA_PREFLIGHT_LOG=%ANGERONA_DATA%\logs\launcher-preflight.log"
"venv\Scripts\python.exe" -c "import angerona, PySide6; print('Angerona launcher preflight OK')" > "%ANGERONA_PREFLIGHT_LOG%" 2>&1
if errorlevel 1 (
    echo [!] Angerona could not pass its startup check.
    echo     Details: %ANGERONA_PREFLIGHT_LOG%
    type "%ANGERONA_PREFLIGHT_LOG%"
    pause
    exit /b 1
)

:launch
REM ── Launch (pythonw = no console window) ─────────────────────────────────────
echo [*] Launching Angerona...
REM BL-01: if the signed out-of-process watchdog is built, use it as the resilience
REM PARENT (it launches + hashes + relaunches Angerona). ANGERONA_EXTERNAL_WATCHDOG
REM tells the in-process manager to skip its own watchdog (no double-supervision).
REM See frz\BUILD_SIGN_DEPLOY.md to build and code-sign the binary.
set "ANGERONA_WATCHDOG=%~dp0frz\angerona_watchdog.exe"
set "ANGERONA_WATCHDOG_SIGNED="
set "ANGERONA_PYTHON=%~dp0venv\Scripts\python.exe"
set "ANGERONA_STDOUT_LOG=%ANGERONA_DATA%\logs\launcher-stdout.log"
set "ANGERONA_STDERR_LOG=%ANGERONA_DATA%\logs\launcher-stderr.log"
if exist "%ANGERONA_WATCHDOG%" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "if ((Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_WATCHDOG).Status -eq 'Valid') {exit 0}; exit 1" >nul 2>&1 && set "ANGERONA_WATCHDOG_SIGNED=1"
if defined ANGERONA_WATCHDOG_SIGNED (
    set "ANGERONA_EXTERNAL_WATCHDOG=1"
    for /f %%H in ('"%SystemRoot%\System32\certutil.exe" -hashfile "venv\Scripts\pythonw.exe" SHA256 ^| "%SystemRoot%\System32\findstr.exe" /r "^[0-9a-f]*$"') do set "ANGERONA_AGENT_SHA256=%%H"
    echo [*] Using signed watchdog as resilience parent.
    start "" "%ANGERONA_WATCHDOG%" "venv\Scripts\pythonw.exe" -m angerona
) else (
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=Start-Process -FilePath $env:ANGERONA_PYTHON -ArgumentList @('-m','angerona') -WorkingDirectory $env:ANGERONA_INSTALL_ROOT -WindowStyle Hidden -RedirectStandardOutput $env:ANGERONA_STDOUT_LOG -RedirectStandardError $env:ANGERONA_STDERR_LOG -PassThru; Start-Sleep -Milliseconds 1500; if ($p.HasExited) {exit 1}; exit 0"
    if errorlevel 1 (
        echo [!] Angerona exited before its window opened.
        echo     Error log: %ANGERONA_STDERR_LOG%
        if exist "%ANGERONA_STDERR_LOG%" type "%ANGERONA_STDERR_LOG%"
        pause
        exit /b 1
    )
)

REM ── Black Box out-of-band recorder ─────────────────────────────────────────
REM Detached, independent process (pythonw = no console window). --show opens
REM the window immediately. Strictly read-only: it only tails diagnostic files
REM and queries psutil, never touches the suite, so it survives even a fatal
REM deadlock of the main Angerona process.
REM The suite launches exactly one Black Box child after the GUI paints.
exit /b

REM ── Locate a real Python interpreter, skipping the Microsoft Store stub ──────
:find_python
set "PYCMD="
for %%P in (
    "%ProgramFiles%\Python314\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles%\Python310\python.exe"
    "%LocalAppData%\Python\pythoncore-3.14-64\python.exe"
    "%LocalAppData%\Python\pythoncore-3.13-64\python.exe"
    "%LocalAppData%\Python\pythoncore-3.12-64\python.exe"
    "%LocalAppData%\Programs\Python\Python314\python.exe"
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%LocalAppData%\Programs\Python\Python310\python.exe"
) do if not defined PYCMD if exist "%%~P" call :accept_python "%%~P"
goto :eof

:accept_python
set "ANGERONA_CANDIDATE=%~1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_CANDIDATE; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Python Software Foundation') {exit 0}; exit 1" >nul 2>&1
if errorlevel 1 goto :eof
"%~1" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 set "PYCMD="%~1""
goto :eof
