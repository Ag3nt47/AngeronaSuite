@echo off
REM ============================================================================
REM  Install-Angerona.bat  —  one-double-click deployment for Project Angerona.
REM
REM  Idempotent infrastructure-as-code bootstrapper. Safe to run repeatedly: it
REM  checks for each dependency before installing and never clobbers existing
REM  configuration. Steps (in order):
REM     1. Self-elevate to Administrator (UAC).
REM     2. Ensure Python 3.10+ (winget install if missing).
REM     3. Create venv + install Angerona and dependencies.
REM     4. Ensure Ollama + pull the llama3:8b local model (with progress).
REM     5. Compile the Go hypervisor watchdog (if the Go toolchain is present).
REM     6. Create Desktop shortcuts (Angerona + Angerona Black Box).
REM  Output is color-coded: [INFO] cyan, [OK] green, [WARN] yellow, [ERROR] red.
REM ============================================================================
setlocal EnableExtensions
title Angerona Installer
cd /d "%~dp0"

REM ── 1. UAC elevation ────────────────────────────────────────────────────────
net session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call :log INFO "Angerona bootstrapper starting in %CD%"

REM ── 2. Python 3.10+ ─────────────────────────────────────────────────────────
call :find_python
if not defined PYCMD (
    call :log INFO "Python 3.10+ not found - attempting winget install ..."
    where winget >nul 2>&1
    if errorlevel 1 (
        call :log ERROR "winget not available. Install Python 3.10+ from https://python.org and re-run."
        goto :fail
    )
    winget install --id Python.Python.3.10 --silent --accept-package-agreements --accept-source-agreements
    call :find_python
)
if not defined PYCMD (
    call :log ERROR "Python still not found after install attempt."
    goto :fail
)
call :log OK "Python interpreter: %PYCMD%"

REM ── 3. venv + dependencies (idempotent) ─────────────────────────────────────
if exist "venv\Scripts\python.exe" (
    call :log OK "Virtual environment already present - reusing it"
) else (
    call :log INFO "Creating virtual environment ..."
    %PYCMD% -m venv venv
    if errorlevel 1 ( call :log ERROR "venv creation failed" & goto :fail )
)
call :log INFO "Upgrading pip ..."
"venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
call :log INFO "Installing Angerona + dependencies (this can take a minute) ..."
if exist "pyproject.toml" (
    "venv\Scripts\python.exe" -m pip install -e .[windows]
    if errorlevel 1 "venv\Scripts\python.exe" -m pip install -r requirements.txt
) else (
    "venv\Scripts\python.exe" -m pip install -r requirements.txt
)
if errorlevel 1 ( call :log ERROR "Dependency install failed" & goto :fail )
call :log OK "Python dependencies installed"

REM ── 4. Ollama + local model ─────────────────────────────────────────────────
where ollama >nul 2>&1
if errorlevel 1 (
    call :log INFO "Installing Ollama via winget ..."
    where winget >nul 2>&1
    if errorlevel 1 (
        call :log WARN "winget missing - skipping Ollama. Install from https://ollama.com and run: ollama pull llama3:8b"
        goto :after_ollama
    )
    winget install --id Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements
) else (
    call :log OK "Ollama already installed"
)
where ollama >nul 2>&1
if errorlevel 1 (
    call :log WARN "Ollama not on PATH yet - open a NEW terminal and run: ollama pull llama3:8b"
) else (
    call :log INFO "Pulling llama3:8b - large one-time download, progress below ..."
    ollama pull llama3:8b
    if errorlevel 1 ( call :log WARN "Model pull did not complete - retry later with: ollama pull llama3:8b" ) else ( call :log OK "Local model llama3:8b ready" )
)
:after_ollama

REM ── 5. Compile the Go hypervisor watchdog ───────────────────────────────────
if exist "frz\angerona_watchdog.exe" (
    call :log OK "Watchdog binary already built: frz\angerona_watchdog.exe"
) else (
    where go >nul 2>&1
    if errorlevel 1 (
        call :log WARN "Go toolchain not found - skipping watchdog build. Install Go, then run frz\hypervisor\build.bat"
    ) else (
        call :log INFO "Compiling the hypervisor watchdog via Go ..."
        call "frz\hypervisor\build.bat"
        if errorlevel 1 ( call :log WARN "Watchdog build failed - see output above" ) else ( call :log OK "Watchdog compiled -> frz\angerona_watchdog.exe" )
    )
)

REM ── 6. Desktop shortcuts (reuse the existing, idempotent PS1) ────────────────
if exist "create-blackbox-launcher.ps1" (
    call :log INFO "Creating Desktop shortcuts: Angerona + Angerona Black Box ..."
    powershell -NoProfile -ExecutionPolicy Bypass -File "create-blackbox-launcher.ps1" >nul 2>&1
    if errorlevel 1 ( call :log WARN "Shortcut creation reported an issue" ) else ( call :log OK "Desktop shortcuts created" )
) else (
    call :log WARN "create-blackbox-launcher.ps1 not found - skipping shortcuts"
)

echo.
call :log OK "Angerona installation complete."
call :log INFO "Launch the suite with run.bat  (elevated GUI)."
call :log INFO "To run the decoupled watchdog/scanner ecosystem, set ANGERONA_RESILIENCE=1 before launch."
echo.
pause
exit /b 0

:fail
echo.
call :log ERROR "Installation aborted. Resolve the issue above and re-run (the script is idempotent)."
pause
exit /b 1

REM ── colored logger:  call :log LEVEL "message" ──────────────────────────────
:log
set "LVL=%~1"
set "MSG=%~2"
set "COLOR=Gray"
if /I "%LVL%"=="INFO"  set "COLOR=Cyan"
if /I "%LVL%"=="OK"    set "COLOR=Green"
if /I "%LVL%"=="WARN"  set "COLOR=Yellow"
if /I "%LVL%"=="ERROR" set "COLOR=Red"
powershell -NoProfile -Command "Write-Host ('[%LVL%] %MSG%') -ForegroundColor %COLOR%"
goto :eof

REM ── Locate a real Python 3.10+, skipping the Microsoft Store stub ────────────
:find_python
set "PYCMD="
py -3 --version >nul 2>&1 && set "PYCMD=py -3" && goto :eof
for %%P in (
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%LocalAppData%\Programs\Python\Python310\python.exe"
) do if not defined PYCMD if exist "%%~P" set PYCMD="%%~P"
goto :eof
