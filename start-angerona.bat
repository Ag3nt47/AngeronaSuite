@echo off
REM ============================================================================
REM  Angerona source checkout - one-click UNELEVATED Observe/development start.
REM  First run creates a venv and installs exact/hash-locked dependencies.
REM  Every run after launches the GUI without requesting Administrator rights.
REM
REM  Finds a REAL Python even when the Microsoft Store "python.exe" stub is on
REM  PATH (the #1 cause of "Python was not found" on a fresh Windows machine).
REM  Standalone guarantee: this launcher starts Angerona components only.  The
REM  optional authenticated JARVIS adapter is passive and never launches JARVIS.
REM ============================================================================

REM cmd.exe supplies __APPDIR__ from its own loaded image and ignores an
REM inherited variable of the same name. Use that process-owned directory as
REM the trust root before any executable lookup.
set "SAFE_SYSTEM32=%__APPDIR__%"
if not exist "%SAFE_SYSTEM32%cmd.exe" exit /b 1
for %%I in ("%SAFE_SYSTEM32%..") do set "SAFE_WINDOWS=%%~fI"
for %%I in ("%SAFE_WINDOWS%") do set "SAFE_SYSTEMDRIVE=%%~dI"
set "SystemRoot=%SAFE_WINDOWS%"
set "WINDIR=%SAFE_WINDOWS%"
set "SystemDrive=%SAFE_SYSTEMDRIVE%"
set "ComSpec=%SAFE_SYSTEM32%cmd.exe"
set "PATH=%SAFE_SYSTEM32%;%SAFE_WINDOWS%;%SAFE_SYSTEM32%Wbem;%SAFE_SYSTEM32%WindowsPowerShell\v1.0"
set "PATHEXT=.COM;.EXE;.BAT;.CMD"
set "ANGERONA_POWERSHELL=%SAFE_SYSTEM32%WindowsPowerShell\v1.0\powershell.exe"
if not exist "%ANGERONA_POWERSHELL%" exit /b 1

REM Strip inherited code-loading, egress, credential, and resilience controls.
REM Protected credentials are loaded later from the OS store; none are needed
REM by this source setup/launch boundary.
set "PYTHONHOME="
set "PYTHONPATH="
set "PYTHONSTARTUP="
set "PYTHONUSERBASE="
set "PYTHONINSPECT="
set "PYTHONBREAKPOINT="
set "PSModulePath="
set "COR_ENABLE_PROFILING="
set "COR_PROFILER="
set "CORECLR_ENABLE_PROFILING="
set "CORECLR_PROFILER="
set "DOTNET_STARTUP_HOOKS="
set "DOTNET_ADDITIONAL_DEPS="
set "DOTNET_SHARED_STORE="
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "ALL_PROXY="
set "FTP_PROXY="
set "NO_PROXY="
set "ANTHROPIC_API_KEY="
set "GEMINI_API_KEY="
set "GEMINI_API_KEYS="
set "GOOGLE_API_KEY="
set "GROQ_API_KEY="
set "OPENAI_API_KEY="
set "OPENROUTER_API_KEY="
set "ARIA_IMAP_PASS="
set "ANGERONA_TEAMS_APP_PASSWORD="
set "ANGERONA_FLEET_SERVICE_KEY="
set "ANGERONA_BRIDGE_KEY="
set "ANGERONA_MCP_TOKEN="
set "ANGERONA_GUARD_TOKEN="
set "ANGERONA_JARVIS_CONTROL_TOKEN="
set "ANGERONA_HOME="
set "ANGERONA_DATA_DRIVE="
set "ANGERONA_CORE_CMD="
set "ANGERONA_PY="
set "ANGERONA_EXTERNAL_WATCHDOG="
set "ANGERONA_RESILIENCE="
set "ANGERONA_WATCHDOG_TOKEN="
set "ANGERONA_WATCHDOG_MMAP="
set "ANGERONA_WD_DATADIR="
set "ANGERONA_AGENT_SHA256="
set "ANGERONA_EXTERNAL_MODULES="

REM Rebuild the remaining launch paths from trusted registry/system locations,
REM not from the caller's environment. Per-user CPython remains supported, but
REM its executable must still pass the PSF Authenticode + ABI checks below.
set "ProgramData=%SAFE_SYSTEMDRIVE%\ProgramData"
set "ProgramFiles=%SAFE_SYSTEMDRIVE%\Program Files"
set "ProgramFiles(x86)=%SAFE_SYSTEMDRIVE%\Program Files (x86)"
for /f "skip=2 tokens=2,*" %%A in ('call "%SAFE_SYSTEM32%reg.exe" query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir /reg:64 2^>nul') do set "ProgramFiles=%%B"
set "ProgramW6432=%ProgramFiles%"
set "LocalAppData="
for /f "skip=2 tokens=3,*" %%A in ('call "%SAFE_SYSTEM32%reg.exe" query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Local AppData" 2^>nul') do set "LocalAppData=%%B"

REM Non-mutating regression hook: validate the trust-boundary scrub without UAC,
REM installation, or application launch. Only this exact literal is accepted.
if /i "%~1"=="--bootstrap-selftest" (
    if not "%SystemRoot%"=="%SAFE_WINDOWS%" exit /b 1
    if not "%ComSpec%"=="%SAFE_SYSTEM32%cmd.exe" exit /b 1
    if not defined LocalAppData exit /b 1
    if not exist "%LocalAppData%" exit /b 1
    if defined PYTHONPATH exit /b 1
    if defined ANGERONA_CORE_CMD exit /b 1
    if defined ANGERONA_FLEET_SERVICE_KEY exit /b 1
    if defined ANGERONA_JARVIS_CONTROL_TOKEN exit /b 1
    if defined OPENAI_API_KEY exit /b 1
    echo ANGERONA_BOOTSTRAP_SELFTEST_OK
    exit /b 0
)
set "ANGERONA_SETUP_ONLY="
if /i "%~1"=="--source-setup" set "ANGERONA_SETUP_ONLY=1"
if not "%~1"=="" if not defined ANGERONA_SETUP_ONLY (
    echo [!] Unsupported source-launch option.
    exit /b 1
)

REM A source checkout must never inherit an Administrator token. The signed
REM MSIX is the only Windows first-install authority for full Protect coverage.
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -Command "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {exit 0}; exit 1" >nul 2>&1
if not errorlevel 1 (
    echo [!] Refusing to execute mutable Angerona source with Administrator rights.
    echo     Use a normal user session for Observe/development coverage.
    echo     Use the OS-validated signed MSIX for full Windows Protect coverage:
    echo     https://github.com/Ag3nt47/AngeronaSuite/releases
    exit /b 1
)

cd /d "%~dp0"
title Angerona launcher
echo.
echo  [ANGERONA] Starting the unelevated source Observe/development profile...
echo  [ANGERONA] This window will close after the dashboard is confirmed alive.
echo.

REM Keep mutable source-profile data in the current user's OS-owned local-data
REM folder, never in the checkout and never at a caller-selected inherited path.
if not defined LocalAppData (
    echo [!] Windows could not resolve the current user's Local AppData folder.
    exit /b 1
)
for %%I in ("%LocalAppData%\Angerona\SourceData") do set "ANGERONA_DATA=%%~fI"
set "ANGERONA_DIAG_DIR=%ANGERONA_DATA%\diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=0"
set "TEMP=%ANGERONA_DATA%\tmp"
set "TMP=%TEMP%"
set "ANGERONA_INSTALL_ROOT=%~dp0"
set "ANGERONA_ENFORCE_KEY_ACL=0"
set "ANGERONA_DEVELOPMENT_MODE=0"
set "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=0"

REM Fail closed on redirected/removable source roots before executing local code.
title Angerona launcher - validating source
echo [1/4] Validating the local installation...
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -Command "$r=Get-Item -LiteralPath $env:ANGERONA_INSTALL_ROOT -Force; $v=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($r.FullName)); if (($r.Attributes -band [IO.FileAttributes]::ReparsePoint) -or !$v.IsReady -or $v.DriveType -ne [IO.DriveType]::Fixed) {exit 1}; $required=@('start-angerona.bat','pyproject.toml','src\angerona\__init__.py'); foreach($n in $required) {$p=Join-Path $r.FullName $n; if (!(Test-Path -LiteralPath $p -PathType Leaf) -or ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {exit 1}}; exit 0"
if errorlevel 1 (
    echo [!] Refusing redirected, incomplete, or non-fixed source checkout.
    pause
    exit /b 1
)
title Angerona launcher - preparing user storage
echo [2/4] Preparing user-scoped source-profile storage...
if not exist "%TEMP%" mkdir "%TEMP%"
if not exist "%ANGERONA_DATA%\logs" mkdir "%ANGERONA_DATA%\logs"

REM ── First-run install (skip straight to launch if the venv already exists) ──
if exist "venv\Scripts\python.exe" if exist "venv\Scripts\pythonw.exe" goto validate

echo [*] First run - setting up from the reviewed CPython 3.12 x64 wheel lock...
call :find_python
if not defined PYCMD (
    echo [!] Signed CPython 3.12 x64 was not found.
    echo     Install Python 3.12 x64 from https://www.python.org/downloads/
    echo     ^(tick "Add python.exe to PATH"^),
    echo     or turn OFF the Microsoft Store stub under
    echo     Settings ^> Apps ^> Advanced app settings ^> App execution aliases, then re-run.
    pause
    exit /b 1
)
echo [*] Using Python: %PYCMD%
%PYCMD% -m venv venv || (echo [!] venv creation failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --require-hashes --no-deps -r requirements-bootstrap-pip.txt || (echo [!] Verified pip bootstrap failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --require-hashes --no-deps -r requirements-release-hashed.txt || (echo [!] Hash-locked dependency install failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --no-build-isolation --no-deps -e . || (echo [!] Local Angerona install failed. & pause & exit /b 1)
"venv\Scripts\python.exe" "tools\build_srt_compat_wheel.py" --out "%TEMP%\wheels" || (echo [!] Speech compatibility wheel build failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --no-deps "%TEMP%\wheels\srt-0.0.0+angerona.1-py3-none-any.whl" || (echo [!] Speech compatibility wheel install failed. & pause & exit /b 1)
echo [*] Installing the verified offline speech model to the D-drive data folder...
"venv\Scripts\python.exe" -c "from angerona.connectors.voice import install_offline_model; print(install_offline_model())" || echo [!] Speech model setup failed; retry from Settings ^> ARIA.

:validate
REM Fail visibly before using pythonw, which intentionally has no console output.
title Angerona launcher - checking application
echo [3/4] Checking the application and its dependencies...
REM Never trust existence alone: an older/developer venv can use an ABI that is
REM outside the reviewed Windows wheel lock.  Keep that environment untouched
REM and fail visibly instead of launching an unsupported Python/Qt combination.
"venv\Scripts\python.exe" -c "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' else 1)" >nul 2>&1
if errorlevel 1 (
    echo [!] This virtual environment is not the reviewed CPython 3.12 x64 build.
    echo     Angerona did not modify or delete it.
    echo     Source checkout repair: double-click Repair-Angerona-Python.bat.
    echo     It asks first, preserves the old venv, and builds the reviewed one.
    echo     Packaged release repair: double-click Install-Angerona-Release.bat.
    pause
    exit /b 1
)
"venv\Scripts\python.exe" -c "import importlib.metadata as m; raise SystemExit(0 if m.version('pip') == '26.2.1' else 1)" >nul 2>&1
if errorlevel 1 (
    echo [!] This environment does not contain the reviewed pip 26.2.1 build.
    echo     Double-click Repair-Angerona-Python.bat to upgrade it through the
    echo     exact SHA-256-verified wheel before Angerona starts.
    pause
    exit /b 1
)
set "ANGERONA_PREFLIGHT_LOG=%ANGERONA_DATA%\logs\launcher-preflight.log"
"venv\Scripts\python.exe" "tools\source_trust_preflight.py" > "%ANGERONA_PREFLIGHT_LOG%" 2>&1
if errorlevel 1 (
    echo [!] Angerona source trust preflight failed.
    type "%ANGERONA_PREFLIGHT_LOG%"
    pause
    exit /b 1
)
if not defined ANGERONA_SETUP_ONLY goto launch
"venv\Scripts\python.exe" -c "import angerona, PySide6; print('Angerona launcher preflight OK')" > "%ANGERONA_PREFLIGHT_LOG%" 2>&1
if errorlevel 1 (
    echo [!] Angerona could not pass its startup check.
    echo     Details: %ANGERONA_PREFLIGHT_LOG%
    type "%ANGERONA_PREFLIGHT_LOG%"
    pause
    exit /b 1
)
if defined ANGERONA_SETUP_ONLY (
    echo [OK] Unelevated source Observe/development setup is ready.
    echo      Run start-angerona.bat from a normal user session to launch.
    exit /b 0
)


:launch
REM The separate Tk assistant owns isolated dependency probes, bounded startup,
REM and a per-launch nonce/PID handshake after the dashboard paints.
title Angerona launcher - safe startup
echo [4/4] Opening Angerona Safe Startup...
set "ANGERONA_PYTHON=%~dp0venv\Scripts\python.exe"
set "ANGERONA_STDOUT_LOG=%ANGERONA_DATA%\logs\launcher-stdout.log"
set "ANGERONA_STDERR_LOG=%ANGERONA_DATA%\logs\launcher-stderr.log"
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -Command "$p=Start-Process -FilePath $env:ANGERONA_PYTHON -ArgumentList @('-m','angerona.startup') -WorkingDirectory $env:ANGERONA_INSTALL_ROOT -WindowStyle Hidden -RedirectStandardOutput $env:ANGERONA_STDOUT_LOG -RedirectStandardError $env:ANGERONA_STDERR_LOG -PassThru -Wait; exit $p.ExitCode"
if errorlevel 1 (
    echo [!] The startup assistant did not complete. Review its message or this log:
    echo     %ANGERONA_STDERR_LOG%
    if exist "%ANGERONA_STDERR_LOG%" type "%ANGERONA_STDERR_LOG%"
    pause
    exit /b 1
)
exit /b %errorlevel%

REM ── Fresh bootstrap uses the ABI-specific reviewed CPython 3.12 x64 lock ────
:find_python
set "PYCMD="
for %%P in (
    "%ProgramFiles%\Python312\python.exe"
    "%LocalAppData%\Python\pythoncore-3.12-64\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
) do if not defined PYCMD if exist "%%~P" call :accept_python "%%~P"
goto :eof

:accept_python
set "ANGERONA_CANDIDATE=%~1"
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -Command "$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_CANDIDATE; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Python Software Foundation') {exit 0}; exit 1" >nul 2>&1
if errorlevel 1 goto :eof
"%~1" -c "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' else 1)" >nul 2>&1
if not errorlevel 1 set "PYCMD="%~1""
goto :eof
