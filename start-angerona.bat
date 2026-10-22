@echo off
setlocal DisableDelayedExpansion
REM ============================================================================
REM  Angerona source checkout - one-click UNELEVATED Observe/development start.
REM  One supervised repair can restore a reviewed hash-locked environment.
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
set "ANGERONA_INSTALL_ROOT=%~dp0"
set "ANGERONA_ENFORCE_KEY_ACL=0"
set "ANGERONA_DEVELOPMENT_MODE=0"
set "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=0"

REM Validate the fixed source supervisor before executing repository PowerShell.
REM Its mandatory checks and runtime lease cover every venv process, including
REM ABI/pip/source probes, the helper, and at most one full retry after repair.
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -Command "$r=[IO.Path]::GetFullPath($env:ANGERONA_INSTALL_ROOT); $p=$r; while($p) {if (Test-Path -LiteralPath $p) {if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {exit 1}}; $p=[IO.Path]::GetDirectoryName($p)}; $v=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($r)); if (!$v.IsReady -or $v.DriveType -ne [IO.DriveType]::Fixed) {exit 1}; foreach($n in @('tools\Invoke-AngeronaSourceStartup.ps1','tools\startup_repair_common.ps1')) {$p=Join-Path $r $n; while($p -and $p -ne $r) {if (!(Test-Path -LiteralPath $p) -or ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {exit 1}; $p=[IO.Path]::GetDirectoryName($p)}}; exit 0"
if errorlevel 1 (
    echo [!] Refusing redirected, incomplete, or non-fixed source checkout.
    pause
    exit /b 1
)
if defined ANGERONA_SETUP_ONLY goto source_setup
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -File "%~dp0tools\Invoke-AngeronaSourceStartup.ps1" -RepositoryRoot "%~dp0."
goto source_finished

:source_setup
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -File "%~dp0tools\Invoke-AngeronaSourceStartup.ps1" -RepositoryRoot "%~dp0." -SetupOnly
:source_finished
set "ANGERONA_SOURCE_RC=%errorlevel%"
if not "%ANGERONA_SOURCE_RC%"=="0" (
    echo [!] Safe Startup could not verify a healthy runtime and dashboard.
    echo     Review the explanation above; settings and evidence were preserved.
    echo     Manual source repair: Repair-Angerona-Python.bat
    echo     Signed release repair: Install-Angerona-Release.bat
    pause
)
exit /b %ANGERONA_SOURCE_RC%
