@echo off
REM ============================================================================
REM  Compatibility entry point for older shortcuts. The canonical launcher now
REM  owns protected storage, source validation, watchdog selection, and the
REM  visible startup health check. Keeping two independent launch pipelines
REM  caused the guarded shortcut to look blank or fail when the old root-level
REM  watchdog binary was absent.
REM ============================================================================

REM Establish the same process-owned Windows trust root before redirecting. The
REM canonical launcher repeats the complete scrub before any executable or UAC.
set "SAFE_SYSTEM32=%__APPDIR__%"
if not exist "%SAFE_SYSTEM32%cmd.exe" exit /b 1
for %%I in ("%SAFE_SYSTEM32%..") do set "SAFE_WINDOWS=%%~fI"
set "SystemRoot=%SAFE_WINDOWS%"
set "WINDIR=%SAFE_WINDOWS%"
set "ComSpec=%SAFE_SYSTEM32%cmd.exe"
set "PATH=%SAFE_SYSTEM32%;%SAFE_WINDOWS%;%SAFE_SYSTEM32%Wbem;%SAFE_SYSTEM32%WindowsPowerShell\v1.0"
set "PATHEXT=.COM;.EXE;.BAT;.CMD"
set "PYTHONHOME="
set "PYTHONPATH="
set "PYTHONSTARTUP="
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "ALL_PROXY="
set "ANGERONA_CORE_CMD="
set "ANGERONA_PY="
set "ANGERONA_EXTERNAL_WATCHDOG="
set "ANGERONA_RESILIENCE="
set "ANGERONA_WATCHDOG_TOKEN="
set "ANGERONA_FLEET_SERVICE_KEY="

cd /d "%~dp0"

REM Canonicalize before redirecting; never pass an inherited privileged path.
for %%I in ("%~dp0..\AngeronaData") do set "ANGERONA_DATA=%%~fI"
set "ANGERONA_DIAG_DIR=%ANGERONA_DATA%\diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=1"
set "ANGERONA_ENFORCE_KEY_ACL=1"
set "ANGERONA_DEVELOPMENT_MODE=0"
set "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=0"
set "TEMP=%ANGERONA_DATA%\tmp"
set "TMP=%TEMP%"

echo [ANGERONA] Redirecting the legacy guarded shortcut to the canonical launcher...
if /i "%~1"=="--bootstrap-selftest" (
    call "%~dp0start-angerona.bat" --bootstrap-selftest
    exit /b %errorlevel%
)
call "%~dp0start-angerona.bat"
exit /b %errorlevel%
