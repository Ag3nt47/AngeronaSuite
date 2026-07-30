@echo off
REM ============================================================================
REM  Compatibility entry point for older shortcuts. The canonical launcher now
REM  owns protected storage, source validation, watchdog selection, and the
REM  visible startup health check. Keeping two independent launch pipelines
REM  caused the guarded shortcut to look blank or fail when the old root-level
REM  watchdog binary was absent.
REM ============================================================================
cd /d "%~dp0"

REM Keep agent data, watchdog state, diagnostics, and temp files on D:.
set "ANGERONA_DATA=%~dp0runtime-data"
set "ANGERONA_DIAG_DIR=%~dp0runtime-data\diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=1"
set "ANGERONA_ENFORCE_KEY_ACL=1"
set "ANGERONA_DEVELOPMENT_MODE=0"
set "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=0"
set "TEMP=%~dp0runtime-data\tmp"
set "TMP=%TEMP%"

echo [ANGERONA] Redirecting the legacy guarded shortcut to the canonical launcher...
call "%~dp0start-angerona.bat"
exit /b %errorlevel%
