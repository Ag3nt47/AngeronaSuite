@echo off
REM ============================================================================
REM  start-angerona-guarded.bat — launch Angerona UNDER the resilience Watchdog
REM  (BL-01/BL-09). The watchdog verifies the agent binary's SHA-256, launches it
REM  detached, keeps a mutual authenticated heartbeat, and relaunches it (throttled)
REM  if it is killed or suspended. Stop cleanly with the app's STOP button, by
REM  creating "%ANGERONA_WD_DATADIR%\watchdog.stop", or Ctrl-Break in this window.
REM ============================================================================
cd /d "%~dp0"

REM Keep agent data, watchdog state, diagnostics, and temp files on D:.
set "ANGERONA_DATA=%~dp0runtime-data"
set "ANGERONA_DIAG_DIR=%~dp0diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=1"
set "TEMP=%~dp0runtime-data\tmp"
set "TMP=%TEMP%"
if not exist "%ANGERONA_DATA%" mkdir "%ANGERONA_DATA%"
if not exist "%TEMP%" mkdir "%TEMP%"

if not exist "angerona_watchdog.exe" (
    echo [!] angerona_watchdog.exe not found. Build it first: frz\build-watchdog.bat
    pause
    exit /b 1
)
if not exist "venv\Scripts\pythonw.exe" (
    echo [!] venv not found. Run start-angerona.bat once, or install.bat.
    pause
    exit /b 1
)

REM Heartbeats + watchdog log live here (the agent's frz_heartbeat.mmap dir).
set "ANGERONA_WD_DATADIR=%ANGERONA_DATA%"
if not exist "%ANGERONA_WD_DATADIR%" mkdir "%ANGERONA_WD_DATADIR%"

REM Optionally pin the expected agent hash (recommended once you have a signed
REM build): set ANGERONA_AGENT_SHA256=<hex>. Left unset => the watchdog learns a
REM baseline from the launcher on first run and enforces it thereafter.

REM Watchdog supervises pythonw running the Angerona package.
angerona_watchdog.exe "venv\Scripts\pythonw.exe" -m angerona
