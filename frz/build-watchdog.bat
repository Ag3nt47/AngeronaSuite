@echo off
REM build-watchdog.bat — compile the Angerona resilience/anti-tamper Watchdog
REM (BL-01/BL-09). Produces AngeronaSuite\angerona_watchdog.exe.
setlocal
where go >nul 2>&1
if errorlevel 1 (
    echo [WD] ERROR: Go compiler not found. Install from https://go.dev/dl/
    exit /b 1
)
cd /d "%~dp0"
echo [WD] Fetching dependencies...
go get golang.org/x/sys/windows || goto :err
echo [WD] Compiling angerona_watchdog.exe ...
go build -ldflags="-s -w" -o ..\angerona_watchdog.exe angerona_watchdog.go || goto :err
echo [WD] Build successful: AngeronaSuite\angerona_watchdog.exe
exit /b 0
:err
echo [WD] Build FAILED.
exit /b 1
