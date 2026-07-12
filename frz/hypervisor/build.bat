@echo off
REM Build the Angerona hypervisor watchdog (Windows, requires the Go toolchain).
REM Produces ..\angerona_watchdog.exe so ResilienceManager auto-detects it.
setlocal
cd /d "%~dp0"
echo [INFO] Fetching dependencies (golang.org/x/sys)...
go mod tidy || goto :err
echo [INFO] Building angerona_watchdog.exe ...
go build -ldflags "-s -w" -o ..\angerona_watchdog.exe . || goto :err
echo [SUCCESS] Built %~dp0..\angerona_watchdog.exe
endlocal
exit /b 0
:err
echo [ERROR] Build failed. Ensure Go is installed and on PATH (go version).
endlocal
exit /b 1
