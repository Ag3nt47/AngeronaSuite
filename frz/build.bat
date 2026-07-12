@echo off
:: build.bat — Compile the FRZ watchdog binary.
:: Run from the AngeronaSuite/frz/ directory or the repo root.
::
:: Prerequisites:
::   go install golang.org/x/sys/windows@latest
::   (Go 1.21+ required)

setlocal

where go >nul 2>&1
if errorlevel 1 (
    echo [FRZ] ERROR: Go compiler not found. Install from https://go.dev/dl/
    exit /b 1
)

cd /d "%~dp0"
echo [FRZ] Fetching dependencies...
go get golang.org/x/sys/windows
if errorlevel 1 goto :err

echo [FRZ] Compiling frz_watchdog.exe ...
go build -ldflags="-s -w" -o ..\frz_watchdog.exe frz_watchdog.go
if errorlevel 1 goto :err

echo [FRZ] Build successful: AngeronaSuite\frz_watchdog.exe
exit /b 0

:err
echo [FRZ] Build FAILED.
exit /b 1
