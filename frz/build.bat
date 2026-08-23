@echo off
:: build.bat — Compile the FRZ watchdog binary.
:: Run from the AngeronaSuite/frz/ directory or the repo root.
::
:: Prerequisites:
::   Go 1.25+ (the exact x/sys dependency is pinned by go.mod/go.sum)

setlocal

where go >nul 2>&1
if errorlevel 1 (
    echo [FRZ] ERROR: Go compiler not found. Install from https://go.dev/dl/
    exit /b 1
)

cd /d "%~dp0"
set "GOWORK=off"
echo [FRZ] Downloading the checksum-pinned module graph...
go mod download
if errorlevel 1 goto :err
go mod verify
if errorlevel 1 goto :err

echo [FRZ] Compiling authenticated frz_watchdog_v2.exe ...
go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" -o frz_watchdog_v2.exe frz_watchdog.go
if errorlevel 1 goto :err

echo [FRZ] Build successful: AngeronaSuite\frz\frz_watchdog_v2.exe
exit /b 0

:err
echo [FRZ] Build FAILED.
exit /b 1
