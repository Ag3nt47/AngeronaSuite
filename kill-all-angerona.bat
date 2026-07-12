@echo off
REM ============================================================================
REM  kill-all-angerona.bat
REM  External "nuke" for when Angerona instances pile up and a normal PowerShell
REM  can't kill them (they run elevated). This self-elevates, so it has the
REM  rights to terminate them.
REM ============================================================================

REM ── Self-elevate (the whole point — normal shells get Access Denied) ────────
net session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [*] Terminating all Angerona / Python GUI processes ...
taskkill /F /IM pythonw.exe /T 2>nul
taskkill /F /IM python.exe  /T 2>nul

echo.
echo [+] Done. All instances stopped. Launch ONE clean copy with start-angerona.bat
echo.
timeout /t 4 >nul
