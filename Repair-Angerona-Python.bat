@echo off
setlocal EnableExtensions
title Angerona - Repair reviewed Python environment
set "SAFE_SYSTEM32=%__APPDIR__%"
if not exist "%SAFE_SYSTEM32%WindowsPowerShell\v1.0\powershell.exe" (
    echo [ERROR] Trusted Windows PowerShell was not found.
    pause
    exit /b 1
)

REM This wrapper intentionally does not elevate or change checkout/data ACLs.
REM The PowerShell repair validates the exact repo-root venv and asks for an
REM explicit confirmation before replacing it.
set "ANGERONA_REPAIR_PS=%~dp0Repair-Angerona-Python.ps1"
if not exist "%ANGERONA_REPAIR_PS%" (
    echo [ERROR] Repair-Angerona-Python.ps1 is missing.
    pause
    exit /b 1
)

"%SAFE_SYSTEM32%WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%ANGERONA_REPAIR_PS%"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo [ERROR] Python environment repair did not complete.
if "%RC%"=="0" echo [DONE] The reviewed Python 3.12 environment is ready. Start Angerona normally.
pause
exit /b %RC%
