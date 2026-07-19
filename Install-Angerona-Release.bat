@echo off
setlocal EnableExtensions
title Angerona Release Installer
set "ANGERONA_RELEASE_PS=%~dp0Install-Angerona-Release.ps1"
if not exist "%ANGERONA_RELEASE_PS%" (
    echo [ERROR] Install-Angerona-Release.ps1 is missing.
    pause
    exit /b 1
)

"%SystemRoot%\System32\net.exe" session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges for the protected install ...
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath ($env:SystemRoot+'\System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$env:ANGERONA_RELEASE_PS) -Verb RunAs"
    exit /b
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%ANGERONA_RELEASE_PS%"
if errorlevel 1 (
    echo.
    echo [ERROR] Installation failed. Review the message above.
    pause
    exit /b 1
)
exit /b 0
