@echo off
REM Double-click to put an "Angerona Black Box" shortcut on your Desktop
REM (and an "Angerona" shortcut if you don't have one). Runs the PS1 with an
REM execution-policy bypass so it works regardless of your default policy.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0create-blackbox-launcher.ps1"
echo.
pause
