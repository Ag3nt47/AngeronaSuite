@echo off
REM Double-click this once to put an "Angerona - Push to GitHub" shortcut on your
REM Desktop. Runs the PS1 with an execution-policy bypass so it works regardless
REM of your default policy.
cd /d "%~dp0"
echo Installing the "Angerona - Push to GitHub" desktop shortcut ...
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0create-push-shortcut.ps1"
echo.
pause
