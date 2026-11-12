@echo off
rem Update and start Ollama on loopback, wait for its API, then start Angerona.
rem Add -FixHostBinding once to make OLLAMA_HOST=127.0.0.1:11434 permanent.
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Start-AngeronaOllama.ps1" -LaunchAngerona %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo Ollama preparation ended with code %RC%. Angerona was not started by this script.
  pause
)
exit /b %RC%
