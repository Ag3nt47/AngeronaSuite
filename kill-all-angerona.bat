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

echo [*] Terminating Angerona-owned Python processes only ...
set "ANGERONA_ROOT=%~dp0"
powershell -NoProfile -Command "$root=[IO.Path]::GetFullPath($env:ANGERONA_ROOT).TrimEnd([char]92); Get-CimInstance Win32_Process | Where-Object { ($_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe') -and (($_.ExecutablePath -and $_.ExecutablePath.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) -or ($_.CommandLine -and $_.CommandLine.IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0)) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

echo [*] Unloading Angerona's llama3 model ...
set "OLLAMA_CLI=ollama"
if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" set "OLLAMA_CLI=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
"%OLLAMA_CLI%" stop llama3 2>nul
"%OLLAMA_CLI%" stop llama3:8b 2>nul
"%OLLAMA_CLI%" stop llama3:latest 2>nul
REM Never image-kill Ollama runners: other local applications may be using them.
REM If graceful model unload fails, report it and leave unrelated work alone.

echo.
echo [+] Done. All instances stopped. Launch ONE clean copy with start-angerona.bat
echo.
timeout /t 4 >nul
