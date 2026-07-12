@echo off
REM ============================================================================
REM  Angerona - fast syntax gate. Byte-compiles every .py under src\angerona
REM  and reports any file that fails to parse (file:line). Stdlib only, so it
REM  runs on ANY python - no venv, no PySide6, no imports. Run this before
REM  run-selfcheck.bat to catch syntax breakage early and cheaply.
REM ============================================================================
cd /d "%~dp0"

REM Prefer the venv python if present, else fall back to system python.
if exist "venv\Scripts\python.exe" (
    set "PY=venv\Scripts\python.exe"
) else (
    set "PY=python"
)

"%PY%" -X utf8 tools\compile_check.py %*
exit /b %errorlevel%
