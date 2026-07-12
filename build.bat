@echo off
REM ============================================================================
REM  Build a standalone Angerona.exe with PyInstaller.
REM ============================================================================
cd /d "%~dp0"
set "PY=venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" -m pip install pyinstaller
"%PY%" -m PyInstaller ^
    --noconfirm --clean --windowed ^
    --name Angerona ^
    --paths src ^
    --collect-all PySide6 ^
    --add-data "modules;modules" ^
    --hidden-import angerona ^
    src\angerona\__main__.py

echo.
echo [+] Build complete -> dist\Angerona\Angerona.exe
pause
