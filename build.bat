@echo off
REM ============================================================================
REM  Build Angerona and its separate startup helper with PyInstaller.
REM ============================================================================
cd /d "%~dp0"
set "PY=venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PyInstaller is missing. Install the reviewed release dependencies first.
    exit /b 1
)
"%PY%" -m PyInstaller ^
    --noconfirm --clean --windowed ^
    --name Angerona ^
    --paths src ^
    --collect-all PySide6 ^
    --add-data "modules;modules" ^
    --hidden-import angerona ^
    src\angerona\__main__.py
if errorlevel 1 exit /b 1

"%PY%" -m PyInstaller ^
    --noconfirm --clean --windowed --onefile ^
    --name AngeronaStartup ^
    --distpath dist\Angerona ^
    --workpath build\AngeronaStartup ^
    --specpath build ^
    --paths src ^
    --icon "%~dp0assets\icons\angerona.ico" ^
    src\angerona\startup.py
if errorlevel 1 exit /b 1
if not exist dist\Angerona\AngeronaStartup.exe exit /b 1

echo.
echo [+] Build complete - start dist\Angerona\AngeronaStartup.exe
pause
exit /b 0
