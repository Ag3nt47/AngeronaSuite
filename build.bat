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
    --add-data "assets;assets" ^
    --add-data "modules;modules" ^
    --hidden-import angerona ^
    --hidden-import angerona.core.curated_tool_worker ^
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

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive ^
    -File "%~dp0tools\build_packaged_safe_start.ps1" -PayloadRoot "%~dp0dist\Angerona"
if errorlevel 1 exit /b 1
if not exist dist\Angerona\AngeronaSafeStart.exe exit /b 1
"%~dp0dist\Angerona\AngeronaSafeStart.exe" --verify-bootstrap
if errorlevel 1 exit /b 1

echo.
echo [+] Build complete - start dist\Angerona\AngeronaSafeStart.exe
pause
exit /b 0
