@echo off
cd /d "%~dp0"
echo ==========================================
echo   Angerona environment setup
echo ==========================================
echo.
echo --- diagnostics ---
echo where python:
where python 2>nul
echo py -0p (installed runtimes):
py -0p 2>nul
echo.

REM Find a REAL Python, avoiding the Microsoft Store alias
set "PYEXE="
py -3 --version >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE if exist "%LocalAppData%\Programs\Python\Python314\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python314\python.exe"
if not defined PYEXE if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python313\python.exe"
if not defined PYEXE if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PYEXE if exist "%LocalAppData%\Programs\Python\Python311\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python311\python.exe"
if not defined PYEXE if exist "%LocalAppData%\Programs\Python\Python310\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python310\python.exe"

if not defined PYEXE (
  echo.
  echo [!] Could not find a real Python. The Microsoft Store alias is blocking "python".
  echo     Fix in Settings ^> Apps ^> Advanced app settings ^> App execution aliases:
  echo     turn OFF python.exe and python3.exe, then re-run this script.
  echo.
  pause
  exit /b 1
)

echo [*] Using Python: %PYEXE%
%PYEXE% --version
echo.
echo [*] Creating virtual environment (venv) ...
%PYEXE% -m venv venv || (echo [!] venv creation FAILED & pause & exit /b 1)

echo [*] Upgrading pip ...
"venv\Scripts\python.exe" -m pip install --upgrade pip

echo [*] Installing Angerona + dependencies (downloads PySide6, ~1-2 min) ...
"venv\Scripts\python.exe" -m pip install -e .[windows]

echo.
echo ==========================================
echo [+] DONE. Environment ready.
echo     Launch with run.bat or start-angerona.bat
echo ==========================================
pause
