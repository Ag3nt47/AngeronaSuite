@echo off
REM ============================================================================
REM  Angerona - dev install. Creates a venv and installs dependencies.
REM
REM  Finds a REAL Python even when the Microsoft Store "python.exe" stub is on
REM  PATH (the #1 cause of "Python was not found" on a fresh Windows machine).
REM ============================================================================
cd /d "%~dp0"

call :find_python
if not defined PYCMD (
    echo [!] No real Python 3.10+ found.
    echo     Fix either way:
    echo       - Install Python from https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
    echo       - OR turn off the Microsoft Store stub:
    echo         Settings ^> Apps ^> Advanced app settings ^> App execution aliases
    echo         -^> switch OFF python.exe and python3.exe, then re-run this.
    pause
    exit /b 1
)
echo [*] Using Python: %PYCMD%
%PYCMD% --version

echo [*] Creating virtual environment ...
%PYCMD% -m venv venv || (echo [!] venv creation failed. & pause & exit /b 1)

echo [*] Upgrading pip ...
"venv\Scripts\python.exe" -m pip install --upgrade pip

echo [*] Installing Angerona + dependencies (editable install) ...
"venv\Scripts\python.exe" -m pip install -e .[windows]

echo.
echo [+] Done. Launch with run.bat  (or start-angerona.bat)
pause
exit /b 0

REM ── Locate a real Python interpreter, skipping the Store stub ────────────────
:find_python
set "PYCMD="
REM 1) The Python launcher (py.exe) is never shadowed by the Store stub.
py -3 --version >nul 2>&1 && set "PYCMD=py -3" && goto :eof
REM 2) Common per-user install locations (official installer + install manager).
for %%P in (
    "%LocalAppData%\Programs\Python\Python314\python.exe"
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%LocalAppData%\Programs\Python\Python310\python.exe"
    "%LocalAppData%\Python\bin\python.exe"
) do if not defined PYCMD if exist "%%~P" set PYCMD="%%~P"
goto :eof
