@echo off
setlocal
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
  echo [ERROR] Angerona virtual environment is missing. Run Install-Angerona.bat first.
  exit /b 2
)
echo [1/3] Fast correctness scan...
"venv\Scripts\ruff.exe" check src tests || exit /b 1
echo [2/3] Authoritative regression suite...
"venv\Scripts\python.exe" -m pytest -q || exit /b 1
echo [3/3] Installed dependency vulnerability audit...
"venv\Scripts\python.exe" -m pip_audit --progress-spinner off --format columns || exit /b 1
echo [PASS] Angerona fast quality gate completed.
exit /b 0
