@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src"
set "ANGERONA_ADVERSARY_COMBAT_ENABLED=1"
set "ANGERONA_ADVERSARY_COMBAT_MODE=maximum"
set "ANGERONA_ADVERSARY_COMBAT_MIN_SEVERITY=LOW"

set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

echo Running Extreme Red Team campaigns until Angerona proves 100%% detection,
echo automatic response, action contracts, verified closure, and resilience.
echo Reversible firewall, isolation, suspension, and quarantine actions are undone
echo after each signed report is saved.
echo.

"%PYTHON_EXE%" "%~dp0tools\validate_adversary_combat.py" --data-root "%~dp0.tmp\adversary-combat-validation" --max-rounds 0
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" (
  echo ADVERSARY COMBAT VALIDATION PASSED.
) else (
  echo ADVERSARY COMBAT VALIDATION STOPPED WITHOUT A 100%% PASS.
)
pause
exit /b %RESULT%
