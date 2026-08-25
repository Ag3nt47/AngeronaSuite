@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src"
set "ANGERONA_ADVERSARY_COMBAT_ENABLED=1"
set "ANGERONA_ADVERSARY_COMBAT_MODE=maximum"
set "ANGERONA_ADVERSARY_COMBAT_MIN_SEVERITY=LOW"

set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"

echo Running deterministic negative controls first: remote authority, mobile spoof,
echo token expiry, typed-only ARIA confirmation, protected assets, PID reuse,
echo scoped producer authority, authenticated crash journals/cursors, sandbox
echo confinement, model-blob integrity, firewall postconditions, and undo boundaries.
echo.

"%PYTHON_EXE%" -m pytest -q ^
  "%~dp0tests\test_adversary_combat_boundaries.py" ^
  "%~dp0tests\test_adversary_combat.py" ^
  "%~dp0tests\test_adversary_combat_journal.py" ^
  "%~dp0tests\test_adversary_response_producers.py" ^
  "%~dp0tests\test_semantic_response_contracts.py" ^
  "%~dp0tests\test_soar_mobile_response_boundaries.py" ^
  "%~dp0tests\test_aria_boundary_hardening.py" ^
  "%~dp0tests\test_model_pack_manager.py" ^
  "%~dp0tests\test_source_sandbox_hardening.py" ^
  "%~dp0tests\test_sysmon_cursor.py" ^
  "%~dp0tests\test_sysmon_event_coverage.py" ^
  "%~dp0tests\test_cycle19_theoretical_hardening.py"
if errorlevel 1 (
  echo ADVERSARY COMBAT NEGATIVE-CONTROL GATE FAILED.
  if not defined CI pause
  exit /b 1
)

echo.
echo Negative controls passed. Running Extreme Red Team campaigns until Angerona
echo proves 100%% detection, automatic response, action contracts, verified closure,
echo and resilience in one signed report.
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
if not defined CI pause
exit /b %RESULT%
