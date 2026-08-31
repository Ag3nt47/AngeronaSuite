@echo off
REM ============================================================================
REM  Serve only the flow canvas and its bounded metrics artifact over loopback.
REM  The repository root is never exposed or directory-listed.
REM  The Python helper binds an OS-selected loopback port before opening it.
REM ============================================================================
set "ANGERONA_CANVAS_PY=%~dp0venv\Scripts\python.exe"
if exist "%ANGERONA_CANVAS_PY%" (
    "%ANGERONA_CANVAS_PY%" "%~dp0tools\serve_canvas.py"
) else (
    echo Angerona's repository virtual environment is required. 1>&2
    echo Expected: "%ANGERONA_CANVAS_PY%" 1>&2
    exit /b 2
)
