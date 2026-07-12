@echo off
REM ============================================================================
REM  Serve the flow-visualization canvas over http so it can fetch live metrics
REM  (diagnostics/flow_metrics.json, written by the running Angerona app).
REM  Opens http://localhost:8009/flow_canvas.html in your browser.
REM ============================================================================
cd /d "%~dp0"
set "PY=venv\Scripts\python.exe"
if not exist "%PY%" set "PY=py -3"
start "" http://localhost:8009/flow_canvas.html
%PY% -m http.server 8009
