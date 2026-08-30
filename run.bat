@echo off
REM Compatibility launcher for the unelevated source Observe/development path.
REM Full Windows Protect coverage is available only through the signed MSIX.
call "%~dp0start-angerona.bat"
exit /b %errorlevel%
