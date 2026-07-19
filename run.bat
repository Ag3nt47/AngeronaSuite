@echo off
REM Compatibility launcher. Keep all setup, trust-root validation, dependency
REM checks, and elevation in the single supported entry point.
call "%~dp0start-angerona.bat"
exit /b %errorlevel%
