@echo off
REM Compatibility alias. The hardened installer owns all dependency setup.
call "%~dp0Install-Angerona.bat"
exit /b %errorlevel%
