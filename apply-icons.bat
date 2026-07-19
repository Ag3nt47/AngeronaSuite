@echo off
REM Applies the skull / green-F icons to the Kill-All-Angerona and Backup-to-F
REM shortcuts. Double-click this file to run; it closes itself when done.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0apply-icons.ps1"
