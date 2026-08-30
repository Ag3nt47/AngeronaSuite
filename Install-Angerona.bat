@echo off
REM ============================================================================
REM  Angerona source setup (UNELEVATED OBSERVE / DEVELOPMENT COVERAGE ONLY).
REM
REM  A mutable Git checkout is not a privileged installation authority. This
REM  compatibility entry point delegates to the canonical source launcher, which
REM  creates an exact/hash-locked per-checkout virtual environment without UAC,
REM  machine-scope installation, protected-tree mutation, or elevated execution.
REM
REM  Full Windows Protect coverage requires the OS-validated signed MSIX from:
REM      https://github.com/Ag3nt47/AngeronaSuite/releases
REM ============================================================================
setlocal EnableExtensions
title Angerona Source Setup - Unelevated Observe

if not exist "%~dp0start-angerona.bat" (
    echo [ERROR] start-angerona.bat is missing; refusing an incomplete checkout.
    exit /b 1
)

echo [ANGERONA] Preparing the unelevated source Observe/development profile...
call "%~dp0start-angerona.bat" --source-setup
exit /b %errorlevel%
