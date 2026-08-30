@echo off
REM Compatibility entry point for older source shortcuts.
REM
REM The canonical launcher owns environment scrubbing, user-scoped storage,
REM exact/hash-locked dependency checks, Administrator-token refusal, and the
REM unelevated Observe/development launch. This wrapper never selects a data
REM path, weakens a policy, requests elevation, or starts another executable.

if /i "%~1"=="--bootstrap-selftest" (
    if not "%~2"=="" exit /b 1
    call "%~dp0start-angerona.bat" --bootstrap-selftest
    exit /b %errorlevel%
)
if not "%~1"=="" (
    echo [!] Unsupported legacy-launch option.
    exit /b 1
)

echo [ANGERONA] Redirecting to the unelevated source Observe/development launcher...
call "%~dp0start-angerona.bat"
exit /b %errorlevel%
