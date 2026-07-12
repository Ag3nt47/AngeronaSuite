@echo off
:: build-hermetic.bat — Build the Angerona HERMETIC monolithic binary.
::
:: REVIEW GATED: inspect this script before running.
:: Output: AngeronaSuite\dist\angerona.exe  (code-sign afterwards)
::
:: Prerequisites:
::   pyoxidizer >= 0.24   (pip install pyoxidizer  OR  cargo install pyoxidizer)
::   Visual Studio Build Tools with MSVC + Windows SDK
::   Python 3.10 on PATH

setlocal enabledelayedexpansion

:: ── pre-flight checks ───────────────────────────────────────────────────────
where pyoxidizer >nul 2>&1
if errorlevel 1 (
    echo [HERMETIC] ERROR: pyoxidizer not found.
    echo            Install: pip install pyoxidizer
    exit /b 1
)

where cl >nul 2>&1
if errorlevel 1 (
    echo [HERMETIC] ERROR: MSVC cl.exe not found.
    echo            Open this prompt from a Visual Studio Developer Command Prompt.
    exit /b 1
)

set "ROOT=%~dp0.."
set "HERMETIC_DIR=%~dp0"
set "DIST_DIR=%ROOT%\dist"

echo [HERMETIC] Building monolithic Angerona binary...
echo [HERMETIC] Source root : %ROOT%
echo [HERMETIC] Output dir  : %DIST_DIR%
echo.

:: ── build ────────────────────────────────────────────────────────────────────
cd /d "%HERMETIC_DIR%"
pyoxidizer build --release
if errorlevel 1 (
    echo [HERMETIC] Build FAILED.
    exit /b 1
)

:: ── locate and copy output ───────────────────────────────────────────────────
set "BUILT_EXE=%HERMETIC_DIR%build\x86_64-pc-windows-msvc\release\install\angerona.exe"
if not exist "%BUILT_EXE%" (
    echo [HERMETIC] Output binary not found at expected path:
    echo            %BUILT_EXE%
    exit /b 1
)

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
copy /y "%BUILT_EXE%" "%DIST_DIR%\angerona.exe" >nul
echo [HERMETIC] Binary written: %DIST_DIR%\angerona.exe
echo.

:: ── optional: code-sign ──────────────────────────────────────────────────────
where signtool >nul 2>&1
if not errorlevel 1 (
    echo [HERMETIC] signtool found.  To sign:
    echo   signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
    echo     /f your_cert.pfx /p ^<password^> %DIST_DIR%\angerona.exe
) else (
    echo [HERMETIC] signtool not found — binary is UNSIGNED.  Sign before deployment.
)

echo.
echo [HERMETIC] Done.  Run %DIST_DIR%\angerona.exe for hardened mode.
exit /b 0
