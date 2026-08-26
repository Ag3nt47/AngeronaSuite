@echo off
REM ============================================================================
REM  pull-from-github.bat — scan-before-merge GitHub pull.
REM  Fetches without running project code, scans incoming commits with the
REM  pinned Gitleaks binary, rejects workflow changes and divergent history,
REM  and permits only a fast-forward merge into a clean working tree.
REM ============================================================================
setlocal EnableExtensions
title Angerona - Secure Pull from GitHub
cd /d "%~dp0"

where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git is not installed or not on PATH.
    pause & exit /b 1
)
if not exist ".git" (
    echo [ERROR] This folder is not a git repository.
    pause & exit /b 1
)
git status --porcelain | findstr . >nul
if not errorlevel 1 (
    echo [ABORT] Local changes are present. Commit or stash them before pulling.
    pause & exit /b 1
)

for /f "usebackq delims=" %%R in (`git remote get-url origin`) do set "REMOTE_URL=%%R"
if not defined REMOTE_URL (
    echo [ABORT] No origin remote is configured.
    pause & exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$u=[Uri]$env:REMOTE_URL; if($u.Scheme -cne 'https' -or $u.Host -cne 'github.com' -or $u.UserInfo){exit 1}"
if errorlevel 1 (
    echo [ABORT] Origin must be credential-free HTTPS on github.com.
    pause & exit /b 1
)
for /f "usebackq delims=" %%B in (`git branch --show-current`) do set "BRANCH=%%B"
if not defined BRANCH (
    echo [ABORT] Detached HEAD is not accepted by the secure pull helper.
    pause & exit /b 1
)

set "GITLEAKS=%CD%\.dev-tools\bin\gitleaks.exe"
if not exist "%GITLEAKS%" (
    echo [*] Installing the verified local secret scanner ...
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%CD%\tools\bootstrap_github_toolkit.ps1"
    if errorlevel 1 (
        echo [ERROR] The verified secret scanner could not be prepared. Nothing was fetched.
        pause & exit /b 1
    )
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$m=Get-Content -LiteralPath '.\tools\github_toolkit.lock.json' -Raw|ConvertFrom-Json;$a=$m.github_assets|Where-Object id -CEQ 'gitleaks';$h=(Get-FileHash -LiteralPath $env:GITLEAKS -Algorithm SHA256).Hash.ToLowerInvariant();if($null -eq $a -or $h -cne $a.sha256){exit 1}"
if errorlevel 1 (
    echo [ABORT] The local secret scanner failed its pinned SHA-256 check.
    pause & exit /b 1
)

echo [*] Fetching origin/%BRANCH% without tags or submodule recursion ...
git -c protocol.file.allow=never -c submodule.recurse=false fetch --no-tags origin "%BRANCH%"
if errorlevel 1 (
    echo [ERROR] Fetch failed. The working tree was not changed.
    pause & exit /b 1
)
for /f "usebackq delims=" %%L in (`git rev-parse HEAD`) do set "LOCAL_SHA=%%L"
for /f "usebackq delims=" %%U in (`git rev-parse "refs/remotes/origin/%BRANCH%"`) do set "REMOTE_SHA=%%U"
if "%LOCAL_SHA%"=="%REMOTE_SHA%" (
    echo [PASS] Already up to date.
    pause & exit /b 0
)
git merge-base --is-ancestor "%REMOTE_SHA%" "%LOCAL_SHA%"
if not errorlevel 1 (
    echo [PASS] Local branch already contains every remote commit.
    pause & exit /b 0
)
git merge-base --is-ancestor "%LOCAL_SHA%" "%REMOTE_SHA%"
if errorlevel 1 (
    echo [ABORT] Local and remote histories diverged. Manual review is required.
    pause & exit /b 1
)

git diff --name-only "%LOCAL_SHA%" "%REMOTE_SHA%" -- .github/workflows | findstr . >nul
if not errorlevel 1 (
    echo [ABORT] Incoming commits modify GitHub workflows. Review them manually before merging.
    pause & exit /b 1
)
git diff --check "%LOCAL_SHA%" "%REMOTE_SHA%"
if errorlevel 1 (
    echo [ABORT] Incoming commits fail Git whitespace/integrity checks.
    pause & exit /b 1
)
echo [*] Scanning incoming commits for secrets before merge ...
"%GITLEAKS%" git . --redact --no-banner --log-opts="%LOCAL_SHA%..%REMOTE_SHA%"
if errorlevel 1 (
    echo [ABORT] Incoming commits contain a credential-like value. Nothing was merged.
    pause & exit /b 1
)

git -c submodule.recurse=false merge --ff-only --no-edit "refs/remotes/origin/%BRANCH%"
if errorlevel 1 (
    echo [ERROR] Fast-forward merge failed. Manual review is required.
    pause & exit /b 1
)
echo [PASS] Secure pull completed with a clean secret scan.
pause
exit /b 0
