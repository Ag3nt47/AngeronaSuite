@echo off
REM ============================================================================
REM  push-to-github.bat  —  one-click: stage all changes, commit, and push.
REM  Respects .gitignore (so .env is never included) and aborts if .env is
REM  somehow tracked. Double-click the Desktop shortcut created by
REM  create-push-shortcut.bat, or run this file directly.
REM ============================================================================
setlocal EnableExtensions
title Angerona - Push to GitHub
cd /d "%~dp0"

where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git is not installed / not on PATH.
    echo         Install Git for Windows: https://git-scm.com/download/win
    pause & exit /b 1
)
if not exist ".git" (
    echo [ERROR] This folder is not a git repository yet.
    echo         Create it in GitHub Desktop first, or run git-init.bat.
    pause & exit /b 1
)

echo ============================================================
echo   Angerona  -  commit ^& push to GitHub
echo ============================================================
echo.

REM --- Safety: never let .env get committed ---------------------------------
git ls-files --error-unmatch .env >nul 2>&1
if not errorlevel 1 (
    echo [ABORT] .env is TRACKED by git and must never be committed.
    echo         Remove it from tracking first:  git rm --cached .env
    pause & exit /b 1
)

echo Changes that will be committed:
git status --short
echo.

set "MSG="
set /p "MSG=Commit message (leave blank to CANCEL): "
if not defined MSG (
    echo [CANCELLED] No commit message entered - nothing was pushed.
    pause & exit /b 0
)

echo.
echo [*] Staging + committing ...
git add -A
if errorlevel 1 (
    echo [ERROR] Git could not stage the current tree. Nothing was pushed.
    pause & exit /b 1
)
git diff --cached --quiet
if not errorlevel 1 (
    echo [INFO] No staged changes exist. Nothing was committed or pushed.
    pause & exit /b 0
)

REM Scan the exact staged file contents with the same engine used by GitHub
REM before creating a commit. Deleted lines are deliberately excluded so a
REM credential-removal commit cannot be blocked by the value it removes. The
REM developer copy is downloaded from the pinned,
REM SHA-256-verified toolkit manifest on first use.
set "GITLEAKS=%CD%\.dev-tools\bin\gitleaks.exe"
if not exist "%GITLEAKS%" (
    echo [*] Installing the verified local secret scanner ...
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%CD%\tools\bootstrap_github_toolkit.ps1"
    if errorlevel 1 (
        echo [ERROR] The verified secret scanner could not be prepared. Nothing was committed.
        pause & exit /b 1
    )
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$m=Get-Content -LiteralPath '.\tools\github_toolkit.lock.json' -Raw|ConvertFrom-Json;$a=$m.github_assets|Where-Object id -CEQ 'gitleaks';$h=(Get-FileHash -LiteralPath $env:GITLEAKS -Algorithm SHA256).Hash.ToLowerInvariant();if($null -eq $a -or $h -cne $a.sha256){exit 1}"
if errorlevel 1 (
    echo [ABORT] The local secret scanner failed its pinned SHA-256 check. Nothing was committed.
    pause & exit /b 1
)
echo [*] Scanning the exact staged file contents for secrets ...
set "SECRET_SCAN_FAILED=0"
for /f "usebackq delims=" %%F in (`git diff --cached --name-only --diff-filter^=ACMR`) do (
    git show ":%%F" | "%GITLEAKS%" stdin --redact --no-banner
    if errorlevel 1 set "SECRET_SCAN_FAILED=1"
)
if "%SECRET_SCAN_FAILED%"=="1" (
    echo [ABORT] Secret scanning found a credential-like value. Nothing was committed or pushed.
    pause & exit /b 1
)

REM Never expand operator text into cmd.exe syntax. Write it through the
REM environment to a repo-internal temporary file, then let Git read the file.
set "MSGFILE=%CD%\.git\ANGERONA_COMMIT_MESSAGE.tmp"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "[IO.File]::WriteAllText($env:MSGFILE, $env:MSG, [Text.UTF8Encoding]::new($false))"
if errorlevel 1 (
    echo [ERROR] The commit message could not be prepared. Nothing was pushed.
    pause & exit /b 1
)
git commit -F "%MSGFILE%"
set "COMMIT_RC=%ERRORLEVEL%"
del /q "%MSGFILE%" >nul 2>&1
if not "%COMMIT_RC%"=="0" (
    echo [ERROR] Commit failed. Nothing was pushed.
    pause & exit /b 1
)

echo.
echo [*] Pushing to GitHub ...
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo [INFO] No 'origin' remote is configured, so the commit is saved locally only.
    echo        Publish the repo once in GitHub Desktop, or add a remote:
    echo          git remote add origin https://github.com/USER/REPO.git
    echo          git push -u origin HEAD
    pause & exit /b 0
)
for /f "usebackq delims=" %%R in (`git remote get-url origin`) do set "REMOTE_URL=%%R"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$u=[Uri]$env:REMOTE_URL; if($u.Scheme -cne 'https' -or $u.Host -cne 'github.com' -or $u.UserInfo){exit 1}"
if errorlevel 1 (
    echo [ABORT] Origin must be credential-free HTTPS on github.com. Nothing was pushed.
    pause & exit /b 1
)
git push
if errorlevel 1 (
    echo.
    echo [WARN] Push did not complete. If this is the first push, set the upstream:
    echo          git push -u origin HEAD
    echo        You may also be prompted to sign in to GitHub.
    pause & exit /b 1
)

echo.
echo [DONE] Changes pushed to GitHub.
pause
exit /b 0
