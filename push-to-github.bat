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
