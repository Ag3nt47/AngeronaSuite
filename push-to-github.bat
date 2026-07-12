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
if "%MSG%"=="" (
    echo [CANCELLED] No commit message entered - nothing was pushed.
    pause & exit /b 0
)

echo.
echo [*] Staging + committing ...
git add -A
git commit -m "%MSG%"

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
