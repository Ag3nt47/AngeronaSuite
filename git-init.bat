@echo off
REM One-shot: initialise a git repo for AngeronaSuite and make the first commit.
REM Output is written to _gitinit.log so it can be reviewed.
cd /d "%~dp0"
set "LOG=%~dp0_gitinit.log"

echo === where git === > "%LOG%"
where git >> "%LOG%" 2>&1
if errorlevel 1 (
    echo. >> "%LOG%"
    echo [!] git is not installed / not on PATH. Install Git for Windows from >> "%LOG%"
    echo     https://git-scm.com/download/win  then re-run this. >> "%LOG%"
    exit /b 1
)

echo === git init === >> "%LOG%"
git init >> "%LOG%" 2>&1
git config user.email "angerona@local" >> "%LOG%" 2>&1
git config user.name "Angerona Dev" >> "%LOG%" 2>&1
git config core.autocrlf true >> "%LOG%" 2>&1

echo === git add === >> "%LOG%"
git add -A >> "%LOG%" 2>&1

echo === git commit === >> "%LOG%"
git commit -m "360 hardening: self-hardening, Judgment Gate, driver-intel shield, jitter/perf, forensics UI, unified red-team simulation; fix PE32+ export parser" >> "%LOG%" 2>&1

echo === result === >> "%LOG%"
git log --oneline -1 >> "%LOG%" 2>&1
git status --short >> "%LOG%" 2>&1
echo (done) >> "%LOG%"
