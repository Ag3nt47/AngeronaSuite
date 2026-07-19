@echo off
REM ============================================================================
REM  Angerona - one-click start.
REM  First run: self-elevates, creates a venv, installs the app + dependencies
REM  (downloads PySide6, ~1-2 min). Every run after: just launches the GUI.
REM
REM  Finds a REAL Python even when the Microsoft Store "python.exe" stub is on
REM  PATH (the #1 cause of "Python was not found" on a fresh Windows machine).
REM ============================================================================
cd /d "%~dp0"
title Angerona launcher

REM Keep every persistent/runtime write on the D: installation drive.
set "ANGERONA_DATA=%~dp0runtime-data"
set "ANGERONA_DIAG_DIR=%~dp0diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=1"
set "TEMP=%~dp0runtime-data\tmp"
set "TMP=%TEMP%"
set "ANGERONA_INSTALL_ROOT=%~dp0"
set "ANGERONA_PRETRUSTED="
call :check_existing_trust_root
if not errorlevel 1 set "ANGERONA_PRETRUSTED=1"

REM ── Self-elevate (full-system telemetry needs Administrator) ────────────────
"%SystemRoot%\System32\net.exe" session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    set "ANGERONA_ELEVATE_PATH=%~f0"
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath $env:ANGERONA_ELEVATE_PATH -Verb RunAs"
    exit /b
)

REM Protect the elevated Python/code trust root before any local executable runs.
call :harden_trust_root
if errorlevel 1 (
    echo [!] Could not establish a private install trust root.
    echo     Move Angerona to an NTFS folder owned by this Windows account.
    pause
    exit /b 1
)
if not defined ANGERONA_PRETRUSTED if exist "%~dp0venv" (
    echo [WARN] Removing an untrusted pre-existing virtual environment ...
    set "ANGERONA_VENV_TO_REMOVE=%~dp0venv"
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$r=[IO.Path]::GetFullPath($env:ANGERONA_INSTALL_ROOT); $v=[IO.Path]::GetFullPath($env:ANGERONA_VENV_TO_REMOVE); if ([IO.Path]::GetDirectoryName($v.TrimEnd('\')) -ne $r.TrimEnd('\')) {exit 2}; if (Test-Path -LiteralPath $v) {Remove-Item -LiteralPath $v -Recurse -Force}"
    if errorlevel 1 (pause & exit /b 1)
)
if not exist "%TEMP%" mkdir "%TEMP%"

REM ── First-run install (skip straight to launch if the venv already exists) ──
if exist "venv\Scripts\pythonw.exe" goto launch

echo [*] First run - setting up. This downloads PySide6, ~1-2 minutes...
call :find_python
if not defined PYCMD (
    echo [!] No real Python 3.10+ found.
    echo     Install it from https://www.python.org/downloads/ ^(tick "Add python.exe to PATH"^),
    echo     or turn OFF the Microsoft Store stub under
    echo     Settings ^> Apps ^> Advanced app settings ^> App execution aliases, then re-run.
    pause
    exit /b 1
)
echo [*] Using Python: %PYCMD%
%PYCMD% -m venv venv || (echo [!] venv creation failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --upgrade "pip==26.1.2"
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --build-constraint constraints-release.txt -c constraints-release.txt -e .[windows,voice] || (echo [!] Install failed. & pause & exit /b 1)
"venv\Scripts\python.exe" "tools\build_srt_compat_wheel.py" --out "%TEMP%\wheels" || (echo [!] Speech compatibility wheel build failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: "%TEMP%\wheels\srt-0.0.0+angerona.1-py3-none-any.whl" || (echo [!] Speech compatibility wheel install failed. & pause & exit /b 1)
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --no-deps "vosk==0.3.45" || (echo [!] Offline speech engine install failed. & pause & exit /b 1)
echo [*] Installing the verified offline speech model to the D-drive data folder...
"venv\Scripts\python.exe" -c "from angerona.connectors.voice import install_offline_model; print(install_offline_model())" || echo [!] Speech model setup failed; retry from Settings ^> ARIA.

:launch
REM ── Launch (pythonw = no console window) ─────────────────────────────────────
echo [*] Launching Angerona...
REM BL-01: if the signed out-of-process watchdog is built, use it as the resilience
REM PARENT (it launches + hashes + relaunches Angerona). ANGERONA_EXTERNAL_WATCHDOG
REM tells the in-process manager to skip its own watchdog (no double-supervision).
REM See frz\BUILD_SIGN_DEPLOY.md to build and code-sign the binary.
set "ANGERONA_WATCHDOG=%~dp0frz\angerona_watchdog.exe"
set "ANGERONA_WATCHDOG_SIGNED="
if exist "%ANGERONA_WATCHDOG%" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "if ((Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_WATCHDOG).Status -eq 'Valid') {exit 0}; exit 1" >nul 2>&1 && set "ANGERONA_WATCHDOG_SIGNED=1"
if defined ANGERONA_WATCHDOG_SIGNED (
    set "ANGERONA_EXTERNAL_WATCHDOG=1"
    for /f %%H in ('"%SystemRoot%\System32\certutil.exe" -hashfile "venv\Scripts\pythonw.exe" SHA256 ^| "%SystemRoot%\System32\findstr.exe" /r "^[0-9a-f]*$"') do set "ANGERONA_AGENT_SHA256=%%H"
    echo [*] Using signed watchdog as resilience parent.
    start "" "%ANGERONA_WATCHDOG%" "venv\Scripts\pythonw.exe" -m angerona
) else (
    start "" "venv\Scripts\pythonw.exe" -m angerona
)

REM ── Black Box out-of-band recorder ─────────────────────────────────────────
REM Detached, independent process (pythonw = no console window). --show opens
REM the window immediately. Strictly read-only: it only tails diagnostic files
REM and queries psutil, never touches the suite, so it survives even a fatal
REM deadlock of the main Angerona process.
REM The suite launches exactly one Black Box child after the GUI paints.
exit /b

REM ── Locate a real Python interpreter, skipping the Microsoft Store stub ──────
:harden_trust_root
set "ANGERONA_INSTALL_ROOT=%~dp0"
set "ANGERONA_TRUST_MARKER=%~dp0.install-trust-v2"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$a=New-Object Security.AccessControl.DirectorySecurity; $ad=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); $sy=New-Object Security.Principal.SecurityIdentifier('S-1-5-18'); $us=[Security.Principal.WindowsIdentity]::GetCurrent().User; $a.SetOwner($ad); $a.SetAccessRuleProtection($true,$false); foreach($s in @($ad,$sy)) {$r=[Security.AccessControl.FileSystemAccessRule]::new($s,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); [void]$a.AddAccessRule($r)}; $ur=[Security.AccessControl.FileSystemAccessRule]::new($us,[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); [void]$a.AddAccessRule($ur); Set-Acl -LiteralPath $env:ANGERONA_INSTALL_ROOT -AclObject $a" >nul 2>&1
if errorlevel 1 exit /b 1
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=$env:ANGERONA_TRUST_MARKER; try {$a=Get-Acl -LiteralPath $p; $o=(New-Object Security.Principal.NTAccount($a.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value; $ids=@($a.Access|ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}|Select-Object -Unique); if ((Get-Content -LiteralPath $p -Raw) -eq 'Angerona-Trust-v2' -and $o -in @('S-1-5-18','S-1-5-32-544') -and @($ids|Where-Object {$_ -notin @('S-1-5-18','S-1-5-32-544')}).Count -eq 0) {exit 0}} catch {}; exit 1" >nul 2>&1
if not errorlevel 1 exit /b 0
"%SystemRoot%\System32\icacls.exe" "%~dp0*" /reset /T /C >nul 2>&1
if errorlevel 1 exit /b 1
"%SystemRoot%\System32\icacls.exe" "%~dp0" /setowner "*S-1-5-32-544" /T /C >nul 2>&1
if errorlevel 1 exit /b 1
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=$env:ANGERONA_TRUST_MARKER; Set-Content -LiteralPath $p -NoNewline -Encoding ASCII -Value 'Angerona-Trust-v2'; $a=New-Object Security.AccessControl.FileSecurity; $ad=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); $sy=New-Object Security.Principal.SecurityIdentifier('S-1-5-18'); $a.SetOwner($ad); $a.SetAccessRuleProtection($true,$false); foreach($s in @($ad,$sy)) {$r=[Security.AccessControl.FileSystemAccessRule]::new($s,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow); [void]$a.AddAccessRule($r)}; Set-Acl -LiteralPath $p -AclObject $a" >nul 2>&1
if errorlevel 1 exit /b 1
exit /b 0

:find_python
set "PYCMD="
for %%P in (
    "%ProgramFiles%\Python314\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles%\Python310\python.exe"
) do if not defined PYCMD if exist "%%~P" call :accept_python "%%~P"
goto :eof

:accept_python
set "ANGERONA_CANDIDATE=%~1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_CANDIDATE; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Python Software Foundation') {exit 0}; exit 1" >nul 2>&1
if errorlevel 1 goto :eof
"%~1" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 set "PYCMD="%~1""
goto :eof

:check_existing_trust_root
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=$env:ANGERONA_INSTALL_ROOT; try {$i=Get-Item -LiteralPath $p -Force; if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {exit 1}; $a=Get-Acl -LiteralPath $p; $o=(New-Object Security.Principal.NTAccount($a.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value; $d=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership; $bad=@($a.Access^|Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -and (($_.FileSystemRights -band $d) -ne 0)}); if ($o -in @('S-1-5-18','S-1-5-32-544') -and $bad.Count -eq 0) {exit 0}} catch {}; exit 1" >nul 2>&1
goto :eof
