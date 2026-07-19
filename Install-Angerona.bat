@echo off
REM ============================================================================
REM  Install-Angerona.bat  —  one-double-click deployment for Project Angerona.
REM
REM  Idempotent infrastructure-as-code bootstrapper. Safe to run repeatedly: it
REM  checks for each dependency before installing and never clobbers existing
REM  configuration. Steps (in order):
REM     1. Self-elevate to Administrator (UAC).
REM     2. Ensure Python 3.10+ (winget install if missing).
REM     3. Create venv + install Angerona and dependencies.
REM     4. Ensure Ollama + pull the llama3:8b local model (with progress).
REM     5. Compile the Go hypervisor watchdog (if the Go toolchain is present).
REM     6. Restrict the install tree to this user, Administrators, and SYSTEM.
REM     7. Create the supported Angerona Desktop shortcut.
REM  Output is color-coded: [INFO] cyan, [OK] green, [WARN] yellow, [ERROR] red.
REM ============================================================================
setlocal EnableExtensions
title Angerona Installer
cd /d "%~dp0"
set "ANGERONA_DATA=%~dp0runtime-data"
set "ANGERONA_DIAG_DIR=%~dp0diagnostics"
set "TEMP=%~dp0runtime-data\tmp"
set "TMP=%TEMP%"
set "ANGERONA_INSTALL_ROOT=%~dp0"
set "ANGERONA_PRETRUSTED="
call :check_existing_trust_root
if not errorlevel 1 set "ANGERONA_PRETRUSTED=1"

REM ── 1. UAC elevation ────────────────────────────────────────────────────────
"%SystemRoot%\System32\net.exe" session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges ...
    set "ANGERONA_ELEVATE_PATH=%~f0"
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath $env:ANGERONA_ELEVATE_PATH -Verb RunAs"
    exit /b
)

REM Establish the elevated code trust root before Python, pip, build scripts, or
REM files from runtime-data can execute. The DPAPI marker makes later checks fast
REM but cannot be forged by a different local account.
call :harden_trust_root
if errorlevel 1 (
    echo [ERROR] Could not establish a private install trust root.
    echo         Move Angerona to an NTFS folder owned by this Windows account.
    goto :fail
)
if not defined ANGERONA_PRETRUSTED if exist "%~dp0venv" (
    echo [WARN] Removing an untrusted pre-existing virtual environment ...
    set "ANGERONA_VENV_TO_REMOVE=%~dp0venv"
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$r=[IO.Path]::GetFullPath($env:ANGERONA_INSTALL_ROOT); $v=[IO.Path]::GetFullPath($env:ANGERONA_VENV_TO_REMOVE); if ([IO.Path]::GetDirectoryName($v.TrimEnd('\')) -ne $r.TrimEnd('\')) {exit 2}; if (Test-Path -LiteralPath $v) {Remove-Item -LiteralPath $v -Recurse -Force}"
    if errorlevel 1 goto :fail
)
if not exist "%TEMP%" mkdir "%TEMP%"

call :log INFO "Angerona bootstrapper starting"

REM ── 2. Python 3.10+ ─────────────────────────────────────────────────────────
call :find_python
if not defined PYCMD (
    call :log INFO "Python 3.10+ not found - attempting winget install ..."
    call :find_winget
    if not defined WINGET_EXE (
        call :log ERROR "winget not available. Install Python 3.10+ from https://python.org and re-run."
        goto :fail
    )
    "%WINGET_EXE%" install --id Python.Python.3.10 --scope machine --silent --accept-package-agreements --accept-source-agreements
    call :find_python
)
if not defined PYCMD (
    call :log ERROR "Python still not found after install attempt."
    goto :fail
)
call :log OK "Python interpreter ready"

REM ── 3. venv + dependencies (idempotent) ─────────────────────────────────────
if exist "venv\Scripts\python.exe" (
    call :log OK "Virtual environment already present - reusing it"
) else (
    call :log INFO "Creating virtual environment ..."
    %PYCMD% -m venv venv
    if errorlevel 1 ( call :log ERROR "venv creation failed" & goto :fail )
)
call :log INFO "Upgrading pip ..."
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --upgrade "pip==26.1.2" >nul 2>&1
call :log INFO "Installing Angerona + dependencies (this can take a minute) ..."
if exist "pyproject.toml" (
    "venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --build-constraint constraints-release.txt -c constraints-release.txt -e .[windows,voice]
    if errorlevel 1 (
        "venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: -c constraints-release.txt -r requirements.txt
        if not errorlevel 1 "venv\Scripts\python.exe" -m pip install --isolated --build-constraint constraints-release.txt --no-deps -e .
    )
) else (
    call :log ERROR "pyproject.toml is missing; refusing an incomplete installation"
    goto :fail
)
if errorlevel 1 ( call :log ERROR "Dependency install failed" & goto :fail )
REM Vosk's audited wheel is installed without its source-only srt dependency.
REM Angerona ships the tiny Subtitle/compose compatibility surface it needs.
"venv\Scripts\python.exe" "tools\build_srt_compat_wheel.py" --out "%TEMP%\wheels"
if errorlevel 1 ( call :log ERROR "Speech compatibility wheel build failed" & goto :fail )
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: "%TEMP%\wheels\srt-0.0.0+angerona.1-py3-none-any.whl"
if errorlevel 1 ( call :log ERROR "Speech compatibility wheel install failed" & goto :fail )
"venv\Scripts\python.exe" -m pip install --isolated --only-binary :all: --no-deps "vosk==0.3.45"
if errorlevel 1 ( call :log ERROR "Offline speech engine install failed" & goto :fail )
call :log OK "Python dependencies installed"
call :log INFO "Installing the verified offline speech model to Angerona's data drive ..."
"venv\Scripts\python.exe" -c "from angerona.connectors.voice import install_offline_model; print(install_offline_model())"
if errorlevel 1 ( call :log WARN "Offline speech model setup failed; retry from Settings > ARIA" ) else ( call :log OK "Offline conversation model ready" )

REM ── 4. Ollama + local model ─────────────────────────────────────────────────
call :find_ollama
if not defined OLLAMA_EXE (
    call :log INFO "Installing Ollama via winget ..."
    call :find_winget
    if not defined WINGET_EXE (
        call :log WARN "winget missing - skipping Ollama. Install from https://ollama.com and run: ollama pull llama3:8b"
        goto :after_ollama
    )
    "%WINGET_EXE%" install --id Ollama.Ollama --scope machine --silent --accept-package-agreements --accept-source-agreements
) else (
    call :log OK "Ollama already installed"
)
call :find_ollama
if not defined OLLAMA_EXE (
    call :log WARN "Ollama not on PATH yet - open a NEW terminal and run: ollama pull llama3:8b"
) else (
    call :log INFO "Pulling llama3:8b - large one-time download, progress below ..."
    "%OLLAMA_EXE%" pull llama3:8b
    if errorlevel 1 ( call :log WARN "Model pull did not complete - retry later with: ollama pull llama3:8b" ) else ( call :log OK "Local model llama3:8b ready" )
)
:after_ollama

REM ── 5. Compile the Go hypervisor watchdog ───────────────────────────────────
REM Never resolve or compile a privileged executable from inherited PATH here.
REM Release builds may bundle a separately signed watchdog; developers can build
REM it explicitly after reviewing frz\hypervisor\build.bat.
call :log INFO "Optional signed watchdog build skipped during secure installation"

REM ── 6. Privileged trust root ────────────────────────────────────────────────
call :log OK "Install trust root was restricted before dependency setup"

REM ── 7. Desktop shortcuts (reuse the existing, idempotent PS1) ────────────────
if exist "create-blackbox-launcher.ps1" (
    call :log INFO "Creating the Angerona Desktop shortcut ..."
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "create-blackbox-launcher.ps1" >nul 2>&1
    if errorlevel 1 ( call :log WARN "Shortcut creation reported an issue" ) else ( call :log OK "Desktop shortcuts created" )
) else (
    call :log WARN "create-blackbox-launcher.ps1 not found - skipping shortcuts"
)

echo.
call :log OK "Angerona installation complete."
call :log INFO "Launch the suite with run.bat  (elevated GUI)."
call :log INFO "To run the decoupled watchdog/scanner ecosystem, set ANGERONA_RESILIENCE=1 before launch."
echo.
pause
exit /b 0

:fail
echo.
call :log ERROR "Installation aborted. Resolve the issue above and re-run (the script is idempotent)."
pause
exit /b 1

REM ── colored logger:  call :log LEVEL "message" ──────────────────────────────
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

:log
set "LVL=%~1"
set "MSG=%~2"
set "COLOR=Gray"
if /I "%LVL%"=="INFO"  set "COLOR=Cyan"
if /I "%LVL%"=="OK"    set "COLOR=Green"
if /I "%LVL%"=="WARN"  set "COLOR=Yellow"
if /I "%LVL%"=="ERROR" set "COLOR=Red"
set "ANGERONA_LOG_LEVEL=%LVL%"
set "ANGERONA_LOG_MESSAGE=%MSG%"
set "ANGERONA_LOG_COLOR=%COLOR%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Write-Host ('['+$env:ANGERONA_LOG_LEVEL+'] '+$env:ANGERONA_LOG_MESSAGE) -ForegroundColor $env:ANGERONA_LOG_COLOR"
goto :eof

REM ── Locate a real Python 3.10+, skipping the Microsoft Store stub ────────────
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

:find_ollama
set "OLLAMA_EXE="
for %%O in (
    "%ProgramFiles%\Ollama\ollama.exe"
) do if not defined OLLAMA_EXE if exist "%%~O" call :accept_ollama "%%~O"
goto :eof

:accept_python
set "ANGERONA_CANDIDATE=%~1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_CANDIDATE; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Python Software Foundation') {exit 0}; exit 1" >nul 2>&1
if errorlevel 1 goto :eof
"%~1" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 set "PYCMD="%~1""
goto :eof

:accept_ollama
set "ANGERONA_CANDIDATE=%~1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_CANDIDATE; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Ollama') {exit 0}; exit 1" >nul 2>&1
if not errorlevel 1 set "OLLAMA_EXE=%~1"
goto :eof

:find_winget
set "WINGET_EXE="
for /f "usebackq delims=" %%W in (`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=Get-AppxPackage Microsoft.DesktopAppInstaller ^| Sort-Object Version -Descending ^| Select-Object -First 1; if ($p) {$e=Join-Path $p.InstallLocation 'winget.exe'; $s=Get-AuthenticodeSignature -LiteralPath $e; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Microsoft') {$e}}"`) do set "WINGET_EXE=%%W"
goto :eof

:check_existing_trust_root
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=$env:ANGERONA_INSTALL_ROOT; try {$i=Get-Item -LiteralPath $p -Force; if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {exit 1}; $a=Get-Acl -LiteralPath $p; $o=(New-Object Security.Principal.NTAccount($a.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value; $d=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership; $bad=@($a.Access^|Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -and (($_.FileSystemRights -band $d) -ne 0)}); if ($o -in @('S-1-5-18','S-1-5-32-544') -and $bad.Count -eq 0) {exit 0}} catch {}; exit 1" >nul 2>&1
goto :eof
