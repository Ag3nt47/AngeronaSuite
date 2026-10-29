@echo off
setlocal DisableDelayedExpansion
set "ERRORLEVEL="
REM ============================================================================
REM  Angerona source checkout - one-click UNELEVATED Observe/development start.
REM  Distinct supervised strategies restore a reviewed hash-locked environment.
REM  Every run after launches the GUI without requesting Administrator rights.
REM
REM  Finds a REAL Python even when the Microsoft Store "python.exe" stub is on
REM  PATH (the #1 cause of "Python was not found" on a fresh Windows machine).
REM  Standalone guarantee: this launcher starts Angerona components only.  The
REM  optional authenticated JARVIS adapter is passive and never launches JARVIS.
REM ============================================================================

REM cmd.exe supplies __APPDIR__ from its own loaded image and ignores an
REM inherited variable of the same name. Use that process-owned directory as
REM the trust root before any executable lookup.
set "SAFE_SYSTEM32=%__APPDIR__%"
if not exist "%SAFE_SYSTEM32%cmd.exe" exit /b 1
for %%I in ("%SAFE_SYSTEM32%..") do set "SAFE_WINDOWS=%%~fI"
for %%I in ("%SAFE_WINDOWS%") do set "SAFE_SYSTEMDRIVE=%%~dI"
set "SystemRoot=%SAFE_WINDOWS%"
set "WINDIR=%SAFE_WINDOWS%"
set "SystemDrive=%SAFE_SYSTEMDRIVE%"
set "ComSpec=%SAFE_SYSTEM32%cmd.exe"
set "PATH=%SAFE_SYSTEM32%;%SAFE_WINDOWS%;%SAFE_SYSTEM32%Wbem;%SAFE_SYSTEM32%WindowsPowerShell\v1.0"
set "PATHEXT=.COM;.EXE;.BAT;.CMD"
set "ANGERONA_POWERSHELL=%SAFE_SYSTEM32%WindowsPowerShell\v1.0\powershell.exe"
if not exist "%ANGERONA_POWERSHELL%" exit /b 1

REM Strip inherited code-loading, egress, credential, and resilience controls.
REM Protected credentials are loaded later from the OS store; none are needed
REM by this source setup/launch boundary.
set "PYTHONHOME="
set "PYTHONPATH="
set "PYTHONSTARTUP="
set "PYTHONUSERBASE="
set "PYTHONINSPECT="
set "PYTHONBREAKPOINT="
set "PSModulePath="
set "COR_ENABLE_PROFILING="
set "COR_PROFILER="
set "CORECLR_ENABLE_PROFILING="
set "CORECLR_PROFILER="
set "DOTNET_STARTUP_HOOKS="
set "DOTNET_ADDITIONAL_DEPS="
set "DOTNET_SHARED_STORE="
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "ALL_PROXY="
set "FTP_PROXY="
set "NO_PROXY="
set "ANTHROPIC_API_KEY="
set "GEMINI_API_KEY="
set "GEMINI_API_KEYS="
set "GOOGLE_API_KEY="
set "GROQ_API_KEY="
set "OPENAI_API_KEY="
set "OPENROUTER_API_KEY="
set "ARIA_IMAP_PASS="
set "ANGERONA_TEAMS_APP_PASSWORD="
set "ANGERONA_FLEET_SERVICE_KEY="
set "ANGERONA_BRIDGE_KEY="
set "ANGERONA_MCP_TOKEN="
set "ANGERONA_GUARD_TOKEN="
set "ANGERONA_JARVIS_CONTROL_TOKEN="
set "ANGERONA_HOME="
set "ANGERONA_DATA_DRIVE="
set "ANGERONA_CORE_CMD="
set "ANGERONA_PY="
set "ANGERONA_EXTERNAL_WATCHDOG="
set "ANGERONA_RESILIENCE="
set "ANGERONA_WATCHDOG_TOKEN="
set "ANGERONA_WATCHDOG_MMAP="
set "ANGERONA_WD_DATADIR="
set "ANGERONA_AGENT_SHA256="
set "ANGERONA_EXTERNAL_MODULES="
set "ANGERONA_BOOTSTRAP_RESTORED="

REM Rebuild the remaining launch paths from trusted registry/system locations,
REM not from the caller's environment. Per-user CPython remains supported, but
REM its executable must still pass the PSF Authenticode + ABI checks below.
set "ProgramData=%SAFE_SYSTEMDRIVE%\ProgramData"
set "ProgramFiles=%SAFE_SYSTEMDRIVE%\Program Files"
set "ProgramFiles(x86)=%SAFE_SYSTEMDRIVE%\Program Files (x86)"
for /f "skip=2 tokens=2,*" %%A in ('call "%SAFE_SYSTEM32%reg.exe" query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir /reg:64 2^>nul') do set "ProgramFiles=%%B"
set "ProgramW6432=%ProgramFiles%"
set "LocalAppData="
for /f "skip=2 tokens=3,*" %%A in ('call "%SAFE_SYSTEM32%reg.exe" query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Local AppData" 2^>nul') do set "LocalAppData=%%B"

REM Non-mutating regression hook: validate the trust-boundary scrub without UAC,
REM installation, or application launch. Only this exact literal is accepted.
if /i "%~1"=="--bootstrap-selftest" (
    if not "%SystemRoot%"=="%SAFE_WINDOWS%" exit /b 1
    if not "%ComSpec%"=="%SAFE_SYSTEM32%cmd.exe" exit /b 1
    if not defined LocalAppData exit /b 1
    if not exist "%LocalAppData%" exit /b 1
    if defined PYTHONPATH exit /b 1
    if defined ANGERONA_CORE_CMD exit /b 1
    if defined ANGERONA_FLEET_SERVICE_KEY exit /b 1
    if defined ANGERONA_JARVIS_CONTROL_TOKEN exit /b 1
    if defined OPENAI_API_KEY exit /b 1
    echo ANGERONA_BOOTSTRAP_SELFTEST_OK
    exit /b 0
)
set "ANGERONA_SETUP_ONLY="
if /i "%~1"=="--source-setup" set "ANGERONA_SETUP_ONLY=1"
if not "%~1"=="" if not defined ANGERONA_SETUP_ONLY (
    echo [!] Unsupported source-launch option.
    exit /b 1
)

REM A source checkout must never inherit an Administrator token. The signed
REM MSIX is the only Windows first-install authority for full Protect coverage.
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -Command "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {exit 0}; exit 1" >nul 2>&1
if not errorlevel 1 (
    echo [!] Refusing to execute mutable Angerona source with Administrator rights.
    echo     Use a normal user session for Observe/development coverage.
    echo     Use the OS-validated signed MSIX for full Windows Protect coverage:
    echo     https://github.com/Ag3nt47/AngeronaSuite/releases
    exit /b 1
)

cd /d "%~dp0"
title Angerona launcher
echo.
echo  [ANGERONA] Starting the unelevated source Observe/development profile...
echo  [ANGERONA] This window will close after the dashboard is confirmed alive.
echo.

REM Keep mutable source-profile data in the current user's OS-owned local-data
REM folder, never in the checkout and never at a caller-selected inherited path.
if not defined LocalAppData (
    echo [!] Windows could not resolve the current user's Local AppData folder.
    exit /b 1
)
for %%I in ("%LocalAppData%\Angerona\SourceData") do set "ANGERONA_DATA=%%~fI"
set "ANGERONA_DIAG_DIR=%ANGERONA_DATA%\diagnostics"
set "ANGERONA_STORAGE_AUTOMIGRATE=0"
set "ANGERONA_INSTALL_ROOT=%~dp0"
set "ANGERONA_ENFORCE_KEY_ACL=0"
set "ANGERONA_DEVELOPMENT_MODE=0"
set "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=0"

REM The readable pinned bootstrap below runs before mutable recovery helpers.
REM It verifies the verifier, manifest and operational files before execution.
REM This editable source launcher remains the trust anchor for this checkout.
set "ANGERONA_BATCH_FILE=%~f0"
:source_retry
"%ANGERONA_POWERSHELL%" -NoProfile -NonInteractive -STA -Command "$s=[IO.File]::ReadAllText($env:ANGERONA_BATCH_FILE);$p=$s -split '(?m)^:__ANGERONA_PINNED_BOOTSTRAP__\r?$',2;if($p.Count -ne 2){exit 1};& ([scriptblock]::Create($p[1]))"
:source_finished
set "ANGERONA_SOURCE_RC=%errorlevel%"
if "%ANGERONA_SOURCE_RC%"=="10" goto source_retry
if "%ANGERONA_SOURCE_RC%"=="1223" exit /b %ANGERONA_SOURCE_RC%
if not "%ANGERONA_SOURCE_RC%"=="0" (
    echo [!] Startup needs recovery attention; settings and evidence were preserved.
    echo     Persistent details: %ANGERONA_DATA%\logs\startup-recovery\supervisor.jsonl
    echo     Manual source repair: Repair-Angerona-Python.bat
    echo     Signed release repair: Install-Angerona-Release.bat
    goto source_finished_error
)
exit /b %ANGERONA_SOURCE_RC%
:source_finished_error
pause
exit /b %ANGERONA_SOURCE_RC%

:__ANGERONA_PINNED_BOOTSTRAP__
# This readable payload is embedded in start-angerona.bat by the manifest builder
# companion. The editable source batch file is its trust anchor, not an enclave.
$ErrorActionPreference='Stop'
$manifestSha='e5dfc4b704ec6fdac75d6cfdb3edeec137a39a2cea2f3a7dd2f1707aaf7f4320'
$manifestBlob='f39b0703b5cd4ef9c325464b55f87ffa7e484a0d'
$verifierSha='49e169d2ed7a27dfbcf9bf97fa6e673cc1e10df823bdfdacea21adf019b19230'
$verifierBlob='7ff691075c15f8a5e7775ff2d6f739fc77efe491'
$root=[IO.Path]::GetFullPath($env:ANGERONA_INSTALL_ROOT).TrimEnd('\')
$storage=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData'
$script:BootstrapCanonicalStorage=$storage
$fixedPS=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'

function Assert-BootstrapPlainPath([string]$Path) {
    if($Path -notmatch '^[a-zA-Z]:\\' -or $Path.StartsWith('\\')) { throw 'Startup requires a fixed local path.' }
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor) {
        if(Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType -eq 'HardLink') {
                throw 'Startup refuses redirected or hardlinked recovery paths.'
            }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}
function Assert-BootstrapPrivate([string]$Path, [switch]$AllowInherited) {
    Assert-BootstrapPlainPath $Path
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $item=Get-Item -LiteralPath $Path -Force
    $acl=if($item.PSIsContainer) {[IO.Directory]::GetAccessControl($Path)} else {[IO.File]::GetAccessControl($Path)}
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'Recovery state has an unexpected owner.' }
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @($owner,'S-1-5-18','S-1-5-32-544')) {
            throw 'Recovery state lacks private custody.'
        }
    }
}
function New-BootstrapPrivateDirectory([string]$Path) {
    Assert-BootstrapPlainPath $Path
    if(!(Test-Path -LiteralPath $Path)) {
        $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        }
        [void][IO.Directory]::CreateDirectory($Path,$acl)
    }
    Assert-BootstrapPrivate $Path
}
function Get-BootstrapCanonical([byte[]]$Raw) {
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($Raw)
    if($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text=$text.Substring(1) }
    $text=$text.Replace("`r`n","`n")
    if($text.Contains("`r") -or $text.Contains([string][char]0)) { throw 'Recovery verifier text is invalid.' }
    return ,([Text.UTF8Encoding]::new($false).GetBytes($text))
}
function Get-BootstrapHash([byte[]]$Raw) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Raw))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}
function Get-BootstrapBlob([byte[]]$Raw) {
    $header=[Text.Encoding]::ASCII.GetBytes(('blob '+$Raw.Length+[char]0))
    $joined=New-Object byte[] ($header.Length+$Raw.Length)
    [Buffer]::BlockCopy($header,0,$joined,0,$header.Length);[Buffer]::BlockCopy($Raw,0,$joined,$header.Length,$Raw.Length)
    $algorithm=[Security.Cryptography.SHA1]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($joined))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Read-SourceStartupRecoveryPreferences([string]$Storage) {
    $result = @{ Enabled = $true; Github = $true }
    try {
        $path = Join-Path $Storage 'settings.json'
        Assert-BootstrapPlainPath $path
        if (!(Test-Path -LiteralPath $path)) { return $result }
        Assert-BootstrapPrivate $path -AllowInherited
        $stream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
        try {
            if ($stream.Length -gt 64KB) { throw 'Recovery preferences exceed 64 KiB.' }
            # Match Config's strict UTF-8 JSON contract. StreamReader's BOM
            # detection would accept UTF-16/UTF-8-BOM settings that Config
            # refuses, incorrectly enabling recovery from ambiguous consent.
            $bytes = New-Object byte[] ([int]$stream.Length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $count = $stream.Read($bytes, $offset, $bytes.Length-$offset)
                if (!$count) { throw 'Recovery preferences changed during read.' }
                $offset += $count
            }
            $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        } finally { $stream.Dispose() }
        # First validate JSON, then retain top-level duplicate keys which the
        # PowerShell deserializer would otherwise discard. Nested values have
        # no authority over these preferences. Unknown/ambiguous consent is off.
        $parsed = $raw | ConvertFrom-Json
        if ($null -eq $parsed -or $parsed -isnot [pscustomobject] -or $raw -notmatch '^\s*\{') { throw 'Settings must be a JSON object.' }
        $tokens = [regex]::Matches($raw, '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|[{}\[\]:,]|true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
        $position = 0; $depth = 0; $counts = @{}; $values = @{}
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            $token = $tokens[$i]
            if ($raw.Substring($position, $token.Index-$position).Trim().Length) { throw 'Invalid JSON token.' }
            $position = $token.Index + $token.Length
            if ($token.Value -in @('{','[')) { $depth++; continue }
            if ($token.Value -in @('}',']')) { $depth--; continue }
            if ($depth -eq 1 -and $token.Value.StartsWith('"') -and $i+2 -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
                $name = ConvertFrom-Json ('['+$token.Value+']')
                if ($name -cin @('startup_recovery_enabled','startup_recovery_github_enabled')) {
                    if (!$counts.ContainsKey([string]$name)) { $counts[[string]$name] = 0 }
                    $counts[[string]$name]++
                    $values[[string]$name] = $tokens[$i+2].Value
                }
            }
        }
        if ($raw.Substring($position).Trim().Length -or $raw -match ',\s*[}\]]') { throw 'Invalid JSON suffix or trailing comma.' }
        foreach ($pair in @(@('startup_recovery_enabled','Enabled'),@('startup_recovery_github_enabled','Github'))) {
            if ($counts.ContainsKey($pair[0])) { $result[$pair[1]] = ($counts[$pair[0]] -eq 1 -and $values[$pair[0]] -ceq 'true') }
        }
        return $result
    } catch { return @{ Enabled = $false; Github = $false } }
}

function Initialize-BundleNative([string]$State) {
    if('Angerona.StartupBundleFile' -as [type]) { return }
    $compiler=Join-Path $State 'compiler'
    New-BootstrapPrivateDirectory $compiler
    $total=0; $count=0
    foreach($file in Get-ChildItem -LiteralPath $compiler -Force) {
        Assert-BootstrapPlainPath $file.FullName
        if($file.PSIsContainer -or ++$count -gt 128) { throw 'Recovery compiler scratch requires review.' }
        $total+=$file.Length
        if($total -gt 2MB) { throw 'Recovery compiler scratch reached its capacity.' }
    }
    $oldTemp,$oldTmp=$env:TEMP,$env:TMP
    try {
        $env:TEMP=$compiler; $env:TMP=$compiler
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
namespace Angerona {
public sealed class StartupBundleFile : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct INFO {
        public uint attrs,createdLow,createdHigh,accessLow,accessHigh,writeLow,writeHigh;
        public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct SECURITY {
        public int size; public IntPtr descriptor; public bool inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct DISPOSITION { public uint flags; }
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint create,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out INFO info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(IntPtr file,int kind,ref DISPOSITION value,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileTime(IntPtr file,IntPtr created,IntPtr accessed,ref long modified);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr file);
    readonly List<IntPtr> directories=new List<IntPtr>();
    FileStream stream; INFO initial; readonly string path; bool closed;
    static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static INFO Information(IntPtr handle,bool directory) {
        INFO value; Check(GetFileInformationByHandle(handle,out value));
        if((value.attrs&0x400)!=0 || (((value.attrs&0x10)!=0)!=directory) || (!directory && value.links!=1))
            throw new IOException("Recovery bundle requires plain single-link files and directories.");
        return value;
    }
    static bool Equal(INFO a,INFO b) {
        return a.volume==b.volume && a.indexHigh==b.indexHigh && a.indexLow==b.indexLow &&
            a.sizeHigh==b.sizeHigh && a.sizeLow==b.sizeLow && a.writeHigh==b.writeHigh && a.writeLow==b.writeLow;
    }
    void Bound() {
        INFO held=Information(stream.SafeFileHandle.DangerousGetHandle(),false);
        IntPtr named=CreateFileW(path,0x80000000,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        Check(named!=new IntPtr(-1));
        try { if(!Equal(initial,held) || !Equal(initial,Information(named,false))) throw new IOException("Recovery file identity changed."); }
        finally { CloseHandle(named); }
    }
    public StartupBundleFile(string name,bool create,bool deletion) {
        path=Path.GetFullPath(name);
        try {
            if(!Path.IsPathRooted(path) || path.StartsWith(@"\\",StringComparison.Ordinal)) throw new IOException("Local recovery path required.");
            string root=Path.GetPathRoot(path),parent=Path.GetDirectoryName(path),current=root;
            var parts=new List<string>(); parts.Add(root);
            foreach(string part in parent.Substring(root.Length).Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries)) {
                current=Path.Combine(current,part);parts.Add(current);
                if(parts.Count>64) throw new IOException("Recovery ancestry bound exceeded.");
            }
            foreach(string directory in parts) {
                // Traverse/attributes engage sharing checks without directory
                // enumeration. Allow child writes; deny deletion/rename of the
                // held ancestor itself. Verified file bytes remain SHARE_READ.
                IntPtr held=CreateFileW(directory,0x80|0x20,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                Check(held!=new IntPtr(-1)); directories.Add(held);Information(held,true);
            }
            uint access=0x80000000|(deletion?0x10000u:0u)|(create?0x40000000u:0u);
            IntPtr handle=CreateFileW(path,access,1,IntPtr.Zero,create?1u:3u,0x00200000,IntPtr.Zero);
            Check(handle!=new IntPtr(-1));
            var safe=new SafeFileHandle(handle,true);
            try { stream=new FileStream(safe,create?FileAccess.ReadWrite:FileAccess.Read); }
            catch { safe.Dispose();throw; }
            initial=Information(handle,false);Bound();
        } catch { Dispose();throw; }
    }
    public byte[] Read(int limit) {
        Bound();long size=((long)initial.sizeHigh<<32)|initial.sizeLow;
        if(size>limit) throw new IOException("Recovery file exceeds its byte bound.");
        byte[] result=new byte[(int)size];stream.Position=0;int count=0;
        while(count<result.Length) { int read=stream.Read(result,count,result.Length-count);if(read==0)break;count+=read; }
        if(count!=result.Length || stream.ReadByte()!=-1) throw new IOException("Recovery file length changed.");
        Bound();return result;
    }
    public void Write(byte[] data) {
        stream.Write(data,0,data.Length);stream.Flush(true);initial=Information(stream.SafeFileHandle.DangerousGetHandle(),false);Bound();
    }
    public void SetModified(long time) {
        Bound();Check(SetFileTime(stream.SafeFileHandle.DangerousGetHandle(),IntPtr.Zero,IntPtr.Zero,ref time));
        initial=Information(stream.SafeFileHandle.DangerousGetHandle(),false);Bound();
    }
    public void Delete() {
        Bound();var value=new DISPOSITION();value.flags=0x11;
        Check(SetFileInformationByHandle(stream.SafeFileHandle.DangerousGetHandle(),21,ref value,4));
    }
    public void Dispose() {
        if(closed)return;closed=true;
        if(stream!=null)stream.Dispose();
        for(int index=directories.Count-1;index>=0;index--)CloseHandle(directories[index]);directories.Clear();
    }
}
}
'@
    } finally { $env:TEMP=$oldTemp; $env:TMP=$oldTmp }
}

function Get-BundleDataRoot { return $script:BootstrapCanonicalStorage }
function Assert-BundleLockCustody([string]$Path,[switch]$PermitReadOnlyPrincipals) {
    Assert-BootstrapPlainPath $Path
    $item=Get-Item -LiteralPath $Path -Force
    $acl=if($item.PSIsContainer) {[IO.Directory]::GetAccessControl($Path)}else{[IO.File]::GetAccessControl($Path)}
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'Recovery mutation lease has unknown owner custody.' }
    $readOnly=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -ne 'Allow') { throw 'Recovery mutation lease has ambiguous access rules.' }
        if($rule.IdentityReference.Value -notin @($owner,'S-1-5-18','S-1-5-32-544') -and
            (!$PermitReadOnlyPrincipals -or ([long]$rule.FileSystemRights -band (-bnot [long]$readOnly)))) {
            throw 'Recovery mutation lease permits unrelated mutation.'
        }
    }
}

function Open-BundleMutationLock([string]$Path,[switch]$PermitReadOnlyPrincipals) {
    Assert-BootstrapPlainPath $Path
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    $lease=[IO.FileStream]::new($Path,[IO.FileMode]::OpenOrCreate,
        ([Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write),
        [IO.FileShare]::ReadWrite,4096,[IO.FileOptions]::None,$acl)
    try {
        Assert-BundleLockCustody $Path -PermitReadOnlyPrincipals:$PermitReadOnlyPrincipals
        $lease.Lock(0,1);return $lease
    } catch { $lease.Dispose();throw 'Recovery mutation is held by an active runtime/helper or unknown lease custody.' }
}

function Close-BundleMutationLocks($Leases) {
    for($index=$Leases.Count-1;$index -ge 0;$index--) {
        try {$Leases[$index].Unlock(0,1)}finally{$Leases[$index].Dispose()}
    }
}

function Enter-BundleMutationLocks([string]$Root) {
    $leases=[Collections.Generic.List[object]]::new()
    try {
        $repair=Join-Path $Root '.tmp\repair-wheels'
        Assert-BootstrapPlainPath $repair;[void][IO.Directory]::CreateDirectory($repair);Assert-BootstrapPlainPath $repair
        $leases.Add((Open-BundleMutationLock (Join-Path $repair 'startup-repair.lock') -PermitReadOnlyPrincipals))
        $storage=Get-BundleDataRoot
        if(!(Test-Path -LiteralPath $storage)) { New-BootstrapPrivateDirectory $storage }
        Assert-BundleLockCustody $storage
        $leases.Add((Open-BundleMutationLock (Join-Path $storage 'startup-helper.lock')))
        $leases.Add((Open-BundleMutationLock (Join-Path $storage 'angerona.instance.lock')))
        return ,($leases.ToArray())
    } catch { Close-BundleMutationLocks $leases;throw }
}

function Show-BootstrapRecovery([string]$Message) {
    Write-Host ('[startup] '+$Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $form=[Windows.Forms.Form]::new();$form.Text='Angerona startup recovery';$form.Width=700;$form.Height=330
        $form.StartPosition='CenterScreen'
        $label=[Windows.Forms.TextBox]::new();$label.Multiline=$true;$label.ReadOnly=$true
        $label.Dock='Fill';$label.ScrollBars='Vertical'
        $label.Text="Angerona could not verify its recovery files. Protection is not verified.`r`n`r`n$Message`r`n`r`nSettings and evidence were preserved. Review the recovery settings or restore the official source launcher. Retry repeats verification."
        $buttons=[Windows.Forms.FlowLayoutPanel]::new();$buttons.Dock='Bottom';$buttons.Height=50
        $retry=[Windows.Forms.Button]::new();$retry.Text='Retry';$retry.Width=120;$retry.DialogResult='Retry'
        $close=[Windows.Forms.Button]::new();$close.Text='Close';$close.Width=120;$close.DialogResult='Cancel'
        $buttons.Controls.Add($retry);$buttons.Controls.Add($close);$form.Controls.Add($label);$form.Controls.Add($buttons)
        try { if($form.ShowDialog() -eq 'Retry') { return 10 };return 1223 } finally {$form.Dispose()}
    } catch { Write-Host '[startup] Recovery display unavailable; retain this console.'; return 1 }
}

$verifierLease=$null
$bootstrapMutation=@()
try {
    Assert-BootstrapPlainPath $root
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
    if(!$drive.IsReady -or $drive.DriveType -ne 'Fixed') { throw 'Source startup requires a ready fixed local drive.' }
    $prefs=Read-SourceStartupRecoveryPreferences $storage
    $path=Join-Path $root 'tools\verify_startup_recovery_bundle.ps1'
    Assert-BootstrapPlainPath $path
    $archive=Join-Path $storage 'logs\startup-recovery\bootstrap-preserved'
    New-BootstrapPrivateDirectory $archive
    Initialize-BundleNative $archive
    $raw=$null;$valid=$false
    if(Test-Path -LiteralPath $path) {
        $verifierLease=[Angerona.StartupBundleFile]::new($path,$false,$false)
        $raw=$verifierLease.Read(2097152)
        try {$valid=(Get-BootstrapHash (Get-BootstrapCanonical $raw)) -ceq $verifierSha} catch {$valid=$false}
    }
    if(!$valid) {
        if(!$prefs.Enabled -or !$prefs.Github) { throw 'Pinned recovery verifier is missing or changed; automatic GitHub recovery is disabled in Settings.' }
        $bootstrapMutation=Enter-BundleMutationLocks $root
        # No latest-branch code executes. Download only this exact pinned blob,
        # validate all bytes, and preserve any existing edits before replacement.
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $request=[Net.HttpWebRequest]::Create('https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/blobs/'+$verifierBlob)
        $request.Proxy=$null;$request.UserAgent='Angerona-Pinned-Recovery';$request.Timeout=15000;$request.ReadWriteTimeout=15000
        $request.AllowAutoRedirect=$false
        $response=$request.GetResponse()
        try {
            $body=$response.GetResponseStream();$memory=[IO.MemoryStream]::new();$buffer=New-Object byte[] 8192
            $clock=[Diagnostics.Stopwatch]::StartNew()
            try {
                while(($count=$body.Read($buffer,0,$buffer.Length)) -gt 0) {
                    if($memory.Length+$count -gt 4MB -or $clock.Elapsed.TotalSeconds -gt 30) {throw 'Pinned recovery download exceeded its bound.'}
                    $memory.Write($buffer,0,$count)
                }
                $record=[Text.UTF8Encoding]::new($false,$true).GetString($memory.ToArray())|ConvertFrom-Json
            } finally {$memory.Dispose();$body.Dispose()}
        } finally {$response.Dispose()}
        if($record.encoding -cne 'base64' -or $record.sha -cne $verifierBlob -or $record.size -gt 2MB) { throw 'Pinned recovery response is invalid.' }
        $candidate=[Convert]::FromBase64String($record.content)
        if($candidate.Length -ne $record.size -or (Get-BootstrapBlob $candidate) -cne $verifierBlob -or
            (Get-BootstrapHash $candidate) -cne $verifierSha) { throw 'Pinned recovery verifier bytes do not match the published pins.' }
        $count=0;$total=0L
        foreach($file in [IO.Directory]::EnumerateFiles($archive)) {
            Assert-BootstrapPrivate $file;$count++;$total+=(Get-Item -LiteralPath $file).Length
            if($count -ge 16 -or $total -gt 32MB) {throw 'Preserved bootstrap edits reached their limit; review them before recovery.'}
        }
        if($null -ne $raw -and $total+$raw.Length -gt 32MB) {throw 'Preserved bootstrap edits would exceed their 32 MiB limit.'}
        foreach($base in @($archive,$root)) {
            if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($base))).AvailableFreeSpace -lt (2GB+4MB)) {throw 'Recovery preserves a 2 GiB free-space reserve.'}
        }
        if($verifierLease) {$verifierLease.Dispose();$verifierLease=$null}
        # Recheck the edited generation before publication; never overwrite a
        # concurrent new edit or remove a path outside this one fixed leaf.
        if(Test-Path -LiteralPath $path) {
            Assert-BootstrapPlainPath $path
            $check=[Angerona.StartupBundleFile]::new($path,$false,$true)
            try {
                if($null -eq $raw -or (Get-BootstrapHash ($check.Read(2097152))) -cne (Get-BootstrapHash $raw)) {throw 'Recovery verifier changed during review.'}
                $backup=Join-Path $archive (([Guid]::NewGuid().ToString('N'))+'.verifier.edited')
                $output=[Angerona.StartupBundleFile]::new($backup,$true,$false)
                try {$output.Write($raw)} finally {$output.Dispose()}
                Assert-BootstrapPrivate $backup
                $check.Delete()
            } finally {$check.Dispose()}
        } elseif($null -ne $raw) {
            throw 'The recovery verifier disappeared during review; edited bytes were not overwritten.'
        }
        $output=[Angerona.StartupBundleFile]::new($path,$true,$false)
        try {$output.Write($candidate)} finally {$output.Dispose()}
        $verifierLease=[Angerona.StartupBundleFile]::new($path,$false,$false)
        if((Get-BootstrapHash (Get-BootstrapCanonical ($verifierLease.Read(2097152)))) -cne $verifierSha) {throw 'Recovery verifier publication did not verify.'}
        Write-Host ('[startup] Restored the exact pinned recovery verifier. Preserved edits: '+$archive)
        $env:ANGERONA_BOOTSTRAP_RESTORED='1'
    }
    Close-BundleMutationLocks $bootstrapMutation;$bootstrapMutation=@()
    $arguments=@('-NoProfile','-NonInteractive','-File',$path,'-Root',$root,'-ManifestSha256',$manifestSha,
        '-ManifestBlobSha1',$manifestBlob,'-ExpectedVerifierSha256',$verifierSha,'-RunSupervisor')
    if(!$prefs.Enabled) {$arguments+='-CheckOnly'}
    if(!$prefs.Github) {$arguments+='-Offline'}
    if($env:ANGERONA_SETUP_ONLY -eq '1') {$arguments+='-SetupOnly'}
    & $fixedPS @arguments
    $code=[int]$LASTEXITCODE
    if($code -notin @(0,10,1223) -and $env:ANGERONA_SETUP_ONLY -ne '1') {
        exit (Show-BootstrapRecovery 'Recovery bundle or supervisor checks were held. Review the private startup-recovery diagnostics for the failing phase and preserved files.')
    }
    exit $code
} catch {
    if($env:ANGERONA_SETUP_ONLY -eq '1') {Write-Host ('[startup] '+$_.Exception.Message);exit 1}
    exit (Show-BootstrapRecovery $_.Exception.Message)
} finally {
    if($verifierLease) {$verifierLease.Dispose()}
    Close-BundleMutationLocks $bootstrapMutation
}
