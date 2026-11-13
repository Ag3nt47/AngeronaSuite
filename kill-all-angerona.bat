@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="
REM Emergency source stop only. This editable checkout is not installed authority.
REM Never elevate an interpreter, batch file or mutable ownership script.
set "__APPDIR__="
set "ANGERONA_STOP_SYSTEM=%__APPDIR__%"
if not exist "%ANGERONA_STOP_SYSTEM%cmd.exe" exit /b 1
for %%I in ("%ANGERONA_STOP_SYSTEM%..") do set "ANGERONA_STOP_WINDOWS=%%~fI"
set "SystemRoot=%ANGERONA_STOP_WINDOWS%"
set "WINDIR=%ANGERONA_STOP_WINDOWS%"
set "ComSpec=%ANGERONA_STOP_SYSTEM%cmd.exe"
set "PATH=%ANGERONA_STOP_SYSTEM%;%ANGERONA_STOP_WINDOWS%;%ANGERONA_STOP_SYSTEM%WindowsPowerShell\v1.0"
set "PSModulePath=%ANGERONA_STOP_SYSTEM%WindowsPowerShell\v1.0\Modules"
set "COR_ENABLE_PROFILING="
set "COR_PROFILER="
set "COR_PROFILER_PATH="
set "COR_PROFILER_PATH_32="
set "COR_PROFILER_PATH_64="
set "CORECLR_ENABLE_PROFILING="
set "CORECLR_PROFILER="
set "CORECLR_PROFILER_PATH="
set "CORECLR_PROFILER_PATH_32="
set "CORECLR_PROFILER_PATH_64="
set "APPDOMAIN_MANAGER_ASM="
set "APPDOMAIN_MANAGER_TYPE="
set "COMPLUS_Version="
set "COMPLUS_InstallRoot="
set "COMPLUS_ApplicationMigrationRuntimeActivationConfigPath="
set "DOTNET_STARTUP_HOOKS="
set "DOTNET_ADDITIONAL_DEPS="
set "DOTNET_SHARED_STORE="
set "ANGERONA_STOP_BATCH=%~f0"
set "ANGERONA_STOP_ROOT=%~dp0"
"%ANGERONA_STOP_SYSTEM%WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$s=[IO.File]::ReadAllText($env:ANGERONA_STOP_BATCH);$p=$s -split '(?m)^:__ANGERONA_SOURCE_STOP__\r?$',2;if($p.Count -ne 2){exit 1};& ([scriptblock]::Create($p[1]))"
exit /b %errorlevel%
:__ANGERONA_SOURCE_STOP__
$ErrorActionPreference = 'Stop'

function Stop-ExactSourceProcess($SnapshotProcess, [string]$Root, [object[]]$Snapshot) {
    if (!(Test-AngeronaProcessOwnership -Process $SnapshotProcess -Root $Root -ProcessSnapshot $Snapshot)) {
        return $false
    }
    $process = $null
    try {
        $process = [Diagnostics.Process]::GetProcessById([int]$SnapshotProcess.ProcessId)
        # Cache the OS handle before inspecting or terminating this generation.
        # Process.Kill then uses this retained handle, never a bare Stop-Process PID.
        $null = $process.Handle
        if ($process.HasExited) { return $true }
        $birth = $process.StartTime.ToUniversalTime().Ticks
        $expected = ([datetime]$SnapshotProcess.CreationDate).ToUniversalTime().Ticks
        $image = $process.MainModule.FileName
        if (($birth-($birth%10)) -ne ($expected-($expected%10)) -or
                ![string]::Equals($image,[string]$SnapshotProcess.ExecutablePath,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Process generation changed after ownership discovery; no termination was admitted.'
        }
        if (!$process.HasExited) { $process.Kill() }
        if (!$process.WaitForExit(10000)) { throw 'Owned process retirement was not confirmed.' }
        return $true
    } finally { if ($null -ne $process) { $process.Dispose() } }
}

try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Source shutdown refuses an Administrator token. Run it in a normal user session, or use STOP in the verified installed console.'
    }
    $root = [IO.Path]::GetFullPath($env:ANGERONA_STOP_ROOT).TrimEnd('\')
    $python = [IO.Path]::Combine($root,'venv\Scripts\python.exe')
    $ownerScript = [IO.Path]::Combine($root,'tools\angerona_process_owner.ps1')
    if (![IO.File]::Exists($python) -or ![IO.File]::Exists($ownerScript)) {
        throw 'Source shutdown dependencies are missing. Use Angerona STOP or tray Quit; no executable fallback or elevation was attempted.'
    }
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    if ([string]::IsNullOrWhiteSpace($local)) { throw 'Windows could not establish the source data KnownFolder; use normal STOP.' }
    $system = [Environment]::SystemDirectory
    $windows = [IO.Directory]::GetParent($system).FullName
    $safe = @{
        SystemRoot=$windows; WINDIR=$windows; ComSpec=[IO.Path]::Combine($system,'cmd.exe')
        PATH=($system+';'+$windows+';'+[IO.Path]::Combine($system,'WindowsPowerShell\v1.0'))
        PSModulePath=[IO.Path]::Combine($system,'WindowsPowerShell\v1.0\Modules')
        USERPROFILE=[Environment]::GetFolderPath('UserProfile')
        LOCALAPPDATA=$local; APPDATA=[Environment]::GetFolderPath('ApplicationData')
        TEMP=[IO.Path]::Combine($local,'Temp'); TMP=[IO.Path]::Combine($local,'Temp')
        ANGERONA_ROOT=$root; ANGERONA_DATA=[IO.Path]::Combine($local,'Angerona\SourceData')
        ANGERONA_STORAGE_AUTOMIGRATE='0'
    }
    foreach ($name in @([Environment]::GetEnvironmentVariables().Keys)) {
        [Environment]::SetEnvironmentVariable([string]$name,$null,'Process')
    }
    foreach ($name in $safe.Keys) {
        [Environment]::SetEnvironmentVariable([string]$name,[string]$safe[$name],'Process')
    }
    $stopCode = @'
import os, sys
sys.path.insert(0, os.path.join(os.environ['ANGERONA_ROOT'], 'src'))
from angerona.resilience import shutdown_token as stop
admin = stop._admin_authority()
if admin is not None:
    if not admin.stop_active():
        raise RuntimeError('Protected STOP requires the verified installed console; source shutdown will not request UAC.')
else:
    stop.request_operator_stop('manual source shutdown helper')
if not stop.is_standdown_requested():
    raise RuntimeError('Authenticated STOP could not be verified; no processes were terminated.')
'@
    & $python -I -B -c $stopCode
    if ($LASTEXITCODE -ne 0) {
        throw 'Authenticated STOP was held. Use STOP/tray Quit, or the verified installed console for protected components.'
    }
    # Only after medium-integrity admission and durable STOP may mutable source
    # ownership code be loaded. There is no elevated dot-source path.
    . $ownerScript
    $snapshot = @(Get-CimInstance Win32_Process)
    $held = 0; $retired = 0
    foreach ($candidate in ($snapshot | Where-Object {
            $_.Name -in @('python.exe','pythonw.exe')
        } | Sort-Object CreationDate -Descending)) {
        try {
            if (Stop-ExactSourceProcess $candidate $root $snapshot) { $retired++ }
        } catch {
            $held++
            [Console]::Error.WriteLine('Owned process retirement held: '+$_.Exception.Message)
        }
    }
    if ($held -ne 0) { throw 'Some exact process generations remain unverified; no privilege escalation was attempted.' }
    [Console]::WriteLine('Authenticated STOP recorded. Confirmed source process retirements: '+$retired+'.')
    [Console]::WriteLine('Installed/elevated components require their supported STOP. Use normal dashboard STOP for managed AI cleanup; shared Ollama processes were preserved.')
    exit 0
} catch {
    [Console]::Error.WriteLine('[Angerona shutdown held] '+$_.Exception.Message)
    exit 1
}
