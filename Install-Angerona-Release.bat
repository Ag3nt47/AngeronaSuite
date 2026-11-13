@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="
REM Clear the inherited shadow before cmd.exe resolves its dynamic directory.
set "__APPDIR__="
REM The editable batch file is this bootstrap's trust anchor. It cannot resist
REM an administrator or a writer of this file. Never inherit executable paths.
set "ANGERONA_RELEASE_SYSTEM=%__APPDIR__%"
if not exist "%ANGERONA_RELEASE_SYSTEM%cmd.exe" exit /b 1
for %%I in ("%ANGERONA_RELEASE_SYSTEM%..") do set "ANGERONA_RELEASE_WINDOWS=%%~fI"
set "SystemRoot=%ANGERONA_RELEASE_WINDOWS%"
set "WINDIR=%ANGERONA_RELEASE_WINDOWS%"
set "ComSpec=%ANGERONA_RELEASE_SYSTEM%cmd.exe"
set "PATH=%ANGERONA_RELEASE_SYSTEM%;%ANGERONA_RELEASE_WINDOWS%;%ANGERONA_RELEASE_SYSTEM%WindowsPowerShell\v1.0"
set "PSModulePath=%ANGERONA_RELEASE_SYSTEM%WindowsPowerShell\v1.0\Modules"
set "PATHEXT=.COM;.EXE;.BAT;.CMD"
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
set "COMPLUS_Version="
set "COMPLUS_InstallRoot="
set "COMPLUS_ApplicationMigrationRuntimeActivationConfigPath="
set "APPDOMAIN_MANAGER_ASM="
set "APPDOMAIN_MANAGER_TYPE="
set "DOTNET_STARTUP_HOOKS="
set "DOTNET_ADDITIONAL_DEPS="
set "DOTNET_SHARED_STORE="
set "ANGERONA_RELEASE_BATCH=%~f0"
set "ANGERONA_RELEASE_ZIP=%~f1"
if "%~1"=="" (
    echo [ERROR] Pass the original downloaded Angerona win64 ZIP as the first argument.
    echo [ERROR] Its adjacent .sha256 file is also required.
    exit /b 1
)
if not "%~2"=="" exit /b 1
"%ANGERONA_RELEASE_SYSTEM%WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$s=[IO.File]::ReadAllText($env:ANGERONA_RELEASE_BATCH);$p=$s -split '(?m)^:__ANGERONA_RELEASE_BOOTSTRAP__\r?$',2;if($p.Count -ne 2){exit 1};& ([scriptblock]::Create($p[1]))"
exit /b %errorlevel%
:__ANGERONA_RELEASE_BOOTSTRAP__
$ErrorActionPreference = 'Stop'

# This script is an editable trust anchor, not a hardware/security-service root.
# Custody rejects unrelated writers and environment-selected helpers. A local
# administrator or a writer of this bootstrap can replace the bootstrap itself.
function Assert-ReleaseAuthorityAcl($Acl, [string]$Label, [bool]$Ancestor) {
    $approved = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $approved) { throw "Release authority has an untrusted owner: $Label" }
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        $Acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $descriptor.DiscretionaryAcl) {
        throw "Release authority has an unrestricted DACL: $Label"
    }
    $mask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    # A drive's create-subdirectory permission cannot replace an existing,
    # independently protected child. Leaf authority may permit no such writer.
    if (!$Ancestor) { $mask = $mask -bor [Security.AccessControl.FileSystemRights]::AppendData }
    foreach ($rule in $Acl.GetAccessRules($true, $true,
            [Security.Principal.SecurityIdentifier])) {
        if (($rule.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ([long]$rule.FileSystemRights -band [long]$mask) -ne 0 -and
                $rule.IdentityReference.Value -notin $approved) {
            throw "Release authority permits an unrelated writer: $Label"
        }
    }
}

function Assert-ReleaseAuthorityPath([string]$Path, [switch]$AllowSystemHardlinks) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.StartsWith('\\')) {
        throw 'Release authority requires a fixed local absolute path.'
    }
    $cursor = $full; $leaf = $true; $count = 0
    while ($cursor) {
        if (++$count -gt 64) { throw 'Release authority ancestry exceeds its bound.' }
        $before = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ((!$leaf -and !$before.PSIsContainer) -or ($leaf -and $before.PSIsContainer) -or
                ![string]::Equals($before.FullName, $cursor, [StringComparison]::OrdinalIgnoreCase) -or
                ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release authority is redirected or has an invalid type: $cursor"
        }
        if ($before.PSObject.Properties.Name -contains 'LinkType' -and
                ![string]::IsNullOrEmpty([string]$before.LinkType) -and
                !($leaf -and $AllowSystemHardlinks -and $before.LinkType -eq 'HardLink')) {
            throw "Release authority is linked: $cursor"
        }
        $length = if ($before.PSIsContainer) { -1L } else { [long]$before.Length }
        $write = $before.LastWriteTimeUtc.Ticks; $attributes = $before.Attributes
        $acl = Get-Acl -LiteralPath $cursor -ErrorAction Stop
        Assert-ReleaseAuthorityAcl $acl $cursor (!$leaf)
        $after = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        $afterLength = if ($after.PSIsContainer) { -1L } else { [long]$after.Length }
        if (![string]::Equals($after.FullName, $cursor, [StringComparison]::OrdinalIgnoreCase) -or
                $after.Attributes -ne $attributes -or $after.LastWriteTimeUtc.Ticks -ne $write -or
                $afterLength -ne $length -or [bool]$after.PSIsContainer -ne [bool]$before.PSIsContainer) {
            throw 'Release authority changed during custody inspection.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor); $leaf = $false
    }
}

function Get-ReleaseSystemPowerShell {
    $hostPath = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    Assert-ReleaseAuthorityPath $hostPath -AllowSystemHardlinks
    return $hostPath
}

function Initialize-ReleaseChildEnvironment {
    if (![Environment]::Is64BitOperatingSystem -or ![Environment]::Is64BitProcess) {
        throw 'Angerona win64 upgrades require the native 64-bit Windows host.'
    }
    $system = [Environment]::SystemDirectory
    $windows = [IO.Directory]::GetParent($system).FullName
    $safe = @{
        SystemRoot=$windows; WINDIR=$windows
        SystemDrive=[IO.Path]::GetPathRoot($windows).TrimEnd('\')
        ComSpec=[IO.Path]::Combine($system,'cmd.exe'); PATHEXT='.COM;.EXE;.BAT;.CMD'
        PATH=($system+';'+$windows+';'+[IO.Path]::Combine($system,'Wbem')+';'+[IO.Path]::Combine($system,'WindowsPowerShell\v1.0'))
        PSModulePath=[IO.Path]::Combine($system,'WindowsPowerShell\v1.0\Modules')
    }
    foreach ($pair in @(@('ProgramFiles','ProgramFiles'), @('ProgramFiles(x86)','ProgramFilesX86'),
            @('ProgramData','CommonApplicationData'), @('USERPROFILE','UserProfile'),
            @('LOCALAPPDATA','LocalApplicationData'), @('APPDATA','ApplicationData'))) {
        $value = [Environment]::GetFolderPath([Environment+SpecialFolder]$pair[1])
        if ([string]::IsNullOrWhiteSpace($value) -or $value -notmatch '^[A-Za-z]:\\') {
            throw ('Windows could not establish a trusted '+$pair[0]+' directory.')
        }
        $safe[$pair[0]] = $value
    }
    $safe.ProgramW6432 = $safe.ProgramFiles
    $safe.TEMP = [IO.Path]::Combine($safe.LOCALAPPDATA,'Temp'); $safe.TMP = $safe.TEMP
    # Exact allowlist: inherited module/profiler/proxy/gh configuration and
    # credentials cannot select code or a verification endpoint in child tools.
    foreach ($name in @([Environment]::GetEnvironmentVariables().Keys)) {
        [Environment]::SetEnvironmentVariable([string]$name, $null, 'Process')
    }
    foreach ($name in $safe.Keys) {
        [Environment]::SetEnvironmentVariable([string]$name, [string]$safe[$name], 'Process')
    }
}

function ConvertTo-ReleaseProcessArgument([string]$Value) {
    if ($Value.Contains([string][char]0) -or $Value.Contains([string][char]10) -or
            $Value.Contains([string][char]13)) { throw 'Release argument contains a control character.' }
    # Windows CommandLineToArgvW quoting, including embedded quotes and trailing
    # backslashes. Start-Process joins its array argument; pass ONE quoted string.
    $encoded = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $encoded = [regex]::Replace($encoded, '(\\+)$', '$1$1')
    return '"'+$encoded+'"'
}

try {
    $archive = $env:ANGERONA_RELEASE_ZIP
    Initialize-ReleaseChildEnvironment
    $hostPath = Get-ReleaseSystemPowerShell
    $actualHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if (![string]::Equals($actualHost, $hostPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Release bootstrap is not running in the trusted native Windows host.'
    }
    $installer = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Angerona\Install-Angerona-Release.ps1'
    # Establish custody independently, BEFORE executing any selected installer.
    Assert-ReleaseAuthorityPath $installer
    # Protected ACL custody prevents an unelevated replacement between checks.
        & $hostPath -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $installer -CustodyPreflightOnly
        if ($LASTEXITCODE -ne 0) { throw 'Protected installed upgrade custody failed before elevation.' }
        Assert-ReleaseAuthorityPath $installer
        $arguments = @('-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned',
            '-File',$installer,'-ReleaseArchive',$archive)
        $commandLine = ($arguments | ForEach-Object { ConvertTo-ReleaseProcessArgument $_ }) -join ' '
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $child = Start-Process -WindowStyle Hidden -FilePath $hostPath -ArgumentList $commandLine -Verb RunAs -Wait -PassThru
            if ($null -eq $child -or $child.ExitCode -ne 0) { throw 'Elevated protected upgrade failed or was cancelled.' }
        } else {
            & $hostPath @arguments
            if ($LASTEXITCODE -ne 0) { throw 'Protected upgrade did not complete.' }
        }
    exit 0
} catch {
    [Console]::Error.WriteLine('[ERROR] Release bootstrap held: '+$_.Exception.Message)
    [Console]::Error.WriteLine('The portable package is upgrade-only. Public first install requires the signed Angerona MSIX.')
    [Console]::Error.WriteLine('Classic Setup is restricted to a protected legacy migration.')
    [Console]::Error.WriteLine('Enterprise clean install requires a separate governed deployment artifact.')
    exit 1
}
