[CmdletBinding()]
param([string]$RepositoryRoot, [switch]$SetupOnly)

$ErrorActionPreference = 'Stop'

function Assert-SourceStartupHost {
    $system = [Environment]::SystemDirectory
    $expected = Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
    $actual = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if (![string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Source startup requires the fixed Windows PowerShell host.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $expected
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw 'The Windows PowerShell host signature could not be verified.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Mutable source startup requires a normal user session. Use the signed MSIX for Protect coverage.'
    }
}

function Assert-SourceStartupPath([string]$Path) {
    if (![IO.Path]::IsPathRooted($Path)) { throw 'Source startup requires absolute local paths.' }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Source startup refuses a redirected path: $cursor"
            }
        }
        $next = [IO.Path]::GetDirectoryName($cursor)
        if ($next -eq $cursor) { break }
        $cursor = $next
    }
}

function Assert-SourceStartupBoundary([string]$Root) {
    Assert-SourceStartupHost
    Assert-SourceStartupPath $Root
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Root))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'Source startup requires a ready fixed local installation drive.'
    }
    foreach ($name in @('start-angerona.bat', 'pyproject.toml', 'constraints-release.txt',
        'src\angerona\__init__.py', 'src\angerona\startup.py', 'src\angerona\core\startup_recovery.py',
        'tools\Invoke-AngeronaSourceStartup.ps1',
        'tools\source_trust_preflight.py', 'tools\startup_repair_common.ps1',
        'tools\Invoke-AngeronaStartupRepair.ps1', 'Repair-Angerona-Python.ps1')) {
        $path = Join-Path $Root $name
        Assert-SourceStartupPath $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "The source checkout is incomplete: $name"
        }
    }
    Assert-SourceStartupPath (Join-Path $Root 'venv')
    Assert-SourceStartupPath (Join-Path $Root 'venv\Scripts\python.exe')
}

function Test-SourceStorageProof([string]$Directory) {
    $probe = Join-Path $Directory ('startup-check.' + [Guid]::NewGuid().ToString('N'))
    $bytes = [Text.Encoding]::UTF8.GetBytes('Angerona startup storage proof ' + [Guid]::NewGuid().ToString('N'))
    $stream = $null
    try {
        $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Position = 0
        $read = New-Object byte[] $bytes.Length
        if ($stream.Read($read, 0, $read.Length) -ne $bytes.Length -or
            [Convert]::ToBase64String($read) -cne [Convert]::ToBase64String($bytes)) {
            throw 'Startup storage readback did not match the flushed bytes.'
        }
    } finally {
        if ($stream) {
            $stream.Dispose()
            [IO.File]::Delete($probe) # Only the exclusively created proof file.
        }
    }
}

function Initialize-SourceStartupStorage {
    # Never migrate persistent state to a scratch drive, even if that drive has
    # ample room. Audit/evidence capacity is an independent mandatory gate.
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    if (!$local) { throw 'Windows could not resolve Local AppData.' }
    $storage = [IO.Path]::GetFullPath((Join-Path $local 'Angerona\SourceData'))
    Assert-SourceStartupPath $storage
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($storage))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.AvailableFreeSpace -lt 128MB) {
        throw "The canonical source data drive needs at least 128 MB free: $storage. Free space there and retry; temporary storage on another drive cannot replace evidence capacity."
    }
    foreach ($path in @($storage, (Join-Path $storage 'logs'))) {
        Assert-SourceStartupPath $path
        [void][IO.Directory]::CreateDirectory($path)
        Assert-SourceStartupPath $path
    }
    Test-SourceStorageProof $storage
    return $storage
}

function New-SourceStartupTemporary([string]$Root, [string]$Storage) {
    # Caller-selected TEMP/TMP never becomes path authority. Validate its fixed
    # local ancestry/capacity before inspecting it, then select fresh owned
    # scratch rather than forwarding an inherited directory to executable code.
    foreach ($name in @('TEMP', 'TMP')) {
        $candidate = [Environment]::GetEnvironmentVariable($name)
        if ($candidate) {
            try {
                Assert-SourceStartupPath $candidate
                $inheritedDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($candidate))
                if (!$inheritedDrive.IsReady -or $inheritedDrive.DriveType -ne [IO.DriveType]::Fixed -or
                    $inheritedDrive.AvailableFreeSpace -lt 128MB -or
                    !(Test-Path -LiteralPath $candidate -PathType Container)) {
                    throw 'Inherited temporary storage is unavailable.'
                }
            } catch { Write-Verbose "$name is unsuitable; choosing verified owned startup scratch." }
        }
    }
    foreach ($base in @((Join-Path $Storage 'tmp'), (Join-Path $Root '.tmp'))) {
        try {
            Assert-SourceStartupPath $base
            $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($base))
            if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.AvailableFreeSpace -lt 128MB) { continue }
            [void][IO.Directory]::CreateDirectory($base)
            Assert-SourceStartupPath $base
            $scratch = Join-Path $base ('startup-temp.' + [Guid]::NewGuid().ToString('N'))
            New-PrivateRepairDirectory -Path $scratch
            Test-SourceStorageProof $scratch
            return $scratch
        } catch { Write-Verbose 'A startup scratch candidate was unavailable; checking the next owned location.' }
    }
    throw 'No private, nonredirected startup temporary directory has 128 MB free. Free space on the local data or installation drive and retry.'
}

function Invoke-SourceStartupAssistant([string]$Python, [string]$Root,
    [Collections.IDictionary]$Environment, [string]$Scratch) {
    $stdout = Join-Path $Scratch 'launcher-stdout.log'
    $stderr = Join-Path $Scratch 'launcher-stderr.log'
    # Windows PowerShell 5 has no Start-Process -Environment. Replace only this
    # disposable supervisor's environment while creating its child, restoring
    # it immediately afterwards. No registry, user or parent environment changes.
    $saved = [Environment]::GetEnvironmentVariables('Process')
    try {
        foreach ($key in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
            [Environment]::SetEnvironmentVariable($key, $null, 'Process')
        }
        foreach ($key in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable($key, [string]$Environment[$key], 'Process')
        }
        $process = Start-Process -FilePath $Python -ArgumentList @('-m', 'angerona.startup', '--chill') `
            -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr -PassThru
    } finally {
        foreach ($key in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
            [Environment]::SetEnvironmentVariable($key, $null, 'Process')
        }
        foreach ($key in $saved.Keys) {
            [Environment]::SetEnvironmentVariable($key, [string]$saved[$key], 'Process')
        }
    }
    # Never place the assistant/dashboard in a kill-on-close repair job. The
    # helper preserves a live dashboard after monitoring cancellation/timeout.
    $null = $process.Handle
    $process.WaitForExit()
    $process.Refresh()
    $code = $process.ExitCode
    $process.Dispose()
    if ($null -eq $code) { throw 'The startup assistant exit status could not be verified.' }
    if ($code -ne 0) { Write-Host "Startup assistant details: $stderr" }
    return $code
}

function Invoke-SourceStartupPass([string]$Root, [switch]$SetupOnly) {
    Assert-SourceStartupBoundary $Root
    $storage = Initialize-SourceStartupStorage
    $lease = Enter-RepairLease -Root $Root
    try {
        try {
            Assert-NoPendingRepair -Root $Root
        } catch {
            if ($_.Exception.Data['AngeronaRepairPending'] -eq $true) { return 81 }
            throw
        }
        $venv = Join-Path $Root 'venv'
        Assert-NoActiveVenv -VenvPath $venv
        $python = Join-Path $venv 'Scripts\python.exe'
        if (!(Test-Path -LiteralPath $python -PathType Leaf)) { return 81 }
        $scratch = New-SourceStartupTemporary -Root $Root -Storage $storage
        $child = New-RepairChildEnvironment -Scratch $scratch
        [void]$child.Remove('QT_QPA_PLATFORM')
        $child['ANGERONA_DATA'] = $storage
        $child['ANGERONA_DIAG_DIR'] = Join-Path $storage 'diagnostics'
        $child['ANGERONA_STORAGE_AUTOMIGRATE'] = '0'
        $child['ANGERONA_INSTALL_ROOT'] = $Root
        foreach ($name in @('ANGERONA_OLLAMA_MODELS', 'OLLAMA_MODELS')) {
            $value = [Environment]::GetEnvironmentVariable($name)
            if ($null -ne $value) { $child[$name] = $value }
        }
        $savedTemp, $savedTmp = $env:TEMP, $env:TMP
        try {
            $env:TEMP = $scratch; $env:TMP = $scratch
            Initialize-OwnedRepairProcess
        } finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
        $abi = "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' else 81)"
        $code = Invoke-OwnedRepairProcess -FilePath $python -Arguments @('-c', $abi) `
            -WorkingDirectory $Root -Environment $child -TimeoutSeconds 30 -LogPath (Join-Path $scratch 'abi.log')
        if ($code -ne 0) { if ($code -eq 81) { return 81 }; return 1 }
        $pip = @'
import importlib.metadata as m
try:
    raise SystemExit(0 if m.version('pip') == '26.2.1' else 82)
except m.PackageNotFoundError:
    raise SystemExit(82)
'@
        $code = Invoke-OwnedRepairProcess -FilePath $python -Arguments @('-c', $pip) `
            -WorkingDirectory $Root -Environment $child -TimeoutSeconds 30 -LogPath (Join-Path $scratch 'pip.log')
        if ($code -ne 0) { if ($code -eq 82) { return 82 }; return 1 }
        $code = Invoke-OwnedRepairProcess -FilePath $python -Arguments @((Join-Path $Root 'tools\source_trust_preflight.py')) `
            -WorkingDirectory $Root -Environment $child -TimeoutSeconds 30 -LogPath (Join-Path $scratch 'source-trust.log')
        if ($code -ne 0) { return 1 }
        if ($SetupOnly) {
            return Invoke-OwnedRepairProcess -FilePath $python -Arguments @('-m', 'angerona.startup', '--check-only', '--chill') `
                -WorkingDirectory $Root -Environment $child -TimeoutSeconds 45 -LogPath (Join-Path $scratch 'source-setup.log')
        }
        return Invoke-SourceStartupAssistant -Python $python -Root $Root -Environment $child -Scratch $scratch
    } finally { Exit-RepairLease -Lease $lease }
}

function Invoke-SourceStartupRepair([string]$Root, [string]$Category) {
    # A completed helper has exited and its launch lease has been released.
    # Repair independently acquires that same lease, validates authority and
    # refuses a still-live dashboard. This is the only repair call site.
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    & $powershell -NoProfile -NonInteractive -File (Join-Path $Root 'tools\Invoke-AngeronaStartupRepair.ps1') `
        -RepositoryRoot $Root -FailureCategory $Category -Attempt 1
    return $LASTEXITCODE
}

function Invoke-SourceStartupLoop([string]$Root, [switch]$SetupOnly) {
    $attempt = 0 # Parent-owned; inherited flags cannot reset or extend it.
    $categories = @{ 81 = 'Runtime'; 82 = 'Dependencies'; 83 = 'GuiRuntime' }
    while ($true) {
        $code = Invoke-SourceStartupPass -Root $Root -SetupOnly:$SetupOnly
        if ($code -eq 0) { return 0 }
        if (!$categories.ContainsKey([int]$code) -or $attempt -ge 1) {
            Write-Host 'Startup checks did not pass. No further repair or dashboard launch will be attempted.'
            return 1
        }
        $attempt = 1
        Write-Host "Attempting one verified $($categories[[int]$code]) startup repair; settings and evidence are preserved."
        $repairCode = Invoke-SourceStartupRepair -Root $Root -Category $categories[[int]$code]
        if ($repairCode -ne 0) { return 1 }
        Write-Host 'Repair verification passed. Rechecking the complete source startup boundary...'
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Assert-SourceStartupHost
        $fixedRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
        if ($RepositoryRoot -and ![string]::Equals([IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\'), $fixedRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The source startup repository does not match this fixed launcher.'
        }
        Assert-SourceStartupBoundary $fixedRoot
        . (Join-Path $fixedRoot 'tools\startup_repair_common.ps1')
        exit (Invoke-SourceStartupLoop -Root $fixedRoot -SetupOnly:$SetupOnly)
    } catch {
        Write-Host "[!] Angerona Safe Startup: $($_.Exception.Message)"
        exit 1
    }
}
