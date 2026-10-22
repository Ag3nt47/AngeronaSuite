[CmdletBinding()]
param([switch]$Automatic)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$venv = [IO.Path]::GetFullPath((Join-Path $root 'venv'))
$common = Join-Path $root 'tools\startup_repair_common.ps1'
# Validate ancestors before importing even the fixed checkout library.
$cursor = $common
while ($cursor) {
    if ((Test-Path -LiteralPath $cursor) -and
        (((Get-Item -LiteralPath $cursor -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Redirected repair source refused.' }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
}
. $common

function Assert-RepairBoundary {
    Assert-PlainRepairPath $root
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Source runtime repair requires a normal, unelevated user session.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'The Angerona checkout is not on a ready fixed drive; repair refused.'
    }
    if ([IO.Path]::GetFullPath((Split-Path -Parent $venv)) -ne $root) {
        throw 'The virtual-environment target escaped the Angerona checkout.'
    }
    foreach ($name in @('start-angerona.bat', 'pyproject.toml',
            'requirements-bootstrap-pip.txt', 'requirements-release-hashed.txt',
            'src\angerona\__init__.py', 'src\angerona\startup.py',
            'src\srt\__init__.py', 'tools\build_srt_compat_wheel.py')) {
        $path = Join-Path $root $name
        Assert-PlainRepairPath $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required repair source is missing: $name"
        }
    }
    Assert-PlainRepairPath $venv
    if ((Test-Path -LiteralPath $venv) -and
        !(Test-Path -LiteralPath $venv -PathType Container)) {
        throw 'The repo-root venv is not a normal directory; repair refused.'
    }
}

function Invoke-RepairCommand {
    param([string]$Executable, [string[]]$Arguments, [string]$Label,
        [int]$TimeoutSeconds = 180, [switch]$AllowFailure)
    $remaining = [Math]::Floor(900 - $script:RepairClock.Elapsed.TotalSeconds)
    if ($remaining -lt 1) { throw 'The 900-second runtime repair transaction deadline expired.' }
    $limit = [int][Math]::Min($TimeoutSeconds, $remaining)
    $script:RepairCommandNumber++
    $log = Join-Path $script:RepairScratch ("command-{0:D3}.log" -f $script:RepairCommandNumber)
    Write-Host "[repair] $Label (command limit ${limit}s; transaction limit 900s)"
    $code = Invoke-OwnedRepairProcess -FilePath $Executable -Arguments $Arguments `
        -WorkingDirectory $root -Environment $script:RepairEnvironment `
        -TimeoutSeconds $limit -LogPath $log
    if ($code -ne 0 -and !$AllowFailure) { throw "$Label failed (exit $code). Output: $log" }
    return $code
}

function Test-ReviewedPython([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    Assert-PlainRepairPath $Path -AllowHardLinks
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch '(?:CN|O)=Python Software Foundation(?:,|$)') {
        return $false
    }
    $code = Invoke-RepairCommand $Path @('-I', '-c',
        "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' and sys.prefix == sys.base_prefix else 1)") `
        'Verify independently installed PSF CPython 3.12 x64' 30 -AllowFailure
    return $code -eq 0
}

function Find-ReviewedPython {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    foreach ($candidate in @((Join-Path $programFiles 'Python312\python.exe'),
            (Join-Path $localAppData 'Python\pythoncore-3.12-64\python.exe'),
            (Join-Path $localAppData 'Programs\Python\Python312\python.exe'))) {
        if (Test-ReviewedPython $candidate) { return $candidate }
    }
    return $null
}

function Find-TrustedWinget {
    $package = Get-AppxPackage Microsoft.DesktopAppInstaller |
        Sort-Object Version -Descending | Select-Object -First 1
    if (!$package) { return $null }
    $candidate = Join-Path $package.InstallLocation 'winget.exe'
    if (!(Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
    Assert-PlainRepairPath $candidate -AllowHardLinks
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch '(?:CN|O)=Microsoft Corporation(?:,|$)') {
        return $null
    }
    return $candidate
}

function Get-RepairAllowedHashes([string]$RequirementsPath) {
    Assert-PlainRepairPath $RequirementsPath
    $hashes = @{}
    foreach ($line in [IO.File]::ReadAllLines($RequirementsPath)) {
        if ($line -match '^\s*--hash=sha256:([0-9a-f]{64})(?:\s*\\)?\s*$') {
            $hashes[$Matches[1]] = $true
        }
    }
    if (!$hashes.Count) { throw 'The reviewed artifact hash lock is empty or invalid.' }
    return $hashes
}

function Assert-RepairArtifactHashes([string]$Directory, [hashtable]$AllowedHashes) {
    Assert-PlainRepairPath $Directory
    foreach ($artifact in Get-ChildItem -LiteralPath $Directory -File -Force) {
        Assert-PlainRepairPath $artifact.FullName
        if ($artifact.Extension -ne '.whl' -or
            !$AllowedHashes.ContainsKey((Get-RepairFileSha256 $artifact.FullName))) {
            throw "Unreviewed artifact refused: $($artifact.Name)"
        }
    }
}

function Get-LockedRepairArtifacts {
    param([string]$Python, [string]$RequirementsPath, [string]$Destination)
    [void][IO.Directory]::CreateDirectory($Destination)
    $allowed = Get-RepairAllowedHashes $RequirementsPath
    $cache = Join-Path $root '.tmp\repair-wheels\cache'
    if (Test-Path -LiteralPath $cache -PathType Container) {
        Assert-PlainRepairPath $cache
        foreach ($wheel in Get-ChildItem -LiteralPath $cache -Filter '*.whl' -File) {
            Assert-PlainRepairPath $wheel.FullName
            $digest = Get-RepairFileSha256 $wheel.FullName
            if ($allowed.ContainsKey($digest)) {
                Copy-Item -LiteralPath $wheel.FullName -Destination (Join-Path $Destination $wheel.Name)
            }
        }
    }
    $prefix = @('-I', '-m', 'pip', 'download', '--isolated', '--only-binary', ':all:',
        '--require-hashes', '--no-deps', '--dest', $Destination)
    $offline = $prefix + @('--no-index', '--find-links', $Destination, '-r', $RequirementsPath)
    $code = Invoke-RepairCommand $Python $offline 'Resolve reviewed artifacts from verified local cache' 120 -AllowFailure
    if ($code -ne 0) {
        # No index/URL/hash override is accepted from caller or log text.
        $network = $prefix + @('--index-url', 'https://pypi.org/simple', '--timeout', '15',
            '--retries', '1', '--find-links', $Destination, '-r', $RequirementsPath)
        [void](Invoke-RepairCommand $Python $network 'Obtain missing exact hash-locked artifacts' 240)
    }
    Assert-RepairArtifactHashes $Destination $allowed
}

function Install-LockedRepairArtifacts {
    param([string]$Python, [string]$RequirementsPath, [string]$Wheelhouse)
    # Fixed pip guarantees: --require-hashes --no-deps; every install is offline.
    [void](Invoke-RepairCommand $Python @('-I', '-m', 'pip', 'install', '--isolated',
        '--only-binary', ':all:', '--require-hashes', '--no-deps', '--no-index',
        '--find-links', $Wheelhouse, '--force-reinstall', '-r', $RequirementsPath) `
        'Install exact reviewed wheels offline' 180)
}

function Install-LocalRepairPackages([string]$Python, [string]$SpeechWheel) {
    [void](Invoke-RepairCommand $Python @('-I', '-m', 'pip', 'install', '--isolated',
        '--no-index', '--no-build-isolation', '--no-deps', '-e', $root) `
        'Install reviewed local editable Angerona source offline' 120)
    [void](Invoke-RepairCommand $Python @('-I', '-m', 'pip', 'install', '--isolated',
        '--no-index', '--only-binary', ':all:', '--no-deps', '--force-reinstall', $SpeechWheel) `
        'Install reviewed local speech compatibility wheel offline' 60)
}

function Test-RepairedRuntime([string]$VenvPath, [string]$OldStagingPath = '') {
    $python = Join-Path $VenvPath 'Scripts\python.exe'
    $probe = @'
import importlib.metadata as m, pathlib, re, sys, sysconfig
assert sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64'
assert m.version('pip') == '26.2.1'
assert pathlib.Path(sys.prefix).absolute() == pathlib.Path(sys.argv[1]).absolute()
for line in pathlib.Path(sys.argv[2]).read_text(encoding='utf-8').splitlines():
    pin = re.match(r'^([A-Za-z0-9_.-]+)==([^\s\\]+)', line)
    if pin:
        assert m.version(pin[1]) == pin[2], pin[1] + ' version mismatch'
import angerona, psutil, yaml, dotenv, cryptography, requests, srt, tkinter
tk = tkinter.Tk(); tk.withdraw(); tk.update_idletasks(); tk.destroy()
from PySide6.QtWidgets import QApplication
app = QApplication([]); app.processEvents(); app.quit()
print('Reviewed ABI, exact distributions, Tcl/Tk and offscreen Qt verified')
'@
    [void](Invoke-RepairCommand $python @('-I', '-c', $probe, $VenvPath,
        (Join-Path $root 'requirements-release-hashed.txt')) 'Independently verify runtime, Tk and Qt' 45)
    [void](Invoke-RepairCommand $python @('-I', '-m', 'pip', 'check') 'Independently verify dependency consistency' 30)
    [void](Invoke-RepairCommand (Join-Path $VenvPath 'Scripts\pip.exe') @('--version') `
        'Verify executable entrypoint' 30)
    if ($OldStagingPath) {
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $VenvPath 'Scripts') -File) {
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            if ([Text.Encoding]::UTF8.GetString($bytes).Contains($OldStagingPath) -or
                [Text.Encoding]::Unicode.GetString($bytes).Contains($OldStagingPath)) {
                throw "An entrypoint still references staging: $($file.Name)"
            }
        }
        $activate = [IO.File]::ReadAllText((Join-Path $VenvPath 'Scripts\activate.bat'))
        if (!$activate.Contains($VenvPath)) { throw 'Final-path activation scaffold was not recreated.' }
    }
}

function New-VerifiedRepairCandidate($Transaction) {
    [void](Invoke-RepairCommand $Transaction.Python @('-I', '-m', 'venv', '--copies', $Transaction.Stage) `
        'Create candidate without moving the current venv' 120)
    $python = Join-Path $Transaction.Stage 'Scripts\python.exe'
    # Exact reviewed bootstrap pip BEFORE dependency download or installation.
    $bootstrap = (Join-Path $root 'requirements-bootstrap-pip.txt')
    $dependencies = (Join-Path $root 'requirements-release-hashed.txt')
    Get-LockedRepairArtifacts $python $bootstrap $Transaction.BootstrapWheels
    Install-LockedRepairArtifacts $python $bootstrap $Transaction.BootstrapWheels
    Get-LockedRepairArtifacts $python $dependencies $Transaction.DependencyWheels
    Install-LockedRepairArtifacts $python $dependencies $Transaction.DependencyWheels
    [void](Invoke-RepairCommand $python @('-I', (Join-Path $root 'tools\build_srt_compat_wheel.py'),
        '--out', $Transaction.LocalWheels) 'Build reviewed deterministic local speech wheel' 30)
    $Transaction.SpeechHash = Get-RepairFileSha256 $Transaction.SpeechWheel
    Install-LocalRepairPackages $python $Transaction.SpeechWheel
    Test-RepairedRuntime $Transaction.Stage
}

function Repair-PromotedEnvironment($Transaction) {
    # A venv rename leaves absolute activation/launcher paths behind. Recreate
    # scaffold and every package entrypoint from the same verified local wheels.
    [void](Invoke-RepairCommand $Transaction.Python @('-I', '-m', 'venv', '--copies',
        '--without-pip', $venv) 'Recreate venv scaffold at its final location' 120)
    $python = Join-Path $venv 'Scripts\python.exe'
    Install-LockedRepairArtifacts $python (Join-Path $root 'requirements-bootstrap-pip.txt') $Transaction.BootstrapWheels
    Install-LockedRepairArtifacts $python (Join-Path $root 'requirements-release-hashed.txt') $Transaction.DependencyWheels
    if ((Get-RepairFileSha256 $Transaction.SpeechWheel) -ne $Transaction.SpeechHash) {
        throw 'The reviewed local speech wheel changed during repair.'
    }
    Install-LocalRepairPackages $python $Transaction.SpeechWheel
}

function Remove-OwnedRepairDirectory([string]$Path, [string]$ExpectedPath) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if ($absolute -ne [IO.Path]::GetFullPath($ExpectedPath) -or
        !$absolute.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside this exact repair transaction.'
    }
    Assert-PlainRepairPath $absolute
    if (!(Test-Path -LiteralPath $absolute)) { return }
    foreach ($item in Get-ChildItem -LiteralPath $absolute -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Redirected content in owned repair directory; cleanup refused.'
        }
    }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}

function Get-RepairDirectoryIdentity([string]$Path) {
    Assert-PlainRepairPath $Path
    if (!(Test-Path -LiteralPath $Path)) { return '' }
    Initialize-OwnedRepairProcess
    return [Angerona.StartupRepairProcess]::DirectoryIdentity($Path)
}

function Write-DurableRepairJson([string]$Path, $Value, [switch]$Replace) {
    Assert-PlainRepairPath $Path
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Compress -Depth 4))
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ($Replace -and (Test-Path -LiteralPath $Path)) {
        [IO.File]::Replace($temporary, $Path, [NullString]::Value)
    } else { [IO.File]::Move($temporary, $Path) }
}

function Set-RepairIntentPhase([string]$Pending, [string]$Id,
    [ValidateSet('Prepared','BeforeBackup','BeforePromotion','Refreshing','Verified','RollingBack')][string]$Phase) {
    Assert-PrivateRepairCustody $Pending
    Write-DurableRepairJson (Join-Path $Pending 'phase.json') `
        ([ordered]@{Schema=1;Id=$Id;Phase=$Phase}) -Replace
}

function New-PendingRepairIntent($Transaction) {
    $pending = Get-StartupRepairPendingPath $root
    if (Test-Path -LiteralPath $pending) { throw 'An unresolved runtime repair intent already exists.' }
    $hadOriginal = Test-Path -LiteralPath $venv -PathType Container
    $intent = [ordered]@{
        Schema=1; Id=$Transaction.Id; Root=$root; Venv=$venv
        Scratch=$Transaction.Scratch; Stage=$Transaction.Stage; Backup=$Transaction.Backup
        OriginalId=(Get-RepairDirectoryIdentity $venv)
        CandidateId=(Get-RepairDirectoryIdentity $Transaction.Stage); HadOriginal=[bool]$hadOriginal
    }
    New-PrivateRepairDirectory $pending
    $Transaction.PendingOwned = $true
    Write-DurableRepairJson (Join-Path $Transaction.Scratch 'intent.witness.json') $intent
    Write-DurableRepairJson (Join-Path $Transaction.Stage '.angerona-startup-repair.json') $intent
    Write-DurableRepairJson (Join-Path $pending 'intent.json') $intent
    Set-RepairIntentPhase $pending $Transaction.Id 'Prepared'
    [void](Read-PendingRepairIntent $root)
    $Transaction.HasIntent = $true
}

function Restore-InterruptedRepair {
    $pending = Get-StartupRepairPendingPath $root
    if (!(Test-Path -LiteralPath $pending)) { Assert-NoPendingRepair $root; return }
    $record = Read-PendingRepairIntent $root
    $intent = $record.Intent
    Assert-NoActiveVenv -VenvPath $venv
    $current = Get-RepairDirectoryIdentity $venv
    $stage = Get-RepairDirectoryIdentity $intent.Stage
    $backup = Get-RepairDirectoryIdentity $intent.Backup
    if (($current -and $current -notin @($intent.OriginalId,$intent.CandidateId)) -or
        ($stage -and $stage -ne $intent.CandidateId) -or
        ($backup -and (!$intent.HadOriginal -or $backup -ne $intent.OriginalId)) -or
        ($current -eq $intent.CandidateId -and $stage) -or
        ($intent.HadOriginal -and (($current -eq $intent.OriginalId) -eq ($backup -eq $intent.OriginalId)))) {
        throw 'Runtime transaction directory identities are ambiguous; automatic reconciliation refused.'
    }
    $candidate = if ($current -eq $intent.CandidateId) { $venv } elseif ($stage) { $intent.Stage } else { '' }
    if (!$candidate -and $record.Phase -ne 'RollingBack') {
        throw 'The interrupted runtime candidate is missing; reconciliation refused.'
    }
    if ($candidate) {
        Assert-PrivateRepairCustody $candidate -AllowInherited
        $marker = Join-Path $candidate '.angerona-startup-repair.json'
        if (Test-Path -LiteralPath $marker) {
            Assert-PrivateRepairCustody $marker -AllowInherited
            if ((Get-RepairFileSha256 $marker) -ne (Get-RepairFileSha256 (Join-Path $pending 'intent.json'))) {
                throw 'The runtime candidate marker was changed; reconciliation refused.'
            }
        } elseif ($record.Phase -notin @('Verified','RollingBack')) {
            throw 'The runtime candidate marker is missing; reconciliation refused.'
        }
    }
    if ($current -eq $intent.OriginalId -and $current -and
        (Test-Path -LiteralPath (Join-Path $venv '.angerona-startup-repair.json'))) {
        throw 'The previous runtime unexpectedly contains a pending marker.'
    }
    Set-RepairIntentPhase $pending $intent.Id 'RollingBack'
    if ($current -eq $intent.CandidateId) {
        Move-Item -LiteralPath $venv -Destination $intent.Stage
    }
    if ($backup) { Move-Item -LiteralPath $intent.Backup -Destination $venv }
    if ((Get-RepairDirectoryIdentity $venv) -ne $intent.OriginalId) {
        throw 'The preserved original runtime could not be restored exactly.'
    }
    Write-DurableRepairJson (Join-Path $intent.Scratch 'resolution.json') `
        ([ordered]@{Schema=1;Id=$intent.Id;Outcome='RolledBack'}) -Replace
    Remove-OwnedRepairDirectory $pending $pending
    Write-Host '[repair] Interrupted runtime transaction rolled back; original environment preserved.'
}

function Close-RepairSession($Transaction) {
    if ($Transaction.Closed) { return }
    try { Exit-RepairLease $Transaction.HelperLease } finally {
      try { Exit-RepairLease $Transaction.Lease } finally {
        [Environment]::SetEnvironmentVariable('TEMP', $Transaction.OldTemp, 'Process')
        [Environment]::SetEnvironmentVariable('TMP', $Transaction.OldTmp, 'Process')
        $Transaction.Closed = $true
      }
    }
}

function Undo-RepairTransaction($Transaction) {
    if (!$Transaction -or $Transaction.Closed) { return }
    try {
        if ($Transaction.HasIntent) { Restore-InterruptedRepair }
        elseif ($Transaction.PendingOwned) {
            $pending = Get-StartupRepairPendingPath $root
            Remove-OwnedRepairDirectory $pending $pending
        }
        Remove-OwnedRepairDirectory $Transaction.Stage $Transaction.Stage
    } finally { Close-RepairSession $Transaction }
}

function Complete-RepairTransaction($Transaction) {
    try {
        $pending = Get-StartupRepairPendingPath $root
        Set-RepairIntentPhase $pending $Transaction.Id 'Verified'
        $marker = Join-Path $venv '.angerona-startup-repair.json'
        Assert-PrivateRepairCustody $marker -AllowInherited
        [IO.File]::Delete($marker)
        Write-DurableRepairJson (Join-Path $Transaction.Scratch 'resolution.json') `
            ([ordered]@{Schema=1;Id=$Transaction.Id;Outcome='Verified'}) -Replace
        Remove-OwnedRepairDirectory $pending $pending
        Write-Host 'Reviewed CPython 3.12 x64 environment independently verified.' -ForegroundColor Green
        if ($Transaction.PreviousMoved) { Write-Host "Preserved previous environment: $($Transaction.Backup)" }
        try { Remove-OwnedRepairDirectory $Transaction.Scratch $Transaction.Scratch }
        catch { Write-Warning "Verified repair retained its owned scratch: $($Transaction.Scratch)" }
    } catch { throw }
    Close-RepairSession $Transaction
}

function Invoke-RepairTransaction {
    Assert-RepairBoundary
    $lease = Enter-RepairLease -Root $root
    $helperLease = $null
    $transaction = $null
    try {
        $helperLease = Enter-CanonicalSourceHelperLease
        Assert-NoActiveVenv -VenvPath $venv
        $id = [Guid]::NewGuid().ToString('N')
        $scratch = Join-Path $root ('.tmp\repair-wheels\startup-repair.' + $id)
        New-PrivateRepairDirectory $scratch
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fffffff'
        $transaction = [pscustomobject]@{
            Id = $id; Scratch = $scratch; Stage = (Join-Path $scratch 'candidate')
            Backup = [IO.Path]::GetFullPath((Join-Path $root "venv.incompatible.repair.$id"))
            BootstrapWheels = (Join-Path $scratch 'bootstrap-wheels')
            DependencyWheels = (Join-Path $scratch 'dependency-wheels')
            LocalWheels = (Join-Path $scratch 'local-wheels')
            SpeechWheel = (Join-Path $scratch 'local-wheels\srt-0.0.0+angerona.1-py3-none-any.whl')
            SpeechHash = ''; Python = ''; PreviousMoved = $false; Promoted = $false
            HasIntent = $false; PendingOwned = $false
            Lease = $lease; HelperLease = $helperLease; Closed = $false; OldTemp = $env:TEMP; OldTmp = $env:TMP
        }
        [void][IO.Directory]::CreateDirectory((Join-Path $scratch 'temp'))
        $env:TEMP = Join-Path $scratch 'temp'; $env:TMP = $env:TEMP
        $script:RepairScratch = $scratch
        $script:RepairEnvironment = New-RepairChildEnvironment $env:TEMP
        $script:RepairEnvironment['QT_QPA_PLATFORM'] = 'offscreen'
        $script:RepairClock = [Diagnostics.Stopwatch]::StartNew()
        $script:RepairCommandNumber = 0
        Initialize-OwnedRepairProcess
        Restore-InterruptedRepair
        Write-Host '[repair] One runtime transaction; 900s overall command budget; no AI/model tools.'
        $transaction.Python = Find-ReviewedPython
        if (!$transaction.Python) {
            $winget = Find-TrustedWinget
            if (!$winget) { throw 'Trusted PSF CPython 3.12 x64 and Microsoft-signed winget are unavailable.' }
            [void](Invoke-RepairCommand $winget @('install', '--id', 'Python.Python.3.12', '--exact', '--source', 'winget',
                '--scope', 'user', '--silent', '--disable-interactivity', '--accept-package-agreements',
                '--accept-source-agreements') 'Obtain signed PSF CPython 3.12 x64' 300)
            $transaction.Python = Find-ReviewedPython
            if (!$transaction.Python) { throw 'Installed CPython signature/ABI could not be verified.' }
        }
        New-VerifiedRepairCandidate $transaction
        Assert-RepairBoundary
        Assert-NoActiveVenv -VenvPath $venv
        if (Test-Path -LiteralPath $transaction.Backup) { throw 'Unique venv backup path is already occupied.' }
        New-PendingRepairIntent $transaction
        $pending = Get-StartupRepairPendingPath $root
        Set-RepairIntentPhase $pending $transaction.Id 'BeforeBackup'
        if (Test-Path -LiteralPath $venv) {
            Move-Item -LiteralPath $venv -Destination $transaction.Backup
            $transaction.PreviousMoved = $true
        }
        Set-RepairIntentPhase $pending $transaction.Id 'BeforePromotion'
        Move-Item -LiteralPath $transaction.Stage -Destination $venv
        $transaction.Promoted = $true
        Set-RepairIntentPhase $pending $transaction.Id 'Refreshing'
        Repair-PromotedEnvironment $transaction
        return $transaction
    } catch {
        if ($transaction) {
            Write-Host "Repair failed; owned command logs remain at $($transaction.Scratch)" -ForegroundColor Red
            Undo-RepairTransaction $transaction
        } else {
            try { Exit-RepairLease $helperLease } finally { Exit-RepairLease $lease }
        }
        throw
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $transaction = $null
    try {
        Assert-RepairBoundary
        if (!$Automatic) {
            Write-Host 'Repair stages/verifies a hash-locked venv, preserves the previous venv, and never changes settings or evidence.'
            $answer = Read-Host 'Type REPAIR to continue'
            if ($answer -cne 'REPAIR') { Write-Host 'Repair cancelled; no files were changed.'; exit 2 }
        }
        $transaction = Invoke-RepairTransaction
        Test-RepairedRuntime $venv $transaction.Stage
        Complete-RepairTransaction $transaction
        exit 0
    } catch {
        if ($transaction -and !$transaction.Closed) { Undo-RepairTransaction $transaction }
        Write-Host "Repair failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
