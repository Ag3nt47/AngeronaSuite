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

function Get-RepairAvailableBytes([string]$Path) {
    Assert-PlainRepairPath $Path
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path)))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'Runtime repair storage requires a ready fixed local drive.'
    }
    return [long]$drive.AvailableFreeSpace
}

function Get-RepairRetainedDirectoryCount([string]$Parent, [string]$Pattern, [string]$NamePattern) {
    Assert-PlainRepairPath $Parent
    if (!(Test-Path -LiteralPath $Parent)) { return 0 }
    $count = 0
    # Inspect only immediate known-prefix directories. Stop on the ninth entry;
    # never recurse through a retained runtime, wheel cache or unknown evidence.
    $entries = [IO.Directory]::EnumerateDirectories($Parent, $Pattern).GetEnumerator()
    try {
        while ($entries.MoveNext()) {
            if (++$count -gt 8) {
                throw "Runtime repair storage inventory exceeds eight retained entries: $Parent ($Pattern). Review the retained artifacts before Retry."
            }
            $path = [string]$entries.Current
            Assert-PlainRepairPath $path
            if ([IO.Path]::GetFileName($path) -cnotmatch $NamePattern) {
                throw "Runtime repair storage has an unrecognized retained directory: $path. Preserve it for review before Retry."
            }
        }
    } finally { $entries.Dispose() }
    return $count
}

function Assert-RepairStorageAdmission {
    $transactions = Join-Path $root '.tmp\repair-wheels'
    $locations = "Retained backups: $root\venv.incompatible.repair.<id>; retained transactions: $transactions\startup-repair.<id>."
    $backups = Get-RepairRetainedDirectoryCount $root 'venv.incompatible.repair.*' '^venv\.incompatible\.repair\.[0-9a-f]{32}$'
    $retained = Get-RepairRetainedDirectoryCount $transactions 'startup-repair.*' '^startup-repair\.[0-9a-f]{32}$'
    if ($backups -ge 1) {
        throw "Runtime repair storage held: one full previous runtime is already retained; another repair would exceed the one-backup limit. $locations Review the original backup before allowing another full copy; nothing was deleted."
    }
    # The new transaction has not been created yet. One retained transaction
    # plus this attempt reaches the two-directory limit; two already fills it.
    if ($retained -ge 2) {
        throw "Runtime repair storage held: two transaction directories are already retained. $locations Review their diagnostics and preserved payloads before Retry; nothing was deleted."
    }
    $available = Get-RepairAvailableBytes $root
    if ($available -lt (2GB + 3GB)) {
        throw "Runtime repair storage held: at least 5 GiB free is required for a 2 GiB reserve plus 3 GiB transaction capacity. $locations Free space and review storage choices before Retry; no candidate, download or runtime promotion was admitted."
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
    Write-RepairDiagnostic 'command' 'started' $Label ([IO.Path]::GetFileName($log))
    try {
        if ($script:ReviewedPythonBinding -and
            [string]::Equals($Executable, $script:ReviewedPythonBinding.PhysicalPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            $script:ReviewedPythonBinding.AssertBound()
        }
        $code = Invoke-OwnedRepairProcess -FilePath $Executable -Arguments $Arguments `
            -WorkingDirectory $root -Environment $script:RepairEnvironment `
            -TimeoutSeconds $limit -LogPath $log
        if ($script:ReviewedPythonBinding -and
            [string]::Equals($Executable, $script:ReviewedPythonBinding.PhysicalPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            $script:ReviewedPythonBinding.AssertBound()
        }
        Write-RepairDiagnostic 'command' ('exit-' + $code) $Label ([IO.Path]::GetFileName($log))
    } catch {
        Write-RepairDiagnostic 'command' 'failed' ($Label + ': ' + $_.Exception.Message) ([IO.Path]::GetFileName($log))
        throw
    }
    if ($code -ne 0 -and !$AllowFailure) { throw "$Label failed (exit $code). Output: $log" }
    return $code
}

function Write-RepairDiagnostic([string]$Phase, [string]$Outcome, [string]$Detail = '', [string]$CommandLog = '') {
    if (!$script:RepairScratch -or !(Test-Path -LiteralPath $script:RepairScratch -PathType Container)) { return }
    try {
        Assert-PrivateRepairCustody $script:RepairScratch
        $phaseText = ($Phase -replace '[\x00-\x1f\x7f]', ' ')
        $outcomeText = ($Outcome -replace '[\x00-\x1f\x7f]', ' ')
        $detailText = ($Detail -replace '[\x00-\x1f\x7f]', ' ')
        if ($phaseText.Length -gt 64) { $phaseText = $phaseText.Substring(0,64) }
        if ($outcomeText.Length -gt 64) { $outcomeText = $outcomeText.Substring(0,64) }
        if ($detailText.Length -gt 1024) { $detailText = $detailText.Substring(0,1024) }
        $record = [ordered]@{ Schema=1; Utc=[DateTime]::UtcNow.ToString('o');
            Phase=$phaseText; Outcome=$outcomeText; Detail=$detailText; CommandLog=$CommandLog }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Compress) + [Environment]::NewLine)
        $path = Join-Path $script:RepairScratch 'repair-events.jsonl'
        $stream = Open-PrivateRepairFile -Path $path -Mode ([IO.FileMode]::OpenOrCreate)
        try {
            if ($stream.Length + $bytes.Length -gt 65536) {
                if (!$script:RepairDiagnosticCapped) { Write-Warning 'Repair event log reached its 64 KiB limit; command logs remain separate.' }
                $script:RepairDiagnosticCapped = $true
                return
            }
            [void]$stream.Seek(0,[IO.SeekOrigin]::End)
            $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)
        } finally { $stream.Dispose() }
    } catch {
        Write-Warning 'Repair diagnostic persistence was unavailable; retain the supervisor output and private command logs.'
    }
}

function Write-RepairFailureDiagnostic([string]$Phase, $Failure) {
    $cause = $Failure.Exception
    while ($cause.InnerException) { $cause = $cause.InnerException }
    $native = if ($cause -is [ComponentModel.Win32Exception]) {
        $cause.NativeErrorCode
    } else { $cause.HResult -band 0xffff }
    $location = $Failure.InvocationInfo
    $detail = 'type={0}; hresult=0x{1:x8}; native={2}; file={3}; line={4}; error={5}; message={6}' -f `
        $cause.GetType().FullName, ([long]$cause.HResult -band 0xffffffffL),
        $native, $location.ScriptName, $location.ScriptLineNumber,
        $Failure.FullyQualifiedErrorId, $cause.Message
    Write-RepairDiagnostic $Phase 'failed' $detail
    if ($Failure.ScriptStackTrace) {
        Write-RepairDiagnostic ($Phase + '-stack') 'failed' $Failure.ScriptStackTrace
    }
}

function Test-ReviewedPython([string]$Path) {
    $binding = $null
    try {
        if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
        $binding = Open-RepairPythonHint $Path
        $physical = $binding.PhysicalPath
        if (![string]::Equals([IO.Path]::GetFileName($physical),'python.exe',
                [StringComparison]::OrdinalIgnoreCase)) {
            Write-RepairDiagnostic 'python-discovery' 'rejected' ('Physical image is not python.exe: ' + $physical)
            return $false
        }
        Assert-PlainRepairPath $physical -AllowHardLinks
        $binding.AssertBound()
        $signature = Get-AuthenticodeSignature -LiteralPath $physical
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch '(?:CN|O)=Python Software Foundation(?:,|$)') {
            Write-RepairDiagnostic 'python-discovery' 'rejected' ('PSF signature proof failed: ' + $Path)
            return $false
        }
        $binding.AssertBound()
        $code = Invoke-RepairCommand $physical @('-I', '-c',
            "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' and sys.prefix == sys.base_prefix else 1)") `
            'Verify independently installed PSF CPython 3.12 x64' 30 -AllowFailure
        $binding.AssertBound()
        if ($code -ne 0) {
            Write-RepairDiagnostic 'python-discovery' 'rejected' ('ABI/base-install proof failed: ' + $physical)
            return $false
        }
        $script:ReviewedPythonBinding = $binding
        $binding = $null # Session retains image/namespace custody through repair.
        Write-RepairDiagnostic 'python-discovery' 'accepted' $script:ReviewedPythonBinding.PhysicalPath
        return $true
    } catch {
        # A missing, redirected, unavailable or wrong candidate cannot prevent
        # independent candidates from being checked. No refused pathname runs.
        Write-RepairDiagnostic 'python-discovery' 'rejected' ($Path + ': ' + $_.Exception.Message)
        return $false
    } finally {
        if ($binding) { $binding.Dispose() }
    }
}

function Get-RepairPythonHints {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    $hints = [Collections.Generic.List[string]]::new()
    foreach ($candidate in @((Join-Path $programFiles 'Python312\python.exe'),
            (Join-Path $localAppData 'Python\pythoncore-3.12-64\python.exe'),
            (Join-Path $localAppData 'Programs\Python\Python312\python.exe'))) {
        $hints.Add($candidate)
    }
    # Registry strings are discovery hints only. They never grant execution
    # authority and are not environment-expanded or passed to a shell.
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
            $base = $null; $core = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
                $core = $base.OpenSubKey('Software\Python\PythonCore')
                if (!$core) { continue }
                foreach ($tag in @('3.12','3.12-64')) {
                    if ($hints.Count -ge 32) { break }
                    $install = $null
                    try {
                        $install = $core.OpenSubKey($tag + '\InstallPath')
                        if (!$install) { continue }
                        foreach ($name in @('ExecutablePath','')) {
                            $value = $install.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                            if ($value -isnot [string] -or $value.Length -gt 4096 -or $value -notmatch '^[A-Za-z]:\\') { continue }
                            $hint = if ($name -eq '') { Join-Path $value 'python.exe' } else { $value }
                            if ($hints.Count -lt 32 -and !$hints.Contains($hint)) { $hints.Add($hint) }
                        }
                    } finally { if ($install) { $install.Dispose() } }
                }
            } catch { Write-RepairDiagnostic 'python-registry' 'unavailable' $_.Exception.GetType().Name }
            finally { if ($core) { $core.Dispose() }; if ($base) { $base.Dispose() } }
        }
    }
    return $hints.ToArray()
}

function Find-ReviewedPython {
    if ($script:ReviewedPythonBinding) { $script:ReviewedPythonBinding.Dispose() }
    $script:ReviewedPythonBinding = $null
    $seen = @{}; $count = 0
    foreach ($candidate in Get-RepairPythonHints) {
        if ($count++ -ge 32) { break }
        if ($candidate -isnot [string] -or $candidate.Length -gt 4096 -or $seen.ContainsKey($candidate)) { continue }
        $seen[$candidate] = $true
        if (Test-ReviewedPython $candidate) { return $script:ReviewedPythonBinding.PhysicalPath }
    }
    Write-RepairDiagnostic 'python-discovery' 'unavailable' 'No independently verified CPython candidate was admitted.'
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
    $prefix = @('-I', '-m', 'pip', 'download', '--isolated', '--no-cache-dir', '--only-binary', ':all:',
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
    [void](Invoke-RepairCommand $Python @('-I', '-m', 'pip', 'install', '--isolated', '--no-cache-dir', '--no-compile',
        '--only-binary', ':all:', '--require-hashes', '--no-deps', '--no-index',
        '--find-links', $Wheelhouse, '--force-reinstall', '-r', $RequirementsPath) `
        'Install exact reviewed wheels offline' 300)
}

function Install-LocalRepairPackages([string]$Python, [string]$SpeechWheel) {
    [void](Invoke-RepairCommand $Python @('-I', '-m', 'pip', 'install', '--isolated', '--no-cache-dir', '--no-compile',
        '--no-index', '--no-build-isolation', '--no-deps', '-e', $root) `
        'Install reviewed local editable Angerona source offline' 120)
    [void](Invoke-RepairCommand $Python @('-I', '-m', 'pip', 'install', '--isolated', '--no-cache-dir', '--no-compile',
        '--no-index', '--only-binary', ':all:', '--no-deps', '--force-reinstall', $SpeechWheel) `
        'Install reviewed local speech compatibility wheel offline' 60)
}

function Test-RepairedRuntime([string]$VenvPath, [string]$OldStagingPath = '') {
    $python = Join-Path $VenvPath 'Scripts\python.exe'
    $probe = @'
import importlib.metadata as m, pathlib, re, sys, sysconfig
assert sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64'
assert m.version('pip') == '26.2.2'
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

function Invoke-RepairDirectoryRename([string]$From, [string]$To, [string]$ExpectedIdentity) {
    # The native operation binds the exact source identity and destination
    # parent, and atomically refuses an existing destination. Move-Item can
    # instead nest a runtime inside a container created after the precheck.
    Initialize-OwnedRepairProcess
    [Angerona.StartupRepairProcess]::RenameDirectoryExact($From, $To, $ExpectedIdentity)
}

function Move-RepairRuntimeDirectory([string]$From, [string]$To, [string]$ExpectedIdentity,
    [switch]$Reconcile) {
    $source = [IO.Path]::GetFullPath($From)
    $destination = [IO.Path]::GetFullPath($To)
    $prefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    if (!$ExpectedIdentity -or $source -eq $destination -or
        !$source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        !$destination.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runtime move escaped the reviewed transaction boundary.'
    }
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        Assert-PlainRepairPath $source
        Assert-PlainRepairPath $destination
        if ((Get-RepairDirectoryIdentity $source) -cne $ExpectedIdentity -or
            (Test-Path -LiteralPath $destination)) {
            throw 'Runtime move identities changed or the destination is occupied; mutation is held.'
        }
        Assert-NoActiveVenv -VenvPath $venv
        if (!$Reconcile -and $script:RepairClock -and $script:RepairClock.Elapsed.TotalSeconds -ge 900) {
            throw 'The 900-second runtime repair transaction deadline expired before a runtime move.'
        }
        try {
            Invoke-RepairDirectoryRename $source $destination $ExpectedIdentity
            if ((Get-RepairDirectoryIdentity $destination) -cne $ExpectedIdentity -or
                (Test-Path -LiteralPath $source)) {
                throw 'Runtime move could not prove its resulting directory identities.'
            }
            return
        } catch {
            $failure = $_
            $cause = $failure.Exception
            while ($cause.InnerException) { $cause = $cause.InnerException }
            $native = if ($cause -is [ComponentModel.Win32Exception]) {
                $cause.NativeErrorCode
            } else { $cause.HResult -band 0xffff }
            # Short-lived readers can hold Windows directory renames after all
            # disposable commands have exited. Never overwrite, close another
            # process's handle, or retry changed/ambiguous transaction state.
            if ($attempt -ge 12 -or $native -notin @(5,32,33)) {
                Write-RepairFailureDiagnostic 'runtime-move' $failure
                throw
            }
            Write-RepairDiagnostic 'runtime-move' 'retry' `
                ("attempt=$attempt; native=$native; source=$source; destination=$destination")
            [Threading.Thread]::Sleep(250)
        }
    }
}

function Write-DurableRepairJson([string]$Path, $Value, [switch]$Replace) {
    Assert-PlainRepairPath $Path
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Compress -Depth 4))
    $stream = Open-PrivateRepairFile -Path $temporary
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ($Replace -and (Test-Path -LiteralPath $Path)) {
        $before = Get-RepairFileSha256 $Path
        for ($attempt = 0; ; $attempt++) {
            Assert-PrivateRepairCustody $Path -AllowInherited
            Assert-PrivateRepairCustody $temporary -AllowInherited
            if ((Get-RepairFileSha256 $Path) -cne $before) { throw 'Repair receipt changed during atomic publication; mutation is held.' }
            try { [IO.File]::Replace($temporary, $Path, [NullString]::Value); break }
            catch {
                $cause = $_.Exception
                while ($cause.InnerException) { $cause = $cause.InnerException }
                $native = $cause.HResult -band 0xffff
                # A short-lived read/delete-sharing conflict must not undo a
                # verified runtime. Revalidate custody and old bytes on retry;
                # malformed/tampered receipts never become retry authority.
                if ($attempt -ge 5 -or $native -notin @(5,32,33,1175)) { throw }
                [Threading.Thread]::Sleep(100)
            }
        }
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
        Move-RepairRuntimeDirectory $venv $intent.Stage $intent.CandidateId -Reconcile
    }
    if ($backup) { Move-RepairRuntimeDirectory $intent.Backup $venv $intent.OriginalId -Reconcile }
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
    try {
        if ($Transaction.PythonBinding) {
            $Transaction.PythonBinding.Dispose()
            if ([Object]::ReferenceEquals($script:ReviewedPythonBinding,$Transaction.PythonBinding)) {
                $script:ReviewedPythonBinding = $null
            }
        }
    } finally {
      try { Exit-RepairLease $Transaction.CoreLease } finally {
      try { Exit-RepairLease $Transaction.HelperLease } finally {
      try { Exit-RepairLease $Transaction.Lease } finally {
        [Environment]::SetEnvironmentVariable('TEMP', $Transaction.OldTemp, 'Process')
        [Environment]::SetEnvironmentVariable('TMP', $Transaction.OldTmp, 'Process')
        $Transaction.Closed = $true
      }
      }
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
        Write-RepairDiagnostic 'transaction' 'independently-verified' 'Final-path ABI, exact dependencies, Tk and Qt checks passed.'
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
    $coreLease = $null
    $transaction = $null
    try {
        $helperLease = Enter-CanonicalSourceHelperLease
        $coreLease = Enter-CanonicalCoreMutationLease
        Assert-NoActiveVenv -VenvPath $venv
        # Reconcile an already-owned interrupted transaction before applying
        # new-copy quotas. Reconciliation uses its existing private receipts;
        # rejected fresh attempts must not accumulate empty scratch directories.
        Restore-InterruptedRepair
        Assert-RepairStorageAdmission
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
            SpeechHash = ''; Python = ''; PythonBinding = $null; PreviousMoved = $false; Promoted = $false
            HasIntent = $false; PendingOwned = $false
            Lease = $lease; HelperLease = $helperLease; CoreLease = $coreLease
            Closed = $false; OldTemp = $env:TEMP; OldTmp = $env:TMP
        }
        [void][IO.Directory]::CreateDirectory((Join-Path $scratch 'temp'))
        $env:TEMP = Join-Path $scratch 'temp'; $env:TMP = $env:TEMP
        $script:RepairScratch = $scratch
        $script:RepairEnvironment = New-RepairChildEnvironment $env:TEMP
        $script:RepairEnvironment['QT_QPA_PLATFORM'] = 'offscreen'
        $script:RepairClock = [Diagnostics.Stopwatch]::StartNew()
        $script:RepairCommandNumber = 0
        $script:RepairDiagnosticCapped = $false
        Write-DurableRepairJson (Join-Path $scratch 'repair-session.json') `
            ([ordered]@{Schema=1;Id=$id;PhaseLog='repair-events.jsonl';
                CommandLogs='command-NNN.log';CommandBudgetSeconds=900;EventLogMaxBytes=65536})
        Write-RepairDiagnostic 'transaction' 'started' 'No runtime move occurs before independently verified candidate creation.'
        Initialize-OwnedRepairProcess
        Write-Host '[repair] One runtime transaction; 900s overall command budget; no AI/model tools.'
        $transaction.Python = Find-ReviewedPython
        $transaction.PythonBinding = $script:ReviewedPythonBinding
        if (!$transaction.Python) {
            $winget = Find-TrustedWinget
            if (!$winget) { throw 'Trusted PSF CPython 3.12 x64 and Microsoft-signed winget are unavailable.' }
            [void](Invoke-RepairCommand $winget @('install', '--id', 'Python.Python.3.12', '--exact', '--source', 'winget',
                '--scope', 'user', '--silent', '--disable-interactivity', '--accept-package-agreements',
                '--accept-source-agreements') 'Obtain signed PSF CPython 3.12 x64' 300)
            $transaction.Python = Find-ReviewedPython
            $transaction.PythonBinding = $script:ReviewedPythonBinding
            if (!$transaction.Python) { throw 'Installed CPython signature/ABI could not be verified.' }
        }
        Write-RepairDiagnostic 'candidate' 'started' 'Create and verify isolated candidate before promotion.'
        New-VerifiedRepairCandidate $transaction
        Write-RepairDiagnostic 'candidate' 'verified' 'Candidate proof passed; original environment still retained at its original path.'
        Assert-RepairBoundary
        Assert-NoActiveVenv -VenvPath $venv
        if (Test-Path -LiteralPath $transaction.Backup) { throw 'Unique venv backup path is already occupied.' }
        New-PendingRepairIntent $transaction
        $pending = Get-StartupRepairPendingPath $root
        $intent = (Read-PendingRepairIntent $root).Intent
        Set-RepairIntentPhase $pending $transaction.Id 'BeforeBackup'
        Write-RepairDiagnostic 'promotion' 'prepared' 'Durable intent recorded before any runtime move.'
        if (Test-Path -LiteralPath $venv) {
            Move-RepairRuntimeDirectory $venv $transaction.Backup $intent.OriginalId
            $transaction.PreviousMoved = $true
        }
        Set-RepairIntentPhase $pending $transaction.Id 'BeforePromotion'
        Move-RepairRuntimeDirectory $transaction.Stage $venv $intent.CandidateId
        $transaction.Promoted = $true
        Set-RepairIntentPhase $pending $transaction.Id 'Refreshing'
        Repair-PromotedEnvironment $transaction
        Write-RepairDiagnostic 'promotion' 'refreshed' 'Final-path scaffold refreshed; independent recheck remains required.'
        return $transaction
    } catch {
        $failure = $_
        Write-RepairFailureDiagnostic 'transaction' $failure
        if ($transaction) {
            Write-Host "Repair failed; owned command logs remain at $($transaction.Scratch)" -ForegroundColor Red
            Write-Host ("[repair] reason=" + $failure.Exception.Message) -ForegroundColor Red
            try { Undo-RepairTransaction $transaction }
            catch {
                Write-RepairDiagnostic 'rollback' 'failed-or-refused' $_.Exception.Message
                Write-Host ("[repair] rollback-refused=" + $_.Exception.Message) -ForegroundColor Red
                throw
            }
        } else {
            try { Exit-RepairLease $coreLease } finally {
            try { Exit-RepairLease $helperLease } finally { Exit-RepairLease $lease }
            }
        }
        throw $failure
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
