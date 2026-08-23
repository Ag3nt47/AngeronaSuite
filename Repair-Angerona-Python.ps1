[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path))
$venv = [IO.Path]::GetFullPath((Join-Path $root 'venv'))
$required = @(
    'start-angerona.bat',
    'pyproject.toml',
    'requirements-bootstrap-pip.txt',
    'requirements-release-hashed.txt',
    'src\angerona\__init__.py',
    'tools\build_srt_compat_wheel.py'
)

function Assert-RepairBoundary {
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The Angerona checkout is a redirected/reparse path; repair refused.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($rootItem.FullName))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'The Angerona checkout is not on a ready fixed drive; repair refused.'
    }
    if ([IO.Path]::GetFullPath((Split-Path -Parent $venv)) -ne $root) {
        throw 'The virtual-environment target escaped the Angerona checkout.'
    }
    foreach ($name in $required) {
        $path = Join-Path $root $name
        $item = Get-Item -LiteralPath $path -Force
        if (!$item -or $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Required source file is missing or redirected: $name"
        }
    }
    if (Test-Path -LiteralPath $venv) {
        $item = Get-Item -LiteralPath $venv -Force
        if (!$item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'The repo-root venv is not a normal directory; repair refused.'
        }
    }
}

function Test-ReviewedPython([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
        return $false
    }
    & $Path -c "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' else 1)" *> $null
    return $LASTEXITCODE -eq 0
}

function Find-ReviewedPython {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    $candidates = @(
        (Join-Path $programFiles 'Python312\python.exe'),
        (Join-Path $localAppData 'Python\pythoncore-3.12-64\python.exe'),
        (Join-Path $localAppData 'Programs\Python\Python312\python.exe')
    )
    foreach ($candidate in $candidates) {
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
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        return $null
    }
    return $candidate
}

function Remove-PartialVenv {
    if (!(Test-Path -LiteralPath $venv)) { return }
    Assert-RepairBoundary
    Remove-Item -LiteralPath $venv -Recurse -Force
}

Assert-RepairBoundary
Write-Host 'Angerona Python repair will:' -ForegroundColor Cyan
Write-Host '  1. obtain signed PSF CPython 3.12 x64 when needed;'
Write-Host '  2. preserve the current repo-root venv as a timestamped sibling;'
Write-Host '  3. build a fresh hash-locked venv without touching Angerona data or settings.'
$answer = Read-Host "Type REPAIR to continue"
if ($answer -cne 'REPAIR') {
    Write-Host 'Repair cancelled; no files were changed.' -ForegroundColor Yellow
    exit 2
}

$python = Find-ReviewedPython
if (!$python) {
    $winget = Find-TrustedWinget
    if (!$winget) {
        throw 'Trusted winget is unavailable. Install signed CPython 3.12 x64 from python.org and retry.'
    }
    Write-Host 'Installing signed CPython 3.12 x64 with trusted winget...' -ForegroundColor Cyan
    & $winget install --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw "winget returned $LASTEXITCODE" }
    $python = Find-ReviewedPython
    if (!$python) { throw 'CPython installed, but its signature/ABI could not be verified.' }
}

$backup = $null
if (Test-Path -LiteralPath $venv) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = [IO.Path]::GetFullPath((Join-Path $root "venv.incompatible.$stamp"))
    if ([IO.Path]::GetFullPath((Split-Path -Parent $backup)) -ne $root -or
        (Test-Path -LiteralPath $backup)) {
        throw 'A safe unique backup path could not be established.'
    }
    Move-Item -LiteralPath $venv -Destination $backup
    Write-Host "Preserved previous environment: $backup" -ForegroundColor Yellow
}

try {
    & $python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'venv creation failed' }
    $venvPython = Join-Path $venv 'Scripts\python.exe'
    & $venvPython -m pip install --isolated --only-binary ':all:' --require-hashes --no-deps -r (Join-Path $root 'requirements-bootstrap-pip.txt')
    if ($LASTEXITCODE -ne 0) { throw 'verified pip bootstrap failed' }
    & $venvPython -m pip install --isolated --only-binary ':all:' --require-hashes --no-deps -r (Join-Path $root 'requirements-release-hashed.txt')
    if ($LASTEXITCODE -ne 0) { throw 'hash-locked dependency installation failed' }
    & $venvPython -m pip install --isolated --no-build-isolation --no-deps -e $root
    if ($LASTEXITCODE -ne 0) { throw 'local Angerona installation failed' }
    $wheelDir = Join-Path $root '.tmp\repair-wheels'
    New-Item -ItemType Directory -Path $wheelDir -Force | Out-Null
    & $venvPython (Join-Path $root 'tools\build_srt_compat_wheel.py') --out $wheelDir
    if ($LASTEXITCODE -ne 0) { throw 'speech compatibility wheel build failed' }
    $srtWheel = Join-Path $wheelDir 'srt-0.0.0+angerona.1-py3-none-any.whl'
    & $venvPython -m pip install --isolated --only-binary ':all:' --no-deps $srtWheel
    if ($LASTEXITCODE -ne 0) { throw 'speech compatibility wheel installation failed' }
    & $venvPython -c "import angerona,importlib.metadata as m,PySide6,sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' and m.version('pip') == '26.2.1' else 1)"
    if ($LASTEXITCODE -ne 0) { throw 'final Python/Angerona verification failed' }
}
catch {
    Write-Host "Repair failed: $($_.Exception.Message)" -ForegroundColor Red
    Remove-PartialVenv
    if ($backup -and (Test-Path -LiteralPath $backup)) {
        Move-Item -LiteralPath $backup -Destination $venv
        Write-Host 'The previous environment was restored.' -ForegroundColor Yellow
    }
    throw
}

Write-Host 'Reviewed CPython 3.12 x64 environment verified.' -ForegroundColor Green
if ($backup) {
    Write-Host "The preserved old environment can be removed later after validation: $backup"
}
