<#
================================================================================
  finalize-and-deploy.ps1
  Copies Angerona to an explicitly selected, Angerona-owned home and backup.

  Mirroring can delete destination-only files. This helper therefore rejects
  broad/protected/overlapping paths, previews every mirror, and requires the
  exact typed phrase MIRROR ANGERONA before each destination is changed.

  Interactive:
    .\finalize-and-deploy.ps1 -Home C:\Projects\Angerona -Backup E:\Backups\Angerona

  Explicit non-interactive authorization (for a reviewed automation job):
    .\finalize-and-deploy.ps1 -Home C:\Projects\Angerona `
      -ConfirmMirror 'MIRROR ANGERONA'
================================================================================
#>

param(
    [string]$Stage = $PSScriptRoot,
    [Parameter(Mandatory=$true)][Alias('Home')][string]$DeploymentHome,
    [string]$Backup = '',
    [string]$ConfirmMirror = ''
)
$ErrorActionPreference = 'Stop'
$MarkerName = '.angerona-deployment-owner.json'
$ConfirmationPhrase = 'MIRROR ANGERONA'

function Say($Message, $Color='Gray') {
    Write-Host $Message -ForegroundColor $Color
}

function Resolve-CanonicalPath([string]$RawPath) {
    if ([string]::IsNullOrWhiteSpace($RawPath)) {
        throw 'A required deployment path is empty.'
    }
    return [IO.Path]::GetFullPath($RawPath).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
}

function Test-PathWithin([string]$Candidate, [string]$Parent) {
    $candidatePath = Resolve-CanonicalPath $Candidate
    $parentPath = Resolve-CanonicalPath $Parent
    if ($candidatePath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = $parentPath + [IO.Path]::DirectorySeparatorChar
    return $candidatePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-SafeDestination([string]$Path, [string]$Label) {
    $canonical = Resolve-CanonicalPath $Path
    $volumeRoot = Resolve-CanonicalPath ([IO.Path]::GetPathRoot($canonical))
    if ($canonical.Equals($volumeRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label cannot be a filesystem root: $canonical"
    }
    if ($env:USERPROFILE) {
        $profile = Resolve-CanonicalPath $env:USERPROFILE
        if ($canonical.Equals($profile, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label cannot be the user profile root: $canonical"
        }
    }
    $protectedTrees = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($protected in $protectedTrees) {
        if (Test-PathWithin $canonical $protected) {
            throw "$Label cannot be inside a protected operating-system tree: $canonical"
        }
    }
}

function Assert-NoOverlap(
    [string]$First,
    [string]$FirstLabel,
    [string]$Second,
    [string]$SecondLabel
) {
    if ((Test-PathWithin $First $Second) -or (Test-PathWithin $Second $First)) {
        throw "$FirstLabel and $SecondLabel cannot be equal or nested: $First <> $Second"
    }
}

function Test-AngeronaOwnedDestination([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Label is not a directory: $Path"
    }
    $marker = Join-Path $Path $MarkerName
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw "$Label already exists but has no Angerona ownership marker: $Path"
    }
    try {
        $ownership = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    } catch {
        throw "$Label has an unreadable Angerona ownership marker: $marker"
    }
    if ($ownership.product -ne 'AngeronaSuite') {
        throw "$Label ownership marker does not belong to AngeronaSuite: $marker"
    }
    return $true
}

function Initialize-AngeronaDestination([string]$Path, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    $marker = Join-Path $Path $MarkerName
    if (-not (Test-Path -LiteralPath $marker)) {
        @{
            product = 'AngeronaSuite'
            deployment_id = [Guid]::NewGuid().ToString('D')
            created_at = [DateTimeOffset]::UtcNow.ToString('o')
            initial_source = $Source
        } | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding UTF8
    }
}

function Confirm-And-Mirror(
    [string]$Source,
    [string]$Destination,
    [string]$Label,
    [string]$RobocopyPath
) {
    Say "`nPreview: $Source -> $Destination" Cyan
    & $RobocopyPath $Source $Destination /MIR /L /XD __pycache__ venv .git runtime-data diagnostics /XF .env $MarkerName /NJH /NJS /NP
    if ($LASTEXITCODE -ge 8) {
        throw "$Label preview failed with robocopy code $LASTEXITCODE"
    }
    $typed = if ($ConfirmMirror) {
        $ConfirmMirror
    } else {
        Read-Host "Type $ConfirmationPhrase to mirror $Label"
    }
    if ($typed -cne $ConfirmationPhrase) {
        throw "$Label mirror was not authorized; destination was not changed."
    }
    Initialize-AngeronaDestination $Destination $Source
    & $RobocopyPath $Source $Destination /MIR /XD __pycache__ venv .git runtime-data diagnostics /XF .env $MarkerName /NFL /NDL /NP /NJH
    if ($LASTEXITCODE -ge 8) {
        throw "$Label mirror failed with robocopy code $LASTEXITCODE"
    }
}

Say '=== Finalize & deploy Angerona Suite ===' Cyan

$stage = Resolve-CanonicalPath $Stage
$home_ = Resolve-CanonicalPath $DeploymentHome
$fbak = if ($Backup) { Resolve-CanonicalPath $Backup } else { '' }
$robocopy = Join-Path $env:SystemRoot 'System32\robocopy.exe'

if (-not (Test-Path -LiteralPath $stage -PathType Container)) {
    throw "Staging folder not found: $stage"
}
if (-not (Test-Path -LiteralPath $robocopy -PathType Leaf)) {
    throw "Windows robocopy was not found: $robocopy"
}

Assert-SafeDestination $home_ 'Home'
Assert-NoOverlap $stage 'Stage' $home_ 'Home'
[void](Test-AngeronaOwnedDestination $home_ 'Home')

if ($fbak) {
    Assert-SafeDestination $fbak 'Backup'
    Assert-NoOverlap $stage 'Stage' $fbak 'Backup'
    Assert-NoOverlap $home_ 'Home' $fbak 'Backup'
    [void](Test-AngeronaOwnedDestination $fbak 'Backup')
}

Say "`n[1] Deploying to $home_ ..." Cyan
Confirm-And-Mirror $stage $home_ 'Home' $robocopy
Say "    verified mirror complete -> $home_" Green

Say "`n[2] Git repository ..." Cyan
if (Get-Command git -ErrorAction SilentlyContinue) {
    Push-Location $home_
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $home_ '.git'))) {
            git init -b main | Out-Null
            git add . | Out-Null
            git -c user.email='you@example.com' -c user.name='Angerona' commit -m 'Initial commit: Angerona Security Suite' | Out-Null
            Say '    initialized a local Git repository' Green
        } else {
            Say '    existing Git repository left intact' DarkGray
        }
    } finally {
        Pop-Location
    }
} else {
    Say '    Git is not installed; repository initialization skipped.' Yellow
}

Say "`n[3] Optional backup copy ..." Cyan
if ($fbak) {
    Confirm-And-Mirror $home_ $fbak 'Backup' $robocopy
    Say "    verified backup mirror complete -> $fbak" Green
} else {
    Say '    no -Backup path supplied; skipped.' DarkGray
}

Say "`n================ DONE ================" Green
Say "Clean repo : $home_"
Say "Backup     : $(if ($fbak) {$fbak} else {'not requested'})"
Say "Run it     : cd $home_ ; .\install.bat ; .\run.bat"
