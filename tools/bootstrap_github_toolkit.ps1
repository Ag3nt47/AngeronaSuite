[CmdletBinding()]
param(
    [switch]$ForceDownload
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ToolkitRoot = Join-Path $RepoRoot ".dev-tools"
$DownloadRoot = Join-Path $ToolkitRoot "downloads"
$SourceRoot = Join-Path $ToolkitRoot "sources"
$BinRoot = Join-Path $ToolkitRoot "bin"
$LockPath = Join-Path $PSScriptRoot "github_toolkit.lock.json"
$AuditEnvironment = Join-Path $ToolkitRoot "audit-venv"

function Assert-UnderToolkitRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolvedToolkitBase = [System.IO.Path]::GetFullPath($ToolkitRoot).TrimEnd("\")
    $resolvedToolkit = $resolvedToolkitBase + "\"
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $isRoot = $resolvedPath.Equals(
        $resolvedToolkitBase,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    $isChild = $resolvedPath.StartsWith(
        $resolvedToolkit,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    if (-not ($isRoot -or $isChild)) {
        throw "Refusing a developer-tool write outside $ToolkitRoot"
    }
}

function Get-VerifiedAsset {
    param([Parameter(Mandatory = $true)]$Asset)

    $destination = Join-Path $DownloadRoot ([string]$Asset.asset)
    $partial = "$destination.partial"
    Assert-UnderToolkitRoot $destination
    Assert-UnderToolkitRoot $partial

    $downloadNeeded = $ForceDownload -or -not (Test-Path -LiteralPath $destination)
    if (-not $downloadNeeded) {
        $actual = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        $downloadNeeded = $actual -ne ([string]$Asset.sha256).ToLowerInvariant()
    }
    if ($downloadNeeded) {
        if (Test-Path -LiteralPath $partial) {
            Remove-Item -LiteralPath $partial -Force
        }
        Write-Host "Downloading pinned $($Asset.id) $($Asset.version) from GitHub..."
        Invoke-WebRequest -UseBasicParsing -Uri ([string]$Asset.url) -OutFile $partial
        $actual = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
        $expected = ([string]$Asset.sha256).ToLowerInvariant()
        if ($actual -ne $expected) {
            Remove-Item -LiteralPath $partial -Force
            throw "SHA-256 mismatch for $($Asset.asset): expected $expected, received $actual"
        }
        Move-Item -LiteralPath $partial -Destination $destination -Force
    }

    $verified = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($verified -ne ([string]$Asset.sha256).ToLowerInvariant()) {
        throw "Cached $($Asset.asset) no longer matches its pinned SHA-256."
    }

    $extractRoot = Join-Path $SourceRoot "$($Asset.id)-$($Asset.version)"
    Assert-UnderToolkitRoot $extractRoot
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
    # Wheels and the release ZIPs are both ZIP containers. Expand-Archive checks
    # the filename extension, so give a wheel a local .zip alias before opening.
    $archivePath = $destination
    if ([System.IO.Path]::GetExtension($archivePath) -ne ".zip") {
        $archivePath = "$destination.zip"
        Assert-UnderToolkitRoot $archivePath
        Copy-Item -LiteralPath $destination -Destination $archivePath -Force
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot -Force

    foreach ($executable in $Asset.executables) {
        $matches = @(
            Get-ChildItem -LiteralPath $extractRoot -Recurse -File -Filter ([string]$executable)
        )
        if ($matches.Count -ne 1) {
            throw "Expected exactly one $executable in $($Asset.asset), found $($matches.Count)."
        }
        Copy-Item -LiteralPath $matches[0].FullName -Destination (Join-Path $BinRoot $executable) -Force
    }
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "This pinned toolkit manifest currently supports 64-bit Windows only."
}

$manifest = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
if ([int]$manifest.schema_version -ne 1) {
    throw "Unsupported GitHub toolkit lock schema."
}

foreach ($directory in @($ToolkitRoot, $DownloadRoot, $SourceRoot, $BinRoot)) {
    Assert-UnderToolkitRoot $directory
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

foreach ($asset in $manifest.github_assets) {
    Get-VerifiedAsset $asset
}

$uv = Join-Path $BinRoot "uv.exe"
$projectPython = Join-Path $RepoRoot "venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $projectPython)) {
    throw "Angerona's project Python was not found at $projectPython"
}

$auditPython = Join-Path $AuditEnvironment "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $auditPython)) {
    & $uv venv $AuditEnvironment --python $projectPython --no-project
    if ($LASTEXITCODE -ne 0) {
        throw "uv could not create the isolated audit environment."
    }
}

$requirements = @($manifest.python_tools | ForEach-Object { [string]$_.requirement })
& $uv pip install --python $auditPython --no-config @requirements
if ($LASTEXITCODE -ne 0) {
    throw "uv could not install the pinned audit tools."
}

Write-Host ""
Write-Host "Verified Angerona developer toolkit:"
& (Join-Path $BinRoot "uv.exe") --version
& (Join-Path $BinRoot "py-spy.exe") --version
& (Join-Path $BinRoot "hyperfine.exe") --version
& (Join-Path $BinRoot "gh.exe") --version
& $auditPython -m bandit --version
& $auditPython -m vulture --version
Write-Host "Location: $ToolkitRoot (development-only and ignored by Git)"
