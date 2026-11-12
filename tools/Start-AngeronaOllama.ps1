<#
.SYNOPSIS
  Prepare the local Ollama service for Angerona: update it, bind it to
  loopback, start it, and wait until its API really answers.

.DESCRIPTION
  Angerona only uses an Ollama listener it can bind to one trusted process on
  127.0.0.1. Two host conditions defeat that:
    * OLLAMA_HOST set to 0.0.0.0 / [::] (a wildcard listener, also reachable
      from the network without authentication), and
    * a cold start whose GPU discovery keeps the API silent for minutes,
      far beyond Angerona's own startup budget.
  This script starts the signed Ollama image on loopback and waits (default
  seven minutes) for /api/version before Angerona is launched.

  Nothing is downloaded by this script itself. The optional update step asks
  winget to upgrade the official Ollama.Ollama package and re-verifies the
  publisher signature afterwards.

.PARAMETER WaitSeconds     How long to wait for the API (30-1800, default 420).
.PARAMETER SkipUpdate      Do not check for an Ollama update.
.PARAMETER FixHostBinding  Persist OLLAMA_HOST=127.0.0.1:11434 for this user
                           when the stored value is a wildcard address.
.PARAMETER LaunchAngerona  Run start-angerona.bat after Ollama is ready.
#>
[CmdletBinding()]
param(
    [ValidateRange(30, 1800)][int]$WaitSeconds = 420,
    [switch]$SkipUpdate,
    [switch]$FixHostBinding,
    [switch]$LaunchAngerona
)
$ErrorActionPreference = 'Stop'
$Loopback = '127.0.0.1:11434'
$Repo = Split-Path -Parent $PSScriptRoot

$diag = Join-Path $env:LOCALAPPDATA 'Angerona\SourceData\diagnostics'
if (-not (Test-Path -LiteralPath $diag -PathType Container)) { $diag = $env:TEMP }
$Log = Join-Path $diag 'ollama-launch.log'
function Write-Step([string]$Text, [string]$Color = 'Gray') {
    $line = '[{0}] {1}' -f (Get-Date -Format 's'), $Text
    Write-Host $line -ForegroundColor $Color
    try { Add-Content -LiteralPath $Log -Value $line -Encoding UTF8 } catch { }
}

function Find-OllamaExe {
    $found = @()
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{44E83376-CE68-45EB-8FC1-393500EB558C}_is1',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{44E83376-CE68-45EB-8FC1-393500EB558C}_is1'
    )
    foreach ($key in $keys) {
        try {
            $dir = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).InstallLocation
            if ($dir) { $found += (Join-Path $dir.Trim('"') 'ollama.exe') }
        } catch { }
    }
    $found += (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe')
    $found += (Join-Path $env:ProgramFiles 'Ollama\ollama.exe')
    foreach ($candidate in $found) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Get-Item -LiteralPath $candidate).FullName
        }
    }
    return $null
}

function Test-OllamaSignature([string]$Path) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate) { return $false }
    $name = $sig.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    return [string]::Equals($name, 'Ollama Inc.', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-Wildcard([string]$Value) {
    if (-not $Value) { return $false }
    $v = $Value.Trim().ToLowerInvariant() -replace '^https?://', ''
    return ($v -match '^(0\.0\.0\.0|\[::\]|::|\*)(:\d+)?/?$')
}

function Get-OllamaVersion {
    try {
        $r = Invoke-RestMethod -Uri "http://$Loopback/api/version" -TimeoutSec 5 -Method Get
        if ($r.version) { return [string]$r.version }
    } catch { }
    return $null
}

function Stop-InstalledOllama([string]$InstallDir) {
    # Only processes whose image lives in the verified install directory.
    $prefix = $InstallDir.TrimEnd('\') + '\'
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
    } | ForEach-Object {
        Write-Step ("Stopping {0} (pid {1})" -f $_.ProcessName, $_.Id)
        try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch { Write-Step "  could not stop: $($_.Exception.Message)" 'Yellow' }
    }
    Start-Sleep -Seconds 2
}

Write-Step '--- Angerona Ollama preparation ---' 'Cyan'
$exe = Find-OllamaExe
if (-not $exe) { Write-Step 'Ollama is not installed in a registered or standard location.' 'Red'; exit 2 }
if (-not (Test-OllamaSignature $exe)) { Write-Step "Refusing unsigned or non-Ollama image: $exe" 'Red'; exit 3 }
$installDir = Split-Path -Parent $exe
Write-Step "Ollama image: $exe (publisher signature valid)"

# 1. Host binding ------------------------------------------------------------
$stored = [Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'User')
$machine = [Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'Machine')
$mustRestart = $false
if (Test-Wildcard $stored) {
    Write-Step "User OLLAMA_HOST is '$stored': the API is exposed on every network interface." 'Yellow'
    if ($FixHostBinding) {
        [Environment]::SetEnvironmentVariable('OLLAMA_HOST', $Loopback, 'User')
        Write-Step "User OLLAMA_HOST set to $Loopback." 'Green'
    } else {
        Write-Step 'Re-run with -FixHostBinding to make loopback permanent. This run uses loopback only for the process it starts.' 'Yellow'
    }
    $mustRestart = $true
}
if (Test-Wildcard $machine) {
    Write-Step "Machine-level OLLAMA_HOST is '$machine'. Change it from an elevated prompt; this script does not." 'Yellow'
    $mustRestart = $true
}
$env:OLLAMA_HOST = $Loopback

# 2. Update ------------------------------------------------------------------
if (-not $SkipUpdate) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Step 'Checking for an Ollama update through winget...'
        $listing = (& $winget.Source list --id Ollama.Ollama -e --upgrade-available --accept-source-agreements 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0 -and $listing -match 'Ollama\.Ollama') {
            Write-Step 'Update available; stopping Ollama and upgrading.' 'Cyan'
            Stop-InstalledOllama $installDir
            & $winget.Source upgrade --id Ollama.Ollama -e --silent --accept-source-agreements --accept-package-agreements 2>&1 |
                ForEach-Object { Write-Step "  winget: $_" }
            $exe = Find-OllamaExe
            if (-not $exe -or -not (Test-OllamaSignature $exe)) {
                Write-Step 'Ollama image failed signature verification after the update.' 'Red'; exit 4
            }
            $installDir = Split-Path -Parent $exe
            # The installer may start its own tray app with the stored host value.
            $mustRestart = $true
            Write-Step "Update finished. Image: $exe" 'Green'
        } else {
            Write-Step 'No Ollama update is offered.'
        }
    } else {
        Write-Step 'winget is unavailable; update check skipped.' 'Yellow'
    }
}

# 3. Start on loopback -------------------------------------------------------
$version = Get-OllamaVersion
if ($mustRestart -or -not $version) {
    if ($mustRestart) { Stop-InstalledOllama $installDir }
    if (-not (Get-OllamaVersion)) {
        Write-Step "Starting 'ollama serve' on $Loopback."
        Start-Process -FilePath $exe -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
    }
}

# 4. Wait for a real answer --------------------------------------------------
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$version = $null
$next = Get-Date
while ((Get-Date) -lt $deadline) {
    $version = Get-OllamaVersion
    if ($version) { break }
    if ((Get-Date) -ge $next) {
        $left = [int]($deadline - (Get-Date)).TotalSeconds
        Write-Step "Waiting for the Ollama API (GPU discovery can take minutes)... ${left}s left"
        $next = (Get-Date).AddSeconds(30)
    }
    Start-Sleep -Seconds 3
}
if (-not $version) {
    Write-Step "Ollama did not answer on $Loopback within $WaitSeconds seconds. See $env:LOCALAPPDATA\Ollama\server.log" 'Red'
    exit 5
}
Write-Step "Ollama $version is answering on $Loopback." 'Green'

$wild = Get-NetTCPConnection -State Listen -LocalPort 11434 -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -in @('0.0.0.0', '::') }
if ($wild) {
    Write-Step 'A wildcard listener is still present on port 11434; Angerona will refuse it.' 'Yellow'
}

# 5. Hand over ---------------------------------------------------------------
$env:ANGERONA_OLLAMA_STARTUP_SECONDS = '120'
if ($LaunchAngerona) {
    $start = Join-Path $Repo 'start-angerona.bat'
    if (Test-Path -LiteralPath $start -PathType Leaf) {
        Write-Step 'Launching Angerona.' 'Cyan'
        & $env:ComSpec /c "`"$start`""
    } else {
        Write-Step "start-angerona.bat not found in $Repo" 'Red'; exit 6
    }
}
exit 0
