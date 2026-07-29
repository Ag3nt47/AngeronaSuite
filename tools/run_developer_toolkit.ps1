[CmdletBinding(DefaultParameterSetName = "Audit")]
param(
    [Parameter(ParameterSetName = "Audit")]
    [switch]$Audit,

    [Parameter(Mandatory = $true, ParameterSetName = "Profile")]
    [switch]$Profile,

    [Parameter(Mandatory = $true, ParameterSetName = "Profile")]
    [ValidateRange(1, 86400)]
    [int]$TargetProcessId,

    [Parameter(ParameterSetName = "Profile")]
    [ValidateRange(1, 300)]
    [int]$DurationSeconds = 30,

    [Parameter(Mandatory = $true, ParameterSetName = "Benchmark")]
    [switch]$Benchmark,

    [Parameter(Mandatory = $true, ParameterSetName = "Benchmark")]
    [ValidateNotNullOrEmpty()]
    [string]$Command,

    [Parameter(ParameterSetName = "Benchmark")]
    [ValidateRange(2, 100)]
    [int]$Runs = 5
)

$ErrorActionPreference = "Stop"
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ToolkitRoot = Join-Path $RepoRoot ".dev-tools"
$BinRoot = Join-Path $ToolkitRoot "bin"
$OutputRoot = Join-Path $RepoRoot ".tmp\developer-toolkit"
$AuditPython = Join-Path $ToolkitRoot "audit-venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath (Join-Path $BinRoot "uv.exe"))) {
    throw "Run tools\bootstrap_github_toolkit.ps1 first."
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

if ($PSCmdlet.ParameterSetName -eq "Profile") {
    $pySpy = Join-Path $BinRoot "py-spy.exe"
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $output = Join-Path $OutputRoot "angerona-$TargetProcessId-$stamp.speedscope.json"
    & $pySpy record --pid $TargetProcessId --duration $DurationSeconds --format speedscope --output $output
    if ($LASTEXITCODE -ne 0) {
        throw "py-spy could not attach. On Windows, run this terminal as Administrator."
    }
    Write-Host "Profile written to $output"
    exit 0
}

if ($PSCmdlet.ParameterSetName -eq "Benchmark") {
    $hyperfine = Join-Path $BinRoot "hyperfine.exe"
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $output = Join-Path $OutputRoot "benchmark-$stamp.json"
    & $hyperfine --warmup 1 --runs $Runs --export-json $output $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark command failed."
    }
    Write-Host "Benchmark written to $output"
    exit 0
}

$banditOutput = Join-Path $OutputRoot "bandit.json"
$vultureOutput = Join-Path $OutputRoot "vulture.txt"

# Audits are evidence-producing by default. Findings do not prevent the second
# tool from running; callers decide which findings are actionable.
# Medium/high findings are the actionable review queue. Bandit's low tier is
# dominated here by assert statements in embedded self-tests and intentional
# best-effort telemetry fallbacks, obscuring stronger signals.
& $AuditPython -m bandit -r (Join-Path $RepoRoot "src") -ll -f json -o $banditOutput
$banditExit = $LASTEXITCODE
& $AuditPython -m vulture (Join-Path $RepoRoot "src") --min-confidence 90 |
    Out-File -LiteralPath $vultureOutput -Encoding utf8
$vultureExit = $LASTEXITCODE

Write-Host "Bandit report: $banditOutput (exit $banditExit)"
Write-Host "Vulture report: $vultureOutput (exit $vultureExit)"
