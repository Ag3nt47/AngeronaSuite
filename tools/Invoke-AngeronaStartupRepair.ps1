[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RepositoryRoot,
    [Parameter(Mandatory=$true)][ValidateSet('Runtime','Dependencies','GuiRuntime')][string]$FailureCategory,
    [ValidateRange(1,1)][int]$Attempt = 1
)
$ErrorActionPreference = 'Stop'

function Assert-StartupRepairSupervisor([string]$RepositoryRoot) {
    $expectedRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
    if ([IO.Path]::GetFullPath($RepositoryRoot) -ne $expectedRoot) {
        throw 'Startup repair accepts only its own fixed source checkout.'
    }
    $expectedHost = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($hostPath -ne $expectedHost) { throw 'Startup repair requires fixed system Windows PowerShell.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $hostPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw 'System Windows PowerShell signature could not be verified.'
    }
    foreach ($path in @($expectedRoot, (Join-Path $expectedRoot 'Repair-Angerona-Python.ps1'),
            (Join-Path $expectedRoot 'tools\startup_repair_common.ps1'))) {
        $cursor = $path
        while ($cursor) {
            if (!(Test-Path -LiteralPath $cursor) -or
                (((Get-Item -LiteralPath $cursor -Force).Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'Startup repair source is missing or redirected.'
            }
            $cursor = [IO.Path]::GetDirectoryName($cursor)
        }
    }
}

function Invoke-StartupRepair {
    param([string]$RepositoryRoot,
        [ValidateSet('Runtime','Dependencies','GuiRuntime')][string]$FailureCategory,
        [ValidateRange(1,1)][int]$Attempt = 1)
    $transaction = $null
    try {
        Assert-StartupRepairSupervisor $RepositoryRoot
        . (Join-Path $RepositoryRoot 'Repair-Angerona-Python.ps1')
        Write-Host "[startup-repair] failed-check=$FailureCategory attempt=$Attempt tool=Repair-Angerona-Python.ps1"
        $transaction = Invoke-RepairTransaction
        Write-Host '[startup-repair] tool-result=completed; independent-recheck=running'
        if (Get-Command -Name Write-RepairDiagnostic -CommandType Function -ErrorAction SilentlyContinue) {
            Write-RepairDiagnostic 'supervisor' 'independent-recheck' 'Runtime transaction returned; independent final-path verification starts.'
        }
        Test-RepairedRuntime $venv $transaction.Stage
        Complete-RepairTransaction $transaction
        Write-Host '[startup-repair] independent-recheck=verified; retry remains Chill'
        return 0
    } catch {
        $failure = $_
        if (Get-Command -Name Write-RepairDiagnostic -CommandType Function -ErrorAction SilentlyContinue) {
            Write-RepairDiagnostic 'supervisor' 'failed-or-unverified' $failure.Exception.Message
        }
        if ($transaction -and !$transaction.Closed) {
            try { Undo-RepairTransaction $transaction } catch {
                if (Get-Command -Name Write-RepairDiagnostic -CommandType Function -ErrorAction SilentlyContinue) {
                    Write-RepairDiagnostic 'supervisor-rollback' 'failed-or-refused' $_.Exception.Message
                }
                Write-Host "[startup-repair] rollback-refused=$($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host "[startup-repair] result=failed-or-unverified; $($failure.Exception.Message)" -ForegroundColor Red
        return 1
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-StartupRepair -RepositoryRoot $RepositoryRoot -FailureCategory $FailureCategory -Attempt $Attempt)
}
