"""Inert native repair storage admission; no Python install or host mutation."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows source repair storage admission")


LIBRARY = r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'Repair-Angerona-Python.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count) { throw ($issues|Out-String) }
foreach($definition in $ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
},$true)) { Invoke-Expression $definition.Extent.Text }
$root=Join-Path $env:ANGERONA_TEST_SCRATCH 'inert-root'
$venv=Join-Path $root 'venv'
[void][IO.Directory]::CreateDirectory($venv)
[IO.File]::WriteAllText((Join-Path $venv 'original'),'original fixture bytes')
$script:events=[Collections.Generic.List[string]]::new()
$script:scratchCreated=0;$script:candidateCalls=0
$script:freeBytes=5GB
function Assert-RepairBoundary {}
function Enter-RepairLease { return 'repository-lease' }
function Enter-CanonicalSourceHelperLease { return 'helper-lease' }
function Enter-CanonicalCoreMutationLease { return 'core-lease' }
function Exit-RepairLease { param($Lease) }
function Assert-NoActiveVenv {}
function Restore-InterruptedRepair { $script:events.Add('reconcile') }
function Get-RepairAvailableBytes { param($Path);$script:events.Add('capacity');return $script:freeBytes }
function New-PrivateRepairDirectory {
    param($Path);$script:scratchCreated++;[void][IO.Directory]::CreateDirectory($Path)
}
function Initialize-OwnedRepairProcess {}
function Write-RepairDiagnostic {}
function Write-DurableRepairJson { param($Path,$Value,[switch]$Replace) }
function Find-ReviewedPython { $script:events.Add('candidate');return 'inert-python.exe' }
function Find-TrustedWinget { throw 'A live installer must never be discovered.' }
function Invoke-RepairCommand { throw 'A native installation command must never execute.' }
function New-VerifiedRepairCandidate {
    param($Transaction);$script:candidateCalls++
    [void][IO.Directory]::CreateDirectory($Transaction.Stage)
    [IO.File]::WriteAllText((Join-Path $Transaction.Stage 'candidate'),'new inert fixture')
}
function New-PendingRepairIntent { param($Transaction) }
function Read-PendingRepairIntent {
    param($Root)
    # These storage-only fixtures replace journal/native identity tooling;
    # crash-safe journal and handle-bound rename have separate native tests.
    return [pscustomobject]@{Intent=[pscustomobject]@{OriginalId='original-id';CandidateId='candidate-id'}}
}
function Get-RepairDirectoryIdentity {
    param($Path)
    if([IO.File]::Exists((Join-Path $Path 'original'))){return 'original-id'}
    if([IO.File]::Exists((Join-Path $Path 'candidate'))){return 'candidate-id'}
    return ''
}
function Invoke-RepairDirectoryRename {param($From,$To,$ExpectedIdentity);[IO.Directory]::Move($From,$To)}
function Set-RepairIntentPhase { param($Pending,$Id,$Phase) }
function Repair-PromotedEnvironment { param($Transaction) }
"""


def run(tmp_path, body):
    environment = dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path),
                       ANGERONA_TEST_ROOT=str(ROOT), ANGERONA_TEST_SCRATCH=str(tmp_path))
    harness = tmp_path / "storage-fixture.ps1"
    harness.write_text("$ErrorActionPreference='Stop'\n" + LIBRARY + body, encoding="utf-8")
    return subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(harness)],
                          cwd=ROOT, env=environment, capture_output=True, text=True, timeout=35, check=False)


@pytest.mark.parametrize("case,expected", [
    ("low-space", "at least 5 GiB"),
    ("backup", "one full previous runtime"),
    ("two-transactions", "two transaction directories"),
    ("unknown", "unrecognized retained directory"),
    ("inventory", "eight retained entries"),
])
def test_storage_hold_precedes_scratch_candidate_download_or_promotion(tmp_path, case, expected):
    setup = {
        "low-space": "$script:freeBytes=5GB-1\n",
        "backup": r"""$backup=Join-Path $root ('venv.incompatible.repair.'+('a'*32))
[void][IO.Directory]::CreateDirectory($backup)
[IO.File]::WriteAllText((Join-Path $backup 'preserved'),'retained original')
""",
        "two-transactions": r"""foreach($id in @('a','b')) {
    [void][IO.Directory]::CreateDirectory((Join-Path $root ('.tmp\repair-wheels\startup-repair.'+($id*32))))
}
""",
        "unknown": r"""[void][IO.Directory]::CreateDirectory((Join-Path $root 'venv.incompatible.repair.unknown'))
""",
        "inventory": r"""foreach($id in 1..9) {
    [void][IO.Directory]::CreateDirectory((Join-Path $root ('venv.incompatible.repair.'+('{0:x32}' -f $id))))
}
""",
    }[case]
    result = run(tmp_path, setup + "$expected='" + expected + "'\n" + r"""
foreach($repeat in 1..2) {
    $held=$false
    try { [void](Invoke-RepairTransaction) } catch {
        $held=$_.Exception.Message.Contains($expected)
        if(!$held) { throw }
    }
    if(!$held) { throw 'The storage refusal was lost.' }
}
if($script:scratchCreated -or $script:candidateCalls -or $script:events.Contains('candidate')) {
    throw 'Storage hold admitted a new candidate, download or transaction scratch.'
}
if(([IO.File]::ReadAllText((Join-Path $venv 'original'))) -cne 'original fixture bytes') {
    throw 'Original runtime was changed.'
}
if(@($script:events|Where-Object {$_ -eq 'reconcile'}).Count -ne 2) {
    throw 'Existing transactions were not reconciled before storage admission.'
}
if($backup -and [IO.File]::ReadAllText((Join-Path $backup 'preserved')) -cne 'retained original') {
    throw 'Retained backup bytes were changed.'
}
Write-Output 'storage-held-with-originals-preserved'
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "storage-held-with-originals-preserved" in result.stdout


def test_five_gib_and_one_old_transaction_admit_only_inert_candidate(tmp_path):
    result = run(tmp_path, r"""
$prior=Join-Path $root ('.tmp\repair-wheels\startup-repair.'+('a'*32))
[void][IO.Directory]::CreateDirectory($prior)
[IO.File]::WriteAllText((Join-Path $prior 'preserved'),'old diagnostics')
$transaction=Invoke-RepairTransaction
try {
    if($script:candidateCalls -ne 1 -or $script:scratchCreated -ne 1) { throw 'Valid storage failed admission.' }
    if(($script:events -join ',') -cne 'reconcile,capacity,candidate') { throw 'Admission ordering changed.' }
    if(!(Test-Path -LiteralPath (Join-Path $venv 'candidate'))) { throw 'Inert candidate was not promoted.' }
    if([IO.File]::ReadAllText((Join-Path $transaction.Backup 'original')) -cne 'original fixture bytes') {
        throw 'Previous runtime was not preserved.'
    }
    $count=Get-RepairRetainedDirectoryCount (Join-Path $root '.tmp\repair-wheels') 'startup-repair.*' '^startup-repair\.[0-9a-f]{32}$'
    if($count -ne 2) { throw 'Transaction bound does not include the new attempt.' }
    if([IO.File]::ReadAllText((Join-Path $prior 'preserved')) -cne 'old diagnostics') { throw 'Old diagnostic changed.' }
} finally { Close-RepairSession $transaction }
""")
    assert result.returncode == 0, result.stdout + result.stderr


def test_pending_reconciliation_precedes_retained_backup_admission(tmp_path):
    result = run(tmp_path, r"""
$old=Join-Path $root ('venv.incompatible.repair.'+('a'*32))
[void][IO.Directory]::CreateDirectory($old)
[IO.File]::WriteAllText((Join-Path $old 'preserved'),'interrupted original')
function Restore-InterruptedRepair {
    $script:events.Add('reconcile')
    # Model the prior transaction restoring its original out of the backup
    # namespace before new storage admission. The real rollback has separate tests.
    Move-Item -LiteralPath $old -Destination (Join-Path $root 'reconciled-original')
}
$transaction=Invoke-RepairTransaction
try {
    if(($script:events -join ',') -cne 'reconcile,capacity,candidate') { throw 'Admission ran before reconciliation.' }
    if([IO.File]::ReadAllText((Join-Path $root 'reconciled-original\preserved')) -cne 'interrupted original') {
        throw 'Reconciled original disappeared.'
    }
} finally { Close-RepairSession $transaction }
""")
    assert result.returncode == 0, result.stdout + result.stderr
