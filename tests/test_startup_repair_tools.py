from __future__ import annotations

import os
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
    r"System32\WindowsPowerShell\v1.0\powershell.exe"
)
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows repair tooling")


def _run(script: str, scratch: Path, *, timeout: int = 40) -> subprocess.CompletedProcess[str]:
    # Set these before PowerShell, native compilation, or any child starts.
    environment = dict(os.environ, TEMP=str(scratch), TMP=str(scratch))
    environment["ANGERONA_TEST_ROOT"] = str(ROOT)
    environment["ANGERONA_TEST_SCRATCH"] = str(scratch)
    environment["ANGERONA_TEST_PYTHON"] = sys.executable
    script_path = scratch / "harness.ps1"
    script_path.write_text("$ErrorActionPreference = 'Stop'\n" + script, encoding="utf-8")
    return subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script_path)],
        cwd=ROOT, env=environment, text=True, capture_output=True, timeout=timeout,
        check=False,
    )


LIBRARY = r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
Initialize-OwnedRepairProcess
$tokens = $null; $issues = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'Repair-Angerona-Python.ps1'),
    [ref]$tokens, [ref]$issues)
if ($issues.Count) { throw ($issues | Out-String) }
foreach ($function in $ast.FindAll({
    param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
}, $true)) { Invoke-Expression $function.Extent.Text }
$root = Join-Path $env:ANGERONA_TEST_SCRATCH 'fixture'
$venv = Join-Path $root 'venv'
[void][IO.Directory]::CreateDirectory($venv)
[IO.File]::WriteAllText((Join-Path $venv 'identity'), 'old-environment')
New-PrivateRepairDirectory (Join-Path $root 'SourceData')
function Assert-RepairBoundary {}
function Assert-NoActiveVenv {}
function Get-CanonicalSourceStartupStorage { return (Join-Path $root 'SourceData') }
function Find-ReviewedPython { return 'fixture-signed-python.exe' }
function Find-TrustedWinget { throw 'Test must not invoke installer discovery.' }
function Invoke-RepairCommand { throw 'Test must not execute an installation command.' }
function New-VerifiedRepairCandidate($Transaction) {
    if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne 'old-environment') {
        throw 'Old environment moved before candidate verification.'
    }
    [void][IO.Directory]::CreateDirectory($Transaction.Stage)
    [IO.File]::WriteAllText((Join-Path $Transaction.Stage 'identity'), 'new-environment')
    if ($env:ANGERONA_TEST_CASE -eq 'candidate-failure') { throw 'Injected candidate verification failure.' }
}
function Repair-PromotedEnvironment($Transaction) {
    if ([IO.File]::ReadAllText((Join-Path $Transaction.Backup 'identity')) -ne 'old-environment') {
        throw 'Previous environment was not preserved during promotion.'
    }
    if ($env:ANGERONA_TEST_CASE -eq 'refresh-failure') { throw 'Injected final-path refresh failure.' }
}
"""


@pytest.mark.parametrize("case", ["success", "candidate-failure", "refresh-failure", "recheck-failure"])
def test_transaction_stages_first_and_restores_previous_runtime(tmp_path: Path, case: str) -> None:
    script = LIBRARY + f"\n$env:ANGERONA_TEST_CASE = '{case}'\n" + r"""
$beforeTemp = $env:TEMP; $beforeTmp = $env:TMP
$transaction = $null; $failed = $false; $failureMessage = ''
try {
    $transaction = Invoke-RepairTransaction
    if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne 'new-environment') {
        throw 'Verified candidate was not promoted.'
    }
    if ($env:ANGERONA_TEST_CASE -eq 'recheck-failure') { throw 'Injected independent verification failure.' }
    Complete-RepairTransaction $transaction
} catch {
    $failed = $true
    $failureMessage = $_.Exception.Message
    if ($transaction -and !$transaction.Closed) { Undo-RepairTransaction $transaction }
}
$expected = if ($env:ANGERONA_TEST_CASE -eq 'success') { 'new-environment' } else { 'old-environment' }
if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne $expected) { throw 'Rollback/promotion mismatch.' }
if ($failed -ne ($env:ANGERONA_TEST_CASE -ne 'success')) { throw 'Unexpected transaction result.' }
if ($failed -and $failureMessage -notmatch 'Injected') { throw "Unexpected failure: $failureMessage" }
if ($env:TEMP -ne $beforeTemp -or $env:TMP -ne $beforeTmp) { throw 'Caller temporary environment was not restored.' }
$lease = Enter-RepairLease -Root $root
Exit-RepairLease $lease
if ($env:ANGERONA_TEST_CASE -eq 'success') {
    if (!(Test-Path -LiteralPath $transaction.Backup)) { throw 'Successful repair lost the old environment.' }
    if (Test-Path -LiteralPath $transaction.Scratch) { throw 'Successful repair left owned staging files.' }
}
Write-Output 'transaction-verified'
"""
    result = _run(script, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "transaction-verified" in result.stdout


def test_missing_trusted_runtime_fails_before_any_existing_venv_move(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
function Find-ReviewedPython { return $null }
function Find-TrustedWinget { return $null }
$failed = $false
try { [void](Invoke-RepairTransaction) } catch { $failed = $_.Exception.Message -match 'unavailable' }
if (!$failed) { throw 'Missing trusted runtime was not refused.' }
if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne 'old-environment') { throw 'Old runtime was changed.' }
if (Get-ChildItem -LiteralPath $root -Filter 'venv.incompatible.*') { throw 'Old runtime moved before trusted artifacts existed.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_active_runtime_refuses_repair_without_staging_or_promotion(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
function Assert-NoActiveVenv { throw 'Active helper runtime.' }
function New-PrivateRepairDirectory { throw 'Scratch must not be created for active runtime.' }
$failed = $false
try { [void](Invoke-RepairTransaction) } catch { $failed = $_.Exception.Message -match 'Active helper' }
if (!$failed) { throw 'Active helper exclusion failed.' }
if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne 'old-environment') { throw 'Active runtime changed.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_process_scan_refuses_live_venv_and_uninspectable_python(tmp_path: Path) -> None:
    result = _run(r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$target = Join-Path $env:ANGERONA_TEST_SCRATCH 'venv'
function Get-CimInstance {
    [pscustomobject]@{ ExecutablePath = (Join-Path $target 'Scripts\python.exe'); Name='python.exe'; ProcessId=123 }
}
$failed = $false
try { Assert-NoActiveVenv $target } catch { $failed = $_.Exception.Message -match 'still active' }
if (!$failed) { throw 'Active helper was not detected.' }
function Get-CimInstance { [pscustomobject]@{ ExecutablePath=$null; Name='python.exe'; ProcessId=124 } }
$failed = $false
try { Assert-NoActiveVenv $target } catch { $failed = $_.Exception.Message -match 'could not be inspected' }
if (!$failed) { throw 'Unknown runtime identity did not fail closed.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_signature_and_artifact_hash_refusal_never_executes_untrusted_bytes(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
$fake = Join-Path $root 'untrusted.exe'; [IO.File]::WriteAllText($fake, 'untrusted')
function Get-AuthenticodeSignature {
    [pscustomobject]@{ Status='HashMismatch'; SignerCertificate=[pscustomobject]@{Subject='O=Python Software Foundation'} }
}
if (Test-ReviewedPython $fake) { throw 'Invalid PSF signature accepted.' }
function Get-AppxPackage { [pscustomobject]@{ Version='1.0'; InstallLocation=$root } }
[IO.File]::WriteAllText((Join-Path $root 'winget.exe'), 'untrusted')
Invoke-Expression ($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Find-TrustedWinget'
}, $true)[0].Extent.Text)
if (Find-TrustedWinget) { throw 'Invalid Microsoft signature accepted.' }
$artifacts = Join-Path $root 'artifacts'; [void][IO.Directory]::CreateDirectory($artifacts)
[IO.File]::WriteAllText((Join-Path $artifacts 'untrusted-1-py3-none-any.whl'), 'wrong-bytes')
$hashes = @{('0' * 64)=$true}
$failed = $false
try { Assert-RepairArtifactHashes $artifacts $hashes } catch { $failed = $_.Exception.Message -match 'Unreviewed artifact' }
if (!$failed) { throw 'An artifact with the wrong SHA256 was accepted.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_missing_cache_and_pinned_network_failure_never_promotes_runtime(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
$lock = Join-Path $root 'lock.txt'
[IO.File]::WriteAllText($lock, ('example==1.0 \' + [Environment]::NewLine + '    --hash=sha256:' + ('0' * 64)))
$script:commands = [Collections.Generic.List[object]]::new()
function Invoke-RepairCommand {
    param($Executable, $Arguments, $Label, $TimeoutSeconds, [switch]$AllowFailure)
    $script:commands.Add($Arguments)
    if ($AllowFailure) { return 1 }
    throw 'Pinned network artifacts unavailable.'
}
$failed = $false
try { Get-LockedRepairArtifacts 'fake.exe' $lock (Join-Path $root 'download') }
catch { $failed = $_.Exception.Message -match 'unavailable' }
if (!$failed -or $script:commands.Count -ne 2) { throw 'Missing cache/network was not bounded.' }
foreach ($command in $script:commands) {
    if ('--require-hashes' -notin $command -or '--no-deps' -notin $command) { throw 'Verification flags were weakened.' }
}
if ('--no-index' -notin $script:commands[0] -or 'https://pypi.org/simple' -notin $script:commands[1]) {
    throw 'Cache-first fixed-network fallback contract failed.'
}
if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne 'old-environment') { throw 'Old environment changed.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_repair_lease_conflicts_and_private_environment_excludes_inherited_controls(tmp_path: Path) -> None:
    result = _run(r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$root = $env:ANGERONA_TEST_SCRATCH
$first = Enter-RepairLease $root
$rejected = $false
try { $second = Enter-RepairLease $root } catch { $rejected = $true }
Exit-RepairLease $first
if (!$rejected) { if ($second) { Exit-RepairLease $second }; throw 'Concurrent repair lease was accepted.' }
$third = Enter-RepairLease $root; Exit-RepairLease $third
$private = Join-Path $root 'private'; New-PrivateRepairDirectory $private
$env:PYTHONPATH='attacker'; $env:QT_PLUGIN_PATH='attacker'; $env:ANGERONA_CORE_CMD='attacker'
$child = New-RepairChildEnvironment $private
foreach ($name in @('PYTHONPATH','QT_PLUGIN_PATH','ANGERONA_CORE_CMD','OPENAI_API_KEY','OLLAMA_HOST')) {
    if ($child.ContainsKey($name)) { throw "Inherited control leaked: $name" }
}
if ($child.TEMP -ne $private -or $child.TMP -ne $private) { throw 'Scratch did not stay on owned volume.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_hardlinked_lease_refuses_without_initializing_operator_file(tmp_path: Path) -> None:
    sentinel = tmp_path / "operator-file"
    sentinel.write_bytes(b"")
    parent = tmp_path / ".tmp" / "repair-wheels"
    parent.mkdir(parents=True)
    os.link(sentinel, parent / "startup-repair.lock")
    result = _run(r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$refused=$false
try { $lease=Enter-RepairLease $env:ANGERONA_TEST_SCRATCH; Exit-RepairLease $lease }
catch { $refused=$_.Exception.Message -match 'multiple links' }
if (!$refused) { throw 'A hardlinked lease was not refused.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.read_bytes() == b""


def test_transaction_deadline_refuses_before_starting_another_command(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
Invoke-Expression ($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-RepairCommand'
}, $true)[0].Extent.Text)
$script:RepairClock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=901}}
function Invoke-OwnedRepairProcess { throw 'Expired transaction executed another command.' }
$refused=$false
try { [void](Invoke-RepairCommand 'never-execute.exe' @() 'deadline check') }
catch { $refused=$_.Exception.Message -match '900-second.*deadline expired' }
if (!$refused) { throw 'Expired overall repair budget was not enforced.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_owned_native_command_logs_return_code_and_kills_only_timed_out_descendants(tmp_path: Path) -> None:
    grandchild = tmp_path / "grandchild.ps1"
    grandchild.write_text("Start-Sleep -Seconds 20\n", encoding="utf-8")
    parent = tmp_path / "parent.ps1"
    parent.write_text(
        "$image=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\\v1.0\\powershell.exe'\n"
        "$child=Start-Process -FilePath $image -WindowStyle Hidden -PassThru -ArgumentList "
        "@('-NoProfile','-NonInteractive','-File', ('\"' + (Join-Path $env:TEMP 'grandchild.ps1') + '\"'))\n"
        "[IO.File]::WriteAllText((Join-Path $env:TEMP 'child.pid'), [string]$child.Id)\n"
        "Start-Sleep -Seconds 20\n", encoding="utf-8",
    )
    result = _run(r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$scratch = $env:ANGERONA_TEST_SCRATCH
$image = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$child = New-RepairChildEnvironment $scratch
$code = Invoke-OwnedRepairProcess -FilePath $image -Arguments @('-NoProfile','-NonInteractive','-Command',
    "[Console]::WriteLine('owned-runner-ok'); exit 42") -WorkingDirectory $scratch -Environment $child `
    -TimeoutSeconds 15 -LogPath (Join-Path $scratch 'success.log')
if ($code -ne 42 -or [IO.File]::ReadAllText((Join-Path $scratch 'success.log')) -notmatch 'owned-runner-ok') {
    throw 'Native command result/log contract failed.'
}
$timedOut = $false
try {
    [void](Invoke-OwnedRepairProcess -FilePath $image -Arguments @('-NoProfile','-NonInteractive','-File',
        (Join-Path $scratch 'parent.ps1')) -WorkingDirectory $scratch -Environment $child `
        -TimeoutSeconds 3 -LogPath (Join-Path $scratch 'timeout.log'))
} catch { $timedOut = $_.Exception.ToString() -match 'deadline' }
if (!$timedOut) { throw 'Owned command was not bounded.' }
$childId = [int][IO.File]::ReadAllText((Join-Path $scratch 'child.pid'))
$alive = $null
try { $alive = [Diagnostics.Process]::GetProcessById($childId) } catch {}
if ($alive -and !$alive.WaitForExit(5000)) { throw 'Timed-out owned descendant survived its job.' }
if ([Diagnostics.Process]::GetCurrentProcess().HasExited) { throw 'Caller was terminated.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_powershell_parse_and_closed_public_repair_contract(tmp_path: Path) -> None:
    result = _run(r"""
foreach ($name in @('Repair-Angerona-Python.ps1','tools\Invoke-AngeronaStartupRepair.ps1',
        'tools\startup_repair_common.ps1')) {
    $tokens=$null; $issues=$null
    [void][Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $env:ANGERONA_TEST_ROOT $name), [ref]$tokens, [ref]$issues)
    if ($issues.Count) { throw ($issues | Out-String) }
}
$tokens=$null; $issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Invoke-AngeronaStartupRepair.ps1'), [ref]$tokens, [ref]$issues)
if (($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') -ne 'RepositoryRoot,FailureCategory,Attempt') {
    throw 'Repair supervisor exposes an unreviewed command/input hook.'
}
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("verified", [True, False])
def test_supervisor_returns_success_only_after_independent_verification(tmp_path: Path, verified: bool) -> None:
    # Exercise the real supervisor function against a library fixture. No
    # runtime/import/installer discovery reaches the host or checkout venv.
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "Repair-Angerona-Python.ps1").write_text(r"""
$venv = Join-Path $root 'venv'
function Invoke-RepairTransaction {
    $script:repairCalls++
    return [pscustomobject]@{Closed=$false;Stage='fixture-stage'}
}
function Test-RepairedRuntime {
    $script:verifyCalls++
    if ($env:ANGERONA_TEST_VERIFIED -ne '1') { throw 'Independent verification failed.' }
}
function Complete-RepairTransaction($Transaction) { $script:completeCalls++; $Transaction.Closed=$true }
function Undo-RepairTransaction($Transaction) { $script:rollbackCalls++; $Transaction.Closed=$true }
""", encoding="utf-8")
    script = f"$env:ANGERONA_TEST_VERIFIED = '{int(verified)}'\n" + r"""
$tokens=$null; $issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Invoke-AngeronaStartupRepair.ps1'), [ref]$tokens, [ref]$issues)
foreach ($function in $ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
}, $true)) { Invoke-Expression $function.Extent.Text }
function Assert-StartupRepairSupervisor {}
$root=Join-Path $env:ANGERONA_TEST_SCRATCH 'fixture'
$script:repairCalls=0; $script:verifyCalls=0; $script:completeCalls=0; $script:rollbackCalls=0
$code=Invoke-StartupRepair -RepositoryRoot $root -FailureCategory GuiRuntime -Attempt 1
if ($script:repairCalls -ne 1 -or $script:verifyCalls -ne 1) { throw 'Supervisor did not repair/recheck exactly once.' }
if ($env:ANGERONA_TEST_VERIFIED -eq '1') {
    if ($code -ne 0 -or $script:completeCalls -ne 1 -or $script:rollbackCalls -ne 0) { throw 'Verified recovery contract failed.' }
} else {
    if ($code -eq 0 -or $script:completeCalls -ne 0 -or $script:rollbackCalls -ne 1) { throw 'Unverified recovery was not rolled back.' }
}
"""
    result = _run(script, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_final_path_scaffold_recreation_replaces_staged_activation_paths(tmp_path: Path) -> None:
    # No pip, dependency installation, or operator environment is used. This
    # proves CPython's real scaffold behavior on an isolated empty venv.
    candidate, final = tmp_path / "candidate", tmp_path / "final"
    environment = dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path))
    for target in (candidate, final):
        result = subprocess.run(
            [sys.executable, "-I", "-m", "venv", "--copies", "--without-pip", str(target)],
            env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        activation = (target / "Scripts" / "activate.bat").read_text(encoding="utf-8")
        assert str(target) in activation
        if target == candidate:
            candidate.rename(final)
        else:
            assert str(candidate) not in activation


RECOVERY_LIBRARY = LIBRARY.split("$root = Join-Path")[0] + r"""
$root = Join-Path $env:ANGERONA_TEST_SCRATCH 'fixture'
$venv = Join-Path $root 'venv'
function Assert-RepairBoundary {}
function Assert-NoActiveVenv {}
function Get-CanonicalSourceStartupStorage { return (Join-Path $root 'SourceData') }
"""


def _crash_transaction(scratch: Path, phase: str = "during-refresh") -> Path:
    script = LIBRARY + f"\n$env:ANGERONA_TEST_FAULT = '{phase}'\n" + r"""
function Move-Item {
    param($LiteralPath, $Destination)
    [IO.Directory]::Move($LiteralPath, $Destination)
    if (($env:ANGERONA_TEST_FAULT -eq 'after-backup' -and $LiteralPath -eq $venv) -or
        ($env:ANGERONA_TEST_FAULT -eq 'after-promotion' -and $Destination -eq $venv)) {
        [Environment]::Exit(99)
    }
}
function Repair-PromotedEnvironment($Transaction) {
    if ($env:ANGERONA_TEST_FAULT -eq 'during-refresh') { [Environment]::Exit(99) }
}
[void](Invoke-RepairTransaction)
throw 'Fault injection was not reached.'
"""
    result = _run(script, scratch)
    assert result.returncode == 99, result.stdout + result.stderr
    pending = scratch / "fixture" / ".tmp" / "repair-wheels" / "startup-repair.pending"
    assert (pending / "intent.json").is_file()
    return pending


@pytest.mark.parametrize("phase", ["after-backup", "after-promotion", "during-refresh"])
def test_real_process_exit_at_each_rename_and_refresh_restores_original_before_execution(
    tmp_path: Path, phase: str,
) -> None:
    pending = _crash_transaction(tmp_path, phase)
    intent = json.loads((pending / "intent.json").read_text(encoding="utf-8"))
    backup = Path(intent["Backup"])
    assert (backup / "identity").read_text() == "old-environment"
    script = RECOVERY_LIBRARY + r"""
$gated=$false
try { Assert-NoPendingRepair $root } catch { $gated=$_.Exception.Data['AngeronaRepairPending'] -eq $true }
if (!$gated) { throw 'A valid interrupted repair was not gated before runtime execution.' }
$checkout=Enter-RepairLease $root
$helper=Enter-CanonicalSourceHelperLease
try { Restore-InterruptedRepair } finally { Exit-RepairLease $helper; Exit-RepairLease $checkout }
Assert-NoPendingRepair $root
if ([IO.File]::ReadAllText((Join-Path $venv 'identity')) -ne 'old-environment') { throw 'Original runtime was not restored.' }
"""
    result = _run(script, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not pending.exists()
    assert (tmp_path / "fixture" / "venv" / "identity").read_text() == "old-environment"
    assert (Path(intent["Scratch"]) / "resolution.json").is_file()


@pytest.mark.parametrize("tamper", [
    "missing-intent", "corrupt-intent", "changed-path", "changed-identity", "changed-marker",
    "missing-marker", "hardlinked-intent", "missing-pending", "missing-pending-and-marker",
    "foreign-directory",
])
def test_ambiguous_or_tampered_interrupted_repair_refuses_and_preserves_every_environment(
    tmp_path: Path, tamper: str,
) -> None:
    pending = _crash_transaction(tmp_path)
    intent_path = pending / "intent.json"
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    target, backup = Path(intent["Venv"]), Path(intent["Backup"])
    marker = target / ".angerona-startup-repair.json"
    if tamper == "missing-intent":
        intent_path.unlink()
    elif tamper == "corrupt-intent":
        intent_path.write_text("{", encoding="utf-8")
    elif tamper in {"changed-path", "changed-identity"}:
        changed = dict(intent)
        if tamper == "changed-path":
            changed["Backup"] = str(tmp_path / "unrelated-environment")
        else:
            changed["CandidateId"] = "00000000:0000000000000000"
        intent_path.write_text(json.dumps(changed), encoding="utf-8")
    elif tamper == "changed-marker":
        marker.write_text("changed", encoding="utf-8")
    elif tamper == "missing-marker":
        marker.unlink()
    elif tamper == "hardlinked-intent":
        os.link(intent_path, pending / "extra-link")
    elif tamper in {"missing-pending", "missing-pending-and-marker"}:
        # Delete only this exact fresh fault-injection fixture's intent files.
        assert pending.is_relative_to(tmp_path)
        for file in pending.iterdir():
            assert file.is_file()
            file.unlink()
        pending.rmdir()
        if tamper == "missing-pending-and-marker":
            marker.unlink()
    elif tamper == "foreign-directory":
        target.rename(tmp_path / "preserved-unknown-candidate")
        target.mkdir()
        (target / "identity").write_text("foreign-environment")
    before = (target / "identity").read_bytes()
    result = _run(RECOVERY_LIBRARY + r"""
$checkout=Enter-RepairLease $root
$helper=Enter-CanonicalSourceHelperLease
$refused=$false
try { Restore-InterruptedRepair } catch { $refused=$true }
finally { Exit-RepairLease $helper; Exit-RepairLease $checkout }
if (!$refused) { throw 'An ambiguous/tampered interrupted transaction was accepted.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (target / "identity").read_bytes() == before
    assert (backup / "identity").read_text() == "old-environment"


def test_repair_holds_canonical_helper_lease_while_candidate_is_mutating(tmp_path: Path) -> None:
    (tmp_path / "direct-probe.py").write_text(r"""
from pathlib import Path
import os
import threading
from angerona import startup
root = Path(os.environ['ANGERONA_TEST_SCRATCH']) / 'fixture'
plan = startup.LaunchPlan(root, root / 'SourceData', ('fixture-python.exe',), False)
startup.platform_plan = lambda: plan
startup.probe_source = lambda *args: (root / 'unexpected-probe').write_text('executed')
try:
    startup.run_startup(lambda _: None, threading.Event(), check_only=True)
except startup.StartupError as error:
    if 'already working' not in str(error):
        raise
else:
    raise AssertionError('Direct helper probed while repair held the canonical lease')
""", encoding="utf-8")
    result = _run(LIBRARY + r"""
function New-VerifiedRepairCandidate($Transaction) {
    & $env:ANGERONA_TEST_PYTHON '-I' (Join-Path $env:ANGERONA_TEST_SCRATCH 'direct-probe.py')
    if ($LASTEXITCODE -ne 0) { throw 'Direct helper exclusion fixture failed.' }
    [void][IO.Directory]::CreateDirectory($Transaction.Stage)
    [IO.File]::WriteAllText((Join-Path $Transaction.Stage 'identity'), 'new-environment')
}
$transaction=Invoke-RepairTransaction
Complete-RepairTransaction $transaction
if (Test-Path -LiteralPath (Join-Path $root 'unexpected-probe')) { throw 'Concurrent helper entered its probe.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_exact_windows_devnull_disables_global_and_site_pip_targets(tmp_path: Path, monkeypatch) -> None:
    from pip._internal import configuration

    configuration_file = tmp_path / "pip.ini"
    configuration_file.write_text("[install]\ntarget = D:\\operator-owned-python-packages\n", encoding="utf-8")
    monkeypatch.setattr(configuration, "get_configuration_files", lambda: {
        configuration.kinds.GLOBAL: [str(configuration_file)],
        configuration.kinds.USER: [],
        configuration.kinds.SITE: [str(configuration_file)],
    })
    result = _run(r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$child=New-RepairChildEnvironment $env:ANGERONA_TEST_SCRATCH
Write-Output $child.PIP_CONFIG_FILE
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    disabled = result.stdout.strip()
    assert disabled == os.devnull == "nul"
    monkeypatch.setenv("PIP_CONFIG_FILE", "NUL")
    unsafe = configuration.Configuration(isolated=True)
    unsafe.load()
    assert unsafe.get_value("install.target") == r"D:\operator-owned-python-packages"
    monkeypatch.setenv("PIP_CONFIG_FILE", disabled)
    safe = configuration.Configuration(isolated=True)
    safe.load()
    assert list(safe.items()) == []
