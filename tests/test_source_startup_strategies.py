"""Native PowerShell orchestration with inert launch/repair/source providers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
PS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows source startup")


def run(tmp_path, body):
    script = tmp_path / "strategy.ps1"
    script.write_text(r"""$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Invoke-AngeronaSourceStartup.ps1'),[ref]$null,[ref]$null)
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    . ([scriptblock]::Create($node.Extent.Text))
}
""" + body, encoding="utf-8")
    result = subprocess.run([str(PS), "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=ROOT, env=dict(os.environ, ANGERONA_TEST_ROOT=str(ROOT), ANGERONA_TEST_SCRATCH=str(tmp_path),
                           TEMP=str(tmp_path), TMP=str(tmp_path)),
        text=True, capture_output=True, timeout=50, check=False,
        creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))


PROVIDERS = r"""
$script:Calls=[Collections.Generic.List[string]]::new()
$script:Codes=[Collections.Generic.Queue[int]]::new()
$script:Choices=[Collections.Generic.Queue[int]]::new()
function Write-SourceStartupEvent {}
function Write-SourceStartupStatus {}
function Add-SourceStartupAttempt {}
function Invoke-SourceCodeAction {
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
function Complete-SourceStartupRecovery { $script:Calls.Add('snapshot-and-review') }
function Invoke-SourceStartupPass {
    param($Root,[switch]$SetupOnly,[switch]$SoftwareRenderer,[switch]$NoStartupWindow)
    $script:Calls.Add("pass:software=$SoftwareRenderer,no-window=$NoStartupWindow")
    return $script:Codes.Dequeue()
}
function Invoke-SourceStartupRepair { param($Root,$Category);$script:Calls.Add('repair:'+$Category);return 0 }
function Invoke-SourceRecoveryWindow { $script:Calls.Add('recovery-window');return $script:Choices.Dequeue() }
"""


@pytest.mark.parametrize("codes,expected", [
    ([83, 0], ["pass:software=False,no-window=False", "pass:software=True,no-window=False"]),
    ([84, 0], ["pass:software=False,no-window=False", "pass:software=False,no-window=True"]),
    ([87, 0], ["pass:software=False,no-window=False", "pass:software=False,no-window=True"]),
    ([81, 82, 0], ["pass:software=False,no-window=False", "repair:Runtime",
                    "pass:software=False,no-window=False", "repair:Dependencies",
                    "pass:software=False,no-window=False"]),
    ([83, 83, 0], ["pass:software=False,no-window=False", "pass:software=True,no-window=False",
                    "repair:GuiRuntime", "pass:software=True,no-window=False"]),
])
def test_distinct_safe_strategies_recheck_every_candidate(tmp_path, codes, expected):
    enqueue = "\n".join(f"$script:Codes.Enqueue({code})" for code in codes)
    outcome = run(tmp_path, PROVIDERS + enqueue + r"""
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 0, "calls": expected}


def test_repeated_same_failure_opens_recovery_and_never_reports_closed_as_ready(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:Codes.Enqueue(82);$script:Codes.Enqueue(82);$script:Choices.Enqueue(0)
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome["code"] == 1223
    assert outcome["calls"].count("repair:Dependencies") == 1
    assert outcome["calls"][-1] == "recovery-window"


def test_retired_probe_timeout_uses_one_distinct_bootstrap_then_holds_without_source_recovery(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
$script:Codes.Enqueue(87);$script:Codes.Enqueue(87);$script:Choices.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    $script:Calls.Add('source:'+$Action)
    if($Action -eq 'recover'){throw 'Preflight timeout cannot authorize source rollback.'}
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 1223, "calls": [
        "source:inspect", "source:fingerprint", "pass:software=False,no-window=False",
        "source:inspect", "source:fingerprint", "pass:software=False,no-window=True", "recovery-window"]}


def test_cancelled_helper_is_terminal_without_another_window_or_source_mutation(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:Codes.Enqueue(1223)
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 1223, "calls": ["pass:software=False,no-window=False"]}


def test_operator_retry_starts_fresh_verified_round(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:Codes.Enqueue(1);$script:Codes.Enqueue(0);$script:Choices.Enqueue(10)
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome["code"] == 0
    assert outcome["calls"] == ["pass:software=False,no-window=False", "recovery-window",
                                 "pass:software=False,no-window=False"]


def test_authenticated_stop_is_a_quiet_terminal_result_without_snapshot_or_retry(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-state'
$script:Codes.Enqueue(86)
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 0, "calls": ["pass:software=False,no-window=False"]}


def test_source_recovery_retry_is_automatic_but_explicit_retry_resumes_manually(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-state'
$script:AttemptKinds=[Collections.Generic.List[bool]]::new()
function Invoke-SourceStartupPass {
    $script:AttemptKinds.Add([bool]$script:StartupAutomaticAttempt)
    if($script:AttemptKinds.Count -lt 3){return 1};return 0
}
function Invoke-SourceCodeAction {
    param($Root,$Action,$Strategy,$ExpectedId)
    $changed=($Action -eq 'recover' -and $script:AttemptKinds.Count -eq 1)
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';changed=$changed;source_digest=('a'*64)}
    return 0
}
$script:Choices.Enqueue(10)
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;kinds=@($script:AttemptKinds)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 0, "kinds": [False, True, False]}


def test_operator_retry_success_has_current_detail_and_preserves_prior_failure(tmp_path):
    providers = PROVIDERS.replace("function Add-SourceStartupAttempt {}\n", "")
    outcome = run(tmp_path, providers + r"""
$script:StartupAttempts=[Collections.Generic.List[object]]::new()
$script:EntryIssues=[Collections.Generic.List[string]]::new()
$script:Choices.Enqueue(10)
$script:LastStartupIssue='An older diagnostic must not describe a new pass.'
function Invoke-SourceStartupPass {
    $script:EntryIssues.Add([string]$script:LastStartupIssue)
    if($script:EntryIssues.Count -eq 1) {throw 'PID 2860 is still active; review its exact generation.'}
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;attempts=@($script:StartupAttempts);entry_issues=@($script:EntryIssues);
    current_detail=$script:LastStartupIssue}|ConvertTo-Json -Depth 5 -Compress))
""")
    assert outcome["code"] == 0
    assert outcome["entry_issues"] == ["", ""]
    assert outcome["current_detail"] == ""
    assert outcome["attempts"] == [
        {"strategy": "verified-normal-startup", "outcome": "not-ready", "exit_code": 85,
         "detail": "PID 2860 is still active; review its exact generation."},
        {"strategy": "verified-normal-startup", "outcome": "verified", "exit_code": 0, "detail": ""},
    ]


def test_preserved_source_candidate_must_pass_full_startup_before_snapshot(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
$script:Codes.Enqueue(1);$script:Codes.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action,$Strategy,$ExpectedId)
    $script:Calls.Add("source:$Action`:$Strategy")
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    if($Action -eq 'recover') {
        $script:LastSourceRecoveryResult=[pscustomobject]@{changed=$true;report_id='aabbccdd-1111-2222-3333-444455556666'}
    }
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome["code"] == 0
    assert outcome["calls"] == ["source:inspect:", "source:fingerprint:", "pass:software=False,no-window=False",
                                 "source:recover:last-ready", "source:inspect:", "source:fingerprint:",
                                 "pass:software=False,no-window=False",
                                 "snapshot-and-review"]


def test_launcher_exception_is_typed_hold_without_source_rollback_or_reinstall(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
$script:Attempts=[Collections.Generic.List[int]]::new()
$script:Choices.Enqueue(0)
function Add-SourceStartupAttempt {param($Strategy,$Code,$Detail);$script:Attempts.Add([int]$Code)}
function Invoke-SourceCodeAction {
    param($Root,$Action,$Strategy)
    $script:Calls.Add('source:'+$Action)
    if($Action -eq 'recover') {throw 'Infrastructure must never roll back application source.'}
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
function Invoke-SourceStartupPass {
    $script:Calls.Add('pass:infrastructure-failed')
    throw 'Injected capture admission / scratch / compiler / lease failure'
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;attempts=@($script:Attempts);calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 1223, "attempts": [85], "calls": [
        "source:inspect", "source:fingerprint", "pass:infrastructure-failed", "recovery-window"]}


@pytest.mark.parametrize("native_code", [85, 124, 125])
def test_infrastructure_and_uncertain_capture_outcomes_never_select_source_recovery(tmp_path, native_code):
    body = PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
$script:Choices.Enqueue(0)
$script:Codes.Enqueue(NATIVE_CODE)
function Invoke-SourceCodeAction {
    param($Root,$Action,$Strategy)
    $script:Calls.Add('source:'+$Action)
    if($Action -eq 'recover') {throw 'An uncertain capture cannot authorize source mutation.'}
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
"""
    assert run(tmp_path, body.replace("NATIVE_CODE", str(native_code))) == {"code": 1223, "calls": [
        "source:inspect", "source:fingerprint", "pass:software=False,no-window=False", "recovery-window"]}


@pytest.mark.parametrize("failed_probe", [1, 2, 3], ids=["abi", "pip", "source-trust"])
def test_unclassified_native_admission_probe_is_infrastructure_hold(tmp_path, failed_probe):
    body = r"""
$script:ProbeStep=0;$script:Releases=0
function Assert-SourceStartupBoundary {}
function Initialize-SourceStartupStorage {return $env:ANGERONA_TEST_SCRATCH}
function Enter-RepairLease {return 'inert-lease'}
function Exit-RepairLease {$script:Releases++}
function Assert-NoPendingRepair {}
function Assert-NoActiveVenv {}
function Test-Path {return $true}
function New-SourceStartupTemporary {return $env:ANGERONA_TEST_SCRATCH}
function New-RepairChildEnvironment {return @{TEMP=$env:ANGERONA_TEST_SCRATCH;TMP=$env:ANGERONA_TEST_SCRATCH}}
function Initialize-OwnedRepairProcess {}
function Invoke-OwnedRepairProcess {
    $script:ProbeStep++
    if($script:ProbeStep -eq FAILED_PROBE) {return 1}
    return 0
}
function Invoke-SourceStartupAssistant {throw 'An infrastructure probe failure must not start the assistant.'}
$code=Invoke-SourceStartupPass $env:ANGERONA_TEST_SCRATCH
Write-Output ('RESULT:'+(@{code=$code;probes=$script:ProbeStep;released=$script:Releases}|ConvertTo-Json -Compress))
"""
    assert run(tmp_path, body.replace("FAILED_PROBE", str(failed_probe))) == {
        "code": 85, "probes": failed_probe, "released": 1}


def test_read_only_startup_does_not_require_shared_python_jobs_to_exit(tmp_path):
    outcome = run(tmp_path, r"""
$script:Calls=[Collections.Generic.List[string]]::new()
function Assert-SourceStartupBoundary {}
function Initialize-SourceStartupStorage {return $env:ANGERONA_TEST_SCRATCH}
function Enter-RepairLease {return 'repair-coordination'}
function Exit-RepairLease {$script:Calls.Add('lease-released')}
function Assert-NoPendingRepair {}
function Assert-NoActiveVenv {throw 'An unrelated review is using shared Python; mutation is held.'}
function Test-Path {return $true}
function New-SourceStartupTemporary {return $env:ANGERONA_TEST_SCRATCH}
function New-RepairChildEnvironment {return @{TEMP=$env:ANGERONA_TEST_SCRATCH;TMP=$env:ANGERONA_TEST_SCRATCH}}
function Initialize-OwnedRepairProcess {}
function Invoke-OwnedRepairProcess {$script:Calls.Add('read-only-probe');return 0}
function Invoke-SourceStartupAssistant {$script:Calls.Add('leased-startup-helper');return 0}
$code=Invoke-SourceStartupPass $env:ANGERONA_TEST_SCRATCH
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 0, "calls": ["read-only-probe"] * 3 + ["leased-startup-helper", "lease-released"]}


@pytest.mark.parametrize("action", ["inspect", "fingerprint", "recover", "apply-pending"])
def test_source_mutation_alone_requires_core_and_active_runtime_exclusion(tmp_path, action):
    body = r"""
$root=$env:ANGERONA_TEST_SCRATCH
[void][IO.Directory]::CreateDirectory((Join-Path $root 'tools'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'venv\Scripts'))
[IO.File]::WriteAllText((Join-Path $root 'tools\startup_source_recovery.py'),'inert fixture')
[IO.File]::WriteAllText((Join-Path $root 'venv\Scripts\python.exe'),'inert fixture')
$script:Calls=[Collections.Generic.List[string]]::new()
function Initialize-SourceStartupStorage {return $env:ANGERONA_TEST_SCRATCH}
function Assert-SourceStartupPath {}
function Assert-PlainRepairPath {}
function Enter-RepairLease {return 'repair'}
function Exit-RepairLease {param($Lease);$script:Calls.Add('release:'+$Lease)}
function Assert-NoPendingRepair {}
function Enter-CanonicalSourceHelperLease {$script:Calls.Add('helper');return 'helper'}
function Enter-CanonicalCoreMutationLease {$script:Calls.Add('core');return 'core'}
function Assert-NoActiveVenv {$script:Calls.Add('runtime-exclusion');throw 'Shared review generation is active; mutation refused.'}
function New-SourceStartupTemporary {return $env:ANGERONA_TEST_SCRATCH}
function New-RepairChildEnvironment {return @{TEMP=$env:ANGERONA_TEST_SCRATCH;TMP=$env:ANGERONA_TEST_SCRATCH}}
function Initialize-OwnedRepairProcess {}
function Write-SourceStartupEvent {}
function Invoke-OwnedRepairProcess {
    param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds,$LogPath)
    if($Arguments -contains '--action') {
        [IO.File]::WriteAllText($LogPath,'{"schema":1,"launch_held":false,"requires_mutation":false,"pending_kind":"none"}')
    }
    return 0
}
$held=$false;$code=-1
try {$code=Invoke-SourceCodeAction -Root $root -Action 'ACTION'}catch{$held=$true}
Write-Output ('RESULT:'+(@{code=$code;held=$held;calls=@($script:Calls)}|ConvertTo-Json -Compress))
"""
    outcome = run(tmp_path, body.replace("ACTION", action))
    mutates = action in {"recover", "apply-pending"}
    assert outcome == {"code": -1 if mutates else 0, "held": mutates,
        "calls": ["helper"] + (["core", "runtime-exclusion", "release:core"] if mutates else [])
                 + ["release:helper", "release:repair"]}


@pytest.mark.parametrize("kind,held", [("none", False), ("edits", False), ("transaction", True)])
def test_source_inspection_only_requests_exclusive_apply_for_actual_pending_mutation(tmp_path, kind, held):
    body = PROVIDERS + r"""
$script:Codes.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    $script:Calls.Add('source:'+$Action)
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    if($Action -eq 'inspect') {
        $script:LastSourceRecoveryResult.requires_mutation=('KIND' -ne 'none')
        $script:LastSourceRecoveryResult.pending_kind='KIND'
        $script:LastSourceRecoveryResult.launch_held=HELD
        if(HELD){return 1}
    }
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
"""
    outcome = run(tmp_path, body.replace("KIND", kind).replace("HELD", "$true" if held else "$false"))
    assert outcome == {"code": 0, "calls": ["source:inspect"] + (
        ["source:apply-pending"] if kind != "none" else []) + ["source:fingerprint", "pass:software=False,no-window=False"]}


def test_missing_runtime_during_inspection_still_selects_verified_runtime_repair(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:Inspections=0;$script:Codes.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    if($Action -eq 'inspect'){$script:Inspections++}
    if($script:Inspections -eq 1) {
        $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$true;reason_code='runtime-missing'}
        return 81
    }
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 0, "calls": ["repair:Runtime", "pass:software=False,no-window=False"]}


def test_retry_waits_for_retained_assistant_generation_and_readers(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:Retired=$false
$process=[pscustomobject]@{}
$process|Add-Member ScriptProperty HasExited {$script:Retired}
$process|Add-Member ScriptMethod Dispose {$script:Calls.Add('owned-capture-disposed')}
$capture=[pscustomobject]@{Process=$process;ProcessId=41234;CreationTimeFileTime='1122334455'}
$capture|Add-Member ScriptProperty ReadersComplete {$script:Retired}
$script:StartupPendingCaptures=[Collections.Generic.List[object]]::new();$script:StartupPendingCaptures.Add($capture)
function Invoke-SourceRecoveryWindow {
    $script:Calls.Add('recovery-window');$script:Retired=$true;return 10
}
$script:Codes.Enqueue(0)
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls);pending=$script:StartupPendingCaptures.Count}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 0, "calls": ["recovery-window", "owned-capture-disposed", "pass:software=False,no-window=False"], "pending": 0}


def test_supervisor_waits_for_exact_native_first_paint_and_ready_retires_shell(tmp_path):
    outcome = run(tmp_path, r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$script:InertStorage=Join-Path $env:ANGERONA_TEST_SCRATCH 'SourceData'
New-PrivateRepairDirectory $script:InertStorage
function Initialize-SourceStartupStorage {return $script:InertStorage}
Initialize-SourceStartupDiagnostics $script:InertStorage
try {
    Start-SourceStartupShell $env:ANGERONA_TEST_ROOT
    if(!$script:StartupShell -or $script:StartupShell.HasExited){throw 'Native shell did not survive its first paint.'}
    $status=[IO.File]::ReadAllText($script:StartupStatusPath)|ConvertFrom-Json
    if($status.outcome -cne 'checking' -or $status.run_id -cne $script:StartupRunId){throw 'Paint incorrectly conveyed dashboard readiness.'}
    Write-SourceStartupStatus 'dashboard' 'verified' 'Inert integration receipt; no application engine was launched.'
    if(!$script:StartupShell.WaitForExit(15000)){throw 'Matching ready status did not retire the independent shell.'}
    Write-Output ('RESULT:'+(@{code=$script:StartupShell.ExitCode;painted=$true}|ConvertTo-Json -Compress))
}finally{if($script:StartupShell){$script:StartupShell.Dispose()}}
""")
    assert outcome == {"code": 0, "painted": True}


@pytest.mark.parametrize("native_code", [0, 1, 82, 124, 125])
def test_assistant_diagnostic_failure_preserves_known_native_result_and_capture_owner(tmp_path, native_code):
    body = r"""
$root=$env:ANGERONA_TEST_SCRATCH
[void][IO.Directory]::CreateDirectory((Join-Path $root 'tools'))
$fixture=@'
function Invoke-SourceStartupCapturedAssistant {
    return [pscustomobject]@{ExitCode=$script:NativeCode;ReadersComplete=$false;TimedOut=($script:NativeCode -eq 124);
        Process=[pscustomobject]@{HasExited=$false};ProcessId=424242;ProcessRole='inert-fixture'}
}
'@
[IO.File]::WriteAllText((Join-Path $root 'tools\startup_assistant_capture.ps1'),$fixture)
function Write-SourceStartupEvent {throw 'Injected diagnostic journal failure.'}
function Read-SourceStartupLogTail {throw 'Injected diagnostic tail failure.'}
$script:NativeCode=NATIVE_CODE
$code=Invoke-SourceStartupAssistant -Python 'inert-python.exe' -Root $root -Environment @{} -Scratch $root
Write-Output ('RESULT:'+(@{code=$code;owners=$script:StartupPendingCaptures.Count}|ConvertTo-Json -Compress))
"""
    assert run(tmp_path, body.replace("NATIVE_CODE", str(native_code))) == {"code": native_code, "owners": 1}


def test_repair_diagnostic_tail_failure_preserves_each_native_result(tmp_path):
    outcome = run(tmp_path, r"""
$root=$env:ANGERONA_TEST_SCRATCH
function Initialize-SourceStartupStorage {return $root}
function New-SourceStartupTemporary {return $root}
function New-RepairChildEnvironment {return @{}}
function Initialize-OwnedRepairProcess {}
function Write-SourceStartupEvent {}
function Invoke-OwnedRepairProcess {return $script:NativeCode}
function Read-SourceStartupLogTail {throw 'Injected diagnostic tail unavailable.'}
$results=@()
foreach($script:NativeCode in @(0,7,124)) {
    $results+=,[int](Invoke-SourceStartupRepair -Root $root -Category Dependencies)
}
Write-Output ('RESULT:'+(@{codes=$results}|ConvertTo-Json -Compress))
""")
    assert outcome == {"codes": [0, 7, 124]}


@pytest.mark.parametrize("failed_action", ["inspect", "apply-pending", "fingerprint"])
def test_source_admission_hold_never_loads_engine_or_busy_retries(tmp_path, failed_action):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
$script:Choices.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    $script:Calls.Add("source:$Action")
    $needsMutation=('FAILED_ACTION' -eq 'apply-pending' -and $Action -eq 'inspect')
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=($Action -eq 'FAILED_ACTION');requires_mutation=$needsMutation;pending_kind=$(if($needsMutation){'edits'}else{'none'});source_digest=('a'*64)}
    if($Action -eq 'FAILED_ACTION') { return 1 }; return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""".replace("FAILED_ACTION", failed_action))
    assert outcome["code"] == 1223
    assert outcome["calls"][-1] == "recovery-window"
    assert not any(c.startswith("pass:") or c.startswith("repair:") for c in outcome["calls"])


def test_recovery_off_inspects_without_automatic_mutation(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
$script:StartupRecoveryPreferences=@{Enabled=$false;Github=$false}
$script:Codes.Enqueue(82);$script:Choices.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    $script:Calls.Add("source:$Action")
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 1223, "calls": ["source:inspect", "source:fingerprint",
        "pass:software=False,no-window=False", "recovery-window"]}


@pytest.mark.parametrize("raw,expected", [
    (None, [True, True]), ("{}", [True, True]),
    ('{"startup_recovery_enabled":false}', [False, True]),
    ('{"startup_recovery_github_enabled":false}', [True, False]),
    ('{"startup_recovery_enabled":true,"startup_recovery_enabled":false}', [False, True]),
    ('{"nested":{"startup_recovery_enabled":false}}', [True, True]),
    ('{"startup_recovery_enabled":"true"}', [False, True]),
    ('{"startup_recovery_enabled":1}', [False, True]),
    ('{"startup_recovery_enabled":tru}', [False, False]),
    ('[]', [False, False]), ('{"startup_recovery_enabled":true,}', [False, False]),
    ('{"startup_recovery_\\u0065nabled":false}', [False, True]),
    (b'\xef\xbb\xbf{"startup_recovery_enabled":true}', [False, False]),
    ('{"startup_recovery_enabled":true}'.encode('utf-16'), [False, False]),
    (b'\xff{"startup_recovery_enabled":true}', [False, False]),
])
def test_native_preferences_fail_closed_and_preserve_explicit_off(tmp_path, raw, expected):
    # JSON passes as a data file, never as executable PowerShell text.
    if raw is not None:
        (tmp_path / "input.json").write_bytes(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
    outcome = run(tmp_path, r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$storage=Join-Path $env:ANGERONA_TEST_SCRATCH 'state';New-PrivateRepairDirectory $storage
$input=Join-Path $env:ANGERONA_TEST_SCRATCH 'input.json'
if(Test-Path -LiteralPath $input) {
    $bytes=[IO.File]::ReadAllBytes($input)
    $stream=Open-PrivateRepairFile -Path (Join-Path $storage 'settings.json')
    try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
}
$prefs=Read-SourceStartupRecoveryPreferences $storage
Write-Output ('RESULT:'+(@{enabled=$prefs.Enabled;github=$prefs.Github}|ConvertTo-Json -Compress))
""")
    assert outcome == {"enabled": expected[0], "github": expected[1]}


def test_setup_only_failure_does_not_open_gui_or_restore_source(tmp_path):
    outcome = run(tmp_path, PROVIDERS + r"""
$script:StartupDiagnosticRoot='D:\inert-private-diagnostics'
function Invoke-SourceCodeAction {
    param($Root,$Action)
    if($Action -ne 'inspect') {throw 'Mutating source action in check-only'}
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none'}
    return 0
}
$script:Codes.Enqueue(1)
$code=Invoke-SourceStartupLoop 'D:\inert-root' -SetupOnly
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
""")
    assert outcome == {"code": 1, "calls": ["pass:software=False,no-window=False"]}


@pytest.mark.parametrize("setup_only,diagnostics", [(True, True), (True, False), (False, False)])
def test_unresolved_source_gates_check_only_and_unavailable_diagnostics(tmp_path, setup_only, diagnostics):
    body = PROVIDERS + r"""
$script:StartupDiagnosticRoot=DIAGNOSTICS
$script:Choices.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    $script:Calls.Add('source:'+$Action)
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$true;requires_mutation=$false;pending_kind='none'}
    return 1
}
$code=Invoke-SourceStartupLoop 'D:\inert-root' SETUP
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
"""
    outcome = run(tmp_path, body.replace("DIAGNOSTICS", "'D:\\inert-diagnostics'" if diagnostics else "$null")
                  .replace("SETUP", "-SetupOnly" if setup_only else ""))
    assert outcome["code"] == (1 if setup_only else 1223)
    assert outcome["calls"] == (["source:inspect"] if setup_only else ["source:inspect", "recovery-window"])


@pytest.mark.parametrize("result", ["$null", "[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none'}"])
def test_invalid_fingerprint_never_loads_application(tmp_path, result):
    body = PROVIDERS + r"""
$script:Choices.Enqueue(0)
function Invoke-SourceCodeAction {
    param($Root,$Action)
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;requires_mutation=$false;pending_kind='none'}
    if($Action -eq 'fingerprint') {$script:LastSourceRecoveryResult=BAD_RESULT;return 1}
    return 0
}
$code=Invoke-SourceStartupLoop 'D:\inert-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:Calls)}|ConvertTo-Json -Compress))
"""
    assert run(tmp_path, body.replace("BAD_RESULT", result)) == {"code": 1223, "calls": ["recovery-window"]}


def test_verbose_repair_returns_only_native_exit_code(tmp_path):
    outcome = run(tmp_path, r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$fixture=Join-Path $env:ANGERONA_TEST_SCRATCH 'fixture'
[void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tools'))
$scratch=Join-Path $fixture 'scratch';New-PrivateRepairDirectory $scratch
$wrapper=Join-Path $fixture 'tools\Invoke-AngeronaStartupRepair.ps1'
[IO.File]::WriteAllText($wrapper, 'param($RepositoryRoot,$FailureCategory,$Attempt);Write-Host "verbose repair verification completed";exit 0')
function Initialize-SourceStartupStorage { return $fixture }
function New-SourceStartupTemporary { param($Root,$Storage);return $scratch }
function Write-SourceStartupEvent {}
$value=Invoke-SourceStartupRepair -Root $fixture -Category Dependencies
Write-Output ('RESULT:'+(@{count=@($value).Count;is_int=($value -is [int]);code=$value}|ConvertTo-Json -Compress))
""")
    assert outcome == {"count": 1, "is_int": True, "code": 0}


def test_private_supervisor_journal_caps_and_redacts(tmp_path):
    outcome = run(tmp_path, r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$state=Join-Path $env:ANGERONA_TEST_SCRATCH 'state'
[void][IO.Directory]::CreateDirectory((Join-Path $state 'logs'))
Initialize-SourceStartupDiagnostics $state
Write-SourceStartupEvent 'seed' 'created'
$stream=Open-PrivateRepairFile -Path $script:StartupJournalPath -Mode Open
try { $stream.SetLength(512KB-1024);$stream.Flush($true) } finally { $stream.Dispose() }
for($index=0;$index -lt 3;$index++) { Write-SourceStartupEvent 'dependency' 'held' (('x'*1700)+' token=secret-value') 82 }
Add-SourceStartupAttempt 'verified-normal-startup' 82 'dependency not ready'
Write-SourceStartupStatus 'dependency' 'needs-attention' 'token=secret-value'
Write-SourceStartupStatus 'retry' 'checking' 'Latest retry phase'
$files=@(Get-ChildItem -LiteralPath $script:StartupDiagnosticRoot -Filter '*.jsonl')
$largest=($files|Measure-Object -Property Length -Maximum).Maximum
$all=($files|ForEach-Object {[IO.File]::ReadAllText($_.FullName)}) -join ''
$status=[IO.File]::ReadAllText($script:StartupStatusPath)|ConvertFrom-Json
Write-Output ('RESULT:'+(@{count=$files.Count;largest=$largest;has_secret=$all.Contains('secret-value');attempts=$status.attempts.Count;protection=$status.protection_status;phase=$status.phase}|ConvertTo-Json -Compress))
""")
    assert outcome["count"] <= 4
    assert outcome["largest"] <= 512 * 1024
    assert not outcome["has_secret"] and outcome["attempts"] == 1
    assert outcome["protection"] == "unknown"
    assert outcome["phase"] == "retry"
