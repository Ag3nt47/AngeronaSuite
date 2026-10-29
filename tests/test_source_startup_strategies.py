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


WINDOW_DIAGNOSTICS = r"""
# Fixture-only, read-only evidence for the exact retained native UI generation.
# No RPC read exceeds100ms; the complete window/control pass has a2000ms budget.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public sealed class AngeronaFixtureWindowSnapshot {
    public string State {get;set;}
    public string Error {get;set;}
    public double CpuMilliseconds {get;set;}
    public int ThreadCount {get;set;}
    public int SessionId {get;set;}
    public long MainWindowHandle {get;set;}
    public int Windows {get;set;}
    public int Controls {get;set;}
    public long ElapsedMilliseconds {get;set;}
    public bool BudgetReached {get;set;}
    public bool WindowLimitReached {get;set;}
    public bool[] WindowVisible {get;set;}
    public string[] Text {get;set;}
}
public static class AngeronaFixtureWindowDiagnostic {
    delegate bool Callback(IntPtr window,IntPtr parameter);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long birth,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr value);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder image,ref uint size);
    [DllImport("user32.dll")] static extern bool EnumWindows(Callback callback,IntPtr parameter);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr window,Callback callback,IntPtr parameter);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
    [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr window,uint command);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr SendMessageTimeoutW(IntPtr window,uint message,UIntPtr count,StringBuilder value,uint flags,uint timeout,out UIntPtr result);
    public static AngeronaFixtureWindowSnapshot Read(uint pid,long expectedBirth,string expectedImage) {
        var result=new AngeronaFixtureWindowSnapshot{State="unavailable",Text=new string[0],WindowVisible=new bool[0]};
        var clock=Stopwatch.StartNew(); var text=new List<string>();var visible=new List<bool>();
        IntPtr process=OpenProcess(0x101000,false,pid);
        if(process==IntPtr.Zero){result.Error="OpenProcess error="+Marshal.GetLastWin32Error();return result;}
        try {
            long birth,exit,kernel,user;uint capacity=1024;var image=new StringBuilder(1024);
            if(WaitForSingleObject(process,0)!=258 || !GetProcessTimes(process,out birth,out exit,out kernel,out user) ||
                birth!=expectedBirth || !QueryFullProcessImageNameW(process,0,image,ref capacity) ||
                !String.Equals(image.ToString(),expectedImage,StringComparison.OrdinalIgnoreCase)) {
                result.Error="Exact live image/birth witness unavailable; no window text read.";return result;
            }
            result.State="live";
            using(Process managed=Process.GetProcessById((int)pid)) {
                if(managed.StartTime.ToUniversalTime().ToFileTimeUtc()!=expectedBirth)throw new InvalidOperationException("Metadata generation changed.");
                result.CpuMilliseconds=managed.TotalProcessorTime.TotalMilliseconds;
                result.ThreadCount=managed.Threads.Count;result.SessionId=managed.SessionId;
            }
            Action<IntPtr,string> read=(window,kind)=>{
                long remaining=2000-clock.ElapsedMilliseconds;
                if(remaining<=0){result.BudgetReached=true;return;}
                var value=new StringBuilder(256);UIntPtr copied;
                if(SendMessageTimeoutW(window,0xDu,new UIntPtr(256u),value,3u,(uint)Math.Min(100,remaining),out copied)!=IntPtr.Zero &&
                    copied.ToUInt64()>0)text.Add(kind+":"+value.ToString());
            };
            int visited=0;
            EnumWindows((window,unused)=>{
                if(clock.ElapsedMilliseconds>=2000){result.BudgetReached=true;return false;}
                if(++visited>512){result.WindowLimitReached=true;return false;}
                uint owner;GetWindowThreadProcessId(window,out owner);
                if(owner!=pid)return true;
                if(++result.Windows>=2)result.WindowLimitReached=true;
                visible.Add(IsWindowVisible(window));
                if(result.MainWindowHandle==0 && GetWindow(window,4u)==IntPtr.Zero)result.MainWindowHandle=window.ToInt64();
                read(window,"window");int controls=0;
                EnumChildWindows(window,(child,ignored)=>{
                    if(clock.ElapsedMilliseconds>=2000){result.BudgetReached=true;return false;}
                    if(controls++>=24)return false;
                    uint childOwner;GetWindowThreadProcessId(child,out childOwner);
                    if(childOwner==pid){result.Controls++;read(child,"control");}return true;
                },IntPtr.Zero);
                return result.Windows<2 && clock.ElapsedMilliseconds<2000;
            },IntPtr.Zero);
            result.Text=text.ToArray();result.WindowVisible=visible.ToArray();
        }catch(Exception error){result.Error=error.GetType().Name+": "+error.Message;}
        finally{CloseHandle(process);result.ElapsedMilliseconds=clock.ElapsedMilliseconds;}
        return result;
    }
}
'@
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
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:ANGERONA_TEST_SCRATCH 'private-canonical-source')}
# Keep the original native reader's installation/.tmp scope. Hosted pytest
# temporary directories live outside the real checkout, so pointing the real
# installation's shell at arbitrary tmp_path diagnostics correctly refuses them.
$fixtureRoot=Join-Path $env:ANGERONA_TEST_SCRATCH 'installation'
[void][IO.Directory]::CreateDirectory((Join-Path $fixtureRoot 'tools'))
[IO.File]::WriteAllBytes((Join-Path $fixtureRoot 'tools\Show-AngeronaStartupRecovery.ps1'),
    [IO.File]::ReadAllBytes((Join-Path $env:ANGERONA_TEST_ROOT 'tools\Show-AngeronaStartupRecovery.ps1')))
$script:InertStorage=Join-Path $fixtureRoot '.tmp\SourceData'
New-PrivateRepairDirectory $script:InertStorage
function Initialize-SourceStartupStorage {return $script:InertStorage}
Initialize-SourceStartupDiagnostics $script:InertStorage
$script:FixtureNativeWindowLaunch=${function:Start-OwnedRepairWindow}
function Start-OwnedRepairWindow {
    param([string]$FilePath,[string[]]$Arguments,[string]$WorkingDirectory,
        [Collections.IDictionary]$Environment,[string]$LogPath)
    # Observe the exact original native launch; never substitute its owner,
    # command, environment, first-paint receipt or twenty-second admission gate.
    $script:FixtureWindowLog=$LogPath
    $script:FixturePaintReceipt=Join-Path $Environment['TEMP'] 'startup-shell-painted.json'
    return & $script:FixtureNativeWindowLaunch @PSBoundParameters
}
""" + WINDOW_DIAGNOSTICS + r"""
$script:FixtureFirstPaintFailed=$false
try {
    Start-SourceStartupShell $fixtureRoot
    if(!$script:StartupShell -or $script:StartupShell.HasExited){throw 'Native shell did not survive its first paint.'}
    $status=[IO.File]::ReadAllText($script:StartupStatusPath)|ConvertFrom-Json
    if($status.outcome -cne 'checking' -or $status.run_id -cne $script:StartupRunId){throw 'Paint incorrectly conveyed dashboard readiness.'}
    Write-SourceStartupStatus 'dashboard' 'verified' 'Inert integration receipt; no application engine was launched.'
    if(!$script:StartupShell.WaitForExit(15000)){throw 'Matching ready status did not retire the independent shell.'}
    $phases=@()
    foreach($line in ((Read-SourceStartupLogTail $script:FixtureWindowLog) -split "`n")) {
        try{$record=$line|ConvertFrom-Json}catch{continue}
        if($record.component -ceq 'startup-recovery-ui' -and $record.outcome -ceq 'checking'){
            if($record.run_id -cne $script:StartupRunId -or [string]$record.shell_pid -cne [string]$script:StartupShell.ProcessId){throw 'Phase diagnostic lost its exact launch identity.'}
            if($record.phase -in @('script-entry','ui-assemblies-start','ui-assemblies-ready','form-construction-start','show-dialog-start','shown-entry') -and $record.painted){throw 'A pre-refresh phase claimed paint.'}
            $phases+=,$record.phase
        }
    }
    if(($phases -join ',') -cne 'script-entry,ui-assemblies-start,ui-assemblies-ready,form-construction-start,show-dialog-start,shown-entry,refresh-complete,reader-initialization-start,reader-initialization-ready'){throw 'Native startup phase order is incomplete or changed.'}
    Write-Output ('RESULT:'+(@{code=$script:StartupShell.ExitCode;painted=$true}|ConvertTo-Json -Compress))
}catch{
    $script:FixtureFirstPaintFailed=$true
    $originalFailure=$_
    try {
        $diagnostic=[ordered]@{outcome='first-paint-fixture-failed';message=$originalFailure.Exception.Message}
        if($script:StartupShell){
            $diagnostic.shell_pid=$script:StartupShell.ProcessId
            $diagnostic.shell_creation_filetime=[string]$script:StartupShell.CreationFileTime
            $diagnostic.completion_ready=$script:StartupShell.HasExited
            $expectedImage=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
            $snapshot=[AngeronaFixtureWindowDiagnostic]::Read($script:StartupShell.ProcessId,$script:StartupShell.CreationFileTime,$expectedImage)
            $diagnostic.native_window=$snapshot
            $snapshot.Text=@($snapshot.Text|ForEach-Object {Protect-SourceStartupText $_ 256})
        }
        foreach($entry in @(@('window_log',$script:FixtureWindowLog),
            @('paint_receipt',$script:FixturePaintReceipt),@('status',$script:StartupStatusPath),
            @('journal',$script:StartupJournalPath))) {
            $known=$entry[1]
            try{
                $exists=Test-Path -LiteralPath $known -PathType Leaf
                $diagnostic[$entry[0]+'_exists']=$exists
                $diagnostic[$entry[0]+'_bytes']=if($exists){[long](Get-Item -LiteralPath $known).Length}else{-1}
            }catch{$diagnostic[$entry[0]+'_metadata_error']=$_.Exception.Message}
            try {$diagnostic[$entry[0]]=Read-SourceStartupLogTail $entry[1]}
            catch{$diagnostic[$entry[0]]='Bounded diagnostic unavailable: '+$_.Exception.Message}
        }
        try{
            $rows=[Collections.Generic.List[object]]::new();$visited=0;$total=0L;$nonflat=0
            foreach($entry in [IO.Directory]::EnumerateFileSystemEntries([IO.Path]::GetDirectoryName($script:FixturePaintReceipt))){
                if(++$visited -gt 128){break}
                $attributes=[IO.File]::GetAttributes($entry);$length=0L
                if(($attributes -band 0x410) -ne 0){$nonflat++}else{$length=([IO.FileInfo]::new($entry)).Length;$total+=$length}
                if($rows.Count -lt 16){$name=[IO.Path]::GetFileName($entry);$name=[regex]::Replace($name.Substring(0,[Math]::Min(96,$name.Length)),'[^\x20-\x7e]','?');$rows.Add(@{name=$name;attributes=[int]$attributes;bytes=$length})}
            }
            $diagnostic.workspace_inventory=@{visited=$visited;truncated=($visited -gt 128);bytes=$total;nonflat=$nonflat;entries=@($rows)}
        }catch{$diagnostic.workspace_inventory_unavailable=$true}
        Write-Output ('FIXTURE-DIAGNOSTIC:'+($diagnostic|ConvertTo-Json -Depth 5 -Compress))
    }catch{Write-Output ('FIXTURE-DIAGNOSTIC-UNAVAILABLE:'+ $_.Exception.Message)}
    throw $originalFailure
}finally{
    if($script:StartupShell){
        $disposeReturned=$false
        try{$script:StartupShell.Dispose();$disposeReturned=$true}
        finally{
            if($script:FixtureFirstPaintFailed){
                try{
                    # Preserve the live-timeout observation above, then report
                    # any buffered evidence only after exact owned retirement.
                    # Completion can also fault with a retained custody hold.
                    # Only a successful Dispose proves the owner's retirement.
                    $retired=$disposeReturned -and $script:StartupShell.HasExited
                    $post=[ordered]@{outcome='first-paint-fixture-post-retirement';native_retired=$retired
                        shell_pid=$script:StartupShell.ProcessId
                        shell_creation_filetime=[string]$script:StartupShell.CreationFileTime}
                    if($retired){
                        $post.window_log=Read-SourceStartupLogTail $script:FixtureWindowLog
                        $post.window_log_bytes=if([IO.File]::Exists($script:FixtureWindowLog)){
                            [long](Get-Item -LiteralPath $script:FixtureWindowLog).Length
                        }else{-1}
                    }
                    Write-Output ('FIXTURE-POST-RETIREMENT:'+($post|ConvertTo-Json -Depth 3 -Compress))
                }catch{Write-Output ('FIXTURE-POST-RETIREMENT-UNAVAILABLE:'+ $_.Exception.Message)}
            }
        }
    }
}
""")
    assert outcome == {"code": 0, "painted": True}


def test_native_first_paint_supervisor_mismatch_logs_hold_without_receipt(tmp_path):
    outcome = run(tmp_path, r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:ANGERONA_TEST_SCRATCH 'private-canonical-source')}
$fixtureRoot=Join-Path $env:ANGERONA_TEST_SCRATCH 'installation'
[void][IO.Directory]::CreateDirectory((Join-Path $fixtureRoot 'tools'))
[IO.File]::WriteAllBytes((Join-Path $fixtureRoot 'tools\Show-AngeronaStartupRecovery.ps1'),
    [IO.File]::ReadAllBytes((Join-Path $env:ANGERONA_TEST_ROOT 'tools\Show-AngeronaStartupRecovery.ps1')))
$storage=Join-Path $fixtureRoot '.tmp\SourceData';New-PrivateRepairDirectory $storage
$scratch=Join-Path $storage 'negative';New-PrivateRepairDirectory $scratch
""" + WINDOW_DIAGNOSTICS + r"""
$receipt=Join-Path $scratch 'startup-shell-painted.json'
$file=Open-PrivateRepairFile $receipt;$file.Dispose()
$status=Join-Path $scratch 'status.json'
$file=Open-PrivateRepairFile $status;$file.Dispose()
$log=Join-Path $scratch 'native-window.log'
$self=Get-LiveRepairProcessIdentity ([uint32]$PID)
try {$wrongBirth=$self.CreationFileTime+1}finally{$self.Dispose()}
$runId=[Guid]::NewGuid().ToString('N')
$powershell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$window=Start-OwnedRepairWindow -FilePath $powershell -Arguments @('-NoProfile','-STA','-File',
    (Join-Path $fixtureRoot 'tools\Show-AngeronaStartupRecovery.ps1'),'-StartupShell','-StatusFile',$status,
    '-StartupRunId',$runId,'-SupervisorPid',[string]$PID,'-SupervisorCreationFileTime',[string]$wrongBirth,
    '-PaintReceiptFile',$receipt) -WorkingDirectory $fixtureRoot -Environment (New-RepairChildEnvironment $scratch) -LogPath $log
try {
    $record=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
    while(!$record -and $clock.ElapsedMilliseconds -lt 20000){
        foreach($line in ((Read-SourceStartupLogTail $log) -split "`n")) {
            try {
                $candidate=$line|ConvertFrom-Json
                if($candidate.component -ceq 'startup-recovery-ui' -and $candidate.outcome -ceq 'held'){$record=$candidate;break}
            }catch{} # An incomplete captured line carries no diagnostic authority.
        }
        if(!$record){if($window.HasExited){throw ('Native hold window exited: '+(Read-SourceStartupLogTail $log))};Start-Sleep -Milliseconds 20}
    }
    if(!$record){throw ('Native hold window did not publish its failure: '+(Read-SourceStartupLogTail $log))}
    if($record.phase -cne 'supervisor-verification' -or $record.outcome -cne 'held' -or !$record.painted){throw 'Wrong native held diagnostic.'}
    if($record.run_id -cne $runId -or [string]$record.supervisor_pid -cne [string]$PID -or
        $record.supervisor_creation_filetime -cne [string]$wrongBirth -or
        [string]$record.shell_pid -cne [string]$window.ProcessId -or
        $record.shell_creation_filetime -cne [string]$window.CreationFileTime){throw 'Held diagnostic lost its exact run/process identities.'}
    if((Get-Item -LiteralPath $receipt).Length -ne 0 -or $window.HasExited){throw 'Held window admitted a paint receipt or changed its original hold.'}
    $snapshot=[AngeronaFixtureWindowDiagnostic]::Read($window.ProcessId,$window.CreationFileTime,$powershell)
    if($snapshot.State -cne 'live' -or $snapshot.Error -or $snapshot.Windows -lt 1 -or $snapshot.Text.Count -lt 1 -or
        $snapshot.Windows -gt 2 -or $snapshot.WindowVisible.Count -ne $snapshot.Windows -or
        $snapshot.Controls -gt 48 -or $snapshot.ThreadCount -lt 1 -or
        $snapshot.SessionId -lt 0 -or $snapshot.CpuMilliseconds -lt 0 -or
        $snapshot.ElapsedMilliseconds -gt 2100){throw 'Bounded exact-generation native window observation failed.'}
    $foreign=[AngeronaFixtureWindowDiagnostic]::Read($window.ProcessId,($window.CreationFileTime+1),$powershell)
    if($foreign.State -cne 'unavailable' -or $foreign.Text.Count -ne 0){throw 'A mismatched native generation allowed UI text inspection.'}
    if((Get-Item -LiteralPath $receipt).Length -ne 0 -or $window.HasExited){throw 'Read-only UI evidence changed the original hold.'}
    $window.Dispose()
    if(!$window.HasExited -or $window.ExitCode -ne 1223){throw 'Owned held window did not retire with explicit cancellation.'}
    Write-Output ('RESULT:'+(@{held=$true;receipt_bytes=0;retired=$true;phase=$record.phase}|ConvertTo-Json -Compress))
}finally{$window.Dispose()}
""")
    assert outcome == {"held": True, "receipt_bytes": 0, "retired": True, "phase": "supervisor-verification"}


def test_startup_shell_phase_markers_are_fixed_checking_without_authority(tmp_path):
    outcome = run(tmp_path, r"""
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Show-AngeronaStartupRecovery.ps1'),[ref]$null,[ref]$null)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Write-StartupShellPhase'},$true)
. ([scriptblock]::Create($node.Extent.Text))
$StartupRunId='Bearer fixture-secret';$SupervisorPid=$PID;$SupervisorCreationFileTime=123
$PaintReceiptFile=Join-Path $env:ANGERONA_TEST_SCRATCH 'authority-must-not-exist.json'
$originalError=[Console]::Error;$captured=[IO.StringWriter]::new();$rejected=$false
try {
    [Console]::SetError($captured)
    Write-StartupShellPhase 'script-entry'
    try {Write-StartupShellPhase 'unknown-unsafe-phase'}catch{$rejected=$true}
}finally{[Console]::SetError($originalError)}
$raw=$captured.ToString();$captured.Dispose();$record=$raw|ConvertFrom-Json
if(!$rejected -or $record.phase -cne 'script-entry' -or $record.outcome -cne 'checking' -or
    $record.painted -or $record.run_id -cne '' -or $raw.Contains('fixture-secret') -or
    $raw -match '[^\x00-\x7f]' -or [Text.Encoding]::UTF8.GetByteCount($raw) -gt 1024 -or
    (Test-Path -LiteralPath $PaintReceiptFile) -or $record.PSObject.Properties.Name -contains 'protection_status'){
    throw 'Phase marker reflected untrusted text, exceeded its scope or granted authority.'
}
Write-Output ('RESULT:'+(@{checking=$true;allowlist=$true;no_receipt=$true;bounded=$true}|ConvertTo-Json -Compress))
""")
    assert outcome == {"checking": True, "allowlist": True, "no_receipt": True, "bounded": True}


def test_native_gui_owner_requests_visible_startup_while_commands_stay_hidden(tmp_path):
    outcome = run(tmp_path, r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:ANGERONA_TEST_SCRATCH 'private-canonical-source')}
$storage=Join-Path $env:ANGERONA_TEST_SCRATCH 'state';New-PrivateRepairDirectory $storage
$probe=Join-Path $storage 'kernel-startup-info.ps1'
[IO.File]::WriteAllText($probe,@'
param($Receipt)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class FixtureKernelStartup {
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct INFO {
        public int cb;public IntPtr reserved,desktop,title;
        public uint x,y,width,height,xChars,yChars,fill,flags;
        public ushort show,reservedSize;public IntPtr reservedData,input,output,error;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern void GetStartupInfoW(out INFO info);
    public static string Read() {
        INFO value;GetStartupInfoW(out value);
        return "{\"flags\":"+value.flags+",\"show\":"+value.show+"}";
    }
}
"@
[IO.File]::WriteAllText($Receipt,[FixtureKernelStartup]::Read())
'@)
$powershell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$environment=New-RepairChildEnvironment $storage
$guiReceipt=Join-Path $storage 'gui.json';$commandReceipt=Join-Path $storage 'command.json'
$window=Start-OwnedRepairWindow -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-File',$probe,$guiReceipt) -WorkingDirectory $storage -Environment $environment -LogPath (Join-Path $storage 'gui.log')
try {
    if(!$window.WaitForExit(10000) -or $window.ExitCode -ne 0){throw 'Owned kernel startup-info probe did not retire.'}
}finally{$window.Dispose()}
$code=Invoke-OwnedRepairProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-File',$probe,$commandReceipt) -WorkingDirectory $storage -Environment $environment -TimeoutSeconds 10 -LogPath (Join-Path $storage 'command.log')
if($code -ne 0){throw 'Background kernel startup-info probe failed.'}
$gui=[IO.File]::ReadAllText($guiReceipt)|ConvertFrom-Json
$command=[IO.File]::ReadAllText($commandReceipt)|ConvertFrom-Json
if(($gui.flags -band 0x101) -ne 0x101 -or $gui.show -ne 1 -or
    ($command.flags -band 0x101) -ne 0x101 -or $command.show -ne 0){throw 'Kernel-visible startup flags did not preserve GUI/command roles.'}
Write-Output ('RESULT:'+(@{gui_show=$gui.show;command_show=$command.show;standard_handles=$true}|ConvertTo-Json -Compress))
""")
    assert outcome == {"gui_show": 1, "command_show": 0, "standard_handles": True}


def test_startup_shell_diagnostic_is_redacted_bounded_json_without_json_cmdlet(tmp_path):
    outcome = run(tmp_path, r"""
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Show-AngeronaStartupRecovery.ps1'),[ref]$null,[ref]$null)
foreach($name in @('Protect-RecoveryText','Write-StartupShellDiagnostic')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    . ([scriptblock]::Create($node.Extent.Text))
}
$StartupRunId='a'*32;$SupervisorPid=$PID;$SupervisorCreationFileTime=123
$message=([string]::new([char[]](0..31)))+'"quoted"\path password=fixture-secret '+([string][char]0x6f22)+('X'*8000)
$originalError=[Console]::Error;$captured=[IO.StringWriter]::new()
function ConvertTo-Json {throw 'The diagnostic formatter must not autoload the JSON command.'}
try {
    [Console]::SetError($captured)
    try {throw [InvalidOperationException]::new($message)}catch{Write-StartupShellDiagnostic 'reader-initialization' $_ $true}
}finally{[Console]::SetError($originalError);Remove-Item Function:\ConvertTo-Json}
$raw=$captured.ToString();$captured.Dispose()
$record=$raw|ConvertFrom-Json
if($raw.Contains('fixture-secret') -or !$record.message.Contains('[redacted]') -or
    !$record.message.Contains('"quoted"\path') -or $record.phase -cne 'reader-initialization' -or
    !$record.message.Contains([string][char]0x6f22) -or $raw -match '[^\x00-\x7f]' -or
    $raw.TrimEnd([char[]]"`r`n") -match '[\x00-\x1f]' -or
    $record.outcome -cne 'held' -or !$record.painted -or [Text.Encoding]::UTF8.GetByteCount($raw) -gt 8192){throw 'Diagnostic redaction, escaping or bound failed.'}
Write-Output ('RESULT:'+(@{redacted=$true;bounded=$true;parseable=$true}|ConvertTo-Json -Compress))
""")
    assert outcome == {"redacted": True, "bounded": True, "parseable": True}


def test_startup_shell_diagnostic_overflow_reports_bounded_complete_json(tmp_path):
    outcome = run(tmp_path, r"""
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Show-AngeronaStartupRecovery.ps1'),[ref]$null,[ref]$null)
foreach($name in @('Protect-RecoveryText','Write-StartupShellDiagnostic')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    . ([scriptblock]::Create($node.Extent.Text))
}
$StartupRunId='a'*32;$SupervisorPid=$PID;$SupervisorCreationFileTime=123
$originalError=[Console]::Error;$captured=[IO.StringWriter]::new()
try {
    [Console]::SetError($captured)
    try {throw [InvalidOperationException]::new(([string][char]0x6f22)*8000)}catch{Write-StartupShellDiagnostic 'reader-initialization' $_ $true}
}finally{[Console]::SetError($originalError)}
$raw=$captured.ToString();$captured.Dispose();$record=$raw|ConvertFrom-Json
if($record.outcome -cne 'held' -or !$record.diagnostic_omitted -or $record.reason -cne 'frame-capacity' -or
    [Text.Encoding]::UTF8.GetByteCount($raw) -gt 8192){throw 'Oversized diagnostic did not retain a bounded complete fallback.'}
Write-Output ('RESULT:'+(@{held=$true;omission_explicit=$true;bounded=$true}|ConvertTo-Json -Compress))
""")
    assert outcome == {"held": True, "omission_explicit": True, "bounded": True}


def test_startup_shell_diagnostic_counts_newline_at_reachable_frame_boundaries(tmp_path):
    outcome = run(tmp_path, r"""
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'tools\Show-AngeronaStartupRecovery.ps1'),[ref]$null,[ref]$null)
foreach($name in @('Protect-RecoveryText','Write-StartupShellDiagnostic')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    . ([scriptblock]::Create($node.Extent.Text))
}
$StartupRunId='a'*32;$SupervisorPid=$PID;$SupervisorCreationFileTime=123
function Get-FixtureDiagnostic([string]$Text) {
    $originalError=[Console]::Error;$captured=[IO.StringWriter]::new()
    try {
        [Console]::SetError($captured)
        try {throw [InvalidOperationException]::new($Text)}catch{Write-StartupShellDiagnostic 'reader-initialization' $_ $true}
    }finally{[Console]::SetError($originalError)}
    try {return $captured.ToString()}finally{$captured.Dispose()}
}
$base=Get-FixtureDiagnostic ''
if(($base|ConvertFrom-Json).message -cne ''){throw 'Boundary fixture requires an empty message baseline.'}
$overhead=[Text.Encoding]::UTF8.GetByteCount($base.TrimEnd([char[]]"`r`n"))
$newline=[Text.Encoding]::UTF8.GetByteCount([Environment]::NewLine)
foreach($target in @(8190,8191,8192)) {
    # One escaped Unicode code unit occupies six ASCII bytes; the remaining
    # ASCII text makes each exact line length reachable below the 2048-char cap.
    $escapedLength=$target-$overhead
    $unicode=[int][Math]::Ceiling(($escapedLength-2048)/5.0)
    $ascii=$escapedLength-6*$unicode
    if($unicode -lt 0 -or $ascii -lt 0 -or $unicode+$ascii -gt 2048){throw 'Boundary fixture is outside the real source-message cap.'}
    $message=([string][char]0x6f22)*$unicode+('X'*$ascii)
    $raw=Get-FixtureDiagnostic $message;$record=$raw|ConvertFrom-Json
    if([Text.Encoding]::UTF8.GetByteCount($raw) -gt 8192){throw 'Complete diagnostic record exceeded its byte cap.'}
    if($target+$newline -le 8192){
        if($record.message -cne $message -or [Text.Encoding]::UTF8.GetByteCount($raw) -ne $target+$newline){throw 'Admitted exact-boundary record was truncated or omitted.'}
    }elseif(!$record.diagnostic_omitted -or $record.reason -cne 'frame-capacity'){
        throw 'Line-only capacity check admitted an oversized newline-terminated frame.'
    }
}
Write-Output ('RESULT:'+(@{boundaries=@(8190,8191,8192);complete_frames_bounded=$true}|ConvertTo-Json -Compress))
""")
    assert outcome == {"boundaries": [8190, 8191, 8192], "complete_frames_bounded": True}


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
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:ANGERONA_TEST_SCRATCH 'private-canonical-source')}
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
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:ANGERONA_TEST_SCRATCH 'private-canonical-source')}
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
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:ANGERONA_TEST_SCRATCH 'private-canonical-source')}
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
