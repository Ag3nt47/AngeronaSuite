"""Fixed startup admission and real native observation, with inert private fixtures.

No application, real source update, install, network, key creation or host action
is requested. Native wait tests prove resource observations, not update authority.
"""
from __future__ import annotations

import json
import os
import py_compile
from pathlib import Path
import struct
import subprocess
import sys
import time

import pytest

from angerona import startup
from angerona.__main__ import _source_activation_pending_at
from angerona.resilience.heartbeat import HeartbeatReader, optional_component
from test_source_update_activation import (
    activation as activation, composition as composition, context as context,
    inert_child_factory as inert_child_factory, inert_owner as inert_owner,
    _plan, _approve, _operation,
)


ROOT = Path(__file__).resolve().parents[1]
PS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows source startup")


def wait_json(path, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(.01)
    raise AssertionError("Exact inert native startup fixture did not publish its bounded identity")


def private(path):
    assert startup.private_directory(path, create=True)
    return path


@pytest.fixture
def launch(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    data = private(tmp_path / "data")
    state = private(data / "github-updates")
    launches = private(state / "launches")
    directory = private(launches / ("a" * 32))
    output, release = tmp_path / "identity.json", tmp_path / "release"
    script = tmp_path / "inert-supervisor.ps1"
    script.write_text(r'''$ErrorActionPreference='Stop'
$self=[Diagnostics.Process]::GetCurrentProcess()
$core=[Diagnostics.Process]::GetProcessById([int]$env:TEST_CORE_PID)
$identity=@{pid=$PID;birth=[string]$self.StartTime.ToUniversalTime().ToFileTimeUtc();image=$self.MainModule.FileName
    core_birth=[string]$core.StartTime.ToUniversalTime().ToFileTimeUtc();core_image=$core.MainModule.FileName}
[IO.File]::WriteAllText($env:TEST_IDENTITY,($identity|ConvertTo-Json -Compress))
$clock=[Diagnostics.Stopwatch]::StartNew()
while(!(Test-Path -LiteralPath $env:TEST_RELEASE) -and $clock.ElapsedMilliseconds -lt 8000){Start-Sleep -Milliseconds 10}
$core.Dispose();$self.Dispose();exit 0
''', encoding="utf-8")
    environment = dict(os.environ, TEST_CORE_PID=str(os.getpid()), TEST_IDENTITY=str(output), TEST_RELEASE=str(release))
    child = subprocess.Popen([str(PS), "-NoProfile", "-NonInteractive", "-File", str(script)], cwd=tmp_path,
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        native = wait_json(output)
        assert native["pid"] == child.pid
        descriptor = {"schema": "angerona.source-activation-launch/v1", "launch_id": "a" * 32,
            "source_root": str(root), "state_root": str(state), "supervisor_pid": child.pid,
            "supervisor_birth": native["birth"], "supervisor_image": native["image"],
            "token": "f" * 64, "broker_script_sha256": "b" * 64}
        path = directory / "descriptor.json"
        path.write_text(json.dumps(descriptor), encoding="utf-8")
        monkeypatch.setenv("ANGERONA_SOURCE_ACTIVATION_LAUNCH_ID", "a" * 32)
        plan = startup.LaunchPlan(root, data, (sys.executable, "-m", "angerona"), False)
        yield plan, directory, descriptor, native, child, release
    finally:
        release.touch()
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, stdout + stderr


def test_ready_export_is_actual_native_identity_exclusive_and_token_free(launch):
    plan, directory, descriptor, native, _child, _release = launch
    assert startup._export_activation_ready(plan, os.getpid()) is True
    raw = (directory / "ready.json").read_bytes()
    value = json.loads(raw)
    assert set(value) == {"schema", "launch_id", "source_root", "state_root", "core_pid", "core_birth", "core_image", "descriptor_sha256"}
    assert value["core_pid"] == os.getpid() and value["core_birth"] == native["core_birth"]
    assert value["core_image"].casefold() == native["core_image"].casefold()
    assert descriptor["token"].encode() not in raw and b"token" not in raw
    with pytest.raises(FileExistsError):
        startup._export_activation_ready(plan, os.getpid())
    assert (directory / "ready.json").read_bytes() == raw
    assert startup._ACTIVATION_READY_CLOSE_HOLDS == []


@pytest.mark.parametrize("change", [{"extra": True}, {"supervisor_pid": True}, {"supervisor_birth": "1"},
    {"source_root": "different"}, {"broker_script_sha256": "A" * 64}, {"token": "x"}])
def test_bad_launch_descriptor_never_exports_a_ready_identity(launch, change):
    plan, directory, descriptor, _native, _child, _release = launch
    descriptor.update(change)
    (directory / "descriptor.json").write_text(json.dumps(descriptor), encoding="utf-8")
    with pytest.raises((startup.StartupError, ValueError, TypeError)):
        startup._export_activation_ready(plan, os.getpid())
    assert not (directory / "ready.json").exists()


def test_retired_supervisor_cannot_authorize_a_later_ready_export(launch):
    plan, directory, _descriptor, _native, child, release = launch
    release.touch()
    child.communicate(timeout=10)
    assert child.returncode == 0
    with pytest.raises(startup.StartupError, match="native|query"):
        startup._export_activation_ready(plan, os.getpid())
    assert not (directory / "ready.json").exists()


def test_hardlinked_launch_descriptor_is_held_before_read(launch):
    plan, directory, _descriptor, _native, _child, _release = launch
    os.link(directory / "descriptor.json", directory / "other-link.json")
    with pytest.raises(startup.StartupError, match="links|custody|private"):
        startup._export_activation_ready(plan, os.getpid())
    assert not (directory / "ready.json").exists()


@pytest.mark.parametrize("kind", ["malformed-file", "directory"])
def test_pending_unknown_always_holds_both_bootstrap_predicates(tmp_path, kind):
    local = tmp_path / "local"
    pending = local / "Angerona" / "SourceData" / "github-updates" / "activation-pending.json"
    pending.parent.mkdir(parents=True)
    assert _source_activation_pending_at(local) is False
    if kind == "directory":
        pending.mkdir()
    else:
        pending.write_bytes(b"not an approval or a command")
    assert _source_activation_pending_at(local) is True
    plan = startup.LaunchPlan(tmp_path, local / "Angerona" / "SourceData", (sys.executable,), False)
    with pytest.raises(startup.StartupError, match="interrupted source activation"):
        startup._assert_no_pending_repair(plan)
    assert pending.exists()


def run_ps(tmp_path, body, *, extra=None):
    """Load real function definitions, never executable source entry blocks."""
    script = tmp_path / "activation-fixture.ps1"
    script.write_text(r'''$ErrorActionPreference='Stop'
foreach($name in @('tools\startup_repair_common.ps1','tools\Resume-AngeronaSourceActivation.ps1','tools\startup_assistant_capture.ps1','tools\Invoke-AngeronaSourceStartup.ps1')){
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TEST_ROOT $name),[ref]$tokens,[ref]$errors)
    if(@($errors).Count){throw 'Actual source function definitions have a PowerShell syntax error.'}
    foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
        . ([scriptblock]::Create($node.Extent.Text))
    }
}
function Get-RepairProcessCompilerScratch {return $env:TEST_SCRATCH}
''' + body, encoding="utf-8")
    result = subprocess.run([str(PS), "-NoProfile", "-NonInteractive", "-File", str(script)], cwd=tmp_path,
        env=dict(os.environ, TEST_ROOT=str(ROOT), TEST_PYTHON=str(Path(sys.executable).absolute()),
                 TEST_SCRATCH=str(tmp_path), TEMP=str(tmp_path), TMP=str(tmp_path), **(extra or {})),
        capture_output=True, text=True, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    frames = [line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")]
    assert len(frames) == 1, (
        f"Expected one standalone RESULT frame, got {len(frames)}; "
        f"stdout_chars={len(result.stdout)} stderr_chars={len(result.stderr)}; "
        f"stdout_tail={result.stdout[-4096:]!r}; stderr_tail={result.stderr[-4096:]!r}"
    )
    return json.loads(frames[0])


def test_real_native_identity_wait_and_host_job_are_separate_from_ack_file(tmp_path):
    result = run_ps(tmp_path, r'''
Initialize-SourceActivationProcessOwner
$self=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID)
try{
    $before=$self.WaitForExit(0)
    [IO.File]::WriteAllText((Join-Path $env:TEST_SCRATCH 'fake-ack.json'),'{}')
    $after=$self.WaitForExit(0)
    $retired=[Angerona.SourceActivationProcessOwner]::GenerationRetired([uint32]$PID,$self.Birth,$self.Image)
    $parent=$self.ParentProcessId();$command=$self.CommandLine()
    Write-Output ('RESULT:'+(@{before=$before;after=$after;retired=$retired;parent=$parent;has_command=($command.Contains('activation-fixture.ps1'));birth=[string]$self.Birth;in_job=$self.InAnyJob()}|ConvertTo-Json -Compress))
}finally{$self.Dispose();if(!$self.CloseProven){throw 'Exact native fixture query did not close.'}}
''')
    assert result["before"] == result["after"] == 258 and result["retired"] is False
    assert result["parent"] == os.getpid() and result["has_command"] is True
    assert result["birth"].isdigit() and isinstance(result["in_job"], bool)


def test_closed_stop_binding_rejects_forced_missing_stale_and_bool_counts(tmp_path):
    result = run_ps(tmp_path, r'''
$context=[pscustomobject]@{launch_id=('a'*32);core_pid=123;core_birth='134381000000000000'}
$request=[pscustomobject]@{Sha256=('c'*64);Value=[pscustomobject]@{activation_id=('b'*32)}}
$base=[ordered]@{schema=1;state='retired';operator_stop_recorded=$true;forced=$false;pending_workers=@();pending_custody=@()
    before_cleanup_pending=0;tracked_workers=0;cleanup_error='';discovery_error=''
    source_activation=@{launch_id=$context.launch_id;activation_id=$request.Value.activation_id;request_sha256=$request.Sha256;core_pid=123;core_birth=$context.core_birth}}
$valid=$base|ConvertTo-Json -Depth 5 -Compress|ConvertFrom-Json
Assert-SourceActivationStopReceipt $valid $request $context
$failures=[Collections.Generic.List[string]]::new()
foreach($case in @('forced','missing','stale','pending','error','bool-count')){
    $row=$base|ConvertTo-Json -Depth 5 -Compress|ConvertFrom-Json
    switch($case){
        'forced'{$row.state='forced-incomplete';$row.forced=$true}
        'missing'{$row.PSObject.Properties.Remove('source_activation')}
        'stale'{$row.source_activation.core_birth='1'}
        'pending'{$row.pending_workers=@('real-held-worker')}
        'error'{$row.cleanup_error='actual-failure'}
        'bool-count'{$row.before_cleanup_pending=$false}
    }
    try{Assert-SourceActivationStopReceipt $row $request $context}catch{$failures.Add($case)}
}
Write-Output ('RESULT:'+(@{valid=$true;rejected=@($failures)}|ConvertTo-Json -Compress))
''')
    assert result == {"valid": True, "rejected": ["forced", "missing", "stale", "pending", "error", "bool-count"]}


def test_csharp_owner_frames_authenticate_with_actual_python_reader(tmp_path):
    directory = tmp_path / "heartbeats"
    directory.mkdir()
    result = run_ps(tmp_path, r'''
Initialize-SourceActivationProcessOwner
$master=[byte[]](0..31)
$path=Join-Path $env:TEST_SCRATCH 'heartbeats\source_update_owner.hb'
$slot=[IO.File]::Open($path,'CreateNew','ReadWrite','ReadWrite');$slot.SetLength(32)
$writer=[Angerona.SourceControllerHeartbeat]::new('source_update_owner',('a'*32),$master,$slot)
function Copy-Frame([string]$Name){
    $read=[IO.File]::Open($path,'Open','Read','ReadWrite')
    try{$raw=New-Object byte[] 32;if($read.Read($raw,0,32) -ne 32){throw 'Fixed frame is incomplete.'}
        [IO.File]::WriteAllBytes((Join-Path $env:TEST_SCRATCH $Name),$raw)
    }finally{$read.Dispose()}
}

try{
    $immediate=[Diagnostics.Stopwatch]::StartNew()
    $writer.Pulse();$first=$writer.Counter
    $writer.Pulse();$limited=$writer.Counter;$immediateMilliseconds=$immediate.ElapsedMilliseconds
    Copy-Frame 'first.bin'
    Start-Sleep -Milliseconds 1100
    $writer.Pulse()
    Copy-Frame 'second.bin'
    $second=$writer.Counter;$writer.Stop()
    Copy-Frame 'stopped.bin'
    Write-Output ('RESULT:'+(@{pid=$writer.ProcessId;birth=$writer.Birth;component=$writer.Component;first=$first;limited=$limited;second=$second
        stopped=$writer.Counter;immediate_ms=$immediateMilliseconds;available=$writer.Available;same_thread=($writer.OwnerThreadId -eq $writer.LastThreadId);length=$slot.Length}|ConvertTo-Json -Compress))
}finally{$writer.Dispose();$slot.Dispose();[Array]::Clear($master,0,$master.Length)}
''')
    assert result["available"] is True and result["same_thread"] is True and result["length"] == 32
    assert result["first"] == 1 and result["limited"] in {1, 2}
    if result["immediate_ms"] < 1000:
        assert result["limited"] == 1  # Actual interval excludes legitimate slow scheduling.
    assert result["second"] == result["limited"] + 1 and result["stopped"] == result["second"]
    component = optional_component("source_update_owner", "a" * 32, result["birth"])
    assert result["component"] == component
    records = []
    for name in ("first", "second", "stopped"):
        path = tmp_path / (name + ".bin")
        raw = path.read_bytes()
        assert len(raw) == 32
        reader = HeartbeatReader(component, path=path, key_raw=bytes(range(32)))
        record = reader.read()
        assert reader.authentication_status(record=record) == "authenticated"
        assert record["pid"] == result["pid"] and record["version"] == 2
        assert HeartbeatReader(component + "-different", path=path, key_raw=bytes(range(32))).authentication_status() == "invalid"
        magic, stamp, pid, proof, count, flags = struct.unpack("<IQIQII", raw)
        assert magic == 0x41574447 and stamp == record["ts_ns"] and pid == result["pid"]
        assert proof == record["proof"] and count == record["counter"] and flags == record["wire_flags"]
        records.append(record)
    assert [row["counter"] for row in records] == [result["limited"], result["second"], result["second"]]
    assert [row["flags"] for row in records] == [1, 1, 0]


def test_existing_native_and_capture_callbacks_are_same_thread_optional_and_failure_safe(tmp_path):
    result = run_ps(tmp_path, r'''
Initialize-OwnedRepairProcess
Initialize-SourceStartupCapture
Add-Type -TypeDefinition @'
using System;
using System.Threading;
public static class ActivationPulseFixture {
    public static int Caller=Thread.CurrentThread.ManagedThreadId;
    public static int Count,Wrong;
    public static Action TickAction {get{return new Action(Tick);}}
    public static Action FailAction {get{return new Action(Fail);}}
    public static void Tick(){if(Thread.CurrentThread.ManagedThreadId!=Caller)Wrong++;Count++;}
    public static void Fail(){throw new System.IO.IOException("controlled callback failure");}
}
'@
# This owner transports Windows CRT argv, matching production Python/-File callers.
# Arbitrary CMD shell strings have a separate real /c-/k contract test below.
$exe=$env:TEST_PYTHON
$environment=New-RepairChildEnvironment $env:TEST_SCRATCH
$normal=Invoke-OwnedRepairProcess -FilePath $exe -Arguments @('-I','-B','-c','pass') -WorkingDirectory $env:TEST_SCRATCH -Environment $environment -TimeoutSeconds 5 -LogPath (Join-Path $env:TEST_SCRATCH 'plain.log')
$action=[ActivationPulseFixture]::TickAction
$observed=Invoke-OwnedRepairProcess -FilePath $exe -Arguments @('-I','-B','-c','pass') -WorkingDirectory $env:TEST_SCRATCH -Environment $environment -TimeoutSeconds 5 -LogPath (Join-Path $env:TEST_SCRATCH 'pulse.log') -Heartbeat $action
$failure=[ActivationPulseFixture]::FailAction
$failureExit=Invoke-OwnedRepairProcess -FilePath $exe -Arguments @('-I','-B','-c','pass') -WorkingDirectory $env:TEST_SCRATCH -Environment $environment -TimeoutSeconds 5 -LogPath (Join-Path $env:TEST_SCRATCH 'error.log') -Heartbeat $failure
$strictExit=Invoke-OwnedRepairProcess -FilePath $exe -Arguments @('-I','-B','-c','pass') -WorkingDirectory $env:TEST_SCRATCH -Environment $environment -TimeoutSeconds 5 -LogPath (Join-Path $env:TEST_SCRATCH 'strict.log') -Heartbeat $action -RequireClosedHandles -ScratchLease $null -CriticalStartup:$false
[Angerona.StartupRepairProcess]::RequireRetiredCustody()
$python=$env:TEST_PYTHON
$parentAcl=[IO.Directory]::GetAccessControl($env:TEST_SCRATCH).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
$captureScratch=Join-Path $env:TEST_SCRATCH 'capture-private'
New-PrivateRepairDirectory -Path $captureScratch
Assert-PrivateRepairCustody $captureScratch
$captureEnvironment=New-RepairChildEnvironment $captureScratch
$captured=Invoke-SourceStartupCapturedAssistant -Python $python -Arguments @('-I','-B','-c','print("inert")') -WorkingDirectory $captureScratch -Environment $captureEnvironment -TimeoutSeconds 5 -StdoutPath (Join-Path $captureScratch 'stdout.log') -StderrPath (Join-Path $captureScratch 'stderr.log') -Heartbeat $action
$capturedFailure=Invoke-SourceStartupCapturedAssistant -Python $python -Arguments @('-I','-B','-c','print("inert")') -WorkingDirectory $captureScratch -Environment $captureEnvironment -TimeoutSeconds 5 -StdoutPath (Join-Path $captureScratch 'stdout-error.log') -StderrPath (Join-Path $captureScratch 'stderr-error.log') -Heartbeat $failure
try{
    if(!$captured.Process.HasExited -or !$captured.ReadersComplete -or !$capturedFailure.Process.HasExited -or !$capturedFailure.ReadersComplete){throw 'Actual inert capture/native readers did not retire.'}
    Write-Output ('RESULT:'+(@{plain=$normal;observed=$observed;callback_failure_exit=$failureExit
        strict=$strictExit;count=[ActivationPulseFixture]::Count;wrong=[ActivationPulseFixture]::Wrong;native_errors=[Angerona.StartupRepairProcess]::HeartbeatFailures
        capture=$captured.ExitCode;capture_failure=$capturedFailure.ExitCode;capture_errors=$capturedFailure.HeartbeatFailures
        parent_acl_unchanged=($parentAcl -ceq [IO.Directory]::GetAccessControl($env:TEST_SCRATCH).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
        pipes=($captured.ReadersComplete -and $capturedFailure.ReadersComplete);custody=[Angerona.StartupRepairProcess]::CustodyPending}|ConvertTo-Json -Compress))
}finally{$captured.Process.Dispose();$capturedFailure.Process.Dispose()}
''')
    assert result["plain"] == result["observed"] == result["callback_failure_exit"] == result["strict"] == 0
    assert result["capture"] == result["capture_failure"] == 0 and result["pipes"] is True
    assert result["parent_acl_unchanged"] is True
    assert result["count"] >= 2 and result["wrong"] == 0
    assert result["native_errors"] >= 1 and result["capture_errors"] >= 1 and result["custody"] is False


def test_optional_query_close_failure_keeps_real_startup_pass_ready_without_owner(tmp_path):
    # Inert disposal-failure acknowledgement at the native observation seam;
    # actual Close-SourceActivationQueries and Invoke-SourceStartupPass run.
    # No real query handle is leaked and no assistant/application is launched.
    result = run_ps(tmp_path, r'''
$script:closeCalls=0;$script:assistantReady=$false;$script:activationComplete=$false;$script:released=$false
$script:cacheChecks=0;$script:cachePrefix='';$script:SourceStartupCriticalMode=$true
$script:uncertain=[pscustomobject]@{}
$script:uncertain|Add-Member ScriptMethod Dispose {$script:closeCalls++;throw 'controlled query-close acknowledgement failure'}
function Assert-SourceStartupBoundary([string]$Root){}
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:TEST_SCRATCH 'private-canonical-source')}
New-PrivateRepairDirectory (Get-CanonicalSourceStartupStorage)
function Initialize-SourceStartupStorage {return (Get-CanonicalSourceStartupStorage)}
function Enter-RepairLease([string]$Root){return [pscustomobject]@{inert=$true}}
function Exit-RepairLease($Lease){$script:released=$true}
function Assert-NoPendingRepair([string]$Root){}
function New-RepairChildEnvironment([string]$Scratch) {
    return @{ANGERONA_SOURCE_ACTIVATION_LAUNCH_ID=('f'*32);TEMP=$Scratch;TMP=$Scratch}
}
function Assert-FixtureCacheLease([string]$Prefix,[string]$Root,[string]$Scratch) {
    Assert-SourceStartupCachePrefix $Prefix $Root $Scratch
    $key=[IO.Path]::GetFullPath($Root)+'|'+[IO.Path]::GetFullPath((Get-CanonicalSourceStartupStorage))+'|preflight'
    $context=$script:SourceStartupCriticalWorkspaces[$key]
    if(!$context -or $context.Path -cne $Scratch -or !$context.Guard.CanRead -or $context.Guard.CanWrite -or
       ![Object]::ReferenceEquals($context.Guard,$script:SourceStartupScratchLease)){
        throw 'The optional observer fixture lost the actual retained preflight scratch lease.'
    }
    if($script:cachePrefix -and $script:cachePrefix -cne $Prefix){throw 'The startup pass changed its fresh-cache prefix.'}
    $script:cachePrefix=$Prefix;$script:cacheChecks++
}
function New-SourceActivationLaunch([string]$Root){Close-SourceActivationQueries @($script:uncertain) -OptionalStartup}
function Initialize-OwnedRepairProcess {}
function Invoke-OwnedRepairProcess {
    param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds,$LogPath)
    if($Arguments.Count -lt 3 -or $Arguments[0] -cne '-B' -or $Arguments[1] -cne '-X' -or
       !$Arguments[2].StartsWith('pycache_prefix=',[StringComparison]::Ordinal)){
        throw 'The inert read-only probe lost fresh-cache interpreter options.'
    }
    if($Environment['TMP'] -cne $Environment['TEMP']){throw 'The read-only probe scratch paths diverged.'}
    Assert-FixtureCacheLease $Arguments[2].Substring('pycache_prefix='.Length) $WorkingDirectory $Environment['TEMP']
    return 0
}
function Test-SourceStartupShellClosed {return $false}
function Complete-SourceActivationLaunch {$script:activationComplete=$true}
function Invoke-SourceStartupAssistant {
    param($Python,$Root,$Environment,$Scratch,[switch]$SoftwareRenderer,[switch]$NoStartupWindow,$FreshCachePrefix)
    if($Environment.ContainsKey('ANGERONA_SOURCE_ACTIVATION_LAUNCH_ID')){throw 'A failed optional observer leaked an owner expectation.'}
    Assert-FixtureCacheLease $FreshCachePrefix $Root $Scratch
    $script:assistantReady=$true;return 0
}
$fixtureRoot=Join-Path $env:TEST_SCRATCH 'source'
[void][IO.Directory]::CreateDirectory((Join-Path $fixtureRoot 'venv\Scripts'))
[IO.File]::WriteAllBytes((Join-Path $fixtureRoot 'venv\Scripts\python.exe'),[byte[]]@())
try {
    $code=Invoke-SourceStartupPass -Root $fixtureRoot
    Write-Output ('RESULT:'+(@{code=$code;ready=$script:assistantReady;activation=$script:activationComplete
        close_calls=$script:closeCalls;lease_released=$script:released;cache_checks=$script:cacheChecks
        cache_absent=!(Test-Path -LiteralPath $script:cachePrefix)}|ConvertTo-Json -Compress))
} finally { Close-SourceStartupCriticalWorkspaces }
''')
    assert result == {"code": 0, "ready": True, "activation": False, "close_calls": 1,
                      "lease_released": True, "cache_checks": 4, "cache_absent": True}


def test_real_launcher_handles_must_retire_after_ack_before_reconcile_can_continue(tmp_path):
    result = run_ps(tmp_path, r'''
Initialize-SourceActivationProcessOwner
$childScript=Join-Path $env:TEST_SCRATCH 'inert-native-launcher.ps1'
[IO.File]::WriteAllText($childScript,@'
param([int]$FixtureExit,[string]$Release)
$end=[Diagnostics.Stopwatch]::StartNew()
while(!(Test-Path -LiteralPath $Release) -and $end.ElapsedMilliseconds -lt 15000){Start-Sleep -Milliseconds 10}
exit $FixtureExit
'@)
$release=Join-Path $env:TEST_SCRATCH 'allow-real-native-exit'
$systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
function Start-InertLauncher([int]$Code){
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$systemPs;$info.UseShellExecute=$false
    $info.CreateNoWindow=$true;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    $args=@('-NoProfile','-NonInteractive','-File',$childScript,'-FixtureExit',[string]$Code,'-Release',$release)
    $info.Arguments=($args|ForEach-Object{ConvertTo-SourceActivationArgument ([string]$_)}) -join ' '
    return [Diagnostics.Process]::Start($info)
}
$gateProcess=$null;$cmdProcess=$null;$gate=$null;$cmd=$null;$gateCloseAttempted=$false;$cmdCloseAttempted=$false
try{
    $gateProcess=Start-InertLauncher 88;$cmdProcess=Start-InertLauncher 0
    $gate=[Angerona.SourceActivationProcessOwner]::new([uint32]$gateProcess.Id)
    $cmd=[Angerona.SourceActivationProcessOwner]::new([uint32]$cmdProcess.Id)
    [IO.File]::WriteAllText((Join-Path $env:TEST_SCRATCH 'ready-ack.json'),'{}')
    $held=$false
    try{[void](Wait-SourceActivationLauncherRetirement $gate $cmd 100)}catch{$held=$true}
    if(!$held -or $gate.WaitForExit(0) -ne 258 -or $cmd.WaitForExit(0) -ne 258){throw 'A file was incorrectly accepted as native retirement.'}
    [IO.File]::WriteAllText($release,'release')
    $retired=Wait-SourceActivationLauncherRetirement $gate $cmd 10000
    $gateCode=$gate.ExitCode;$cmdCode=$cmd.ExitCode
    $gateCloseAttempted=$true;$gate.Dispose();$cmdCloseAttempted=$true;$cmd.Dispose()
    if(!$gate.CloseProven -or !$cmd.CloseProven){throw 'Exact launcher query closure is incomplete.'}
    Write-Output ('RESULT:'+(@{held_before_native_exit=$held;retired=$retired;gate_exit=$gateCode;cmd_exit=$cmdCode
        query_close=($gate.CloseProven -and $cmd.CloseProven)}|ConvertTo-Json -Compress))
}finally{
    [IO.File]::WriteAllText($release,'release')
    foreach($process in @($gateProcess,$cmdProcess)){if($process){if(!$process.WaitForExit(18000)){throw 'Inert launcher did not retire.'};$process.Dispose()}}
    # Each original owner receives at most one close attempt, including errors.
    if($gate -and !$gateCloseAttempted){$gateCloseAttempted=$true;$gate.Dispose()}
    if($cmd -and !$cmdCloseAttempted){$cmdCloseAttempted=$true;$cmd.Dispose()}
}
''')
    assert result == {"held_before_native_exit": True, "retired": True, "gate_exit": 88,
                      "cmd_exit": 0, "query_close": True}


def test_existing_inherited_heartbeat_directory_is_read_only_compatible_and_no_key_is_created(tmp_path):
    result = run_ps(tmp_path, r'''
$script:fixtureData=Join-Path $env:TEST_SCRATCH 'private-data'
New-PrivateRepairDirectory $script:fixtureData
function Get-CanonicalSourceStartupStorage {return $script:fixtureData}
$missing=Start-SourceControllerHeartbeat 'source_startup' ('a'*32)
if($missing -or (Test-Path -LiteralPath (Join-Path $script:fixtureData 'shutdown.key'))){throw 'A missing existing key was manufactured.'}
$directory=Join-Path $script:fixtureData 'heartbeats'
[void][IO.Directory]::CreateDirectory($directory) # Same inherited default as hb_dir().mkdir.
$before=[Convert]::ToBase64String(([IO.Directory]::GetAccessControl($directory)).GetSecurityDescriptorBinaryForm())
$keyPath=Join-Path $script:fixtureData 'shutdown.key'
$key=Open-PrivateRepairFile $keyPath
try{$bytes=[Text.Encoding]::ASCII.GetBytes(('01'*32));$key.Write($bytes,0,$bytes.Length);$key.Flush($true)}finally{$key.Dispose()}
$keyHash=Get-RepairFileSha256 $keyPath
$writer=Start-SourceControllerHeartbeat 'source_startup' ('a'*32)
if(!$writer -or !$writer.Writer.Available){throw 'Default inherited heartbeat directory was unavailable.'}
$counter=$writer.Writer.Counter
Stop-SourceControllerHeartbeat $writer
Assert-SourceControllerHeartbeatCustody
$after=[Convert]::ToBase64String(([IO.Directory]::GetAccessControl($directory)).GetSecurityDescriptorBinaryForm())
if($before -cne $after -or (Get-RepairFileSha256 $keyPath) -cne $keyHash){throw 'Existing directory ACL or key bytes changed.'}
$acl=[IO.Directory]::GetAccessControl($directory)
$world=[Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$rule=[Security.AccessControl.FileSystemAccessRule]::new($world,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
[void]$acl.AddAccessRule($rule);[IO.Directory]::SetAccessControl($directory,$acl)
$unsafe=[Convert]::ToBase64String(([IO.Directory]::GetAccessControl($directory)).GetSecurityDescriptorBinaryForm())
$rejected=$false
try{Assert-SourceControllerHeartbeatDirectory $directory $script:fixtureData}catch{$rejected=$true}
if(!$rejected -or $unsafe -cne [Convert]::ToBase64String(([IO.Directory]::GetAccessControl($directory)).GetSecurityDescriptorBinaryForm())){throw 'Unknown directory ACL was accepted or rewritten.'}
Write-Output ('RESULT:'+(@{missing_key_held=($null -eq $missing);counter=$counter;acl_unchanged=($before -ceq $after);unsafe_held=$rejected
    one_close=$writer.CloseAttempted;close_held=$writer.CloseHeld}|ConvertTo-Json -Compress))
''')
    assert result == {"missing_key_held": True, "counter": 1, "acl_unchanged": True,
                      "unsafe_held": True, "one_close": True, "close_held": False}


def test_heartbeat_cleanup_uncertainty_retains_exact_owner_once_and_denies_activation(tmp_path):
    result = run_ps(tmp_path, r'''
$script:writerClose=0;$script:slotClose=0
$writer=[pscustomobject]@{}
$writer|Add-Member ScriptMethod Dispose {$script:writerClose++;throw 'inert close acknowledgement failure'}
$slot=[pscustomobject]@{}
$slot|Add-Member ScriptMethod Dispose {$script:slotClose++}
$owner=[pscustomobject]@{Writer=$writer;Slot=$slot;KeyLease=$null;KeyPin=$null;WriterLease=$null;CloseAttempted=$false;CloseHeld=$false}
Stop-SourceControllerHeartbeat $owner
Stop-SourceControllerHeartbeat $owner # Must not repeat an uncertain close acknowledgement.
$held=$false
try{Assert-SourceControllerHeartbeatCustody}catch{$held=$true}
$exact=($script:SourceControllerHeartbeatCloseHolds.Count -eq 1 -and [object]::ReferenceEquals($script:SourceControllerHeartbeatCloseHolds[0],$owner))
Write-Output ('RESULT:'+(@{writer_calls=$script:writerClose;slot_calls=$script:slotClose;held=$held;exact_owner=$exact;sticky=$owner.CloseHeld}|ConvertTo-Json -Compress))
''')
    assert result == {"writer_calls": 1, "slot_calls": 1, "held": True, "exact_owner": True, "sticky": True}


def test_ready_unknown_close_acknowledgement_retains_api_and_raw_owner_without_retry(tmp_path):
    # The inert acknowledgement seam closes the ACTUAL query, then raises.
    # The child must still retain uncertainty; it never retries that value.
    script = tmp_path / "native-close-ack.py"
    script.write_text("import sys\nsys.path.insert(0, " + repr(str(ROOT / "src")) + ")\n" + r'''
import ctypes, json, os
from ctypes import wintypes as w
from angerona import startup
actual_factory = ctypes.WinDLL
actual = actual_factory("kernel32", use_last_error=True)
actual.CloseHandle.argtypes = (w.HANDLE,)
actual.CloseHandle.restype = w.BOOL
class UnknownAcknowledgement(BaseException):
    pass
class Proxy:
    def __getattr__(self, name):
        return getattr(actual, name)
proxy = Proxy()
calls, closed, raw = [], [], []
def close(handle):
    calls.append(1)
    raw.append(handle)
    closed.append(bool(actual.CloseHandle(handle)))
    raise UnknownAcknowledgement()
proxy.CloseHandle = close
ctypes.WinDLL = lambda name, *a, **kw: proxy if str(name).lower() == "kernel32" else actual_factory(name, *a, **kw)
try:
    try:
        startup._activation_native_identity(os.getpid())
    except UnknownAcknowledgement:
        held = startup._ACTIVATION_READY_CLOSE_HOLDS
        assert len(calls) == 1 and closed == [True] and len(held) == 1
        assert held[0][0] is proxy and held[0][1] == raw[0]
        try:
            startup._activation_native_identity(os.getpid())
        except startup.StartupError as error:
            assert "earlier" in str(error)
        else:
            raise AssertionError("A retained unknown close allowed another observation")
        assert len(calls) == 1
        print(json.dumps({"calls": len(calls), "actual_close": closed[0], "exact_unknown_owner": True}))
    else:
        raise AssertionError("Unknown native close acknowledgement was swallowed")
finally:
    ctypes.WinDLL = actual_factory
''', encoding="utf-8")
    outcome = subprocess.run([sys.executable, "-I", "-B", str(script)], cwd=tmp_path,
        capture_output=True, text=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    assert outcome.returncode == 0, outcome.stdout + outcome.stderr
    assert json.loads(outcome.stdout) == {"calls": 1, "actual_close": True, "exact_unknown_owner": True}


@pytest.mark.parametrize("strict, mode", [(False, "false"), (True, "false"), (True, "throw")])
def test_activation_only_strict_close_retains_false_or_unknown_ack_without_retry(tmp_path, strict, mode):
    # Synthetic raw value is NEVER sent to the kernel. The actual private
    # acknowledgement helper receives an inert delegate only through reflection;
    # production RunCore always passes the fixed native CloseHandle method.
    body = r'''
Initialize-OwnedRepairProcess
Add-Type -TypeDefinition @'
using System;
public static class StrictCloseAcknowledgementFixture {
    public static int Calls;
    public static bool False(IntPtr raw){Calls++;return false;}
    public static bool Unknown(IntPtr raw){Calls++;throw new System.IO.IOException("inert unknown acknowledgement");}
    public static Func<IntPtr,bool> FalseAction{get{return new Func<IntPtr,bool>(False);}}
    public static Func<IntPtr,bool> UnknownAction{get{return new Func<IntPtr,bool>(Unknown);}}
}
'@
$flags=[Reflection.BindingFlags]'Static,NonPublic'
$type=[Angerona.StartupRepairProcess]
$method=$type.GetMethod('CloseOriginal',$flags)
$callback=if('__MODE__' -ceq 'throw'){[StrictCloseAcknowledgementFixture]::UnknownAction}else{[StrictCloseAcknowledgementFixture]::FalseAction}
$owner=[object]::new();$raw=[IntPtr]::new(16962)
$returned=$method.Invoke($null,[object[]]@($raw,'inert-unit-ack',$owner,__STRICT__,$callback))
$held=$type.GetField('heldCustody',$flags).GetValue($null)
$denied=0
for($index=0;$index -lt 2;$index++){try{[Angerona.StartupRepairProcess]::RequireRetiredCustody()}catch{$denied++}}
$exact=$false
if($held.Count -eq 1){
    $row=$held[0];$public=[Reflection.BindingFlags]'Instance,Public'
    $exact=($row.GetType().GetField('raw',$public).GetValue($row) -eq $raw -and
        $row.GetType().GetField('kind',$public).GetValue($row) -ceq 'inert-unit-ack' -and
        [object]::ReferenceEquals($row.GetType().GetField('owner',$public).GetValue($row),$owner))
}
Write-Output ('RESULT:'+(@{returned=$returned;calls=[StrictCloseAcknowledgementFixture]::Calls;holds=$held.Count
    exact_owner=$exact;denied=$denied}|ConvertTo-Json -Compress))
'''
    result = run_ps(tmp_path, body.replace("__STRICT__", "$true" if strict else "$false").replace("__MODE__", mode))
    assert result == {"returned": not strict, "calls": 1, "holds": int(strict),
                      "exact_owner": strict, "denied": 2 if strict else 0}


@pytest.mark.parametrize("case", ["current-helpers-absent", "original-resume-missing", "original-common-tampered"])
def test_fixed_original_capsule_is_independent_of_mutable_helpers_and_refuses_missing_or_tampered_originals(
        tmp_path, activation, case):
    # Reuse the REAL staged ZIP/plan/capsule API fixture. This invokes only the
    # production content/custody verifier, not native/STOP authority or effects;
    # no invented ready/parent/retirement receipt is supplied.
    sample = activation
    plan = _plan(sample)
    operation = _operation(sample, plan)
    capsule = operation / "broker"
    if case == "current-helpers-absent":
        for name in ("tools/Invoke-AngeronaSourceStartup.ps1", "tools/startup_repair_common.ps1"):
            path = sample.root / name
            assert path.is_relative_to(sample.root) and path.is_file()
            path.rename(path.with_name(path.name + ".preserved"))
    elif case == "original-resume-missing":
        path = capsule / "tools/Resume-AngeronaSourceActivation.ps1"
        path.rename(path.with_name(path.name + ".preserved"))
    else:
        path = capsule / "tools/startup_repair_common.ps1"
        with path.open("r+b") as stream:
            stream.write(b"# tampered inert original fixture")
            stream.truncate()
    result = run_ps(tmp_path, r'''
$plan=Read-SourceActivationRecord $env:TEST_PLAN 16777216
$held=$false;$count=0
try{
    $snapshot=Get-SourceActivationOriginalSnapshot $env:TEST_CAPSULE $plan.Value.broker_snapshot
    $count=@($snapshot.Value.files.PSObject.Properties).Count
}catch{$held=$true}
Write-Output ('RESULT:'+(@{held=$held;files=$count}|ConvertTo-Json -Compress))
''', extra={"TEST_PLAN": str(operation / "plan.json"), "TEST_CAPSULE": str(capsule)})
    if case == "current-helpers-absent":
        assert result == {"held": False, "files": 18}
        assert not (sample.root / "tools/Invoke-AngeronaSourceStartup.ps1").exists()
        assert not (sample.root / "tools/startup_repair_common.ps1").exists()
    else:
        assert result == {"held": True, "files": 0}


def test_two_exact_owner_archivals_leave_next_context_slot_free_and_never_overwrite_unknown_history(tmp_path):
    # Actual private file/record API bookkeeping only. These deliberately
    # non-authority schemas cannot pass production launch/owner admission.
    result = run_ps(tmp_path, r'''
$script:fixtureData=Join-Path $env:TEST_SCRATCH 'archive-data'
New-PrivateRepairDirectory $script:fixtureData
function Get-CanonicalSourceStartupStorage {return $script:fixtureData}
$state=Join-Path $script:fixtureData 'github-updates';New-PrivateRepairDirectory $state
$launches=Join-Path $state 'launches';New-PrivateRepairDirectory $launches
$source=Join-Path $state 'activation-owner.json';$history=[Collections.Generic.List[object]]::new()
foreach($digit in @('1','2')){
    $id=$digit*32;$directory=Join-Path $launches $id;New-PrivateRepairDirectory $directory
    $value=[ordered]@{schema='fixture-record-not-activation-authority/v1';launch_id=$id;sequence=[int]$digit}
    $owner=Write-NewSourceActivationRecord $source $value
    Archive-SourceActivationOwnerRecord $owner $state
    $archived=Read-SourceActivationRecord (Join-Path $directory 'owner-retired.json')
    if((Test-Path -LiteralPath $source) -or $archived.Sha256 -cne $owner.Sha256){throw 'Exact old owner was not archived before the next context.'}
    $history.Add($archived.Sha256)
}
$id='3'*32;$directory=Join-Path $launches $id;New-PrivateRepairDirectory $directory
$owner=Write-NewSourceActivationRecord $source ([ordered]@{schema='fixture-record-not-activation-authority/v1';launch_id=$id;sequence=3})
$bytes=[Text.Encoding]::UTF8.GetBytes('{"schema":"changed-record","launch_id":"'+$id+'"}')
$stream=[IO.File]::Open($source,'Open','Write','Read')
try{$stream.Write($bytes,0,$bytes.Length);$stream.SetLength($bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$changed=Read-SourceActivationRecord $source;$mismatch=$false
try{Archive-SourceActivationOwnerRecord $owner $state}catch{$mismatch=$true}
$destination=Join-Path $directory 'owner-retired.json'
[void](Write-NewSourceActivationRecord $destination ([ordered]@{scope='unknown-history-preserve'}))
$originalHistory=Get-RepairFileSha256 $destination;$collision=$false
try{Archive-SourceActivationOwnerRecord $changed $state}catch{$collision=$true}
Write-Output ('RESULT:'+(@{archives=$history.Count;distinct=($history[0] -cne $history[1]);mismatch=$mismatch;collision=$collision
    current_unchanged=((Read-SourceActivationRecord $source).Sha256 -ceq $changed.Sha256)
    unknown_preserved=((Get-RepairFileSha256 $destination) -ceq $originalHistory)}|ConvertTo-Json -Compress))
''')
    assert result == {"archives": 2, "distinct": True, "mismatch": True, "collision": True,
                      "current_unchanged": True, "unknown_preserved": True}


@pytest.mark.parametrize("mode", ["/c", "/k"])
def test_real_fixed_cmd_invocation_allows_only_noninteractive_launcher_handoff(tmp_path, mode):
    # This is an exclusively owned INERT test cmd, never the user's shell.
    # Normal stdin releases the batch and then exits /k; no termination/kill.
    body = r'''
Initialize-SourceActivationProcessOwner
$root=Join-Path $env:TEST_SCRATCH 'inert-source';[void][IO.Directory]::CreateDirectory($root)
$batch=Join-Path $root 'start-angerona.bat'
$ready=Join-Path $root 'stdin-release.ready'
if([IO.File]::Exists($ready)){throw 'Inert command readiness unexpectedly predates its owned launch.'}
[IO.File]::WriteAllLines($batch,[string[]]@('@echo off','set /p _owned_wait=','>"%~dp0stdin-release.ready" echo release-observed','exit /b 0'))
function Wait-InertCmdRelease([string]$Ready) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while($clock.ElapsedMilliseconds -lt 5000){
        try{
            if([IO.File]::Exists($Ready) -and ([IO.FileInfo]::new($Ready)).Length -le 64 -and
                [IO.File]::ReadAllText($Ready).Trim() -ceq 'release-observed'){return $true}
        }catch [IO.IOException] {} # The fixed writer may still be closing its tiny marker.
        Start-Sleep -Milliseconds 10
    }
    throw 'Inert command did not acknowledge set/p release within its existing outer test budget.'
}
$info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
$info.Arguments='/d __MODE__ "'+$batch+'"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;$info.RedirectStandardInput=$true
$process=$null;$owner=$null;$closeAttempted=$false;$releaseSent=$false;$releaseObserved=$false
$interactive=('__MODE__' -ceq '/k')
try{
    $process=[Diagnostics.Process]::Start($info)
    $owner=[Angerona.SourceActivationProcessOwner]::new([uint32]$process.Id)
    $held=$false;$reason='';$inJob=$owner.InAnyJob()
    try{Assert-SourceActivationBatchParent $owner $root}catch{$held=$true;$reason=$_.Exception.Message}
    $process.StandardInput.WriteLine('release-owned-fixture');$process.StandardInput.Flush();$releaseSent=$true
    $releaseObserved=Wait-InertCmdRelease $ready
    if($interactive){$process.StandardInput.WriteLine('exit');$process.StandardInput.Flush()}
    $wait=$owner.WaitForExit(10000);$exit=$owner.ExitCode
    $closeAttempted=$true;$owner.Dispose()
    Write-Output ("`nRESULT:"+(@{held=$held;in_job=$inJob;reason=$reason;wait=$wait;exit=$exit;closed=$owner.CloseProven;release_observed=$releaseObserved}|ConvertTo-Json -Compress))
}finally{
    if($process){
        if(!$process.HasExited){try{
            if(!$releaseSent){$process.StandardInput.WriteLine('release-owned-fixture');$process.StandardInput.Flush();$releaseSent=$true}
            [void](Wait-InertCmdRelease $ready)
            if($interactive){$process.StandardInput.WriteLine('exit');$process.StandardInput.Flush()}
        }catch{}}
        if(!$process.WaitForExit(10000)){throw 'Exact inert command fixture did not retire normally.'}
        $process.Dispose()
    }
    if($owner -and !$closeAttempted){$closeAttempted=$true;$owner.Dispose()}
}
'''
    result = run_ps(tmp_path, body.replace("__MODE__", mode))
    assert result["wait"] == result["exit"] == 0 and result["closed"] is True
    assert result["release_observed"] is True
    assert type(result["in_job"]) is bool
    assert result["held"] is (mode == "/k" or result["in_job"])
    if mode == "/k":
        assert "noninteractive /c" in result["reason"]
    elif result["in_job"]:
        # CI's real outer Job must remain a real hold, never a fake exemption.
        assert "Job lifetime" in result["reason"]
    else:
        assert result["reason"] == ""


def test_same_size_same_second_legacy_pyc_is_bypassed_for_helper_and_core_without_deleting_cache(tmp_path):
    root = private(tmp_path / "cache-source")
    data = private(tmp_path / "cache-data")
    # Direct probe_source assumes the storage setup normally done by startup.
    private(data / "logs")
    temporary = private(data / "tmp")
    scratch = private(temporary / "startup-temp.critical-preflight")
    state = private(data / "github-updates")
    # Presence is only a restrictive cache-policy trigger, never approval.
    (state / "applied-base.json").write_bytes(b"synthetic-cache-policy-presence-not-an-approval")
    old_bytes = b"VALUE = 'old'\n"
    new_bytes = b"VALUE = 'new'\n"
    assert len(old_bytes) == len(new_bytes)
    cached = {}
    for name in ("helper_cache_probe", "core_cache_probe"):
        source = root / (name + ".py")
        source.write_bytes(old_bytes)
        stamp = 1_710_000_000_000_000_000
        os.utime(source, ns=(stamp, stamp))
        # The -I baseline child ignores PYTHONPYCACHEPREFIX. Place the old
        # timestamp cache in its actual adjacent lookup path, even when this
        # parent pytest was started with an unrelated cache-prefix setting.
        legacy_cache = root / "__pycache__" / f"{name}.{sys.implementation.cache_tag}.pyc"
        cache = Path(py_compile.compile(str(source), cfile=str(legacy_cache),
                     doraise=True, optimize=0,
                     invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
        assert cache == legacy_cache
        assert int.from_bytes(cache.read_bytes()[4:8], "little") == 0
        cached[cache] = (cache.read_bytes(), cache.stat().st_ino)
        original = source.stat()
        with source.open("r+b") as stream:
            stream.write(new_bytes)
            stream.truncate()
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        assert source.stat().st_size == len(old_bytes)
        assert source.stat().st_mtime_ns == original.st_mtime_ns
    baseline = subprocess.run([sys.executable, "-I", "-B", "-c",
        "import sys;sys.path.insert(0,sys.argv[1]);import helper_cache_probe;print(helper_cache_probe.VALUE)", str(root)],
        cwd=tmp_path, capture_output=True, text=True, timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    assert baseline.returncode == 0 and baseline.stdout.strip() == "old", baseline.stderr
    prefix = scratch / ("source-pycache-" + "a" * 32)
    assert not prefix.exists()
    helper = tmp_path / "fresh-helper.py"
    helper.write_text("import sys\nsys.path.insert(0," + repr(str(ROOT / "src")) + ")\n" + r'''
import json, subprocess, threading
from pathlib import Path
from angerona import startup
root, data = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(root))
import helper_cache_probe
command = startup._source_core_command(Path(sys.executable), root, data, frozen=False)
assert command[-2:] == ("-m", "angerona")
assert command[1:4] == ("-B", "-X", "pycache_prefix=" + sys.pycache_prefix)
assert startup._source_core_command(Path(sys.executable), root, data, frozen=True) == (sys.executable,)
class ProbeArgumentsCaptured(Exception):
    pass
captured = []
def capture_probe(arguments, **kwargs):
    captured.append(arguments)
    raise ProbeArgumentsCaptured()
startup._spawn_probe = capture_probe
try:
    startup.probe_source(startup.LaunchPlan(root, data, command, False), {}, threading.Event())
except ProbeArgumentsCaptured:
    pass
assert captured and tuple(captured[0][1:4]) == command[1:4]

probe = "import sys;sys.path.insert(0,sys.argv[1]);import core_cache_probe;print(core_cache_probe.VALUE)"
child = subprocess.run([*command[:-2], "-c", probe, str(root)], capture_output=True,
                       text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
assert child.returncode == 0, child.stderr
print(json.dumps({"helper": helper_cache_probe.VALUE, "core": child.stdout.strip(),
                  "prefix_exists": Path(sys.pycache_prefix).exists(), "core_options": list(command[1:4])}))
''', encoding="utf-8")
    fresh = subprocess.run([sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(prefix),
        str(helper), str(root), str(data)], cwd=tmp_path, capture_output=True, text=True,
        timeout=25, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    assert fresh.returncode == 0, fresh.stdout + fresh.stderr
    value = json.loads(fresh.stdout)
    assert value == {"helper": "new", "core": "new", "prefix_exists": False,
                     "core_options": ["-B", "-X", "pycache_prefix=" + str(prefix)]}
    assert not prefix.exists()
    for path, original in cached.items():
        assert (path.read_bytes(), path.stat().st_ino) == original


def test_canonical_helper_cache_options_precede_module_and_persist_after_update_evidence(tmp_path):
    result = run_ps(tmp_path, r'''
$script:cacheData=Join-Path $env:TEST_SCRATCH 'cache-data';New-PrivateRepairDirectory $script:cacheData
function Get-CanonicalSourceStartupStorage {return $script:cacheData}
$root=Join-Path $env:TEST_SCRATCH 'cache-source';New-PrivateRepairDirectory $root
$tools=Join-Path $root 'tools';New-PrivateRepairDirectory $tools
# Arguments-only seam throws BEFORE any returned native/capture proof.
[IO.File]::WriteAllText((Join-Path $tools 'startup_assistant_capture.ps1'),@'
function Invoke-SourceStartupCapturedAssistant {
    param($Python,[string[]]$Arguments,$WorkingDirectory,$Environment,$StdoutPath,$StderrPath,$TimeoutSeconds,[Action]$Heartbeat)
    $script:seenArguments=@($Arguments)
    throw 'arguments-only-fixture-no-process-or-authority'
}
'@)
$tmp=Join-Path $script:cacheData 'tmp';New-PrivateRepairDirectory $tmp
$scratch=Join-Path $tmp 'startup-temp.critical-preflight';New-PrivateRepairDirectory $scratch
$FreshSourceCache=$false
$before=Test-SourceStartupFreshCacheRequired
$script:seenArguments=@()
try{[void](Invoke-SourceStartupAssistant -Python $env:TEST_PYTHON -Root $root -Environment @{} -Scratch $scratch)}catch{}
$ordinary=@($script:seenArguments)
$state=Join-Path $script:cacheData 'github-updates';New-PrivateRepairDirectory $state
[void](Write-NewSourceActivationRecord (Join-Path $state 'applied-base.json') ([ordered]@{scope='cache-trigger-only-not-approval'}))
$after=Test-SourceStartupFreshCacheRequired
$first=New-SourceStartupCachePrefix $root $scratch
try{[void](Invoke-SourceStartupAssistant -Python $env:TEST_PYTHON -Root $root -Environment @{} -Scratch $scratch -FreshCachePrefix $first)}catch{}
$updated=@($script:seenArguments)
$second=New-SourceStartupCachePrefix $root $scratch
$missingHeld=$false
try{[void](Invoke-SourceStartupAssistant -Python $env:TEST_PYTHON -Root $root -Environment @{} -Scratch $scratch)}catch{$missingHeld=$true}
Write-Output ('RESULT:'+(@{before=$before;after=$after;ordinary=$ordinary;updated=$updated;prefix=$first
    distinct=($first -cne $second);absent=(!(Test-Path -LiteralPath $first) -and !(Test-Path -LiteralPath $second));missing_held=$missingHeld}|ConvertTo-Json -Depth 4 -Compress))
''')
    assert result["before"] is True and result["after"] is True
    assert result["ordinary"] == []  # Missing cache held before any helper import.
    assert result["updated"] == ["-B", "-X", "pycache_prefix=" + result["prefix"], "-m", "angerona.startup", "--chill"]
    assert result["distinct"] is result["absent"] is result["missing_held"] is True


def test_manual_handoff_requires_actual_record_and_live_generation_cannot_be_user_confirmed(tmp_path, activation):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    operation = _operation(sample, plan)
    result = run_ps(tmp_path, r'''
$bound=[pscustomobject]@{Operation=$env:TEST_OPERATION
    Plan=(Read-SourceActivationRecord (Join-Path $env:TEST_OPERATION 'plan.json') 16777216)
    Request=(Read-SourceActivationRecord $env:TEST_REQUEST)}
$nonce='a'*32;$missing=$false
try{[void](Get-SourceActivationRetiredHandoff $bound $nonce)}catch{$missing=$_.Exception.Message.Contains('bound original handoff record')}
$handoffs=Join-Path $env:TEST_OPERATION 'handoffs';New-PrivateRepairDirectory $handoffs
$directory=Join-Path $handoffs $nonce;New-PrivateRepairDirectory $directory
Initialize-SourceActivationProcessOwner
$self=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID)
try{
    # Deliberately non-authorizing metadata fixture. The ACTUAL still-live
    # native gate alone must reject, before any user question or source action.
    $value=[ordered]@{schema='angerona.source-activation-resume-ready/v1';handoff_nonce=$nonce
        activation_id=$bound.Plan.Value.activation_id;plan_sha256=$bound.Plan.Sha256;request_sha256=$bound.Request.Sha256
        gate_pid=$PID;gate_birth=[string]$self.Birth;cmd_pid=$PID;cmd_birth=[string]$self.Birth
        resume_pid=$PID;resume_birth=[string]$self.Birth;resume_image=$self.Image}
    $record=Write-NewSourceActivationRecord (Join-Path $directory 'ready.json') $value
    Assert-SourceActivationRecordedHandoff $record $bound $nonce
    $liveHeld=$false
    try{[void](Get-SourceActivationRetiredHandoff $bound $nonce)}catch{$liveHeld=$_.Exception.Message.Contains('still live or unverified')}
    $bad=[pscustomobject]@{Value=($value|ConvertTo-Json -Compress|ConvertFrom-Json)};$bad.Value.plan_sha256='0'*64
    $stale=$false;try{Assert-SourceActivationRecordedHandoff $bad $bound $nonce}catch{$stale=$true}
    $bad=[pscustomobject]@{Value=($value|ConvertTo-Json -Compress|ConvertFrom-Json)};$bad.Value.gate_pid=$true
    $literal=$false;try{Assert-SourceActivationRecordedHandoff $bad $bound $nonce}catch{$literal=$true}
    Write-Output ('RESULT:'+(@{missing_held=$missing;live_held=$liveHeld;stale_held=$stale;bool_pid_held=$literal}|ConvertTo-Json -Compress))
}finally{$self.Dispose();if(!$self.CloseProven){throw 'Exact fixture query closure is unverified.'}}
''', extra={"TEST_OPERATION": str(operation), "TEST_REQUEST": str(operation / "requests" / (request["request_sha256"] + ".json"))})
    assert result == {"missing_held": True, "live_held": True, "stale_held": True, "bool_pid_held": True}


def test_capture_unknown_principal_is_still_held_before_output_or_child_start(tmp_path):
    result = run_ps(tmp_path, r'''
Initialize-SourceStartupCapture
$directory=Join-Path $env:TEST_SCRATCH 'capture-unknown-principal'
New-PrivateRepairDirectory -Path $directory
$acl=[IO.Directory]::GetAccessControl($directory)
$world=[Security.Principal.SecurityIdentifier]::new('S-1-1-0')
[void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($world,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow))
[IO.Directory]::SetAccessControl($directory,$acl)
$before=[IO.Directory]::GetAccessControl($directory).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
$stdout=Join-Path $directory 'stdout.log';$stderr=Join-Path $directory 'stderr.log'
$environment=New-RepairChildEnvironment $directory
$held=$false;$unexpected=$null
try {
    $unexpected=Invoke-SourceStartupCapturedAssistant -Python $env:TEST_PYTHON -Arguments @('-I','-B','-c','print("must-not-start")') -WorkingDirectory $directory -Environment $environment -TimeoutSeconds 5 -StdoutPath $stdout -StderrPath $stderr
} catch {
    if($_.Exception.Message -notmatch 'Capture scratch has an unexpected access rule\.'){throw}
    $held=$true
} finally {if($null -ne $unexpected){$unexpected.Process.Dispose()}}
$after=[IO.Directory]::GetAccessControl($directory).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
Write-Output ('RESULT:'+(@{held=$held;acl_unchanged=($before -ceq $after);no_output=(!(Test-Path -LiteralPath $stdout) -and !(Test-Path -LiteralPath $stderr))}|ConvertTo-Json -Compress))
''')
    assert result == {"held": True, "acl_unchanged": True, "no_output": True}
