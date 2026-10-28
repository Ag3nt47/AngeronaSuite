"""Fault-injected source orchestration; no real repair, installer or GUI runs."""
from __future__ import annotations

import hashlib
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona import startup
from angerona.core import startup_recovery as recovery


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "Invoke-AngeronaSourceStartup.ps1"


def _powershell(tmp_path: Path, body: str) -> dict:
    if os.name != "nt":
        pytest.skip("Windows PowerShell orchestration")
    program = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    # Extract only named function definitions. Product entry points and their
    # native/process/filesystem dependencies are never executed by this harness.
    prelude = r"""$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($env:ANGERONA_TEST_SOURCE,[ref]$null,[ref]$null)
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    if($node.Name -in @('Invoke-SourceStartupLoop','Invoke-SourceStartupPass')) {
        . ([scriptblock]::Create($node.Extent.Text))
    }
}
"""
    path = tmp_path / "fake-source-flow.ps1"
    path.write_text(prelude + body, encoding="utf-8")
    environment = dict(os.environ, ANGERONA_TEST_SOURCE=str(SOURCE))
    result = subprocess.run(
        [str(program), "-NoProfile", "-NonInteractive", "-File", str(path)],
        env=environment, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))


_FAKE_SOURCE = r"""
$script:Events=[Collections.Generic.List[string]]::new()
$script:Passes=0; $script:Repairs=0; $script:Dashboards=0; $script:Lease=0
function Write-SourceStartupStatus {}
function Write-SourceStartupEvent {}
function Add-SourceStartupAttempt {}
function Invoke-SourceCodeAction {
    $script:LastSourceRecoveryResult=[pscustomobject]@{launch_held=$false;source_digest=('a'*64)}
    return 0
}
function Protect-SourceStartupText { param($Value,$Limit=2000) return [string]$Value }
function Invoke-SourceRecoveryWindow { $script:Events.Add('recovery'); return 0 }
function Assert-SourceStartupBoundary { param($Root) $script:Passes++; $script:Events.Add('boundary'); if($env:ANGERONA_TEST_CASE -in @('elevated','integrity','custody','low-disk')) { throw $env:ANGERONA_TEST_CASE } }
function Initialize-SourceStartupStorage { return 'D:\fixture\state' }
function Enter-RepairLease { param($Root) if($env:ANGERONA_TEST_CASE -eq 'busy') { throw 'busy' }; $script:Lease++; $script:Events.Add('lease'); return 'fake-lease' }
function Exit-RepairLease { param($Lease) $script:Lease--; $script:Events.Add('release') }
function Assert-NoPendingRepair {
    param($Root)
    if($script:Lease -ne 1) {throw 'pending inspection escaped lease'}
    $script:Events.Add('pending')
    if($env:ANGERONA_TEST_CASE -in @('pending-old-renamed','pending-candidate-renamed','pending-refresh') -and $script:Passes -eq 1) {
        $error=[InvalidOperationException]::new('Interrupted trusted promotion')
        $error.Data['AngeronaRepairPending']=$true; throw $error
    }
    if($env:ANGERONA_TEST_CASE -in @('pending-tampered','pending-corrupt')) {throw 'Pending repair evidence is unsafe'}
}
function Assert-NoActiveVenv { param($VenvPath) if($script:Lease -ne 1) {throw 'unleased process check'}; if($env:ANGERONA_TEST_CASE -eq 'live-dashboard') {throw 'active dashboard'} }
function Test-Path { param($LiteralPath,$PathType) return $true }
function New-SourceStartupTemporary { param($Root,$Storage) return 'D:\fixture\scratch' }
function New-RepairChildEnvironment { param($Scratch) return @{TEMP=$Scratch;TMP=$Scratch;QT_QPA_PLATFORM='offscreen'} }
function Initialize-OwnedRepairProcess {}
function Invoke-OwnedRepairProcess {
    param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds,$LogPath)
    if($script:Lease -ne 1) {throw 'venv process escaped lease'}
    if($Arguments[1] -like '*sys.version_info*') {
        $script:Events.Add('abi')
        if($script:Passes -eq 1 -and $env:ANGERONA_TEST_CASE -eq 'runtime') {return 81}
    } elseif($Arguments[1] -like '*m.version*') {
        $script:Events.Add('pip')
        if($script:Passes -eq 1 -and $env:ANGERONA_TEST_CASE -eq 'pip') {return 82}
    } else {
        $script:Events.Add('source-trust')
        if($env:ANGERONA_TEST_CASE -eq 'source-trust') {return 1}
    }
    return 0
}
function Invoke-SourceStartupAssistant {
    param($Python,$Root,$Environment,$Scratch,[switch]$SoftwareRenderer)
    if($script:Lease -ne 1) {throw 'helper escaped lease'}
    if($Environment.ContainsKey('QT_QPA_PLATFORM')) {throw 'offscreen leaked to dashboard'}
    $script:Events.Add('helper')
    if($env:ANGERONA_TEST_CASE -in @('unknown','timeout-live','cancel-live')) {return 1}
    if($env:ANGERONA_TEST_CASE -in @('repair-recheck-failed','repair-failed')) {return 82}
    if($script:Passes -eq 1 -and $env:ANGERONA_TEST_CASE -notin @('normal','runtime','pip')) {return 83}
    $script:Dashboards++; return 0
}
function Invoke-SourceStartupRepair {
    param($Root,$Category)
    if($script:Lease -ne 0) {throw 'repair started while venv lease held'}
    $script:Repairs++; $script:Events.Add('repair:'+$Category)
    if($env:ANGERONA_TEST_CASE -eq 'repair-failed') {return 7}
    return 0
}
$code=1; $failure=''
try {$code=Invoke-SourceStartupLoop -Root 'D:\fixture'} catch {$failure=$_.Exception.Message}
Write-Output ('RESULT:'+(@{code=$code;passes=$script:Passes;repairs=$script:Repairs;dashboards=$script:Dashboards;lease=$script:Lease;events=@($script:Events);failure=$failure}|ConvertTo-Json -Compress))
"""


@pytest.mark.parametrize("case,passes,repairs,dashboards,code", [
    ("normal", 1, 0, 1, 0),
    ("runtime", 2, 1, 1, 0),
    ("pip", 2, 1, 1, 0),
    ("gui", 2, 0, 1, 0),
    ("repair-failed", 1, 1, 0, 1223),
    ("repair-recheck-failed", 2, 1, 0, 1223),
    ("unknown", 1, 0, 0, 1223),
    ("source-trust", 1, 0, 0, 1223),
    ("timeout-live", 1, 0, 0, 1223),
    ("cancel-live", 1, 0, 0, 1223),
    ("elevated", 1, 0, 0, 1223),
    ("integrity", 1, 0, 0, 1223),
    ("custody", 1, 0, 0, 1223),
    ("low-disk", 1, 0, 0, 1223),
    ("busy", 1, 0, 0, 1223),
    ("live-dashboard", 1, 0, 0, 1223),
    ("pending-old-renamed", 2, 1, 1, 0),
    ("pending-candidate-renamed", 2, 1, 1, 0),
    ("pending-refresh", 2, 1, 1, 0),
    ("pending-corrupt", 1, 0, 0, 1223),
    ("pending-tampered", 1, 0, 0, 1223),
])
def test_actual_source_supervisor_rechecks_and_launches_at_most_once(
    tmp_path, monkeypatch, case, passes, repairs, dashboards, code,
):
    monkeypatch.setenv("ANGERONA_TEST_CASE", case)
    monkeypatch.setenv("ANGERONA_REPAIR_ATTEMPT", "0") # Never a product budget input.
    result = _powershell(tmp_path, _FAKE_SOURCE)
    assert (result["passes"], result["repairs"], result["dashboards"], result["code"]) == (
        passes, repairs, dashboards, code,
    )
    assert result["lease"] == 0
    if repairs:
        repair = next(i for i, event in enumerate(result["events"]) if event.startswith("repair:"))
        assert result["events"][repair - 1] == "release"
        if passes == 2:
            assert result["events"][repair + 1:repair + 6] == ["boundary", "lease", "pending", "abi", "pip"]
    if case.startswith("pending-"):
        before_repair = result["events"][:next((i for i, event in enumerate(result["events"]) if event.startswith("repair:")), len(result["events"]))]
        assert "abi" not in before_repair and "helper" not in before_repair


class _Probe:
    def __init__(self, code):
        self.returncode = code
    def poll(self):
        return self.returncode


@pytest.mark.parametrize("codes,eligible", [
    ([81], 81), ([82], 82), ([0, 82], 82), ([0, 0, 83], 83),
    ([0, 0, -1073741819], 83), ([0, 0, 0xC0000135], 83),
    ([1], None), ([0, 1], None), ([0, 0, 1], None), ([42], None),
])
def test_only_closed_pre_dashboard_probe_results_are_repairable(tmp_path, monkeypatch, codes, eligible):
    plan = startup.LaunchPlan(tmp_path, tmp_path / "state", ("fake-python.exe",), False)
    startup.prepare_storage(plan.storage)
    remaining = iter(codes)
    monkeypatch.setattr(startup.subprocess, "Popen", lambda *_a, **_kw: _Probe(next(remaining)))
    with pytest.raises(startup.StartupError) as error:
        startup.probe_source(plan, {}, threading.Event())
    assert getattr(error.value, "exit_code", None) == eligible


def test_temp_fallback_is_private_verified_and_changes_only_child_environment(tmp_path, monkeypatch):
    storage = tmp_path / "state"
    root = tmp_path / "installation"
    root.mkdir()
    startup.prepare_storage(storage)
    # A regular file blocks the preferred temp directory; leave it untouched.
    (storage / "tmp").rmdir()
    (storage / "tmp").write_bytes(b"operator-owned obstruction")
    monkeypatch.setenv("TEMP", str(tmp_path / "missing-temp"))
    monkeypatch.setenv("TMP", str(tmp_path / "missing-temp"))
    before = dict(os.environ)
    selected = recovery.select_temporary(storage, root, validate=startup._plain_path,
        fixed=lambda _drive: True, inherited=dict(os.environ))
    assert selected.parent == root / ".tmp"
    assert selected.name.startswith("startup-temp.")
    assert recovery.private_directory(selected, create=False)
    assert not list(selected.iterdir())
    assert dict(os.environ) == before
    assert (storage / "tmp").read_bytes() == b"operator-owned obstruction"
    plan = startup.LaunchPlan(root, storage, ("fake-python.exe",), False, selected)
    environment = startup.child_environment(plan)
    assert environment["TEMP"] == environment["TMP"] == str(selected)
    assert environment["ANGERONA_DATA"] == str(storage)
    assert dict(os.environ) == before


def test_healthy_scratch_cannot_bypass_full_persistent_data_drive(tmp_path, monkeypatch):
    root = tmp_path / "installation"
    root.mkdir()
    state = tmp_path / "canonical-state"
    state.mkdir()
    protected = {name: state / name for name in ("settings.json", "evidence.json", "runtime_chill_ai_blocked")}
    for name, path in protected.items():
        path.write_bytes(name.encode())
    before = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in protected.items()}
    plan = startup.LaunchPlan(root, state, ("fake-python.exe",), False)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup.shutil, "disk_usage", lambda _path: SimpleNamespace(free=127 * 1024 * 1024))
    monkeypatch.setattr(startup, "select_temporary", lambda *_a, **_kw: pytest.fail("Scratch cannot replace persistent capacity"))
    monkeypatch.setattr(startup.subprocess, "Popen", lambda *_a, **_kw: pytest.fail("Full state drive must not launch anything"))
    with pytest.raises(startup.StartupError, match="canonical.*128 MB|128 MB.*canonical"):
        startup.run_startup(lambda _message: None, threading.Event())
    assert {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in protected.items()} == before


def test_invalid_repair_category_is_never_accepted():
    for value in (1, 0, 42, True, "82", -1):
        with pytest.raises(ValueError):
            startup.RepairableStartupError(value, "untrusted failure text")


def test_private_supervisor_temp_is_reused_only_after_independent_proof(tmp_path):
    state, installation = tmp_path / "state", tmp_path / "installation"
    installation.mkdir()
    startup.prepare_storage(state)
    candidate = state / "tmp" / "startup-temp.test-owned"
    assert recovery.private_directory(candidate, create=True)
    selected = recovery.select_temporary(state, installation, validate=startup._plain_path,
        fixed=lambda _drive: True, inherited={"TEMP": str(candidate), "TMP": str(candidate)})
    assert selected == candidate
    assert list(candidate.iterdir()) == []


def test_unsafe_inherited_temp_does_not_gain_authority(tmp_path):
    state, installation = tmp_path / "state", tmp_path / "installation"
    installation.mkdir()
    startup.prepare_storage(state)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    marker = unrelated / "operator-file"
    marker.write_bytes(b"preserved")
    selected = recovery.select_temporary(state, installation, validate=startup._plain_path,
        fixed=lambda _drive: True, inherited={"TEMP": str(unrelated), "TMP": r"\\untrusted.invalid\share"})
    assert selected.parent == state / "tmp"
    assert marker.read_bytes() == b"preserved"
    assert list(unrelated.iterdir()) == [marker]


def test_temp_flush_failure_never_claims_a_healthy_directory(tmp_path, monkeypatch):
    state, installation = tmp_path / "state", tmp_path / "installation"
    installation.mkdir()
    startup.prepare_storage(state)
    def fail(_path):
        raise OSError("simulated flush or readback failure")
    monkeypatch.setattr(recovery, "write_read_proof", fail)
    with pytest.raises(OSError, match="No verified private"):
        recovery.select_temporary(state, installation, validate=startup._plain_path,
            fixed=lambda _drive: True, inherited={})


def test_source_delegation_bounds_distinct_strategies_and_keeps_chill_checks():
    text = SOURCE.read_text(encoding="utf-8")
    bat = (ROOT / "start-angerona.bat").read_text(encoding="utf-8")
    assert "setlocal DisableDelayedExpansion" in bat
    assert "__ANGERONA_PINNED_BOOTSTRAP__" in bat
    assert "'-RunSupervisor'" in bat
    assert "Invoke-AngeronaSourceStartup.ps1" in (ROOT / "tools/verify_startup_recovery_bundle.ps1").read_text(encoding="utf-8")
    assert "'-FailureCategory', $Category, '-Attempt', '1'" in text
    assert "$arguments = @('-m', 'angerona.startup', '--chill')" in text
    assert "while ($true)" in text and "$repairs.ContainsKey($code)" in text
    assert "$sourceStrategies.ContainsKey($sourceStrategy)" in text
    assert "-Verb RunAs" not in text and "start-angerona.bat\"" not in text
    assert "HEAL" not in text and "pull" not in text.casefold()


def test_direct_helper_and_check_only_refuse_cross_process_repair_custody(tmp_path, monkeypatch):
    checkout, state = tmp_path / "checkout", tmp_path / "canonical-state"
    checkout.mkdir()
    ready = tmp_path / "repair-holds-both-locks"
    holder_code = r"""
import os, sys
from pathlib import Path
from angerona import startup
root, state, ready = map(Path, sys.argv[1:])
startup.prepare_storage(state)
lock = root / '.tmp' / 'repair-wheels' / 'startup-repair.lock'
lock.parent.mkdir(parents=True)
stream = lock.open('w+b')
if os.name == 'nt':
    import msvcrt
    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
else:
    import fcntl
    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
helper = startup.StartupLease(state)
ready.write_text('checkout then canonical helper custody', encoding='utf-8')
sys.stdin.readline()
helper.close()
stream.close()
"""
    holder = subprocess.Popen([sys.executable, "-c", holder_code, str(checkout), str(state), str(ready)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and holder.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists(), holder.communicate("release\n", timeout=5)
        plan = startup.LaunchPlan(checkout, state, ("fake-python.exe",), False)
        monkeypatch.setattr(startup, "platform_plan", lambda: plan)
        monkeypatch.setattr(startup, "probe_source", lambda *_a: pytest.fail("A repair lease must exclude direct probes"))
        with pytest.raises(startup.StartupError, match="already working"):
            startup.run_startup(lambda _message: None, threading.Event())
        direct_code = r"""
import sys
from pathlib import Path
from angerona import startup
root, state = map(Path, sys.argv[1:])
startup.platform_plan = lambda: startup.LaunchPlan(root, state, ('fake-python.exe',), False)
startup.probe_source = lambda *args: (_ for _ in ()).throw(AssertionError('Unexpected probe'))
sys.argv = ['startup', '--check-only', '--chill']
raise SystemExit(startup.main())
"""
        direct = subprocess.run([sys.executable, "-c", direct_code, str(checkout), str(state)],
            capture_output=True, text=True, timeout=15, check=False)
        assert direct.returncode == 1
        assert "already working" in direct.stderr
        assert "Unexpected probe" not in direct.stderr
        # The direct Tk route must stop at the same guard before loading Tk.
        monkeypatch.setattr(startup, "_configure_tk_environment", lambda: pytest.fail("Tk loaded during repair"))
        monkeypatch.setattr(startup.sys, "argv", ["startup", "--chill"])
        assert startup.main() == 1
    finally:
        if holder.poll() is None:
            holder.communicate("release\n", timeout=10)
        else:
            holder.communicate(timeout=5)
    assert holder.returncode == 0
    startup.StartupLease(state).close()


@pytest.mark.parametrize("location", ["pending", "marker"])
def test_direct_helper_refuses_pending_or_marker_before_any_probe_or_tk(tmp_path, monkeypatch, location):
    checkout, state = tmp_path / "checkout", tmp_path / "canonical-state"
    checkout.mkdir()
    startup.prepare_storage(state)
    if location == "pending":
        (checkout / ".tmp" / "repair-wheels" / "startup-repair.pending").mkdir(parents=True)
    else:
        (checkout / "venv").mkdir()
        (checkout / "venv" / ".angerona-startup-repair.json").write_bytes(b"untrusted interrupted marker")
    plan = startup.LaunchPlan(checkout, state, ("fake-python.exe",), False)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "probe_source", lambda *_a: pytest.fail("Pending repair reached a runtime probe"))
    with pytest.raises(startup.StartupError, match="interrupted source repair"):
        startup.run_startup(lambda _message: None, threading.Event(), check_only=True)
    monkeypatch.setattr(startup, "_configure_tk_environment", lambda: pytest.fail("Pending repair reached Tk"))
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--chill"])
    assert startup.main() == 1


def test_ui_and_worker_references_retain_helper_custody_until_both_finish(tmp_path):
    startup.prepare_storage(tmp_path)
    interface = startup.StartupLease(tmp_path)
    worker = interface.borrow(tmp_path)
    interface.close()
    with pytest.raises(startup.StartupError, match="already working"):
        startup.StartupLease(tmp_path)
    worker.close()
    startup.StartupLease(tmp_path).close()


def test_caller_data_cannot_replace_a_retained_os_helper_lease(tmp_path, monkeypatch):
    state = tmp_path / "state"
    plan = startup.LaunchPlan(tmp_path, state, ("fake-python.exe",), False)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "probe_source", lambda *_a: pytest.fail("An invalid custody handle reached probes"))
    with pytest.raises(startup.StartupError, match="actual retained OS lease"):
        startup.run_startup(lambda _message: None, threading.Event(),
            _interface_lease=SimpleNamespace(borrow=lambda _root: None))


def _orphan_repair_witness(checkout: Path, resolution: bytes | None) -> Path:
    parent = checkout / ".tmp" / "repair-wheels"
    parent.mkdir(parents=True)
    scratch = parent / ("startup-repair." + "a" * 32)
    assert recovery.private_directory(scratch, create=True)
    witness = scratch / "intent.witness.json"
    _write_private_orphan_file(witness, b"preserved private orphan intent witness")
    if resolution is not None:
        result = scratch / "resolution.json"
        _write_private_orphan_file(result, resolution)
    return scratch


def _write_private_orphan_file(path: Path, contents: bytes) -> None:
    """Create fixture evidence with explicit custody even on elevated runners.

    An elevated Windows token can default new file ownership to Administrators,
    regardless of its private parent's owner. Copy the verified parent's owner
    and closed DACL atomically onto this new file; never edit an existing ACL.
    """
    assert recovery.private_directory(path.parent, create=False)
    if os.name == "nt":
        from ctypes import wintypes as w
        import msvcrt

        class Attributes(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD,
            ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID)]
        advapi.GetNamedSecurityInfoW.restype = w.DWORD
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD,
            ctypes.POINTER(Attributes), w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.LocalFree.argtypes = [w.LPVOID]
        kernel.LocalFree.restype = w.LPVOID
        kernel.CloseHandle.argtypes = [w.HANDLE]
        kernel.CloseHandle.restype = w.BOOL
        owner, dacl, descriptor = w.LPVOID(), w.LPVOID(), w.LPVOID()
        handle = None
        try:
            error = advapi.GetNamedSecurityInfoW(str(path.parent), 1, 5,
                ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
            if error:
                raise ctypes.WinError(error)
            assert owner and dacl and descriptor
            attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
            # GENERIC_WRITE, no sharing, CREATE_NEW, FILE_ATTRIBUTE_NORMAL.
            handle = kernel.CreateFileW(str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
            if handle == w.HANDLE(-1).value:
                handle = None
                raise ctypes.WinError(ctypes.get_last_error())
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            handle = None  # The descriptor now owns and closes the OS handle.
        finally:
            if handle is not None:
                kernel.CloseHandle(handle)
            if descriptor:
                kernel.LocalFree(descriptor)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)
    assert recovery.private_repair_file(path)


def test_private_orphan_fixture_creation_never_changes_existing_evidence(tmp_path):
    scratch = tmp_path / "private-scratch"
    assert recovery.private_directory(scratch, create=True)
    evidence = scratch / "intent.witness.json"
    _write_private_orphan_file(evidence, b"preserve original evidence")
    identity = evidence.stat().st_ino
    with pytest.raises(OSError):
        _write_private_orphan_file(evidence, b"unwanted replacement")
    assert evidence.read_bytes() == b"preserve original evidence"
    assert evidence.stat().st_ino == identity
    assert recovery.private_repair_file(evidence)


@pytest.mark.parametrize("resolution", [
    None, b"not JSON", b"x" * 1025,
    b'{"Schema":1,"Id":"wrong","Outcome":"Verified"}',
    ('{"Schema":true,"Id":"' + "a" * 32 + '","Outcome":"Verified"}').encode(),
    ('{"Schema":1,"Id":"' + "a" * 32 + '","Outcome":"Unknown"}').encode(),
    ('{"Schema":1,"Id":"' + "a" * 32 + '","Outcome":"Verified","extra":1}').encode(),
    ('{"Schema":1,"Id":"' + "a" * 32 + '","Outcome":"Verified","Schema":1}').encode(),
])
def test_orphan_witness_without_closed_resolution_refuses_api_and_pre_tk(tmp_path, monkeypatch, resolution):
    checkout, state = tmp_path / "checkout", tmp_path / "state"
    checkout.mkdir()
    scratch = _orphan_repair_witness(checkout, resolution)
    before = {path.name: path.read_bytes() for path in scratch.iterdir()}
    plan = startup.LaunchPlan(checkout, state, ("fake-python.exe",), False)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "probe_source", lambda *_a: pytest.fail("Orphan repair evidence reached probes"))
    with pytest.raises(startup.StartupError, match="source repair evidence"):
        startup.run_startup(lambda _message: None, threading.Event(), check_only=True)
    monkeypatch.setattr(startup, "_configure_tk_environment", lambda: pytest.fail("Orphan repair evidence reached Tk"))
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--chill"])
    assert startup.main() == 1
    assert {path.name: path.read_bytes() for path in scratch.iterdir()} == before


@pytest.mark.parametrize("outcome", ["Verified", "RolledBack"])
def test_orphan_witness_with_private_matching_closed_resolution_is_resolved(tmp_path, outcome):
    checkout, state = tmp_path / "checkout", tmp_path / "state"
    checkout.mkdir()
    resolution = json.dumps({"Schema": 1, "Id": "a" * 32, "Outcome": outcome}).encode()
    _orphan_repair_witness(checkout, resolution)
    startup.prepare_storage(state)
    lease = startup.StartupLease(state)
    try:
        startup._assert_no_pending_repair(startup.LaunchPlan(checkout, state, ("fake-python.exe",), False))
    finally:
        lease.close()
