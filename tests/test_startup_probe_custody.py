"""Disposable preflight children retain exact native tree custody before retry."""
from __future__ import annotations

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
from angerona.core.startup_diagnostics import process_identity


def test_each_required_probe_receives_its_own_budget(tmp_path, monkeypatch):
    plan = startup.LaunchPlan(tmp_path, tmp_path / "state", ("python.exe",), False)
    startup.prepare_storage(plan.storage)
    elapsed = [0.0]
    commands = []

    class Probe:
        pid = os.getpid()
        returncode = None

        def poll(self):
            elapsed[0] += 19
            self.returncode = 0
            return 0

        def wait_tree(self, timeout):
            return True

        def close(self):
            pass

    def spawn(command, **_kwargs):
        commands.append(command)
        return Probe()

    monkeypatch.setattr(startup, "_spawn_probe", spawn)
    monkeypatch.setattr(startup.time, "monotonic", lambda: elapsed[0])
    startup.probe_source(plan, {}, threading.Event())
    assert [command[2] for command in commands] == [startup._PROBE, startup._PIP_CHECK, startup._QT_PROBE]
    assert elapsed[0] == 57  # Past the former shared 30-second deadline.


def test_overall_preflight_budget_still_bounds_individually_slow_checks(tmp_path, monkeypatch):
    plan = startup.LaunchPlan(tmp_path, tmp_path / "state", ("python.exe",), False)
    startup.prepare_storage(plan.storage)
    elapsed = [0]
    retired = []

    class Probe:
        pid = os.getpid()
        returncode = 0

        def poll(self):
            elapsed[0] += 19
            return 0

        def wait_tree(self, timeout):
            retired.append(True)
            return True

        def close(self):
            pass

    monkeypatch.setattr(startup, "_spawn_probe", lambda *_a, **_k: Probe())
    monkeypatch.setattr(startup, "_PROBE_OVERALL_SECONDS", 50)
    monkeypatch.setattr(startup.time, "monotonic", lambda: elapsed[0])
    with pytest.raises(startup.ProbeTimedOut) as error:
        startup.probe_source(plan, {}, threading.Event())
    assert startup._startup_exit_code(error.value) == 87 and len(retired) == 3


def test_only_closed_error_classes_can_select_application_rollback():
    class UnclassifiedFault(startup.StartupError):
        exit_code = 1

    assert startup._startup_exit_code(UnclassifiedFault("unclassified probe fault")) == 85
    assert startup._startup_exit_code(OSError("could not create child")) == 85
    assert startup._startup_exit_code(startup.DashboardProcessFailed("actual dashboard exit")) == 1


def _fault_probe(tmp_path, monkeypatch, *, close_result=True):
    startup.prepare_storage(tmp_path)
    lease = startup.StartupLease(tmp_path)
    probe = object.__new__(startup._WindowsProbe)
    probe.pid, probe._handle, probe._job = 71001, 101, 102
    probe._members = {71002: 103}
    probe.closed = probe.tree_retired = probe._custody_ambiguous = False
    probe._close_lock = threading.Lock()
    probe._lease = lease.borrow(tmp_path)
    calls, holds = [], []
    probe._kernel = SimpleNamespace(CloseHandle=lambda handle: calls.append(("close", handle)) or close_result)
    probe._ctypes = SimpleNamespace(WinError=lambda error: OSError(error, "synthetic native close failure"),
                                   get_last_error=lambda: 6)
    probe.kill = lambda: calls.append("kill")
    probe.wait = lambda timeout: calls.append(("wait", timeout)) or 0
    probe.wait_tree = lambda timeout: False
    monkeypatch.setattr(startup, "_start_probe_custody_reaper", holds.append)
    return probe, lease, calls, holds


def test_failed_tree_retirement_retains_native_owner_and_real_startup_lease(tmp_path, monkeypatch):
    probe, lease, calls, holds = _fault_probe(tmp_path, monkeypatch)
    try:
        with pytest.raises(startup.StartupError, match="lease remain held"):
            probe.close()
        lease.close()
        assert holds == [probe] and not probe.closed
        assert (probe._handle, probe._job, probe._members) == (101, 102, {71002: 103})
        assert not any(isinstance(call, tuple) and call[0] == "close" for call in calls)
        with pytest.raises(startup.StartupError, match="already working"):
            startup.StartupLease(tmp_path)
        probe.wait_tree = lambda timeout: True
        probe.close()
        assert probe.closed and probe._lease is None
        startup.StartupLease(tmp_path).close()
    finally:
        if probe._lease is not None:
            probe._lease.close()
        lease.close()


def test_ambiguous_native_close_never_retries_stale_handle_values(tmp_path, monkeypatch):
    probe, lease, calls, holds = _fault_probe(tmp_path, monkeypatch, close_result=False)
    probe.tree_retired = True
    try:
        for _attempt in range(2):
            with pytest.raises(startup.StartupError, match="lease remain held"):
                probe.close()
        assert calls == [("close", 103)]  # A failed CloseHandle is never reissued.
        assert not probe.closed and probe._custody_ambiguous
        assert probe._members == {71002: 103} and probe._job == 102 and probe._handle == 101
        assert holds == [probe, probe]  # Real registry de-duplicates the owner.
    finally:
        probe._lease.close()
        lease.close()


def test_custody_reaper_bounds_retirement_attempts_then_parks_without_reusing_handles(monkeypatch):
    attempts, waits = [], []
    class Parked(BaseException):
        pass
    class Event:
        def wait(self, delay):
            waits.append(delay)
            if delay == 5:
                raise Parked()
    def unavailable():
        attempts.append(True)
        raise startup.StartupError("native tree remains active")
    owner = SimpleNamespace(closed=False, _custody_ambiguous=False, _close_once=unavailable)
    monkeypatch.setattr(startup.threading, "Event", Event)
    with pytest.raises(Parked):
        startup._reap_probe_custody(owner)
    assert len(attempts) == 3 and waits == [1, 2, 4, 5]


def test_unretired_probe_gets_one_non_daemon_native_owner(monkeypatch):
    owner = object()
    threads = []
    def thread(**kwargs):
        threads.append(kwargs)
        return SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(startup.threading, "Thread", thread)
    try:
        startup._start_probe_custody_reaper(owner)
        startup._start_probe_custody_reaper(owner)
        assert len(threads) == 1 and threads[0]["daemon"] is False
        assert threads[0]["args"] == (owner,)
        assert owner in startup._PROBE_CUSTODY_HOLDS
    finally:
        startup._PROBE_CUSTODY_HOLDS.discard(owner)


def test_zero_job_accounting_requires_retained_root_and_member_handles_to_signal(monkeypatch):
    class Accounting(ctypes.Structure):
        _fields_ = [("active_processes", ctypes.c_uint32)]
    probe = object.__new__(startup._WindowsProbe)
    probe._ctypes, probe._accounting_type = ctypes, Accounting
    probe._handle, probe._job, probe._members = 101, 102, {71002: 103}
    probe.tree_retired = False
    probe._capture_job_members = lambda: None
    signals = {101: 258, 103: 258}
    probe._kernel = SimpleNamespace(QueryInformationJobObject=lambda *_a: True,
                                   WaitForSingleObject=lambda handle, _wait: signals[handle])
    assert probe.wait_tree(timeout=0) is False and not probe.tree_retired
    signals[101] = 0
    assert probe.wait_tree(timeout=0) is False
    signals[103] = 0
    assert probe.wait_tree(timeout=0) is True and probe.tree_retired


@pytest.mark.parametrize("codes,expected", [([1], 85), ([82], 82), ([83], 83),
                                           ([0, 0, 0xC0000135], 83)])
def test_nonzero_probe_outcomes_preserve_only_closed_repair_categories(tmp_path, monkeypatch, codes, expected):
    plan = startup.LaunchPlan(tmp_path, tmp_path / "state", ("python.exe",), False)
    startup.prepare_storage(plan.storage)
    values = iter(codes)
    closed = []

    class Probe:
        pid = os.getpid()

        def __init__(self):
            self.returncode = next(values)

        def poll(self):
            return self.returncode

        def wait_tree(self, timeout):
            return True

        def close(self):
            closed.append(True)

    monkeypatch.setattr(startup, "_spawn_probe", lambda *_a, **_k: Probe())
    with pytest.raises(startup.StartupError) as error:
        startup.probe_source(plan, {}, threading.Event())
    assert startup._startup_exit_code(error.value) == expected and len(closed) == len(codes)


@pytest.mark.parametrize("reason", ["cancel", "timeout"])
def test_uncertain_probe_tree_retirement_is_an_infrastructure_hold(tmp_path, monkeypatch, reason):
    plan = startup.LaunchPlan(tmp_path, tmp_path / "state", ("python.exe",), False)
    startup.prepare_storage(plan.storage)
    cancelled = threading.Event()
    actions = []

    class Probe:
        pid = os.getpid()
        returncode = None

        def poll(self):
            return None

        def kill(self):
            actions.append("kill")

        def wait(self, timeout):
            return -1

        def wait_tree(self, timeout):
            return False

        def close(self):
            actions.append("close")

    def spawn(*_args, **_kwargs):
        if reason == "cancel":
            cancelled.set()
        return Probe()

    monkeypatch.setattr(startup, "_spawn_probe", spawn)
    if reason == "timeout":
        times = iter([0, 0, 0, 31])
        monkeypatch.setattr(startup.time, "monotonic", lambda: next(times))
    with pytest.raises(startup.StartupError, match="retirement") as error:
        startup.probe_source(plan, {}, cancelled)
    assert startup._startup_exit_code(error.value) == 85
    assert actions == ["kill", "close"]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows venv redirector and job lifetime")
@pytest.mark.parametrize("reason", ["cancel", "timeout"])
def test_real_venv_probe_retires_redirector_and_delayed_descendants_only(tmp_path, monkeypatch, reason):
    from ctypes import wintypes as w

    executable = Path(sys.executable)
    if executable.parent.name.lower() != "scripts" or not (executable.parent.parent / "pyvenv.cfg").is_file():
        pytest.skip("This integration check requires the selected Windows venv executable")
    state = tmp_path / "state"
    startup.prepare_storage(state)
    generations = tmp_path / "probe-generations.jsonl"
    child = ("import json,os,time;"
             f"open({str(generations)!r},'a').write(json.dumps({{'role':'delayed-child','pid':os.getpid()}})+'\\n');"
             "time.sleep(120)")
    script = ("import json,os,subprocess,sys,time;"
              f"open({str(generations)!r},'a').write(json.dumps({{'role':'actual-interpreter','pid':os.getpid()}})+'\\n');"
              f"subprocess.Popen([sys.executable,'-I','-c',{child!r}]);time.sleep(120)")
    plan = startup.LaunchPlan(tmp_path, state, (str(executable),), False)
    environment = dict(os.environ, PYTHONNOUSERSITE="1", PYTHONSAFEPATH="1")
    cancel = threading.Event()
    retained = []
    probes = []
    probe_identities = []
    watcher_errors = []
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
    kernel.OpenProcess.restype = w.HANDLE
    kernel.WaitForSingleObject.argtypes = (w.HANDLE, w.DWORD)
    kernel.WaitForSingleObject.restype = w.DWORD
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    original_spawn = startup._spawn_probe

    def spawn(*args, **kwargs):
        probe = original_spawn(*args, **kwargs)
        probes.append(probe)
        probe_identities.append(process_identity(probe))
        return probe

    def observe_exact_generations():
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    rows = [json.loads(row) for row in generations.read_text().splitlines()] if generations.exists() else []
                except (OSError, ValueError):
                    rows = []  # The private producer may be in its bounded write.
                if len(rows) == 2:
                    for row in rows:
                        handle = kernel.OpenProcess(0x101000, False, row["pid"])
                        assert handle, ctypes.WinError(ctypes.get_last_error())
                        identity = process_identity(SimpleNamespace(pid=row["pid"], _handle=handle))
                        assert identity.get("birth_filetime", "").isdecimal()
                        retained.append((handle, identity))
                    if reason == "cancel":
                        cancel.set()
                    return
                time.sleep(0.02)
            raise AssertionError("The real venv descendants did not register before the bounded deadline")
        except BaseException as exc:
            watcher_errors.append(exc)
            cancel.set()

    # The unrelated retained generation uses the same runtime and must survive.
    sentinel = subprocess.Popen([sys._base_executable, "-I", "-c", "import time;time.sleep(120)"],
                                creationflags=subprocess.CREATE_NO_WINDOW)
    sentinel_identity = process_identity(sentinel)
    watcher = threading.Thread(target=observe_exact_generations, daemon=False)
    monkeypatch.setattr(startup, "_PROBE", script)
    monkeypatch.setattr(startup, "_spawn_probe", spawn)
    monkeypatch.setattr(startup, "_PROBE_PHASE_SECONDS", 10)
    watcher.start()
    try:
        with pytest.raises(startup.StartupError) as error:
            startup.probe_source(plan, environment, cancel)
        watcher.join(timeout=9)
        assert not watcher.is_alive() and not watcher_errors, watcher_errors
        assert startup._startup_exit_code(error.value) == (1223 if reason == "cancel" else 87)
        assert len(probes) == 1 and len(retained) == 2
        assert probe_identities[0].get("birth_filetime", "").isdecimal()
        assert retained[0][1]["pid"] != probes[0].pid  # CPython's venv redirector is a separate generation.
        assert probes[0].tree_retired is True and probes[0].closed is True
        assert all(kernel.WaitForSingleObject(handle, 0) == 0 for handle, _identity in retained)
        assert sentinel.poll() is None and process_identity(sentinel) == sentinel_identity
        print("ANGERONA_PROBE_CUSTODY " + json.dumps({
            "case": reason, "probe": probe_identities[0],
            "descendants": [identity for _handle, identity in retained],
            "retired": True, "unrelated_survived": sentinel_identity,
        }))
    finally:
        cancel.set()
        watcher.join(timeout=9)
        for probe in probes:
            probe.close()
        for handle, _identity in retained:
            kernel.CloseHandle(handle)
        sentinel.kill()
        sentinel.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows inherited-handle allowlist")
def test_disposable_probe_does_not_inherit_an_unrelated_inheritable_handle(tmp_path):
    from ctypes import wintypes as w

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = (w.LPVOID, w.BOOL, w.BOOL, w.LPCWSTR)
    kernel.CreateEventW.restype = w.HANDLE
    kernel.SetHandleInformation.argtypes = (w.HANDLE, w.DWORD, w.DWORD)
    kernel.WaitForSingleObject.argtypes = (w.HANDLE, w.DWORD)
    kernel.WaitForSingleObject.restype = w.DWORD
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    unrelated = kernel.CreateEventW(None, True, False, None)
    assert unrelated and kernel.SetHandleInformation(unrelated, 1, 1)
    child = ("import ctypes;kernel=ctypes.WinDLL('kernel32',use_last_error=True);"
             "kernel.SetEvent.argtypes=(ctypes.c_void_p,);"
             f"assert not kernel.SetEvent({unrelated})")
    try:
        with (tmp_path / "handle-check.log").open("wb") as output:
            probe = startup._spawn_probe([sys.executable, "-I", "-c", child],
                                         cwd=tmp_path, env=dict(os.environ), stdout=output)
            identity = process_identity(probe)
            try:
                assert probe.wait(timeout=10) == 0
                assert probe.wait_tree(timeout=5)
                assert kernel.WaitForSingleObject(unrelated, 0) == 258
                print("ANGERONA_PROBE_HANDLE_ALLOWLIST " + json.dumps({"probe": identity, "retired": True}))
            finally:
                probe.close()
    finally:
        kernel.CloseHandle(unrelated)
