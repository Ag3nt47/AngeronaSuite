"""Native owner context is distinct from heartbeat presentation and permission."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.core.werfault_guard import read_owned_processes
from angerona.resilience.component_status import ComponentHeartbeatCache, ROLES, _FILETIME_EPOCH


@pytest.fixture
def context():
    """Inert native/reader seams; real authenticated wire is tested separately."""
    clock, wall = [100.0], [1_700_000_010_000_000_000]
    identities = {role: ProcessObjectIdentity(10 + index,
        _FILETIME_EPOCH + (wall[0] - 1_000_000_000) // 100,
        f"c:\\owned\\{role}.exe") for index, role in enumerate(ROLES)}
    records = {role: dict(pid=identity.pid, ts_ns=wall[0], counter=1, flags=1)
               for role, identity in identities.items()}
    owners = dict(identities)
    witnesses = {role: [] for role in ROLES}
    reads, probes = [], []

    class Witness:
        def __init__(self, role, pid):
            if identities[role].pid != pid:
                raise ValueError("Unknown native PID")
            self.role, self.identity = role, identities[role]
            self.pid, self.birth_ticks = pid, self.identity.birth_ticks
            self.generation_id = f"{pid}:{self.birth_ticks}"
            self.closed = False
            self.close_count = 0
            self.fail_close = False

        def validate(self):
            probes.append(self.role)
            return not self.closed and self.identity == identities[self.role]

        def close(self):
            self.close_count += 1
            self.closed = True
            if self.fail_close:
                raise OSError("Inert ambiguous native close")

    def identity_factory(pid, expected):
        role = "core" if expected is None else Path(expected[0]).stem
        result = Witness(role, pid)
        witnesses[role].append(result)
        return result

    def reader_factory(role):
        def read():
            reads.append(role)
            return records[role]
        return SimpleNamespace(read=read, authentication_status=lambda **_kw: "authenticated")

    cache = ComponentHeartbeatCache({role: (f"C:/owned/{role}.exe",) for role in ROLES},
        reader_factory=reader_factory, identity_factory=identity_factory,
        clock=lambda: clock[0], wall_ns=lambda: wall[0], owned_core_pid=identities["core"].pid,
        owner_matcher=lambda role, identity: owners.get(role) == identity)
    sample = SimpleNamespace(cache=cache, clock=clock, wall=wall, identities=identities,
                             records=records, owners=owners, witnesses=witnesses,
                             reads=reads, probes=probes)
    try:
        yield sample
    finally:
        cache.close()


def publish(sample):
    sample.cache.sample()
    sample.cache.refresh_owned_processes()
    return sample.cache.owned_process_identities()


def test_native_context_can_exist_before_progress_has_advanced_and_expires(context):
    rows = publish(context)
    assert {row.role for row in rows} == set(ROLES)
    assert all(row["state"] == "starting" for row in context.cache.snapshot())
    assert all(row.expires_monotonic - row.observed_monotonic == 2 for row in rows)
    assert read_owned_processes(context.cache.owned_process_identities, now=context.clock[0]) == rows
    with pytest.raises(ValueError, match="stale"):
        read_owned_processes(context.cache.owned_process_identities, now=context.clock[0] + 2.01)


def test_stale_or_missing_progress_cannot_erase_a_still_owned_native_generation(context):
    before = publish(context)
    context.clock[0] += 20
    context.wall[0] += 20_000_000_000
    context.cache.sample()
    assert all(row["state"] == "stale" for row in context.cache.snapshot())
    context.cache.refresh_owned_processes()
    assert [(row.pid, row.birth_ticks) for row in context.cache.owned_process_identities()] == [
        (row.pid, row.birth_ticks) for row in before]
    for role in ROLES:
        context.records[role] = None
    context.cache.sample()
    assert all(row["state"] == "unavailable" for row in context.cache.snapshot())
    context.cache.refresh_owned_processes()
    assert {row.role for row in context.cache.owned_process_identities()} == set(ROLES)


def test_current_core_is_not_selected_from_a_heartbeat_pid(context):
    context.records["core"] = dict(context.records["core"], pid=999999)
    rows = publish(context)
    core = next(row for row in rows if row.role == "core")
    assert core.pid == context.identities["core"].pid
    assert core.pid != context.records["core"]["pid"]


def test_native_role_needs_real_owner_link_not_heartbeat_or_adoption_metadata(context):
    context.owners.clear()  # No actual retained owner, even though all beats authenticate.
    rows = publish(context)
    assert [row.role for row in rows] == ["core"]
    assert all(row["pid"] is not None for row in context.cache.snapshot())
    context.owners.update(context.identities)
    context.cache.refresh_owned_processes()
    assert len(context.cache.owned_process_identities()) == 4
    context.owners.pop("scanner")
    context.cache.refresh_owned_processes()
    assert "scanner" not in {row.role for row in context.cache.owned_process_identities()}


def test_pid_reuse_and_owner_replacement_do_not_rebind_old_proof(context):
    publish(context)
    old = context.identities["scanner"]
    # New native birth is AFTER the last old heartbeat, not an impossible
    # overlapping generation. Replaying the old record cannot admit this PID.
    new_birth = old.birth_ticks + 10_001_000
    context.identities["scanner"] = replace(old, birth_ticks=new_birth)
    context.cache.refresh_owned_processes()
    assert "scanner" not in {row.role for row in context.cache.owned_process_identities()}
    context.records["scanner"] = dict(context.records["scanner"], ts_ns=context.wall[0] + 100_000)
    context.wall[0] += 100_000
    context.cache.sample()
    context.cache.refresh_owned_processes()
    assert "scanner" not in {row.role for row in context.cache.owned_process_identities()}
    context.owners["scanner"] = context.identities["scanner"]
    context.cache.refresh_owned_processes()
    scanner = next(row for row in context.cache.owned_process_identities() if row.role == "scanner")
    assert scanner.birth_ticks == str(new_birth)


def test_cached_getter_does_no_clock_file_native_or_lock_work(context, monkeypatch):
    rows = publish(context)
    def forbidden(*_a, **_k):
        pytest.fail("Consumer attempted observation work")
    monkeypatch.setattr(context.cache, "_clock", forbidden)
    monkeypatch.setattr(context.cache, "_reader_factory", forbidden)
    monkeypatch.setattr(context.cache, "_identity_factory", forbidden)
    monkeypatch.setattr(context.cache, "_owner_matcher", forbidden)
    monkeypatch.setattr(context.cache, "snapshot", forbidden)
    assert context.cache.owned_process_identities() is rows
    with pytest.raises(FrozenInstanceError):
        rows[0].pid = 999


def test_stop_fence_withdraws_inflight_and_late_publications(context):
    rows = publish(context)
    prior_epoch = context.cache._owned_epoch
    def stop_during_match(role, identity):
        context.cache.mark_stopped()
        return True
    context.cache._owner_matcher = stop_during_match
    context.cache.refresh_owned_processes()
    assert context.cache.owned_process_identities() == ()
    context.cache._owned_publication = (prior_epoch, rows)  # Model a late worker assignment.
    assert context.cache.owned_process_identities() == ()


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), -1, 99.0])
def test_invalid_or_regressed_clock_cannot_refresh_context(context, clock):
    publish(context)
    context.clock[0] = clock
    context.cache.refresh_owned_processes()
    assert context.cache.owned_process_identities() == ()


def test_ambiguous_native_close_is_reported_without_retry(context):
    publish(context)
    witness = context.cache._owned_witnesses["scanner"]
    witness.fail_close = True
    context.owners.pop("scanner")
    context.cache.refresh_owned_processes()
    assert witness.close_count == 1
    assert "scanner" not in {row.role for row in context.cache.owned_process_identities()}
    with pytest.raises(RuntimeError, match="close remains unproven"):
        context.cache.close()
    assert witness.close_count == 1
    context.cache._owned_close_failure = ""  # Only the inert fixture's expected diagnostic.


def test_owner_membership_cleanup_uncertainty_does_not_become_a_valid_context(context):
    from angerona.core.windows_child_job import NativeOwnershipObservationError

    publish(context)
    def unproven(*_args):
        raise NativeOwnershipObservationError("Inert duplicate-handle close failure")
    context.cache._owner_matcher = unproven
    context.cache.refresh_owned_processes()
    assert [row.role for row in context.cache.owned_process_identities()] == ["core"]
    with pytest.raises(RuntimeError, match="close remains unproven"):
        context.cache.close()
    context.cache._owned_close_failure = ""


@pytest.mark.parametrize("observer", ["heartbeat", "owned"])
@pytest.mark.parametrize("rejection", ["identity", "invocation"])
def test_rejected_witness_admission_retains_cleanup_failure_without_reopening(monkeypatch, observer, rejection):
    """Constructor failures own no registered witness, but still owe cleanup."""
    from angerona.core import windows_process_lease
    from angerona.core.windows_child_job import NativeOwnershipObservationError
    from angerona.resilience import component_status, supervisor
    import psutil

    opened, closed, failures = [], [], []
    wall = 1_700_000_010_000_000_000
    identity = ProcessObjectIdentity(123, _FILETIME_EPOCH + (wall - 1_000_000_000) // 100,
                                     "c:\\owned\\scanner.exe")
    close_failure = OSError("Inert admission-close ambiguity")

    class Native:
        def open(self, pid, rights, inherit):
            assert (pid, rights, inherit) == (123, 0x101000, False)
            opened.append(pid)
            return 901  # Inert numeric seam: never passed to Windows.

        def identity(self, handle):
            assert handle == 901
            if rejection == "identity":
                raise ValueError("Inert native identity rejection")
            return identity

        def wait(self, *_args):
            pytest.fail("Rejected invocation cannot reach native liveness admission")

        def close(self, handle):
            assert handle == 901
            closed.append(handle)
            raise close_failure

    def witness_factory(pid, expected):
        try:
            return component_status._ReadOnlyProcessWitness(pid, expected)
        except NativeOwnershipObservationError as exc:
            failures.append(exc)
            raise

    monkeypatch.setattr(windows_process_lease, "_Native", Native)
    monkeypatch.setattr(psutil, "Process", lambda _pid: object())
    monkeypatch.setattr(supervisor, "_invocation_identity", lambda *_args: None)
    record = dict(pid=123, ts_ns=wall, counter=1, flags=1)
    cache = ComponentHeartbeatCache({"scanner": (identity.image,)},
        enabled={role: role == "scanner" for role in ROLES},
        reader_factory=lambda _role: SimpleNamespace(read=lambda: record,
            authentication_status=lambda **_kwargs: "authenticated"),
        identity_factory=witness_factory, clock=lambda: 100.0, wall_ns=lambda: wall,
        owned_core_pid=999, owner_matcher=lambda *_args: True)
    if observer == "owned":
        # Admit the fixed role only through an inert internal seam; the test
        # exercises native witness construction, not wire authentication.
        cache._authenticated_identities["scanner"] = identity
        cache.refresh_owned_processes()
    else:
        cache.sample()
    assert cache.owned_process_identities() == ()
    assert opened == [123] and closed == [901]
    assert len(failures) == 1 and failures[0].__cause__ is close_failure
    assert cache._owned_close_failure == "NativeOwnershipObservationError"
    assert cache._native_cleanup_failed_roles == {"scanner"}
    assert not cache._witnesses and not cache._owned_witnesses

    # Neither observer may open another handle to compensate for a close whose
    # result is unknown. The uncertainty survives both reads and repeated close.
    for _ in range(2):
        cache.sample()
        cache.refresh_owned_processes()
        assert cache.owned_process_identities() == ()
    assert "cleanup remains unproven" in next(
        row["reason"] for row in cache.snapshot() if row["role"] == "scanner")
    for _ in range(2):
        with pytest.raises(RuntimeError, match="close remains unproven: NativeOwnershipObservationError"):
            cache.close()
    assert opened == [123] and closed == [901]


def test_app_and_manager_suppliers_are_cached_and_stop_fenced(context):
    from angerona.app import AngeronaApp
    from angerona.resilience.manager import ResilienceManager

    rows = publish(context)
    owner = object.__new__(ResilienceManager)
    owner._stop = threading.Event()
    owner._component_heartbeat_cache = context.cache
    app = object.__new__(AngeronaApp)
    app._shutdown_requested = threading.Event()
    assert app._owned_process_identities_cached() == ()
    app._resilience = owner
    assert app._owned_process_identities_cached() is rows
    app._shutdown_requested.set()
    assert app._owned_process_identities_cached() == ()
    app._shutdown_requested.clear()
    owner._stop.set()
    assert owner.owned_process_identities() == ()


def test_supervisor_labels_and_unknown_owners_cannot_enroll_context(context):
    from angerona.resilience.manager import ResilienceManager

    owner = object.__new__(ResilienceManager)
    owner._stop = threading.Event()
    owner._sup = SimpleNamespace(_lifecycle_lock=threading.Lock(), components={
        "scanner": SimpleNamespace(_dead=False, proc=SimpleNamespace(
            owns_descendants=True, contains_native_process=lambda _identity: True)),
    })
    identity = context.identities["scanner"]
    assert not owner._owns_component_native_identity("scanner", identity)
    owner._sup._lifecycle_lock.acquire()
    try:
        assert not owner._owns_component_native_identity("scanner", identity)
    finally:
        owner._sup._lifecycle_lock.release()
    owner._stop.set()
    assert not owner._owns_component_native_identity("scanner", identity)


@pytest.mark.skipif(os.name != "nt", reason="Retained Windows native process/Job observation")
def test_query_membership_cleanup_failure_is_not_a_successful_native_receipt(monkeypatch):
    """Inert Win32 seams; the numeric handles below never reach Windows."""
    import ctypes
    import win32api
    from angerona.core import windows_process_lease
    from angerona.core.windows_child_job import NativeOwnershipObservationError, OwnedWindowsChild

    identity = ProcessObjectIdentity(123, _FILETIME_EPOCH + 10_000_000, "c:\\owned\\member.exe")
    closed = []
    class Duplicate:
        def __int__(self):
            return 3
        def Close(self):
            closed.append("job")
    class Function:
        def __call__(self, process, job, result):
            assert process == 5 and job == 3
            result._obj.value = True
            return 1
    class Native:
        def open(self, pid, rights, inherit):
            assert (pid, rights, inherit) == (123, 0x101000, False)
            return 5
        def identity(self, handle):
            assert handle == 5
            return identity
        def wait(self, handle, _milliseconds):
            assert handle == 5
            return False
        def close(self, handle):
            assert handle == 5
            closed.append("process")
            raise OSError("Inert close ambiguity")
    monkeypatch.setattr(windows_process_lease, "_Native", Native)
    monkeypatch.setattr(win32api, "GetCurrentProcess", lambda: 1)
    monkeypatch.setattr(win32api, "DuplicateHandle", lambda *a: Duplicate())
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: SimpleNamespace(IsProcessInJob=Function()))
    owner = object.__new__(OwnedWindowsChild)
    owner._handle_lock = threading.RLock()
    owner._process = SimpleNamespace(Close=lambda: None)
    owner._job = SimpleNamespace(_handle=2, close=lambda: None)
    try:
        with pytest.raises(NativeOwnershipObservationError, match="cleanup remains unproven"):
            owner.contains_native_process(identity)
        assert closed == ["process", "job"]
    finally:
        owner.close()


@pytest.mark.skipif(os.name != "nt", reason="Retained Windows native process/Job observation")
def test_native_self_context_uses_query_only_handles_and_memory_only_getter(monkeypatch):
    from angerona.core.windows_process_lease import _Native

    requested = []
    actual_open = _Native.open
    def query_only(native, pid, rights, inherit):
        requested.append((pid, rights, inherit))
        return actual_open(native, pid, rights, inherit)
    monkeypatch.setattr(_Native, "open", query_only)
    cache = ComponentHeartbeatCache({role: None for role in ROLES}, owned_core_pid=os.getpid())
    try:
        cache.refresh_owned_processes()
        rows = cache.owned_process_identities()
        assert len(rows) == 1 and rows[0].role == "core" and rows[0].pid == os.getpid()
        assert int(rows[0].birth_ticks) == cache._owned_witnesses["core"].identity.birth_ticks
        assert requested == [(os.getpid(), 0x101000, False)]
        def forbidden(*_a, **_k):
            pytest.fail("Cached consumer called native observation")
        monkeypatch.setattr(_Native, "open", forbidden)
        monkeypatch.setattr(_Native, "identity", forbidden)
        monkeypatch.setattr(_Native, "wait", forbidden)
        assert cache.owned_process_identities() is rows
    finally:
        cache.close()
    assert cache._owned_witnesses == {}


@pytest.mark.skipif(os.name != "nt", reason="Retained Windows native process/Job observation")
def test_native_owned_job_proves_actual_member_rejects_foreign_and_reuse():
    import psutil
    from angerona.core.windows_child_job import launch_windows_child
    from angerona.core.windows_process_lease import _Native

    child = launch_windows_child([str(Path(sys.executable).absolute()), "-c", "import time; time.sleep(3)"],
                                  dict(os.environ))
    native, handles = _Native(), []
    try:
        wrapper = native.open(child.pid, 0x101000, False)
        handles.append(wrapper)
        assert child.contains_native_process(native.identity(wrapper))
        deadline = time.monotonic() + 1.5
        candidates = []
        while not candidates and time.monotonic() < deadline:
            candidates = psutil.Process(child.pid).children(recursive=False)
            if len(candidates) > 4:
                pytest.fail("Owned inert redirector exceeded its fixed child bound")
            if not candidates:
                time.sleep(.01)
        if candidates:
            actual = native.open(candidates[0].pid, 0x101000, False)
            handles.append(actual)
            identity = native.identity(actual)
            assert identity.pid != child.pid and child.contains_native_process(identity)
            assert not child.contains_native_process(replace(identity, birth_ticks=identity.birth_ticks + 1))
        caller = native.open(os.getpid(), 0x101000, False)
        handles.append(caller)
        assert not child.contains_native_process(native.identity(caller))
        child.wait(timeout=8)
        child.wait_tree(timeout=3)
        assert all(native.wait(handle, 0) for handle in handles[:-1])
    finally:
        try:
            if child.poll() is None:
                try:
                    child.wait(timeout=8)
                    child.wait_tree(timeout=3)
                except subprocess.TimeoutExpired:
                    child.terminate()  # Exact fixture Job only; test remains failed.
                    child.wait(timeout=3)
                    child.wait_tree(timeout=3)
                    pytest.fail("Owned inert fixture failed natural retirement")
        finally:
            for handle in handles:
                native.close(handle)
            child.close()
