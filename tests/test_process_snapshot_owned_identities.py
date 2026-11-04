"""Inventory ownership observation: inert native seams and a real Windows owner.

The unit fixture never opens an OS handle.  The separately marked integration
case starts only the ordinary process-inventory worker and retires that owner.
"""
from __future__ import annotations

import ctypes
from dataclasses import FrozenInstanceError, replace
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import windows_process_lease
from angerona.core.werfault_guard import OwnedProcessIdentity, read_owned_process_snapshot
from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.telemetry import process_snapshot_worker as worker


_BIRTH = 116444736000000000 + 1_700_000_000 * 10_000_000


class _InertNative:
    """Opaque numeric test tokens; no token is ever passed to Windows."""

    def __init__(self):
        self.identities = {
            pid: ProcessObjectIdentity(pid, _BIRTH + pid, rf"C:\inert\owned-{pid}.exe")
            for pid in (1001, 1002, 1003)
        }
        self.handles = {20_000 + pid: pid for pid in self.identities}
        self.held_handles = frozenset(self.handles)
        self.opened = []
        self.closed = []
        self.calls = []
        self.fail = {}
        self.hook = None
        self._next_handle = 90_000

    def _call(self, name, handle):
        pid = self.handles[handle]
        self.calls.append((name, pid))
        if self.hook is not None:
            self.hook(name, pid)
        failure = self.fail.get((name, pid))
        if failure is not None:
            raise failure
        return pid

    def open(self, pid, rights, inherit):
        self.calls.append(("open", pid))
        assert (rights, inherit) == (0x101000, False)
        failure = self.fail.get(("open", pid))
        if failure is not None:
            raise failure
        assert pid in self.identities
        self._next_handle += 1
        handle = self._next_handle
        self.handles[handle] = pid
        self.opened.append((pid, rights, inherit, handle))
        return handle

    def identity(self, handle):
        return self.identities[self._call("identity", handle)]

    def object_identity(self, handle):
        identity = self.identities[self._call("object_identity", handle)]
        return identity.pid, identity.birth_ticks

    def wait(self, handle, milliseconds):
        assert milliseconds == 0
        self._call("wait", handle)
        return False

    def close(self, handle):
        assert handle not in self.held_handles, "Observer closed a retained lifetime pin"
        assert handle not in self.closed, "Observer retried a numeric handle"
        self.closed.append(handle)
        self._call("close", handle)

    def terminate(self, *_args):
        pytest.fail("Read-only observation attempted process termination")


@pytest.fixture
def inert_owner(monkeypatch):
    """Actual owner types with inert native methods, not a fake ownership row."""
    provider = worker.ProcessSnapshotProvider((r"C:\inert\python.exe", "-c", "inert"))
    native = _InertNative()
    job = object.__new__(worker._Job)
    job.handle, job.close_failed = 700, False
    members = [[1001, 1002, 1003]]
    member_reads = []

    def read_members(actual):
        assert actual is job and actual.handle == 700
        index = min(len(member_reads), len(members) - 1)
        member_reads.append(index)
        return list(members[index])

    def contains_handle(actual, handle):
        assert actual is job
        pid = native._call("contains", handle)
        return pid in members[-1]

    def pin(pid):
        result = object.__new__(worker._Pin)
        result.pid, result.process = pid, None
        result.handle = 20_000 + pid
        result.native = native
        result.identity = (pid, native.identities[pid].birth_ticks)
        result.birth = str(result.identity[1])
        result.closed = result.close_failed = False
        result.proof = None
        return result

    provider._job = job
    provider._wrapper, provider._child = pin(1001), pin(1002)
    provider._started = provider._ready = True
    provider._reason = "ready"
    clock = [100.0]
    monkeypatch.setattr(worker, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(worker, "on_gui_thread", lambda: False)
    monkeypatch.setattr(windows_process_lease, "_Native", lambda: native)
    monkeypatch.setattr(worker._Job, "members", read_members)
    monkeypatch.setattr(worker._Job, "contains_handle", contains_handle)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Observation created, changed or retired an owner")

    monkeypatch.setattr(worker._Pin, "__init__", forbidden)
    monkeypatch.setattr(worker._Pin, "retire", forbidden)
    monkeypatch.setattr(worker._Job, "assign", forbidden)
    monkeypatch.setattr(worker.ProcessSnapshotProvider, "lifecycle_snapshot", forbidden)
    # Guard this provider namespace only. Mutating the shared stdlib module
    # also forbids legitimate separate subprocess owners in composed fixtures.
    subprocess_api = worker.subprocess
    monkeypatch.setattr(worker, "subprocess", SimpleNamespace(
        Popen=forbidden, TimeoutExpired=subprocess_api.TimeoutExpired,
        PIPE=subprocess_api.PIPE, DEVNULL=subprocess_api.DEVNULL,
        CREATE_NO_WINDOW=getattr(subprocess_api, "CREATE_NO_WINDOW", 0),
    ))
    return SimpleNamespace(provider=provider, native=native, job=job, members=members,
                           member_reads=member_reads, clock=clock)


def test_inert_complete_native_observation_has_consumer_leases_and_no_mutation(inert_owner):
    sample = inert_owner
    wrapper, child = sample.provider._wrapper, sample.provider._child
    rows = sample.provider.observe_owned_process_identities()
    assert type(rows) is tuple and all(type(row) is OwnedProcessIdentity for row in rows)
    assert {row.pid: row.role for row in rows} == {
        1001: "inventory-wrapper", 1002: "inventory-worker", 1003: "inventory-member"}
    assert {(row.pid, int(row.birth_ticks), row.image) for row in rows} == {
        (identity.pid, identity.birth_ticks, identity.image.lower())
        for identity in sample.native.identities.values()}
    assert all(row.observed_monotonic == 100.0 and row.expires_monotonic == 102.0 for row in rows)
    admitted = read_owned_process_snapshot(lambda: rows, not_before=100.0, clock=lambda: 100.0)
    assert admitted.rows is rows
    with pytest.raises(FrozenInstanceError):
        rows[0].pid = 999
    with pytest.raises(ValueError, match="stale"):
        read_owned_process_snapshot(lambda: rows, not_before=102.0, clock=lambda: 102.0)
    assert len(sample.member_reads) >= 2
    assert len(sample.native.opened) == 3
    assert set(sample.native.closed) == {entry[3] for entry in sample.native.opened}
    assert (sample.provider._wrapper, sample.provider._child) == (wrapper, child)
    assert not wrapper.closed and not child.closed
    assert sample.provider._proofs == [] and sample.provider._extra_pins == []


def test_inert_wrapper_collector_alias_is_one_worker_row(inert_owner):
    sample = inert_owner
    sample.provider._child = sample.provider._wrapper
    sample.members[:] = [[1001]]
    rows = sample.provider.observe_owned_process_identities()
    assert [(row.pid, row.role) for row in rows] == [(1001, "inventory-worker")]
    assert len(sample.native.opened) == len(sample.native.closed) == 1


@pytest.mark.parametrize("value", [True, 0, -1, 1.01, float("nan"), float("inf"), "1", None])
def test_invalid_deadline_does_not_touch_native_owner(inert_owner, value):
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities(timeout=value)
    assert inert_owner.native.calls == []


def test_gui_refusal_precedes_locks_and_native_queries(inert_owner, monkeypatch):
    monkeypatch.setattr(worker, "on_gui_thread", lambda: True)
    assert inert_owner.provider._retirement.acquire(blocking=False)
    try:
        with pytest.raises(worker.InventoryWorkerError):
            inert_owner.provider.observe_owned_process_identities()
        assert inert_owner.native.calls == []
    finally:
        inert_owner.provider._retirement.release()


def test_non_windows_owner_cannot_invent_a_filetime_observation(inert_owner, monkeypatch):
    monkeypatch.setattr(worker, "os", SimpleNamespace(name="posix"))
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert inert_owner.native.calls == []


@pytest.mark.parametrize("attribute,value", [
    ("_ready", False), ("_stopping", True), ("_retired", True),
    ("_failure", "original-inventory-failure"), ("_auxiliary_close_unproven", True),
    ("_launching", True), ("_starting_thread", True),
    ("_retirement_error", "original-retirement-failure"), ("_popen_close_failed", True),
    ("_job", None), ("_wrapper", None), ("_child", None),
])
def test_unavailable_or_incomplete_owner_is_never_an_empty_success(inert_owner, attribute, value):
    setattr(inert_owner.provider, attribute, value)
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert inert_owner.native.opened == []


@pytest.mark.parametrize("pin_name", ["_wrapper", "_child"])
@pytest.mark.parametrize("attribute,value", [("closed", True), ("close_failed", True), ("handle", None)])
def test_ambiguous_known_pin_cannot_be_replaced_by_querying_its_pid(inert_owner, pin_name, attribute, value):
    setattr(getattr(inert_owner.provider, pin_name), attribute, value)
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert inert_owner.native.opened == []


@pytest.mark.parametrize("members", [[1001, 1003], [1002, 1003], []])
def test_incomplete_job_snapshot_does_not_publish_remaining_known_rows(inert_owner, members):
    inert_owner.members[:] = [members]
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


def test_job_member_change_during_observation_rejects_every_row(inert_owner):
    inert_owner.members[:] = [[1001, 1002, 1003], [1001, 1002]]
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


def test_reused_known_pid_does_not_replace_its_retained_native_birth(inert_owner):
    identity = inert_owner.native.identities[1002]
    inert_owner.native.identities[1002] = replace(identity, birth_ticks=identity.birth_ticks + 1)
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


@pytest.mark.parametrize("operation", ["open", "identity", "wait", "contains"])
def test_native_failure_is_all_or_nothing_and_closes_every_acquired_handle(inert_owner, operation):
    inert_owner.native.fail[(operation, 1002)] = OSError("Inert native observation denial")
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}
    assert inert_owner.provider._proofs == []


def test_exited_member_does_not_look_owned_from_its_pid_and_image(inert_owner, monkeypatch):
    original_wait = inert_owner.native.wait
    monkeypatch.setattr(inert_owner.native, "wait", lambda handle, ms:
                        inert_owner.native.handles[handle] == 1002 or original_wait(handle, ms))
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


def test_identity_change_on_second_native_read_rejects_the_whole_sample(inert_owner):
    reads = []
    def change_on_second_read(name, pid):
        if name == "identity" and pid == 1002:
            reads.append(pid)
            if len(reads) == 2:
                identity = inert_owner.native.identities[pid]
                inert_owner.native.identities[pid] = replace(identity, image=r"C:\inert\replacement.exe")
    inert_owner.native.hook = change_on_second_read
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert len(reads) == 2
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


def test_stop_fence_during_native_observation_rejects_late_result(inert_owner):
    def stop_on_query(name, _pid):
        if name == "identity":
            assert inert_owner.provider._lock.acquire(blocking=False), "Native query held the state lock"
            try:
                inert_owner.provider._stopping = True
                inert_owner.provider._ready = False
            finally:
                inert_owner.provider._lock.release()
    inert_owner.native.hook = stop_on_query
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


def test_deadline_expiring_inside_observation_cannot_return_fresh_leases(inert_owner):
    def expire_on_query(name, _pid):
        if name == "identity":
            inert_owner.clock[0] = 102.0
    inert_owner.native.hook = expire_on_query
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities(timeout=1.0)
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}


def test_retirement_admission_timeout_does_not_observe_native_state(inert_owner):
    assert inert_owner.provider._retirement.acquire(blocking=False)
    try:
        with pytest.raises(worker.InventoryWorkerError):
            inert_owner.provider.observe_owned_process_identities(timeout=0.01)
        assert inert_owner.native.opened == []
    finally:
        inert_owner.provider._retirement.release()


def test_state_lock_admission_deadline_does_not_observe_native_state(inert_owner):
    assert inert_owner.provider._lock.acquire(blocking=False)
    try:
        with pytest.raises(worker.InventoryWorkerError):
            inert_owner.provider.observe_owned_process_identities(timeout=0.01)
        assert inert_owner.native.opened == []
    finally:
        inert_owner.provider._lock.release()


@pytest.mark.parametrize("prior_read_failure", [False, True])
def test_close_failure_poison_is_not_a_success_and_numeric_handle_is_never_retried(
    inert_owner, prior_read_failure,
):
    if prior_read_failure:
        inert_owner.native.fail[("identity", 1002)] = OSError("Inert earlier read failure")
    inert_owner.native.fail[("close", 1002)] = OSError("Inert close uncertainty")
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert inert_owner.provider._auxiliary_close_unproven is True
    assert set(inert_owner.native.closed) == {entry[3] for entry in inert_owner.native.opened}
    before = list(inert_owner.native.calls)
    with pytest.raises(worker.InventoryWorkerError):
        inert_owner.provider.observe_owned_process_identities()
    assert inert_owner.native.calls == before
    assert len(inert_owner.native.closed) == len(set(inert_owner.native.closed))


@pytest.mark.parametrize("assigned,count,ids", [
    (2, 1, [1001]), (1, 2, [1001, 1002]), (4, 4, [1001, 1002, 1003, 1004]),
    (2, 2, [1001, 1001]), (1, 1, [0]),
])
def test_job_query_rejects_truncation_duplicate_and_invalid_ids(assigned, count, ids):
    job = object.__new__(worker._Job)
    job.handle, job.close_failed = 700, False
    job.c, job.w = ctypes, SimpleNamespace(DWORD=ctypes.c_uint32)

    def query(handle, information, pointer, _size, _returned):
        assert (handle, information) == (700, 3)
        result = pointer._obj
        result.assigned, result.count = assigned, count
        for index, pid in enumerate(ids):
            result.ids[index] = pid
        return True

    job.api = SimpleNamespace(QueryInformationJobObject=query)
    with pytest.raises(worker.InventoryWorkerError):
        job.members()


def _off_gui(call, timeout=15.0):
    """Retain and join the exact caller; never hide an unretired test worker."""
    output = []
    def run():
        try:
            output.append((True, call()))
        except BaseException as exc:
            output.append((False, exc))
    thread = threading.Thread(target=run, name="InventoryOwnedIdentityTest", daemon=False)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "Owned observation caller did not retire"
    assert len(output) == 1
    if not output[0][0]:
        raise output[0][1]
    return output[0][1]


@pytest.mark.skipif(os.name != "nt", reason="Real retained Windows inventory Job identities")
def test_native_owned_worker_observation_covers_exact_job_and_then_retires(monkeypatch):
    """Genuine native positive: no fixture rows or native ownership stubs."""
    command = [sys.executable, "-c",
               "from angerona.telemetry.process_snapshot_worker import worker_main; raise SystemExit(worker_main())"]
    provider = worker.ProcessSnapshotProvider(command, startup_timeout=10.0)
    actual_open, actual_close = windows_process_lease._Native.open, windows_process_lease._Native.close
    opened, closed = [], []
    try:
        assert _off_gui(provider.start), provider.lifecycle_snapshot()
        before = provider.lifecycle_snapshot()
        def record_open(native, pid, rights, inherit):
            assert (rights, inherit) == (0x101000, False)
            handle = actual_open(native, pid, rights, inherit)
            opened.append((pid, handle))
            return handle
        def record_close(native, handle):
            assert handle in {value for _pid, value in opened}
            assert handle not in closed
            closed.append(handle)
            return actual_close(native, handle)
        with monkeypatch.context() as guarded:
            guarded.setattr(windows_process_lease._Native, "open", record_open)
            guarded.setattr(windows_process_lease._Native, "close", record_close)
            rows = _off_gui(provider.observe_owned_process_identities)
        now = time.monotonic()
        admitted = read_owned_process_snapshot(lambda: rows, not_before=now, clock=time.monotonic)
        assert admitted.rows is rows
        assert rows and len(rows) <= 3
        assert len({row.pid for row in rows}) == len(rows)
        assert {row.pid for row in rows} == set(_off_gui(provider._job.members))
        assert {before["wrapper_pid"], before["child_pid"]} <= {row.pid for row in rows}
        assert all(type(row) is OwnedProcessIdentity and row.expires_monotonic - row.observed_monotonic == 2.0
                   for row in rows)
        native = windows_process_lease._Native()
        handles = []
        try:
            for row in rows:
                handle = native.open(row.pid, 0x101000, False)
                handles.append(handle)
                identity = native.identity(handle)
                assert (row.pid, int(row.birth_ticks), row.image) == (
                    identity.pid, identity.birth_ticks, identity.image)
                assert not native.wait(handle, 0)
        finally:
            for handle in handles:
                native.close(handle)
        assert set(closed) == {handle for _pid, handle in opened}
        assert len(opened) == len(closed) == len(rows)
        after = provider.lifecycle_snapshot()
        assert after["ready"] and not after["retired"] and not after["retirement_proofs"]
        assert after["child_pid"] == before["child_pid"] and after["child_birth"] == before["child_birth"]
        assert after["wrapper_pid"] == before["wrapper_pid"]
    finally:
        assert _off_gui(lambda: provider.stop(timeout=5.0)), provider.lifecycle_snapshot()
    state = provider.lifecycle_snapshot()
    assert state["retired"] and not state["ready"]
    assert state["retirement_proofs"] and all(proof["wait_signaled"] and proof["handle_closed"]
                                              for proof in state["retirement_proofs"])
    with pytest.raises(worker.InventoryWorkerError):
        _off_gui(provider.observe_owned_process_identities)


def test_inert_owner_spawn_guard_is_local_and_leaves_separate_stdlib_owner_real(inert_owner, tmp_path):
    import subprocess

    sample = inert_owner
    assert worker.subprocess is not subprocess
    assert worker.subprocess.TimeoutExpired is subprocess.TimeoutExpired
    # The original provider's no-spawn contract still fails before any launch.
    with pytest.raises(pytest.fail.Exception, match="Observation created, changed or retired an owner"):
        worker.subprocess.Popen(["must-not-run-provider-owner"])
    rows = sample.provider.observe_owned_process_identities()
    assert {row.pid for row in rows} == {1001, 1002, 1003}
    assert sample.provider._proofs == [] and sample.provider._extra_pins == []
    before = (sample.provider._wrapper, sample.provider._child, sample.job.handle)
    # This actual short-lived test owner is independent of the inert inventory
    # provider. It starts no application, service, network or descendant payload.
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", "print('independent-owned-fixture')"],
        cwd=tmp_path, capture_output=True, text=True, timeout=10, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "independent-owned-fixture" and result.stderr == ""
    assert (sample.provider._wrapper, sample.provider._child, sample.job.handle) == before
    assert not sample.provider._wrapper.closed and not sample.provider._child.closed
    assert sample.provider._proofs == [] and sample.provider._extra_pins == []
