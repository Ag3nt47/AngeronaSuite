"""Inert native seams for real child owners, plus a separately gated OS case."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import FrozenInstanceError, asdict, replace
import gc
import json
import os
import sys
import threading
import time
from types import SimpleNamespace
import weakref

import pytest

from angerona.core import windows_child_job as child_jobs
from angerona.core import windows_process_lease
from angerona.core.werfault_guard import OwnedProcessIdentity, read_owned_process_snapshot
from angerona.core.windows_process_lease import ProcessObjectIdentity


_BIRTH = 116444736000000000 + 1_700_000_000 * 10_000_000


class _Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class _Lifetime:
    def __init__(self, value):
        self.value, self.closed, self.closes = value, False, 0

    def __int__(self):
        return 0 if self.closed else self.value

    def Close(self):
        assert not self.closed, "A lifetime handle was closed twice"
        self.closes += 1
        self.closed = True


class InertChildNative:
    """Opaque integer tokens: no token or API below ever reaches Windows."""

    def __init__(self):
        self.ctypes, self.wintypes = ctypes, wintypes
        self.identities, self.lifetimes, self.handles = {}, {}, {}
        self.calls, self.duplicates, self.opened, self.closed = [], [], [], []
        self.fail, self.hook, self.exited, self.nonmembers = {}, None, set(), set()
        self.next_handle, self.next_lifetime = 90_000, 20_000
        self.api = SimpleNamespace(
            GetCurrentProcess=_Function(lambda: -1),
            DuplicateHandle=_Function(self._duplicate),
            QueryInformationJobObject=_Function(self._members),
            IsProcessInJob=_Function(self._contains),
        )

    def event(self, operation, subject):
        self.calls.append((operation, subject))
        if self.hook is not None:
            self.hook(operation, subject)
        error = self.fail.get((operation, subject))
        if error is not None:
            raise error

    def lifetime(self, kind, subject):
        self.next_lifetime += 1
        result = _Lifetime(self.next_lifetime)
        self.lifetimes[result.value] = (kind, subject, result)
        return result

    def query(self, kind, subject):
        self.next_handle += 1
        self.handles[self.next_handle] = (kind, subject)
        return self.next_handle

    def _duplicate(self, current, source, target, output, rights, inherit, options):
        assert (current, target, inherit, options) == (-1, -1, False, 0)
        kind, subject, lifetime = self.lifetimes[source]
        assert not lifetime.closed
        assert rights == (0x0004 if kind == "job" else 0x101000)
        self.event("duplicate", (kind, subject.token if kind == "job" else subject))
        handle = self.query(kind, subject)
        self.duplicates.append((kind, rights, source, handle))
        output._obj.value = handle
        return True

    def _members(self, handle, information_class, output, size, returned):
        kind, model = self.handles[handle]
        assert kind == "job" and information_class == 3 and returned is None
        value = output._obj
        assert len(value.pids) == 16 and size == ctypes.sizeof(value)
        self.event("members", model.token)
        index = min(model.reads, len(model.members) - 1)
        model.reads += 1
        members = model.members[index]
        value.assigned = len(members) if model.assigned is None else model.assigned
        value.count = min(len(members), 16) if model.count is None else model.count
        for index, pid in enumerate(members[:16]):
            value.pids[index] = pid
        return len(members) <= 16

    def _contains(self, process, job, output):
        kind, model = self.handles[job]
        process_kind, pid = self.handles[process]
        assert kind == "job" and process_kind == "process"
        self.event("contains", pid)
        output._obj.value = pid in model.members[-1] and pid not in self.nonmembers
        return True

    def open(self, pid, rights, inherit):
        assert rights == 0x101000 and inherit is False
        self.event("open", pid)
        assert pid in self.identities
        handle = self.query("process", pid)
        self.opened.append((pid, rights, inherit, handle))
        return handle

    def identity(self, handle):
        kind, pid = self.handles[handle]
        assert kind == "process"
        self.event("identity", pid)
        return self.identities[pid]

    def wait(self, handle, milliseconds):
        kind, pid = self.handles[handle]
        assert kind == "process" and milliseconds == 0
        self.event("wait", pid)
        return pid in self.exited

    def close(self, handle):
        assert handle in self.handles and handle not in self.closed
        self.closed.append(handle)  # An uncertain attempt is still never retried.
        self.event("close", handle)

    def terminate(self, *_args):
        pytest.fail("Ownership observation attempted process termination")


@pytest.fixture
def inert_child_factory(monkeypatch):
    """Multiple real owners, real query adapter, one shared inert native domain.

    Import this fixture in composition tests. make(pids, root_pid=...) returns
    owner/child, actual Job, native, mutable complete-membership samples, clock.
    Only Windows kernel calls/clock/Qt presence are inert; the API is real.
    """
    native, clock, made = InertChildNative(), [100.0], []
    monkeypatch.setattr(child_jobs, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(child_jobs, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(child_jobs, "_on_gui_thread", lambda: False)
    monkeypatch.setattr(windows_process_lease, "_Native", lambda: native)
    monkeypatch.setattr(child_jobs, "_OWNED_OBSERVATION_CLOSE_HOLDS", [])

    def make(pids=(1001, 1002), *, root_pid=None):
        pids = list(pids)
        root_pid = pids[0] if root_pid is None else root_pid
        for pid in {*pids, root_pid}:
            native.identities[pid] = ProcessObjectIdentity(pid, _BIRTH + pid,
                                                          rf"C:\inert\child-{pid}.exe")
        model = SimpleNamespace(token=len(made) + 1, members=[pids], reads=0,
                                assigned=None, count=None, termination_calls=[])
        job = object.__new__(child_jobs.WindowsChildJob)
        job._handle = native.lifetime("job", model)

        def terminate(handle, code):
            assert handle is job._handle and code == 1
            model.termination_calls.append(code)
            native.exited.update(model.members[-1])

        job._api = SimpleNamespace(TerminateJobObject=terminate)
        root_handle = native.lifetime("process", root_pid)
        owner = child_jobs.OwnedWindowsChild(root_handle, root_pid, job)
        result = SimpleNamespace(owner=owner, child=owner, job=job, root=root_handle,
                                 native=native, members=model.members, model=model, clock=clock)
        made.append(result)
        return result

    make.native, make.clock, make.made = native, clock, made
    try:
        yield make
    finally:
        # These are inert Python tokens, not OS handles. Drop mutated lifetime
        # aliases without letting fixture-GC order invent duplicate closes.
        # Real native cleanup is exercised separately below.
        for sample in made:
            sample.job._handle = None
            sample.owner._job._handle = None
            sample.owner._process = None


def test_complete_actual_owner_uses_retained_root_and_query_only_members(inert_child_factory):
    sample = inert_child_factory()
    rows = sample.owner.observe_owned_process_identities(role="scanner-ui")
    assert type(rows) is tuple and all(type(row) is OwnedProcessIdentity for row in rows)
    assert {row.pid for row in rows} == {1001, 1002}
    assert all(row.role == "scanner-ui" for row in rows)
    assert all(row.observed_monotonic == 100 and row.expires_monotonic == 102 for row in rows)
    assert [(kind, rights) for kind, rights, _source, _handle in sample.native.duplicates] == [
        ("job", 0x0004), ("process", 0x101000)]
    assert [entry[0] for entry in sample.native.opened] == [1002], "Root must never be opened by PID"
    assert set(sample.native.closed) == {entry[3] for entry in sample.native.duplicates} | {
        entry[3] for entry in sample.native.opened}
    assert sample.model.reads == 3 and not sample.root.closed and sample.job._handle is not None
    assert not sample.owner._owned_observation_close_holds
    assert read_owned_process_snapshot(lambda: rows, not_before=100, clock=lambda: 100).rows is rows
    with pytest.raises(FrozenInstanceError):
        rows[0].pid = 9
    with pytest.raises(ValueError):
        read_owned_process_snapshot(lambda: rows, not_before=102, clock=lambda: 102)


def test_multiple_actual_jobs_share_native_domain_without_borrowing_roots(inert_child_factory):
    first = inert_child_factory((1001, 1002))
    second = inert_child_factory((2001, 2002))
    a = first.owner.observe_owned_process_identities(role="scanner-ui")
    b = second.owner.observe_owned_process_identities(role="blackbox-ui")
    assert {row.pid for row in a} == {1001, 1002}
    assert {row.pid for row in b} == {2001, 2002}
    assert {row.role for row in a} == {"scanner-ui"} and {row.role for row in b} == {"blackbox-ui"}
    assert [item[0] for item in first.native.opened] == [1002, 2002]
    assert len(first.native.closed) == 6


@pytest.mark.parametrize("count,accepted", [(1, True), (16, True), (17, False)])
def test_full_job_bound_never_returns_a_truncated_success(inert_child_factory, count, accepted):
    sample = inert_child_factory(range(1001, 1001 + count))
    if accepted:
        rows = sample.owner.observe_owned_process_identities()
        assert len(rows) == count and {row.pid for row in rows} == set(sample.members[0])
    else:
        with pytest.raises(child_jobs.NativeOwnershipObservationError):
            sample.owner.observe_owned_process_identities()
        assert sample.native.opened == []
    assert len(sample.native.closed) == len(sample.native.duplicates) + len(sample.native.opened)


@pytest.mark.parametrize("members", [[], [1001, 1001], [1002], [0, 1001], [-1, 1001]])
def test_empty_missing_root_duplicate_and_invalid_members_hold_whole_sample(inert_child_factory, members):
    sample = inert_child_factory()
    sample.members[:] = [members]
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(sample.native.closed) == 2 and sample.native.opened == []


@pytest.mark.parametrize("assigned,count", [(3, 2), (2, 1), (17, 16), (0, 0)])
def test_native_list_header_incompleteness_is_not_repaired(inert_child_factory, assigned, count):
    sample = inert_child_factory()
    sample.model.assigned, sample.model.count = assigned, count
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert sample.native.opened == []


@pytest.mark.parametrize("samples", [
    [[1001, 1002], [1001]],
    [[1001, 1002], [1001, 1002], [1001, 1002, 1003]],
])
def test_membership_changes_at_either_closure_query_withhold_every_row(inert_child_factory, samples):
    sample = inert_child_factory((1001, 1002, 1003))
    sample.members[:] = samples
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(sample.native.closed) == 3


@pytest.mark.parametrize("fault", ["root-pid", "birth", "image", "exit", "membership", "malformed-image"])
def test_retained_native_identity_and_liveness_cannot_be_substituted(inert_child_factory, fault):
    sample = inert_child_factory()
    identities = sample.native.identities
    if fault == "root-pid":
        identities[1001] = replace(identities[1001], pid=1999)
    elif fault == "exit":
        sample.native.exited.add(1002)
    elif fault == "membership":
        sample.native.nonmembers.add(1002)
    elif fault == "malformed-image":
        identities[1002] = replace(identities[1002], image="relative.exe")
    else:
        reads = []
        def mutate_at_second_read(operation, subject):
            if (operation, subject) == ("identity", 1002):
                reads.append(True)
                if len(reads) == 2:
                    identities[1002] = (replace(identities[1002], birth_ticks=_BIRTH + 999)
                                         if fault == "birth" else replace(identities[1002], image=r"C:\other.exe"))
        sample.native.hook = mutate_at_second_read
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(sample.native.closed) == len(sample.native.duplicates) + len(sample.native.opened)
    assert not sample.root.closed


@pytest.mark.parametrize("operation,subject", [("members", 1), ("open", 1002),
                                              ("identity", 1002), ("wait", 1002), ("contains", 1002)])
def test_query_failure_preserves_original_lifetime_and_closes_all_admitted_queries(inert_child_factory,
                                                                                operation, subject):
    sample = inert_child_factory()
    sample.native.fail[(operation, subject)] = OSError("Inert native query failure")
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(sample.native.closed) == len(sample.native.duplicates) + len(sample.native.opened)
    assert sample.owner._process is sample.root and not sample.root.closed
    assert sample.job._handle is not None and not sample.owner._owned_observation_close_holds


def test_root_duplication_failure_retires_only_the_already_admitted_job_query(inert_child_factory):
    sample = inert_child_factory()
    sample.native.fail[("duplicate", ("process", 1001))] = OSError("Inert root duplication failure")
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(sample.native.duplicates) == 1 and sample.native.opened == []
    assert sample.native.closed == [sample.native.duplicates[0][3]]
    assert not sample.root.closed and not sample.owner._owned_observation_close_holds


@pytest.mark.parametrize("lock_name", ["_handle_lock", "_owned_observation_lock"])
def test_busy_owner_admission_never_starts_native_queries(inert_child_factory, lock_name):
    sample = inert_child_factory()
    # A separate inert lock makes contention deterministic without sleeping or
    # acquiring a reentrant owner lock again on this same thread.
    lock = threading.Lock()
    lock.acquire()
    setattr(sample.owner, lock_name, lock)
    try:
        with pytest.raises(child_jobs.NativeOwnershipObservationError):
            sample.owner.observe_owned_process_identities(timeout=0.001)
        assert sample.native.calls == []
    finally:
        lock.release()


@pytest.mark.parametrize("timeout", [True, 0, -1, 1.01, float("nan"), float("inf"), "1", None])
def test_bad_deadline_is_rejected_before_owner_locks_or_native(inert_child_factory, timeout):
    sample = inert_child_factory()
    class ForbiddenLock:
        def acquire(self, *_a, **_k):
            pytest.fail("Invalid input touched owner locks")
    sample.owner._handle_lock = sample.owner._owned_observation_lock = ForbiddenLock()
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities(timeout=timeout)
    assert sample.native.calls == []


@pytest.mark.parametrize("role", ["", "scanner_ui", "X", "x" * 33, True, None])
def test_bad_role_cannot_start_a_native_observation(inert_child_factory, role):
    sample = inert_child_factory()
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities(role=role)
    assert sample.native.calls == []


def test_qt_thread_is_refused_before_locks_and_native(inert_child_factory, monkeypatch):
    sample = inert_child_factory()
    class ForbiddenLock:
        def acquire(self, *_a, **_k):
            pytest.fail("Qt caller touched an owner lock")
    sample.owner._handle_lock = sample.owner._owned_observation_lock = ForbiddenLock()
    monkeypatch.setattr(child_jobs, "_on_gui_thread", lambda: True)
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert sample.native.calls == []


def test_native_queries_do_not_hold_owner_lock_across_membership_io(inert_child_factory):
    sample = inert_child_factory()
    lock_results = []
    def check(operation, _subject):
        if operation != "members":
            return
        def other_thread():
            acquired = sample.owner._handle_lock.acquire(blocking=False)
            lock_results.append(acquired)
            if acquired:
                sample.owner._handle_lock.release()
        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join(2)
        assert not thread.is_alive()
    sample.native.hook = check
    sample.owner.observe_owned_process_identities()
    assert lock_results == [True, True, True]


@pytest.mark.parametrize("change", ["process", "job", "job-handle", "process-closed",
                                    "job-closed", "epoch", "stopped"])
def test_owner_replacement_or_stop_during_query_cleanup_withholds_publication(inert_child_factory, change):
    sample = inert_child_factory()
    changed = []
    def alter(operation, _subject):
        if operation != "close" or changed:
            return
        changed.append(True)
        if change == "process":
            sample.owner._process = _Lifetime(int(sample.root))
        elif change == "job":
            job = object.__new__(child_jobs.WindowsChildJob)
            job._handle, job._api = sample.native.lifetime("job", sample.model), sample.job._api
            sample.owner._job = job
        elif change == "job-handle":
            sample.job._handle = _Lifetime(int(sample.job._handle))
        elif change == "process-closed":
            sample.root.Close()
        elif change == "job-closed":
            sample.job._handle.Close()
        elif change == "epoch":
            sample.owner._owned_observation_epoch += 1
        else:
            sample.owner._owned_observation_stopped = True
    sample.native.hook = alter
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert changed == [True] and len(sample.native.closed) == 3


def test_close_during_observation_fences_stop_but_preserves_lifetime_until_query_retired(inert_child_factory):
    sample = inert_child_factory()
    before_job = sample.job._handle
    attempted = []
    def close_while_reading(operation, _subject):
        if operation == "members" and not attempted:
            attempted.append(True)
            with pytest.raises(child_jobs.NativeOwnershipObservationError):
                sample.owner.close()
            assert sample.owner._process is sample.root and sample.job._handle is before_job
    sample.native.hook = close_while_reading
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert attempted == [True] and len(sample.native.closed) == 3
    assert sample.owner._owned_observation_stopped is True
    sample.native.hook = None
    sample.owner.close()
    assert sample.owner._process is None and sample.job._handle is None and sample.root.closed


def test_terminate_still_runs_original_job_action_and_withdraws_observations(inert_child_factory):
    sample = inert_child_factory()
    sample.owner.terminate()
    assert sample.model.termination_calls == [1]
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert sample.native.calls == []


@pytest.mark.parametrize("clock_change", [99.0, 101.0, float("nan"), float("inf")])
def test_clock_regression_expiry_or_invalidity_withholds_after_native_io(inert_child_factory, clock_change):
    sample = inert_child_factory()
    def change(operation, subject):
        if (operation, subject) == ("identity", 1002):
            sample.clock[0] = clock_change
    sample.native.hook = change
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(sample.native.closed) == 3


def test_cleanup_time_never_refreshes_the_original_two_second_observation(inert_child_factory):
    sample = inert_child_factory()
    def advance(operation, _subject):
        if operation == "close":
            sample.clock[0] += 0.1
    sample.native.hook = advance
    rows = sample.owner.observe_owned_process_identities()
    assert sample.clock[0] > 100
    assert all(row.observed_monotonic == 100 and row.expires_monotonic == 102 for row in rows)


@pytest.mark.parametrize("kind", ["job", "process"])
def test_uncertain_query_close_is_permanent_and_retains_original_owner(inert_child_factory, kind):
    sample = inert_child_factory()
    native = sample.native
    failed = []
    def fail_one_close(operation, handle):
        if operation == "close" and not failed and native.handles[handle][0] == kind:
            failed.append(handle)
            native.fail[("close", handle)] = OSError("Inert ambiguous query close")
    native.hook = fail_one_close
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert len(failed) == 1 and native.closed.count(failed[0]) == 1
    holds = sample.owner._owned_observation_close_holds
    assert len(holds) == 1 and holds[0][0] is sample.owner and holds[0][2] == failed[0]
    assert child_jobs._OWNED_OBSERVATION_CLOSE_HOLDS[0] is holds[0]
    before = list(native.calls)
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.close()
    assert native.calls == before and not sample.root.closed and sample.job._handle is not None
    ref = weakref.ref(sample.owner)
    native.hook = None
    inert_child_factory.made.clear()
    del holds
    del sample
    gc.collect()
    assert ref() is not None and native.closed.count(failed[0]) == 1


def test_legacy_lifecycle_seam_can_close_but_cannot_supply_missing_observation_state(inert_child_factory):
    sample = inert_child_factory()
    for name in ("_owned_observation_lock", "_owned_observation_epoch",
                 "_owned_observation_stopped", "_owned_observation_close_holds"):
        delattr(sample.owner, name)
    with pytest.raises(child_jobs.NativeOwnershipObservationError):
        sample.owner.observe_owned_process_identities()
    assert sample.native.calls == []
    sample.owner.close()
    assert sample.root.closed and sample.job._handle is None


@pytest.mark.skipif(sys.platform != "win32", reason="Actual private Windows Job custody")
def test_actual_owned_job_observation_binds_root_and_spawned_descendant(tmp_path):
    """Genuine native complete Job, including any interpreter intermediary."""
    # The selected executable does not establish a physical process count.
    executable = getattr(sys, "_base_executable", sys.executable)
    assert type(executable) is str and os.path.isabs(executable)
    ready = tmp_path / "owned-descendant.txt"
    code = ("import subprocess,sys,time,pathlib,os,json; "
            "p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(60)'],"
            "creationflags=0x08000000); q=pathlib.Path(sys.argv[1]); t=q.with_suffix('.tmp'); "
            "t.write_text(json.dumps({'runtime_pid':os.getpid(),'spawned_pid':p.pid,"
            "'executable':sys.executable}),encoding='ascii'); t.replace(q); time.sleep(60)")
    owner = child_jobs.launch_windows_child(
        [executable, "-I", "-B", "-c", code, str(ready)], dict(os.environ),
        cwd=str(tmp_path), deadline=time.monotonic() + 10, window="hidden")
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        assert ready.exists()
        assert ready.stat().st_size <= 4096
        fixture = json.loads(ready.read_text(encoding="ascii"))
        assert type(fixture) is dict and set(fixture) == {"runtime_pid", "spawned_pid", "executable"}
        assert all(type(fixture[key]) is int and 0 < fixture[key] <= 0xFFFFFFFF
                   for key in ("runtime_pid", "spawned_pid"))
        child_pid = fixture["spawned_pid"]
        output, errors = [], []
        def observe():
            try:
                output.append(owner.observe_owned_process_identities(role="test-child"))
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=observe)
        thread.start()
        thread.join(5)
        assert not thread.is_alive() and not errors
        rows = output[0]
        # Independent native query of the actual retained original Job. The
        # complete current kernel PID list, rather than an assumed executable
        # wrapper shape, is the expected set; no returned row is discarded.
        class JobIds(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("count", wintypes.DWORD),
                        ("pids", ctypes.c_size_t * 16)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        query = kernel.QueryInformationJobObject
        query.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                          wintypes.DWORD, wintypes.LPVOID]
        query.restype = wintypes.BOOL
        current = JobIds()
        with owner._handle_lock:
            assert owner._process is not None and owner._job._handle is not None
            assert query(int(owner._job._handle), 3, ctypes.byref(current), ctypes.sizeof(current), None)
        assert 1 <= current.assigned == current.count <= 16
        job_pids = tuple(current.pids[:current.count])
        (tmp_path / "native-owned-job-observation.json").write_text(json.dumps({
            "fixture_reported": fixture, "retained_root_pid": owner.pid,
            "selected_executable": executable, "native_job_pids": job_pids,
            "observed_identities": [asdict(row) for row in rows],
        }, sort_keys=True, indent=2), encoding="utf-8")
        assert len(job_pids) == len(set(job_pids)) == len(rows)
        assert {row.pid for row in rows} == set(job_pids)
        assert {owner.pid, child_pid, fixture["runtime_pid"]} <= set(job_pids)
        assert all(type(row) is OwnedProcessIdentity and row.fresh(time.monotonic()) for row in rows)
        assert all(row.expires_monotonic - row.observed_monotonic == 2 for row in rows)
        # Every member, including intermediaries, must also match a separately
        # acquired query-only native lease. PID/name equality is insufficient.
        for row in rows:
            with windows_process_lease.WindowsProcessLease(row.pid, row.create_time, row.image,
                                                          lifetime=1, query_only=True) as lease:
                assert lease.identity == ProcessObjectIdentity(row.pid, int(row.birth_ticks), row.image)
    finally:
        owner.terminate()
        owner.wait(timeout=5)
        owner.wait_tree(timeout=5)
        owner.close()
