"""Owned child/Job algorithms under an API model, plus separate real OS cells.

API-model tests execute actual classes with inert native tokens; they do not
prove actual Windows Job closure. The explicitly named native-OS cases launch
only harmless retained fixture server/runner Jobs and use actual kernel APIs.
No test discovers, starts or kills a real Ollama service.
"""
from __future__ import annotations

from collections import OrderedDict
import json
from pathlib import Path
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from test_child_job_owned_identities import (
    _Function, inert_child_factory as inert_child_factory,
)
from angerona.core.windows_process_lease import _Native as _RawProcessNative
from test_app_shutdown_drain import _app as drained_app
from test_app_owned_process_composition import (
    composition as composition, context as context, inert_owner as inert_owner,
)
from angerona.core import ollama_lifecycle as ollama
from angerona.core import windows_child_job as child_jobs
from angerona.telemetry.process_snapshot_worker import InventoryWorkerError


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows owned Ollama Job lifecycle")
_HOST = "http://127.0.0.1:11434"


class _TimeView:
    def __init__(self, actual, clock):
        self.actual, self.clock = actual, clock

    def __getattr__(self, name):
        return getattr(self.actual, name)

    def monotonic(self):
        return self.clock[0]

    def sleep(self, seconds):
        assert 0 <= seconds <= 1
        self.clock[0] += seconds


class _RetirementKernel:
    """Local kernel API model; real guard/wait/identity methods still execute.

    Associated Job entries and signaled process objects are independent facts.
    No opaque token below is ever passed to an actual Windows function.
    """

    def __init__(self, native, transport, clock):
        self.native, self.transport, self.clock = native, transport, clock
        self.original_members = native.api.QueryInformationJobObject
        self.original_contains, self.original_wait = native.api.IsProcessInJob, native.wait
        self.bound_models = {}
        self.waits = []
        native.api.QueryInformationJobObject = _Function(self.query)
        native.api.IsProcessInJob = _Function(self.contains)
        native.api.GetProcessId = _Function(self.process_id)
        native.api.GetProcessTimes = _Function(self.process_times)
        native.api.WaitForSingleObject = _Function(self.wait)
        native.object_identity = lambda handle: _RawProcessNative.object_identity(native, handle)
        native.wait = lambda handle, milliseconds: _RawProcessNative.wait(native, handle, milliseconds)
        native._error = lambda operation: _RawProcessNative._error(native, operation)

    def process(self, handle):
        handle = int(handle)
        assert handle not in self.native.closed, "A closed query handle was used"
        kind, pid = self.native.handles[handle]
        assert kind == "process"
        return pid

    def job(self, handle):
        handle = int(handle)
        assert handle not in self.native.closed, "A closed Job query was used"
        kind, model = self.native.handles[handle]
        assert kind == "job"
        return model

    def bind(self, sample):
        model = sample.model
        assert id(model) not in self.bound_models
        self.bound_models[id(model)] = model
        model.retirement_total = len(set(sample.members[0]))
        model.retirement_assigned = frozenset(sample.members[0])
        model.retirement_dispatched = False
        model.retirement_roster = ()
        model.retirement_active_override = None
        model.retirement_signal_at = {}
        model.retirement_wait_codes = {}

    def current(self, model):
        if model.retirement_dispatched:
            return tuple(model.retirement_roster)
        return tuple(pid for pid in model.members[-1] if pid not in self.native.exited)

    def accounting(self, model):
        assert self.bound_models.get(id(model)) is model
        self.native.event("retirement-accounting", model.token)
        active = self.current(model)
        self.transport.events.append(("job-accounting", active))
        self.transport.accounting.append(active)
        count = len(active) if model.retirement_active_override is None else model.retirement_active_override
        return model.retirement_total, count

    def query(self, handle, information, output, size, returned):
        model = self.job(handle)
        if self.bound_models.get(id(model)) is not model:
            return self.original_members(handle, information, output, size, returned)
        if information == 3:
            result = self.original_members(handle, information, output, size, returned)
            value = output._obj
            if result and model.assigned is None and model.count is None:
                original = tuple(int(pid) for pid in value.pids[:value.count])
                members = (self.current(model) if model.retirement_dispatched else
                           tuple(pid for pid in original if pid not in self.native.exited))
                assert len(members) <= 16
                value.assigned = value.count = len(members)
                for index in range(16):
                    value.pids[index] = members[index] if index < len(members) else 0
            return result
        assert information == 1 and returned is None
        value = output._obj
        assert [name for name, _type in value._fields_] == [
            "user", "kernel", "period_user", "period_kernel", "faults", "total", "active", "terminated"]
        assert size == self.native.ctypes.sizeof(value)
        value.total, value.active = self.accounting(model)
        return True

    def contains(self, process, job, output):
        pid, model = self.process(process), self.job(job)
        if self.bound_models.get(id(model)) is not model:
            return self.original_contains(process, job, output)
        self.native.event("contains", pid)
        output._obj.value = pid in model.retirement_assigned and pid not in self.native.nonmembers
        return True

    def process_id(self, handle):
        pid = self.process(handle)
        self.native.event("object-pid", pid)
        return pid

    def process_times(self, handle, created, exited, kernel, user):
        pid = self.process(handle)
        self.native.event("object-birth", pid)
        birth = self.native.identities[pid].birth_ticks
        created._obj.dwLowDateTime, created._obj.dwHighDateTime = birth & 0xffffffff, birth >> 32
        return True

    def wait(self, handle, milliseconds):
        pid = self.process(handle)
        models = [model for model in self.bound_models.values() if pid in model.retirement_assigned]
        if not models:
            return 0 if self.original_wait(handle, milliseconds) else 258
        assert len(models) == 1, "Ambiguous local process/Job model"
        model = models[0]
        assert type(milliseconds) is int and 0 <= milliseconds <= 5000
        self.native.event("wait", pid)
        self.waits.append((int(handle), pid, milliseconds, self.clock[0]))
        if pid in model.retirement_wait_codes:
            return model.retirement_wait_codes[pid]
        if pid in self.native.exited:
            return 0
        if milliseconds:
            end = self.clock[0] + milliseconds / 1000
            signal = model.retirement_signal_at.get(pid)
            if signal is not None and self.clock[0] <= signal <= end:
                self.clock[0] = signal
                self.native.exited.add(pid)
                return 0
            self.clock[0] = end
        return 258


class _JobTransport:
    def __init__(self, native, clock):
        self.native, self.events, self.accounting = native, [], []
        self.stubborn = set()
        self.current = object()
        self.kernel = _RetirementKernel(native, self, clock)

    def process(self, handle):
        assert handle is not None and int(handle) != 0, "A closed/absent process handle was used"
        kind, pid, lifetime = self.native.lifetimes[int(handle)]
        assert kind == "process" and lifetime is handle and not handle.closed
        return pid

    def poll(self, handle):
        pid = self.process(handle)
        self.events.append(("poll", pid))
        return 0 if pid in self.native.exited else 259

    def duplicate(self, current, handle, target, rights, inherit, options):
        assert current is target is self.current
        assert (rights, inherit, options) == (0, False, 2)
        pid = self.process(handle)
        self.events.append(("duplicate-wait", pid))
        retained = self.native.lifetime("process", pid)
        actual_close = retained.Close

        def close():
            self.events.append(("close-wait", pid))
            actual_close()

        retained.Close = close
        return retained

    def wait(self, handle, milliseconds):
        assert 0 <= milliseconds <= 5000
        pid = self.process(handle)
        self.events.append(("wait-root", pid))
        return 0 if pid in self.native.exited else 258

    def bind(self, sample):
        self.kernel.bind(sample)
        actual_terminate = sample.job._api.TerminateJobObject

        def terminate(handle, code):
            assert handle is not None and not handle.closed
            self.events.append(("terminate-job", sample.owner.pid))
            actual_terminate(handle, code)
            self.native.exited.difference_update(self.stubborn)
            self.native.exited.difference_update(sample.model.retirement_signal_at)
            sample.model.retirement_dispatched = True

        def accounting(handle, information):
            assert handle is not None and handle is sample.job._handle and not handle.closed
            assert information == 1
            total, active = self.kernel.accounting(sample.model)
            return {"TotalProcesses": total, "ActiveProcesses": active}

        sample.job._api = SimpleNamespace(TerminateJobObject=terminate,
            JobObjectBasicAccountingInformation=1, QueryInformationJobObject=accounting)
        for name, handle in (("job", sample.job._handle), ("process", sample.root)):
            actual_close = handle.Close

            def close(actual_close=actual_close, name=name):
                self.events.append(("close-" + name, sample.owner.pid))
                actual_close()

            handle.Close = close
        return sample


@pytest.fixture
def owned(inert_child_factory, monkeypatch):
    native, clock = inert_child_factory.native, inert_child_factory.clock
    transport = _JobTransport(native, clock)
    monkeypatch.setattr(child_jobs, "time", _TimeView(ollama.time, clock))
    monkeypatch.setattr(ollama, "time", _TimeView(ollama.time, clock))
    monkeypatch.setattr(child_jobs, "_OWNED_TREE_RETIREMENTS", [])
    monkeypatch.setattr(ollama, "_owned_services", {})
    monkeypatch.setattr(ollama, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(ollama, "_startup_lock", threading.RLock())
    monkeypatch.setattr(ollama, "_owned_stop_lock", threading.RLock())
    monkeypatch.setattr(ollama, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(ollama, "_ai_shutdown", threading.Event())
    monkeypatch.setattr(ollama, "_owned_epoch", 0)
    monkeypatch.setattr(ollama, "_retirement_registry", None)
    monkeypatch.setattr(ollama, "_retirement_epoch", -1)
    monkeypatch.setattr(ollama, "_retirement_publication", {"schema": 1,
        "state": "not-requested", "complete": False, "pending_owned": 0,
        "launch_quiescent": False, "records": ()})
    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE", raising=False)
    monkeypatch.delenv("ANGERONA_CHILL_AI_BLOCKED", raising=False)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(
        GetCurrentProcess=lambda: transport.current, DuplicateHandle=transport.duplicate))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(DUPLICATE_SAME_ACCESS=2))
    monkeypatch.setitem(sys.modules, "win32event", SimpleNamespace(
        INFINITE=0xffffffff, WAIT_TIMEOUT=258, WaitForSingleObject=transport.wait))
    monkeypatch.setitem(sys.modules, "win32process", SimpleNamespace(GetExitCodeProcess=transport.poll))

    lifecycle_calls = {}
    for label in ("terminate", "wait", "wait_tree", "close"):
        actual = getattr(child_jobs.OwnedWindowsChild, label)

        def invoke(child, *args, _label=label, _actual=actual, **kwargs):
            if child in lifecycle_calls:
                lifecycle_calls[child].append((_label, child._process is None,
                                                child._job._handle is None))
            return _actual(child, *args, **kwargs)

        monkeypatch.setattr(child_jobs.OwnedWindowsChild, label, invoke)

    def make(pids=(7001, 7002), *, register=True):
        sample = transport.bind(inert_child_factory(pids))
        sample.key = (_HOST, id(sample.owner))
        sample.job_lifetime = sample.job._handle
        sample.lifecycle_calls = lifecycle_calls[sample.owner] = []
        if register:
            with ollama._startup_lock:
                ollama._owned_services[sample.key] = sample.owner
        return sample

    result = SimpleNamespace(make=make, transport=transport, native=native, clock=clock, kernel=transport.kernel)
    yield result
    assert len(native.closed) == len(set(native.closed)), "A query close was retried"



def _background(function):
    result, errors = [], []

    def run():
        try:
            result.append(function())
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run, name="actual-owned-ai-native-scope")
    worker.start()
    worker.join(5.0)
    assert not worker.is_alive(), "The bounded actual native scope did not retire"
    if errors:
        raise errors[0]
    assert len(result) == 1
    return result[0]


def _identity_rows(sample):
    return _background(lambda: ollama.observe_owned_ollama_process_identities(timeout=1.0))


def _assert_closed(sample, transport):
    assert sample.model.termination_calls
    assert transport.accounting and transport.accounting[-1] == ()
    labels = [row[0] for row in sample.lifecycle_calls]
    assert labels == ["terminate", "wait", "wait_tree", "close"]
    events = [row[0] for row in transport.events]
    assert events.index("terminate-job") < events.index("wait-root")
    assert events.index("job-accounting") < events.index("close-job")
    assert sample.job_lifetime.closed and sample.job_lifetime.closes == 1
    assert sample.root.closed and sample.root.closes == 1
    assert sample.owner._process is None and sample.job._handle is None
    assert sample.key not in ollama._owned_services


@pytest.mark.parametrize("server_exited", [False, True])
def test_actual_job_zero_is_required_even_after_server_exit(owned, server_exited):
    sample = owned.make()
    before = _identity_rows(sample)
    assert {row.pid for row in before} == set(sample.members[-1])
    for row in before:
        expected = owned.native.identities[row.pid]
        assert str(row.birth_ticks) == str(expected.birth_ticks)
        assert os.path.normcase(os.path.normpath(row.image)) == os.path.normcase(os.path.normpath(expected.image))
    if server_exited:
        owned.native.exited.add(sample.owner.pid)
        assert sample.members[-1][1] not in owned.native.exited
    outcome = ollama.stop_owned_ollama_services(timeout=1.0)
    assert outcome["schema"] == 1 and outcome["state"] == "retired"
    assert outcome["complete"] is True and outcome["pending_owned"] == 0
    assert outcome["launch_quiescent"] is True and len(outcome["records"]) == 1
    row = outcome["records"][0]
    assert row["service_exited"] and row["job_empty"] and row["handles_closed"]
    assert not row["close_held"]
    if not server_exited:
        historical = {item["pid"]: item for item in row["identities"]}
        assert set(historical) == set(sample.members[-1])
        for observed in before:
            assert historical[observed.pid] == {"pid": observed.pid,
                "birth_ticks": observed.birth_ticks, "image": observed.image}
    _assert_closed(sample, owned.transport)


def test_live_runner_job_timeout_keeps_registry_and_can_retire_after_actual_job_zero(owned):
    sample = owned.make()
    runner = sample.members[-1][1]
    owned.transport.stubborn.add(runner)
    outcome = ollama.stop_owned_ollama_services(timeout=0.1)
    assert outcome["state"] == "incomplete" and outcome["complete"] is False
    assert outcome["pending_owned"] == 1 and ollama._owned_services[sample.key] is sample.owner
    assert owned.transport.accounting and all(runner in row for row in owned.transport.accounting)
    row = outcome["records"][0]
    assert row["service_exited"] is True and row["job_empty"] is False
    assert row["handles_closed"] is False and row["error_type"] == "TimeoutExpired"
    assert not sample.job_lifetime.closed and not sample.root.closed
    assert not any(label == "close" for label, _process, _job in sample.lifecycle_calls)
    owned.transport.stubborn.clear()
    owned.native.exited.add(runner)
    result = ollama.stop_owned_ollama_services(timeout=1.0)
    assert result["complete"] is True and result["pending_owned"] == 0
    assert owned.transport.accounting[-1] == ()
    assert sample.job_lifetime.closes == sample.root.closes == 1
    assert sample.key not in ollama._owned_services


@pytest.mark.parametrize("which", ["job", "process"])
def test_actual_close_then_lost_ack_is_sticky_without_retry_on_none_handles(owned, which):
    sample = owned.make()
    lifetime = sample.job_lifetime if which == "job" else sample.root
    actual = lifetime.Close
    failure = OSError("inert native close completed but acknowledgement was lost")
    attempts = []

    def close():
        attempts.append(which)
        actual()
        raise failure

    lifetime.Close = close
    outcome = ollama.stop_owned_ollama_services(timeout=1.0)
    assert outcome["complete"] is False and outcome["pending_owned"] == 1
    row = outcome["records"][0]
    assert row["service_exited"] and row["job_empty"] and row["close_held"]
    assert not row["handles_closed"] and row["error_type"] == "OSError"
    assert lifetime.closed and lifetime.closes == 1 and attempts == [which]
    assert ollama._owned_services[sample.key] is sample.owner
    custody = sample.owner._angerona_ollama_retirement["close_custody"]
    assert custody == (sample.root, sample.job, sample.job_lifetime)
    before = list(sample.lifecycle_calls), list(owned.transport.events)
    # Mutating a detached report cannot clear actual native close uncertainty.
    outcome["complete"], outcome["pending_owned"] = True, 0
    repeated = ollama.stop_owned_ollama_services(timeout=1.0)
    assert repeated["complete"] is False and repeated["pending_owned"] == 1
    assert (sample.lifecycle_calls, owned.transport.events) == before
    assert attempts == [which] and lifetime.closes == 1
    ollama.begin_ollama_shutdown()
    assert ollama.owned_ollama_retirement_proven() is False


@pytest.mark.parametrize("change", ["replacement", "pending-start", "launch-inflight", "stop"])
def test_scope_holds_registry_or_admission_change_without_partial_rows(owned, change):
    sample = owned.make()
    captured = ollama.capture_owned_ollama_process_scope(timeout=1.0)
    held_lock = False
    if change == "replacement":
        other = owned.make((7101, 7102), register=False)
        ollama._owned_services[sample.key] = other.owner
    elif change == "pending-start":
        ollama._startup_attempts[_HOST] = ollama._StartupAttempt()
    elif change == "launch-inflight":
        assert ollama._startup_launch_lock.acquire(blocking=False)
        held_lock = True
    else:
        ollama.begin_ollama_shutdown()
    before = list(owned.native.calls)
    try:
        with pytest.raises(InventoryWorkerError):
            _background(lambda: ollama.observe_owned_ollama_process_identities(
                captured=captured, timeout=1.0))
        assert owned.native.calls == before
    finally:
        if held_lock:
            ollama._startup_launch_lock.release()


def test_unsupported_adapter_claims_cannot_substitute_for_real_owned_job(owned):
    calls = []
    adapter = SimpleNamespace(pid=7301, owns_descendants=True,
        poll=lambda: 0, terminate=lambda: calls.append("terminate"),
        wait=lambda **_kwargs: 0, wait_tree=lambda **_kwargs: None,
        close=lambda: calls.append("close"))
    key = (_HOST, id(adapter))
    ollama._owned_services[key] = adapter
    with pytest.raises(InventoryWorkerError, match="unsupported"):
        ollama.capture_owned_ollama_process_scope(timeout=1.0)
    outcome = ollama.stop_owned_ollama_services(timeout=0.1)
    assert outcome["complete"] is False and outcome["pending_owned"] == 1
    row = outcome["records"][0]
    assert row["service_exited"] is True and row["job_empty"] is False
    assert row["error_type"] == "UnsupportedOwnedDescendantCoverage"
    assert ollama._owned_services[key] is adapter and "close" not in calls


def test_shared_listener_metadata_never_enrolls_or_terminates_an_unregistered_child(owned, monkeypatch):
    shared = owned.make((7401, 7402), register=False)

    def discovery(*_args, **_kwargs):
        pytest.fail("STOP attempted broad listener discovery to create ownership")

    monkeypatch.setattr(ollama, "_ollama_listener_pids", discovery)
    outcome = ollama.stop_owned_ollama_services(timeout=0.1)
    assert outcome["complete"] is True and outcome["records"] == ()
    assert not shared.model.termination_calls and not shared.root.closed
    assert not shared.job_lifetime.closed and not shared.lifecycle_calls
    assert _background(lambda: ollama.observe_owned_ollama_process_identities(timeout=1.0)) == ()


def test_shutdown_returns_unloaded_models_only_after_real_job_retirement(owned, monkeypatch):
    sample = owned.make()
    models = ["llama3:latest", "reviewed-model:latest"]
    calls = []

    def unload(host, model, *, timeout):
        calls.append((host, model, timeout))
        return list(models)

    monkeypatch.setattr(ollama, "unload_angerona_models", unload)
    result = ollama.shutdown_ollama(_HOST, "llama3", timeout=1.0)
    assert result == models and calls and 0 < calls[0][2] <= 1.0
    assert ollama.owned_ollama_retirement_proven() is True
    assert ollama.ollama_retirement_snapshot()["complete"] is True
    _assert_closed(sample, owned.transport)


def test_unload_error_cannot_mask_incomplete_actual_owned_job(owned, monkeypatch):
    sample = owned.make()
    owned.transport.stubborn.add(sample.members[-1][1])
    failure = OSError("inert unexpected unload transport failure")

    def unload(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(ollama, "unload_angerona_models", unload)
    with pytest.raises(ollama.OllamaRetirementIncomplete) as result:
        ollama.shutdown_ollama(_HOST, "llama3", timeout=0.1)
    assert result.value.__cause__ is failure
    assert result.value.outcome["complete"] is False
    assert result.value.outcome["pending_owned"] == 1
    assert ollama._owned_services[sample.key] is sample.owner
    assert not sample.root.closed and not sample.job_lifetime.closed
    assert ollama.owned_ollama_retirement_proven() is False



def test_late_launch_after_terminal_fence_retires_actual_job_and_cannot_be_ready(owned, monkeypatch):
    sample = owned.make(register=False)
    admitted, release = threading.Event(), threading.Event()
    attempt = ollama._StartupAttempt()
    ollama._startup_attempts[_HOST] = attempt
    errors = []

    def spawn(_host, _deadline, *, verified):
        verified()  # Actual Full/STOP admission ran before the parked launch.
        admitted.set()
        assert release.wait(8.0)
        return sample.owner

    def run():
        try:
            ollama._run_startup(_HOST, attempt, timeout=2.0)
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(ollama, "_spawn_ollama_service", spawn)
    monkeypatch.setattr(ollama, "_startup_port_present", lambda _host: False)
    monkeypatch.setattr(ollama, "unload_angerona_models", lambda *_a, **_k: [])
    worker = threading.Thread(target=run, name="actual-late-owned-ai-launch")
    worker.start()
    try:
        assert admitted.wait(8.0)
        with pytest.raises(ollama.OllamaRetirementIncomplete) as result:
            ollama.shutdown_ollama(_HOST, "llama3", timeout=0.05)
        assert result.value.outcome["launch_quiescent"] is False
        assert ollama.owned_ollama_retirement_proven() is False
    finally:
        release.set()
        worker.join(8.0)
    assert not worker.is_alive() and errors == []
    assert attempt.done.is_set() and attempt.status.daemon_ready is False
    assert attempt.status.state == "blocked"
    assert ollama._owned_services == {} and ollama.owned_ollama_retirement_proven() is True
    _assert_closed(sample, owned.transport)


def test_app_finishes_other_cleanup_then_typed_failure_reaches_existing_coordinator(
    owned, monkeypatch, tmp_path
):
    from PySide6.QtCore import QObject
    from PySide6.QtWidgets import QApplication
    from angerona.gui.shutdown_retirement import ShutdownRetirement

    sample = owned.make()
    owned.transport.stubborn.add(sample.members[-1][1])
    monkeypatch.setattr(ollama, "unload_angerona_models", lambda *_a, **_k: [])
    app = drained_app(True, True)
    app.config.data_dir = tmp_path / "private-app-data"
    app.config.data_dir.mkdir(mode=0o700)
    stopped = []
    app.manager.stop_all = lambda: stopped.append("modules")
    qt = QApplication.instance() or QApplication([])
    parent, finished = QObject(), []
    coordinator = ShutdownRetirement(parent, workers=lambda: (), cleanup=app.shutdown,
        finish=finished.append, data_root=tmp_path / "operator-diagnostic", timeout=3.0)
    try:
        assert coordinator.start() is True
        deadline = time.monotonic() + 8.0
        while not finished and time.monotonic() < deadline:
            qt.processEvents()
            coordinator.poll()
            threading.Event().wait(0.01)
        assert len(finished) == 1
        final = finished[0]
        assert final["state"] == "forced-incomplete" and final["forced"] is True
        assert final["cleanup_error"] == "OllamaRetirementIncomplete"
        assert final["pending_custody"] == []  # No new all-before-cleanup gate.
        assert app.reporter.called and app.flight_recorder_worker.called and app.evidence_ingestion.called
        assert app.storage.closed and app.evidence_store.closed and stopped == ["modules"]
        assert app._critical_ai_done is False
        assert app._critical_ai_outcome["complete"] is False
        assert app._critical_ai_diagnostic_saved is True
        assert ollama._owned_services[sample.key] is sample.owner
        assert not sample.job_lifetime.closed and not sample.root.closed
        assert ollama.owned_ollama_retirement_proven() is False
    finally:
        coordinator._timer.stop()
        for thread in (coordinator._cleanup_thread, coordinator._diagnostic_thread):
            if thread is not None:
                thread.join(8.0)
                assert not thread.is_alive()



@pytest.mark.parametrize("change", ["stable", "epoch-during-inventory", "pending-during-inventory"])
def test_actual_app_supplier_includes_ai_job_and_holds_whole_inventory_race(
    owned, composition, monkeypatch, change
):
    ai = owned.make()
    rows = _background(composition.app._owned_process_identities_for_response)
    expected = {os.getpid(), 1001, 1002, 1003, 2001, 2002, 2101, 2201, *ai.members[-1]}
    assert {row.pid for row in rows} == expected
    observed = {row.pid: row for row in rows if row.role == "local-ai"}
    assert set(observed) == set(ai.members[-1])
    for pid, row in observed.items():
        identity = owned.native.identities[pid]
        assert str(row.birth_ticks) == str(identity.birth_ticks)
        assert os.path.normcase(os.path.normpath(row.image)) == os.path.normcase(os.path.normpath(identity.image))
    assert composition.native.opened and composition.inventory_context.native.opened
    assert not ai.lifecycle_calls
    if change == "stable":
        return
    actual = composition.provider.observe_owned_process_identities
    reached = []
    before = len(composition.inventory_context.native.opened)

    def inventory(**kwargs):
        result = actual(**kwargs)  # Actual provider/native membership runs first.
        reached.append(True)
        with ollama._startup_lock:
            if change == "epoch-during-inventory":
                ollama._owned_epoch += 1
            else:
                ollama._startup_attempts[_HOST] = ollama._StartupAttempt()
        return result

    monkeypatch.setattr(composition.provider, "observe_owned_process_identities", inventory)
    with pytest.raises(InventoryWorkerError, match="Owned AI"):
        _background(composition.app._owned_process_identities_for_response)
    assert reached == [True] and len(composition.inventory_context.native.opened) > before
    assert ollama._owned_services[ai.key] is ai.owner and not ai.lifecycle_calls


def _native_registry(monkeypatch):
    # These are ordinary isolated Python control records. Native APIs and every
    # OwnedWindowsChild/WindowsChildJob implementation remain unmodified.
    monkeypatch.setattr(ollama, "_owned_services", {})
    monkeypatch.setattr(ollama, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(ollama, "_startup_lock", threading.RLock())
    monkeypatch.setattr(ollama, "_owned_stop_lock", threading.RLock())
    monkeypatch.setattr(ollama, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(ollama, "_ai_shutdown", threading.Event())
    monkeypatch.setattr(ollama, "_owned_epoch", 0)
    monkeypatch.setattr(ollama, "_retirement_registry", None)
    monkeypatch.setattr(ollama, "_retirement_epoch", -1)
    monkeypatch.setattr(ollama, "_retirement_publication", {"schema": 1,
        "state": "not-requested", "complete": False, "pending_owned": 0,
        "launch_quiescent": False, "records": ()})
    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE", raising=False)
    monkeypatch.delenv("ANGERONA_CHILL_AI_BLOCKED", raising=False)
    monkeypatch.setattr(ollama, "unload_angerona_models", lambda *_a, **_k: [])


def _wait_native_report(path, runner_report, child):
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_bytes())
            ready = runner_report.read_text(encoding="ascii")
            if not ready.endswith("\n"):
                raise ValueError("Runner readiness record is incomplete")
            runner_pid = int(ready)
        except (FileNotFoundError, UnicodeError, ValueError):
            pass
        else:
            assert set(value) == {"runtime_pid", "runner_pid"}
            assert all(type(pid) is int and pid > 0 for pid in value.values())
            assert runner_pid > 0
            return value, runner_pid
        assert child.poll() is None, "Harmless native fixture exited before its identity report"
        threading.Event().wait(0.01)
    pytest.fail("Harmless native fixture did not publish its bounded identity report")


@pytest.mark.parametrize("server_exited", [False, True])
def test_native_os_lifecycle_retires_harmless_server_runner_and_preserves_unrelated_job(
    tmp_path, monkeypatch, server_exited
):
    import win32api
    import win32event
    import win32job

    _native_registry(monkeypatch)
    executable = Path(getattr(sys, "_base_executable", sys.executable))
    assert executable.is_absolute() and executable.is_file()
    environment = {name: os.environ[name] for name in ("SystemRoot", "WINDIR") if name in os.environ}
    assert "SystemRoot" in environment
    environment.update(TEMP=str(tmp_path), TMP=str(tmp_path))
    assert not any(name.upper().startswith("ANGERONA_") for name in environment)
    report, release = tmp_path / "server-report.json", tmp_path / "exit-server"
    runner_report = tmp_path / "runner-ready.pid"
    runner_code = (
        "import os,pathlib,time\n"
        f"pathlib.Path({str(runner_report)!r}).write_text(str(os.getpid())+'\\n', encoding='ascii')\n"
        "time.sleep(30)"
    )
    script = tmp_path / "harmless-owned-server.py"
    script.write_text(
        "import json,os,pathlib,subprocess,time\n"
        f"runner=subprocess.Popen([{str(executable)!r},'-I','-B','-c',{runner_code!r}],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
        "creationflags=subprocess.CREATE_NO_WINDOW)\n"
        f"pathlib.Path({str(report)!r}).write_text(json.dumps({{'runtime_pid':os.getpid(),'runner_pid':runner.pid}}))\n"
        "deadline=time.monotonic()+30\n"
        f"while time.monotonic()<deadline and not pathlib.Path({str(release)!r}).exists():time.sleep(.02)\n",
        encoding="utf-8",
    )
    server = unrelated = None
    observed_handles = []
    console_hosts = {}
    checked = []
    source_close_started = False
    close_native_values = {"wait_results": [], "active_processes": None}
    actual_close = child_jobs.OwnedWindowsChild.close
    try:
        unrelated = child_jobs.launch_windows_child(
            [str(executable), "-I", "-B", "-c", "import time;time.sleep(30)"],
            environment, cwd=str(tmp_path), deadline=time.monotonic() + 10.0,
        )
        server = child_jobs.launch_windows_child(
            [str(executable), "-I", "-B", str(script)], environment,
            cwd=str(tmp_path), deadline=time.monotonic() + 10.0,
        )
        identity, runner_pid = _wait_native_report(report, runner_report, server)
        key = (_HOST, id(server))
        with ollama._startup_lock:
            ollama._owned_services[key] = server
        try:
            rows = _background(lambda: ollama.observe_owned_ollama_process_identities(timeout=1.0))
        except child_jobs.NativeOwnershipObservationError as error:
            if str(error) != "Child Job membership changed":
                raise
            # A native membership transition supplies no rows. Re-observe
            # the same retained Job once before setting retirement expectations.
            rows = _background(lambda: ollama.observe_owned_ollama_process_identities(timeout=1.0))
        native_pids = {row.pid for row in rows}
        expected_pids = (server.pid, identity["runner_pid"], runner_pid, identity["runtime_pid"])
        assert set(expected_pids).issubset(native_pids)
        assert unrelated.pid not in native_pids
        assert all(int(row.birth_ticks) > 0 and Path(row.image).is_absolute() for row in rows)
        for pid in dict.fromkeys(expected_pids):
            handle = win32api.OpenProcess(0x00101000, False, pid)
            observed_handles.append(handle)
            assert win32event.WaitForSingleObject(handle, 0) == win32event.WAIT_TIMEOUT
        if server_exited:
            import psutil

            # The server's own console host leaves the Job a few milliseconds
            # after the server. Hold that exact member (its PID cannot be
            # reused) and let it leave before the retirement cut is taken.
            for pid in sorted(native_pids - set(expected_pids)):
                if psutil.Process(pid).ppid() == server.pid:
                    console_hosts[pid] = win32api.OpenProcess(0x00100000, False, pid)
            release.write_bytes(b"exit only this harmless fixture server")
            assert type(server.wait(timeout=8.0)) is int
            assert type(server.poll()) is int
            settled = time.monotonic() + 5.0
            while console_hosts.keys() & set(win32job.QueryInformationJobObject(
                    server._job._handle, win32job.JobObjectBasicProcessIdList)):
                assert time.monotonic() < settled, "Exited server's console host stayed in the Job"
                threading.Event().wait(0.005)
            assert win32event.WaitForSingleObject(observed_handles[1], 0) == win32event.WAIT_TIMEOUT
            accounting = win32job.QueryInformationJobObject(server._job._handle,
                win32job.JobObjectBasicAccountingInformation)
            assert accounting["ActiveProcesses"] >= 1

        def close(child):
            nonlocal source_close_started
            if child is server:
                def observed_exit(handle):
                    value = win32event.WaitForSingleObject(handle, 0)
                    close_native_values["wait_results"].append(value)
                    return value == win32event.WAIT_OBJECT_0

                # Record only results of the original short-circuit queries.
                assert all(observed_exit(handle) for handle in observed_handles)
                accounting = win32job.QueryInformationJobObject(child._job._handle,
                    win32job.JobObjectBasicAccountingInformation)
                close_native_values["active_processes"] = accounting["ActiveProcesses"]
                assert accounting["ActiveProcesses"] == 0
                checked.append(("native-wait0", "native-Job0"))
                source_close_started = True
            return actual_close(child)

        # Keep the observer only while the explicit lifecycle close can run.
        # __del__ resolves self.close late; it must never inherit this callback
        # after the observed process/Job or query handles have been closed.
        with monkeypatch.context() as close_observer:
            close_observer.setattr(child_jobs.OwnedWindowsChild, "close", close)
            try:
                assert ollama.shutdown_ollama(_HOST, "synthetic-fixture", timeout=3.0) == []
            except ollama.OllamaRetirementIncomplete as error:
                # Evidence only: no extra native query, wait, retry or success.
                # JSON serialization detaches the existing outcome for stdout.
                try:
                    diagnostic = json.dumps({
                        "schema": "angerona.native-ai-fixture-retirement-diagnostic/v1",
                        "server_exited_before_shutdown": server_exited,
                        "outcome": error.outcome, "checked": checked,
                        "source_close_started": source_close_started,
                        "close_native_values": close_native_values,
                    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
                    if len(diagnostic) > 16384:
                        diagnostic = json.dumps({
                            "truncated": True, "diagnostic_ascii_bytes": len(diagnostic),
                            "diagnostic_prefix": diagnostic[:4096],
                        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                    print("NATIVE_AI_RETIREMENT_DIAGNOSTIC " + diagnostic, flush=True)
                except Exception:
                    pass  # Optional evidence failure cannot replace the real error.
                raise  # Preserve the SAME typed failure and its original traceback.
        assert child_jobs.OwnedWindowsChild.close is actual_close
        outcome = ollama.ollama_retirement_snapshot()
        assert outcome["state"] == "retired" and outcome["complete"] is True
        assert outcome["pending_owned"] == 0 and checked == [("native-wait0", "native-Job0")]
        assert len(outcome["records"]) == 1
        row = outcome["records"][0]
        assert row["service_exited"] and row["job_empty"] and row["handles_closed"]
        assert server._process is None and server._job._handle is None
        assert unrelated.poll() is None
        assert all(win32event.WaitForSingleObject(handle, 0) == win32event.WAIT_OBJECT_0
                   for handle in observed_handles)
        assert ollama.owned_ollama_retirement_proven() is True
    finally:
        # Failure cleanup remains limited to exact retained fixture owners.
        # Never retry an unknown source-close attempt or choose a process by PID.
        for child in (server, unrelated):
            if child is None or child._process is None or child._job._handle is None:
                continue
            if child is server and source_close_started:
                continue
            child.terminate()
            child.wait(timeout=5.0)
            child.wait_tree(timeout=5.0)
            actual_close(child)
        for handle in (*observed_handles, *console_hosts.values()):
            handle.Close()



@pytest.mark.parametrize("failure_at", ["app-snapshot", "writer-ack"])
@pytest.mark.parametrize("job_retired", [True, False])
def test_optional_ai_diagnostic_failure_preserves_other_cleanup_and_real_retirement_gate(
    owned, monkeypatch, tmp_path, failure_at, job_retired
):
    from angerona.core.startup_diagnostics import StartupDiagnostics

    sample = owned.make()
    if not job_retired:
        owned.transport.stubborn.add(sample.members[-1][1])
    monkeypatch.setattr(ollama, "unload_angerona_models", lambda *_a, **_k: [])
    app = drained_app(True, True)
    app.config.data_dir = tmp_path / "private-ai-diagnostic-fault"
    app.config.data_dir.mkdir(mode=0o700)
    cleanup, reached = [], []
    app._resilience = SimpleNamespace(stop=lambda **kwargs: cleanup.append(("resilience", kwargs)))
    app._runtime_healer = SimpleNamespace(stop=lambda: cleanup.append(("healer", {})))
    app.manager.stop_all = lambda: cleanup.append(("modules", {}))
    failure = OSError("inert optional diagnostic acknowledgement failure")
    if failure_at == "app-snapshot":
        actual = ollama.ollama_retirement_snapshot
        callers = {type(app)._record_ai_retirement_outcome.__code__, type(app)._shutdown_owned.__code__}

        def snapshot():
            # Only the App's optional reads fail. Core native stop/publication
            # reads still execute unchanged and cannot be replaced by a stub.
            if sys._getframe(1).f_code in callers:
                reached.append("snapshot")
                raise failure
            return actual()

        monkeypatch.setattr(ollama, "ollama_retirement_snapshot", snapshot)
    else:
        actual = StartupDiagnostics.record

        def record(writer, *args, **kwargs):
            # Real private writer succeeds first; simulate only lost ack. The
            # App must truthfully mark persistence unknown and keep cleaning up.
            assert actual(writer, *args, **kwargs) is True
            reached.append(writer.path)
            raise failure

        monkeypatch.setattr(StartupDiagnostics, "record", record)
    if job_retired:
        app.shutdown()
        assert ollama.owned_ollama_retirement_proven() is True
        assert sample.key not in ollama._owned_services
        assert sample.root.closed and sample.job_lifetime.closed
        assert owned.transport.accounting[-1] == ()
    else:
        with pytest.raises(ollama.OllamaRetirementIncomplete) as result:
            app.shutdown()
        assert result.value.outcome["state"] == "incomplete"
        assert result.value.outcome["complete"] is False
        if failure_at == "app-snapshot":
            assert result.value.__cause__ is failure
            assert result.value.outcome["diagnostic_error_type"] == "OSError"
            assert "records" not in result.value.outcome  # No invented native rows.
        assert ollama._owned_services[sample.key] is sample.owner
        assert not sample.root.closed and not sample.job_lifetime.closed
        assert ollama.owned_ollama_retirement_proven() is False
    assert reached and app._critical_ai_diagnostic_saved is False
    assert app._critical_ai_diagnostic_error_type == "OSError"
    assert {name for name, _kwargs in cleanup} == {"resilience", "healer", "modules"}
    assert all(kwargs == {"terminate_children": True} for name, kwargs in cleanup if name == "resilience")
    assert app.reporter.called and app.flight_recorder_worker.called and app.evidence_ingestion.called
    assert app.storage.closed and app.evidence_store.closed



@pytest.mark.parametrize("preheld", [False, True])
@pytest.mark.parametrize("failure_at", ["owned-stop", "final-publisher"])
def test_mandatory_retirement_backend_failure_releases_only_acquired_lock_and_keeps_job(
    owned, monkeypatch, failure_at, preheld
):
    sample = owned.make()
    runner = sample.members[-1][1]
    owned.transport.stubborn.add(runner)
    monkeypatch.setattr(ollama, "unload_angerona_models", lambda *_a, **_k: [])
    failure = OSError("inert mandatory retirement backend failure after actual attempt")
    reached = []
    if failure_at == "owned-stop":
        actual = ollama.stop_owned_ollama_services

        def stop(*args, **kwargs):
            outcome = actual(*args, **kwargs)
            assert outcome["complete"] is False and outcome["pending_owned"] == 1
            reached.append("actual-owned-stop")
            raise failure

        monkeypatch.setattr(ollama, "stop_owned_ollama_services", stop)
    else:
        actual = ollama._publish_retirement
        final_code = ollama.shutdown_ollama.__code__

        def publish(*args, **kwargs):
            outcome = actual(*args, **kwargs)
            # The stop helper's publisher stays real. Only the final mandatory
            # shutdown publication loses acknowledgement after its actual work.
            if sys._getframe(1).f_code is final_code:
                assert outcome["complete"] is False and outcome["pending_owned"] == 1
                reached.append("actual-final-publisher")
                raise failure
            return outcome

        monkeypatch.setattr(ollama, "_publish_retirement", publish)
    launch_lock = ollama._startup_launch_lock
    if preheld:
        assert launch_lock.acquire(blocking=False)
    try:
        with pytest.raises(OSError) as result:
            ollama.shutdown_ollama(_HOST, "llama3", timeout=0.1)
        assert result.value is failure and len(reached) == 1
        assert launch_lock.locked() is preheld
        assert ollama._owned_services[sample.key] is sample.owner
        assert ollama.owned_ollama_retirement_proven() is False
        assert owned.transport.accounting and all(runner in row for row in owned.transport.accounting)
        assert not sample.root.closed and not sample.job_lifetime.closed
        assert not any(label == "close" for label, _process, _job in sample.lifecycle_calls)
    finally:
        if preheld and launch_lock.locked():
            launch_lock.release()  # Only the fixture releases its foreign hold.
