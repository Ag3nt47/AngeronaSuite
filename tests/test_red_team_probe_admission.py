"""Production probe preflight and bounded execution diagnostics, without OS work."""
from __future__ import annotations

import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from angerona.core.werfault_guard import (
    OwnedProcessIdentity, OwnedProcessReadError, read_owned_process_snapshot,
)
from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.gui import red_team_bridge as bridge_module
from angerona.gui.red_team_bridge import RedTeamToolOwner, ToolProbe
from angerona.modules import purple_guard
from angerona.shark import red_team, simulation_session
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.red_team_ipc import ToolProtocolError
from angerona.shark.simulation_session import PreparedRun


@pytest.fixture(autouse=True)
def no_host_dispatch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Probe admission fixtures cannot launch OS processes or network work")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def production_probe(tmp_path, monkeypatch):
    """Only issuer/native operations are inert; request and roster API are real."""
    base = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True))
    run_id = "redteam-" + "a" * 32
    token = "ANGERONA_REDTEAM_1234abcd"
    prepared = PreparedRun("b" * 32, run_id, "red_team", str(tmp_path), str(tmp_path),
        "{}", "c" * 64, (), 600, "d" * 64)
    lease = object.__new__(purple_guard.RedTeamValidationLease)
    engine = RedTeamEngine(tmp_path / "data", documents_dir=tmp_path / "target")
    active = {"key": "random_processes", "plan_step_id": "RTP1-C01-RANDOM_PROCESSES"}
    engine.run_id, engine._prepared_run, engine._validation_lease = run_id, prepared, lease
    engine._thread = threading.current_thread()
    engine._active_plan_entry, engine._expected_plan = active, [active]
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._ready.set()
    owner._job = object()
    owner._wrapper = SimpleNamespace(pid=1002, alive=lambda: True)
    owner._child = SimpleNamespace(pid=1003, alive=lambda: True)
    identity = ProcessObjectIdentity(4242, 134377029371751523, base)
    handle = object()
    released = []
    pin = SimpleNamespace(pid=identity.pid, birth=str(identity.birth_ticks), handle=handle,
        closed=False, alive=lambda: True, release_unadmitted=lambda: released.append("unadmitted"))
    events = []
    sample = SimpleNamespace(rows=tuple(OwnedProcessIdentity(pid, str(identity.birth_ticks + pid),
        (identity.birth_ticks + pid - 116444736000000000) / 10000000, base,
        "redteam-tool", 100., 102.) for pid in (1001, 1002, 1003)))

    def supplier():
        events.append("supplier")
        return sample.rows

    manager = SimpleNamespace(owned_process_identities=supplier)
    state = SimpleNamespace(lock=threading.RLock(), released=False, consumed=True,
        bound_run_id=run_id, manager=manager, process_challenges={token: {"state": "enrolled"}})

    def exact_state(supplied):
        assert supplied is lease
        return state

    def exact_prepared(supplied, *, kind=None):
        return supplied is prepared and kind == "red_team"

    def live_producers(supplied, *, run_id):
        assert supplied is lease and run_id == engine.run_id

    def native_pin(pid):
        assert pid == identity.pid
        events.append("native-pin")
        return pin

    def native_identity(supplied):
        assert supplied is handle
        return identity

    def native_member(supplied):
        events.append("native-membership")
        return supplied == identity

    clock_samples = []

    def clock():
        events.append("clock")
        value = 100. if not clock_samples else 100.25
        clock_samples.append(value)
        return value

    monkeypatch.setattr(purple_guard, "_lease_authority", exact_state)
    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "assert_live_producers", live_producers)
    monkeypatch.setattr(simulation_session, "validate_prepared_run", exact_prepared)
    monkeypatch.setattr(bridge_module, "_Pin", native_pin)
    # Simulate Windows without changing the process-global os module on POSIX CI.
    monkeypatch.setattr(bridge_module, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(bridge_module, "time", SimpleNamespace(monotonic=clock))
    from angerona.core import windows_process_lease
    monkeypatch.setattr(windows_process_lease, "_Native", lambda: SimpleNamespace(identity=native_identity))
    import psutil
    process = SimpleNamespace(ppid=lambda: 1003, exe=lambda: base,
        cmdline=lambda: [base, "-I", "-S", "-c", "import time; time.sleep(30)", token])

    def exact_process(pid):
        assert pid == identity.pid
        return process

    monkeypatch.setattr(psutil, "Process", exact_process)
    owner._native_owner = SimpleNamespace(contains_native_process=native_member)
    yield SimpleNamespace(owner=owner, engine=engine, token=token, prepared=prepared,
        lease=lease, sample=sample, identity=identity, pin=pin, events=events,
        clock_samples=clock_samples, released=released, base=base)
    owner._stop.set()


def test_production_start_probe_uses_real_required_post_supplier_clock(production_probe):
    sample = production_probe
    received = []
    failures = []

    def reply_once():
        try:
            kind, payload, reply_to, request, descriptor = sample.owner._queue.get(timeout=2)
        except queue.Empty:
            return
        try:
            assert kind == "start-probe" and reply_to == "" and descriptor is None
            assert payload["token"] == sample.token
            received.append(payload)
            request.result = dict(probe_id=payload["probe_id"], pid=sample.identity.pid,
                birth=str(sample.identity.birth_ticks))
            request.done.set()
        except BaseException as error:
            failures.append(type(error).__name__)
            request.failed = True
            request.done.set()
        finally:
            sample.owner._queue.task_done()

    worker = threading.Thread(target=reply_once, name="InertProbeReply", daemon=False)
    worker.start()
    try:
        probe = sample.owner.start_probe(sample.engine, sample.token)
    finally:
        worker.join(2.5)
    assert not worker.is_alive() and not failures
    assert type(probe) is ToolProbe and len(received) == 1
    assert probe.pid == sample.identity.pid and probe.record.identity == sample.identity
    assert sample.owner._probes[probe.record.probe_id] is probe.record
    assert probe.record.prepared is sample.prepared and probe.record.validation_lease is sample.lease
    assert sample.events == ["clock", "supplier", "clock", "native-pin", "native-membership"]
    assert sample.clock_samples == [100., 100.25]
    assert not sample.released and sample.owner._queue.empty()
    # No permissive function replacement can hide another missing keyword.
    import inspect
    assert inspect.signature(read_owned_process_snapshot).parameters["clock"].default is inspect.Parameter.empty


def test_production_start_probe_still_refuses_expired_roster_before_transport(production_probe):
    sample = production_probe
    old = sample.sample.rows[0]
    sample.sample.rows = (OwnedProcessIdentity(old.pid, old.birth_ticks, old.create_time,
        old.image, old.role, 95., 97.),)
    with pytest.raises(OwnedProcessReadError) as failure:
        sample.owner.start_probe(sample.engine, sample.token)
    assert failure.value.reason_code == "row_expired"
    assert sample.events == ["clock", "supplier", "clock"]
    assert sample.owner._queue.empty() and not sample.owner._probes


def test_production_start_probe_keeps_existing_two_slot_capacity_reserve(production_probe):
    sample = production_probe
    sample.sample.rows = tuple(OwnedProcessIdentity(pid, str(sample.identity.birth_ticks + pid),
        (sample.identity.birth_ticks + pid - 116444736000000000) / 10000000,
        sample.base, "redteam-tool", 100., 102.) for pid in range(1000, 1015))
    with pytest.raises(ToolProtocolError, match="capacity"):
        sample.owner.start_probe(sample.engine, sample.token)
    assert sample.events == ["clock", "supplier", "clock"]
    assert sample.owner._queue.empty() and not sample.owner._probes


@pytest.mark.parametrize("mode,phase,error,bound", [
    ("start-error", "executor-start", "TypeError", 0),
    ("unknown-error", "executor-start", "Exception", 0),
    ("bind-error", "challenge-bind", "ValueError", 0),
    ("success", "none", "none", 3),
])
def test_process_step_preserves_closed_failure_detail_and_success(tmp_path, monkeypatch,
                                                                 mode, phase, error, bound):
    messages, created, retired, registered = [], [], [], []
    engine = RedTeamEngine(tmp_path, documents_dir=tmp_path / "target", on_event=messages.append)
    engine.run_id = "redteam-" + "e" * 32
    engine._active_plan_entry = {"cycle": 1, "plan_step_id": "RTP1-C01-RANDOM_PROCESSES"}
    engine._threat_level = engine._proc_mult = 1
    engine._jitter = lambda low, high, note="": None
    engine._cancel = SimpleNamespace(is_set=lambda: False, wait=lambda seconds: False)
    owner = RedTeamToolOwner(lambda *_args: None)
    engine._independent_executor = owner
    token_values = []

    class PRIVATE_PROBE_EXCEPTION(Exception):
        pass

    class Probe:
        def __init__(self, index):
            self.pid = 4242 + index
            self.record = SimpleNamespace(probe_id="inert-" + str(index))
        def poll(self):
            return 0
        def wait(self, timeout=None):
            return 0
        def terminate(self):
            retired.append(self.pid)
        def kill(self):
            retired.append(self.pid)

    def start(supplied_engine, token):
        assert supplied_engine is engine
        token_values.append(token)
        if mode == "start-error":
            raise TypeError("DO_NOT_KEEP_RAW_ARGUMENT_OR_TOKEN")
        if mode == "unknown-error":
            raise PRIVATE_PROBE_EXCEPTION("DO_NOT_KEEP_RAW_ARGUMENT_OR_TOKEN")
        probe = Probe(len(created))
        created.append(probe)
        return probe

    def register(token, run_id, *, kind, pid=None):
        assert run_id == engine.run_id and kind == "red-team"
        registered.append((token, pid))

    owner.start_probe = start
    owner.retire_probe = lambda probe_id: retired.append(probe_id) or True
    monkeypatch.setattr(red_team, "register_process", register)
    if mode == "bind-error":
        lease = object.__new__(purple_guard.RedTeamValidationLease)
        engine._validation_lease = lease

        def enroll(supplied, *, token, run_id):
            assert supplied is lease and run_id == engine.run_id

        def refuse_binding(supplied, *, token, pid, run_id):
            assert supplied is lease and run_id == engine.run_id and pid >= 4242
            raise ValueError("DO_NOT_KEEP_CREATED_PROCESS_DETAILS")

        monkeypatch.setattr(purple_guard.RedTeamValidationLease, "enroll_process_challenge", enroll)
        monkeypatch.setattr(purple_guard.RedTeamValidationLease, "bind_process_challenge", refuse_binding)
    engine._step_random_processes((0., 0.))
    assert len(engine.steps) == 1
    step = engine.steps[0]
    failed = 0 if mode == "success" else 3
    assert step.ok is (mode == "success")
    assert len(step.pids) == bound and step.pid == (4242 if bound else None)
    assert f"required=3; attempted=3; bound={bound}; failures={failed}" in step.detail
    assert f"first_phase={phase}; first_exception={error}" in step.detail
    assert "Creation before admission is not inferred" in step.detail
    assert "Detection and containment require separate receipts" in step.detail
    assert len(step.detail) <= 500 and "DO_NOT_KEEP" not in step.detail
    assert "PRIVATE_PROBE_EXCEPTION" not in step.detail
    assert all(token not in step.detail for token in token_values)
    assert "Recorded" in step.description and "Spawned" not in step.description
    if mode == "bind-error":
        assert len(created) == 3 and len(retired) == 3 and not step.pids
    if mode == "success":
        assert len(created) == 3 and len(retired) == 3 and len(step.correlation_tokens) == 3
