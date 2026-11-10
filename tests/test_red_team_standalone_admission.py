"""No OS launch: registry/roster regression tests with explicit inert native seams.

The existing issuer verifier is represented as already verified in this fixture;
these results do not establish cryptographic issuer or real host efficacy.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.core.werfault_guard import OwnedProcessIdentity
from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner, _ProbeRecord
from angerona.modules import adversary_combat as combat_module
from angerona.modules.adversary_combat import AdversaryCombat, CombatAction, HostMutationHeld, _CanaryMutation
from angerona.modules import purple_guard
from angerona.shark.red_team import RedTeamEngine


@pytest.fixture
def admission(tmp_path, monkeypatch):
    from PySide6.QtCore import QObject
    clock = [100.0]
    monkeypatch.setattr(combat_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    base = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True))
    identity = ProcessObjectIdentity(4242, 134377029371751523, base)
    owner = RedTeamToolOwner(lambda *_: None)
    owner._job = object()
    owner._wrapper = SimpleNamespace(pid=1002, alive=lambda: True)
    owner._child = SimpleNamespace(pid=1003, alive=lambda: True)
    owner._ready.set()
    job = SimpleNamespace(member=True, closed=False)
    job.contains_native_process = lambda target: job.member and not job.closed and target == identity
    owner._native_owner = job
    lease = object()
    active = {"key": "random_processes", "plan_step_id": "RTP1-C01-PROCESS"}
    prepared = SimpleNamespace(run_id="redteam-" + "a" * 32, plan_sha256="b" * 64)
    engine = RedTeamEngine(tmp_path / "data", documents_dir=tmp_path / "target")
    engine.run_id, engine._prepared_run, engine._validation_lease = prepared.run_id, prepared, lease
    engine._active_plan_entry, engine._expected_plan = active, [active]
    pin = SimpleNamespace(closed=False, alive=lambda: True)
    token = "ANGERONA_REDTEAM_1234abcd"
    record = _ProbeRecord("c" * 32, token, engine.run_id, prepared.plan_sha256,
                          active["plan_step_id"], prepared, engine, lease, pin, identity)
    owner._probes[record.probe_id] = record
    state = SimpleNamespace(lock=threading.RLock(), released=False, consumed=True,
        bound_run_id=engine.run_id, process_challenges={token: {"state": "bound", "pid": identity.pid}})
    monkeypatch.setattr(purple_guard, "_lease_authority", lambda supplied: state if supplied is lease else None)
    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "assert_live_producers", lambda *_args, **_kwargs: None)
    command = [base, "-I", "-S", "-c", "import time; time.sleep(30)", token]
    process = SimpleNamespace(ppid=lambda: 1003, cmdline=lambda: list(command), exe=lambda: base)
    import psutil
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)
    bridge = RedTeamBridge.__new__(RedTeamBridge)
    QObject.__init__(bridge)
    bridge.owner = owner
    combat = AdversaryCombat(tmp_path / "combat", rollback_anchor={})
    manager = SimpleNamespace(modules={combat.name: combat}, red_team_tool_owner=bridge)
    combat.bind_manager(manager)
    # Simulate the upstream exact issuer verifier only. Registry/native/roster
    # paths below are production methods and remain under test.
    monkeypatch.setattr(combat, "_canary_mutation_valid", lambda *_args, **_kwargs: True)
    event = Event("Purple Remediation Guard", "inert fixture", Severity.HIGH,
        details={"correlation_token": token, "run_id": engine.run_id})
    canary = _CanaryMutation(event, "d" * 64, lease, "terminate_process", identity.pid,
                             combat.lifecycle_generation, {})
    action = CombatAction("act-" + "a" * 16, "combat-" + "b" * 12, "terminate_process",
        100.0, False, str(identity.pid), {"pid": identity.pid, "create_time": identity.create_time,
        "exe": identity.image}, "Purple Remediation Guard", 99.0)
    rows = tuple(OwnedProcessIdentity(pid, str(identity.birth_ticks + pid),
        (identity.birth_ticks + pid - 116444736000000000) / 10000000, identity.image, role, 100., 102.)
        for pid, role in ((os.getpid(), "core"), (1002, "redteam-tool"), (1003, "redteam-tool")))
    rows += (OwnedProcessIdentity(identity.pid, str(identity.birth_ticks), identity.create_time,
                                  identity.image, "redteam-tool", 100., 102.),)
    manager.owned_process_identities = lambda: rows
    return SimpleNamespace(owner=owner, bridge=bridge, combat=combat, manager=manager,
        engine=engine, record=record, identity=identity, pin=pin, lease=lease, state=state,
        token=token, action=action, canary=canary, process=process, command=command,
        job=job, clock=clock, rows=rows)


def admit(sample):
    return sample.combat._require_not_owned_identity(sample.identity, canary=sample.canary, action=sample.action)


def test_exact_registered_inert_probe_only_can_cross_this_owned_process_barrier(admission):
    assert admit(admission) is None
    for pid in (1002, 1003, os.getpid()):
        row = next(row for row in admission.rows if row.pid == pid)
        target = ProcessObjectIdentity(row.pid, int(row.birth_ticks), row.image)
        with pytest.raises(HostMutationHeld):
            admission.combat._require_not_owned_identity(target,
                canary=admission.canary, action=admission.action)


@pytest.mark.parametrize("failure", ["forged-canary", "wrong-token", "wrong-run", "wrong-lease",
    "released-lease", "wrong-plan", "wrong-step", "cancelled", "other-job", "closed-job",
    "closed-pin", "wrong-parent", "wrong-command", "wrong-image", "reused-pid", "wrong-birth",
    "root-identity", "other-operation", "other-role", "expired-roster", "unknown-supplier"])
def test_every_ambiguity_refuses_owned_process_termination(admission, failure, monkeypatch):
    sample = admission
    if failure == "forged-canary":
        sample.canary = SimpleNamespace(**sample.canary.__dict__)
    elif failure == "wrong-token":
        sample.canary.event.details["correlation_token"] = "ANGERONA_REDTEAM_ffffffff"
    elif failure == "wrong-run":
        sample.canary.event.details["run_id"] = "redteam-" + "f" * 32
    elif failure == "wrong-lease":
        sample.canary = replace(sample.canary, lease=object())
    elif failure == "released-lease":
        sample.state.released = True
    elif failure == "wrong-plan":
        sample.engine._prepared_run = SimpleNamespace(plan_sha256="e" * 64)
    elif failure == "wrong-step":
        sample.engine._active_plan_entry = {"key": "other", "plan_step_id": "different"}
    elif failure == "cancelled":
        sample.engine._cancel.set()
    elif failure == "other-job":
        sample.job.member = False
    elif failure == "closed-job":
        sample.job.closed = True
    elif failure == "closed-pin":
        sample.pin.closed = True
    elif failure == "wrong-parent":
        sample.process.ppid = lambda: 9999
    elif failure == "wrong-command":
        sample.command[-1] = "ANGERONA_REDTEAM_ffffffff"
    elif failure == "wrong-image":
        sample.process.exe = lambda: r"C:\other\python.exe"
    elif failure in {"reused-pid", "wrong-birth", "root-identity"}:
        # A corrupted/forged registry row cannot exempt an actual native target
        # merely because the attacker copied its token or its PID.
        altered = replace(sample.identity, **({"pid": 9999} if failure == "reused-pid" else
            {"birth_ticks": sample.identity.birth_ticks + 1} if failure == "wrong-birth" else {"pid": 1003}))
        sample.owner._probes[sample.record.probe_id] = replace(sample.record, identity=altered)
    elif failure == "other-operation":
        sample.action = replace(sample.action, action="isolate_program")
    elif failure == "other-role":
        sample.manager.owned_process_identities = lambda: tuple(replace(row, role="scanner")
            if row.pid == sample.identity.pid else row for row in sample.rows)
    elif failure == "expired-roster":
        sample.clock[0] = 102.
    else:
        def unavailable():
            raise RuntimeError("inert transient native supplier failure")
        sample.manager.owned_process_identities = unavailable
    with pytest.raises(HostMutationHeld):
        admit(sample)


def test_roster_cannot_expire_during_exact_registry_and_native_revalidation(admission):
    sample = admission
    def after_native(_identity):
        sample.clock[0] = 102.
        return True
    sample.job.contains_native_process = after_native
    with pytest.raises(HostMutationHeld, match="expired"):
        admit(sample)
    assert sample.combat._owned_process_hold_reason == "row_expired"
