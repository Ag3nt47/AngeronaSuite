"""Original YARA control authorities with a separately exercised write capability.

The file capability remains real. Transport/Job lifetime is inert here; the
separate native standalone gate proves the admitted child/Job relationship.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest

from test_yara_automatic_response import controlled_runtime  # noqa: F401

from angerona.gui.red_team_app import write_reserved_capability
from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner, ReservedMarkerWriter, ToolRequest
from angerona.modules.purple_guard import RedTeamValidationError, RedTeamValidationLease
from angerona.shark.shark_attack import SharkAttackEngine
from angerona.shark.simulation_session import PreparedRun, PreparedStep, SharkRunSession
from angerona.telemetry.process_snapshot_worker import _Pin


@pytest.fixture
def writer_scope(controlled_runtime):
    from PySide6.QtCore import QObject
    ctx = controlled_runtime
    ctx.config.adversary_combat_quarantine_files = False
    owner = RedTeamToolOwner(lambda *_: None)
    # No helper exists in this fixture. Never terminate its native self-pin.
    owner.abort_lifetime = lambda: None
    owner.stop = lambda _timeout: True
    pin = _Pin(os.getpid())
    owner._child = owner._wrapper = pin
    owner._job = object()
    owner._ready.set()
    completed = []
    def write(reservation_id, handle, payload, *, descriptor=None):
        request = ToolRequest()
        request.result = write_reserved_capability(dict(reservation_id=reservation_id,
            handle=handle, content_b64=base64.b64encode(payload).decode("ascii")), None)
        completed.append(payload)
        request.done.set()
        return request
    owner.request_marker = write
    writer = ReservedMarkerWriter(owner)
    bridge = RedTeamBridge.__new__(RedTeamBridge)
    QObject.__init__(bridge)
    bridge.owner, bridge.marker_writer = owner, writer
    ctx.manager.red_team_tool_owner = bridge
    engine = SharkAttackEngine(ctx.root, documents_dir=ctx.target, downloads_dir=ctx.target)
    engine._thread, engine._marker_writer = threading.current_thread(), writer
    planned = PreparedStep("PSTEP-" + "A" * 24, 0, 1, "initial_access", "text", ("text",))
    prepared = PreparedRun("session-" + "a" * 32, ctx.run_id, "shark", str(ctx.root),
        str(ctx.target), "{}", "b" * 64, (planned,), 60, "c" * 64)
    session_owner = SimpleNamespace(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        cancelled=threading.Event(), _run_deadline=time.monotonic() + 60)
    source = SharkRunSession(session_owner, prepared, ctx.lease, engine,
        ctx.detector.control_enrollment(), ctx.lease.readiness)
    session_owner._active_binding = source
    engine._active_planned_step = planned
    source._issued_steps.add(planned.planned_step_id)
    try:
        yield SimpleNamespace(ctx=ctx, owner=owner, writer=writer, bridge=bridge,
            source=source, planned=planned, engine=engine, completed=completed)
    finally:
        source.close_capture()
        for descriptor in owner._marker_reservations:
            os.close(descriptor)
        owner._marker_reservations.clear()
        pin.release_unadmitted()


@pytest.mark.skipif(os.name != "nt", reason="Windows duplicated capability fixture")
def test_prepared_shark_control_keeps_original_issuer_and_readonly_identity(writer_scope):
    sample = writer_scope
    value = RedTeamValidationLease.create_yara_control(sample.ctx.lease,
        run_id=sample.ctx.run_id, step_id=sample.planned.planned_step_id,
        scanner_enrollment=sample.ctx.detector.control_enrollment(), control_kind="text",
        marker_writer=sample.writer, writer_source=sample.source)
    path = Path(value["path"])
    assert sample.completed == [path.read_bytes()]
    assert value["identity"]["inode"] == path.stat().st_ino
    assert path.read_bytes().startswith(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    with pytest.raises(OSError):
        path.rename(path.with_name("swapped.txt"))


@pytest.mark.skipif(os.name != "nt", reason="Windows duplicated capability fixture")
@pytest.mark.parametrize("mismatch", ["source", "role", "lease", "run", "step", "owner", "writer"])
def test_source_role_lease_and_plan_mismatches_cannot_acquire_shark_writer(writer_scope, mismatch):
    sample = writer_scope
    source, writer = sample.source, sample.writer
    run_id, step_id = sample.ctx.run_id, sample.planned.planned_step_id
    if mismatch == "source":
        source = SimpleNamespace(**sample.source.__dict__)
    elif mismatch == "role":
        sample.source._engine = object()
    elif mismatch == "lease":
        sample.source._lease = object()
    elif mismatch == "run":
        run_id = "other-run"
    elif mismatch == "step":
        step_id = "other-step"
    elif mismatch == "owner":
        sample.bridge.owner = object()
    else:
        writer = object()
    before = set(sample.ctx.target.iterdir())
    with pytest.raises(RedTeamValidationError):
        RedTeamValidationLease.create_yara_control(sample.ctx.lease, run_id=run_id, step_id=step_id,
            scanner_enrollment=sample.ctx.detector.control_enrollment(), control_kind="text",
            marker_writer=writer, writer_source=source)
    assert not sample.completed
    assert set(sample.ctx.target.iterdir()) == before
