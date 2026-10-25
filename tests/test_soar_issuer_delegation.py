"""Issuer delegation retains the exact source and committed target evidence."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.modules import process_monitor, purple_guard as purple
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.telemetry.sensors import ProcessSnapshot


@pytest.fixture
def issuer(tmp_path, monkeypatch):
    # The inventory is a declared offline fixture. Issuer lifecycle, held file,
    # receipt signatures and all source-event verification remain real.
    monkeypatch.setattr(process_monitor, "process_snapshot", lambda **_kwargs: ProcessSnapshot(
        processes=(), collected_at=time.time(), complete=True, enumerated=0,
        skipped=0, unreadable=0, identity_incomplete=0, error="", enumeration_complete=True))
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus(ring_size=4096)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard, soar, combat = purple.PurpleGuard(tmp_path), ActiveResponseSOAR(), AdversaryCombat(tmp_path)
    for module in (guard, soar, combat):
        module.bind(bus)
    manager = SimpleNamespace(modules={m.name: m for m in (guard, soar, combat)}, bus=bus)
    soar.bind_manager(manager)
    combat.bind_manager(manager)
    # The actor is never started/subscribed: unit tests cannot execute a host
    # action. Exact production class/manager identity is still enforced.
    combat.status = "running"
    marker = guard.sandbox / "_redteam_lsass_dump_issuer.txt"
    lease = None
    try:
        lease = purple.acquire_redteam_validation_lease(
            manager, bus, recorder, tmp_path, guard.sandbox, timeout=3)
        purple.RedTeamValidationLease.consume_for_run(
            lease, run_id="issuer-bridge-unit", target=guard.sandbox, data_root=tmp_path)
        marker.write_text("inert exact issuer marker", encoding="utf-8")
        purple.RedTeamValidationLease.register_artifact_handle(lease, marker, run_id="issuer-bridge-unit")
        guard.scan_once({"T1003": {}})
        deadline = time.monotonic() + 2
        event = None
        while event is None and time.monotonic() < deadline:
            event = next((e for e in bus.recent(4096) if e.module == guard.name
                and e.details.get("receipt_type") == "purple_simulation_validation"), None)
            if event is None:
                time.sleep(.01)
        assert event is not None and bus.verify(event)
        monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(guard.sandbox))
        yield SimpleNamespace(bus=bus, guard=guard, soar=soar, combat=combat,
                              manager=manager, lease=lease, event=event, marker=marker)
    finally:
        threads = [getattr(m, "_thread", None) for m in manager.modules.values()]
        if lease is not None:
            purple.RedTeamValidationLease.release(lease)
        guard.stop()
        for thread in threads:
            if thread is not None:
                thread.join(timeout=3)
                assert not thread.is_alive()
        recorder.close()


def _committed(ctx, event=None):
    event = event or ctx.event
    row = {"action_id": "act-exact", "action": "quarantine_file", "target": str(ctx.marker),
        "status": "applied", "integrity_status": "verified", "undone": False,
        "trigger_module": event.module, "trigger_ts": event.ts,
        "details": {"aar_trigger_event_digest": event.hmac_sig, "postcondition_verified": True,
                    "sha256": hashlib.sha256(ctx.marker.read_bytes()).hexdigest()}}
    return row


def _publish_receipt(ctx, row, event=None, **overrides):
    event = event or ctx.event
    details = {"trigger_module": event.module, "trigger_ts": event.ts,
        "trigger_event_digest": event.hmac_sig, "action_succeeded": True,
        "mitigated": True, "postcondition_verified": True,
        "action_ids": [row["action_id"]], "actions": [row["action"]]}
    details.update(overrides)
    ctx.bus.publish(Event("Adversary Combat", "committed exact response", Severity.HIGH, details=details))
    return ctx.bus.recent(1)[0]


def test_original_is_submitted_once_and_completed_receipt_is_adopted_on_replay(issuer, monkeypatch):
    ctx = issuer
    rows, submitted = [], []
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: rows)
    def submit(event):
        assert event is ctx.event and ctx.bus.verify(event)
        submitted.append(event)
        row = _committed(ctx)
        rows.append(row)
        _publish_receipt(ctx, row)
    monkeypatch.setattr(ctx.combat, "_submit", submit)
    ctx.soar._kill_and_rollback(ctx.event)
    ctx.soar._kill_and_rollback(ctx.event)
    assert submitted == [ctx.event]
    assert not [e for e in ctx.bus.recent(4096) if e.module == "Active Response SOAR Request"]
    summaries = [e for e in ctx.bus.recent(4096) if e.module == ctx.soar.name
                 and e.details.get("delegation_mode") == "issuer-original-event"]
    assert len(summaries) == 2 and all(e.details["mitigated"] is True for e in summaries)
    assert all(e.details["combat_action_ids"] == ["act-exact"] for e in summaries)


@pytest.mark.parametrize("broken", ["manager", "bus", "lease", "actor", "guard", "contract", "publisher",
                                    "source_target", "source_digest"])
def test_wrong_issuer_actor_or_forged_metadata_cannot_enter_bridge(issuer, monkeypatch, broken):
    ctx = issuer
    with monkeypatch.context() as patch:
        event = ctx.event
        if broken == "manager":
            patch.setattr(ctx.soar, "_manager", SimpleNamespace(modules=ctx.manager.modules, bus=ctx.bus))
        elif broken == "bus":
            patch.setattr(ctx.combat, "_bus", EventBus())
        elif broken == "lease":
            patch.setattr(ctx.guard, "_validation_lease", SimpleNamespace(active=True))
        elif broken == "actor":
            patch.setitem(ctx.manager.modules, "Adversary Combat", SimpleNamespace(status="running"))
        elif broken == "guard":
            patch.setitem(ctx.manager.modules, ctx.guard.name, purple.PurpleGuard(ctx.guard.data_root))
        else:
            details = copy.deepcopy(event.details)
            if broken == "contract":
                details["response_contract"]["actions"].append("isolate_host")
                details["response_contract"]["targets"]["host"] = "local"
            elif broken == "source_target":
                details["path"] = details["artifact_path"] = str(ctx.marker.with_name("other.txt"))
                details["response_contract"]["targets"]["path"] = details["path"]
            elif broken == "source_digest":
                details["observed_content_sha256"] = "0" * 64
            ctx.bus.publish(Event("copied publisher" if broken == "publisher" else event.module,
                event.message, event.severity, details=details))
            event = ctx.bus.recent(1)[0]
        assert ctx.soar._issuer_original_combat(event) is None


@pytest.mark.parametrize("broken", ["uncommitted", "undone", "digest", "target", "content", "failed", "receipt_digest"])
def test_receipt_cannot_borrow_other_uncommitted_or_undone_action(issuer, monkeypatch, broken):
    ctx = issuer
    row = _committed(ctx)
    receipt_changes = {}
    if broken == "uncommitted": row["status"] = "pending"
    elif broken == "undone": row["undone"] = True
    elif broken == "digest": row["details"]["aar_trigger_event_digest"] = "wrong"
    elif broken == "target": row["target"] = str(ctx.marker.with_name("other.txt"))
    elif broken == "content": row["details"]["sha256"] = "0" * 64
    elif broken == "failed": row["details"]["postcondition_verified"] = False
    else: receipt_changes["trigger_event_digest"] = "wrong"
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: [row])
    _publish_receipt(ctx, row, **receipt_changes)
    assert ctx.soar._verified_origin_receipt(ctx.combat, ctx.event) is None


def test_pending_and_outside_bounded_bus_receipts_never_read_journal(issuer, monkeypatch):
    ctx = issuer
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: pytest.fail("pending poll read journal"))
    assert ctx.soar._verified_origin_receipt(ctx.combat, ctx.event) is None
    row = _committed(ctx)
    _publish_receipt(ctx, row)
    for index in range(501):
        ctx.bus.publish(Event("Unrelated", str(index), Severity.INFO))
    assert ctx.soar._verified_origin_receipt(ctx.combat, ctx.event) is None


def test_matching_success_claim_reads_journal_only_once_and_negative_never_credits(issuer, monkeypatch):
    ctx = issuer
    calls = []
    row = _committed(ctx)
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: calls.append(1) or [row])
    _publish_receipt(ctx, row)
    latest = _publish_receipt(ctx, row)
    assert ctx.soar._verified_origin_receipt(ctx.combat, ctx.event) is latest
    assert calls == [1]
    # Even contradictory metadata on an explicit no-action claim cannot
    # become success. No terminal action IDs exist to adopt.
    ctx.bus.publish(Event("Adversary Combat", "no action", Severity.MEDIUM,
        details={"trigger_module": ctx.event.module, "trigger_ts": ctx.event.ts,
            "trigger_event_digest": ctx.event.hmac_sig, "action_succeeded": False,
            "mitigated": False, "postcondition_verified": True,
            "action_ids": [], "actions": []}))
    negative = ctx.bus.recent(1)[0]
    original_recent = ctx.bus.recent
    monkeypatch.setattr(ctx.bus, "recent", lambda _limit: [negative])
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: pytest.fail("negative read journal"))
    ctx.soar._kill_and_rollback(ctx.event)
    summary = original_recent(1)[0]
    assert summary.module == ctx.soar.name
    assert summary.details["mitigated"] is False
    assert summary.details["combat_action_ids"] == []


@pytest.mark.parametrize("outcome", ["valid", "expired", "custody_failed"])
def test_pending_handoff_waits_for_full_proof_or_refuses_without_submission(issuer, monkeypatch, outcome):
    ctx = issuer
    original = ctx.soar._issuer_original_combat
    phase = {"waiting": True, "valid": False}
    row = _committed(ctx)
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: [row])
    monkeypatch.setattr(ctx.combat, "_submit", lambda _event: pytest.fail("pending custody submitted"))
    def admission(event, *, pending_handoff=False):
        if phase["waiting"]:
            return ctx.combat if pending_handoff else None
        return original(event) if phase["valid"] and not pending_handoff else None
    def settle(_seconds):
        phase["waiting"] = False
        phase["valid"] = outcome == "valid"
        if phase["valid"]:
            _publish_receipt(ctx, row)
    monkeypatch.setattr(ctx.soar, "_issuer_original_combat", admission)
    monkeypatch.setattr("angerona.modules.soar_engine.time", SimpleNamespace(
        monotonic=time.monotonic, time=time.time, sleep=settle))
    ctx.soar._kill_and_rollback(ctx.event)
    summaries = [e for e in ctx.bus.recent(4096) if e.module == ctx.soar.name
        and e.details.get("delegation_mode") == "issuer-original-event"]
    assert bool(summaries) is (outcome == "valid")


@pytest.mark.parametrize("terminal", ["released", "artifact_custody_failed", "expired"])
def test_terminal_issuer_state_denies_pending_handoff_immediately(issuer, monkeypatch, terminal):
    ctx = issuer
    state = purple._lease_authority(ctx.lease)
    key = os.path.normcase(os.path.abspath(ctx.marker))
    with monkeypatch.context() as patch:
        patch.setattr(state, "artifact_handoffs", {key})
        if terminal == "expired":
            patch.setattr(state, "run_deadline_monotonic", time.monotonic() - 1)
        else:
            patch.setattr(state, terminal, True)
        assert ctx.soar._issuer_original_combat(ctx.event, pending_handoff=True) is None
        assert ctx.soar._issuer_original_combat(ctx.event) is None


def _native_record():
    return {"pid": 731, "create_time": 1000.25, "native_pid": 731,
        "native_birth_ticks": int((11_644_473_600 + 1000.25) * 10_000_000),
        "process_custody": "windows-retained-handle-v1", "native_wait_signaled": True,
        "native_image": "C:/owned/python.exe", "native_image_observation": "before-termination",
        "native_exit_code": 1}


@pytest.mark.parametrize("already_completed,allow_termination", [(True, True), (False, True), (True, False)])
def test_completed_native_origin_can_be_adopted_but_missing_identity_cannot_submit(
        issuer, monkeypatch, already_completed, allow_termination):
    ctx = issuer
    ctx.bus.publish(Event(ctx.guard.name, "owned issuer process", Severity.HIGH,
        details={"receipt_type": "purple_simulation_validation", "evidence_kind": "nonce_tagged_process",
            "response_authorized": True, "pid": 731, "process_create_time": 1000.25,
            "exe": "C:/owned/python.exe", "cmdline": "python ANGERONA_REDTEAM_a1b2c3d4",
            "response_contract": {"version": 1, "actions": ["terminate_process" if allow_termination else "suspend_process"],
                "targets": {"pid": 731, "process_create_time": 1000.25}}}))
    event = ctx.bus.recent(1)[0]
    row = {"action_id": "act-native", "action": "terminate_process", "target": "python (731)",
        "status": "applied", "integrity_status": "verified", "undone": False,
        "trigger_module": event.module, "trigger_ts": event.ts,
        "details": {**_native_record(), "aar_trigger_event_digest": event.hmac_sig,
                    "postcondition_verified": True}}
    if not already_completed:
        row["details"]["create_time"] = 1001.25
    monkeypatch.setattr(ctx.combat, "list_actions", lambda **_kwargs: [row])
    _publish_receipt(ctx, row, event=event)
    # This fixture isolates adoption after issuer admission. Real issuer-native
    # process admission is covered by the integration's owned sleep child.
    monkeypatch.setattr(ctx.soar, "_issuer_original_combat", lambda _event: ctx.combat)
    monkeypatch.setattr(ctx.combat, "_submit", lambda _event: pytest.fail("completed/missing process resubmitted"))
    credit = already_completed and allow_termination
    if credit:
        monkeypatch.setattr(ctx.soar, "_exact_process_binding_ok", lambda _event: pytest.fail("dead target needed a live lookup"))
    else:
        monkeypatch.setattr(ctx.soar, "_exact_process_binding_ok", lambda _event: False)
    ctx.soar._kill_and_rollback(event)
    summaries = [e for e in ctx.bus.recent(4096) if e.module == ctx.soar.name
        and e.details.get("delegation_mode") == "issuer-original-event"]
    assert bool(summaries) is credit
    if summaries:
        assert summaries[0].details["mitigated"] is True


@pytest.mark.parametrize("field,value", [("pid", 732), ("native_pid", True),
    ("create_time", 1001.25), ("native_birth_ticks", 1), ("native_wait_signaled", False),
    ("process_custody", "unretained"), ("native_exit_code", None),
    ("native_image", "C:/other/python.exe")])
def test_native_receipt_rejects_wrong_generation_or_uncertain_exit(field, value):
    details = {"pid": 731, "process_create_time": 1000.25, "exe": "C:/owned/python.exe"}
    record = _native_record()
    assert ActiveResponseSOAR._native_origin_termination(record, details)
    record[field] = value
    assert not ActiveResponseSOAR._native_origin_termination(record, details)
