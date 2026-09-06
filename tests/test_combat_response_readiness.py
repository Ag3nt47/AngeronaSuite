from __future__ import annotations

import queue
import hashlib
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat


def _combat(tmp_path, monkeypatch):
    import os

    for name in tuple(os.environ):
        if name.startswith("ANGERONA_ADVERSARY_COMBAT_"):
            monkeypatch.delenv(name)
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    module.bind(EventBus())
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(
        data_dir=tmp_path, adversary_combat_activate_honeypots=False,
        adversary_combat_block_network=False, adversary_combat_isolate_host=False,
    )))
    return module


def _event(**details):
    return Event("Detector", "inert response fixture", Severity.HIGH, time.time(), {
        "response_authorized": True,
        "response_contract": {
            "version": 1, "actions": ["activate_honeypots"],
            "targets": {"deception": "Smart Deception"},
        },
        **details,
    })


def test_idle_and_handled_events_renew_worker_liveness(tmp_path, monkeypatch):
    module = _combat(tmp_path, monkeypatch)
    module.status = "running"
    monkeypatch.setattr(module, "_reconcile_state", lambda: True)
    handled = []
    monkeypatch.setattr(module, "_handle", handled.append)
    calls = []
    event = _event()

    def next_event(timeout):
        calls.append(timeout)
        if len(calls) == 1:
            raise queue.Empty
        if len(calls) == 2:
            return event
        module._stop.set()
        raise queue.Empty

    monkeypatch.setattr(module._queue, "get", next_event)
    monkeypatch.setattr(module._queue, "task_done", lambda: None)
    module.run()
    assert handled == [event]
    assert module._cycle_count == 4  # startup, idle, handled, final wait
    assert calls == [1.0, 1.0, 1.0]
    assert module._watchdog_deadline_at > module._last_cycle_completed_at
    assert module._response_initialized is False


def test_admission_does_not_wait_for_receipts_or_resolve_target_paths(tmp_path, monkeypatch):
    module = _combat(tmp_path, monkeypatch)
    module.status = "running"
    event = _event(path=str(tmp_path / "inert.txt"), response_contract={
        "version": 1, "actions": ["quarantine_file"],
        "targets": {"path": str(tmp_path / "inert.txt")},
    })

    def forbidden(*args, **kwargs):
        raise AssertionError("publisher attempted filesystem-dependent validation")

    monkeypatch.setattr(module, "_response_actions", forbidden)
    finished = threading.Event()
    worker = threading.Thread(target=lambda: (module._submit(event), finished.set()))
    try:
        with module._receipt_lock:
            worker.start()
            assert finished.wait(1.0), "admission blocked behind response journal"
    finally:
        worker.join(timeout=2)
    assert module._queue.get_nowait() is event


def test_snapshot_is_read_only_and_reports_startup_recovery_and_capacity(tmp_path, monkeypatch):
    module = _combat(tmp_path, monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("readiness display touched journal authority")

    monkeypatch.setattr(module, "_read_journal", forbidden)
    monkeypatch.setattr(module, "response_ready", forbidden)
    assert module.response_snapshot()["state"] == "status=stopped"
    module.status = "running"
    assert module.response_snapshot()["state"] == "STARTING"
    assert module.self_test()[0] is False
    module._response_initialized = True
    assert module.response_snapshot()["ready"] is True
    module._journal_saturated = True
    assert module.response_snapshot()["state"] == "JOURNAL FULL"
    assert module.self_test()[0] is False
    module._mutation_blocked = True
    module._journal_error = "combat journal rollback or incomplete anchor transaction detected"
    assert module.response_snapshot()["reason"] == module._journal_error
    assert module.response_snapshot()["state"] == "RECOVERY REQUIRED"
    assert module._mutation_blocked and module._journal_saturated
    assert not module.receipt_path.exists()


def test_unsigned_request_cannot_claim_authenticated_request_identity(tmp_path, monkeypatch):
    module = _combat(tmp_path, monkeypatch)
    module.status = "running"
    module._bus.arm(BusAuthority(b"r" * 32))
    event = _event(queue_request_id="b" * 32)
    module._submit(event)
    assert module._queue.empty()
    assert not module._seen
    module._bus.publish(event)
    signed = module._bus.recent(1)[0]
    module._submit(signed)
    assert module._queue.get_nowait() is signed


@pytest.mark.parametrize("change,reason", [
    ("threshold", "below_threshold"),
    ("disabled", "policy_disabled"),
    ("exposure", "not_actionable"),
    ("invalid_contract", "invalid_contract"),
])
def test_worker_rechecks_policy_and_evidence_before_host_action(tmp_path, monkeypatch, change, reason):
    module = _combat(tmp_path, monkeypatch)
    module.status = "running"
    event = _event()
    module._submit(event)
    assert module._queue.qsize() == 1
    if change == "threshold":
        module._manager.config.adversary_combat_min_severity = "CRITICAL"
    elif change == "disabled":
        module._manager.config.adversary_combat_enabled = False
    elif change == "exposure":
        event.details["disposition"] = "exposure"
    else:
        event.details["response_contract"]["version"] = True

    def forbidden(*args, **kwargs):
        raise AssertionError("ineligible evidence reached an action backend")

    monkeypatch.setattr(module, "_act_on_process", forbidden)
    monkeypatch.setattr(module, "_ensure_honeypots", forbidden)
    module._handle(module._queue.get_nowait())
    assert module.response_snapshot()["last_decision"] == reason
    assert not module.receipt_path.exists()


@pytest.mark.parametrize("delegated", [False, True])
def test_queued_inert_artifact_has_verified_receipt_and_reversible_restore(tmp_path, monkeypatch, delegated):
    module = _combat(tmp_path, monkeypatch)
    module.status = "running"
    module._bus.arm(BusAuthority(b"s" * 32))
    artifact = tmp_path / "inert-response-fixture.txt"
    artifact.write_text("harmless test data", encoding="utf-8")
    event = _event(path=str(artifact), response_contract={
        "version": 1, "actions": ["quarantine_file"], "targets": {"path": str(artifact)},
    }, run_id="inert-proof-run", step_id="inert-proof-step",
        observed_content_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        evidence_type="native_analytic_detection", detector_verdict="positive")
    module._bus.publish(event)
    if delegated:
        original = module._bus.recent(1)[0]
        request = replace(event, module="Active Response SOAR Request", ts=time.time(), details={
            **event.details, "origin_module": original.module, "origin_ts": original.ts,
            "origin_event_digest": original.hmac_sig,
        })
        module._bus.publish(request)
    module._submit(module._bus.recent(1)[0])
    module._handle(module._queue.get_nowait())
    assert not artifact.exists()
    action = module.list_actions()[0]
    assert action["integrity_status"] == "verified"
    assert action["details"]["postcondition_verified"] is True
    receipt = next(ev for ev in module._bus.recent(20)
                   if ev.module == module.name and ev.details.get("verified_actions"))
    assert module._bus.verify(receipt)
    assert receipt.details["run_id"] == "inert-proof-run"
    assert receipt.details["step_id"] == "inert-proof-step"
    if delegated:
        assert receipt.details["origin_event_digest"] == original.hmac_sig
        assert receipt.details["origin_module"] == original.module
        assert receipt.details["origin_ts"] == original.ts
    proof = receipt.details["verified_actions"][0]
    assert proof == {
        "action": "quarantine_file", "action_id": action["action_id"],
        "target": str(artifact), "postcondition_verified": True,
        "details": {"path": str(artifact),
                    "sha256": hashlib.sha256(b"harmless test data").hexdigest()},
    }
    # Exercise production summary -> authenticated evaluator without launching
    # any campaign. The file is disposable and restored below.
    from angerona.shark.aar_report import evaluate

    verdict = evaluate({"run_id": "inert-proof-run", "steps": [{
        "step_id": "inert-proof-step", "stage": "Initial Access",
        "technique": "inert local file", "description": "harmless fixture",
        "ts_start": event.ts - 0.1, "ts_end": receipt.ts,
        "artifact_paths": [str(artifact)],
    }]}, module._bus.recent(20), require_authenticated=True,
        event_verifier=module._bus.verify, native_verifier=lambda ev, step: ev.module == "Detector",
    )[0]
    assert verdict.target_containment_verified
    assert module.undo_action(action["action_id"])["ok"] is True
    assert artifact.read_text(encoding="utf-8") == "harmless test data"


def test_process_proof_exposes_committed_identity_without_private_journal_fields():
    from angerona.modules.adversary_combat import CombatAction

    action = CombatAction("act-inert", "combat-inert", "suspend_process", 100.0,
                          True, "inert (123)", {
                              "pid": 123, "create_time": 90.0,
                              "postcondition_verified": True,
                              "mutation_generation": "private journal value",
                          }, "Detector", 99.0)
    proof = AdversaryCombat._response_action_evidence(action)
    assert proof["details"] == {"pid": 123, "process_create_time": 90.0}
    assert proof["postcondition_verified"] is True
    assert "private journal value" not in str(proof)


@pytest.mark.parametrize("verification_error", [False, True])
def test_missing_recovery_assurance_stays_exposure(tmp_path, monkeypatch, verification_error):
    from angerona.core.threat import event_disposition
    from angerona.modules.immutable_recovery_guard import ImmutableRecoveryGuardModule

    module = ImmutableRecoveryGuardModule(
        evidence_dir=tmp_path / "missing-evidence", trust_store={},
    )
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(module, "sleep", lambda *_args: module._stop.set())
    if verification_error:
        def broken():
            raise ValueError("inert verification failure")
        monkeypatch.setattr(module, "observe_once", broken)
    module.run()
    event = bus.recent(1)[0]
    assert event.severity == Severity.CRITICAL
    assert event_disposition(event) == "exposure"
    assert event.details["response_authorized"] is False


def test_response_recovery_hold_is_health_not_an_active_intrusion():
    from angerona.core.threat import event_disposition, is_active_threat

    event = Event("Adversary Combat", "Action journal integrity failed.", Severity.CRITICAL,
                  details={"disposition": "health", "response_authorized": False})
    assert event_disposition(event) == "health"
    assert not is_active_threat(event)


def test_startup_checkpoint_failure_immediately_holds_response(tmp_path, monkeypatch):
    from angerona.modules.adversary_combat import JournalIntegrityError

    module = _combat(tmp_path, monkeypatch)
    starts = []
    module._manager.modules = {"Smart Deception": SimpleNamespace(
        status="stopped", start=lambda: starts.append(True),
    )}

    def unavailable(_record):
        raise JournalIntegrityError("interrupted startup checkpoint")

    monkeypatch.setattr(module, "_advance_recovery_anchor", unavailable)
    assert module._ensure_honeypots() is None
    assert not starts
    assert module.response_snapshot()["state"] == "RECOVERY REQUIRED"
    assert "interrupted startup checkpoint" in module.response_snapshot()["reason"]


def test_disabled_policy_does_not_start_deception(tmp_path, monkeypatch):
    module = _combat(tmp_path, monkeypatch)
    module._manager.config.adversary_combat_enabled = False
    module._manager.config.adversary_combat_activate_honeypots = True
    module.status = "running"
    monkeypatch.setattr(module, "_reconcile_state", lambda: True)

    def forbidden():
        raise AssertionError("disabled response started deception")

    def idle(timeout):
        module._stop.set()
        raise queue.Empty

    monkeypatch.setattr(module, "_ensure_honeypots", forbidden)
    monkeypatch.setattr(module._queue, "get", idle)
    module.run()
    assert "disabled" in module.health_note
