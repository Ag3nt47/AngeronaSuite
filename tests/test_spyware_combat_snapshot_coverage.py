"""Real journal-custody contention must degrade SG coverage without killing it.

These are disposable accounting and scheduling fixtures. No module run loop,
process scan, native containment, network request, or encrypted archive runs.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import threading
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat, JournalIntegrityError
from angerona.modules.spyware_guard import SpywareGuardModule


class _NoArchive:
    def seal_file(self, *_args):
        raise AssertionError("A held or pending receipt must not trigger archival work")


def _fixture(tmp_path):
    (tmp_path / "bus.key").write_text((b"s" * 32).hex(), encoding="ascii")
    combat = AdversaryCombat(tmp_path, rollback_anchor={})
    # A genuinely signed pending intent is retained custody, not an applied
    # action or fabricated successful commit. No host action is invoked.
    action = combat._action(
        "activate_honeypots", "inert-fixture",
        Event("SpywareGuard", "inert accounting fixture", Severity.INFO),
        "inert-fixture", reversible=True, details={"module": "inert-fixture"},
    )
    combat._journal_intent(action)
    now = [1800000000.0]
    guard = SpywareGuardModule(clock=lambda: now[0], vault=_NoArchive())
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    guard.bind(bus)
    guard._manager = SimpleNamespace(modules={"Adversary Combat": combat})
    guard.status = "running"
    return guard, combat, action, now


def _authority(combat):
    return (
        {path.name: path.read_bytes() for path in (
            combat.receipt_path, combat.recovery_witness_path,
            combat.data_root / "bus.key",
        )},
        copy.deepcopy(combat._rollback_anchor_override),
    )


@contextmanager
def _held_custody(combat, gate):
    acquired, release = threading.Event(), threading.Event()
    errors = []

    def hold():
        try:
            lock = combat._receipt_lock if gate == "receipt" else combat._journal_writer_lease()
            with lock:
                acquired.set()
                assert release.wait(5), "The exact test-owned custody holder was not released"
        except BaseException as exc:
            errors.append(exc)

    owner = threading.Thread(target=hold, name="inert-combat-snapshot-custody")
    owner.start()
    try:
        assert acquired.wait(2)
        yield
    finally:
        release.set()
        owner.join(timeout=3)
    assert not owner.is_alive() and errors == []


def _isolate_tick(guard, monkeypatch, priority):
    work = []
    guard._definitions_initialized = True
    monkeypatch.setattr(guard, "_run_priority_scan", lambda: priority)
    monkeypatch.setattr(guard, "_process_commands", lambda: None)
    monkeypatch.setattr(guard, "_ensure_report_worker", lambda: None)
    monkeypatch.setattr(guard, "_consume_events", lambda: work.append("events"))
    monkeypatch.setattr(guard, "_ensure_beacon", lambda: None)
    monkeypatch.setattr(guard, "_scan_once", lambda: work.append("host"))
    return work


@pytest.mark.parametrize("gate", ["receipt", "writer"])
@pytest.mark.parametrize("priority", [False, True])
def test_real_busy_custody_retains_history_and_does_not_abort_either_tick_branch(
    tmp_path, monkeypatch, gate, priority,
):
    guard, combat, action, now = _fixture(tmp_path)
    guard._collect_responses()
    retained = copy.deepcopy(guard._response_rows)
    assert len(retained) == 1 and retained[0]["action_id"] == action.action_id
    assert retained[0]["record_type"] == "recovery_required"
    assert retained[0]["integrity_status"] == "verified"
    previous = copy.deepcopy(guard._coverage["responses"])
    receipts = dict(guard._receipt_ids)
    authority = _authority(combat)
    work = _isolate_tick(guard, monkeypatch, priority)

    with _held_custody(combat, gate):
        # Three real calls previously escaped to the wrapper's quarantine path.
        for _ in range(3):
            now[0] += 1
            guard._scan_requested = True
            guard._tick()
            coverage = guard.dashboard_snapshot()["coverage"]["responses"]
            assert coverage["state"] == "busy" and coverage["status"] == "partial"
            assert coverage["current"] is False and coverage["retained_rows"] == 1
            assert coverage["last_verified_at"] == previous["last_verified_at"]
            assert guard._response_rows == retained and dict(guard._receipt_ids) == receipts
            assert guard.health == 50 and guard.status == "running" and guard._crash_count == 0
            assert combat._journal_error == "" and not combat._mutation_blocked
            assert _authority(combat) == authority
    assert work.count("events") == 3
    assert work.count("host") == (0 if priority else 3)

    now[0] += 1
    guard._scan_requested = True
    guard._tick()
    current = guard.dashboard_snapshot()["coverage"]["responses"]
    assert current["current"] is True and current["state"] == "current"
    assert current["last_verified_at"] == now[0]
    assert guard._response_rows == retained and guard.health == 85
    assert _authority(combat) == authority


@pytest.mark.parametrize("gate", ["receipt", "writer"])
def test_first_busy_read_with_no_cached_rows_is_a_gap_not_an_empty_current_view(tmp_path, gate):
    guard, combat, _action, _now = _fixture(tmp_path)
    with _held_custody(combat, gate):
        guard._collect_responses()
    coverage = guard.dashboard_snapshot()["coverage"]["responses"]
    assert coverage["current"] is False and coverage["status"] == "partial"
    assert coverage["state"] == "busy" and coverage["retained_rows"] == 0
    assert coverage["last_verified_at"] is None and guard._response_rows == []
    assert not guard._receipt_ids and guard._vault_state["status"] == "not-used"


def test_real_authenticated_prefix_rollback_stays_integrity_held_and_is_never_repaired(tmp_path):
    guard, combat, action, now = _fixture(tmp_path)
    guard._collect_responses()
    retained = copy.deepcopy(guard._response_rows)
    verified_at = guard._coverage["responses"]["last_verified_at"]
    combat._journal_failure(action, "inert fixture; no effect was dispatched")
    complete = combat.receipt_path.read_bytes()
    combat.receipt_path.write_bytes(b"".join(complete.splitlines(keepends=True)[:-1]))
    held_authority = _authority(combat)
    now[0] += 1
    guard._collect_responses()
    coverage = guard.dashboard_snapshot()["coverage"]["responses"]
    assert coverage["state"] == "integrity-held" and coverage["current"] is False
    assert coverage["last_verified_at"] == verified_at and guard._response_rows == retained
    assert "rollback or incomplete anchor transaction" in combat._journal_error
    assert _authority(combat) == held_authority and guard.health == 50

    # Restoring fixture bytes does not authorize this consumer to clear Combat's
    # latched error, repair its checkpoint, or adopt an apparently clean view.
    combat.receipt_path.write_bytes(complete)
    restored_authority = _authority(combat)
    guard._collect_responses()
    assert guard._coverage["responses"]["state"] == "integrity-held"
    assert guard._response_rows == retained and _authority(combat) == restored_authority
    assert combat._journal_error and guard._vault_state["status"] == "not-used"


def test_recovery_circuit_cannot_label_a_returned_receipt_view_current(tmp_path):
    guard, combat, _action, now = _fixture(tmp_path)
    guard._collect_responses()
    retained = copy.deepcopy(guard._response_rows)
    verified_at = guard._coverage["responses"]["last_verified_at"]
    combat._mutation_blocked = True
    now[0] += 1
    guard._collect_responses()
    assert guard._coverage["responses"]["state"] == "integrity-held"
    assert guard._coverage["responses"]["last_verified_at"] == verified_at
    assert guard._response_rows == retained and combat._mutation_blocked


def test_provider_unavailable_retains_existing_rows_with_explicit_coverage_loss(tmp_path):
    guard, _combat, _action, _now = _fixture(tmp_path)
    guard._collect_responses()
    retained = copy.deepcopy(guard._response_rows)
    guard._manager = SimpleNamespace(modules={})
    guard._collect_responses()
    assert guard._coverage["responses"]["state"] == "unavailable"
    assert guard._coverage["responses"]["current"] is False
    assert guard._response_rows == retained and guard.health == 50


def test_same_error_text_without_the_real_typed_journal_exception_is_not_swallowed(tmp_path):
    guard, _combat, _action, _now = _fixture(tmp_path)

    def broken_provider(**_kwargs):
        raise RuntimeError("combat journal snapshot is busy")

    guard._manager = SimpleNamespace(modules={
        "Adversary Combat": SimpleNamespace(list_actions=broken_provider),
    })
    with pytest.raises(RuntimeError, match="combat journal snapshot is busy"):
        guard._collect_responses()
    assert guard._coverage["responses"]["status"] == "not-collected"
    assert guard._response_rows == [] and not guard._receipt_ids


@pytest.mark.parametrize("message", [
    "combat journal authentication failed", "combat journal writer lease object is unsafe",
])
def test_other_typed_journal_failures_are_integrity_holds_not_busy_or_empty_success(tmp_path, message):
    guard, _combat, _action, _now = _fixture(tmp_path)
    guard._collect_responses()
    retained = copy.deepcopy(guard._response_rows)

    def held_provider(**_kwargs):
        raise JournalIntegrityError(message)

    guard._manager = SimpleNamespace(modules={
        "Adversary Combat": SimpleNamespace(list_actions=held_provider),
    })
    guard._collect_responses()
    coverage = guard._coverage["responses"]
    assert coverage["state"] == "integrity-held" and coverage["current"] is False
    assert guard._response_rows == retained and coverage["last_verified_at"] is not None
    assert message not in coverage["reason"] and guard.health == 50


def test_response_hold_does_not_overwrite_a_real_priority_worker_retirement_failure(tmp_path, monkeypatch):
    guard, combat, _action, _now = _fixture(tmp_path)
    _isolate_tick(guard, monkeypatch, priority=True)

    def real_failure_projection():
        # Only the caller's already-proven failure projection is modeled; this
        # fixture does not perform a native priority transition or claim one.
        guard.generation_stop_event().set()
        guard.status = "error"
        guard.set_health(0, "Native worker priority restoration failed; worker retired.")
        return True

    monkeypatch.setattr(guard, "_run_priority_scan", real_failure_projection)
    with _held_custody(combat, "receipt"):
        guard._tick()
    assert guard._coverage["responses"]["state"] == "busy"
    assert guard.status == "error" and guard.health == 0
    assert guard.health_note == "Native worker priority restoration failed; worker retired."
