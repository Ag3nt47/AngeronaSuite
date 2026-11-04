"""Synthetic command lifecycle only; no archive, trust or native action runs."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from angerona.modules.immutable_recovery_guard import ImmutableRecoveryGuardModule


class Workflow:
    def __init__(self):
        self.state = "fixture-initial"
        self.received = []

    def snapshot(self):
        return {"status": self.state, "physical_independence_proven": False}

    def recheck(self, *, keys=None):
        self.received.extend(keys or ())
        self.state = "fixture-recheck-returned"

    def configure_schedule(self, enabled, interval_hours):
        assert enabled is False and interval_hours == 24
        self.state = "fixture-schedule-configured"

    def failure(self, error):
        self.state = "fixture-failed-" + type(error).__name__


@pytest.fixture
def guard():
    module = ImmutableRecoveryGuardModule(source_revision="a" * 40)
    # Model one BaseModule generation without running its sensors or workflow.
    # The existing real-worker/archive fixture separately verifies integration.
    module._lifecycle_generation = 7
    module.status = "running"
    module.bind_manager(SimpleNamespace(ugcap_paused=False))
    module._workflow = Workflow()
    module._continue_recovery = lambda: not module.generation_stop_event().is_set()
    module.emit = lambda *_args, **_kwargs: None
    yield module
    module._cancel_queued_recovery(module.lifecycle_generation)
    assert module._commands.unfinished_tasks == 0


def test_ticket_is_queued_then_running_until_action_and_all_key_cleanup_settle(guard):
    keys = (bytearray(b"e" * 32), bytearray(b"a" * 32))
    ticket = guard.queue_tracked_recovery("queue_recheck_recovery", keys=keys)
    assert ticket["generation"] == 7
    assert guard.command_request_snapshot(ticket)["state"] == "queued"
    with guard._command_lock:
        retained_keys = guard._commands.queue[0][1]["keys"]
    entered, release = threading.Event(), threading.Event()
    original = guard._wipe_keys

    def held_cleanup(payload):
        entered.set()
        assert release.wait(4)
        original(payload)

    guard._wipe_keys = held_cleanup
    native = threading.Thread(target=guard._process_recovery_command)
    try:
        native.start()
        assert entered.wait(2)
        pending = guard.command_request_snapshot(ticket)
        assert pending["state"] == "running" and pending["operation_settled"] is False
        assert pending["completed"] is pending["total"] is None
        assert guard._workflow.received and any(guard._workflow.received[0])
        release.set()
        native.join(3)
        assert not native.is_alive()
        result = guard.command_request_snapshot(ticket)
        assert result["state"] == "completed" and result["operation_settled"] is True
        assert result["action_returned"] is True and result["workflow_status"] == "fixture-recheck-returned"
        assert all(not any(key) for key in (*retained_keys, *guard._workflow.received))
        assert keys == (bytearray(b"e" * 32), bytearray(b"a" * 32))
        assert "keys" not in result and "payload" not in result
    finally:
        release.set()
        native.join(3)
        assert not native.is_alive()


def test_queue_stays_bounded_and_stop_drain_settles_only_wiped_queued_payloads(guard):
    keys = (bytearray(b"e" * 32), bytearray(b"a" * 32))
    tickets = [guard.queue_tracked_recovery("queue_recheck_recovery", keys=keys) for _index in range(4)]
    assert all(type(ticket) is dict for ticket in tickets)
    with guard._command_lock:
        retained = [queued[1]["keys"] for queued in guard._commands.queue]
    assert guard.queue_tracked_recovery("queue_recheck_recovery", keys=keys) is False
    assert len(guard._command_requests) == guard._commands.qsize() == 4
    guard.stop()
    assert all(guard.command_request_snapshot(ticket)["operation_settled"] is False for ticket in tickets)
    guard._cancel_queued_recovery(7)
    assert all(not any(key) for group in retained for key in group)
    for ticket in tickets:
        row = guard.command_request_snapshot(ticket)
        assert row["state"] == "cancelled" and row["operation_settled"] is True
        assert row["action_returned"] is False
    assert guard.queue_tracked_recovery("queue_recheck_recovery", keys=keys) is False


def test_stale_generation_never_runs_or_overwrites_newer_ticket(guard):
    keys = (bytearray(b"e" * 32), bytearray(b"a" * 32))
    old = guard.queue_tracked_recovery("queue_recheck_recovery", keys=keys)
    old_stop = guard._stop
    with guard._lifecycle_lock:
        guard._lifecycle_generation = 8
        guard._stop = threading.Event()
    fresh = guard.queue_tracked_recovery("queue_recheck_recovery", keys=keys)
    guard._process_recovery_command()  # Stale admission is refused before action.
    assert guard._workflow.received == []
    assert guard.command_request_snapshot(old)["state"] == "cancelled"
    assert guard.command_request_snapshot(fresh)["state"] == "queued"
    guard._command_state(dict(fresh, generation=7), state="completed", operation_settled=True)
    assert guard.command_request_snapshot(fresh)["state"] == "queued"
    old_stop.set()
    guard._cancel_queued_recovery(7)
    assert guard._commands.qsize() == 1 and guard.command_request_snapshot(fresh)["state"] == "queued"
    guard._cancel_queued_recovery(8)


def test_workflow_construction_error_still_wipes_keys_and_retires_queue_slot(guard, monkeypatch):
    ticket = guard.queue_tracked_recovery("queue_recheck_recovery", keys=(bytearray(b"x" * 32), bytearray(b"y" * 32)))
    with guard._command_lock:
        retained = guard._commands.queue[0][1]["keys"]
    monkeypatch.setattr(guard, "_get_workflow", lambda: (_ for _ in ()).throw(OSError("untrusted private path")))
    guard._process_recovery_command()
    row = guard.command_request_snapshot(ticket)
    assert row["state"] == "failed" and row["operation_settled"] is True
    assert row["action_returned"] is False and row["error_type"] == "OSError"
    assert "private path" not in json.dumps(row)
    assert all(not any(key) for key in retained)


def test_advisory_ticket_history_is_bounded_and_copied_without_changing_health(guard):
    oldest = None
    for _index in range(24):
        ticket = guard.queue_tracked_recovery("queue_recovery_schedule", False, 24)
        oldest = oldest or ticket
        guard._process_recovery_command()
    snapshot = guard.dashboard_snapshot()
    assert len(snapshot["command_requests"]) == 16
    assert snapshot["status"] == "fixture-schedule-configured"
    assert snapshot["physical_independence_proven"] is False
    assert guard.command_request_snapshot(oldest)["state"] == "unavailable"
    row = guard.command_request_snapshot(ticket)
    row["state"] = "forged"
    assert guard.command_request_snapshot(ticket)["state"] == "completed"
    assert guard.queue_tracked_recovery("stop") is False
    assert guard.command_request_snapshot(dict(ticket, payload="must not be echoed")) == {"state": "unavailable", "operation_settled": False}


def test_nonce_collision_never_replaces_an_admitted_request(guard, monkeypatch):
    monkeypatch.setattr("angerona.modules.immutable_recovery_guard.secrets.token_hex", lambda _size: "a" * 32)
    first = guard.queue_tracked_recovery("queue_recovery_schedule", False)
    assert type(first) is dict
    assert guard.queue_tracked_recovery("queue_recovery_schedule", False) is False
    assert guard.command_request_snapshot(first)["state"] == "queued"
    assert len(guard._command_requests) == guard._commands.qsize() == 1


def test_recovery_panel_tracks_command_scope_and_keeps_shared_health_distinct(guard):
    from PySide6.QtWidgets import QApplication
    from angerona.gui.recovery_panel import RecoveryPanel
    entered, release = threading.Event(), threading.Event()

    def recheck(*, keys=None):
        entered.set()
        assert release.wait(4)
        guard._workflow.state = "fixture-recheck-returned"

    guard._workflow.recheck = recheck
    panel = RecoveryPanel(SimpleNamespace(modules={guard.name: guard}))
    native = threading.Thread(target=guard._process_recovery_command)
    try:
        panel.show()
        QApplication.instance().processEvents()
        assert panel._queue("queue_recheck_recovery") is True
        assert len(panel._command_requests) == 1 and panel.progress_view.ring.percent is None
        ticket = next(iter(panel._command_requests.values()))["ticket"]
        native.start()
        assert entered.wait(2)
        panel.refresh()
        assert guard.command_request_snapshot(ticket)["state"] == "running"
        assert "fixture-initial" in panel.status.text()
        assert panel._activities.snapshot()
        panel.hide()
        assert not panel._activities.snapshot() and panel._command_requests
        release.set()
        native.join(3)
        assert not native.is_alive()
        panel.show()
        panel.refresh()
        assert not panel._activities.snapshot() and not panel._command_requests
        assert "completed" in panel.command_progress.text() and "generation 7" in panel.command_progress.text()
        assert "future scheduled drills are separate" in panel.command_progress.text()
    finally:
        release.set()
        if native.ident is not None:
            native.join(3)
            assert not native.is_alive()
        panel.close()
        panel.deleteLater()


def test_recovery_ui_never_accepts_unsettled_or_actionless_completion(guard, monkeypatch):
    from angerona.gui.recovery_panel import RecoveryPanel
    panel = RecoveryPanel(SimpleNamespace(modules={guard.name: guard}))
    try:
        assert panel._queue("queue_recheck_recovery")
        ticket = next(iter(panel._command_requests.values()))["ticket"]
        snapshot = dict(ticket, state="completed", operation_settled=False, action_returned=False)
        monkeypatch.setattr(guard, "command_request_snapshot", lambda _ticket: dict(snapshot))
        panel.refresh()
        assert panel._activities.snapshot() and panel.progress_view.ring.percent is None
        assert "settlement unverified" in panel.progress_view.caption.text()
        snapshot["operation_settled"] = True
        panel.refresh()
        assert not panel._activities.snapshot()
        assert "completion-unverified" in panel.command_progress.text()
    finally:
        panel.close()
        panel.deleteLater()
