"""Cached-only, nonmodal telemetry controls with inert policy and queue owners."""
from __future__ import annotations

from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton, QWidget
from shiboken6 import delete, isValid

from angerona.core.config import Config
from angerona.core.telemetry_storage_policy import STORAGE_REASONS
from angerona.gui import telemetry_storage_controls as gui


def _snapshot():
    return dict(schema=1, configured=True, state="ready", reason_code="", policy_generation=1,
        facts_generation=1, blocked=False, db_target_bytes=256 * gui.MIB, wal_target_bytes=64 * gui.MIB,
        min_free_bytes=2048 * gui.MIB, unit_limit_bytes=gui.MIB, db_bytes=40 * gui.MIB,
        wal_bytes=2 * gui.MIB, shm_bytes=32768, free_bytes=10000 * gui.MIB,
        facts_observed_monotonic=100.0, facts_age_seconds=0.1, facts_stale=False, probe_pending=False,
        storage_pending_events=0, parked_primary_events=0, parked_overflow_events=0,
        rejection_storage_hold=0, storage_user_discarded=0, storage_write_failures=0, storage_hold_attempts=0,
        replay_deferred=0, maintenance_deferred=0, coverage_gap=False,
        scope="telemetry-writer-only", shared_database=True, no_os_quota=True,
        no_response_reserve=True, durable=False)


class Recorder:
    def __init__(self):
        self.state = _snapshot()
        self.calls, self.discards = [], []
        self.snapshots = 0
        self.token = "a" * 32
        self.review_changes = {}
        self.refuse = False

    def storage_budget_snapshot(self):
        self.snapshots += 1
        return dict(self.state, private_path="must-not-be-presented")

    def configure_storage_policy(self, **policy):
        self.calls.append(policy)
        if self.refuse:
            raise RuntimeError("private writer exception")
        generation = self.state["policy_generation"] + 1
        self.state.update(policy, configured=True, policy_generation=generation, facts_stale=True,
                          probe_pending=True, state="held" if policy["blocked"] else "unmeasured",
                          reason_code="operator_blocked" if policy["blocked"] else "facts_unmeasured")
        return dict(schema=1, accepted=True, policy_generation=generation,
                    reason_code=self.state["reason_code"], probe_pending=True)

    def held_unit_review(self, lane):
        return {**dict(schema=1, available=True, discard_allowed=True, reason_code="unit_too_large",
                       lane=lane, token=self.token, policy_generation=self.state["policy_generation"],
                       worker_generation=1, pending_generation=3, event_count=1,
                       serialized_bytes=2 * gui.MIB, volatile=True, in_flight=False), **self.review_changes}

    def discard_held_unit(self, **selected):
        self.discards.append(selected)
        accepted = selected["token"] == self.token and selected["policy_generation"] == self.state["policy_generation"]
        if accepted:
            self.state.update(storage_pending_events=0, parked_primary_events=0,
                              storage_user_discarded=1, coverage_gap=True)
        return dict(schema=1, accepted=accepted, discarded_events=int(accepted), reason_code="reviewed")


@pytest.fixture
def scene(tmp_path):
    app = QApplication.instance()
    assert app is not None
    config, recorder, parent = Config(data_dir=tmp_path), Recorder(), QWidget()
    manager = SimpleNamespace(recorder=recorder)
    opened, objects = [], []
    state = SimpleNamespace(app=app, config=config, recorder=recorder, parent=parent,
                            manager=manager, opened=opened, objects=objects)
    try:
        yield state
    finally:
        for widget in objects:
            if isinstance(widget, gui.TelemetryStorageWarningController):
                widget.close()
            elif isValid(widget):
                widget.close()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        if isValid(parent):
            delete(parent)
        app.processEvents()


def controls(scene):
    widget = gui.TelemetryStorageControls(scene.config, scene.manager, scene.parent)
    scene.objects.append(widget)
    return widget


def warning(scene):
    owner = gui.TelemetryStorageWarningController(scene.config, scene.manager, scene.parent, scene.opened.append)
    scene.objects.append(owner)
    return owner


def click(dialog, text):
    next(button for button in dialog.buttons() if text in button.text()).click()
    QApplication.processEvents()


def test_constructor_refresh_and_warning_consume_only_cached_memory(scene, monkeypatch):
    attempts = []
    def forbidden(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("No GUI capacity or SQLite probe")
    with monkeypatch.context() as denied:
        denied.setattr(Path, "stat", forbidden)
        denied.setattr(Path, "lstat", forbidden)
        denied.setattr(shutil, "disk_usage", forbidden)
        denied.setattr(sqlite3, "connect", forbidden)
        widget, owner = controls(scene), warning(scene)
        widget.refresh()
        owner.poll()
        view = gui.telemetry_storage_snapshot(scene.recorder)
        assert view is not None and view["state"] == "ready"
        assert "private_path" not in view and "must-not-be-presented" not in widget.usage.text()
        assert owner._warning is None
    assert attempts == [] and scene.recorder.snapshots >= 4


def test_block_allow_and_candidate_save_are_distinct_from_runtime_choices(scene):
    widget = controls(scene)
    widget._block()
    assert scene.recorder.calls[-1]["blocked"] is True
    assert scene.config.telemetry_storage_blocked is False and not scene.config.settings_path.exists()
    widget.fields["telemetry_db_target_mib"].setValue(512)
    widget._allow()
    assert scene.recorder.calls[-1] == dict(blocked=False, db_target_bytes=512 * gui.MIB,
                                           wal_target_bytes=64 * gui.MIB, min_free_bytes=2048 * gui.MIB)
    assert "Policy accepted" in widget.result.text() and "fresh worker check" in widget.result.text()
    assert scene.config.telemetry_db_target_mib == 256
    assert "Waiting for worker" in widget.usage.text()
    widget.write_candidate(scene.config)
    assert scene.config.telemetry_db_target_mib == 512 and scene.config.telemetry_storage_blocked is False


def test_refused_policy_stays_visible_and_retry_is_explicit(scene):
    widget, owner = controls(scene), warning(scene)
    scene.recorder.refuse = True
    widget._block()
    assert "unverified" in widget.result.text() and scene.config._telemetry_storage_policy_pending
    owner.poll()
    dialog = owner._warning
    assert dialog is not None and not dialog.isModal()
    assert "private writer exception" not in dialog.text()
    before = len(scene.recorder.calls)
    owner.poll()
    assert len(scene.recorder.calls) == before
    scene.recorder.refuse = False
    click(dialog, "Retry saved")
    assert len(scene.recorder.calls) == before + 1
    assert not scene.config._telemetry_storage_policy_pending and not scene.config._telemetry_storage_apply_note


def test_nonmodal_warning_leaves_parent_stop_usable_and_change_routes_to_system(scene):
    scene.recorder.state.update(state="held", reason_code="db_target", db_bytes=300 * gui.MIB)
    owner = warning(scene)
    activations = []
    button = QPushButton("STOP fixture", scene.parent)
    button.clicked.connect(lambda: activations.append(True))
    scene.parent.show()
    owner.poll()
    dialog = owner._warning
    assert dialog is not None and dialog.windowModality() == Qt.NonModal
    assert dialog.property("_angerona_no_reveal") is True
    assert scene.app.activeModalWidget() is not dialog
    QTest.mouseClick(button, Qt.LeftButton)
    assert activations == [True]
    owner.poll()
    assert owner._warning is dialog
    click(dialog, "change targets")
    assert scene.opened == ["System"] and not scene.recorder.calls


def test_warning_block_preserves_latest_active_targets_without_saving(scene):
    scene.recorder.state.update(state="held", reason_code="db_target", db_bytes=600 * gui.MIB)
    owner = warning(scene)
    owner.poll()
    scene.recorder.state.update(db_target_bytes=512 * gui.MIB + 1, policy_generation=2, facts_generation=2)
    click(owner._warning, "Block")
    assert scene.recorder.calls[-1]["blocked"] is True
    assert scene.recorder.calls[-1]["db_target_bytes"] == 512 * gui.MIB + 1
    assert scene.config.telemetry_db_target_mib == 256
    assert not scene.config.telemetry_storage_blocked and not scene.config.settings_path.exists()


def test_warning_acknowledgments_are_bounded_across_policy_changes(scene):
    scene.recorder.state.update(state="held", reason_code="db_target", db_bytes=300 * gui.MIB)
    owner = warning(scene)
    for generation in range(1, 67):
        scene.recorder.state.update(policy_generation=generation, facts_generation=generation)
        owner.poll()
        assert owner._warning is not None
        click(owner._warning, "Keep current")
    assert len(owner._acknowledged) <= 64 and not scene.recorder.calls


@pytest.mark.parametrize("change", [
    {"db_bytes": "40"}, {"schema": True}, {"blocked": 1}, {"no_os_quota": False},
    {"state": "ready", "facts_stale": True}, {"state": "ready", "probe_pending": True},
    {"storage_pending_events": 0, "parked_primary_events": 1},
    {"coverage_gap": False, "rejection_storage_hold": 1},
])
def test_malformed_status_does_not_advertise_ready_or_zero_loss(scene, change):
    scene.recorder.state.update(change)
    assert gui.telemetry_storage_snapshot(scene.recorder) is None
    widget = controls(scene)
    assert "status unavailable" in widget.usage.text()
    assert "Pending telemetry status unavailable" in widget.pending.text()


def test_missing_nullable_key_is_unavailable_and_stale_oversized_reason_stays_actionable(scene):
    del scene.recorder.state["db_bytes"]
    assert gui.telemetry_storage_snapshot(scene.recorder) is None
    scene.recorder.state = _snapshot()
    scene.recorder.state.update(state="held", reason_code="unit_too_large", facts_stale=True,
                                policy_generation=2, storage_pending_events=1, parked_primary_events=1)
    text = gui.telemetry_storage_usage(gui.telemetry_storage_snapshot(scene.recorder))
    assert "exceeds the bounded write unit" in text


@pytest.mark.parametrize("reason", sorted(STORAGE_REASONS))
def test_every_fixed_storage_reason_has_plain_formatter_text(reason):
    assert set(gui._REASONS) == STORAGE_REASONS
    snapshot = _snapshot()
    snapshot.update(reason_code=reason, state="held" if reason else "ready")
    text = gui.telemetry_storage_usage(snapshot)
    assert gui._REASONS[reason] in text
    assert "Cumulative deferral attempts this instance: replay 0; maintenance 0." in text


def test_usage_separates_failure_counters_from_cumulative_deferred_attempts():
    snapshot = _snapshot()
    snapshot.update(rejection_storage_hold=3, storage_write_failures=4,
                    storage_user_discarded=2, coverage_gap=True,
                    replay_deferred=7, maintenance_deferred=9)
    text = gui.telemetry_storage_usage(snapshot)
    assert "rejected 3; failed or unconfirmed writes 4; discarded queued copies 2" in text
    assert "Cumulative deferral attempts this instance: replay 7; maintenance 9." in text
    assert "do not establish a current durable backlog" in text
    assert "oversized replay line needs offline review" in text
    assert "does not discard originals" in text


@pytest.mark.parametrize("choice", ["no", "escape", "close", "owner_close"])
def test_review_confirmation_no_escape_and_close_never_discard(scene, choice):
    widget = controls(scene)
    widget._review_unit()
    dialog = widget._review_dialog
    assert dialog is not None and not dialog.isModal() and dialog.defaultButton() is dialog.button(QMessageBox.No)
    assert dialog.property("_angerona_no_reveal") is True and not scene.recorder.discards
    assert "earlier uncertain write" in dialog.text() and "another subscriber" in dialog.text()
    if choice == "no":
        dialog.button(QMessageBox.No).click()
    elif choice == "escape":
        QTest.keyClick(dialog, Qt.Key_Escape)
    elif choice == "close":
        dialog.close()
    else:
        widget.close()
    scene.app.processEvents()
    assert not scene.recorder.discards


@pytest.mark.parametrize("stale", [False, True])
def test_yes_submits_only_the_exact_reviewed_volatile_unit(scene, stale):
    scene.recorder.state.update(state="held", reason_code="unit_too_large", storage_pending_events=1,
                                parked_primary_events=1)
    widget = controls(scene)
    widget._review_unit()
    if stale:
        scene.recorder.token = "b" * 32
    widget._review_dialog.button(QMessageBox.Yes).click()
    scene.app.processEvents()
    assert scene.recorder.discards == [dict(lane="primary", token="a" * 32, policy_generation=1,
                                           worker_generation=1, pending_generation=3)]
    if stale:
        assert "not verified" in widget.result.text()
    else:
        assert "queued copy was discarded" in widget.result.text()
    assert scene.recorder.state["coverage_gap"] is (not stale)


@pytest.mark.parametrize("field,value", [
    ("token", "not-a-review-token"), ("reason_code", "db_target"),
    ("in_flight", True), ("event_count", True), ("discard_allowed", False),
])
def test_invalid_or_nonoversized_review_never_opens_destructive_choice(scene, field, value):
    # Replace one field without changing the independent cached status.
    original = scene.recorder.held_unit_review
    scene.recorder.held_unit_review = lambda lane: {**original(lane), field: value}
    widget = controls(scene)
    widget._review_unit()
    assert widget._review_dialog is None and not scene.recorder.discards


def test_closing_controls_and_controller_stops_timers_without_policy_mutation(scene):
    scene.recorder.state.update(state="held", reason_code="db_target", db_bytes=300 * gui.MIB)
    widget, owner = controls(scene), warning(scene)
    owner.poll()
    owner.close()
    widget.close()
    scene.app.processEvents()
    assert not owner._timer.isActive() and not widget._timer.isActive()
    assert not scene.recorder.calls and not scene.recorder.discards
