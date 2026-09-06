"""Resolve snapshots must not block Qt or lose policy/bus/selection changes."""
from __future__ import annotations

import threading
import time

import pytest
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QApplication

from angerona.core import drill_resolution, process_allowlist
from angerona.core.eventbus import Event, Severity
from angerona.gui import resolve_center


def _pump_until(predicate, seconds=5):
    app = QApplication.instance()
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate(), "Timed out waiting for asynchronous Resolve snapshot"


def _event(message="distinct detection", *, age=0, details=None):
    return Event("Test Detector", message, Severity.HIGH, time.time() - age,
                 details=details or {})


class _Bus:
    def __init__(self):
        self.events = []

    def recent(self, limit):
        return self.events[:limit]


class _Storage:
    def __init__(self, events):
        self.events = events
        self.reads = 0
        self.token = 1
        self.result = "ok"
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False

    def revision(self):
        return self.token

    def try_recent_in_window(self, *_args):
        self.reads += 1
        self.entered.set()
        if self.block:
            assert self.release.wait(5), "Test did not release the blocked storage reader"
        if self.result == "error":
            raise OSError("temporary fixture reader failure")
        return None if self.result == "busy" else list(self.events)


@pytest.fixture
def centers(monkeypatch):
    dialogs = []
    monkeypatch.setattr(resolve_center.alert_ack, "acked_signatures", lambda: set())
    monkeypatch.setattr(resolve_center.alert_ack, "acked_records", lambda: [])

    def create(storage, bus=None, **kwargs):
        center = resolve_center.ResolveCenter(bus or _Bus(), storage, None, **kwargs)
        center._timer.stop()
        dialogs.append(center)
        return center

    yield create
    for dialog in dialogs:
        dialog.storage.release.set()
    # Wait for held readers to finish before monkeypatches and test isolation end.
    for dialog in dialogs:
        if not dialog._closed.is_set():
            _pump_until(lambda d=dialog: not d._busy)
            dialog.close()


def _refresh(center):
    center._refresh()
    _pump_until(lambda: not center._busy)


def test_blocked_storage_keeps_heartbeat_and_single_flight(centers):
    storage = _Storage([_event()])
    storage.block = True
    started = time.monotonic()
    center = centers(storage)
    assert time.monotonic() - started < 1.0
    _pump_until(storage.entered.is_set)
    beats = []
    heartbeat = QTimer()
    heartbeat.timeout.connect(lambda: beats.append(time.monotonic()))
    heartbeat.start(5)
    try:
        for _ in range(30):
            center._refresh()
        _pump_until(lambda: len(beats) >= 8)
        assert storage.reads == 1
        assert center.table.rowCount() == 0
        assert "Secure" not in center._head.text()
    finally:
        heartbeat.stop()
        storage.release.set()
    _pump_until(lambda: not center._busy and center._snapshot is not None)
    assert center.table.rowCount() == 1
    assert storage.reads == 1  # Coalesced refresh uses the completed history cache.


def test_all_periodic_reads_and_policy_work_stay_off_gui(centers, monkeypatch):
    gui_thread = threading.get_ident()
    calls = []

    def read(name, result):
        def inner(*_args, **_kwargs):
            assert threading.get_ident() != gui_thread, name
            calls.append(name)
            return result
        return inner

    storage = _Storage([_event()])
    monkeypatch.setattr(storage, "revision", read("revision", 1))
    monkeypatch.setattr(storage, "try_recent_in_window", read("database", storage.events))
    monkeypatch.setattr(resolve_center.alert_ack, "acked_signatures", read("ack signatures", set()))
    monkeypatch.setattr(resolve_center.alert_ack, "acked_records", read("ack records", []))
    monkeypatch.setattr(process_allowlist, "policy_snapshot", read("policy", ()))
    monkeypatch.setattr(drill_resolution, "resolution_snapshot", read("resolution", {}))
    center = centers(storage)
    _pump_until(lambda: center._snapshot is not None)
    assert {"revision", "database", "ack signatures", "ack records", "policy", "resolution"} <= set(calls)


@pytest.mark.parametrize("result", ["busy", "error"])
def test_busy_or_error_retains_view_and_retries_without_revision_change(centers, result):
    first, second = _event("first detection"), _event("second detection")
    storage = _Storage([first])
    center = centers(storage)
    _pump_until(lambda: center._snapshot is not None)
    storage.events = [second]
    storage.token += 1
    storage.result = result
    _refresh(center)
    assert center._selected_event() is first
    assert "previous view" in center._status.text()
    storage.result = "ok"
    _refresh(center)
    assert center._events() == [second]
    assert center._selected_event() is None  # Never retarget an operator action.
    assert storage.reads == 3


def test_cache_observes_bus_same_count_acks_and_time_expiry(centers, monkeypatch):
    first, second = _event("alpha detection"), _event("beta detection")
    signatures = {resolve_center.alert_ack.signature(first)}
    monkeypatch.setattr(resolve_center.alert_ack, "acked_signatures", lambda: set(signatures))
    storage = _Storage([first, second])
    bus = _Bus()
    center = centers(storage, bus, window_s=10)
    _pump_until(lambda: center._snapshot is not None)
    assert center._events() == [second]
    signatures.clear()
    signatures.add(resolve_center.alert_ack.signature(second))
    _refresh(center)
    assert center._events() == [first]
    third = _event("gamma detection")
    bus.events = [third]
    _refresh(center)
    assert center._events() == [third, first]
    assert storage.reads == 1
    future = time.time() + 11
    monkeypatch.setattr(resolve_center.time, "time", lambda: future)
    _refresh(center)
    assert center._events() == []
    assert "Secure" in center._head.text()
    assert storage.reads == 1


def test_history_outlives_posture_window_and_result_polling_stops_when_idle(centers):
    old = _event("older unresolved alert", age=601)
    storage = _Storage([old])
    center = centers(storage)
    _pump_until(lambda: center._snapshot is not None)
    assert center._events() == [old]
    assert "Secure" in center._head.text()
    assert not center._result_timer.isActive()
    _refresh(center)
    assert not center._result_timer.isActive()
    assert storage.reads == 1


def test_selection_survives_new_records_reordering_and_history_reloads(centers):
    first, target = _event("alpha", age=2), _event("target", age=1)
    storage = _Storage([first, target])
    center = centers(storage)
    _pump_until(lambda: center._snapshot is not None)
    center.table.sortItems(3, Qt.SortOrder.AscendingOrder)
    center.table.selectRow(1)
    assert center._selected_event() is target
    copy = Event(target.module, target.message, target.severity, target.ts, target.details)
    storage.events = [first, copy, _event("beta")]
    storage.token += 1
    _refresh(center)
    assert center._selected_event() is copy
    assert center.table.currentRow() == 2


def test_legacy_weak_signals_leave_resolve_without_ack_but_confirmed_threat_stays(
        centers, monkeypatch):
    now = time.time()
    weak = [
        Event("Memory Injection Scanner", "RWX page in a desktop application",
              Severity.HIGH, now, {"active_attack": True,
                                   "detector_policy": "rwx-memory-indicator-alert-only"}),
        Event("Ransomware Heuristics", "High-entropy music file",
              Severity.HIGH, now, {"active_attack": True,
                                   "detector_policy": "reviewed-semantic-indicator",
                                   "path": "music.mp3", "entropy": 7.96, "threshold": 7.9}),
        Event("C2 Beacon Detector", "Regular service callbacks",
              Severity.HIGH, now, {"active_attack": True,
                                   "detector_policy": "cadence-indicator-alert-only",
                                   "threat_intel_corroborated": False}),
    ]
    confirmed = Event("Memory Injection Scanner", "Corroborated execution evidence",
                      Severity.HIGH, now, {"active_exploitation": True,
                                           "detector_policy": "rwx-memory-indicator-alert-only"})

    def no_ack(*_args, **_kwargs):
        raise AssertionError("Classification must not acknowledge original evidence")

    monkeypatch.setattr(resolve_center.alert_ack, "ack", no_ack)
    storage = _Storage([*weak, confirmed])
    center = centers(storage)
    _pump_until(lambda: center._snapshot is not None)
    assert center._events() == [confirmed]
    assert len(storage.events) == 4
    assert all(event.severity == Severity.HIGH for event in storage.events)
    assert "High" in center._head.text()


def test_operator_action_discards_inflight_snapshot(centers, monkeypatch):
    event = _event()
    storage = _Storage([event])
    center = centers(storage)
    _pump_until(lambda: center._snapshot is not None)
    read = center._reader.read
    returned = threading.Event()
    release = threading.Event()
    calls = []
    signatures = set()
    monkeypatch.setattr(resolve_center.alert_ack, "acked_signatures", lambda: set(signatures))
    monkeypatch.setattr(resolve_center.alert_ack, "ack", lambda ev, _reason: signatures.add(
        resolve_center.alert_ack.signature(ev)))

    def blocked_read(*, force=False):
        result = read(force=force)
        calls.append(result)
        if len(calls) == 1:
            returned.set()
            assert release.wait(5)
        return result

    monkeypatch.setattr(center._reader, "read", blocked_read)
    rendered = []
    render = center._render_page

    def track_render(**kwargs):
        rendered.append(center._events())
        return render(**kwargs)

    monkeypatch.setattr(center, "_render_page", track_render)
    center._refresh()
    _pump_until(returned.is_set)
    try:
        center._ignore(event)
        release.set()
        _pump_until(lambda: not center._busy)
    finally:
        release.set()
    assert rendered == [[]]
    assert len(calls) == 2


def test_closing_blocked_dialog_drops_result_and_releases_global_slot(centers, monkeypatch):
    # A close cannot interrupt an existing SQLite read, but must neither wait
    # for it nor leave any Qt access in the reader's eventual completion path.
    gate = threading.BoundedSemaphore(1)
    monkeypatch.setattr(resolve_center, "_READERS", gate)
    storage = _Storage([_event()])
    storage.block = True
    center = centers(storage)
    _pump_until(storage.entered.is_set)
    results = center._results
    closed = center._closed
    started = time.monotonic()
    center.close()
    assert time.monotonic() - started < 0.5
    assert closed.is_set()
    storage.release.set()
    acquired = []

    def released():
        if acquired:
            return True
        if gate.acquire(blocking=False):
            acquired.append(True)
        return bool(acquired)

    _pump_until(released)
    gate.release()
    assert results.empty()


def test_global_worker_limit_bounds_reopened_dialogs(centers, monkeypatch):
    monkeypatch.setattr(resolve_center, "_READERS", threading.BoundedSemaphore(1))
    storage = _Storage([_event()])
    storage.block = True
    first = centers(storage)
    _pump_until(storage.entered.is_set)
    other_storage = _Storage([_event("other")])
    second = centers(other_storage)
    for _ in range(10):
        second._refresh()
    assert other_storage.reads == 0
    assert "busy" in second._status.text()
    storage.release.set()
    _pump_until(lambda: not first._busy)
    _refresh(second)
    assert other_storage.reads == 1
    assert second.table.rowCount() == 1
