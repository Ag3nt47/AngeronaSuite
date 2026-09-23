"""Offscreen wake admission fixtures; no MainWindow or live sensors launched."""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, Signal
from PySide6.QtWidgets import QApplication, QWidget

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.gui.main_window import MainWindow


_APP = None


def _app():
    global _APP
    _APP = QApplication.instance() or QApplication([])
    return _APP


def _until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        _app().processEvents()
        time.sleep(0.002)
    assert predicate()


class _Harness(QWidget):
    _security_event_wake = Signal()
    _init_security_event_reader = MainWindow._init_security_event_reader
    _queue_security_event_wake = MainWindow._queue_security_event_wake
    _request_security_snapshot = MainWindow._request_security_snapshot
    _security_snapshot_status = MainWindow._security_snapshot_status
    _check_threat_animation = MainWindow._check_threat_animation
    _prepare_security_snapshot = MainWindow._prepare_security_snapshot
    _apply_security_snapshot = MainWindow._apply_security_snapshot

    def __init__(self, bus):
        super().__init__()
        self.bus = bus
        self._last_bus_revision = bus.revision()
        self._last_threat_ts = 0.0
        self.observed, self.messages = [], []
        self.dispatches = 0
        self._chill_policy = SimpleNamespace(
            observe_active=lambda events: self.observed.extend(events), tick=lambda: None,
        )
        self.shark_engine = self.red_team_engine = SimpleNamespace(is_running=False)
        self.console = SimpleNamespace(_append=self.messages.append)
        self._handle_usb_approval_events = lambda events: None
        self._update_threat_intel_pulse = lambda: None
        self._notify_critical = lambda events: None
        self._blackbox_feed = self.messages.append
        self._init_security_event_reader()

    def _handle_security_event_wake(self):
        self.dispatches += 1
        MainWindow._handle_security_event_wake(self)


class _LegacyGateHarness(_Harness):
    """Exact prior clear-before-request gate, retaining the same inert reader."""

    def _queue_security_event_wake(self, event):
        if event.severity >= Severity.HIGH and not self._security_wake_pending.is_set():
            self._security_wake_pending.set()
            self._security_event_wake.emit()

    def _handle_security_event_wake(self):
        self.dispatches += 1
        self._security_wake_pending.clear()
        self._security_reader.request()

    def _prepare_security_snapshot(self):
        read = MainWindow._prepare_security_snapshot(self)
        # The prior preparation did not hold the gate across its read.
        self._security_wake_pending.clear()
        return read


def _dispose(window, release=None):
    reader = window._security_reader
    window._security_wake_cleanup()
    if release is not None:
        release.set()
    if reader.thread is not None:
        reader.thread.join(2)
        assert not reader.thread.is_alive()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_blocked_reader_coalesces_interleaved_high_flood_without_qt_dispatch_growth(monkeypatch):
    from angerona.core import threat

    _app()
    entered, release = threading.Event(), threading.Event()
    batches = []

    def classify(events, **_kwargs):
        batches.append(list(events))
        if len(batches) == 1:
            entered.set()
            assert release.wait(10)
        return [event for event in events if event.severity >= Severity.HIGH]

    monkeypatch.setattr(threat, "active_threat_events", classify)
    bus = EventBus(ring_size=64, priority_ring_size=2048)
    window = _Harness(bus)
    try:
        bus.publish(Event("fixture", "first", Severity.HIGH))
        _until(entered.is_set)
        thread = window._security_reader.thread
        start_cursor = window._last_bus_revision
        for index in range(1000):
            bus.publish(Event("fixture", str(index), Severity.CRITICAL))
            bus.publish(Event("noise", str(index), Severity.INFO))
            # Interleave Qt dispatch, reproducing the old flag-clearing bug.
            _app().processEvents()
        assert window.dispatches == 1
        assert len(batches) == 1
        assert window._last_bus_revision == start_cursor
        assert window._security_reader._pending is False
        release.set()
        _until(lambda: len(batches) == 2 and not window._security_reader.busy)
        assert window.dispatches == 1
        assert window._security_reader.thread is thread
        assert len(window.observed) == 1001
        assert {event.message for event in window.observed} == {"first", *map(str, range(1000))}
        assert window._last_bus_revision == bus.revision()
        assert not window._security_wake_pending.is_set()
        assert not window._security_reader._timer.isActive()
    finally:
        _dispose(window, release)


@pytest.mark.parametrize("harness_type,expected_dispatches", [
    (_LegacyGateHarness, 1001), (_Harness, 1),
])
def test_before_after_dispatch_count_for_identical_blocked_flood(
    monkeypatch, harness_type, expected_dispatches,
):
    from angerona.core import threat

    _app()
    entered, release = threading.Event(), threading.Event()

    def classify(events, **_kwargs):
        entered.set()
        assert release.wait(10)
        return list(events)

    monkeypatch.setattr(threat, "active_threat_events", classify)
    bus = EventBus(ring_size=2048, priority_ring_size=2048)
    window = harness_type(bus)
    try:
        bus.publish(Event("fixture", "initial", Severity.HIGH))
        _until(entered.is_set)
        for index in range(1000):
            bus.publish(Event("fixture", str(index), Severity.HIGH))
            _app().processEvents()
        assert window.dispatches == expected_dispatches
    finally:
        _dispose(window, release)


def test_concurrent_publishers_queue_one_initial_wake_and_info_is_idle(monkeypatch):
    from angerona.core import threat

    _app()
    monkeypatch.setattr(threat, "active_threat_events", lambda events, **_kwargs: list(events))
    bus = EventBus(ring_size=64, priority_ring_size=512)
    window = _Harness(bus)
    try:
        for index in range(1000):
            bus.publish(Event("fixture", str(index), Severity.INFO))
        _app().processEvents()
        assert window.dispatches == 0
        assert window._security_reader.thread is None
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda index: bus.publish(Event("fixture", str(index), Severity.HIGH)), range(400)))
        assert window.dispatches == 0
        _until(lambda: window.dispatches and not window._security_reader.busy)
        assert window.dispatches == 1
        assert len(window.observed) == 400
    finally:
        _dispose(window)


def test_failed_busy_read_retries_once_for_arrivals_and_preserves_cursor(monkeypatch):
    from angerona.core import threat

    _app()
    entered, release = threading.Event(), threading.Event()
    batches = []

    def classify(events, **_kwargs):
        batches.append(list(events))
        if len(batches) == 1:
            entered.set()
            assert release.wait(5)
            raise OSError("fixture failure")
        return list(events)

    monkeypatch.setattr(threat, "active_threat_events", classify)
    bus = EventBus()
    window = _Harness(bus)
    try:
        bus.publish(Event("fixture", "retry first", Severity.HIGH))
        _until(entered.is_set)
        cursor = window._last_bus_revision
        bus.publish(Event("fixture", "arrived later", Severity.HIGH))
        assert window._last_bus_revision == cursor
        release.set()
        _until(lambda: len(batches) == 2 and not window._security_reader.busy)
        assert {event.message for event in window.observed} == {"retry first", "arrived later"}
        assert window.dispatches == 2  # initial plus one queued failure retry
        assert window._last_bus_revision == bus.revision()
        assert not window._security_wake_pending.is_set()
    finally:
        _dispose(window, release)


def test_invalidated_generation_cannot_apply_or_add_an_extra_followup(monkeypatch):
    from angerona.core import threat

    _app()
    entered, release = threading.Event(), threading.Event()
    batches = []

    def classify(events, **_kwargs):
        batches.append(list(events))
        if len(batches) == 1:
            entered.set()
            assert release.wait(5)
        return list(events)

    monkeypatch.setattr(threat, "active_threat_events", classify)
    bus = EventBus()
    window = _Harness(bus)
    try:
        bus.publish(Event("fixture", "first generation", Severity.HIGH))
        _until(entered.is_set)
        bus.publish(Event("fixture", "second generation", Severity.HIGH))
        window._security_reader.request(invalidate=True)
        release.set()
        _until(lambda: len(batches) == 2 and not window._security_reader.busy)
        assert len(window.observed) == 2
        assert {event.message for event in window.observed} == {"first generation", "second generation"}
        assert window._last_bus_revision == bus.revision()
        assert window.dispatches == 1
        assert not window._security_wake_pending.is_set()
        assert not window._security_reader._timer.isActive()
    finally:
        _dispose(window, release)


@pytest.mark.parametrize("failure", ["prepare", "thread_start"])
def test_pre_worker_failure_releases_gate_for_next_event(monkeypatch, failure):
    from angerona.core import threat

    _app()
    monkeypatch.setattr(threat, "active_threat_events", lambda events, **_kwargs: list(events))
    bus = EventBus()
    window = _Harness(bus)
    try:
        with monkeypatch.context() as scoped:
            if failure == "prepare":
                scoped.setattr(window._security_reader, "_prepare", lambda: 1 / 0)
            else:
                scoped.setattr(threading.Thread, "start", lambda self: 1 / 0)
            bus.publish(Event("fixture", "failed attempt", Severity.HIGH))
            _app().processEvents()
            assert not window._security_wake_pending.is_set()
            assert not window._security_reader.busy
        bus.publish(Event("fixture", "retry", Severity.HIGH))
        _until(lambda: len(window.observed) == 2 and not window._security_reader.busy)
        assert not window._security_wake_pending.is_set()
    finally:
        _dispose(window)


def test_destroyed_owner_drops_blocked_generation_and_stops_timer(monkeypatch):
    from angerona.core import threat

    _app()
    entered, release = threading.Event(), threading.Event()

    def classify(events, **_kwargs):
        entered.set()
        assert release.wait(5)
        return list(events)

    monkeypatch.setattr(threat, "active_threat_events", classify)
    bus = EventBus()
    window = _Harness(bus)
    bus.publish(Event("fixture", "before destruction", Severity.HIGH))
    _until(entered.is_set)
    reader = window._security_reader
    try:
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert not shiboken6.isValid(window)
        assert reader._closed and reader._stopped.is_set()
        assert window._security_wake_closed.is_set()
        assert not shiboken6.isValid(reader._timer)
        release.set()
        reader.thread.join(2)
        assert not reader.thread.is_alive()
        for index in range(1000):
            bus.publish(Event("fixture", str(index), Severity.CRITICAL))
        _app().processEvents()
        assert window.dispatches == 1
        assert window.observed == []
        assert not window._security_wake_pending.is_set()
    finally:
        release.set()
        reader.close()
