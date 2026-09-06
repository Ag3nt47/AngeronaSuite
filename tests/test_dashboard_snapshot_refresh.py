from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.gui import pages
from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.gui.main_window import MainWindow


_APP = None


def _app():
    global _APP
    _APP = QApplication.instance() or QApplication([])
    return _APP


def _until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        _app().processEvents()
        time.sleep(0.005)
    assert predicate()


def _heartbeat(owner):
    ticks = []
    timer = QTimer(owner)
    timer.setInterval(10)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    return ticks, timer


class _Storage:
    def revision(self):
        return 1

    def try_count_since(self, _since):
        return 12


def test_cards_policy_io_is_bounded_and_does_not_block_qt(monkeypatch):
    _app()
    entered, release = threading.Event(), threading.Event()
    calls = []
    event = Event("Detector", "active", Severity.HIGH)

    def read(_events):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        return [event]

    monkeypatch.setattr(pages, "active_threat_events", read)
    cards = pages.DashboardCards(EventBus(), _Storage(), SimpleNamespace(modules={}))
    ticks, timer = _heartbeat(cards)
    try:
        cards.c_threat.set("Critical")
        cards.refresh()
        assert entered.wait(1)
        for _ in range(30):
            cards.refresh()
        QTest.qWait(100)
        assert len(ticks) >= 3
        assert len(calls) == 1
        assert cards.c_threat.value.text() == "Critical"
        release.set()
        _until(lambda: not cards._threat_reader.busy)
        assert len(calls) == 2
        assert all(ident != threading.get_ident() for ident in calls)
        assert cards.c_threat.value.text() == "High"
        monkeypatch.setattr(pages, "active_threat_events", lambda _events: 1 / 0)
        cards.refresh()
        _until(lambda: not cards._threat_reader.busy)
        assert cards.c_threat.value.text() == "High"
        assert "unavailable" in cards.c_threat.toolTip()
    finally:
        release.set()
        timer.stop()
        cards.close()


def test_snapshot_thread_start_failure_can_retry(monkeypatch):
    _app()
    owner, values = QWidget(), []
    reader = AsyncSnapshot(owner, lambda: lambda: 7, values.append, name="StartProbe")
    original = threading.Thread.start
    try:
        monkeypatch.setattr(threading.Thread, "start", lambda _self: 1 / 0)
        reader.request()
        assert not reader.busy
        monkeypatch.setattr(threading.Thread, "start", original)
        reader.request()
        _until(lambda: not reader.busy)
        assert values == [7]
    finally:
        reader.close()
        owner.close()


def test_snapshot_drops_closed_owner_and_stale_generation():
    _app()
    owner, values = QWidget(), []
    entered, release = threading.Event(), threading.Event()
    counter = []

    def prepare():
        index = len(counter)
        counter.append(index)

        def read():
            entered.set()
            assert release.wait(3)
            return index

        return read

    reader = AsyncSnapshot(owner, prepare, values.append, name="GenerationProbe")
    try:
        reader.request()
        assert entered.wait(1)
        reader.request(invalidate=True)
        release.set()
        _until(lambda: not reader.busy)
        assert values == [1]
        release.clear()
        entered.clear()
        reader.request()
        assert entered.wait(1)
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert not shiboken6.isValid(owner)
        release.set()
        reader.thread.join(2)
        _app().processEvents()
        assert values == [1]
    finally:
        release.set()
        reader.close()


class _SecurityHarness(QWidget):
    _check_threat_animation = MainWindow._check_threat_animation
    _prepare_security_snapshot = MainWindow._prepare_security_snapshot
    _apply_security_snapshot = MainWindow._apply_security_snapshot

    def __init__(self, bus):
        super().__init__()
        self.bus = bus
        self._last_bus_revision = bus.revision()
        self._last_threat_ts = time.time()
        self.observed = []
        self._chill_policy = SimpleNamespace(
            observe_active=lambda events: self.observed.extend(events), tick=lambda: None,
        )
        self.shark_engine = self.red_team_engine = SimpleNamespace(is_running=False)
        self.console = SimpleNamespace(_append=lambda message: None)
        self._handle_usb_approval_events = lambda events: None
        self._update_threat_intel_pulse = lambda: None
        self._notify_critical = lambda events: None
        self._security_reader = AsyncSnapshot(
            self, self._prepare_security_snapshot, self._apply_security_snapshot,
            name="SecurityTestReader",
        )


def test_security_wake_delivers_high_arriving_during_busy_reader(monkeypatch):
    from angerona.core import threat

    _app()
    entered, release = threading.Event(), threading.Event()
    calls = []

    def classify(events, window):
        calls.append(list(events))
        entered.set()
        assert release.wait(3)
        return [event for event in events if event.severity >= Severity.HIGH]

    monkeypatch.setattr(threat, "active_threat_events", classify)
    bus = EventBus()
    window = _SecurityHarness(bus)
    ticks, timer = _heartbeat(window)
    try:
        first = Event("Detector", "first", Severity.HIGH)
        bus.publish(first)
        window._check_threat_animation()
        assert entered.wait(1)
        cursor = window._last_bus_revision
        second = Event("Detector", "second", Severity.CRITICAL)
        bus.publish(second)
        for index in range(200):
            bus.publish(Event("Telemetry", str(index), Severity.INFO))
            window._check_threat_animation()
        QTest.qWait(100)
        assert len(ticks) >= 3
        assert window._last_bus_revision == cursor
        assert len(calls) == 1
        release.set()
        _until(lambda: not window._security_reader.busy)
        assert [event.message for event in window.observed] == ["first", "second"]
        assert len(calls) == 2
        assert window._last_bus_revision == bus.revision()
    finally:
        release.set()
        timer.stop()
        window._security_reader.close()
        window.close()


def test_soar_refresh_and_selection_use_background_snapshot(monkeypatch):
    _app()
    entered, release = threading.Event(), threading.Event()
    calls = []
    record = {"request_id": "a" * 32, "ts": time.time(), "status": "PENDING"}

    def read(**_kwargs):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        return [record]

    monkeypatch.setattr(pages, "_read_soar_queue", read)
    monkeypatch.setattr(pages, "_reconcile_soar_submission_receipts", lambda *_: False)
    panel = pages.SoarPanel(EventBus())
    ticks, timer = _heartbeat(panel)
    try:
        panel.refresh()
        assert entered.wait(1)
        for _ in range(20):
            panel.refresh()
        QTest.qWait(100)
        assert len(ticks) >= 3
        assert len(calls) == 1
        release.set()
        _until(lambda: not panel._queue_reader.busy)
        assert panel.table.rowCount() == 1
        count = len(calls)
        panel.table.selectRow(0)
        for _ in range(10):
            panel._sync_action_buttons()
        assert len(calls) == count
        assert all(ident != threading.get_ident() for ident in calls)
        monkeypatch.setattr(pages, "_read_soar_queue", lambda **_: 1 / 0)
        panel.refresh()
        _until(lambda: not panel._queue_reader.busy)
        assert panel.table.rowCount() == 1
        assert "unavailable" in panel._status.toolTip()
    finally:
        release.set()
        timer.stop()
        panel.close()


def test_legacy_observation_detail_keeps_record_and_disables_block():
    _app()
    event = Event("Memory Injection Scanner", "Suspicious RWX memory", Severity.HIGH,
                  details={"detector_policy": "rwx-memory-indicator-alert-only", "active_attack": True})
    dialog = pages.AlertDetailDialog(event)
    try:
        assessment = dialog.findChild(QLabel, "alertEvidenceAssessment")
        assert "Observation" in assessment.text()
        assert "HIGH" in dialog._record_body.toPlainText().upper()
        block = next(button for button in dialog.findChildren(QPushButton)
                     if button.text() == "Block")
        assert not block.isEnabled()
    finally:
        dialog.close()


class _PostureHarness(QWidget):
    _refresh_posture = MainWindow._refresh_posture
    _prepare_posture_snapshot = MainWindow._prepare_posture_snapshot
    _apply_posture_snapshot = MainWindow._apply_posture_snapshot

    def __init__(self):
        super().__init__()
        self.bus = EventBus()
        self.manager = SimpleNamespace(modules={})
        self.config = None
        self.posture_lbl = QLabel("POSTURE 40 · High", self)
        self._posture_reader = AsyncSnapshot(
            self, self._prepare_posture_snapshot, self._apply_posture_snapshot,
            name="PostureTestReader",
        )


def test_posture_keeps_previous_label_during_slow_read_and_failure(monkeypatch):
    from angerona.core import posture, threat

    _app()
    entered, release = threading.Event(), threading.Event()

    def kev():
        entered.set()
        assert release.wait(3)
        return 0, 0

    monkeypatch.setattr(posture, "_kev_penalty", kev)
    monkeypatch.setattr(posture, "_attack_penalty", lambda: 0)
    classifications = []
    monkeypatch.setattr(threat, "active_threat_events", lambda events: classifications.append(1) or [])
    window = _PostureHarness()
    ticks, timer = _heartbeat(window)
    try:
        window._refresh_posture()
        assert entered.wait(1)
        QTest.qWait(100)
        assert len(ticks) >= 3
        assert window.posture_lbl.text() == "POSTURE 40 · High"
        release.set()
        _until(lambda: not window._posture_reader.busy)
        assert classifications == [1]
        assert window.posture_lbl.text() == "POSTURE 100 · Secure"
        monkeypatch.setattr(threat, "active_threat_events", lambda events: 1 / 0)
        window.posture_lbl.setText("POSTURE 40 · High")
        window._refresh_posture()
        _until(lambda: not window._posture_reader.busy)
        assert window.posture_lbl.text() == "POSTURE 40 · High"
    finally:
        release.set()
        timer.stop()
        window._posture_reader.close()
        window.close()


def test_security_classification_failure_keeps_cursor_for_retry(monkeypatch):
    from angerona.core import threat

    _app()
    bus = EventBus()
    window = _SecurityHarness(bus)
    start = window._last_bus_revision
    event = Event("Detector", "retry me", Severity.HIGH)
    bus.publish(event)
    monkeypatch.setattr(threat, "active_threat_events", lambda *args, **kwargs: 1 / 0)
    try:
        window._check_threat_animation()
        _until(lambda: not window._security_reader.busy)
        assert window._last_bus_revision == start
        assert window.observed == []
        monkeypatch.setattr(threat, "active_threat_events", lambda events, **kwargs: list(events))
        window._check_threat_animation()
        _until(lambda: not window._security_reader.busy)
        assert [event.message for event in window.observed] == ["retry me"]
        assert window._last_bus_revision == bus.revision()
    finally:
        window._security_reader.close()
        window.close()
