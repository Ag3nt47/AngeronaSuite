"""Long-session refresh budgets and blocked-history GUI regression checks."""
from __future__ import annotations

import gc
import threading
import time
import weakref
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QWidget

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import EventsWindow


def _settle(reader):
    deadline = time.monotonic() + 4
    while reader.busy and time.monotonic() < deadline:
        reader._poll()
        time.sleep(0.001)
    assert not reader.busy


def _heartbeat(owner):
    ticks = []
    timer = QTimer(owner)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start(10)
    return ticks, timer


def test_repeated_snapshots_reuse_one_worker_and_release_payloads(monkeypatch):
    owner = QWidget()
    starts, references = [], []
    original = threading.Thread.start

    def start(thread):
        if thread.name == "LongSessionProbe":
            starts.append(thread)
        original(thread)

    class Payload:
        pass

    def read():
        value = Payload()
        references.append(weakref.ref(value))
        return value

    monkeypatch.setattr(threading.Thread, "start", start)
    applied = []
    reader = AsyncSnapshot(
        owner, lambda: read, lambda _value: applied.append(1), name="LongSessionProbe",
    )
    try:
        for _ in range(250):
            reader.request()
            _settle(reader)
        gc.collect()
        assert len(applied) == 250
        assert len(starts) == 1
        assert all(reference() is None for reference in references)
        assert reader._results.empty()
    finally:
        reader.close()
        if reader.thread is not None:
            reader.thread.join(2)
            assert not reader.thread.is_alive()
        owner.deleteLater()


def test_blocked_snapshot_close_is_immediate_and_worker_exits():
    owner = QWidget()
    entered, release = threading.Event(), threading.Event()
    applied = []

    def read():
        entered.set()
        assert release.wait(4)
        return 1

    reader = AsyncSnapshot(owner, lambda: read, applied.append, name="CloseProbe")
    try:
        reader.request()
        assert entered.wait(1)
        start = time.monotonic()
        reader.close()
        assert time.monotonic() - start < 0.1
        release.set()
        reader.thread.join(2)
        assert not reader.thread.is_alive()
        reader._poll()
        assert applied == []
    finally:
        release.set()
        reader.close()
        owner.deleteLater()


class _HistoryHarness(QWidget):
    _prepare_aria_history_snapshot = MainWindow._prepare_aria_history_snapshot
    _apply_aria_history_snapshot = MainWindow._apply_aria_history_snapshot

    def __init__(self, history):
        super().__init__()
        self.aria_history = history
        self._aria_history_snapshot = ("old", -2)
        self.label = QLabel("old", self)
        self.aria_hud = SimpleNamespace(
            refresh=lambda: self.label.setText(self._aria_history_snapshot[0]),
        )


def test_aria_history_reads_leave_qt_free_and_preserve_previous_on_failure():
    entered, release = threading.Event(), threading.Event()
    calls = []

    def sparkline(_width):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(4)
        return "new"

    history = SimpleNamespace(sparkline=sparkline, trend=lambda: {"delta": 7})
    owner = _HistoryHarness(history)
    reader = AsyncSnapshot(
        owner, owner._prepare_aria_history_snapshot, owner._apply_aria_history_snapshot,
        name="HistoryProbe",
    )
    ticks, timer = _heartbeat(owner)
    try:
        reader.request()
        assert entered.wait(1)
        for _ in range(50):
            reader.request()
        QTest.qWait(120)
        assert len(ticks) >= 3
        assert len(calls) == 1
        assert owner.label.text() == "old"
        release.set()
        _settle(reader)
        assert owner._aria_history_snapshot == ("new", 7)
        assert owner.label.text() == "new"
        assert all(ident != threading.get_ident() for ident in calls)
        history.sparkline = lambda _width: 1 / 0
        reader.request()
        _settle(reader)
        assert owner._aria_history_snapshot == ("new", 7)
    finally:
        release.set()
        timer.stop()
        reader.close()
        owner.deleteLater()


@pytest.mark.parametrize("active_only", [False, True])
def test_event_history_blocked_read_preserves_gui_rows_and_filters(monkeypatch, active_only):
    from angerona.gui import pages

    entered, release = threading.Event(), threading.Event()
    calls, policy_threads = [], []
    now = time.time()
    event = Event("Detector", "confirmed", Severity.HIGH, ts=now - 1)
    old = Event("Detector", "expired", Severity.HIGH, ts=now - 86401)
    low = Event("Detector", "low", Severity.LOW, ts=now - 1)

    def read(*_args):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(4)
        return [low, old, event]

    def classify(events, **_kwargs):
        policy_threads.append(threading.get_ident())
        return events

    monkeypatch.setattr(pages, "active_threat_events", classify)
    storage = SimpleNamespace(try_recent_in_window=read)
    dialog = EventsWindow("Events", EventBus(), storage, Severity.HIGH, active_only=active_only)
    ticks, timer = _heartbeat(dialog)
    try:
        assert entered.wait(1)
        for _ in range(30):
            dialog._refresh()
        QTest.qWait(120)
        assert len(ticks) >= 3
        assert calls and len(calls) == 1
        release.set()
        _settle(dialog._events_reader)
        assert dialog.table.rowCount() == 1
        assert all(ident != threading.get_ident() for ident in calls + policy_threads)
        for failure in (lambda *_args: None, lambda *_args: 1 / 0):
            storage.try_recent_in_window = failure
            dialog._refresh()
            _settle(dialog._events_reader)
            assert dialog.table.rowCount() == 1
            assert "unavailable" in dialog.count_lbl.text()
    finally:
        release.set()
        timer.stop()
        dialog.close()
        dialog._events_reader.thread.join(2)
        dialog.deleteLater()
        QApplication.instance().processEvents()
