"""Actual fixture streams; no host endpoint, policy mutation or operator PID.

The false-wait gate models the finished-before-native-retirement protocol. It
does not claim to inject Windows TLS cleanup or reproduce an OS scheduler race.
"""
from __future__ import annotations

from collections import deque
import threading
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import live_debug_panel as streams


class FakeClient:
    def __init__(self, records=()):
        self.records = deque(records)
        self.entered = threading.Event()
        self.canceled = threading.Event()
        self.closed = threading.Event()
        self.calls = []

    def connect(self, timeout):
        self.calls.append(("connect", timeout, threading.get_ident()))

    def read(self, timeout):
        self.entered.set()
        if self.records:
            return self.records.popleft()
        self.canceled.wait(timeout)
        return None

    def cancel(self):
        self.canceled.set()

    def close(self):
        self.calls.append(("close", None, threading.get_ident()))
        self.closed.set()


def until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def owned(monkeypatch):
    assert not streams.active_live_debug_streams()
    monkeypatch.setattr(streams, "_STREAM_ADMISSION", True)
    panels = []
    yield panels
    for panel in panels:
        if isValid(panel):
            panel.close()
    for worker in streams.active_live_debug_streams():
        if hasattr(worker, "allow_native_proof"):
            worker.allow_native_proof.set()
        worker.request_stop()
        # Explicit fixture-only resolution of an uncertain unstarted owner.
        # Product code never retries or assumes wait(True) means it started.
        if not QThread.isRunning(worker) and not QThread.isFinished(worker):
            QThread.start(worker)
        assert QThread.wait(worker, 2000)
        streams.poll_live_debug_retirement(worker)
    until(lambda: not streams.active_live_debug_streams())
    for panel in panels:
        if isValid(panel):
            panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture
def gated(owned, monkeypatch):
    original = streams._StreamWorker

    class HeldWait(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.allow_native_proof = threading.Event()
            self.wait_observations = []

        def wait(self, timeout=0):
            self.wait_observations.append(timeout)
            return super().wait(timeout) if self.allow_native_proof.is_set() else False

    monkeypatch.setattr(streams, "_StreamWorker", HeldWait)
    return owned


def make_panel(panels, client):
    panel = streams.LiveDebugPanel(default_pid=45001, client_factory=lambda *_a, **_k: client)
    panels.append(panel)
    return panel


def test_finished_without_wait_keeps_stream_and_exact_panel_references(gated):
    client = FakeClient([{"kind": "event", "message": "fixture retained evidence"}])
    panel = make_panel(gated, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    until(lambda: not panel._activities.snapshot())  # Connection acknowledgment only.
    assert worker in streams.active_live_debug_streams()
    assert not streams.live_debug_retirement_proven(worker)
    panel.disconnect_stream()
    assert QThread.wait(worker, 1500)
    QApplication.instance().processEvents()
    assert worker.isFinished() and isValid(worker)
    assert panel._worker is worker and worker in panel._workers
    assert worker in streams.active_live_debug_streams()
    assert not panel.connect_to_pid() and not panel.connect_button.isEnabled()
    assert not streams.poll_live_debug_retirement(worker)
    worker.allow_native_proof.set()
    assert streams.poll_live_debug_retirement(worker)
    assert panel._worker is None and worker not in panel._workers
    assert panel.connect_button.isEnabled() and not streams.active_live_debug_streams()
    assert client.canceled.is_set() and client.closed.is_set()
    assert all(call[2] != threading.get_ident() for call in client.calls)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker) and streams.live_debug_retirement_proven(worker)
    assert streams.poll_live_debug_retirement(worker) is True


def test_proven_retirement_preserves_entire_bounded_tail_before_reference_cleanup(gated):
    client = FakeClient()
    panel = make_panel(gated, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    panel._timer.stop()
    for index in range(300):
        worker.offer({"kind": "event", "message": f"fixture-{index}"})
    panel.disconnect_stream()
    assert QThread.wait(worker, 1500)
    worker.allow_native_proof.set()
    assert streams.poll_live_debug_retirement(worker)
    assert panel._worker is None and worker not in panel._workers
    assert len(panel.model.rows) == 257
    assert panel.model.rows[0].record["kind"] == "gap"
    assert panel.model.rows[0].record["dropped_events"] == 44
    assert panel.model.rows[1].record["message"] == "fixture-44"
    assert panel.model.rows[-1].record["message"] == "fixture-299"
    assert "Client gaps: 44" in panel.counters.text()
    assert not panel._timer.isActive()


def test_close_and_widget_destruction_are_nonblocking_and_keep_native_custody(gated):
    client = FakeClient()
    panel = make_panel(gated, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    worker.wait_observations.clear()
    panel.close()
    assert panel._closed and not panel._timer.isActive()
    assert client.canceled.is_set()
    assert worker.wait_observations == [0]  # No bounded blocking close wait.
    assert worker in streams.active_live_debug_streams()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(panel) and isValid(worker)
    assert worker in streams.active_live_debug_streams()
    assert QThread.wait(worker, 1500)
    worker.allow_native_proof.set()
    assert streams.poll_live_debug_retirement(worker)
    assert client.closed.is_set() and not streams.active_live_debug_streams()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker) and streams.live_debug_retirement_proven(worker)


def test_ordinary_auto_deleted_stream_keeps_exact_prior_stop_proof(owned):
    client = FakeClient()
    panel = make_panel(owned, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    panel.disconnect_stream()
    until(lambda: panel._worker is None and not streams.active_live_debug_streams())
    assert worker not in panel._workers
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker) and streams.live_debug_retirement_proven(worker)
    assert streams.poll_live_debug_retirement(worker)
    stranger = QThread()
    try:
        assert stranger.wait(0) is True and not stranger.isFinished()
        assert not streams.live_debug_retirement_proven(stranger)
        assert not streams.poll_live_debug_retirement(stranger)
    finally:
        stranger.deleteLater()


def test_owner_cleanup_settles_before_reentrant_stop_may_accept_proof(gated, monkeypatch):
    client = FakeClient()
    panel = make_panel(gated, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    original = panel._stream_native_retired
    calls = []

    def settled(exact):
        assert exact is worker
        assert not streams.live_debug_retirement_proven(exact)
        assert not streams.poll_live_debug_retirement(exact)
        original(exact)
        assert panel._worker is None and exact not in panel._workers
        assert not streams.live_debug_retirement_proven(exact)
        calls.append(exact)

    monkeypatch.setattr(panel, "_stream_native_retired", settled)
    panel.disconnect_stream()
    assert QThread.wait(worker, 1500)
    worker.allow_native_proof.set()
    assert streams.poll_live_debug_retirement(worker)
    assert calls == [worker] and streams.live_debug_retirement_proven(worker)


def test_hold_rejects_new_stream_and_does_not_adopt_unrelated_actor(gated):
    client = FakeClient()
    panel = make_panel(gated, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    streams.hold_live_debug_streams()
    assert client.canceled.is_set() and worker in streams.active_live_debug_streams()
    calls = []
    other = streams.LiveDebugPanel(default_pid=45001, client_factory=lambda *_a, **_k: calls.append(True))
    gated.append(other)
    assert not other.connect_to_pid() and not calls
    assert "admission is held" in other.status.text()
    assert other._worker is None
    assert QThread.wait(worker, 1500)
    worker.allow_native_proof.set()
    assert streams.poll_live_debug_retirement(worker)


def test_final_view_delivery_error_cannot_leave_a_deleted_owner_reference(gated, monkeypatch):
    client = FakeClient()
    panel = make_panel(gated, client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1)
    panel._timer.stop()
    worker.offer({"kind": "event", "message": "fixture final view"})
    panel.disconnect_stream()
    assert QThread.wait(worker, 1500)

    def unavailable(_rows):
        raise RuntimeError("fixture display failure")

    monkeypatch.setattr(panel.model, "append", unavailable)
    worker.allow_native_proof.set()
    assert streams.poll_live_debug_retirement(worker)
    assert panel._worker is None and worker not in panel._workers
    assert not streams.active_live_debug_streams() and not panel._activities.snapshot()
    assert "coverage is UNKNOWN" in panel.status.text()
    assert panel.model.rowCount() == 0 and panel.connect_button.isEnabled()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker) and streams.live_debug_retirement_proven(worker)


def test_raised_start_remains_held_until_real_native_generation_settles(owned, monkeypatch):
    original = streams._StreamWorker

    class RaisedStart(original):
        def start(self, *_args, **_kwargs):
            self._start_attempted = True
            raise RuntimeError("fixture uncertain native admission")

    monkeypatch.setattr(streams, "_StreamWorker", RaisedStart)
    client = FakeClient()
    panel = make_panel(owned, client)
    assert not panel.connect_to_pid()
    worker = panel._worker
    assert worker.admission_error == "RuntimeError" and worker.retirement_uncertain
    assert worker in panel._workers and worker in streams.active_live_debug_streams()
    assert worker.wait(0) is True and worker.isFinished() is False
    assert not streams.poll_live_debug_retirement(worker)
    assert "retirement is unproved" in panel.status.text()
    assert not panel.connect_to_pid() and not client.entered.is_set()
    # Test cleanup explicitly resolves a modeled late native admission; the
    # retained stop request makes run() return without opening any endpoint.
    QThread.start(worker)
    until(lambda: panel._worker is None and not streams.active_live_debug_streams())
    assert streams.live_debug_retirement_proven(worker) and not client.calls
