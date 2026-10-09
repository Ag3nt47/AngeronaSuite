from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import flow_window


@pytest.fixture
def flow(monkeypatch):
    calls, loading, finished = [], [], []

    class InertEngine:
        def host_vs_suite_matrix(self):
            return {"available": False, "reason": "inert"}

        def eps_gauge(self, _count):
            return dict(internal_eps=0, host_ctx_switch_rate=0, host_active=False)

        def ollama_diagnostics(self):
            calls.append(threading.get_ident())
            return {"available": False, "reason": "inert"}

    monkeypatch.setattr(flow_window, "_WorldViewEngine", InertEngine)
    monkeypatch.setattr(flow_window, "begin_loading", lambda *_args: loading.append("token") or "token")
    monkeypatch.setattr(flow_window, "finish_loading", finished.append)
    bus = SimpleNamespace(recent=lambda _limit: [], event_count=lambda: 0)
    window = flow_window.FlowWindow(bus, None, SimpleNamespace(modules={}), SimpleNamespace())
    yield window, calls, loading, finished
    worker = getattr(window, "_ollama_worker", None)
    if worker is not None and isValid(worker):
        assert worker.wait(3000)
    if isValid(window):
        window.close()
    QApplication.instance().processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_queued_diagnostics_kick_after_close_cannot_start_worker(flow):
    window, calls, loading, _finished = flow
    assert window.close()
    window._kick_ollama()  # Model an already-delivered timer callback after close.
    worker = window._ollama_worker
    if worker is not None:
        assert worker.wait(3000)
    assert calls == []
    assert loading == []


def test_native_owner_delete_cancels_initial_diagnostics_timer(flow):
    window, calls, loading, _finished = flow
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(window)
    QTest.qWait(650)
    assert calls == []
    assert loading == []


def test_close_retains_active_worker_without_allowing_late_replacement(flow, monkeypatch):
    window, calls, _loading, _finished = flow
    entered, release = threading.Event(), threading.Event()

    def blocked():
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        return {"available": False, "reason": "inert"}

    monkeypatch.setattr(window._wv_engine, "ollama_diagnostics", blocked)
    try:
        window._kick_ollama()
        worker = window._ollama_worker
        assert entered.wait(1)
        assert not window.close()
        assert isValid(window) and not window.isVisible()
        release.set()
        assert worker.wait(3000)
        window._kick_ollama()
        assert window._ollama_worker is worker
        assert len(calls) == 1
        deadline = time.monotonic() + 3
        while isValid(window) and time.monotonic() < deadline:
            QApplication.instance().processEvents()
            QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
            time.sleep(0.005)
        assert not isValid(window)
    finally:
        release.set()


def test_worker_start_failure_releases_loading_and_allows_retry(flow, monkeypatch):
    window, calls, loading, finished = flow
    original = flow_window._OllamaWorker.start

    def failed_start(_worker):
        raise RuntimeError("inert launch refusal")

    monkeypatch.setattr(flow_window._OllamaWorker, "start", failed_start)
    window._kick_ollama()
    assert window._ollama_worker is None
    assert loading == finished == ["token"]
    assert calls == []
    monkeypatch.setattr(flow_window._OllamaWorker, "start", original)
    window._kick_ollama()
    assert window._ollama_worker.wait(3000)
    assert len(calls) == 1
