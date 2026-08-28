from __future__ import annotations

import os
import threading
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.core.host_adaptation import HostAdaptationService
from angerona.gui.adaptation_workbench import AdaptationWorkbench
from angerona.gui.main_window import MainWindow


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_persisted_refresh_reuses_state_and_unchanged_activity_items(
    tmp_path: Path, monkeypatch,
) -> None:
    _app()
    service = HostAdaptationService(tmp_path)
    service.log_activity("test", "success", "bounded row")
    dialog = AdaptationWorkbench(service)

    first_item = dialog.activity_table.item(0, 0)
    state_calls = 0
    real_state = service.state

    def counted_state():
        nonlocal state_calls
        state_calls += 1
        return real_state()

    monkeypatch.setattr(service, "state", counted_state)
    dialog._load_persisted_views()

    # One shared state read supplies triggers and adaptive weights; the second
    # preserves breaker_status() expiry semantics.
    assert state_calls == 2
    assert dialog.activity_table.item(0, 0) is first_item
    dialog.close()


def test_dashboard_monitor_does_not_read_state_on_the_gui_thread(monkeypatch) -> None:
    worker_threads: list[int] = []

    class Service:
        def run_automatic_cycle(self):
            worker_threads.append(threading.get_ident())
            return {"status": "disabled"}

        def state(self):
            raise AssertionError("dashboard timer must not read signed state directly")

    class Signal:
        def __init__(self):
            self.values = []

        def emit(self, *values):
            self.values.append(values)

    class Window:
        _adaptation_poll_active = threading.Event()
        _adaptation_service = Service()
        _adaptation_poll_done = Signal()

    started_from = threading.get_ident()
    window = Window()
    MainWindow._poll_adaptation_context(window)
    for thread in threading.enumerate():
        if thread.name == "HostAdaptationContextMonitor":
            thread.join(timeout=2)

    assert window._adaptation_poll_done.values == [({"status": "disabled"}, None)]
    assert worker_threads and worker_threads[0] != started_from


def test_stable_context_poll_does_not_refresh_visible_workbench() -> None:
    class Dialog:
        calls: list[str] = []

        @staticmethod
        def isVisible() -> bool:
            return True

        def refresh_after_automatic_cycle(self, status: str) -> None:
            self.calls.append(status)

    class Window:
        _adaptation_poll_active = threading.Event()
        _adaptation_last_error = ""
        _adaptation_dialog = Dialog()

    window = Window()
    MainWindow._on_adaptation_poll_done(window, {"status": "stable"}, None)
    assert window._adaptation_dialog.calls == []

    MainWindow._on_adaptation_poll_done(window, {"status": "applied"}, None)
    assert window._adaptation_dialog.calls == ["applied"]
