from __future__ import annotations

import os
import threading
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.core.host_adaptation import HostAdaptationService
from angerona.gui.adaptation_workbench import AdaptationWorkbench
from angerona.gui.main_window import MainWindow


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _drain_status(dialog: AdaptationWorkbench) -> None:
    deadline = time.monotonic() + 5
    while dialog._status_active and time.monotonic() < deadline:
        _app().processEvents()
        time.sleep(0.001)
    assert not dialog._status_active


def test_persisted_refresh_reuses_state_and_unchanged_activity_items(
    tmp_path: Path, monkeypatch,
) -> None:
    _app()
    service = HostAdaptationService(tmp_path)
    service.log_activity("test", "success", "bounded row")
    dialog = AdaptationWorkbench(service)
    _drain_status(dialog)

    first_item = dialog.activity_table.item(0, 0)
    state_calls = 0
    real_state = service.state

    def counted_state():
        nonlocal state_calls
        state_calls += 1
        return real_state()

    monkeypatch.setattr(service, "state", counted_state)
    dialog._load_persisted_views()
    _drain_status(dialog)

    # One shared state read supplies triggers and adaptive weights; the second
    # preserves breaker_status() expiry semantics.
    assert state_calls == 2
    assert dialog.activity_table.item(0, 0) is first_item
    dialog.close()


def test_recovery_hash_and_status_reads_never_block_gui(
    tmp_path: Path, monkeypatch,
) -> None:
    app = _app()
    service = HostAdaptationService(tmp_path)
    release = threading.Event()
    entered = threading.Event()
    threads: list[int] = []
    gui_thread = threading.get_ident()

    def slow_recovery():
        threads.append(threading.get_ident())
        entered.set()
        assert release.wait(5), "test did not release integrity probe"
        return {"available": True, "captured_at": "fixture"}

    monkeypatch.setattr(service, "security_baseline_status", slow_recovery)
    dialog = AdaptationWorkbench(service)
    try:
        assert entered.wait(2)
        # Construction returned while the hash is still blocked. A Qt event
        # can still run and repeated refreshes cannot start additional hashes.
        for _ in range(8):
            dialog._refresh_status()
        app.processEvents()
        assert threads == [threads[0]]
        assert threads[0] != gui_thread
        assert dialog._status_active
    finally:
        release.set()
        _drain_status(dialog)
        dialog.close()
    assert len(threads) == 2  # one active request + one coalesced refresh
    assert all(thread != gui_thread for thread in threads)


def test_snapshot_probes_overlap_and_concurrent_snapshots_share_budget(
    tmp_path: Path, monkeypatch,
) -> None:
    service = HostAdaptationService(tmp_path)
    lock = threading.Lock()
    barrier = threading.Barrier(5, timeout=5)
    active = 0
    peak = 0
    calls = 0

    def probe(value):
        def run():
            nonlocal active, peak, calls
            with lock:
                active += 1
                calls += 1
                peak = max(peak, active)
            try:
                barrier.wait()
                return value
            finally:
                with lock:
                    active -= 1
        return run

    complete = service._quality(complete=True)
    for name, value in (
        ("_collect_services", ([], complete)),
        ("_collect_ports", ([], complete)),
        ("capture_context", {"collector": complete}),
        ("_firewall", {"supported": True, "complete": True}),
        ("_hardware", {"system": "fixture"}),
    ):
        monkeypatch.setattr(service, name, probe(value))
    results = []
    workers = [threading.Thread(target=lambda: results.append(service.capture_snapshot())) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()
    assert len(results) == 2
    assert calls == 10
    assert peak == 5
    assert all(result["collection"]["strategy"] == "bounded-parallel" for result in results)
    assert all(row["elapsed_ms"] >= 0 for row in results[0]["collector_status"].values())


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
