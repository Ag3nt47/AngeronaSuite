from __future__ import annotations

import os
import threading
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.gui import upgrade_console


class _HoldingPool:
    def __init__(self) -> None:
        self.jobs: list[object] = []

    def start(self, worker, _priority: int = 0) -> None:
        self.jobs.append(worker)


class _PackManager:
    catalog: dict = {}

    @staticmethod
    def state() -> dict:
        return {
            "active_pack": None,
            "installed": {},
            "activation_history": [],
        }


def _run_worker(worker) -> threading.Thread:
    thread = threading.Thread(target=worker.run)
    thread.start()
    thread.join(timeout=5.0)
    assert not thread.is_alive()
    return thread


def _drain_qt() -> None:
    app = QApplication.instance() or QApplication([])
    for _ in range(6):
        app.processEvents()


def test_diagnostic_file_reads_are_single_flight_and_off_qt(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    pool = _HoldingPool()
    main_thread = threading.current_thread()
    watchdog_threads: list[threading.Thread] = []
    scanner_threads: list[threading.Thread] = []
    original_watchdog_refresh = upgrade_console.AngeronaUpgradeConsole._refresh_watchdog

    # Keep the zero-delay constructor timer deterministic. The real scheduling
    # method is invoked explicitly below.
    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
    )
    window = upgrade_console.AngeronaUpgradeConsole(
        model_pack_manager=_PackManager()
    )
    try:
        # Drain the initial model-pack snapshot so only diagnostics remain.
        assert len(pool.jobs) == 1
        _run_worker(pool.jobs.pop())
        _drain_qt()

        def watchdog_snapshot() -> dict:
            watchdog_threads.append(threading.current_thread())
            return {
                "watchdog": {"pid": 7, "rss_mb": 8, "state": "running"},
                "heartbeat": "alive",
                "core": None,
            }

        def scanner_snapshot() -> dict:
            scanner_threads.append(threading.current_thread())
            return {
                "scanner": {
                    "state": "running",
                    "pid": 9,
                    "rss_mb": 10,
                    "events_forwarded": 11,
                    "dropped": 0,
                    "ring_backpressure": 0,
                }
            }

        monkeypatch.setattr(window, "_watchdog_snapshot", watchdog_snapshot)
        monkeypatch.setattr(window, "_telemetry_snapshot", scanner_snapshot)

        original_watchdog_refresh(window)
        original_watchdog_refresh(window)
        window._refresh_telemetry()
        window._refresh_telemetry()
        assert len(pool.jobs) == 2

        watchdog_worker = next(
            job for job in pool.jobs if job._operation == "watchdog_status"
        )
        telemetry_worker = next(
            job for job in pool.jobs if job._operation == "telemetry_status"
        )
        worker_threads = {
            _run_worker(watchdog_worker),
            _run_worker(telemetry_worker),
        }
        _drain_qt()

        assert set(watchdog_threads + scanner_threads) == worker_threads
        assert all(thread is not main_thread for thread in worker_threads)
        assert window._watchdog_refresh_in_flight is False
        assert window._telemetry_refresh_in_flight is False
        assert "heartbeat=alive" in window._wd_status.text()
        assert window._t_running.text() == "scanner running (pid 9, 10MB)"
    finally:
        window.close()
        app.processEvents()


def test_embedded_pack_change_builds_only_the_authoritative_rag_index(
    monkeypatch,
) -> None:
    from angerona.core import runbook_rag

    constructions: list[object] = []

    class UnexpectedDuplicateRag:
        def __init__(self, _roots) -> None:
            constructions.append(self)

        def build(self) -> int:
            return 999

    monkeypatch.setattr(runbook_rag, "RunbookRAG", UnexpectedDuplicateRag)
    callbacks: list[str] = []
    window = SimpleNamespace(
        _pack_change_callback=lambda: callbacks.append("rebuilt") or 23,
    )

    count = upgrade_console.AngeronaUpgradeConsole._rebuild_pack_runbooks(window)

    assert count == 23
    assert callbacks == ["rebuilt"]
    assert constructions == []
