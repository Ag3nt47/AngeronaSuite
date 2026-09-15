"""Offline synthetic runtime-growth probes; never starts sensors or inference.

Run with the development Python. State is confined to a disposable workspace
directory; stdout is JSON so before/after runs can be compared directly.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    (root / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="refresh-bench-", dir=root / ".tmp") as work:
        os.environ["ANGERONA_DATA"] = work
        os.environ["ANGERONA_DIAG_DIR"] = str(Path(work) / "diagnostics")
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        from angerona.__main__ import _install_fast_pyside_feature_detection
        _install_fast_pyside_feature_detection()
        from PySide6.QtWidgets import QApplication
        from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
        from angerona.core.storage import FlightRecorder
        from angerona.gui import pages

        app = QApplication.instance() or QApplication([])
        report = {}
        panel = pages.SoarPanel(EventBus())
        try:
            for size in (50, 500):
                rows = [dict(request_id=f"{i:032x}", ts=float(i), status="PENDING",
                             origin_module="fixture", severity="High", message=f"row {i}")
                        for i in range(size)]
                panel._apply_queue_snapshot((rows, f"initial-{size}"))
                samples = []
                for i in range(20):
                    rows = [dict(row) for row in rows]
                    rows[-1]["status"] = f"fixture update {i}"
                    start = time.perf_counter()
                    panel._apply_queue_snapshot((rows, f"{size}-{i}"))
                    samples.append((time.perf_counter() - start) * 1000)
                report[f"soar_{size}_one_change_ms"] = round(statistics.median(samples), 3)
        finally:
            panel.close()
            panel.deleteLater()

        bus = EventBus()
        bus.arm(BusAuthority(b"b" * 32))
        for i in range(500):
            bus.publish(Event("telemetry", str(i), Severity.INFO))
        rows = [dict(request_id=f"{i:032x}", status="SUBMITTED", submitted_at=time.time())
                for i in range(500)]
        with patch.object(bus, "recent", wraps=bus.recent) as recent:
            start = time.perf_counter()
            pages._reconcile_soar_submission_receipts(rows, bus)
            report["soar_500_pending_scan_ms"] = round((time.perf_counter() - start) * 1000, 3)
            report["soar_500_pending_bus_reads"] = recent.call_count

        recorder = FlightRecorder(Path(work) / "events.db")
        try:
            values = [(float(i), "fixture", i % 5, "fixture", "{}", "") for i in range(40_000)]
            sql = "INSERT INTO events(ts,module,severity,message,details,hmac_sig) VALUES(?,?,?,?,?,?)"
            recorder._db.executemany(sql, values)
            recorder._db.commit()
            samples = []
            for _ in range(8):
                recorder._db.executemany(sql, values[:1000])
                recorder._db.commit()
                start = time.perf_counter()
                with recorder._lock:
                    recorder._prune_locked()
                samples.append((time.perf_counter() - start) * 1000)
            report["retention_41000_to_40000_ms"] = round(statistics.median(samples), 3)
        finally:
            recorder.close()

        state = SimpleNamespace(value=0)
        storage = SimpleNamespace(revision=lambda: state.value,
                                  try_count_since=lambda _: state.value,
                                  try_recent=lambda _: [])
        cards = pages.DashboardCards(EventBus(), storage, SimpleNamespace(modules={}))
        alerts = pages.AlertsPanel(storage)
        starts = []
        original_start = threading.Thread.start

        def start_thread(thread):
            if thread.name in ("DashboardCountReader", "DashboardAlertReader"):
                starts.append(thread.name)
            return original_start(thread)

        try:
            with patch.object(threading.Thread, "start", start_thread):
                for i in range(30):
                    state.value = i
                    cards.refresh()
                    alerts.refresh()
                    deadline = time.monotonic() + 5
                    while (cards._last_storage_revision != i or alerts._last_storage_revision != i):
                        app.processEvents()
                        if time.monotonic() > deadline:
                            raise RuntimeError("dashboard probe timed out")
                        time.sleep(0.001)
            report["dashboard_reader_threads_started_30_refreshes"] = len(starts)
        finally:
            cards.close()
            alerts.close()
            cards.deleteLater()
            alerts.deleteLater()
            app.processEvents()
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
