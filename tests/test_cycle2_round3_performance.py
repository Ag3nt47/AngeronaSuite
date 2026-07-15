from __future__ import annotations

import tempfile
import threading
import time
from pathlib import Path

from angerona.core.eventbus import Event, Severity
from angerona.core.storage import FlightRecorder


def test_gui_storage_reads_never_wait_for_the_writer_lock() -> None:
    with tempfile.TemporaryDirectory(prefix="angerona-r3-perf-") as td:
        recorder = FlightRecorder(Path(td) / "events.db")
        try:
            initial = recorder.revision()
            event = Event("probe", "committed", Severity.INFO, time.time(), {})
            recorder.record(event)
            committed = recorder.revision()

            assert committed > initial
            assert len(recorder.try_recent(10) or []) == 1
            assert recorder.try_count_since(event.ts - 1.0) == 1

            entered = threading.Event()
            release = threading.Event()

            def hold_writer() -> None:
                with recorder._lock:
                    entered.set()
                    release.wait(1.0)

            worker = threading.Thread(target=hold_writer, daemon=True)
            worker.start()
            assert entered.wait(1.0)
            started = time.perf_counter()
            snapshot = recorder.revision()
            recent = recorder.try_recent(10)
            count = recorder.try_count_since(0.0)
            elapsed = time.perf_counter() - started
            release.set()
            worker.join(1.0)

            assert snapshot == committed
            assert recent is None and count is None
            assert elapsed < 0.05, f"interactive storage probe blocked for {elapsed:.3f}s"
            assert not worker.is_alive()
        finally:
            recorder.close()


if __name__ == "__main__":
    test_gui_storage_reads_never_wait_for_the_writer_lock()
    print("PASS - GUI storage reads never wait for the writer lock")
