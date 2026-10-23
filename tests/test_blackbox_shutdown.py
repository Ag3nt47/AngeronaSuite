"""Exercise the real recorder entry point without operator state or a live suite."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap
import threading

import pytest

import blackbox_recorder as blackbox


@pytest.mark.parametrize("mode", ["close", "hidden-close", "quit", "delayed-read", "partial-start"])
def test_real_entry_point_retires_workers_before_native_shutdown(mode):
    root = Path(__file__).resolve().parents[1]
    data = Path(os.environ["ANGERONA_DATA"]) / mode
    data.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(ANGERONA_DATA=str(data), ANGERONA_DIAG_DIR=str(data / "diagnostics"),
                       ANGERONA_BLACKBOX_ENABLED="0", QT_QPA_PLATFORM="offscreen")
    script = textwrap.dedent(r'''
        import json
        import sys
        import threading
        import time
        import blackbox_recorder as b
        from PySide6.QtCore import QTimer
        from angerona.core.uiwatchdog import UiWatchdog

        mode = sys.argv[1]
        entered, release = threading.Event(), threading.Event()
        retired, watches = [], []
        beats = []
        original_start = UiWatchdog.start
        def track_watchdog(self):
            watches.append(self)
            original_start(self)
        UiWatchdog.start = track_watchdog

        original_window = b.BlackBoxWindow
        if mode == "delayed-read":
            def delayed_read(self):
                entered.set()
                assert release.wait(5), "Qt could not dispatch the read release timer"
                return [], "inert delayed fixture"
            b.MemoryProfilerWorker._collect = delayed_read

        class Window(original_window):
            def _start_workers(self):
                super()._start_workers()
                if mode == "partial-start":
                    raise RuntimeError("inert partial worker start")

            def __init__(self):
                super().__init__()
                if mode == "delayed-read":
                    self.probe = QTimer(self)
                    self.probe.setInterval(5)
                    self.probe.timeout.connect(self.probe_close)
                    self.probe.start()
                    QTimer.singleShot(20, self.activate_memory)
                elif mode == "hidden-close":
                    # The reverse-reveal coordinator hides before the final
                    # close. Qt need not emit lastWindowClosed in this case.
                    QTimer.singleShot(150, self.hide_then_close)
                else:
                    QTimer.singleShot(150, self.close if mode == "close"
                                      else b.QApplication.instance().quit)

            def activate_memory(self):
                self.showNormal()
                self.tabs.setCurrentWidget(self.tab_mem)

            def hide_then_close(self):
                self.hide()
                self.close()

            def probe_close(self):
                if self._closing and not release.is_set():
                    beats.append(time.monotonic())
                if entered.is_set() and not self._closing:
                    QTimer.singleShot(250, release.set)
                    self.close()

            def stop_workers(self, timeout_ms=2000):
                stopped = super().stop_workers(timeout_ms=timeout_ms)
                if stopped:
                    states = [w.isRunning() if isinstance(w, b.QThread) else w.is_alive()
                              for w in self._shutdown_threads]
                    assert not any(states), states
                    retired.append(len(states))
                return stopped

        b.BlackBoxWindow = Window
        # Never attach this disposable recorder to the operator's named mutex.
        b._acquire_single_instance = lambda: True
        sys.argv = ["blackbox_recorder.py"]
        try:
            b.main()
        except SystemExit as exc:
            assert mode != "partial-start" and exc.code == 0, exc
        except RuntimeError as exc:
            assert mode == "partial-start" and "inert partial worker start" in str(exc), exc
        assert retired and min(retired) >= 6, retired
        assert b.QApplication.instance() is None
        assert watches and all(not w._thread.is_alive() for w in watches)
        if mode == "delayed-read":
            assert entered.is_set() and release.is_set()
            assert len(beats) >= 5, beats
        print(json.dumps({"mode": mode, "retired": retired[-1], "closing_heartbeats": len(beats)}), flush=True)
    ''')
    result = subprocess.run([sys.executable, "-X", "faulthandler", "-c", script, mode],
                            cwd=root, env=environment, capture_output=True, text=True,
                            timeout=40, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert '"retired":' in result.stdout, result.stdout
    assert "QThread: Destroyed while thread" not in result.stderr


def test_telemetry_stop_interrupts_a_long_sample_interval(monkeypatch):
    primed = threading.Event()
    monkeypatch.setattr(blackbox, "HOST_POLL_S", 60)
    monkeypatch.setattr(blackbox.psutil, "cpu_percent", lambda **kwargs: [])
    monkeypatch.setattr(blackbox.psutil, "disk_io_counters", lambda: primed.set())
    worker = blackbox.HostTelemetryWorker()
    worker.start()
    try:
        assert primed.wait(2)
        worker.stop()
        assert worker.wait(1000), "stop must wake the telemetry cadence wait"
    finally:
        worker.stop()
        assert worker.wait(2000)
