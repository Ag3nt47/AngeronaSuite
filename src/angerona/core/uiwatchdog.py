"""
core/uiwatchdog.py — main-thread (UI) responsiveness watchdog.

A QTimer on the GUI thread bumps a heartbeat timestamp. A separate daemon thread
watches that timestamp; if the GUI thread hasn't bumped it within ``stall_seconds``
the UI is (or is about to be) "Not Responding", so the watchdog appends a snapshot
of EVERY thread's stack to a log file — which shows exactly what is blocking the
GUI thread (look at the ``MainThread`` stack). Best-effort; never raises into the
app.

This is a diagnostic aid: it does not try to unstick the UI, it documents the
cause so the offending blocking call can be moved off the GUI thread.
"""
from __future__ import annotations

import sys
import threading
import time
import traceback
from pathlib import Path


class UiWatchdog:
    _MAX_LOG_BYTES = 4 * 1024 * 1024
    _MIN_DUMP_INTERVAL = 60.0

    def __init__(self, log_path, stall_seconds: float = 5.0) -> None:
        self.log_path = Path(log_path)
        self.stall_seconds = float(stall_seconds)
        self._last_beat = time.monotonic()
        self._stop = threading.Event()
        self._logged_for = None      # dedupe: one dump per distinct stall
        self._last_dump_at = 0.0
        self._thread = None

    def beat(self) -> None:
        """Call on the GUI thread (from a QTimer) to prove it is alive."""
        self._last_beat = time.monotonic()

    def start(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._thread = threading.Thread(target=self._run, name="UiWatchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(1.0):
            age = time.monotonic() - self._last_beat
            now = time.monotonic()
            if (age >= self.stall_seconds
                    and self._last_beat != self._logged_for
                    and now - self._last_dump_at >= self._MIN_DUMP_INTERVAL):
                self._logged_for = self._last_beat      # don't spam the same stall
                self._last_dump_at = now
                self._dump(age)

    def _dump(self, age: float) -> None:
        try:
            names = {t.ident: t.name for t in threading.enumerate()}
            frames = sys._current_frames()
            try:
                if self.log_path.stat().st_size >= self._MAX_LOG_BYTES:
                    rotated = self.log_path.with_suffix(self.log_path.suffix + ".1")
                    if rotated.exists():
                        rotated.unlink()
                    self.log_path.replace(rotated)
            except Exception:
                pass
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write("\n" + "=" * 72 + "\n")
                f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] UI NOT RESPONDING — GUI "
                        f"thread stalled ~{age:.1f}s (threshold {self.stall_seconds:.0f}s)\n")
                f.write("The MainThread stack below is the call that is blocking the UI.\n")
                f.write("-" * 72 + "\n")
                # Dump only the actionable GUI stack. Writing every sleeping
                # module stack held the GIL and amplified the stall being observed.
                main = threading.main_thread()
                frame = frames.get(main.ident)
                f.write(f"\n--- Thread MainThread (id={main.ident}) ---\n")
                if frame is not None:
                    traceback.print_stack(frame, file=f)
                others = sorted(n for tid, n in names.items() if tid != main.ident)
                f.write(f"\nOther live threads ({len(others)}): {', '.join(others)}\n")
        except Exception:
            pass
