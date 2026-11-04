"""
core/uiwatchdog.py — main-thread (UI) responsiveness watchdog.

A QTimer on the GUI thread bumps a heartbeat timestamp. A separate daemon thread
watches that timestamp; if the GUI thread hasn't bumped it within ``stall_seconds``
the UI is (or is about to be) "Not Responding", so the watchdog appends the
actionable GUI-thread stack and a compact list of other live threads. Best-effort;
never raises into the app.

This is a diagnostic aid: it does not try to unstick the UI. A sampled Python
stack supplies context, but cannot by itself identify a native Qt wait, CPU
contention, host suspension, or a deadlock.
"""
from __future__ import annotations

import os
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
        self._process_context: tuple[int, str] | None = None

    def beat(self) -> None:
        """Call on the GUI thread (from a QTimer) to prove it is alive."""
        self._last_beat = time.monotonic()

    def start(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._enforce_retention()
        except Exception:
            pass
        self._thread = threading.Thread(target=self._run, name="UiWatchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _enforce_retention(self) -> None:
        """Keep the active log plus one archive, each bounded to 4 MiB.

        Older versions dumped every module thread and could leave a very large
        ``.1`` archive. Trimming from the front preserves the newest evidence
        without reading the whole archive into memory.
        """
        rotated = self.log_path.with_suffix(self.log_path.suffix + ".1")
        if self.log_path.exists() and self.log_path.stat().st_size > self._MAX_LOG_BYTES:
            rotated.unlink(missing_ok=True)
            self.log_path.replace(rotated)
        if not rotated.exists() or rotated.stat().st_size <= self._MAX_LOG_BYTES:
            return
        tmp = rotated.with_suffix(rotated.suffix + ".trim")
        with open(rotated, "rb") as source:
            source.seek(-self._MAX_LOG_BYTES, 2)
            tail = source.read(self._MAX_LOG_BYTES)
        newline = tail.find(b"\n")
        if newline >= 0:
            tail = tail[newline + 1:]
        with open(tmp, "wb") as target:
            target.write(tail)
        tmp.replace(rotated)

    def _run(self) -> None:
        previous_sample = None
        while not self._stop.wait(1.0):
            last_beat = self._last_beat
            now = time.monotonic()
            # This includes the watcher wait, prior observer work and scheduling.
            sample_gap = None if previous_sample is None else now - previous_sample
            previous_sample = now
            age = now - last_beat
            if (age >= self.stall_seconds
                    and last_beat != self._logged_for
                    and now - self._last_dump_at >= self._MIN_DUMP_INTERVAL):
                if self._dump(age, expected_beat=last_beat, watchdog_sample_gap=sample_gap):
                    self._logged_for = last_beat      # don't spam the same stall
                    self._last_dump_at = now

    def _dump(self, age: float, *, expected_beat: float | None = None,
              watchdog_sample_gap: float | None = None) -> bool:
        try:
            if expected_beat is not None and self._last_beat != expected_beat:
                return False
            pid = os.getpid()
            if self._process_context is None or self._process_context[0] != pid:
                # Look up native birth once on the diagnostic path, away from beat().
                birth = "unavailable"
                try:
                    from angerona.core.startup_diagnostics import process_identity

                    observed = process_identity().get("birth_filetime")
                    if (isinstance(observed, str) and 0 < len(observed) <= 20
                            and observed.isascii() and observed.isdecimal() and observed[0] != "0"):
                        birth = observed
                except Exception:
                    pass
                self._process_context = (pid, birth)
            _, birth = self._process_context
            main = threading.main_thread()
            gap = "unavailable" if watchdog_sample_gap is None else f"{watchdog_sample_gap:.3f}"
            names = {t.ident: t.name for t in threading.enumerate()}
            frames = sys._current_frames()
            # The GUI can recover between the age check and frame sampling.
            # Do not blame its new callback for a delay that has already ended.
            if expected_beat is not None and self._last_beat != expected_beat:
                return False
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
                        f"heartbeat delayed ~{age:.1f}s (threshold {self.stall_seconds:.0f}s)\n")
                f.write(f"Sample context: pid={pid} birth_filetime={birth} "
                        f"main_native_tid={main.native_id or 'unavailable'} watchdog_sample_gap_s={gap}\n")
                f.write("Sampled MainThread stack: a slow Python/native call, CPU contention, "
                        "or system sleep can delay the heartbeat. This sample alone does "
                        "not identify the blocking call or establish a lock cycle.\n")
                f.write("-" * 72 + "\n")
                # Dump only the actionable GUI stack. Writing every sleeping
                # module stack held the GIL and amplified the stall being observed.
                frame = frames.get(main.ident)
                f.write(f"\n--- Thread MainThread (id={main.ident}) ---\n")
                if frame is not None:
                    traceback.print_stack(frame, file=f)
                others = sorted(n for tid, n in names.items() if tid != main.ident)
                f.write(f"\nOther live threads ({len(others)}): {', '.join(others)}\n")
            return True
        except Exception:
            return False
