"""eco_wakeup.py — sequential, non-blocking module wake-up manager.

Turning Eco Mode OFF used to restart every paused heavy module in a tight loop.
Many daemon threads each firing their first full process/connection/memory scan at
once is a "memory stampede" that spikes CPU/RAM and freezes the Qt event loop for
several seconds.

``EcoWakeupWorker`` brings them back online **one at a time** on a background
thread, waiting for each module to complete one real work cycle (or reach a
bounded safety timeout) before starting the next. One slow/broken module can
never stall the whole sequence, and the GUI
stays responsive because all the work happens off the main thread — progress is
reported purely through Qt signals.

Wiring (main_window.py, "Eco Mode Off" path)
--------------------------------------------
    from angerona.core.eco_wakeup import EcoWakeupWorker

    def _resume_from_eco(self) -> None:
        mods = [self.manager.modules[n] for n in self._eco_paused
                if n in self.manager.modules]
        self._eco_worker = EcoWakeupWorker(mods)          # keep a reference!
        self._eco_worker.module_waking.connect(
            lambda name: self.console._append(f"[eco] Waking {name}…"))
        self._eco_worker.module_ready.connect(
            lambda name, ok: self.console._append(
                f"[eco]   {name}: {'online' if ok else 'FAILED to wake'}"))
        self._eco_worker.wakeup_complete.connect(self._on_eco_wakeup_done)
        self._eco_worker.finished.connect(self._eco_worker.deleteLater)
        self._eco_worker.start()

    def _on_eco_wakeup_done(self, ok: int, failed: int) -> None:
        self.console._append(
            f"[eco] Wake-up complete — {ok} online, {failed} failed.")

The worker only calls ``BaseModule.start()/stop()`` (thread-safe via the module's
internal ``threading.Event``) and reads plain lifecycle/health attributes; it never
touches a Qt widget, so it is safe to run in its own ``QThread``.
"""
from __future__ import annotations

import threading
import time
from typing import List, Sequence

from PySide6.QtCore import QThread, Signal

from angerona.core.module_base import BaseModule


class EcoWakeupWorker(QThread):
    """Sequentially wake paused modules with a first-cycle completion gate.

    Signals:
        module_waking(str)        — emitted right before a module is started.
        module_ready(str, bool)   — emitted after health check / timeout (ok flag).
        module_cycle_timeout(str) — module remained alive but exceeded its cycle gate.
        wakeup_complete(int, int) — (total_success, total_failed) when finished.
    """

    module_waking   = Signal(str)
    module_ready    = Signal(str, bool)
    module_cycle_timeout = Signal(str)
    wakeup_complete = Signal(int, int)

    _CYCLE_TIMEOUTS = {
        "YARA Scanner": 180.0,
        "Memory Injection Scanner": 90.0,
        "Memory Time-Machine": 60.0,
        "Persistence Sweep": 60.0,
        "Data Provenance Graph": 60.0,
        "Upstream Threat Intel Sync": 60.0,
    }

    def __init__(
        self,
        modules: Sequence[BaseModule],
        health_timeout: float = 30.0,
        poll_interval: float = 0.1,
        min_settle: float = 0.35,
        parent=None,
    ) -> None:
        super().__init__(parent)
        # Copy so external mutation of the caller's list can't race the sequence.
        self._modules: List[BaseModule] = list(modules)
        self._health_timeout = float(health_timeout)
        self._poll = max(0.02, float(poll_interval))
        self._min_settle = max(0.0, float(min_settle))
        self._abort = False
        self._control_lock = threading.Lock()

    # ── Public ────────────────────────────────────────────────────────────────
    def cancel(self) -> None:
        """Request an early stop; no new module starts after this returns."""
        # Synchronize with the tiny check+start critical section in run(). If a
        # start won the race, cancel returns only after start() and the caller can
        # safely stop it; if cancel won, no later module can start.
        with self._control_lock:
            self._abort = True

    # ── Health probe ────────────────────────────────────────────────────────
    @staticmethod
    def _health_pct(mod: BaseModule) -> int:
        # BaseModule exposes `.health`; some drop-in modules expose `.health_pct`.
        val = getattr(mod, "health_pct", None)
        if val is None:
            val = getattr(mod, "health", 0)
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _alive(mod: BaseModule) -> bool:
        t = getattr(mod, "_thread", None)
        return bool(t and t.is_alive())

    def _wait_for_prior_stop(self, mod: BaseModule, timeout: float = 5.0) -> bool:
        """Let a just-paused module's old thread exit before restarting it."""
        deadline = time.monotonic() + timeout
        while self._alive(mod) and time.monotonic() < deadline:
            if self._abort:
                return False
            time.sleep(self._poll)
        return not self._alive(mod)

    def _gate(self, mod: BaseModule) -> str:
        """Wait for a real first cycle, failure, or a bounded safety timeout."""
        timeout = self._CYCLE_TIMEOUTS.get(
            getattr(mod, "name", ""), self._health_timeout)
        timeout = float(getattr(mod, "eco_cycle_timeout", timeout))
        deadline = time.monotonic() + max(1.0, timeout)
        started = time.monotonic()
        while time.monotonic() < deadline:
            if self._abort:
                return ("alive" if self._alive(mod) and
                        getattr(mod, "status", "") != "error" else "failed")
            status = getattr(mod, "status", "")
            # Hard failure: the fault-isolated run wrapper marks a crashed module
            # "error" (quarantined) — fail fast, don't wait out the timeout.
            if status == "error" or (not self._alive(mod) and status != "running"):
                return "failed"
            # Success: the thread is alive and running, and the module has crossed
            # a real work-cycle boundary. The settle keeps adjacent scanners from
            # bunching their setup work together.
            settled = (time.monotonic() - started) >= self._min_settle
            first_cycle = bool(getattr(mod, "first_cycle_complete", False))
            if (settled and first_cycle and self._alive(mod) and
                    status == "running" and self._health_pct(mod) > 0):
                return "complete"
            time.sleep(self._poll)
        if self._alive(mod) and getattr(mod, "status", "") != "error":
            return "alive"
        return "failed"

    # ── Thread body ───────────────────────────────────────────────────────────
    def run(self) -> None:
        ok = failed = 0
        for mod in self._modules:
            if self._abort:
                break
            name = getattr(mod, "name", mod.__class__.__name__)
            self.module_waking.emit(name)
            if (getattr(mod, "status", "") == "stopped" and self._alive(mod)
                    and not self._wait_for_prior_stop(mod)):
                failed += 1
                self.module_ready.emit(name, False)
                continue
            try:
                with self._control_lock:
                    if self._abort:
                        break
                    mod.start()
            except Exception:
                failed += 1
                self.module_ready.emit(name, False)
                continue

            gate = self._gate(mod)
            success = gate != "failed"
            if success:
                ok += 1
                if gate == "alive":
                    self.module_cycle_timeout.emit(name)
            else:
                failed += 1
                # Leave a broken module stopped so it isn't half-alive and can't
                # keep respawning under the wrapper's restart budget.
                try:
                    mod.stop()
                except Exception:
                    pass
            self.module_ready.emit(name, success)

        self.wakeup_complete.emit(ok, failed)
