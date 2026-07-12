"""eco_wakeup.py — sequential, non-blocking module wake-up manager.

Turning Eco Mode OFF used to restart every paused heavy module in a tight loop.
~19 daemon threads each firing their first full process/connection/memory scan at
once is a "memory stampede" that spikes CPU/RAM and freezes the Qt event loop for
several seconds.

``EcoWakeupWorker`` brings them back online **one at a time** on a background
thread, waiting for each module to report healthy (or time out) before starting
the next. One slow/broken module can never stall the whole sequence, and the GUI
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
internal ``threading.Event``) and reads plain status/health attributes; it never
touches a Qt widget, so it is safe to run in its own ``QThread``.
"""
from __future__ import annotations

import time
from typing import List, Sequence

from PySide6.QtCore import QThread, Signal

from angerona.core.module_base import BaseModule


class EcoWakeupWorker(QThread):
    """Sequentially wake a list of paused modules with a per-module health gate.

    Signals:
        module_waking(str)        — emitted right before a module is started.
        module_ready(str, bool)   — emitted after health check / timeout (ok flag).
        wakeup_complete(int, int) — (total_success, total_failed) when finished.
    """

    module_waking   = Signal(str)
    module_ready    = Signal(str, bool)
    wakeup_complete = Signal(int, int)

    def __init__(
        self,
        modules: Sequence[BaseModule],
        health_timeout: float = 2.5,
        poll_interval: float = 0.1,
        min_settle: float = 0.15,
        parent=None,
    ) -> None:
        super().__init__(parent)
        # Copy so external mutation of the caller's list can't race the sequence.
        self._modules: List[BaseModule] = list(modules)
        self._health_timeout = float(health_timeout)
        self._poll = max(0.02, float(poll_interval))
        self._min_settle = max(0.0, float(min_settle))
        self._abort = False

    # ── Public ────────────────────────────────────────────────────────────────
    def cancel(self) -> None:
        """Request an early stop; the current module finishes its gate first."""
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

    def _gate(self, mod: BaseModule) -> bool:
        """Block until `mod` looks healthy, crashes, or times out. Returns success."""
        deadline = time.monotonic() + self._health_timeout
        started = time.monotonic()
        while time.monotonic() < deadline:
            if self._abort:
                return self._alive(mod) and getattr(mod, "status", "") != "error"
            status = getattr(mod, "status", "")
            # Hard failure: the fault-isolated run wrapper marks a crashed module
            # "error" (quarantined) — fail fast, don't wait out the timeout.
            if status == "error" or (not self._alive(mod) and status != "running"):
                return False
            # Success: thread is alive, running, reporting health, and we've given
            # it a brief settle so its first heavy scan actually spaces out from
            # the next module's — which is the whole point of sequential wake-up.
            settled = (time.monotonic() - started) >= self._min_settle
            if settled and self._alive(mod) and status == "running" and self._health_pct(mod) > 0:
                return True
            time.sleep(self._poll)
        # Timed out: healthy-enough if it's at least alive and not errored.
        return self._alive(mod) and getattr(mod, "status", "") != "error"

    # ── Thread body ───────────────────────────────────────────────────────────
    def run(self) -> None:
        ok = failed = 0
        for mod in self._modules:
            if self._abort:
                break
            name = getattr(mod, "name", mod.__class__.__name__)
            self.module_waking.emit(name)
            try:
                mod.start()
            except Exception:
                failed += 1
                self.module_ready.emit(name, False)
                continue

            success = self._gate(mod)
            if success:
                ok += 1
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
