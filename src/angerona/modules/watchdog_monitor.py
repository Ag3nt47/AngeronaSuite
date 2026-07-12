"""
watchdog_monitor.py — Self-healing module supervisor.

Watches every other module; if one crashes (status 'error') or its worker
thread dies while it should be running, the watchdog restarts it — throttled so
a module that crashes repeatedly is left down (with a CRITICAL alert) instead of
thrashing. Drop-in BaseModule; auto-discovered. Gets the ModuleManager via the
optional bind_manager() hook the manager calls at discovery.
"""
from __future__ import annotations
import time

try:
    from angerona.core.module_base import BaseModule
    from angerona.core.eventbus import Severity
except Exception:                                   # standalone/test fallback
    class Severity:
        INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    class BaseModule:
        name = "base"; description = ""; category = ""; version = "1.0.0"
        enabled_by_default = True
        def __init__(self): self.health = 100; self.health_note = ""; self.status = "stopped"; self.last_error = ""
        def set_health(self, p, n=""): self.health = max(0, min(100, int(p))); self.health_note = n
        def emit(self, *a, **k): pass
        def sleep(self, s): time.sleep(min(s, 0.01))
        @property
        def stopping(self): return getattr(self, "_stopflag", False)


class WatchdogMonitor(BaseModule):
    name = "Watchdog Monitor"
    description = "Self-healing supervisor: detects crashed/hung modules and restarts them (throttled)."
    category = "Resilience"
    version = "1.0.0"
    enabled_by_default = True

    MAX_RESTARTS = 3
    SWEEP_SECONDS = 8.0

    def __init__(self) -> None:
        super().__init__()
        self._mgr = None
        self._restarts: dict[str, int] = {}

    def bind_manager(self, manager) -> None:
        """Called by ModuleManager at discovery so we can see/restart siblings."""
        self._mgr = manager

    def run(self) -> None:
        while not self.stopping:
            try:
                self._sweep()
            except Exception as exc:
                self.last_error = str(exc)
            self.sleep(self.SWEEP_SECONDS)

    def _module_dead(self, mod) -> bool:
        if getattr(mod, "status", "") == "error":
            return True
        th = getattr(mod, "_thread", None)
        if getattr(mod, "status", "") == "running" and th is not None and not th.is_alive():
            return True
        return False

    def _sweep(self) -> None:
        mgr = self._mgr
        if mgr is None:
            self.set_health(60, "manager not bound — detection only")
            return
        recovered = 0
        for name, mod in list(getattr(mgr, "modules", {}).items()):
            if mod is self:
                continue
            if hasattr(mgr, "is_enabled") and not mgr.is_enabled(name):
                continue                      # respect user-disabled modules
            if not self._module_dead(mod):
                continue
            recovered += 1
            n = self._restarts.get(name, 0)
            if n < self.MAX_RESTARTS:
                self._restarts[name] = n + 1
                try:
                    mod.stop(); mod.start()
                    self.emit(f"Recovered crashed module '{name}' (restart {n + 1}/{self.MAX_RESTARTS})",
                              Severity.HIGH, module=name)
                except Exception as exc:
                    self.emit(f"Failed to restart '{name}': {exc}", Severity.HIGH, module=name)
            else:
                self.emit(f"Module '{name}' keeps crashing — left DOWN after {self.MAX_RESTARTS} "
                          f"restarts; manual attention needed.", Severity.CRITICAL, module=name)
        # a healthy watchdog on a healthy stack sits at 100
        self.set_health(100 if recovered == 0 else max(40, 90 - recovered * 15),
                        "all modules healthy" if recovered == 0 else f"recovered {recovered} module(s)")

    def self_test(self) -> tuple[bool, str]:
        class _Fake:
            def __init__(s): s.status = "error"; s._thread = None; s.started = 0
            def stop(s): pass
            def start(s): s.status = "running"; s.started += 1
        class _Mgr:
            def __init__(s, f): s.modules = {"Fake": f}
            def is_enabled(s, n): return True
        # Isolate: DON'T clobber the real manager binding or emit to the live
        # bus. (An earlier version left self._mgr pointing at the stub — silently
        # disabling real supervision — and spammed fake 'Recovered' alerts into
        # the live feed every time Self-Test ran.)
        saved_mgr = self._mgr
        saved_bus = getattr(self, "_bus", None)
        saved_restarts = dict(self._restarts)
        f = _Fake()
        try:
            self._bus = None            # silence emit() during the probe
            self._mgr = _Mgr(f)
            self._restarts = {}
            self._sweep()
            ok = f.status == "running" and f.started == 1
        finally:
            self._mgr = saved_mgr
            self._bus = saved_bus
            self._restarts = saved_restarts
        self.set_health(100 if ok else 0)
        return (ok, f"auto-recovered a simulated crashed module: {ok}")


def register():
    return WatchdogMonitor()


if __name__ == "__main__":
    import json
    print(json.dumps({"self_test": register().self_test()}, indent=2))
