"""
watchdog_monitor.py — Self-healing module supervisor.

Watches every other module; if one crashes (status 'error') or its worker
thread dies while it should be running, the watchdog restarts it — throttled so
a module that crashes repeatedly is left down (with a CRITICAL alert) instead of
thrashing. Drop-in BaseModule; auto-discovered. Gets the ModuleManager via the
optional bind_manager() hook the manager calls at discovery.
"""
from __future__ import annotations
from dataclasses import dataclass
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


@dataclass
class _RestartState:
    module_identity: int
    attempts: int = 0
    incident_generation: int = 0
    last_attempt_at: float = 0.0
    backoff_until: float = 0.0
    stable_since: float = 0.0
    terminal_reported: bool = False
    last_reason: str = ""


class WatchdogMonitor(BaseModule):
    name = "Watchdog Monitor"
    description = "Self-healing supervisor: detects crashed/hung modules and restarts them (throttled)."
    category = "Resilience"
    version = "1.13.0"
    enabled_by_default = True

    MAX_RESTARTS = 3
    SWEEP_SECONDS = 8.0
    RESTART_BACKOFF_SECONDS = (8.0, 30.0, 120.0)
    STABILITY_RESET_SECONDS = 300.0

    def __init__(self) -> None:
        super().__init__()
        self._mgr = None
        self._restart_state: dict[str, _RestartState] = {}

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

    @staticmethod
    def _snapshot(mod) -> dict[str, object]:
        snapshot = getattr(mod, "operational_snapshot", None)
        if callable(snapshot):
            value = snapshot()
            if isinstance(value, dict):
                return value
        thread = getattr(mod, "_thread", None)
        return {
            "status": str(getattr(mod, "status", "unknown")),
            "health": int(getattr(mod, "health", 0)),
            "thread_alive": bool(thread is not None and thread.is_alive()),
            "lifecycle_generation": int(getattr(mod, "lifecycle_generation", 0)),
            "first_cycle_complete": False,
            "cycle_count": 0,
            "last_cycle_age_seconds": None,
            "watchdog_deadline_missed": False,
        }

    @staticmethod
    def _module_fault(snapshot: dict[str, object]) -> str | None:
        status = str(snapshot.get("status", "unknown"))
        alive = bool(snapshot.get("thread_alive", False))
        if status == "error":
            return "worker reported terminal lifecycle error"
        if status == "running" and not alive:
            return "running lifecycle has no live worker thread"
        if bool(snapshot.get("watchdog_deadline_missed", False)):
            age = snapshot.get("last_cycle_age_seconds")
            if bool(snapshot.get("first_cycle_complete", False)):
                rendered = f"{float(age):.1f}s" if isinstance(age, (int, float)) else "unknown"
                return f"worker heartbeat/cycle deadline missed (last cycle age {rendered})"
            return "worker startup deadline elapsed without a completed cycle"
        return None

    def _restart_exact_generation(
        self,
        name: str,
        mod,
        generation: int,
    ) -> bool:
        authority = getattr(self._mgr, "restart_module_generation", None)
        if callable(authority):
            return bool(authority(name, mod, generation))
        # Restricted fallback supports a minimal embedded manager while keeping
        # the same generation CAS.  Never fall back to a racy stop/start pair.
        restart = getattr(mod, "restart_if_generation", None)
        return bool(callable(restart) and restart(generation))

    def _healthy_state(self, name: str, mod, now: float) -> bool:
        """Age and eventually discard restart debt after proven stability."""
        state = self._restart_state.get(name)
        if state is None:
            return False
        if state.module_identity != id(mod):
            self._restart_state.pop(name, None)
            return False
        if state.stable_since <= 0:
            state.stable_since = now
        if now - state.stable_since >= self.STABILITY_RESET_SECONDS:
            self._restart_state.pop(name, None)
            return False
        return True

    def _sweep(self) -> None:
        mgr = self._mgr
        if mgr is None:
            self.set_health(60, "manager not bound — detection only")
            return
        now = time.monotonic()
        recovery_scheduled = 0
        unresolved = 0
        terminal = 0
        stabilizing = 0
        monitored = 0
        active_names: set[str] = set()
        for name, mod in list(getattr(mgr, "modules", {}).items()):
            if mod is self:
                continue
            if hasattr(mgr, "is_enabled") and not mgr.is_enabled(name):
                self._restart_state.pop(name, None)
                continue                      # respect user-disabled modules
            monitored += 1
            active_names.add(name)
            snapshot = self._snapshot(mod)
            fault = self._module_fault(snapshot)
            if fault is None:
                if self._healthy_state(name, mod, now):
                    stabilizing += 1
                continue
            unresolved += 1
            generation = int(snapshot.get("lifecycle_generation", 0))
            state = self._restart_state.get(name)
            if state is None or state.module_identity != id(mod):
                state = _RestartState(module_identity=id(mod))
                self._restart_state[name] = state
            state.stable_since = 0.0
            state.incident_generation = generation
            state.last_reason = fault

            if state.attempts >= self.MAX_RESTARTS:
                terminal += 1
                if not state.terminal_reported:
                    state.terminal_reported = True
                    self.emit(
                        f"Module '{name}' remains unavailable after "
                        f"{self.MAX_RESTARTS} bounded restart attempts; manual attention needed.",
                        Severity.CRITICAL,
                        module=name,
                        lifecycle_generation=generation,
                        finding_code="watchdog.restart.exhausted",
                        reason=fault,
                        response_authorized=False,
                    )
                continue
            if now < state.backoff_until:
                continue

            attempt = state.attempts + 1
            # Charge an attempt before invoking module code so a throwing or
            # adversarial worker cannot force an unbounded hot restart loop.
            state.attempts = attempt
            state.last_attempt_at = now
            state.backoff_until = now + self.RESTART_BACKOFF_SECONDS[attempt - 1]
            try:
                accepted = self._restart_exact_generation(name, mod, generation)
            except Exception as exc:
                accepted = False
                state.last_reason = f"restart authority failed: {exc}"
            if accepted:
                recovery_scheduled += 1
                self.emit(
                    f"Watchdog scheduled exact-generation recovery for '{name}' "
                    f"(attempt {attempt}/{self.MAX_RESTARTS}).",
                    Severity.HIGH,
                    module=name,
                    lifecycle_generation=generation,
                    finding_code="watchdog.restart.accepted",
                    reason=fault,
                    response_authorized=True,
                )
            else:
                self.emit(
                    f"Watchdog rejected stale or unauthorized recovery for '{name}'.",
                    Severity.HIGH,
                    module=name,
                    lifecycle_generation=generation,
                    finding_code="watchdog.restart.rejected",
                    reason=state.last_reason,
                    response_authorized=False,
                )

        # Drop state for capabilities removed from the manager. This also keeps
        # memory bounded if an integration repeatedly replaces module names.
        for stale_name in set(self._restart_state).difference(active_names):
            self._restart_state.pop(stale_name, None)

        if terminal:
            self.set_health(
                20,
                f"{terminal} enabled module(s) exhausted restart recovery; "
                f"{unresolved} unresolved of {monitored} monitored",
            )
        elif unresolved:
            self.set_health(
                55 if recovery_scheduled else 45,
                f"{unresolved} enabled module(s) unresolved; "
                f"{recovery_scheduled} exact-generation recovery request(s) scheduled",
            )
        elif stabilizing:
            self.set_health(
                85,
                f"{stabilizing} recovered module(s) remain inside the "
                f"{self.STABILITY_RESET_SECONDS:.0f}s stability window",
            )
        else:
            self.set_health(100, f"all {monitored} enabled sibling modules healthy")

    def self_test(self) -> tuple[bool, str]:
        class _Fake:
            def __init__(s): s.status = "error"; s.health = 0; s.started = 0; s.generation = 7
            def operational_snapshot(s):
                return {"status": s.status, "health": s.health, "thread_alive": False,
                        "lifecycle_generation": s.generation,
                        "first_cycle_complete": False,
                        "watchdog_deadline_missed": False}
            def restart_if_generation(s, generation):
                if generation != s.generation: return False
                s.status = "running"; s.health = 100; s.started += 1; s.generation += 1
                return True
        class _Mgr:
            def __init__(s, f): s.modules = {"Fake": f}
            def is_enabled(s, n): return True
        # Isolate: DON'T clobber the real manager binding or emit to the live
        # bus. (An earlier version left self._mgr pointing at the stub — silently
        # disabling real supervision — and spammed fake 'Recovered' alerts into
        # the live feed every time Self-Test ran.)
        saved_mgr = self._mgr
        saved_bus = getattr(self, "_bus", None)
        saved_state = dict(self._restart_state)
        f = _Fake()
        try:
            self._bus = None            # silence emit() during the probe
            self._mgr = _Mgr(f)
            self._restart_state = {}
            self._sweep()
            ok = f.status == "running" and f.started == 1
        finally:
            self._mgr = saved_mgr
            self._bus = saved_bus
            self._restart_state = saved_state
        self.set_health(100 if ok else 0)
        return (ok, f"auto-recovered a simulated crashed module: {ok}")


def register():
    return WatchdogMonitor()


if __name__ == "__main__":
    import json
    print(json.dumps({"self_test": register().self_test()}, indent=2))
