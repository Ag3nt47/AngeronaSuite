"""GUI-neutral lifecycle controller for network-first Chill Mode."""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Iterable

from angerona.core.chill_mode import (
    CHILL_PAUSED_MODULES,
    CHILL_THROTTLE_FLOORS,
    ChillPolicy,
)
from angerona.core.ollama_lifecycle import unload_angerona_models
from angerona.core.threat import active_threat_events


CHILL_USER_ONLY_MODULES = frozenset({
    "Speculative Triage Pre-Warm",
    "Scheduled AI Security Briefing",
    "Smart Deception",
})

# Keep parity with MainWindow's sparse maintenance allowlist. These modules have
# a meaningful bounded first-cycle contract and do not exist solely for an
# attended user experience or background model generation.
CHILL_MAINTENANCE_MODULES = (
    "File Integrity Monitor",
    "YARA Scanner",
    "Memory Injection Scanner",
    "Persistence Sweep",
    "AI Model Integrity Guard",
    "Shadow Shield",
)

_CYCLE_TIMEOUTS = {
    "YARA Scanner": 180.0,
    "Memory Injection Scanner": 90.0,
    "Memory Time-Machine": 60.0,
    "Persistence Sweep": 60.0,
    "Data Provenance Graph": 60.0,
}


class ChillRuntimeController:
    """Apply Chill without importing Qt and coordinate temporary sensor wakes."""

    def __init__(
        self,
        manager,
        bus,
        config,
        *,
        policy: ChillPolicy | None = None,
        poll_interval: float = 1.0,
        cycle_timeout: float = 30.0,
        maintenance_interval: float = 60.0 * 60.0,
        wake_retry_initial: float = 1.0,
        wake_retry_max: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        notify: Callable[[str], None] | None = None,
        release_models: Callable[..., object] = unload_angerona_models,
    ) -> None:
        self.manager = manager
        self.bus = bus
        self.config = config
        self.policy = policy or ChillPolicy()
        self.poll_interval = max(0.05, float(poll_interval))
        self.cycle_timeout = max(1.0, float(cycle_timeout))
        self.maintenance_interval = max(1.0, float(maintenance_interval))
        self.wake_retry_initial = max(0.05, float(wake_retry_initial))
        self.wake_retry_max = max(
            self.wake_retry_initial,
            float(wake_retry_max),
        )
        self._clock = clock
        self._notify = notify or (lambda _message: None)
        self._release_models = release_models
        # Capture before module startup so the first monitor pass consumes its
        # complete EventBus revision delta instead of guessing a ring slice.
        self._revision = bus.revision()
        priority_revision = getattr(bus, "priority_revision", None)
        self._priority_revision: int | None = (
            int(priority_revision()) if callable(priority_revision) else None
        )
        self._overflow_count = 0
        self._paused: set[str] = set()
        self._woken: set[str] = set()
        self._wake_failures: dict[str, int] = {}
        self._wake_retry_at: dict[str, float] = {}
        self._stop = threading.Event()
        self._wake_cancel = threading.Event()
        self._state_lock = threading.RLock()
        self._transition_lock = threading.Lock()
        self._wake_epoch = 0
        self._maintenance_epoch = 0
        self._maintenance_index = 0
        self._next_maintenance_at = self._clock() + self.maintenance_interval
        self._maintenance_name: str | None = None
        self._monitor_thread: threading.Thread | None = None
        self._wake_thread: threading.Thread | None = None
        self._maintenance_thread: threading.Thread | None = None
        self._maintenance_cancel = threading.Event()
        self._release_thread: threading.Thread | None = None

    @property
    def paused_names(self) -> frozenset[str]:
        with self._state_lock:
            return frozenset(self._paused)

    @property
    def woken_names(self) -> frozenset[str]:
        with self._state_lock:
            return frozenset(self._woken)

    @property
    def overflow_count(self) -> int:
        return self._overflow_count

    def _set_runtime_quiet(self, quiet: bool) -> None:
        setattr(self.config, "runtime_chill_active", bool(quiet))
        if quiet:
            os.environ["ANGERONA_CHILL_ACTIVE"] = "1"
        else:
            os.environ.pop("ANGERONA_CHILL_ACTIVE", None)

    def _release_models_async(self) -> None:
        with self._state_lock:
            if self._release_thread is not None and self._release_thread.is_alive():
                return
            host = getattr(self.config, "ollama_host", "http://localhost:11434")
            model = getattr(self.config, "ollama_model", "llama3")

            def _release() -> None:
                try:
                    self._release_models(host, model)
                except Exception:
                    pass

            self._release_thread = threading.Thread(
                target=_release,
                name="HeadlessChillOllamaRelease",
                daemon=True,
            )
            self._release_thread.start()

    def _apply_throttles(self, enabled: bool) -> None:
        for name, floor in CHILL_THROTTLE_FLOORS.items():
            module = self.manager.modules.get(name)
            if module is None:
                continue
            try:
                value = floor if enabled else 1.0
                module.set_throttle_floor(value)
                module.set_throttle(value)
            except Exception:
                pass

    def prepare_runtime(self) -> None:
        """Publish quiet runtime state before any module starts."""
        self.policy.enable()
        self._set_runtime_quiet(True)
        self._next_maintenance_at = self._clock() + self.maintenance_interval
        self._release_models_async()

    def prepare_modules(self) -> set[str]:
        """Apply quiet floors after discovery and return startup deferrals."""
        self._apply_throttles(True)
        return set(CHILL_PAUSED_MODULES)

    def start(self, paused_names: Iterable[str], *, monitor: bool = True) -> None:
        """Mark manager-confirmed deferrals and begin revision monitoring."""
        with self._state_lock:
            for name in paused_names:
                module = self.manager.modules.get(name)
                if module is None:
                    continue
                setattr(module, "_chill_paused", True)
                self._paused.add(name)
            if not monitor:
                return
            if self._monitor_thread is not None and self._monitor_thread.is_alive():
                return
            self._monitor_thread = threading.Thread(
                target=self._monitor,
                name="HeadlessChillMonitor",
                daemon=True,
            )
            self._monitor_thread.start()

    def _enabled(self, name: str) -> bool:
        try:
            return bool(self.manager.is_enabled(name))
        except Exception:
            return False

    def _wake_candidates(self) -> list[str]:
        names: list[str] = []
        now = self._clock()
        for name in CHILL_PAUSED_MODULES:
            if name in CHILL_USER_ONLY_MODULES:
                continue
            module = self.manager.modules.get(name)
            if (
                module is not None
                and bool(getattr(module, "_chill_paused", False))
                and self._enabled(name)
                and self._wake_retry_at.get(name, 0.0) <= now
            ):
                names.append(name)
        return names

    def _record_wake_failure(self, name: str, module) -> None:
        """Re-park a failed incident scanner and schedule bounded backoff."""
        with self._state_lock:
            failures = self._wake_failures.get(name, 0) + 1
            self._wake_failures[name] = failures
            delay = min(
                self.wake_retry_max,
                self.wake_retry_initial * (2 ** min(failures - 1, 20)),
            )
            self._wake_retry_at[name] = self._clock() + delay
            self._woken.discard(name)
            self._paused.add(name)
            setattr(module, "_chill_paused", True)
        self._notify(
            f"Chill verification wake failed for {name}; retrying in "
            f"{delay:.1f}s while the incident lease remains active."
        )

    def _clear_wake_failure(self, name: str) -> None:
        with self._state_lock:
            self._wake_failures.pop(name, None)
            self._wake_retry_at.pop(name, None)

    def _wake_is_current(self, epoch: int, cancel: threading.Event) -> bool:
        with self._state_lock:
            return (
                not self._stop.is_set()
                and not cancel.is_set()
                and epoch == self._wake_epoch
            )

    def _wait_ready(self, module, epoch: int, cancel: threading.Event) -> bool:
        name = str(getattr(module, "name", ""))
        timeout = float(getattr(
            module,
            "eco_cycle_timeout",
            _CYCLE_TIMEOUTS.get(name, self.cycle_timeout),
        ))
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            if not self._wake_is_current(epoch, cancel):
                return False
            status = str(getattr(module, "status", ""))
            if status == "error":
                return False
            health = getattr(module, "health_pct", getattr(module, "health", 100))
            try:
                healthy = int(health) > 0
            except (TypeError, ValueError):
                healthy = False
            if (
                bool(getattr(module, "first_cycle_complete", False))
                and status == "running"
                and healthy
            ):
                return True
            if self._stop.wait(0.05):
                return False
        # Match the GUI worker: a live module whose long first scan exceeded its
        # bounded gate remains useful and does not block the next module forever.
        return str(getattr(module, "status", "")) == "running"

    def _maintenance_is_current(
        self,
        epoch: int,
        cancel: threading.Event,
    ) -> bool:
        with self._state_lock:
            return (
                not self._stop.is_set()
                and not cancel.is_set()
                and epoch == self._maintenance_epoch
                and self.policy.enabled
                and not self.policy.escalated
                and bool(getattr(self.config, "runtime_chill_active", False))
            )

    def _wait_maintenance_ready(
        self,
        module,
        epoch: int,
        cancel: threading.Event,
    ) -> bool:
        name = str(getattr(module, "name", ""))
        timeout = float(getattr(
            module,
            "eco_cycle_timeout",
            _CYCLE_TIMEOUTS.get(name, self.cycle_timeout),
        ))
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            if not self._maintenance_is_current(epoch, cancel):
                return False
            status = str(getattr(module, "status", ""))
            if status == "error":
                return False
            if bool(getattr(module, "first_cycle_complete", False)):
                return True
            if self._stop.wait(0.05):
                return False
        return str(getattr(module, "status", "")) == "running"

    def _maintenance_candidate(self) -> str | None:
        total = len(CHILL_MAINTENANCE_MODULES)
        for _ in range(total):
            name = CHILL_MAINTENANCE_MODULES[self._maintenance_index % total]
            self._maintenance_index += 1
            if name in CHILL_USER_ONLY_MODULES:
                continue
            module = self.manager.modules.get(name)
            if (
                module is not None
                and bool(getattr(module, "_chill_paused", False))
                and str(getattr(module, "status", "")) != "error"
                and self._enabled(name)
            ):
                return name
        return None

    def _maintenance_worker(
        self,
        name: str,
        epoch: int,
        cancel: threading.Event,
    ) -> None:
        module = self.manager.modules.get(name)
        if module is None:
            with self._state_lock:
                self._maintenance_name = None
            return
        with self._transition_lock:
            if not self._maintenance_is_current(epoch, cancel):
                return
            try:
                module.start()
            except Exception:
                setattr(module, "_chill_paused", False)
                with self._state_lock:
                    self._maintenance_name = None
                return
            setattr(module, "_chill_paused", False)
            with self._state_lock:
                self._paused.discard(name)
        self._wait_maintenance_ready(module, epoch, cancel)
        with self._transition_lock:
            if not self._maintenance_is_current(epoch, cancel):
                return
            if str(getattr(module, "status", "")) == "error":
                setattr(module, "_chill_paused", False)
            else:
                try:
                    module.stop()
                except Exception:
                    pass
                setattr(module, "_chill_paused", True)
                with self._state_lock:
                    self._paused.add(name)
            with self._state_lock:
                self._maintenance_name = None
        self._notify(f"Sparse Chill maintenance completed one cycle: {name}.")

    def _cancel_maintenance(self) -> None:
        """Cancel and re-park the leased scanner across the start/stop boundary."""
        with self._state_lock:
            self._maintenance_epoch += 1
            self._maintenance_cancel.set()
            name = self._maintenance_name
        with self._transition_lock:
            if name is not None:
                module = self.manager.modules.get(name)
                if module is not None:
                    if str(getattr(module, "status", "")) == "error":
                        setattr(module, "_chill_paused", False)
                    else:
                        if str(getattr(module, "status", "")) not in {
                            "stopped", "unavailable",
                        }:
                            try:
                                module.stop()
                            except Exception:
                                pass
                        setattr(module, "_chill_paused", True)
                        with self._state_lock:
                            self._paused.add(name)
            with self._state_lock:
                self._maintenance_name = None

    def _maybe_start_maintenance(self) -> None:
        if (
            self._stop.is_set()
            or not self.policy.enabled
            or self.policy.escalated
            or not bool(getattr(self.config, "runtime_chill_active", False))
        ):
            return
        now = self._clock()
        if now < self._next_maintenance_at:
            return
        # Advance before selection/start. A missing or broken optional scanner
        # cannot turn the monitor loop into a tight retry.
        self._next_maintenance_at = now + self.maintenance_interval
        with self._state_lock:
            if (
                self._maintenance_thread is not None
                and self._maintenance_thread.is_alive()
            ):
                return
            name = self._maintenance_candidate()
            if name is None:
                return
            self._maintenance_epoch += 1
            epoch = self._maintenance_epoch
            cancel = threading.Event()
            self._maintenance_cancel = cancel
            self._maintenance_name = name
            self._maintenance_thread = threading.Thread(
                target=self._maintenance_worker,
                args=(name, epoch, cancel),
                name=f"HeadlessChillMaintenance-{name}",
                daemon=True,
            )
            self._maintenance_thread.start()

    def _wake_worker(
        self,
        names: list[str],
        epoch: int,
        cancel: threading.Event,
    ) -> None:
        for name in names:
            module = self.manager.modules.get(name)
            if module is None:
                continue
            # Cancellation and start share one boundary. Once park()/stop()
            # crosses it, this generation cannot start another module.
            with self._transition_lock:
                if not self._wake_is_current(epoch, cancel):
                    return
                try:
                    module.start()
                except Exception:
                    self._record_wake_failure(name, module)
                    continue
                setattr(module, "_chill_paused", False)
                with self._state_lock:
                    self._paused.discard(name)
                    self._woken.add(name)
            ready = self._wait_ready(module, epoch, cancel)
            if not self._wake_is_current(epoch, cancel):
                return
            if not ready:
                self._record_wake_failure(name, module)
            else:
                self._clear_wake_failure(name)
        self._notify(f"Chill verification wake completed for {len(names)} module(s).")

    def _begin_wake(
        self,
        active_count: int,
        *,
        reason: str = "Active threat evidence",
    ) -> None:
        # An alert lease takes priority over sparse maintenance. Re-park the
        # maintenance scanner first so it participates in the full sequential
        # verification wake instead of racing that worker.
        self._cancel_maintenance()
        names = self._wake_candidates()
        with self._state_lock:
            if self._wake_thread is not None and self._wake_thread.is_alive():
                return
            self._wake_epoch += 1
            epoch = self._wake_epoch
            cancel = threading.Event()
            self._wake_cancel = cancel
            self._set_runtime_quiet(False)
            self._apply_throttles(False)
            self._wake_thread = threading.Thread(
                target=self._wake_worker,
                args=(names, epoch, cancel),
                name="HeadlessChillWake",
                daemon=True,
            )
            self._wake_thread.start()
        self._notify(
            f"{reason} ({active_count}) woke {len(names)} "
            "deep verification module(s) sequentially."
        )

    def _maybe_retry_wake(self) -> None:
        """Retry failed incident wakes without a tight failure loop."""
        if self._stop.is_set() or not self.policy.enabled or not self.policy.escalated:
            return
        with self._state_lock:
            if self._wake_thread is not None and self._wake_thread.is_alive():
                return
        if self._wake_candidates():
            self._begin_wake(0, reason="Incident verification retry")

    def _park_after_quiet(self) -> None:
        self._cancel_maintenance()
        with self._state_lock:
            self._wake_epoch += 1
            self._wake_cancel.set()
        parked = 0
        with self._transition_lock:
            for name in CHILL_PAUSED_MODULES:
                module = self.manager.modules.get(name)
                if module is None or not self._enabled(name):
                    if module is not None:
                        setattr(module, "_chill_paused", False)
                    with self._state_lock:
                        self._paused.discard(name)
                        self._woken.discard(name)
                        self._wake_failures.pop(name, None)
                        self._wake_retry_at.pop(name, None)
                    continue
                if str(getattr(module, "status", "")) == "error":
                    # An error is still a deferred scanner, not a permanently
                    # active one. Re-attempt it on the next incident lease.
                    setattr(module, "_chill_paused", True)
                    with self._state_lock:
                        self._paused.add(name)
                        self._woken.discard(name)
                        self._wake_failures.pop(name, None)
                        self._wake_retry_at.pop(name, None)
                    continue
                if str(getattr(module, "status", "")) not in {"stopped", "unavailable"}:
                    try:
                        module.stop()
                    except Exception:
                        pass
                setattr(module, "_chill_paused", True)
                with self._state_lock:
                    self._paused.add(name)
                    self._woken.discard(name)
                    self._wake_failures.pop(name, None)
                    self._wake_retry_at.pop(name, None)
                parked += 1
            self._apply_throttles(True)
            self._set_runtime_quiet(True)
        self._release_models_async()
        self._next_maintenance_at = self._clock() + self.maintenance_interval
        self._notify(f"Quiet window complete; {parked} deep module(s) parked.")

    def poll_once(self) -> None:
        """Consume one EventBus revision delta and advance the policy clock."""
        priority_revision = getattr(self.bus, "priority_revision", None)
        priority_since = getattr(self.bus, "priority_since", None)
        use_priority = (
            self._priority_revision is not None
            and callable(priority_revision)
            and callable(priority_since)
        )
        current = (
            int(priority_revision()) if use_priority else self.bus.revision()
        )
        cursor = self._priority_revision if use_priority else self._revision
        if current != cursor:
            if use_priority:
                self._priority_revision, events, overflow = priority_since(cursor)
            else:
                self._revision, events, overflow = self.bus.recent_since(cursor)
            if overflow:
                self._overflow_count += 1
                self._notify(
                    "Chill priority event delta exceeded its bounded lane; "
                    "waking deep verification conservatively."
                )
            verified = []
            for event in events:
                try:
                    if self.bus.verify(event):
                        verified.append(event)
                except Exception:
                    continue
            try:
                threats = active_threat_events(verified)
            except Exception:
                threats = []
            transition = self.policy.observe_active(threats)
            overflow_transition = None
            if overflow:
                overflow_transition = self.policy.force_escalate(
                    "priority security-event lane overflow requires verification"
                )
            wake_transition = (
                transition
                if transition is not None and transition.action == "escalate"
                else overflow_transition
            )
            if wake_transition is not None and wake_transition.action == "escalate":
                reason = (
                    "Active threat evidence"
                    if transition is wake_transition
                    else "Priority-lane overflow verification"
                )
                self._begin_wake(wake_transition.active_count, reason=reason)
        transition = self.policy.tick()
        if transition is not None and transition.action == "cooldown":
            self._park_after_quiet()
        self._maybe_retry_wake()
        self._maybe_start_maintenance()

    def _monitor(self) -> None:
        while not self._stop.wait(self.poll_interval):
            self.poll_once()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop orchestration without permitting a late scanner start."""
        self._stop.set()
        self._cancel_maintenance()
        with self._state_lock:
            self._wake_epoch += 1
            self._wake_cancel.set()
        # Crossing this boundary proves no old worker remains inside start().
        with self._transition_lock:
            pass
        for thread in (
            self._monitor_thread,
            self._wake_thread,
            self._maintenance_thread,
        ):
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=max(0.0, float(timeout)))
        self.policy.disable()
        # Headless shutdown stops modules immediately after the controller. Keep
        # the no-residency contract in force during that small interval and
        # best-effort release a model that an alert lease may have loaded.
        self._set_runtime_quiet(True)
        self._release_models_async()


__all__ = [
    "CHILL_MAINTENANCE_MODULES",
    "CHILL_USER_ONLY_MODULES",
    "ChillRuntimeController",
]
