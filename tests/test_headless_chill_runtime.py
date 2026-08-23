from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

from angerona.core import chill_runtime
from angerona.core.chill_mode import CHILL_THROTTLE_FLOORS, ChillPolicy
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity


class _Module:
    def __init__(self, name: str, starts: list[str]) -> None:
        self.name = name
        self.status = "stopped"
        self.health = 100
        self.first_cycle_complete = False
        self._chill_paused = False
        self.starts = starts
        self.stop_calls = 0
        self.floor = 1.0
        self.throttle = 1.0

    def start(self) -> None:
        self.starts.append(self.name)
        self.status = "running"
        self.first_cycle_complete = True

    def stop(self) -> None:
        self.stop_calls += 1
        self.status = "stopped"

    def set_throttle_floor(self, value: float) -> None:
        self.floor = float(value)

    def set_throttle(self, value: float) -> None:
        self.throttle = max(self.floor, float(value))


class _Manager:
    def __init__(self, modules: dict[str, _Module]) -> None:
        self.modules = modules

    def is_enabled(self, name: str) -> bool:
        return name in self.modules


def _wait_thread(thread: threading.Thread | None) -> None:
    assert thread is not None
    thread.join(timeout=2.0)
    assert not thread.is_alive()


def test_headless_chill_wakes_only_verified_active_deep_modules_and_reparks(
    monkeypatch,
) -> None:
    starts: list[str] = []
    modules = {
        "File Integrity Monitor": _Module("File Integrity Monitor", starts),
        "YARA Scanner": _Module("YARA Scanner", starts),
        "Speculative Triage Pre-Warm": _Module("Speculative Triage Pre-Warm", starts),
        "Posture Hardening": _Module("Posture Hardening", starts),
        "Network Monitor": _Module("Network Monitor", starts),
    }
    manager = _Manager(modules)
    bus = EventBus(ring_size=8)
    bus.arm(BusAuthority(b"x" * 32))
    config = SimpleNamespace(
        runtime_chill_active=False,
        ollama_host="http://localhost:11434",
        ollama_model="llama3",
    )
    clock = [10.0]
    released: list[tuple[str, str]] = []
    # Keep classification deterministic while still exercising the controller's
    # signature gate and exact EventBus revision-delta path.
    monkeypatch.setattr(
        chill_runtime,
        "active_threat_events",
        lambda events: [e for e in events if e.details.get("active_attack") is True],
    )
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        policy=ChillPolicy(quiet_seconds=1.0, clock=lambda: clock[0]),
        cycle_timeout=1.0,
        release_models=lambda host, model: released.append((host, model)),
    )
    controller.prepare_runtime()
    deferred = controller.prepare_modules()
    controller.start(
        [name for name in deferred if name in modules and name != "Posture Hardening"],
        monitor=False,
    )

    assert config.runtime_chill_active is True
    assert modules["Posture Hardening"].floor == CHILL_THROTTLE_FLOORS["Posture Hardening"]
    assert modules["Network Monitor"].floor == 1.0

    # Mutating signed details after publication invalidates the HMAC; it must
    # not wake anything even though the classifier would otherwise accept it.
    changed = {"active_attack": False}
    bus.publish(Event("Network Monitor", "changed after signing", Severity.HIGH,
                      details=changed))
    changed["active_attack"] = True
    controller.poll_once()
    assert starts == []

    bus.publish(Event("Network Monitor", "live hostile evidence", Severity.HIGH,
                      details={"active_attack": True}))
    controller.poll_once()
    _wait_thread(controller._wake_thread)

    assert starts == ["File Integrity Monitor", "YARA Scanner"]
    assert modules["Speculative Triage Pre-Warm"]._chill_paused is True
    assert config.runtime_chill_active is False
    assert modules["Posture Hardening"].floor == 1.0

    clock[0] = 11.1
    controller.poll_once()
    assert config.runtime_chill_active is True
    assert modules["File Integrity Monitor"]._chill_paused is True
    assert modules["YARA Scanner"]._chill_paused is True
    assert modules["File Integrity Monitor"].stop_calls == 1
    assert modules["YARA Scanner"].stop_calls == 1
    assert modules["Posture Hardening"].floor == CHILL_THROTTLE_FLOORS["Posture Hardening"]

    deadline = time.monotonic() + 1.0
    while len(released) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(released) == 2  # startup + cooldown releases
    controller.stop()


def test_headless_chill_stop_cancels_sequential_wake_before_next_start(
    monkeypatch,
) -> None:
    starts: list[str] = []
    first = _Module("File Integrity Monitor", starts)
    second = _Module("Memory Time-Machine", starts)
    original_start = first.start

    def slow_start() -> None:
        original_start()
        first.first_cycle_complete = False

    first.start = slow_start  # type: ignore[method-assign]
    manager = _Manager({first.name: first, second.name: second})
    bus = EventBus()
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    monkeypatch.setattr(chill_runtime, "active_threat_events", lambda events: list(events))
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        policy=ChillPolicy(quiet_seconds=60.0),
        cycle_timeout=5.0,
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([first.name, second.name], monitor=False)
    bus.publish(Event("Network Monitor", "active", Severity.HIGH))
    controller.poll_once()

    deadline = time.monotonic() + 1.0
    while not starts and time.monotonic() < deadline:
        time.sleep(0.01)
    assert starts == [first.name]
    controller.stop(timeout=2.0)
    assert starts == [first.name]


def test_sparse_maintenance_runs_one_round_robin_cycle_per_hour() -> None:
    starts: list[str] = []
    first = _Module("File Integrity Monitor", starts)
    second = _Module("YARA Scanner", starts)
    user_only = _Module("Speculative Triage Pre-Warm", starts)
    manager = _Manager({m.name: m for m in (first, second, user_only)})
    bus = EventBus()
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    clock = [0.0]
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        clock=lambda: clock[0],
        maintenance_interval=3600.0,
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([first.name, second.name, user_only.name], monitor=False)

    clock[0] = 3599.9
    controller.poll_once()
    assert starts == []
    clock[0] = 3600.0
    controller.poll_once()
    _wait_thread(controller._maintenance_thread)
    assert starts == [first.name]
    assert first.stop_calls == 1 and first._chill_paused is True

    # Re-polling inside the same lease cannot launch the next scanner.
    controller.poll_once()
    assert starts == [first.name]
    clock[0] = 7200.0
    controller.poll_once()
    _wait_thread(controller._maintenance_thread)
    assert starts == [first.name, second.name]
    assert second.stop_calls == 1 and second._chill_paused is True
    assert user_only.name not in starts
    controller.stop()


def test_active_threat_cancels_maintenance_without_late_repark(monkeypatch) -> None:
    starts: list[str] = []
    module = _Module("File Integrity Monitor", starts)

    def staged_start() -> None:
        starts.append(module.name)
        module.status = "running"
        # Sparse maintenance blocks in its gate; the subsequent alert wake
        # completes immediately.
        module.first_cycle_complete = len(starts) > 1

    module.start = staged_start  # type: ignore[method-assign]
    manager = _Manager({module.name: module})
    bus = EventBus()
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    clock = [0.0]
    monkeypatch.setattr(chill_runtime, "active_threat_events", lambda events: list(events))
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        policy=ChillPolicy(quiet_seconds=60.0),
        clock=lambda: clock[0],
        maintenance_interval=1.0,
        cycle_timeout=5.0,
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([module.name], monitor=False)
    clock[0] = 1.0
    controller.poll_once()
    deadline = time.monotonic() + 1.0
    while not starts and time.monotonic() < deadline:
        time.sleep(0.01)
    assert starts == [module.name]

    bus.publish(Event("Network Monitor", "active", Severity.HIGH))
    controller.poll_once()
    _wait_thread(controller._maintenance_thread)
    _wait_thread(controller._wake_thread)
    assert starts == [module.name, module.name]
    assert module.stop_calls == 1
    assert module.status == "running"
    assert module._chill_paused is False
    controller.stop()


def test_shutdown_cancels_and_reparks_sparse_maintenance() -> None:
    starts: list[str] = []
    module = _Module("File Integrity Monitor", starts)

    def slow_start() -> None:
        starts.append(module.name)
        module.status = "running"
        module.first_cycle_complete = False

    module.start = slow_start  # type: ignore[method-assign]
    manager = _Manager({module.name: module})
    bus = EventBus()
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    clock = [0.0]
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        clock=lambda: clock[0],
        maintenance_interval=1.0,
        cycle_timeout=5.0,
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([module.name], monitor=False)
    clock[0] = 1.0
    controller.poll_once()
    deadline = time.monotonic() + 1.0
    while not starts and time.monotonic() < deadline:
        time.sleep(0.01)
    controller.stop(timeout=2.0)
    _wait_thread(controller._maintenance_thread)
    assert starts == [module.name]
    assert module.stop_calls == 1
    assert module._chill_paused is True


def test_chill_runtime_is_qt_free() -> None:
    source = Path(chill_runtime.__file__).read_text(encoding="utf-8")
    assert "PySide" not in source


def test_info_flood_cannot_hide_active_event_from_headless_chill(monkeypatch) -> None:
    starts: list[str] = []
    module = _Module("File Integrity Monitor", starts)
    manager = _Manager({module.name: module})
    bus = EventBus(ring_size=3)
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    monkeypatch.setattr(
        chill_runtime,
        "active_threat_events",
        lambda events: [event for event in events if event.details.get("active")],
    )
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        policy=ChillPolicy(quiet_seconds=60.0),
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([module.name], monitor=False)

    bus.publish(Event("Network Monitor", "active", Severity.CRITICAL,
                      details={"active": True}))
    for index in range(100):
        bus.publish(Event("Telemetry", f"noise-{index}", Severity.INFO))
    controller.poll_once()
    _wait_thread(controller._wake_thread)

    assert starts == [module.name]
    assert controller.policy.escalated is True
    assert config.runtime_chill_active is False
    controller.stop()


def test_priority_overflow_wakes_verification_but_does_not_invent_a_threat(
    monkeypatch,
) -> None:
    starts: list[str] = []
    module = _Module("File Integrity Monitor", starts)
    manager = _Manager({module.name: module})
    bus = EventBus(ring_size=2, priority_ring_size=2)
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    monkeypatch.setattr(chill_runtime, "active_threat_events", lambda _events: [])
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        policy=ChillPolicy(quiet_seconds=60.0),
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([module.name], monitor=False)

    for index in range(3):
        bus.publish(Event("Detector", f"high-{index}", Severity.HIGH))
    controller.poll_once()
    _wait_thread(controller._wake_thread)

    assert controller.overflow_count == 1
    assert controller.policy.escalated is True
    assert starts == [module.name]
    controller.stop()


def test_failed_incident_wake_retries_with_bounded_backoff(monkeypatch) -> None:
    starts: list[str] = []
    module = _Module("File Integrity Monitor", starts)
    attempts = [0]

    def flaky_start() -> None:
        attempts[0] += 1
        starts.append(module.name)
        if attempts[0] == 1:
            raise RuntimeError("transient start failure")
        module.status = "running"
        module.first_cycle_complete = True

    module.start = flaky_start  # type: ignore[method-assign]
    manager = _Manager({module.name: module})
    bus = EventBus()
    config = SimpleNamespace(ollama_host="local", ollama_model="llama3")
    clock = [0.0]
    monkeypatch.setattr(chill_runtime, "active_threat_events", lambda events: list(events))
    controller = chill_runtime.ChillRuntimeController(
        manager,
        bus,
        config,
        policy=ChillPolicy(quiet_seconds=60.0, clock=lambda: clock[0]),
        clock=lambda: clock[0],
        wake_retry_initial=1.0,
        wake_retry_max=4.0,
        release_models=lambda *_args: None,
    )
    controller.prepare_runtime()
    controller.start([module.name], monitor=False)

    bus.publish(Event("Network Monitor", "active", Severity.HIGH))
    controller.poll_once()
    _wait_thread(controller._wake_thread)
    assert attempts[0] == 1
    assert module._chill_paused is True

    clock[0] = 0.9
    controller.poll_once()
    assert attempts[0] == 1

    clock[0] = 1.0
    controller.poll_once()
    _wait_thread(controller._wake_thread)
    assert attempts[0] == 2
    assert module.status == "running"
    assert module._chill_paused is False
    controller.stop()
