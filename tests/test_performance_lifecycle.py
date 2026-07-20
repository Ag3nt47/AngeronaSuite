from __future__ import annotations

import os
import time
from pathlib import Path

from angerona.core.module_base import BaseModule


class _OneCycleModule(BaseModule):
    def __init__(self, name: str, trace: list[tuple[str, str, float]]) -> None:
        super().__init__()
        self.name = name
        self.trace = trace

    def run(self) -> None:
        self.trace.append((self.name, "work-start", time.monotonic()))
        time.sleep(0.03)
        self.trace.append((self.name, "work-done", time.monotonic()))
        while not self.stopping:
            self.sleep(0.05)


def test_base_module_exposes_real_first_cycle_boundary() -> None:
    trace: list[tuple[str, str, float]] = []
    mod = _OneCycleModule("cycle-test", trace)
    mod.start()
    try:
        assert mod.wait_for_first_cycle(1.0)
        assert mod.first_cycle_complete
        assert mod._cycle_count >= 1
        assert [phase for _, phase, _ in trace][:2] == ["work-start", "work-done"]
    finally:
        mod.stop()


def test_eco_worker_does_not_overlap_initial_work_cycles() -> None:
    from angerona.core.eco_wakeup import EcoWakeupWorker

    trace: list[tuple[str, str, float]] = []
    first = _OneCycleModule("first", trace)
    second = _OneCycleModule("second", trace)
    worker = EcoWakeupWorker([first, second], health_timeout=1.0, min_settle=0.0)
    try:
        worker.run()
        stamps = {(name, phase): stamp for name, phase, stamp in trace}
        assert stamps[("second", "work-start")] >= stamps[("first", "work-done")]
        assert first.first_cycle_complete and second.first_cycle_complete
    finally:
        first.stop()
        second.stop()


def test_startup_eco_defers_heavy_modules_before_their_first_thread() -> None:
    from angerona.core.module_manager import ModuleManager

    starts: list[tuple[str, float]] = []

    class FakeModule:
        enabled_by_default = True

        def __init__(self, name: str) -> None:
            self.name = name

        def start(self, initial_delay: float = 0.0) -> None:
            starts.append((self.name, initial_delay))

    class FakeConfig:
        module_states = {}

    manager = ModuleManager(None, FakeConfig())
    manager.modules = {
        "Process Monitor": FakeModule("Process Monitor"),
        "Light Monitor": FakeModule("Light Monitor"),
        "Watchdog Monitor": FakeModule("Watchdog Monitor"),
    }

    skipped = manager.start_enabled(deferred_names={"Process Monitor"})
    assert skipped == ["Process Monitor"]
    assert [name for name, _ in starts] == ["Watchdog Monitor", "Light Monitor"]
    assert not any(name == "Process Monitor" for name, _ in starts)


def test_normal_startup_waits_for_each_initial_work_cycle() -> None:
    from angerona.core.module_manager import ModuleManager

    trace: list[tuple[str, str, float]] = []
    first = _OneCycleModule("first", trace)
    second = _OneCycleModule("second", trace)

    class FakeConfig:
        module_states = {}

    manager = ModuleManager(None, FakeConfig())
    manager.modules = {"first": first, "second": second}
    try:
        manager.start_enabled(cycle_timeout=1.0, min_settle=0.0)
        stamps = {(name, phase): stamp for name, phase, stamp in trace}
        assert stamps[("second", "work-start")] >= stamps[("first", "work-done")]
        assert first.first_cycle_complete and second.first_cycle_complete
    finally:
        first.stop()
        second.stop()


def test_core_heartbeat_is_published_before_watchdog_supervision(monkeypatch) -> None:
    from angerona.resilience import manager as resilience

    trace: list[str] = []

    class FakeBeat:
        def beat(self) -> None:
            trace.append("core-beat")

        def close(self) -> None:
            pass

    class FakeReader:
        def close(self) -> None:
            pass

    class FakeSupervisor:
        def __init__(self, *args, **kwargs) -> None:
            self.components = {}

        def add(self, name, *args, **kwargs) -> None:
            self.components[name] = object()

        def start(self) -> None:
            trace.append("supervisor-start")

        def stop(self, terminate_children=True) -> None:
            pass

    monkeypatch.setattr(resilience.hb, "HeartbeatWriter", lambda _name: FakeBeat())
    monkeypatch.setattr(resilience, "ProcessSupervisor", FakeSupervisor)
    monkeypatch.setattr(resilience.ipc_ring, "RingReader", lambda _path: FakeReader())
    monkeypatch.setattr(resilience.ipc_ring, "ring_path", lambda _name: "unused")
    monkeypatch.setattr(resilience, "_blackbox_script", lambda: None)

    manager = resilience.ResilienceManager(
        bus=None, start_watchdog=False, with_ui=False
    )
    monkeypatch.setattr(
        manager, "_spawn_thread",
        lambda _target, name: trace.append(f"thread:{name}"),
    )
    manager.start()
    manager.stop()

    assert trace.index("core-beat") < trace.index("supervisor-start")
    assert trace.index("thread:core-heartbeat") < trace.index("supervisor-start")
    assert trace.index("thread:ring-drain") < trace.index("supervisor-start")
    assert trace.index("thread:core-status") < trace.index("supervisor-start")


def test_resilience_sidecars_start_before_module_discovery(monkeypatch) -> None:
    from angerona.app import AngeronaApp
    from angerona.resilience import manager as resilience

    trace: list[str] = []

    class FakeManager:
        def discover(self):
            trace.append("discover")

        def start_enabled(self, **_kwargs):
            trace.append("modules-start")

    class FakeSignal:
        def emit(self):
            trace.append("eco-signal")

    class FakeWindow:
        _ECO_HEAVY_MODULES = ()
        startup_eco_requested = FakeSignal()

    class FakeReporter:
        def start(self):
            trace.append("reporter")

    app = object.__new__(AngeronaApp)
    app.manager = FakeManager()
    app.config = type("Config", (), {"eco_mode": True})()
    app.window = FakeWindow()
    app.reporter = FakeReporter()
    app.bus = object()
    app._mcp = None
    app._resilience = None

    monkeypatch.setenv("ANGERONA_RESILIENCE", "1")
    monkeypatch.setattr(
        resilience,
        "start_resilience",
        lambda _bus: trace.append("resilience") or object(),
    )
    monkeypatch.setattr(
        "angerona.resilience.shutdown_token.clear_standdown", lambda: None
    )

    app._load_modules()

    assert trace.index("resilience") < trace.index("discover")
    assert trace.index("discover") < trace.index("modules-start")


def test_default_runtime_data_is_on_installation_drive(monkeypatch) -> None:
    from angerona.core import data_paths

    data_paths._canonical_data_path.cache_clear()
    monkeypatch.delenv("ANGERONA_DATA", raising=False)
    root = data_paths.data_dir(create=False)
    assert root == data_paths.project_root() / "runtime-data"
    assert root.drive.casefold() == data_paths.project_root().drive.casefold()
    assert root.drive.casefold() == "d:"


def test_frozen_runtime_prefers_configured_fixed_data_drive(monkeypatch) -> None:
    from angerona.core import data_paths

    data_paths._canonical_data_path.cache_clear()
    monkeypatch.delenv("ANGERONA_DATA", raising=False)
    monkeypatch.delenv("ANGERONA_STORAGE_AUTOMIGRATE", raising=False)
    monkeypatch.setenv("ANGERONA_DATA_DRIVE", "D:")
    monkeypatch.setattr(data_paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(data_paths, "_fixed_volume_available", lambda _root: True)
    root = data_paths.data_dir(create=False)
    assert root == data_paths.Path(r"D:\AngeronaData")
    assert data_paths.os.environ["ANGERONA_STORAGE_AUTOMIGRATE"] == "1"


def test_runtime_path_resolution_is_cached_off_the_gui_hot_path(
    monkeypatch, tmp_path
) -> None:
    from angerona.core import data_paths

    calls = 0
    original = data_paths.Path.resolve

    def counted_resolve(path, *args, **kwargs):
        nonlocal calls
        calls += 1
        return original(path, *args, **kwargs)

    data_paths._canonical_data_path.cache_clear()
    monkeypatch.setattr(data_paths.Path, "resolve", counted_resolve)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path / "runtime"))
    first = data_paths.data_dir(create=False)
    second = data_paths.data_dir(create=False)

    assert first == second
    assert calls == 1


def test_ollama_shutdown_unloads_only_running_angerona_models(monkeypatch) -> None:
    from angerona.core import ollama_lifecycle

    calls: list[tuple[str, dict | None]] = []

    def fake(url: str, payload: dict | None, timeout: float) -> dict:
        calls.append((url, payload))
        if url.endswith("/api/ps"):
            return {"models": [
                {"name": "llama3:8b"},
                {"name": "llama3.2:latest"},
                {"name": "gemma3:latest"},
            ]}
        return {"done": True}

    monkeypatch.setattr(ollama_lifecycle, "_json_request", fake)
    unloaded = ollama_lifecycle.unload_angerona_models(configured_model="llama3")
    assert unloaded == ["llama3:8b", "llama3.2:latest"]
    posts = [payload for _, payload in calls if payload]
    assert all(payload["keep_alive"] == 0 for payload in posts)
    assert not any(payload["model"].startswith("gemma") for payload in posts)
