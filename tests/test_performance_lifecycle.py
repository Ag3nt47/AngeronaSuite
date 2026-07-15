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


def test_default_runtime_data_is_on_installation_drive(monkeypatch) -> None:
    from angerona.core import data_paths

    monkeypatch.delenv("ANGERONA_DATA", raising=False)
    root = data_paths.data_dir(create=False)
    assert root == data_paths.project_root() / "runtime-data"
    assert root.drive.casefold() == data_paths.project_root().drive.casefold()
    assert root.drive.casefold() == "d:"


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
