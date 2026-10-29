"""Request-bound native progress uses inert sources and owned file bytes."""
from __future__ import annotations

import hashlib
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import spyware_guard
from angerona.modules.spyware_guard import SpywareGuardModule
from angerona.telemetry.sensors import ConnectionSnapshot, ProcessSnapshot


REQUEST = "c" * 32
OTHER = "d" * 32
NOW = 1800000000.0


def module_with(monkeypatch, **providers):
    providers.setdefault("persistence_collector", lambda **_kw: {"findings": [], "coverage": {}})
    providers.setdefault("process_observer", lambda: ProcessSnapshot((), NOW, True, 0, 0))
    providers.setdefault("connection_observer", lambda: ConnectionSnapshot((), NOW, True, 0, 0))
    module = SpywareGuardModule(clock=lambda: NOW, **providers)
    module.bind(EventBus())
    module._definitions_initialized = True
    module._scan_requested = False
    module._last_scan = NOW
    for name in ("_ensure_report_worker", "_ensure_beacon", "_consume_events", "_collect_responses"):
        monkeypatch.setattr(module, name, lambda: None)
    return module


def terminal(module, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = module.priority_scan_snapshot()
        if result["state"] not in {"idle", "queued", "running"}:
            return result
        time.sleep(.01)
    pytest.fail("Owned inert native request did not settle")


def retire(module):
    module.stop()
    if module._thread is not None:
        module._thread.join(5)
        assert not module._thread.is_alive()


def step(snapshot, key):
    return next(row for row in snapshot["progress"]["steps"] if row["id"] == key)


def test_blocked_provider_remains_observable_and_cancel_does_not_fake_retirement(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    source_calls = []
    def persistence(**kwargs):
        source_calls.append(kwargs)
        entered.set()
        assert release.wait(8)
        return {"findings": [], "coverage": {"inert": "partial"}}
    module = module_with(monkeypatch, persistence_collector=persistence,
                         process_observer=lambda: pytest.fail("Cancelled request collected the next source"))
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(REQUEST) and entered.wait(2)
        running = module.priority_scan_snapshot()
        assert running["state"] == "running" and running["request_finished"] is False
        assert running["module_worker_alive"] is True
        assert step(running, "persistence")["total"] == 1
        assert running["progress"]["current_step"] == "persistence"
        assert "persistence" in running["progress"]["current_task"]
        assert running["progress"]["remaining_s"] is None
        running["progress"]["steps"][0]["completed"] = 999
        assert step(module.priority_scan_snapshot(), "persistence")["completed"] == 0
        module.cancel_priority_scan(REQUEST)
        time.sleep(2.1)  # Exceeds the old controller's two-second retirement guess.
        draining = module.priority_scan_snapshot()
        assert draining["state"] == "running" and not draining["request_finished"]
        assert draining["progress"]["state"] == "cancelling"
        assert draining["progress"]["overall_percent"] < 100
        assert not module.request_priority_scan(OTHER)
        release.set()
        result = terminal(module)
        assert result["state"] == "cancelled" and result["request_finished"] is True
        assert result["collector_finished"] is True and result["module_worker_alive"] is True
        assert result["progress"]["state"] == "cancelled"
        assert result["progress"]["overall_percent"] == 20  # Only the provider that actually returned settled.
        assert step(result, "processes")["completed"] == 0
        assert source_calls == [{"max_entries": 512}]
    finally:
        release.set()
        retire(module)


def test_real_owned_hash_bytes_show_current_file_and_partial_item_progress(monkeypatch, tmp_path):
    path = tmp_path / "owned-inert-sample.bin"
    raw = b"native progress fixture\n" * 8000
    path.write_bytes(raw)
    entered, release = threading.Event(), threading.Event()
    actual_sha = hashlib.sha256
    class HeldHash:
        def __init__(self):
            self.digest = actual_sha()
            self.calls = 0
        def update(self, data):
            self.calls += 1
            if self.calls == 2:
                entered.set()
                assert release.wait(5)
            self.digest.update(data)
        def hexdigest(self):
            return self.digest.hexdigest()
    module = module_with(monkeypatch, process_observer=lambda: ProcessSnapshot(
        ({"pid": 45001, "create_time": NOW - 10, "exe": str(path)},), NOW, True, 0, 0))
    module._definitions = SimpleNamespace(has_hashes=lambda: True)
    matched = []
    monkeypatch.setattr(module, "_match_indicator", lambda record, kind, value, **_kw: matched.append((record, kind, value)))
    monkeypatch.setattr(spyware_guard, "hashlib", SimpleNamespace(sha256=HeldHash))
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(REQUEST) and entered.wait(2)
        current = module.priority_scan_snapshot()
        row = step(current, "hashes")
        assert current["progress"]["current_file"] == str(path)
        assert row["item_completed"] == 65536 and row["item_total"] == len(raw)
        assert 0 < row["item_percent"] < 100
        assert 0 < row["percent"] < 100
        assert current["request_finished"] is False
        assert current["progress"]["overall_percent"] < 100
        release.set()
        result = terminal(module)
        assert result["state"] == "completed" and result["request_finished"]
        assert result["progress"]["overall_percent"] == 100
        assert step(result, "hashes")["checked"] == 1
        assert [(kind, value) for _record, kind, value in matched] == [("sha256", actual_sha(raw).hexdigest())]
        assert path.read_bytes() == raw
    finally:
        release.set()
        retire(module)


def test_known_memory_sample_counts_and_rate_eta_do_not_expand_collection(monkeypatch):
    clock = [0.0]
    entered, release = threading.Event(), threading.Event()
    collected = []
    rows = tuple({"pid": 45001 + index, "create_time": NOW - 10} for index in range(8))
    def memory(pid, **kwargs):
        collected.append((pid, kwargs))
        if len(collected) == 3:
            entered.set()
            assert release.wait(5)
        clock[0] += 1.0
        return {"findings": [], "coverage": {"inert": {"status": "partial"}}}
    module = module_with(monkeypatch, process_observer=lambda: ProcessSnapshot(rows, NOW, True, 0, 0),
                         memory_collector=memory)
    module._settings["spyware_memory_enabled"] = True
    module._priority_progress_clock = lambda: clock[0]
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(REQUEST) and entered.wait(2)
        current = module.priority_scan_snapshot()
        row = step(current, "memory")
        assert row["completed"] == 2 and row["total"] == 4 and row["percent"] == 50
        assert row["remaining_s"] == 2
        assert "45003" in current["progress"]["current_task"]
        assert current["progress"]["current_file"] == ""
        assert current["progress"]["remaining_s"] is None  # Future connection work has no timing history.
        release.set()
        result = terminal(module)
        assert result["progress"]["overall_percent"] == 100
        assert len(collected) == 4
        assert all(options["max_regions"] == 512 for _pid, options in collected)
        assert step(result, "memory")["checked"] == 4
    finally:
        release.set()
        retire(module)


def test_progress_publication_requires_exact_worker_and_generation(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def persistence(**_kwargs):
        entered.set()
        assert release.wait(5)
        return {"findings": [], "coverage": {}}
    module = module_with(monkeypatch, persistence_collector=persistence)
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(REQUEST) and entered.wait(2)
        before = module.priority_scan_snapshot()["progress"]
        module._scan_progress("persistence", completed=1, total=1, task="foreign caller")
        after = module.priority_scan_snapshot()["progress"]
        assert after["sequence"] == before["sequence"] and after["current_task"] == before["current_task"]
        assert after["request_id"] == REQUEST
        assert after["lifecycle_generation"] == module.lifecycle_generation
        release.set()
        assert terminal(module)["request_finished"]
    finally:
        release.set()
        retire(module)


def test_routine_scan_does_not_create_priority_progress_or_schedule_more_sources(monkeypatch):
    module = module_with(monkeypatch)
    assert module._scan_once()
    snapshot = module.priority_scan_snapshot()
    assert snapshot["state"] == "idle" and "progress" not in snapshot
