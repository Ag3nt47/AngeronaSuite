from __future__ import annotations

import json
import queue
import time
from types import SimpleNamespace

import pytest

from angerona.core import status_report
from angerona.core.eventbus import Event, EventBus
from angerona.modules.process_monitor import ProcessMonitorModule


def _reporter(tmp_path, modules=None):
    return status_report.StatusReporter(
        EventBus(), SimpleNamespace(count_since=lambda _since: 0),
        SimpleNamespace(modules=modules or {}, is_enabled=lambda _name: False),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=False,
                        ollama_host="local", ollama_model="test"),
    )


def test_optional_detail_reuses_the_exact_legacy_metrics_read(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    received = []
    reporter.bus.subscribe(received.append)
    reporter.bus.publish(Event("fixture", "one"))
    original = reporter.bus.subscriber_metrics
    calls = []

    def read():
        calls.append(True)
        return original()

    monkeypatch.setattr(reporter.bus, "subscriber_metrics", read)
    aggregate, detail = reporter._bus_snapshot(with_details=True)
    assert calls == [True]
    assert aggregate == {
        "delivery_mode": "inline", "revision": 1, "subscriber_count": 1,
        "deliveries": 1, "failures": 0,
        "budget_violations": sum(row.budget_violations for row in original()),
    }
    assert detail["completed"]["rows"][0]["deliveries"] == 1
    assert detail["active"]["total_rows"] == 0


def test_projection_failure_does_not_replace_valid_legacy_aggregates(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)

    def fail(*_args):
        raise RuntimeError("inert projection failure")

    monkeypatch.setattr(status_report, "project_subscribers", fail)
    aggregate, detail = reporter._bus_snapshot(with_details=True)
    assert aggregate["subscriber_count"] == aggregate["deliveries"] == 0
    assert detail["state"] == "unavailable"
    assert detail["completed"] is None and detail["active"] is None
    assert reporter._write()


def test_failed_legacy_getter_preserves_previous_status_instead_of_fresh_zero_counts(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    assert reporter._write()
    path = tmp_path / "diagnostics" / "status.json"
    previous = path.read_bytes()

    def fail():
        raise RuntimeError("inert metric source failure")

    monkeypatch.setattr(reporter.bus, "subscriber_metrics", fail)
    assert not reporter._write(force=True)
    assert path.read_bytes() == previous


def test_quiet_details_do_not_create_clock_churn_or_advance_reporter_cadence(tmp_path, monkeypatch):
    module = ProcessMonitorModule()
    reporter = _reporter(tmp_path, {module.name: module})
    now = [1000.0]
    monkeypatch.setattr(status_report.time, "time", lambda: now[0])
    monkeypatch.setattr(status_report.time, "monotonic", lambda: now[0])
    assert reporter._write()
    path = tmp_path / "diagnostics" / "status.json"
    initial = path.read_bytes()
    now[0] += 29
    assert reporter._write()
    assert path.read_bytes() == initial
    now[0] += 1
    assert reporter._write()
    latest = json.loads(path.read_bytes())
    assert latest["generated_ts"] == now[0]
    assert latest["process_monitor_cycle"]["stage"] == "unobserved"


def test_status_only_calls_exact_builtin_process_cycle_cache_getter(tmp_path):
    class Foreign:
        name = "Process Monitor"
        category = "test"
        version = "test"
        status = "running"
        health = 100
        health_state = "ok"
        health_note = "test"
        last_error = ""

        def cycle_diagnostic_snapshot(self):
            pytest.fail("foreign module callback executed")

    reporter = _reporter(tmp_path, {"Process Monitor": Foreign()})
    assert reporter._snapshot()["process_monitor_cycle"]["state"] == "unavailable"


def test_advancing_owned_process_monitor_cycles_preserve_quiet_write_cadence(tmp_path, monkeypatch):
    """Run the genuine lifecycle/loop; only OS rows and waiting are inert."""
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot

    bus = EventBus()
    module = ProcessMonitorModule()
    module.bind(bus)
    commands, waiting = queue.Queue(), queue.Queue()
    monkeypatch.setattr("psutil.pids", lambda: [])
    monkeypatch.setattr(
        process_monitor, "process_snapshot",
        lambda **_kwargs: ProcessSnapshot((), time.time(), True, 0, 0),
    )

    def controlled_sleep(*_args, **_kwargs):
        waiting.put(True)
        if commands.get(timeout=5) == "stop":
            module.stop()

    monkeypatch.setattr(module, "sleep", controlled_sleep)
    module.start()
    worker = module._thread
    try:
        assert waiting.get(timeout=2) is True
        commands.put("poll")
        assert waiting.get(timeout=2) is True  # one genuine collection completed
        assert worker.is_alive() and module.status == "running"
        reporter = _reporter(tmp_path, {module.name: module})
        reporter.bus = bus
        assert reporter._write()
        path = tmp_path / "diagnostics" / "status.json"
        initial_bytes = path.read_bytes()
        initial = json.loads(initial_bytes)["process_monitor_cycle"]
        cycle_count = module.operational_snapshot()["cycle_count"]
        for _ in range(3):
            commands.put("poll")
            assert waiting.get(timeout=2) is True
            current = module.cycle_diagnostic_snapshot()
            assert current["cycle_serial"] > initial["cycle_serial"]
            # Separate cycles can share a Windows monotonic clock tick.
            assert current["stage_started_monotonic"] >= initial["stage_started_monotonic"]
            assert reporter._write()
            assert path.read_bytes() == initial_bytes
        assert module.operational_snapshot()["cycle_count"] == cycle_count + 3
        # Exercise the existing heartbeat without replacing clocks used by the
        # running worker or manufacturing successful collection/readiness.
        reporter._last_persisted_at = time.monotonic() - 31
        assert reporter._write()
        refreshed = json.loads(path.read_bytes())["process_monitor_cycle"]
        assert refreshed["cycle_serial"] == current["cycle_serial"]
        assert refreshed["stage_started_monotonic"] == current["stage_started_monotonic"]
        assert refreshed["stage_durations_ms"] == current["stage_durations_ms"]
    finally:
        commands.put("stop")
        module.stop()
        worker.join(timeout=5)
    assert not worker.is_alive()


@pytest.mark.parametrize("change", [
    {"generation": 2}, {"state": "partial"}, {"update_loss": True}, {"stage": "stopped"},
])
def test_cycle_failure_generation_and_terminal_changes_are_still_material(tmp_path, monkeypatch, change):
    reporter = _reporter(tmp_path)
    snapshot = reporter._snapshot()
    snapshot["process_monitor_cycle"] = {
        "schema": 1, "state": "observed", "response_authorized": False,
        "generation": 1, "update_loss": False, "stage": "collection",
        "cycle_serial": 1, "stage_started_monotonic": 100.0,
        "stage_durations_ms": {"collection": 1.0},
    }
    monkeypatch.setattr(reporter, "_snapshot", lambda: snapshot)
    assert reporter._write()
    path = tmp_path / "diagnostics" / "status.json"
    previous = path.read_bytes()
    snapshot["process_monitor_cycle"].update(change)
    assert reporter._write()
    assert path.read_bytes() != previous
