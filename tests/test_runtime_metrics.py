from __future__ import annotations

import json
import os
import queue
import threading
from types import SimpleNamespace

import pytest

from angerona.core.runtime_metrics import MetricsPublisher, RuntimeMetrics, validate_metrics
from angerona.core.operational_slo import PerformanceBudget, RuntimeSample, SoakEvidence
from tools import run_soak


def recorder():
    return SimpleNamespace(_metrics_lock=threading.Lock(), _queue=queue.Queue(maxsize=20),
                           _overflow_queue=queue.Queue(maxsize=5), _dlq_failures=2)


def collect(*, gui=False, clock=lambda: 0.0, wall_clock=lambda: 100.0):
    return RuntimeMetrics(gui=gui, recorder=recorder(), clock=clock, wall_clock=wall_clock)


def validate(metrics, value, *, now=100.0):
    return validate_metrics(value, pid=metrics.pid, process_started_at=metrics.process_started_at, now=now)


def test_real_queue_depth_worst_capacity_and_delivery_failures_are_measured():
    metrics = collect()
    metrics.recorder._queue.put_nowait("a")
    for _ in range(4):
        metrics.recorder._overflow_queue.put_nowait("b")
    value = validate(metrics, metrics.snapshot())
    assert value["queue_depth"] == 4 and value["queue_capacity"] == 5
    assert value["dropped_events"] == 2
    assert value["gui_applicable"] is False and value["tick_ms"] is None


def test_actual_gui_heartbeat_stall_and_callback_duration_are_not_probe_latency():
    now = [0.0]
    metrics = collect(gui=True, clock=lambda: now[0])
    with pytest.raises(ValueError, match="measurement"):
        validate(metrics, metrics.snapshot())
    metrics.heartbeat()
    metrics.record_tick(45.0)
    now[0] = 1.2
    metrics.heartbeat()
    value = validate(metrics, metrics.snapshot())
    assert value["gui_tick_duration_ms"] == 45.0
    assert value["tick_ms"] == pytest.approx(200.0)
    # The publisher sees a stuck GUI even if no new GUI callback can execute.
    now[0] = 8.0
    assert metrics.snapshot()["tick_ms"] == pytest.approx(5800.0)


@pytest.mark.parametrize("change", [
    lambda value: value.clear(),
    lambda value: value.pop("dropped_events"),
    lambda value: value.update(sampled_at=1.0),
    lambda value: value.update(sampled_at=200.0),
    lambda value: value.update(pid=os.getpid() + 1),
    lambda value: value.update(process_started_at=1.0),
    lambda value: value.update(queue_capacity=0),
    lambda value: value.update(dropped_events=False),
    lambda value: value.update(queues=[]),
    lambda value: value.update(gui_applicable=False, tick_ms=0.0),
])
def test_missing_stale_misattributed_and_fake_headless_measurements_fail(change):
    metrics = collect()
    value = metrics.snapshot()
    change(value)
    with pytest.raises(ValueError):
        validate(metrics, value)


def test_actual_atomic_production_file_roundtrips_with_process_binding(tmp_path):
    metrics = RuntimeMetrics(gui=False, recorder=recorder())
    publisher = MetricsPublisher(metrics, tmp_path)
    publisher.publish()
    raw = run_soak._read_runtime_metrics(publisher.path)
    validated = validate_metrics(raw, pid=metrics.pid, process_started_at=metrics.process_started_at)
    assert validated["queue_capacity"] == 20
    assert publisher.path.stat().st_size < 64 * 1024
    assert publisher.path.name == f"runtime-metrics-{os.getpid()}.json"


def test_publication_is_opt_in_and_cadence_is_bounded(tmp_path, monkeypatch):
    from angerona.core.runtime_metrics import optional_publisher
    monkeypatch.delenv("ANGERONA_RUNTIME_METRICS", raising=False)
    metrics = collect()
    assert optional_publisher(metrics, tmp_path) is None
    assert not list(tmp_path.iterdir())
    with pytest.raises(ValueError, match="ten seconds"):
        MetricsPublisher(metrics, tmp_path, interval=0.1)


def test_empty_metrics_cannot_be_counted_as_long_soak_evidence(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="incomplete"):
        run_soak._sample(os.getpid(), path)


def test_uninstrumented_smoke_has_no_invented_gui_latency():
    sample, supplied = run_soak._sample(os.getpid(), None)
    assert supplied is False
    assert sample.tick_ms is None
    evidence = SoakEvidence(PerformanceBudget())
    evidence.add(RuntimeSample(0, 1, 1, 1, None))
    evidence.add(RuntimeSample(1, 1, 1, 1, None))
    assert "p95_tick_ms" not in evidence.evaluate().indicators


def test_authenticated_engine_sampling_uses_same_strict_schema():
    metrics = RuntimeMetrics(gui=False, recorder=recorder())
    client = SimpleNamespace(metrics=metrics.snapshot)
    sample, supplied = run_soak._sample(os.getpid(), None, engine_client=client,
                                        process_started_at=metrics.process_started_at)
    assert supplied is True and sample.tick_ms is None
    assert sample.dropped_events == 2


def test_gui_refresh_hook_records_real_elapsed_duration_without_io():
    pytest.importorskip("PySide6")
    from angerona.gui.main_window import MainWindow
    ticks = []
    fake = SimpleNamespace(runtime_metrics=SimpleNamespace(record_tick=ticks.append),
                           _tick_count=0, _refresh_body=lambda: None)
    MainWindow._refresh(fake)
    assert len(ticks) == 1 and ticks[0] >= 0


def test_metrics_file_duplicate_fields_are_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"pid":1,"pid":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        run_soak._read_runtime_metrics(path)
