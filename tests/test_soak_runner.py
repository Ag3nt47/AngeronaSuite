from __future__ import annotations

import json

import pytest

from tools import run_soak


def test_runtime_metrics_are_strict_and_bounded(tmp_path):
    metrics = tmp_path / "metrics.json"
    metrics.write_text(
        json.dumps({
            "queue_depth": 4,
            "queue_capacity": 20,
            "dropped_events": 0,
            "tick_ms": 12.5,
        }),
        encoding="utf-8",
    )
    assert run_soak._read_runtime_metrics(metrics)["tick_ms"] == 12.5

    metrics.write_text('{"tick_ms": NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        run_soak._read_runtime_metrics(metrics)

    metrics.write_bytes(b"x" * (run_soak._MAX_METRICS_BYTES + 1))
    with pytest.raises(ValueError, match="byte budget"):
        run_soak._read_runtime_metrics(metrics)


def test_duration_override_is_smoke_only():
    assert run_soak._profile("smoke", 1).duration_seconds == 1
    with pytest.raises(ValueError, match="only for smoke"):
        run_soak._profile("8h", 1)
    with pytest.raises(ValueError, match="between 1 and 300"):
        run_soak._profile("smoke", 0)


def test_metric_numbers_reject_booleans_and_strings():
    with pytest.raises(ValueError, match="numeric"):
        run_soak._metric_number({"tick_ms": True}, "tick_ms", 0)
    with pytest.raises(ValueError, match="numeric"):
        run_soak._metric_number({"tick_ms": "10"}, "tick_ms", 0)
    with pytest.raises(ValueError, match="integer"):
        run_soak._metric_integer({"queue_depth": 1.5}, "queue_depth", 0)
