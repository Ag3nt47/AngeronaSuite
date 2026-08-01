import json
import math

import pytest

from angerona.core.operational_slo import (
    SOAK_PROFILES,
    PerformanceBudget,
    RuntimeSample,
    SoakEvidence,
    build_soak_report,
    sample_process,
    structured_health,
    write_soak_report,
)


def _sample(ts, rss=100, threads=10, handles=20, tick=10, depth=0, drops=0):
    return RuntimeSample(ts, rss, threads, handles, tick, depth, 100, drops)


def test_soak_budget_pass_and_failure_are_evidence_based():
    evidence = SoakEvidence(PerformanceBudget(max_rss_growth_mb=20))
    evidence.add(_sample(0, rss=100, tick=10))
    evidence.add(_sample(10, rss=110, tick=20))
    passed = evidence.evaluate()
    assert passed.passed
    assert passed.indicators["rss_growth_mb"] == 10

    evidence.add(_sample(20, rss=150, tick=500, depth=95, drops=2))
    failed = evidence.evaluate()
    assert not failed.passed
    assert any("rss_growth_mb" in item for item in failed.violations)
    assert any("p95_tick_ms" in item for item in failed.violations)
    assert any("dropped_events_delta" in item for item in failed.violations)


def test_sampler_is_bounded_and_preserves_baseline():
    evidence = SoakEvidence(PerformanceBudget(), max_samples=3)
    for index in range(10):
        evidence.add(_sample(index, rss=100 + index))
    result = evidence.evaluate()
    assert result.sample_count == 3
    assert result.indicators["rss_growth_mb"] == 9
    assert result.indicators["samples_evicted"] == 7


def test_peak_pressure_cannot_be_hidden_by_a_late_drop():
    evidence = SoakEvidence(PerformanceBudget(max_rss_growth_mb=20))
    evidence.add(_sample(0, rss=100, threads=10, handles=20))
    evidence.add(_sample(1, rss=150, threads=40, handles=900))
    evidence.add(_sample(2, rss=101, threads=10, handles=20))

    result = evidence.evaluate()

    assert not result.passed
    assert result.indicators["rss_growth_mb"] == 50
    assert result.indicators["thread_growth"] == 30
    assert result.indicators["handle_growth"] == 880


def test_dropped_event_counter_reset_is_unknown_not_a_false_pass():
    evidence = SoakEvidence(PerformanceBudget(max_dropped_events=10))
    evidence.add(_sample(0, drops=5))
    evidence.add(_sample(1, drops=9))
    evidence.add(_sample(2, drops=1))
    evidence.add(_sample(3, drops=3))

    result = evidence.evaluate()

    assert not result.passed
    assert result.indicators["dropped_events_delta"] == 6
    assert result.unknowns == ("dropped-event counter reset 1 time(s)",)


def test_regressing_time_and_invalid_queue_fail_closed():
    evidence = SoakEvidence(PerformanceBudget())
    evidence.add(_sample(10))
    with pytest.raises(ValueError, match="regress"):
        evidence.add(_sample(9))
    with pytest.raises(ValueError, match="exceeds"):
        RuntimeSample(1, 1, 1, 1, 1, 2, 1, 0)
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="finite"):
            RuntimeSample(1, value, 1, 1, 1)


def test_soak_report_is_bounded_private_and_atomic(tmp_path):
    evidence = SoakEvidence(PerformanceBudget())
    evidence.add(_sample(0))
    evidence.add(_sample(10))
    report = build_soak_report(
        profile=SOAK_PROFILES["smoke"], result=evidence.evaluate(),
        completed=True, clock=lambda: 123,
    )
    path = tmp_path / "soak.json"

    write_soak_report(path, report)
    decoded = json.loads(path.read_text(encoding="utf-8"))
    def keys(value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield str(key).casefold()
                yield from keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from keys(item)

    assert decoded["gate_status"] == "pass"
    assert decoded["generated_at_epoch"] == 123
    assert decoded["coverage_ratio"] == 1.0
    assert not {"hostname", "username", "command_line", "pid"}.intersection(keys(decoded))
    assert not list(tmp_path.glob("*.tmp"))


def test_incomplete_soak_coverage_fails_even_when_metrics_pass():
    evidence = SoakEvidence(PerformanceBudget())
    evidence.add(_sample(0))
    evidence.add(_sample(1))
    report = build_soak_report(
        profile=SOAK_PROFILES["8h"], result=evidence.evaluate(), completed=False,
        clock=lambda: 123,
    )
    assert report["gate_status"] == "fail"
    assert report["coverage_ratio"] < 0.01


def test_process_sampler_reads_only_bounded_counters():
    import os

    sample = sample_process(os.getpid(), tick_ms=2.5)
    assert sample.rss_mb > 0
    assert sample.threads >= 1
    assert sample.tick_ms == 2.5
    with pytest.raises(ValueError, match="process ID"):
        sample_process(0, tick_ms=1)


def test_structured_health_never_calls_missing_signal_healthy():
    health = structured_health({
        "recorder": {"state": "healthy", "fresh": True},
        "inventory": {"state": "healthy", "fresh": False},
        "optional": {},
    })
    assert health["overall"] == "unknown"
    assert health["components"]["inventory"] == "degraded"
    assert health["components"]["optional"] == "unknown"
