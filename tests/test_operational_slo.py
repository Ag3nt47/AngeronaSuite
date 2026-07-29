import pytest

from angerona.core.operational_slo import (
    PerformanceBudget, RuntimeSample, SoakEvidence, structured_health,
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


def test_regressing_time_and_invalid_queue_fail_closed():
    evidence = SoakEvidence(PerformanceBudget())
    evidence.add(_sample(10))
    with pytest.raises(ValueError, match="regress"):
        evidence.add(_sample(9))
    with pytest.raises(ValueError, match="exceeds"):
        RuntimeSample(1, 1, 1, 1, 1, 2, 1, 0)


def test_structured_health_never_calls_missing_signal_healthy():
    health = structured_health({
        "recorder": {"state": "healthy", "fresh": True},
        "inventory": {"state": "healthy", "fresh": False},
        "optional": {},
    })
    assert health["overall"] == "unknown"
    assert health["components"]["inventory"] == "degraded"
    assert health["components"]["optional"] == "unknown"
