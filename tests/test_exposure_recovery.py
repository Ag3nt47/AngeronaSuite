import pytest

from angerona.core.exposure_recovery import (
    ExposureObservation, ExposureRecoveryStore, RecoveryPlan, RecoveryStep,
    prioritize,
)


def test_priority_is_explainable_and_combines_observations():
    items = [
        ExposureObservation("o1", "software", "host/app", "CVE-X", 8, 90,
                            known_exploited=True, reachable=True),
        ExposureObservation("o2", "software", "host/app", "CVE-X", 6, 80,
                            loaded_or_running=True, fix_available=True),
    ]
    result = prioritize(items, now=10)
    assert len(result) == 1
    assert result[0].band == "critical"
    assert result[0].observation_ids == ("o1", "o2")
    assert "known exploited (+15)" in result[0].factors


def test_recovery_plan_is_typed_reversible_and_dependency_checked():
    snapshot = RecoveryStep("s1", "snapshot", "host", "Capture state", (),
                            "snapshot hash recorded", "delete plan-only snapshot reference")
    validate = RecoveryStep("s2", "validate", "host", "Validate recovery", ("s1",),
                            "health checks pass", "restore prior configuration")
    plan = RecoveryPlan("p1", "Safe recovery", ("exp-1",), (snapshot, validate))
    assert plan.execution_authorized is False
    with pytest.raises(ValueError, match="unknown prerequisites"):
        RecoveryPlan("bad", "bad", (), (
            RecoveryStep("x", "validate", "host", "x", ("missing",), "ok", "undo"),
        ))
    with pytest.raises(ValueError, match="planning-only"):
        RecoveryPlan("bad", "bad", (), (snapshot,), execution_authorized=True)


def test_local_snapshot_is_bounded_and_read_only_shape(tmp_path):
    records = prioritize([
        ExposureObservation(str(i), "driver", f"host/d{i}", f"driver-{i}", 5)
        for i in range(5)
    ], now=1)
    store = ExposureRecoveryStore(tmp_path / "exposure-recovery.json", max_records=2)
    store.save(records, [])
    snap = store.snapshot(exposure_limit=100)
    assert snap["local_only"] is True
    assert len(snap["exposures"]) == 2
    assert snap["plans"] == []
