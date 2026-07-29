import json

import pytest

from angerona.core.capacity_registry import CapacityRegistry, CapacitySpec


def test_capacity_registry_accounts_pressure_and_authenticates_report():
    registry = CapacityRegistry((
        CapacitySpec("eventbus", "queue", 500, critical_reserve=50),
        CapacitySpec("resolve-center", "table", 25),
    ), b"k" * 32)
    registry.observe(
        "eventbus", current=480, accepted=500, dropped=4, critical_dropped=0
    )
    registry.observe("eventbus", current=20, evicted=460)
    snapshot = registry.snapshots(now=10)[0]
    assert snapshot.high_water == 480
    assert snapshot.dropped == 4
    assert snapshot.critical_dropped == 0
    report = registry.signed_report(now=10)
    assert registry.verify_report(report)
    tampered = json.loads(report)
    tampered["components"][0]["dropped"] = 0
    assert not registry.verify_report(json.dumps(tampered).encode())


def test_capacity_registry_rejects_unknown_unbounded_or_invalid_counters():
    with pytest.raises(ValueError):
        CapacitySpec("bad", "queue", 10, critical_reserve=10)
    registry = CapacityRegistry(
        (CapacitySpec("worker", "worker", 4),), b"k" * 32
    )
    with pytest.raises(KeyError):
        registry.observe("missing", current=0)
    with pytest.raises(ValueError):
        registry.observe("worker", current=5)
    with pytest.raises(ValueError):
        registry.observe("worker", current=1, dropped=0, critical_dropped=1)
