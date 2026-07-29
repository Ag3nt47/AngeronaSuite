import pytest

from angerona.core.asset_inventory import (
    FieldStatus, InventoryCategory, InventoryRecord, InventoryStore,
    PrivacyClass, collect_snapshot, diff_snapshots, exposure_observations,
)


def record(name, value, *, category=InventoryCategory.OS_POSTURE, collected=100):
    return InventoryRecord(
        category, name, value, FieldStatus.KNOWN, "fixture",
        "signed-local-fixture", collected, 60, PrivacyClass.SYSTEM,
    )


def test_injected_collectors_cover_typed_categories_and_are_deterministic():
    collectors = {
        "software": lambda: [record(
            "app", {"version": "1"}, category=InventoryCategory.SOFTWARE
        )],
        "posture": lambda: [record("secure_boot", True)],
    }
    one = collect_snapshot("host-1", collectors, now=100)
    two = collect_snapshot("host-1", collectors, now=100)
    assert one == two
    assert [item.name for item in one.records] == ["secure_boot", "app"]


def test_collector_errors_are_explicit_unknown_data_not_crashes():
    def broken():
        raise RuntimeError("unavailable")
    snapshot = collect_snapshot("host", {"driver": broken}, now=100)
    item = snapshot.records[0]
    assert item.status is FieldStatus.ERROR
    assert item.value is None
    assert item.source == "driver"
    assert "RuntimeError" in item.error


def test_atomic_roundtrip_and_diff(tmp_path):
    first = collect_snapshot("host", {"x": lambda: [record("firewall", True)]}, now=100)
    second = collect_snapshot("host", {"x": lambda: [record("firewall", False)]}, now=101)
    store = InventoryStore(tmp_path / "inventory.json")
    store.save(first)
    assert store.load() == first
    changes = diff_snapshots(first, second)
    assert len(changes) == 1
    assert changes[0].before.value is True
    assert changes[0].after.value is False


def test_explicit_fresh_risk_metadata_feeds_exposure_model():
    risky = record(
        "vulnerable-driver",
        {"version": "1", "risk": {
            "title": "Known vulnerable driver", "severity": 9,
            "confidence": 95, "known_exploited": True,
            "loaded_or_running": True, "fix_available": True,
            "references": ["CVE-TEST"],
        }},
        category=InventoryCategory.DRIVER,
    )
    snapshot = collect_snapshot("host", {"driver": lambda: [risky]}, now=100)
    observations = exposure_observations(snapshot, now=110)
    assert len(observations) == 1
    assert observations[0].kind == "driver"
    assert observations[0].known_exploited
    assert observations[0].details["privacy"] == "system"
    assert exposure_observations(snapshot, now=1000) == ()


def test_unknown_fields_cannot_claim_values():
    with pytest.raises(ValueError, match="must not claim"):
        InventoryRecord(
            InventoryCategory.FIREWALL, "profiles", {"enabled": True},
            FieldStatus.UNKNOWN, "collector", "api", 1, 10,
        )
