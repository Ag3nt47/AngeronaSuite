import pytest

from angerona.core.exposure_management import ExposureConflict, ExposureManager


def test_exposure_lifecycle_requires_version_and_closure_evidence(tmp_path):
    manager = ExposureManager(tmp_path / "exposure.db", b"k" * 32)
    item = manager.upsert(
        "exposure-001", "asset-001", "CVE-2026-12345", "critical",
        now=100, due_at=200,
    )
    item = manager.transition(
        item.exposure_id, item.version, "assigned", "analyst-001",
        owner="owner-001", now=110,
    )
    with pytest.raises(ExposureConflict):
        manager.transition(item.exposure_id, 1, "mitigating", "analyst-001")
    with pytest.raises(ValueError, match="closure"):
        manager.transition(
            item.exposure_id, item.version, "resolved", "analyst-001",
        )
    closed = manager.transition(
        item.exposure_id, item.version, "resolved", "analyst-001",
        closure_evidence="sha256:" + "a" * 64,
    )
    assert closed.state == "resolved"
    manager.close()


def test_risk_acceptance_requires_reason_and_expiry_then_becomes_due(tmp_path):
    manager = ExposureManager(tmp_path / "exposure.db", b"k" * 32)
    item = manager.upsert(
        "exposure-001", "asset-001", "CVE-2026-12345", "high", now=100,
    )
    with pytest.raises(ValueError, match="reason"):
        manager.transition(
            item.exposure_id, item.version, "accepted", "analyst-001",
            exception_reason="short", exception_expires=200, now=100,
        )
    accepted = manager.transition(
        item.exposure_id, item.version, "accepted", "analyst-001",
        exception_reason="business dependency under active migration",
        exception_expires=200, now=100,
    )
    assert manager.due(now=199) == ()
    assert manager.due(now=200)[0] == accepted
    manager.close()


def test_asset_cve_uniqueness_prevents_duplicate_tracking(tmp_path):
    manager = ExposureManager(tmp_path / "exposure.db", b"k" * 32)
    manager.upsert(
        "exposure-001", "asset-001", "CVE-2026-12345", "high", now=100,
    )
    with pytest.raises(ExposureConflict):
        manager.upsert(
            "exposure-002", "asset-001", "CVE-2026-12345", "critical", now=110,
        )
    manager.close()
