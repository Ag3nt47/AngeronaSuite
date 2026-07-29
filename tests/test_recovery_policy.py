import pytest

from angerona.core.recovery_policy import (
    BackupObservation, BackupSchedulePolicy, RecoveryObjective,
    RecoveryPolicyEngine,
)


def _policy(**overrides):
    value = {
        "policy_id": "backup-policy-001",
        "cadence_seconds": 3600,
        "retention_count": 2,
        "retention_days": 7,
        "minimum_verified_copies": 2,
        "destination_class": "external-drive",
        "selection_ids": ("configuration", "audit"),
        "enabled": True,
    }
    value.update(overrides)
    return BackupSchedulePolicy(**value)


def _backup(index, created, destination="external-drive"):
    return BackupObservation(
        f"backup-{index:03d}", created, created + 10,
        f"{index:064x}", f"{index + 100:064x}", 1000, destination,
    )


def test_backup_due_is_deterministic_and_disabled_means_no_background_action():
    engine = RecoveryPolicyEngine(b"k" * 32, clock=lambda: 5000)
    assert engine.backup_due(_policy(), (), now=5000).due
    recent = _backup(1, 4000)
    assert not engine.backup_due(_policy(), (recent,), now=5000).due
    assert engine.backup_due(_policy(), (recent,), now=8000).due
    disabled = engine.backup_due(
        _policy(enabled=False), (), now=8000,
    )
    assert not disabled.due
    assert "no background action" in disabled.reason


def test_retention_is_plan_only_signed_and_preserves_floor_and_recent_backups():
    engine = RecoveryPolicyEngine(b"k" * 32, clock=lambda: 20 * 86400)
    observations = tuple(
        _backup(index, index * 86400) for index in range(1, 6)
    )
    plan = engine.plan_retention(_policy(), observations)
    assert engine.verify_retention_plan(plan)
    assert plan.preserve_backup_ids[:2] == ("backup-005", "backup-004")
    assert "backup-001" in plan.delete_backup_ids
    assert set(plan.preserve_backup_ids).isdisjoint(plan.delete_backup_ids)


def test_recovery_drill_measures_rpo_rto_and_required_verification():
    engine = RecoveryPolicyEngine(b"k" * 32)
    objective = RecoveryObjective(
        "objective-001", "database-corruption", 3600, 900, 2,
        "resilience-owner", 10000,
    )
    backup = _backup(1, 1000)
    passed = engine.evaluate_drill(
        objective, drill_id="drill-001", backup=backup,
        started_at=2000, completed_at=2300, verified_copies=2,
        archive_verified=True, manifest_verified=True,
        service_health_verified=True, rollback_verified=True,
    )
    assert passed.passed and engine.verify_drill(passed)
    failed = engine.evaluate_drill(
        objective, drill_id="drill-002", backup=backup,
        started_at=5000, completed_at=7000, verified_copies=1,
        archive_verified=True, manifest_verified=False,
        service_health_verified=False, rollback_verified=False,
    )
    assert not failed.passed
    assert "RPO exceeded" in failed.violations
    assert "RTO exceeded" in failed.violations


def test_recovery_policy_rejects_unsafe_or_unbounded_contracts():
    with pytest.raises(ValueError, match="15 minutes"):
        _policy(cadence_seconds=10)
    with pytest.raises(ValueError, match="scenario"):
        RecoveryObjective(
            "objective-001", "magic-recovery", 3600, 900, 1,
            "owner-001", 100,
        )
