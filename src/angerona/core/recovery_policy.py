"""Deterministic backup cadence, retention plans, and RPO/RTO evidence."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Sequence

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DESTINATIONS = {"external-drive", "network-vault", "offline-media"}
_SCENARIOS = {
    "site-loss",
    "database-corruption",
    "control-plane-compromise",
    "bad-policy-update",
    "lost-signing-key",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


@dataclass(frozen=True)
class BackupSchedulePolicy:
    policy_id: str
    cadence_seconds: int
    retention_count: int
    retention_days: int
    minimum_verified_copies: int
    destination_class: str
    selection_ids: tuple[str, ...]
    enabled: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "selection_ids", tuple(self.selection_ids))
        if not _ID.fullmatch(self.policy_id):
            raise ValueError("invalid backup policy identity")
        if not 900 <= int(self.cadence_seconds) <= 7 * 24 * 3600:
            raise ValueError("backup cadence must be between 15 minutes and 7 days")
        if not 2 <= int(self.retention_count) <= 365:
            raise ValueError("backup retention count must be between 2 and 365")
        if not 1 <= int(self.retention_days) <= 3650:
            raise ValueError("backup retention must be between 1 and 3650 days")
        if not 1 <= int(self.minimum_verified_copies) <= self.retention_count:
            raise ValueError("invalid minimum verified backup copies")
        if self.destination_class not in _DESTINATIONS:
            raise ValueError("invalid backup destination class")
        if not 1 <= len(self.selection_ids) <= 256 or any(
            not _ID.fullmatch(item) for item in self.selection_ids
        ):
            raise ValueError("backup policy requires exact selection IDs")
        if len(set(self.selection_ids)) != len(self.selection_ids):
            raise ValueError("backup policy selection IDs contain duplicates")


@dataclass(frozen=True)
class BackupObservation:
    backup_id: str
    created_at: float
    verified_at: float
    archive_sha256: str
    manifest_sha256: str
    size_bytes: int
    destination_class: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.backup_id):
            raise ValueError("invalid backup observation identity")
        if (
            not math.isfinite(float(self.created_at))
            or not math.isfinite(float(self.verified_at))
            or self.created_at < 0
            or self.verified_at < self.created_at
        ):
            raise ValueError("invalid backup observation timestamps")
        if not _SHA256.fullmatch(self.archive_sha256) or not _SHA256.fullmatch(
            self.manifest_sha256
        ):
            raise ValueError("invalid backup observation digest")
        if not 1 <= int(self.size_bytes) <= 20 * 1024 * 1024 * 1024:
            raise ValueError("invalid backup observation size")
        if self.destination_class not in _DESTINATIONS:
            raise ValueError("invalid backup destination class")


@dataclass(frozen=True)
class BackupDueStatus:
    policy_id: str
    due: bool
    due_since: float
    last_verified_backup: float
    reason: str


@dataclass(frozen=True)
class RetentionPlan:
    policy_id: str
    created_at: float
    preserve_backup_ids: tuple[str, ...]
    delete_backup_ids: tuple[str, ...]
    observation_digest: str
    plan_hmac: str


@dataclass(frozen=True)
class RecoveryObjective:
    objective_id: str
    scenario: str
    rpo_seconds: int
    rto_seconds: int
    minimum_verified_copies: int
    owner: str
    review_at: float

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.objective_id) or not _ID.fullmatch(self.owner):
            raise ValueError("invalid recovery objective identity")
        if self.scenario not in _SCENARIOS:
            raise ValueError("invalid disaster-recovery scenario")
        if not 60 <= int(self.rpo_seconds) <= 30 * 24 * 3600:
            raise ValueError("RPO must be between one minute and 30 days")
        if not 60 <= int(self.rto_seconds) <= 7 * 24 * 3600:
            raise ValueError("RTO must be between one minute and 7 days")
        if not 1 <= int(self.minimum_verified_copies) <= 10:
            raise ValueError("invalid recovery copy objective")
        if not math.isfinite(float(self.review_at)) or self.review_at < 0:
            raise ValueError("invalid recovery objective review time")


@dataclass(frozen=True)
class RecoveryDrillEvidence:
    drill_id: str
    objective_id: str
    scenario: str
    backup_id: str
    started_at: float
    completed_at: float
    measured_rpo_seconds: float
    measured_rto_seconds: float
    verified_copies: int
    archive_verified: bool
    manifest_verified: bool
    service_health_verified: bool
    rollback_verified: bool
    passed: bool
    violations: tuple[str, ...]
    evidence_hmac: str


class RecoveryPolicyEngine:
    """Pure policy/evidence engine; never schedules work or deletes a backup."""

    def __init__(self, audit_key: bytes, *, clock=time.time) -> None:
        if len(audit_key) < 32:
            raise ValueError("recovery policy key must contain at least 32 bytes")
        self._key = bytes(audit_key)
        self._clock = clock

    def backup_due(
        self,
        policy: BackupSchedulePolicy,
        observations: Sequence[BackupObservation],
        *,
        now: float | None = None,
    ) -> BackupDueStatus:
        stamp = float(self._clock() if now is None else now)
        relevant = [
            item for item in observations
            if item.destination_class == policy.destination_class
        ]
        latest = max((item.verified_at for item in relevant), default=0.0)
        if not policy.enabled:
            return BackupDueStatus(
                policy.policy_id, False, 0.0, latest,
                "policy is disabled; no background action is authorized",
            )
        due_since = (
            0.0 if not relevant else latest + policy.cadence_seconds
        )
        due = not relevant or stamp >= due_since
        reason = (
            "no verified backup exists" if not relevant
            else ("cadence elapsed" if due else "verified backup is current")
        )
        return BackupDueStatus(
            policy.policy_id, due, due_since, latest, reason,
        )

    def plan_retention(
        self,
        policy: BackupSchedulePolicy,
        observations: Sequence[BackupObservation],
        *,
        now: float | None = None,
    ) -> RetentionPlan:
        stamp = float(self._clock() if now is None else now)
        relevant = sorted(
            (
                item for item in observations
                if item.destination_class == policy.destination_class
            ),
            key=lambda item: (item.verified_at, item.backup_id),
            reverse=True,
        )
        if len({item.backup_id for item in relevant}) != len(relevant):
            raise ValueError("duplicate backup observation identity")
        keep_floor = max(policy.retention_count, policy.minimum_verified_copies)
        cutoff = stamp - policy.retention_days * 86400
        preserve: list[str] = []
        delete: list[str] = []
        for index, item in enumerate(relevant):
            if index < keep_floor or item.created_at >= cutoff:
                preserve.append(item.backup_id)
            else:
                delete.append(item.backup_id)
        observation_digest = hashlib.sha256(
            _canonical([asdict(item) for item in relevant])
        ).hexdigest()
        core = {
            "policy_id": policy.policy_id,
            "created_at": stamp,
            "preserve_backup_ids": tuple(preserve),
            "delete_backup_ids": tuple(delete),
            "observation_digest": observation_digest,
        }
        return RetentionPlan(
            **core, plan_hmac=hmac.new(
                self._key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_retention_plan(self, plan: RetentionPlan) -> bool:
        value = asdict(plan)
        signature = value.pop("plan_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    def evaluate_drill(
        self,
        objective: RecoveryObjective,
        *,
        drill_id: str,
        backup: BackupObservation,
        started_at: float,
        completed_at: float,
        verified_copies: int,
        archive_verified: bool,
        manifest_verified: bool,
        service_health_verified: bool,
        rollback_verified: bool,
    ) -> RecoveryDrillEvidence:
        if not _ID.fullmatch(drill_id):
            raise ValueError("invalid recovery drill identity")
        started, completed = float(started_at), float(completed_at)
        if (
            not math.isfinite(started) or not math.isfinite(completed)
            or started < backup.created_at or completed < started
        ):
            raise ValueError("invalid recovery drill timing")
        measured_rpo = started - backup.created_at
        measured_rto = completed - started
        violations: list[str] = []
        if measured_rpo > objective.rpo_seconds:
            violations.append("RPO exceeded")
        if measured_rto > objective.rto_seconds:
            violations.append("RTO exceeded")
        if int(verified_copies) < objective.minimum_verified_copies:
            violations.append("verified backup copy objective not met")
        checks = {
            "archive verification failed": archive_verified,
            "manifest verification failed": manifest_verified,
            "service health verification failed": service_health_verified,
            "rollback verification failed": rollback_verified,
        }
        violations.extend(name for name, passed in checks.items() if not passed)
        core = {
            "drill_id": drill_id,
            "objective_id": objective.objective_id,
            "scenario": objective.scenario,
            "backup_id": backup.backup_id,
            "started_at": started,
            "completed_at": completed,
            "measured_rpo_seconds": measured_rpo,
            "measured_rto_seconds": measured_rto,
            "verified_copies": int(verified_copies),
            "archive_verified": bool(archive_verified),
            "manifest_verified": bool(manifest_verified),
            "service_health_verified": bool(service_health_verified),
            "rollback_verified": bool(rollback_verified),
            "passed": not violations,
            "violations": tuple(violations),
        }
        return RecoveryDrillEvidence(
            **core, evidence_hmac=hmac.new(
                self._key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_drill(self, evidence: RecoveryDrillEvidence) -> bool:
        value = asdict(evidence)
        signature = value.pop("evidence_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
        )
