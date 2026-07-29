"""Local exposure prioritization and recovery planning (no execution).

The service consumes already-collected observations.  It does not scan hosts,
fetch intelligence, author commands, or execute remediation; those boundaries
remain with the existing collectors, advisors, guards, and approval systems.
"""
from __future__ import annotations

import json
import hashlib
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "1.0"
MAX_RECORDS = 5000
MAX_STEPS = 32


@dataclass(frozen=True)
class ExposureObservation:
    observation_id: str
    kind: str  # software | driver | control
    asset_id: str
    title: str
    severity: int
    confidence: int = 50
    known_exploited: bool = False
    reachable: bool = False
    loaded_or_running: bool = False
    mitigation_present: bool = False
    fix_available: bool = False
    references: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in {"software", "driver", "control"}:
            raise ValueError("unsupported observation kind")
        if not self.observation_id or not self.asset_id or not self.title:
            raise ValueError("observation_id, asset_id and title are required")
        if not 0 <= self.severity <= 10 or not 0 <= self.confidence <= 100:
            raise ValueError("severity/confidence out of range")
        if len(self.references) > 32:
            raise ValueError("too many references")


@dataclass(frozen=True)
class ExposureRecord:
    exposure_id: str
    asset_id: str
    title: str
    kind: str
    priority: int
    band: str
    factors: tuple[str, ...]
    observation_ids: tuple[str, ...]
    fix_available: bool
    updated_at: float


def prioritize(observations: Sequence[ExposureObservation],
               *, now: float | None = None) -> list[ExposureRecord]:
    """Combine same-asset/title observations into explainable priority records."""
    grouped: dict[tuple[str, str, str], list[ExposureObservation]] = {}
    for item in observations[:MAX_RECORDS]:
        grouped.setdefault((item.asset_id, item.kind, item.title.casefold()), []).append(item)
    output: list[ExposureRecord] = []
    stamp = time.time() if now is None else float(now)
    for (asset_id, kind, _), items in grouped.items():
        severity = max(x.severity for x in items)
        confidence = max(x.confidence for x in items)
        score = severity * 7 + confidence // 10
        factors = [f"base severity {severity}/10", f"confidence {confidence}%"]
        flags = (
            ("known exploited", 15, any(x.known_exploited for x in items)),
            ("reachable", 10, any(x.reachable for x in items)),
            ("loaded or running", 10, any(x.loaded_or_running for x in items)),
            ("mitigation absent", 8, not any(x.mitigation_present for x in items)),
            ("fix available", 5, any(x.fix_available for x in items)),
        )
        for label, weight, enabled in flags:
            if enabled:
                score += weight
                factors.append(f"{label} (+{weight})")
        score = min(100, score)
        band = "critical" if score >= 85 else "high" if score >= 65 else (
            "medium" if score >= 40 else "low"
        )
        ids = tuple(sorted({x.observation_id for x in items}))
        identity = json.dumps(
            [asset_id, kind, ids], separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        output.append(ExposureRecord(
            exposure_id="exp-" + hashlib.sha256(identity).hexdigest()[:16],
            asset_id=asset_id, title=items[0].title, kind=kind,
            priority=score, band=band, factors=tuple(factors),
            observation_ids=ids, fix_available=any(x.fix_available for x in items),
            updated_at=stamp,
        ))
    return sorted(output, key=lambda x: (-x.priority, x.asset_id, x.title))


@dataclass(frozen=True)
class RecoveryStep:
    step_id: str
    action: str
    target: str
    description: str
    prerequisites: tuple[str, ...]
    verification: str
    rollback: str
    reversible: bool = True

    def __post_init__(self) -> None:
        allowed = {
            "isolate", "snapshot", "restore", "reconfigure", "restart",
            "validate", "collect_evidence", "notify",
        }
        if self.action not in allowed:
            raise ValueError("unsupported recovery action")
        if not all((self.step_id, self.target, self.description,
                    self.verification, self.rollback)):
            raise ValueError("recovery steps require verification and rollback")
        if not self.reversible:
            raise ValueError("foundation plans accept reversible steps only")


@dataclass(frozen=True)
class RecoveryPlan:
    plan_id: str
    title: str
    exposure_ids: tuple[str, ...]
    steps: tuple[RecoveryStep, ...]
    created_at: float = field(default_factory=time.time)
    schema_version: str = SCHEMA_VERSION
    execution_authorized: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported plan schema")
        if not self.plan_id or not self.title or not 1 <= len(self.steps) <= MAX_STEPS:
            raise ValueError("invalid recovery plan")
        if self.execution_authorized:
            raise ValueError("this service produces planning-only artifacts")
        ids = {step.step_id for step in self.steps}
        if len(ids) != len(self.steps):
            raise ValueError("duplicate recovery step ID")
        for step in self.steps:
            unknown = set(step.prerequisites) - ids
            if unknown:
                raise ValueError(f"unknown prerequisites: {sorted(unknown)}")


class ExposureRecoveryStore:
    """Bounded local JSON snapshot store with atomic replacement."""

    def __init__(self, path: Path, *, max_records: int = MAX_RECORDS) -> None:
        self.path = Path(path)
        self.max_records = max(1, min(int(max_records), MAX_RECORDS))

    def save(self, exposures: Sequence[ExposureRecord],
             plans: Sequence[RecoveryPlan]) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "local_only": True,
            "saved_at": time.time(),
            "exposures": [asdict(x) for x in exposures[:self.max_records]],
            "plans": [asdict(x) for x in plans[:100]],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        if len(data.encode("utf-8")) > 8 * 1024 * 1024:
            raise ValueError("snapshot exceeds 8 MiB")
        temp.write_text(data, encoding="utf-8")
        os.replace(temp, self.path)

    def snapshot(self, *, exposure_limit: int = 500,
                 plan_limit: int = 50) -> dict[str, Any]:
        exposure_limit = max(1, min(int(exposure_limit), 1000))
        plan_limit = max(1, min(int(plan_limit), 100))
        if not self.path.exists():
            return {"schema_version": SCHEMA_VERSION, "local_only": True,
                    "exposures": [], "plans": []}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported snapshot schema")
        return {
            "schema_version": SCHEMA_VERSION, "local_only": True,
            "saved_at": payload.get("saved_at"),
            "exposures": list(payload.get("exposures", []))[:exposure_limit],
            "plans": list(payload.get("plans", []))[:plan_limit],
        }
