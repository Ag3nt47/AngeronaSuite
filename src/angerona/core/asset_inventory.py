"""Bounded, read-only local asset and exposure inventory contracts."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from angerona.core.exposure_recovery import ExposureObservation

MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 20_000
SCHEMA_VERSION = 1


class InventoryCategory(str, Enum):
    OS_POSTURE = "os_security_posture"
    SOFTWARE = "software"
    DRIVER = "driver"
    FIREWALL = "firewall"
    APPLICATION_CONTROL = "application_control"
    POWERSHELL_LOGGING = "powershell_logging"
    SBOM_COMPONENT = "sbom_component"


class FieldStatus(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    ERROR = "error"


class PrivacyClass(str, Enum):
    PUBLIC = "public"
    SYSTEM = "system"
    SENSITIVE = "sensitive"


@dataclass(frozen=True)
class InventoryRecord:
    category: InventoryCategory
    name: str
    value: Any
    status: FieldStatus
    source: str
    provenance: str
    collected_at: float
    freshness_seconds: float
    privacy: PrivacyClass = PrivacyClass.SYSTEM
    error: str = ""

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 300:
            raise ValueError("inventory field name is required and bounded")
        if not self.source or not self.provenance:
            raise ValueError("source and provenance are required")
        if self.freshness_seconds < 0:
            raise ValueError("freshness must be non-negative")
        if self.status is FieldStatus.ERROR and not self.error:
            raise ValueError("error status requires an error description")
        if self.status is not FieldStatus.ERROR and self.error:
            raise ValueError("error text is valid only for error status")
        if self.status is not FieldStatus.KNOWN and self.value is not None:
            raise ValueError("unknown/error fields must not claim a value")

    def is_fresh(self, *, now: float | None = None) -> bool:
        stamp = time.time() if now is None else float(now)
        return stamp - self.collected_at <= self.freshness_seconds


@dataclass(frozen=True)
class InventorySnapshot:
    snapshot_id: str
    asset_id: str
    created_at: float
    records: tuple[InventoryRecord, ...]
    schema_version: int = SCHEMA_VERSION
    local_only: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(self.records))
        if self.schema_version != SCHEMA_VERSION or not self.local_only:
            raise ValueError("only the local inventory schema is supported")
        if not self.snapshot_id or not self.asset_id:
            raise ValueError("snapshot and asset IDs are required")
        if len(self.records) > MAX_RECORDS:
            raise ValueError("inventory record count exceeds bound")
        if len(_canonical(asdict(self))) > MAX_SNAPSHOT_BYTES:
            raise ValueError("inventory snapshot exceeds 5 MiB")


@dataclass(frozen=True)
class InventoryChange:
    category: InventoryCategory
    name: str
    before: InventoryRecord | None
    after: InventoryRecord | None


Collector = Callable[[], Sequence[InventoryRecord]]


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def collect_snapshot(
    asset_id: str,
    collectors: Mapping[str, Collector],
    *,
    now: float | None = None,
) -> InventorySnapshot:
    """Run explicit injected collectors; failures become attributed error fields."""
    stamp = time.time() if now is None else float(now)
    records: list[InventoryRecord] = []
    for collector_name in sorted(collectors):
        try:
            produced = collectors[collector_name]()
            for record in produced:
                if not isinstance(record, InventoryRecord):
                    raise TypeError("collector returned a non-inventory record")
                records.append(record)
                if len(records) > MAX_RECORDS:
                    raise ValueError("inventory record count exceeds bound")
        except Exception as exc:
            records.append(InventoryRecord(
                category=InventoryCategory.OS_POSTURE,
                name=f"collector.{collector_name}",
                value=None, status=FieldStatus.ERROR,
                source=collector_name, provenance="collector_exception",
                collected_at=stamp, freshness_seconds=0,
                error=f"{type(exc).__name__}: {str(exc)[:500]}",
            ))
    records.sort(key=lambda item: (
        item.category.value, item.name, item.source, item.provenance
    ))
    identity = hashlib.sha256(_canonical([
        asset_id, stamp, [asdict(record) for record in records]
    ])).hexdigest()[:32]
    return InventorySnapshot(
        snapshot_id="inventory-" + identity, asset_id=asset_id,
        created_at=stamp, records=tuple(records),
    )


def diff_snapshots(
    before: InventorySnapshot, after: InventorySnapshot
) -> tuple[InventoryChange, ...]:
    if before.asset_id != after.asset_id:
        raise ValueError("cannot compare different assets")
    def index(snapshot: InventorySnapshot) -> dict[tuple[InventoryCategory, str], InventoryRecord]:
        return {(item.category, item.name): item for item in snapshot.records}
    old, new = index(before), index(after)
    changes: list[InventoryChange] = []
    for key in sorted(set(old) | set(new), key=lambda item: (item[0].value, item[1])):
        if old.get(key) != new.get(key):
            changes.append(InventoryChange(key[0], key[1], old.get(key), new.get(key)))
    return tuple(changes)


def exposure_observations(
    snapshot: InventorySnapshot, *, now: float | None = None
) -> tuple[ExposureObservation, ...]:
    """Translate explicit risk metadata into the existing exposure model."""
    stamp = time.time() if now is None else float(now)
    output: list[ExposureObservation] = []
    kind_map = {
        InventoryCategory.SOFTWARE: "software",
        InventoryCategory.SBOM_COMPONENT: "software",
        InventoryCategory.DRIVER: "driver",
    }
    for record in snapshot.records:
        if record.status is not FieldStatus.KNOWN or not record.is_fresh(now=stamp):
            continue
        if not isinstance(record.value, Mapping):
            continue
        risk = record.value.get("risk")
        if not isinstance(risk, Mapping):
            continue
        severity = risk.get("severity")
        if type(severity) is not int or not 0 <= severity <= 10:
            continue
        confidence = risk.get("confidence", 50)
        if type(confidence) is not int or not 0 <= confidence <= 100:
            continue
        raw_references = risk.get("references", ())
        if not isinstance(raw_references, (list, tuple)):
            raw_references = ()
        kind = kind_map.get(record.category, "control")
        output.append(ExposureObservation(
            observation_id="inv-" + hashlib.sha256(_canonical([
                snapshot.snapshot_id, record.category.value, record.name
            ])).hexdigest()[:24],
            kind=kind, asset_id=snapshot.asset_id,
            title=str(risk.get("title") or record.name)[:300],
            severity=severity,
            confidence=confidence,
            known_exploited=bool(risk.get("known_exploited", False)),
            reachable=bool(risk.get("reachable", False)),
            loaded_or_running=bool(risk.get("loaded_or_running", False)),
            mitigation_present=bool(risk.get("mitigation_present", False)),
            fix_available=bool(risk.get("fix_available", False)),
            references=tuple(str(x)[:500] for x in raw_references[:32]),
            details={
                "inventory_category": record.category.value,
                "inventory_source": record.source,
                "inventory_provenance": record.provenance,
                "privacy": record.privacy.value,
            },
        ))
    return tuple(sorted(output, key=lambda item: item.observation_id))


class InventoryStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def save(self, snapshot: InventorySnapshot) -> None:
        data = _canonical(asdict(snapshot))
        if len(data) > MAX_SNAPSHOT_BYTES:
            raise ValueError("inventory snapshot exceeds 5 MiB")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + f".{os.getpid()}.tmp")
        try:
            with open(temp, "xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def load(self) -> InventorySnapshot | None:
        if not self.path.exists():
            return None
        data = self.path.read_bytes()
        if len(data) > MAX_SNAPSHOT_BYTES:
            raise ValueError("stored inventory exceeds 5 MiB")
        raw = json.loads(data)
        records = tuple(InventoryRecord(
            category=InventoryCategory(item["category"]),
            name=item["name"], value=item["value"],
            status=FieldStatus(item["status"]), source=item["source"],
            provenance=item["provenance"],
            collected_at=float(item["collected_at"]),
            freshness_seconds=float(item["freshness_seconds"]),
            privacy=PrivacyClass(item["privacy"]), error=item.get("error", ""),
        ) for item in raw["records"])
        return InventorySnapshot(
            snapshot_id=raw["snapshot_id"], asset_id=raw["asset_id"],
            created_at=float(raw["created_at"]), records=records,
            schema_version=int(raw["schema_version"]),
            local_only=bool(raw["local_only"]),
        )
