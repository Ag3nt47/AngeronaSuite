"""Local-only SOC orchestration over Angerona's existing enterprise primitives.

The operations center deliberately does not add a second telemetry pipeline or
an unrestricted remote shell.  It composes the bounded evidence read model,
durable cases, authenticated custody, privacy-minimized inventory, append-only
audit, and signed detection-package registry into one local operator workflow.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.metadata
import json
import platform
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from angerona import __version__
from angerona.core.admin_audit import AdminAuditEntry, AdminAuditLedger
from angerona.core.asset_inventory import (
    FieldStatus,
    InventoryCategory,
    InventoryRecord,
    InventorySnapshot,
    InventoryStore,
    PrivacyClass,
    collect_snapshot,
)
from angerona.core.case_management import (
    CaseRecord,
    CaseStore,
    EvidenceReference,
)
from angerona.core.detection_registry import DetectionPackageRegistry, ValidationReport
from angerona.core.detection_promotion import (
    DetectionPromotionCoordinator,
    PromotionAuthority,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAuthority,
)
from angerona.core.evidence_store import (
    EvidenceEnvelope,
    HuntPredicate,
    HuntQuery,
    HuntResult,
)
from angerona.core.exposure_graph import ExposureSnapshot, verify_snapshot_digest
from angerona.core.fleet_fabric import FleetFabricStore
from angerona.core.security_interop import (
    EvidenceImportResult,
    import_json_evidence,
    parity_summary,
    run_osquery_template,
)
from angerona.modules.detection_runtime import DetectionRuntimeEngine

_MASTER_KEY_NAME = "ANGERONA_INTERNAL_SOC_MASTER_KEY_V1"
_TENANT = "local"
_ACTOR = "local-operator"
_SESSION = "local-soc-session"
_MAX_RUNTIME_COMPONENTS = 2_000


def _derive(master_key: bytes, purpose: bytes) -> bytes:
    return hmac.new(master_key, b"angerona-soc/v1/" + purpose, hashlib.sha256).digest()


def _decode_master_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("protected Local SOC key is invalid") from exc
    if len(raw) != 32:
        raise RuntimeError("protected Local SOC key has an invalid length")
    return raw


def load_or_create_master_key(data_root: Path) -> bytes:
    """Load a 256-bit master from the current user's protected OS store."""
    from angerona.core.secure_store import read_secret_map, write_secret_map

    root = Path(data_root)
    values = read_secret_map(root, strict=True)
    existing = values.get(_MASTER_KEY_NAME)
    if existing:
        return _decode_master_key(existing)
    created = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(created).decode("ascii")
    write_secret_map({_MASTER_KEY_NAME: encoded}, root)
    verified = read_secret_map(root, strict=True).get(_MASTER_KEY_NAME, "")
    if not hmac.compare_digest(verified, encoded):
        raise RuntimeError("protected Local SOC key write did not verify")
    return created


def _record(
    category: InventoryCategory,
    name: str,
    value: Any,
    *,
    source: str,
    provenance: str,
    collected_at: float,
    privacy: PrivacyClass = PrivacyClass.SYSTEM,
    freshness_seconds: float = 24 * 3600,
) -> InventoryRecord:
    return InventoryRecord(
        category=category,
        name=name,
        value=value,
        status=FieldStatus.KNOWN,
        source=source,
        provenance=provenance,
        collected_at=collected_at,
        freshness_seconds=freshness_seconds,
        privacy=privacy,
    )


class LocalOperationsCenter:
    """One local operations facade with no cloud or remote-execution authority."""

    def __init__(
        self,
        data_root: Path,
        *,
        evidence_store: Any | None = None,
        manager: Any | None = None,
        config: Any | None = None,
        master_key: bytes | None = None,
        clock=time.time,
    ) -> None:
        self.data_root = Path(data_root)
        self.root = self.data_root / "operations-center"
        self.root.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self.evidence_store = evidence_store
        self.manager = manager
        self.config = config
        key = bytes(master_key) if master_key is not None else load_or_create_master_key(
            self.data_root
        )
        if len(key) != 32:
            raise ValueError("Local SOC master key must contain exactly 32 bytes")
        self.cases = CaseStore(self.root / "cases.db", _derive(key, b"case-custody"))
        self.audit = AdminAuditLedger(
            self.root / "admin-audit.db", _derive(key, b"admin-audit"), clock=clock
        )
        self.inventory_store = InventoryStore(self.root / "asset-inventory.json")
        trust = self.root / "trusted-detection-publishers.json"
        self.detections = DetectionPackageRegistry(
            self.root / "detection-registry",
            trusted_keys=trust if trust.is_file() else None,
            require_signed=True,
        )
        # Enterprise-pattern program services remain local, bounded, and
        # independently fail closed. A damaged preview store must not hide the
        # case/audit workspace, so its exact initialization error is retained
        # for the clickable program surface instead of weakening validation.
        self.program_errors: dict[str, str] = {}
        self.fleet_fabric: FleetFabricStore | None = None
        try:
            self.fleet_fabric = FleetFabricStore(
                self.root / "fleet-fabric.db",
                {_TENANT: _derive(key, b"fleet-fabric/local-tenant")},
            )
        except Exception as exc:
            self.program_errors["fleet_fabric"] = (
                f"{type(exc).__name__}: {str(exc)[:400]}"
            )

        self.detection_runtime = DetectionRuntimeEngine()
        self.detection_quality: DetectionQualityStore | None = None
        self.detection_promotion: DetectionPromotionCoordinator | None = None
        try:
            input_authority = QualityInputAuthority(
                _derive(key, b"detection-quality-input")
            )
            self.detection_quality = DetectionQualityStore(
                self.root / "detection-quality.jsonl",
                key=_derive(key, b"detection-quality-ledger"),
                input_authority=input_authority,
            )
            self.detection_promotion = DetectionPromotionCoordinator(
                self.detections,
                self.detection_quality,
                PromotionAuthority(_derive(key, b"detection-promotion")),
                state_path=self.root / "detection-promotion-state.json",
            )
        except Exception as exc:
            # Existing pre-v1.13 registries may not have a durable promotion
            # checkpoint. They stay observable, but transitions fail closed
            # until an explicit migration establishes that authority.
            self.program_errors["detection_governance"] = (
                f"{type(exc).__name__}: {str(exc)[:400]}"
            )
            self.detection_promotion = None

        self.exposure_snapshot: ExposureSnapshot | None = None

    def bind_exposure_snapshot(self, snapshot: ExposureSnapshot | None) -> None:
        """Bind one immutable local-provider snapshot; never invent coverage."""
        if snapshot is not None and (
            not isinstance(snapshot, ExposureSnapshot)
            or not verify_snapshot_digest(snapshot)
        ):
            raise ValueError("exposure snapshot receipt is invalid")
        self.exposure_snapshot = snapshot

    def enterprise_program_status(self) -> dict[str, object]:
        """Return exact readiness without claiming remote enterprise scale."""
        return {
            "schema": "angerona.enterprise-program-status.v1",
            "local_only": True,
            "fleet_fabric": self.fleet_fabric is not None,
            "detection_runtime": True,
            "detection_quality": self.detection_quality is not None,
            "detection_promotion": self.detection_promotion is not None,
            "exposure_snapshot": self.exposure_snapshot is not None,
            "errors": dict(self.program_errors),
            "remote_shell": False,
            "coordinator_transport": False,
            "path_simulation_host_actions": False,
        }

    def _append_audit(
        self,
        action: str,
        target: str,
        *,
        result: str = "success",
        decision: str = "allowed",
        before: Mapping[str, Any] | None = None,
        after: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        correlation = "soc-" + uuid.uuid4().hex
        self.audit.append(AdminAuditEntry(
            record_id="audit-" + uuid.uuid4().hex,
            tenant_id=_TENANT,
            actor_id=_ACTOR,
            session_id=_SESSION,
            source="local-soc",
            action=action,
            target=target,
            decision=decision,
            approval_id="",
            result=result,
            correlation_id=correlation,
            timestamp=float(self._clock()),
            before=dict(before or {}),
            after=dict(after or {}),
            details=dict(details or {}),
        ))

    def summary(self) -> dict[str, Any]:
        cases = self.cases.list_cases(limit=2000)
        status_counts = {
            status: sum(item.status == status for item in cases)
            for status in ("open", "investigating", "contained", "resolved", "closed")
        }
        inventory = self.inventory_store.load()
        packages = self.detection_inventory()
        audit_health = dict(self.audit.health(_TENANT))
        return {
            "schema": "angerona.local-soc-summary/v1",
            "local_only": True,
            "cases": len(cases),
            "case_status": status_counts,
            "evidence_records": (
                int(self.evidence_store.count()) if self.evidence_store is not None else 0
            ),
            "inventory_records": len(inventory.records) if inventory else 0,
            "inventory_updated": float(inventory.created_at) if inventory else 0.0,
            "detection_packages": len(packages),
            "capability_parity": parity_summary(),
            "audit": {
                **audit_health,
                "ok": bool(audit_health.get("chain_verified", False)),
            },
            "boundaries": {
                "cloud_required": False,
                "remote_shell": False,
                "arbitrary_query_language": False,
                "detection_activation": "trusted-signature-required",
                "raw_evidence_in_case_database": False,
            },
        }

    def capability_parity(self) -> dict[str, Any]:
        """Return the canonical evidence-backed comparison matrix."""
        return parity_summary()

    def import_security_evidence(
        self, path: Path, format_name: str,
    ) -> EvidenceImportResult:
        """Import a bounded local NDR/OCSF export into normalized evidence."""
        if self.evidence_store is None:
            raise RuntimeError("normalized evidence store is unavailable")
        result = import_json_evidence(path, format_name, self.evidence_store)
        self._append_audit(
            "interop.import", f"evidence/{format_name}",
            details={
                "file_sha256": result.file_sha256,
                "imported": result.imported,
                "duplicates": result.duplicates,
                "skipped": result.skipped,
                "scanned": result.scanned,
                "truncated": result.truncated,
            },
        )
        return result

    def run_osquery_snapshot(self, template_id: str) -> dict[str, Any]:
        """Run and retain one fixed read-only endpoint snapshot."""
        if self.evidence_store is None:
            raise RuntimeError("normalized evidence store is unavailable")
        records = run_osquery_template(template_id)
        imported, duplicates = self.evidence_store.append_many(records)
        result = {
            "template_id": template_id,
            "rows": len(records),
            "imported": imported,
            "duplicates": duplicates,
        }
        self._append_audit(
            "interop.osquery-snapshot", f"endpoint-query/{template_id}",
            details={**result, "arbitrary_sql": False, "extensions": False},
        )
        return result

    def create_case(
        self,
        title: str,
        *,
        assignee: str = "",
        tags: Sequence[str] = (),
    ) -> CaseRecord:
        case = self.cases.create_case(title, assignee=assignee, tags=tags)
        self._append_audit(
            "case.create", case.case_id,
            after={"status": case.status, "tags": list(case.tags)},
        )
        return case

    def update_case(
        self,
        case_id: str,
        *,
        status: str | None = None,
        assignee: str | None = None,
        legal_hold: bool | None = None,
    ) -> CaseRecord:
        before = self.cases.get_case(case_id)
        after = self.cases.update_case(
            case_id,
            before.version,
            status=status,
            assignee=assignee,
            legal_hold=legal_hold,
        )
        self._append_audit(
            "case.update", case_id,
            before={"status": before.status, "assignee": before.assignee,
                    "legal_hold": before.legal_hold},
            after={"status": after.status, "assignee": after.assignee,
                   "legal_hold": after.legal_hold},
        )
        return after

    def add_case_comment(self, case_id: str, text: str) -> int:
        entry_id = self.cases.add_comment(case_id, _ACTOR, text)
        self._append_audit(
            "case.comment", case_id,
            details={"timeline_entry": entry_id, "comment_characters": len(text)},
        )
        return entry_id

    def hunt(
        self,
        *,
        field: str | None = None,
        operator: str = "contains",
        value: Any = None,
        hours: float = 24.0,
        limit: int = 200,
    ) -> HuntResult:
        if self.evidence_store is None:
            raise RuntimeError("normalized evidence store is unavailable")
        predicates: tuple[HuntPredicate, ...] = ()
        if field:
            predicates = (HuntPredicate(field, operator, value),)
        bounded_hours = max(0.05, min(float(hours), 24 * 365.0))
        query = HuntQuery(
            predicates=predicates,
            start_time=float(self._clock()) - bounded_hours * 3600,
            limit=max(1, min(int(limit), 1000)),
            newest_first=True,
        )
        result = self.evidence_store.hunt(query)
        self._append_audit(
            "hunt.execute", "evidence/local",
            details={
                "field": field or "all",
                "operator": operator if field else "none",
                "hours": bounded_hours,
                "limit": query.limit,
                "matches": len(result.evidence),
                "scanned": result.scanned,
                "truncated": result.truncated,
            },
        )
        return result

    def attach_evidence(self, case_id: str, evidence: EvidenceEnvelope) -> EvidenceReference:
        if not isinstance(evidence, EvidenceEnvelope):
            raise TypeError("normalized evidence envelope is required")
        encoded = json.dumps(
            evidence.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        reference_id = "ev-" + hashlib.sha256(
            f"{case_id}:{evidence.event_id}".encode("utf-8")
        ).hexdigest()[:32]
        display_module = "".join(
            character if character.isalnum() or character in "-_" else "_"
            for character in evidence.module
        )[:80] or "event"
        reference = EvidenceReference(
            evidence_id=reference_id,
            display_name=f"{display_module}-{evidence.category[:60]}.json",
            sha256=digest,
            size=len(encoded),
            source="normalized-evidence-store",
            provenance=f"event:{evidence.event_id}; schema:{evidence.schema_version}",
            collected_at=float(self._clock()),
            privacy_class="sensitive",
        )
        owner = self.cases.evidence_owner(reference_id)
        if owner == case_id:
            return reference
        if owner is not None:
            raise ValueError("evidence reference already belongs to another case")
        self.cases.add_evidence(case_id, reference, _ACTOR)
        self._append_audit(
            "evidence.attach", case_id,
            after={"evidence_id": reference_id, "sha256": digest, "size": len(encoded)},
        )
        return reference

    def collect_inventory(self) -> InventorySnapshot:
        stamp = float(self._clock())

        def system_collector() -> Sequence[InventoryRecord]:
            return (
                _record(
                    InventoryCategory.OS_POSTURE,
                    "operating_system",
                    {
                        "family": platform.system(),
                        "release": platform.release(),
                        "architecture": platform.machine(),
                    },
                    source="python.platform",
                    provenance="local_runtime_api",
                    collected_at=stamp,
                ),
                _record(
                    InventoryCategory.SOFTWARE,
                    "angerona",
                    {"version": __version__, "scope": "local-security-suite"},
                    source="angerona",
                    provenance="installed_package_metadata",
                    collected_at=stamp,
                    privacy=PrivacyClass.PUBLIC,
                ),
            )

        def module_collector() -> Sequence[InventoryRecord]:
            if self.manager is None:
                return ()
            inventory = tuple(self.manager.capability_inventory())
            running = sum(row.get("status") == "running" for row in inventory)
            enabled = sum(bool(row.get("enabled")) for row in inventory)
            available = sum(bool(row.get("available", True)) for row in inventory)
            return (_record(
                InventoryCategory.APPLICATION_CONTROL,
                "angerona_modules",
                {
                    "declared": len(inventory),
                    "available": available,
                    "enabled": enabled,
                    "running": running,
                },
                source="module-manager",
                provenance="capability_inventory",
                collected_at=stamp,
                freshness_seconds=300,
            ),)

        def runtime_components() -> Sequence[InventoryRecord]:
            records: list[InventoryRecord] = []
            seen: set[str] = set()
            rows = sorted(
                importlib.metadata.distributions(),
                key=lambda item: str(item.metadata.get("Name") or "").casefold(),
            )
            for distribution in rows:
                name = str(distribution.metadata.get("Name") or "").strip()
                if not name or name.casefold() in seen:
                    continue
                seen.add(name.casefold())
                records.append(_record(
                    InventoryCategory.SBOM_COMPONENT,
                    name[:300],
                    {"version": str(distribution.version)[:200], "scope": "python-runtime"},
                    source="python.metadata",
                    provenance="installed_distribution",
                    collected_at=stamp,
                    privacy=PrivacyClass.PUBLIC,
                ))
                if len(records) >= _MAX_RUNTIME_COMPONENTS:
                    break
            return tuple(records)

        snapshot = collect_snapshot(
            "local-endpoint",
            {
                "angerona-modules": module_collector,
                "runtime-components": runtime_components,
                "system": system_collector,
            },
            now=stamp,
        )
        self.inventory_store.save(snapshot)
        self._append_audit(
            "inventory.collect", "asset/local-endpoint",
            details={"records": len(snapshot.records), "snapshot_id": snapshot.snapshot_id},
        )
        return snapshot

    def detection_inventory(self) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        for package_id, versions in sorted(self.detections.inventory().items()):
            for digest, record in sorted(versions.items()):
                rows.append({
                    "package_id": package_id,
                    "digest": digest,
                    "state": str(record.get("state", "unknown")),
                    "trusted": bool(record.get("trusted", False)),
                    "signer": str(record.get("signer") or ""),
                    "previous_digest": str(record.get("previous_digest") or ""),
                })
        return tuple(rows)

    def stage_detection(
        self, package: Path, *, signature: Path | None = None,
    ) -> ValidationReport:
        report = self.detections.stage(package, signature=signature)
        self._append_audit(
            "detection.stage", "detection/package",
            result="success" if report.ok else "failure",
            after=report.to_dict(),
        )
        return report

    def activate_detection(self, package_id: str, digest: str) -> ValidationReport:
        report = self.detections.activate(package_id, digest)
        self._append_audit(
            "detection.activate", f"detection/{package_id}",
            result="success" if report.ok else "failure",
            after=report.to_dict(),
        )
        return report

    def rollback_detection(self, package_id: str) -> ValidationReport:
        report = self.detections.rollback(package_id)
        self._append_audit(
            "detection.rollback", f"detection/{package_id}",
            result="success" if report.ok else "failure",
            after=report.to_dict(),
        )
        return report

    def audit_records(self, *, limit: int = 500):
        return self.audit.query(_TENANT, limit=max(1, min(int(limit), 5000)))

    def export_case(self, case_id: str, destination: Path) -> Path:
        target = Path(destination)
        if target.exists():
            raise FileExistsError("refusing to replace an existing case export")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = self.cases.export_sanitized(case_id)
        with target.open("xb") as stream:
            stream.write(payload)
            stream.flush()
        self._append_audit(
            "case.export", case_id,
            details={"bytes": len(payload), "sanitized": True},
        )
        return target

    def export_audit(self, destination: Path) -> Path:
        target = Path(destination)
        self.audit.write_once_export(target, _TENANT)
        return target

    def close(self) -> None:
        if self.fleet_fabric is not None:
            self.fleet_fabric.close()
            self.fleet_fabric = None
        self.cases.close()
        self.audit.close()


__all__ = ["LocalOperationsCenter", "load_or_create_master_key"]
