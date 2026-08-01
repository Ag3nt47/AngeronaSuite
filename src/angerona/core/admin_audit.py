"""Tamper-evident, tenant-scoped, append-only local administrator audit."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

from angerona.core.privacy import redact_text

if TYPE_CHECKING:
    from angerona.core.authorization import AuthorizationDecision

MAX_AUDIT_RECORD_BYTES = 64 * 1024
MAX_AUDIT_EXPORT_BYTES = 64 * 1024 * 1024
MAX_AUDIT_EXPORT_RECORDS = 100_000
MAX_AUDIT_QUERY = 5000
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 5000
MAX_JSON_ITEMS = 1000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{1,159}$")
_DECISIONS = {"allowed", "denied", "not-applicable"}
_RESULTS = {"success", "failure", "pending", "not-executed", "unknown"}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sanitize_json(value: Mapping[str, Any]) -> dict[str, Any]:
    remaining = MAX_JSON_NODES

    def visit(item: Any, depth: int) -> Any:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("admin audit JSON node budget exceeded")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("admin audit JSON depth budget exceeded")
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, str):
            return redact_text(item, limit=4096)
        if isinstance(item, int):
            if not -(2**63) <= item <= 2**63 - 1:
                raise ValueError("admin audit integer exceeds signed 64-bit range")
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("admin audit numbers must be finite")
            return item
        if isinstance(item, Mapping):
            if len(item) > MAX_JSON_ITEMS:
                raise ValueError("admin audit object item budget exceeded")
            result: dict[str, Any] = {}
            for key, nested in item.items():
                if not isinstance(key, str) or not key or len(key) > 128:
                    raise ValueError("admin audit keys must be bounded strings")
                result[key] = visit(nested, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            if len(item) > MAX_JSON_ITEMS:
                raise ValueError("admin audit array item budget exceeded")
            return [visit(nested, depth + 1) for nested in item]
        raise TypeError("admin audit accepts plain JSON values only")

    normalized = visit(value, 0)
    if not isinstance(normalized, dict):  # pragma: no cover - caller contract
        raise TypeError("admin audit details must be a mapping")
    return normalized


def _validate_id(value: str, label: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return value
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


@dataclass(frozen=True)
class AdminAuditEntry:
    record_id: str
    tenant_id: str
    actor_id: str
    session_id: str
    source: str
    action: str
    target: str
    decision: str
    approval_id: str
    result: str
    correlation_id: str
    timestamp: float
    before: Mapping[str, Any]
    after: Mapping[str, Any]
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        for value, label, optional in (
            (self.record_id, "record ID", False),
            (self.tenant_id, "tenant ID", False),
            (self.actor_id, "actor ID", False),
            (self.session_id, "session ID", False),
            (self.source, "source", False),
            (self.action, "action", False),
            (self.target, "target", False),
            (self.approval_id, "approval ID", True),
            (self.correlation_id, "correlation ID", False),
        ):
            _validate_id(value, label, optional=optional)
        if self.decision not in _DECISIONS:
            raise ValueError("invalid admin audit decision")
        if self.result not in _RESULTS:
            raise ValueError("invalid admin audit result")
        if not math.isfinite(float(self.timestamp)) or self.timestamp < 0:
            raise ValueError("admin audit timestamp must be finite and non-negative")
        for field in ("before", "after", "details"):
            value = getattr(self, field)
            if not isinstance(value, Mapping):
                raise TypeError(f"admin audit {field} must be a mapping")
            object.__setattr__(self, field, _sanitize_json(value))
        if len(_canonical(asdict(self))) > MAX_AUDIT_RECORD_BYTES:
            raise ValueError("admin audit record exceeds byte budget")


@dataclass(frozen=True)
class StoredAdminAuditRecord:
    sequence: int
    entry: AdminAuditEntry
    previous_hmac: str
    record_hmac: str


class AdminAuditLedger:
    """SQLite ledger with HMAC chaining and database-level append-only triggers."""

    def __init__(self, path: Path, signing_key: bytes, *, clock=time.time) -> None:
        if len(signing_key) < 32:
            raise ValueError("admin audit key must contain at least 32 bytes")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = bytes(signing_key)
        self._clock = clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS admin_audit(
          sequence INTEGER PRIMARY KEY,
          record_id TEXT NOT NULL UNIQUE,
          tenant_id TEXT NOT NULL,
          timestamp REAL NOT NULL,
          action TEXT NOT NULL,
          target TEXT NOT NULL,
          entry_json TEXT NOT NULL,
          previous_hmac TEXT NOT NULL,
          record_hmac TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_admin_audit_tenant_time
          ON admin_audit(tenant_id,timestamp,sequence);
        CREATE INDEX IF NOT EXISTS idx_admin_audit_tenant_action
          ON admin_audit(tenant_id,action,timestamp);
        CREATE TRIGGER IF NOT EXISTS admin_audit_no_update
          BEFORE UPDATE ON admin_audit BEGIN
            SELECT RAISE(ABORT,'admin audit is append-only');
          END;
        CREATE TRIGGER IF NOT EXISTS admin_audit_no_delete
          BEFORE DELETE ON admin_audit BEGIN
            SELECT RAISE(ABORT,'admin audit is append-only');
          END;
        """)

    def _sign(self, sequence: int, entry: Mapping[str, Any], previous: str) -> str:
        return hmac.new(
            self._key,
            _canonical({
                "sequence": sequence,
                "entry": entry,
                "previous_hmac": previous,
            }),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _decode(row: tuple[Any, ...]) -> StoredAdminAuditRecord:
        entry = AdminAuditEntry(**json.loads(row[6]))
        return StoredAdminAuditRecord(
            sequence=int(row[0]),
            entry=entry,
            previous_hmac=str(row[7]),
            record_hmac=str(row[8]),
        )

    def append(self, entry: AdminAuditEntry) -> StoredAdminAuditRecord:
        if not isinstance(entry, AdminAuditEntry):
            raise TypeError("entry must be an AdminAuditEntry")
        entry_value = asdict(entry)
        encoded = _canonical(entry_value).decode("utf-8")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT sequence,record_id,tenant_id,timestamp,action,target,"
                    "entry_json,previous_hmac,record_hmac FROM admin_audit "
                    "WHERE record_id=?",
                    (entry.record_id,),
                ).fetchone()
                if existing is not None:
                    if existing[6] != encoded:
                        raise ValueError("admin audit record ID conflicts")
                    record = self._decode(existing)
                    expected = self._sign(
                        record.sequence, entry_value, record.previous_hmac
                    )
                    if not hmac.compare_digest(record.record_hmac, expected):
                        raise RuntimeError("admin audit record integrity failed")
                    self._db.execute("COMMIT")
                    return record
                global_tail = self._db.execute(
                    "SELECT sequence FROM admin_audit "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                tenant_tail = self._db.execute(
                    "SELECT record_hmac FROM admin_audit WHERE tenant_id=? "
                    "ORDER BY sequence DESC LIMIT 1",
                    (entry.tenant_id,),
                ).fetchone()
                sequence = 1 if global_tail is None else int(global_tail[0]) + 1
                previous = (
                    "0" * 64 if tenant_tail is None else str(tenant_tail[0])
                )
                signature = self._sign(sequence, entry_value, previous)
                self._db.execute(
                    "INSERT INTO admin_audit VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        sequence, entry.record_id, entry.tenant_id,
                        float(entry.timestamp), entry.action, entry.target,
                        encoded, previous, signature,
                    ),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return StoredAdminAuditRecord(sequence, entry, previous, signature)

    def query(
        self,
        tenant_id: str,
        *,
        start_time: float = 0,
        end_time: float = float("inf"),
        action: str | None = None,
        target: str | None = None,
        after_sequence: int = 0,
        limit: int = 500,
    ) -> tuple[StoredAdminAuditRecord, ...]:
        _validate_id(tenant_id, "tenant ID")
        if not math.isfinite(float(start_time)) or start_time < 0:
            raise ValueError("invalid admin audit start time")
        if not (math.isfinite(float(end_time)) or end_time == float("inf")):
            raise ValueError("invalid admin audit end time")
        if end_time < start_time:
            raise ValueError("admin audit time range is reversed")
        if action is not None:
            _validate_id(action, "action")
        if target is not None:
            _validate_id(target, "target")
        limit = max(1, min(int(limit), MAX_AUDIT_QUERY))
        clauses = ["tenant_id=?", "timestamp>=?", "sequence>?"]
        params: list[Any] = [tenant_id, float(start_time), max(0, int(after_sequence))]
        if math.isfinite(float(end_time)):
            clauses.append("timestamp<=?")
            params.append(float(end_time))
        if action is not None:
            clauses.append("action=?")
            params.append(action)
        if target is not None:
            clauses.append("target=?")
            params.append(target)
        params.append(limit)
        # Only fixed clause literals above are joined; every value remains a
        # SQLite parameter. There is no caller-controlled SQL identifier.
        sql = (  # nosec B608
            "SELECT sequence,record_id,tenant_id,timestamp,action,target,"
            "entry_json,previous_hmac,record_hmac FROM admin_audit WHERE "
            + " AND ".join(clauses)  # nosec B608
            + " ORDER BY sequence LIMIT ?"
        )
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return tuple(self._decode(row) for row in rows)

    def verify(self) -> bool:
        with self._lock:
            rows = self._db.execute(
                "SELECT sequence,record_id,tenant_id,timestamp,action,target,"
                "entry_json,previous_hmac,record_hmac FROM admin_audit "
                "ORDER BY sequence"
            )
            previous_by_tenant: dict[str, str] = {}
            expected_sequence = 1
            while True:
                row = rows.fetchone()
                if row is None:
                    break
                try:
                    record = self._decode(row)
                    entry_value = asdict(record.entry)
                except (TypeError, ValueError, json.JSONDecodeError):
                    return False
                previous = previous_by_tenant.get(
                    record.entry.tenant_id, "0" * 64
                )
                if (
                    record.sequence != expected_sequence
                    or record.previous_hmac != previous
                    or not hmac.compare_digest(
                        record.record_hmac,
                        self._sign(record.sequence, entry_value, previous),
                    )
                ):
                    return False
                previous_by_tenant[record.entry.tenant_id] = record.record_hmac
                expected_sequence += 1
        return True

    def health(self, tenant_id: str) -> Mapping[str, Any]:
        _validate_id(tenant_id, "tenant ID")
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*),MIN(timestamp),MAX(timestamp),MAX(sequence) "
                "FROM admin_audit WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        return {
            "schema": "angerona.admin-audit-health/v1",
            "tenant_id": tenant_id,
            "records": int(row[0]),
            "first_timestamp": float(row[1] or 0),
            "last_timestamp": float(row[2] or 0),
            "last_sequence": int(row[3] or 0),
            "chain_verified": self.verify(),
            "append_only_triggers": True,
        }

    def export(self, tenant_id: str) -> bytes:
        _validate_id(tenant_id, "tenant ID")
        serialized: list[dict[str, Any]] = []
        after_sequence = 0
        record_bytes = 2
        byte_reserve = 16 * 1024
        stopped_for_bytes = False
        while len(serialized) < MAX_AUDIT_EXPORT_RECORDS:
            chunk = self.query(
                tenant_id,
                after_sequence=after_sequence,
                limit=min(
                    500,
                    MAX_AUDIT_EXPORT_RECORDS - len(serialized),
                ),
            )
            if not chunk:
                break
            for item in chunk:
                value = {
                    "sequence": item.sequence,
                    "entry": asdict(item.entry),
                    "previous_hmac": item.previous_hmac,
                    "record_hmac": item.record_hmac,
                }
                item_bytes = len(_canonical(value)) + 1
                if (
                    record_bytes + item_bytes + byte_reserve
                    > MAX_AUDIT_EXPORT_BYTES
                ):
                    stopped_for_bytes = True
                    break
                serialized.append(value)
                record_bytes += item_bytes
                after_sequence = item.sequence
            if stopped_for_bytes or len(chunk) < 500:
                break
        with self._lock:
            total_records = int(self._db.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()[0])
        records_digest = hashlib.sha256(_canonical(serialized)).hexdigest()
        manifest_core = {
            "schema": "angerona.admin-audit-export/v1",
            "tenant_id": tenant_id,
            "created_at": float(self._clock()),
            "record_count": len(serialized),
            "first_sequence": serialized[0]["sequence"] if serialized else 0,
            "last_sequence": serialized[-1]["sequence"] if serialized else 0,
            "chain_head": (
                serialized[-1]["record_hmac"] if serialized else "0" * 64
            ),
            "records_sha256": records_digest,
            "truncated": total_records > len(serialized),
        }
        value = {
            "manifest": {
                **manifest_core,
                "manifest_hmac": hmac.new(
                    self._key, _canonical(manifest_core), hashlib.sha256
                ).hexdigest(),
            },
            "records": serialized,
        }
        encoded = _canonical(value)
        if len(encoded) > MAX_AUDIT_EXPORT_BYTES:
            raise ValueError("admin audit export exceeds byte budget")
        return encoded

    def write_once_export(self, path: Path, tenant_id: str) -> None:
        data = self.export(tenant_id)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def verify_export(self, data: bytes, tenant_id: str) -> bool:
        """Verify a complete tenant export without relying on ledger state."""
        try:
            _validate_id(tenant_id, "tenant ID")
            if not isinstance(data, bytes) or len(data) > MAX_AUDIT_EXPORT_BYTES:
                return False
            value = json.loads(data.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {"manifest", "records"}:
                return False
            manifest = value["manifest"]
            records = value["records"]
            if not isinstance(manifest, dict) or not isinstance(records, list):
                return False
            expected_manifest_fields = {
                "schema", "tenant_id", "created_at", "record_count",
                "first_sequence", "last_sequence", "chain_head",
                "records_sha256", "truncated", "manifest_hmac",
            }
            if set(manifest) != expected_manifest_fields:
                return False
            signature = manifest["manifest_hmac"]
            manifest_core = dict(manifest)
            del manifest_core["manifest_hmac"]
            if (
                manifest_core["schema"] != "angerona.admin-audit-export/v1"
                or manifest_core["tenant_id"] != tenant_id
                or type(manifest_core["truncated"]) is not bool
                or type(manifest_core["record_count"]) is not int
                or not hmac.compare_digest(
                    str(signature),
                    hmac.new(
                        self._key, _canonical(manifest_core), hashlib.sha256
                    ).hexdigest(),
                )
                or manifest_core["record_count"] != len(records)
                or len(records) > MAX_AUDIT_EXPORT_RECORDS
                or not hmac.compare_digest(
                    str(manifest_core["records_sha256"]),
                    hashlib.sha256(_canonical(records)).hexdigest(),
                )
            ):
                return False
            previous = "0" * 64
            previous_sequence = 0
            first_sequence = 0
            for raw in records:
                if not isinstance(raw, dict) or set(raw) != {
                    "sequence", "entry", "previous_hmac", "record_hmac",
                }:
                    return False
                sequence = raw["sequence"]
                if type(sequence) is not int or sequence <= previous_sequence:
                    return False
                entry = AdminAuditEntry(**raw["entry"])
                if entry.tenant_id != tenant_id or raw["previous_hmac"] != previous:
                    return False
                expected = self._sign(sequence, asdict(entry), previous)
                if not hmac.compare_digest(str(raw["record_hmac"]), expected):
                    return False
                if not first_sequence:
                    first_sequence = sequence
                previous_sequence = sequence
                previous = str(raw["record_hmac"])
            return (
                manifest_core["first_sequence"] == first_sequence
                and manifest_core["last_sequence"] == previous_sequence
                and manifest_core["chain_head"] == previous
            )
        except (
            KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError
        ):
            return False

    def record_authorization(
        self, decision: AuthorizationDecision
    ) -> StoredAdminAuditRecord:
        scope_parts = decision.scope.split("/")
        if len(scope_parts) < 2 or scope_parts[0] != "fleet":
            raise ValueError("authorization scope does not identify a fleet tenant")
        tenant_id = _validate_id(scope_parts[1], "tenant ID")
        identity = _canonical({
            "tenant_id": tenant_id,
            "request_id": decision.request_id,
            "request_digest": decision.request_digest,
            "policy_hash": decision.policy_hash,
            "decided_at": decision.decided_at,
        })
        return self.append(AdminAuditEntry(
            record_id=(
                "auth:" + hashlib.sha256(identity).hexdigest()
            ),
            tenant_id=tenant_id,
            actor_id=decision.principal_id,
            session_id=f"policy:{decision.policy_hash[:24]}",
            source="local-authorization-policy",
            action=decision.permission,
            target=decision.resource_id or decision.scope,
            decision="allowed" if decision.allowed else "denied",
            approval_id="",
            result="success" if decision.allowed else "not-executed",
            correlation_id=decision.request_id,
            timestamp=decision.decided_at,
            before={},
            after={},
            details={
                "reason": decision.reason,
                "matched_roles": list(decision.matched_roles),
                "principal_kind": decision.principal_kind,
                "policy_hash": decision.policy_hash,
                "request_digest": decision.request_digest,
                "valid_until": decision.valid_until,
            },
        ))

    def close(self) -> None:
        with self._lock:
            self._db.close()
