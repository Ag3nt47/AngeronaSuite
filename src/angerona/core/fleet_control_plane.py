"""Offline-first, tenant-isolated fleet inventory and ingestion foundation.

This is a local control-plane store, not a network listener. A future mutual
TLS transport may call this boundary only after authenticating the endpoint and
binding its device identity to exactly one tenant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
MAX_EVENT_BYTES = 256 * 1024
MAX_QUERY_LIMIT = 5000
MAX_EVENT_DEPTH = 32
MAX_EVENT_NODES = 20_000
MAX_EVENT_CONTAINER_ITEMS = 4096
CLOCK_SYNC_WINDOW_SECONDS = 5 * 60
CLOCK_SKEW_WINDOW_SECONDS = 24 * 60 * 60
_CLOCK_QUALITY_UPDATES = {
    "synchronized": (
        "UPDATE fleet_ingest_stats SET stored=stored+1,"
        "synchronized=synchronized+1,last_received_at=? WHERE tenant_id=?"
    ),
    "skewed": (
        "UPDATE fleet_ingest_stats SET stored=stored+1,"
        "skewed=skewed+1,last_received_at=? WHERE tenant_id=?"
    ),
    "untrusted": (
        "UPDATE fleet_ingest_stats SET stored=stored+1,"
        "untrusted=untrusted+1,last_received_at=? WHERE tenant_id=?"
    ),
    "server-assigned": (
        "UPDATE fleet_ingest_stats SET stored=stored+1,"
        "server_assigned=server_assigned+1,last_received_at=? WHERE tenant_id=?"
    ),
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _normalize_event_body(body: Mapping[str, Any]) -> dict[str, Any]:
    """Copy and validate an exact, bounded, finite JSON event object."""
    remaining = MAX_EVENT_NODES

    def visit(value: Any, depth: int) -> Any:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("event JSON node budget exceeded")
        if depth > MAX_EVENT_DEPTH:
            raise ValueError("event JSON depth budget exceeded")
        if value is None or isinstance(value, (str, bool)):
            if isinstance(value, str):
                try:
                    encoded_length = len(value.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise ValueError("event JSON strings must be valid UTF-8") from exc
                if encoded_length > MAX_EVENT_BYTES:
                    raise ValueError("event JSON string exceeds byte budget")
            return value
        if isinstance(value, int):
            if not -(2**63) <= value <= (2**63 - 1):
                raise ValueError("event JSON integer exceeds signed 64-bit range")
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("event JSON numbers must be finite")
            return value
        if isinstance(value, Mapping):
            if len(value) > MAX_EVENT_CONTAINER_ITEMS:
                raise ValueError("event JSON object item budget exceeded")
            copied: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str) or not key or len(key) > 512:
                    raise ValueError("event JSON keys must be bounded strings")
                copied[key] = visit(item, depth + 1)
            return copied
        if isinstance(value, list):
            if len(value) > MAX_EVENT_CONTAINER_ITEMS:
                raise ValueError("event JSON array item budget exceeded")
            return [visit(item, depth + 1) for item in value]
        raise TypeError("event body accepts plain JSON values only")

    normalized = visit(body, 0)
    if not isinstance(normalized, dict):  # pragma: no cover - guarded by caller
        raise TypeError("event body must be a mapping")
    return normalized


def _validate_id(value: str, label: str) -> str:
    value = str(value)
    if not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


@dataclass(frozen=True)
class FleetDevice:
    tenant_id: str
    device_id: str
    public_key: str
    hostname_token: str
    platform: str
    version: str
    group_id: str = "default"
    state: str = "active"
    last_seen: float = 0

    def __post_init__(self) -> None:
        for value, label in (
            (self.tenant_id, "tenant ID"), (self.device_id, "device ID"),
            (self.group_id, "group ID"),
        ):
            _validate_id(value, label)
        if self.state not in {"active", "quarantined", "revoked", "retired"}:
            raise ValueError("invalid device state")
        if not self.public_key or len(self.public_key) > 512:
            raise ValueError("invalid device public key")
        if not self.hostname_token.startswith("tok_") or len(self.hostname_token) > 80:
            raise ValueError("hostname must be tokenized")
        if not self.platform or len(self.platform) > 40 or len(self.version) > 80:
            raise ValueError("invalid platform or version")


@dataclass(frozen=True)
class IngestReceipt:
    tenant_id: str
    device_id: str
    event_id: str
    accepted: bool
    duplicate: bool
    recorded_at: float
    received_at: float
    clock_quality: str
    clock_skew_seconds: float
    event_hash: str
    receipt_hmac: str


class FleetControlPlane:
    """Durable local store with mandatory tenant predicates on every operation."""

    def __init__(
        self,
        path: Path,
        tenant_keys: Mapping[str, bytes],
        *,
        clock=time.time,
    ) -> None:
        if not tenant_keys:
            raise ValueError("at least one tenant key is required")
        self._keys = {}
        for tenant, key in tenant_keys.items():
            tenant = _validate_id(tenant, "tenant ID")
            if len(key) < 32:
                raise ValueError("tenant keys must contain at least 32 bytes")
            self._keys[tenant] = bytes(key)
        self.path = Path(path)
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS fleet_devices(
          tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
          public_key TEXT NOT NULL, hostname_token TEXT NOT NULL,
          platform TEXT NOT NULL, version TEXT NOT NULL, group_id TEXT NOT NULL,
          state TEXT NOT NULL, last_seen REAL NOT NULL,
          PRIMARY KEY(tenant_id, device_id));
        CREATE TABLE IF NOT EXISTS fleet_events(
          tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, device_id TEXT NOT NULL,
          observed_at REAL NOT NULL, received_at REAL NOT NULL,
          clock_quality TEXT NOT NULL, clock_skew_seconds REAL NOT NULL,
          event_hash TEXT NOT NULL, body_json TEXT NOT NULL,
          PRIMARY KEY(tenant_id, event_id),
          FOREIGN KEY(tenant_id,device_id)
            REFERENCES fleet_devices(tenant_id,device_id));
        CREATE INDEX IF NOT EXISTS idx_fleet_events_lookup
          ON fleet_events(tenant_id,device_id,observed_at);
        CREATE TABLE IF NOT EXISTS fleet_ingest_stats(
          tenant_id TEXT PRIMARY KEY,
          stored INTEGER NOT NULL DEFAULT 0,
          duplicates INTEGER NOT NULL DEFAULT 0,
          synchronized INTEGER NOT NULL DEFAULT 0,
          skewed INTEGER NOT NULL DEFAULT 0,
          untrusted INTEGER NOT NULL DEFAULT 0,
          server_assigned INTEGER NOT NULL DEFAULT 0,
          legacy INTEGER NOT NULL DEFAULT 0,
          last_received_at REAL NOT NULL DEFAULT 0);
        """)
        self._migrate_schema()

    def _migrate_schema(self) -> None:
        """Upgrade older local-preview databases without discarding evidence."""
        columns = {
            row[1] for row in self._db.execute("PRAGMA table_info(fleet_events)")
        }
        additions = {
            "received_at": "REAL NOT NULL DEFAULT 0",
            "clock_quality": "TEXT NOT NULL DEFAULT 'legacy'",
            "clock_skew_seconds": "REAL NOT NULL DEFAULT 0",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self._db.execute(
                    f"ALTER TABLE fleet_events ADD COLUMN {name} {declaration}"
                )
        self._db.execute(
            "UPDATE fleet_events SET received_at=observed_at "
            "WHERE received_at=0"
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_fleet_events_received "
            "ON fleet_events(tenant_id,received_at)"
        )
        stats_columns = {
            row[1] for row in self._db.execute(
                "PRAGMA table_info(fleet_ingest_stats)"
            )
        }
        if "legacy" not in stats_columns:
            self._db.execute(
                "ALTER TABLE fleet_ingest_stats "
                "ADD COLUMN legacy INTEGER NOT NULL DEFAULT 0"
            )
        self._db.execute(
            "INSERT OR IGNORE INTO fleet_ingest_stats("
            "tenant_id,stored,duplicates,synchronized,skewed,untrusted,"
            "server_assigned,legacy,last_received_at) "
            "SELECT tenant_id,COUNT(*),0,"
            "SUM(clock_quality='synchronized'),SUM(clock_quality='skewed'),"
            "SUM(clock_quality='untrusted'),SUM(clock_quality='server-assigned'),"
            "SUM(clock_quality='legacy'),MAX(received_at) "
            "FROM fleet_events GROUP BY tenant_id"
        )

    def _key(self, tenant_id: str) -> bytes:
        tenant_id = _validate_id(tenant_id, "tenant ID")
        try:
            return self._keys[tenant_id]
        except KeyError as exc:
            raise PermissionError("tenant is not authorized") from exc

    def register_device(self, device: FleetDevice) -> None:
        self._key(device.tenant_id)
        stamp = float(device.last_seen or self._clock())
        if not math.isfinite(stamp) or stamp <= 0:
            raise ValueError("invalid device last-seen timestamp")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT public_key FROM fleet_devices "
                    "WHERE tenant_id=? AND device_id=?",
                    (device.tenant_id, device.device_id),
                ).fetchone()
                if existing and existing[0] != device.public_key:
                    raise ValueError("device identity key conflict")
                self._db.execute(
                    "INSERT INTO fleet_devices VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(tenant_id,device_id) DO UPDATE SET "
                    "hostname_token=excluded.hostname_token,"
                    "platform=excluded.platform,version=excluded.version,"
                    "group_id=excluded.group_id,state=excluded.state,"
                    "last_seen=excluded.last_seen",
                    (
                        device.tenant_id, device.device_id, device.public_key,
                        device.hostname_token, device.platform, device.version,
                        device.group_id, device.state, stamp,
                    ),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def ingest(
        self, tenant_id: str, device_id: str, event_id: str,
        body: Mapping[str, Any], *, observed_at: float | None = None,
    ) -> IngestReceipt:
        key = self._key(tenant_id)
        device_id = _validate_id(device_id, "device ID")
        event_id = _validate_id(event_id, "event ID")
        if not isinstance(body, Mapping):
            raise TypeError("event body must be a mapping")
        normalized_body = _normalize_event_body(body)
        encoded = _canonical(normalized_body)
        if len(encoded) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds ingestion byte budget")
        event_hash = hashlib.sha256(encoded).hexdigest()
        received_at = float(self._clock())
        if not math.isfinite(received_at) or received_at <= 0:
            raise RuntimeError("fleet ingestion clock is unavailable")
        if observed_at is None:
            stamp = received_at
            clock_quality = "server-assigned"
            clock_skew = 0.0
        else:
            stamp = float(observed_at)
            if not math.isfinite(stamp) or stamp <= 0:
                raise ValueError("observed timestamp must be finite and positive")
            clock_skew = stamp - received_at
            absolute_skew = abs(clock_skew)
            if absolute_skew <= CLOCK_SYNC_WINDOW_SECONDS:
                clock_quality = "synchronized"
            elif absolute_skew <= CLOCK_SKEW_WINDOW_SECONDS:
                clock_quality = "skewed"
            else:
                clock_quality = "untrusted"
        duplicate = False
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                device = self._db.execute(
                    "SELECT state FROM fleet_devices WHERE tenant_id=? AND device_id=?",
                    (tenant_id, device_id),
                ).fetchone()
                if device is None:
                    raise PermissionError("device is not enrolled in tenant")
                if device[0] != "active":
                    raise PermissionError(f"device state is {device[0]}")
                existing = self._db.execute(
                    "SELECT event_hash,device_id,observed_at,received_at,"
                    "clock_quality,clock_skew_seconds FROM fleet_events "
                    "WHERE tenant_id=? AND event_id=?",
                    (tenant_id, event_id),
                ).fetchone()
                if existing:
                    if existing[0] != event_hash:
                        raise ValueError("event ID conflicts with different evidence")
                    if existing[1] != device_id:
                        raise ValueError("event ID is already bound to another device")
                    duplicate = True
                    stamp = float(existing[2])
                    received_for_receipt = float(existing[3])
                    clock_quality = str(existing[4])
                    clock_skew = float(existing[5])
                else:
                    self._db.execute(
                        "INSERT INTO fleet_events("
                        "tenant_id,event_id,device_id,observed_at,received_at,"
                        "clock_quality,clock_skew_seconds,event_hash,body_json"
                        ") VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            tenant_id, event_id, device_id, stamp, received_at,
                            clock_quality, clock_skew, event_hash,
                            encoded.decode("utf-8"),
                        ),
                    )
                    received_for_receipt = received_at
                self._db.execute(
                    "UPDATE fleet_devices SET last_seen=? "
                    "WHERE tenant_id=? AND device_id=?",
                    (received_at, tenant_id, device_id),
                )
                self._record_ingest_stat(
                    tenant_id,
                    duplicate=duplicate,
                    clock_quality=clock_quality,
                    received_at=received_at,
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        core = {
            "tenant_id": tenant_id, "device_id": device_id,
            "event_id": event_id, "accepted": True, "duplicate": duplicate,
            "recorded_at": stamp, "received_at": received_for_receipt,
            "clock_quality": clock_quality,
            "clock_skew_seconds": clock_skew,
            "event_hash": event_hash,
        }
        signature = hmac.new(key, _canonical(core), hashlib.sha256).hexdigest()
        return IngestReceipt(**core, receipt_hmac=signature)

    def _record_ingest_stat(
        self,
        tenant_id: str,
        *,
        duplicate: bool,
        clock_quality: str,
        received_at: float,
    ) -> None:
        update_sql = _CLOCK_QUALITY_UPDATES.get(clock_quality)
        if update_sql is None and not duplicate:
            raise ValueError("invalid clock quality classification")
        self._db.execute(
            "INSERT OR IGNORE INTO fleet_ingest_stats(tenant_id) VALUES(?)",
            (tenant_id,),
        )
        if duplicate:
            self._db.execute(
                "UPDATE fleet_ingest_stats SET duplicates=duplicates+1,"
                "last_received_at=? WHERE tenant_id=?",
                (received_at, tenant_id),
            )
        else:
            self._db.execute(
                update_sql,
                (received_at, tenant_id),
            )

    def verify_receipt(self, receipt: IngestReceipt) -> bool:
        try:
            key = self._key(receipt.tenant_id)
        except (ValueError, PermissionError):
            return False
        core = asdict(receipt)
        signature = core.pop("receipt_hmac")
        return hmac.compare_digest(
            signature, hmac.new(key, _canonical(core), hashlib.sha256).hexdigest()
        )

    def devices(self, tenant_id: str) -> tuple[FleetDevice, ...]:
        self._key(tenant_id)
        with self._lock:
            rows = self._db.execute(
                "SELECT tenant_id,device_id,public_key,hostname_token,platform,"
                "version,group_id,state,last_seen FROM fleet_devices "
                "WHERE tenant_id=? ORDER BY device_id", (tenant_id,),
            ).fetchall()
        return tuple(FleetDevice(*row) for row in rows)

    def events(
        self, tenant_id: str, *, device_id: str | None = None,
        limit: int = 500,
    ) -> tuple[Mapping[str, Any], ...]:
        self._key(tenant_id)
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        params: list[Any] = [tenant_id]
        sql = (
            "SELECT event_id,device_id,observed_at,received_at,clock_quality,"
            "clock_skew_seconds,event_hash,body_json "
            "FROM fleet_events WHERE tenant_id=?"
        )
        if device_id is not None:
            sql += " AND device_id=?"
            params.append(_validate_id(device_id, "device ID"))
        sql += " ORDER BY observed_at DESC,event_id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return tuple({
            "event_id": row[0], "device_id": row[1], "observed_at": row[2],
            "received_at": row[3], "clock_quality": row[4],
            "clock_skew_seconds": row[5], "event_hash": row[6],
            "body": json.loads(row[7]),
        } for row in rows)

    def ingestion_health(self, tenant_id: str) -> Mapping[str, Any]:
        """Return bounded, low-cardinality ingestion and clock-quality health."""
        self._key(tenant_id)
        with self._lock:
            counters = self._db.execute(
                "SELECT stored,duplicates,synchronized,skewed,untrusted,"
                "server_assigned,legacy,last_received_at FROM fleet_ingest_stats "
                "WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone() or (0, 0, 0, 0, 0, 0, 0, 0.0)
            states = self._db.execute(
                "SELECT state,COUNT(*) FROM fleet_devices WHERE tenant_id=? "
                "GROUP BY state ORDER BY state",
                (tenant_id,),
            ).fetchall()
        stored = int(counters[0])
        uncertain = int(counters[3]) + int(counters[4]) + int(counters[6])
        return {
            "schema": "angerona.fleet-ingestion-health/v1",
            "tenant_id": tenant_id,
            "stored_events": stored,
            "duplicate_retries": int(counters[1]),
            "clock_quality": {
                "synchronized": int(counters[2]),
                "skewed": int(counters[3]),
                "untrusted": int(counters[4]),
                "server_assigned": int(counters[5]),
                "legacy": int(counters[6]),
            },
            "clock_quality_state": (
                "degraded" if uncertain else "healthy" if stored else "unknown"
            ),
            "last_received_at": float(counters[7]),
            "device_states": {str(state): int(count) for state, count in states},
        }

    def close(self) -> None:
        with self._lock:
            self._db.close()
