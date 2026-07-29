"""Offline-first, tenant-isolated fleet inventory and ingestion foundation.

This is a local control-plane store, not a network listener. A future mutual
TLS transport may call this boundary only after authenticating the endpoint and
binding its device identity to exactly one tenant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
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


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


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
    event_hash: str
    receipt_hmac: str


class FleetControlPlane:
    """Durable local store with mandatory tenant predicates on every operation."""

    def __init__(self, path: Path, tenant_keys: Mapping[str, bytes]) -> None:
        if not tenant_keys:
            raise ValueError("at least one tenant key is required")
        self._keys = {}
        for tenant, key in tenant_keys.items():
            tenant = _validate_id(tenant, "tenant ID")
            if len(key) < 32:
                raise ValueError("tenant keys must contain at least 32 bytes")
            self._keys[tenant] = bytes(key)
        self.path = Path(path)
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
          observed_at REAL NOT NULL, event_hash TEXT NOT NULL, body_json TEXT NOT NULL,
          PRIMARY KEY(tenant_id, event_id),
          FOREIGN KEY(tenant_id,device_id)
            REFERENCES fleet_devices(tenant_id,device_id));
        CREATE INDEX IF NOT EXISTS idx_fleet_events_lookup
          ON fleet_events(tenant_id,device_id,observed_at);
        """)

    def _key(self, tenant_id: str) -> bytes:
        tenant_id = _validate_id(tenant_id, "tenant ID")
        try:
            return self._keys[tenant_id]
        except KeyError as exc:
            raise PermissionError("tenant is not authorized") from exc

    def register_device(self, device: FleetDevice) -> None:
        self._key(device.tenant_id)
        values = asdict(device)
        stamp = float(device.last_seen or time.time())
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
        encoded = _canonical(dict(body))
        if len(encoded) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds ingestion byte budget")
        event_hash = hashlib.sha256(encoded).hexdigest()
        stamp = time.time() if observed_at is None else float(observed_at)
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
                    "SELECT event_hash FROM fleet_events "
                    "WHERE tenant_id=? AND event_id=?",
                    (tenant_id, event_id),
                ).fetchone()
                if existing:
                    if existing[0] != event_hash:
                        raise ValueError("event ID conflicts with different evidence")
                    duplicate = True
                else:
                    self._db.execute(
                        "INSERT INTO fleet_events VALUES(?,?,?,?,?,?)",
                        (tenant_id, event_id, device_id, stamp, event_hash,
                         encoded.decode("utf-8")),
                    )
                    self._db.execute(
                        "UPDATE fleet_devices SET last_seen=? "
                        "WHERE tenant_id=? AND device_id=?",
                        (stamp, tenant_id, device_id),
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        core = {
            "tenant_id": tenant_id, "device_id": device_id,
            "event_id": event_id, "accepted": True, "duplicate": duplicate,
            "recorded_at": stamp, "event_hash": event_hash,
        }
        signature = hmac.new(key, _canonical(core), hashlib.sha256).hexdigest()
        return IngestReceipt(**core, receipt_hmac=signature)

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
            "SELECT event_id,device_id,observed_at,event_hash,body_json "
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
            "event_hash": row[3], "body": json.loads(row[4]),
        } for row in rows)

    def close(self) -> None:
        with self._lock:
            self._db.close()
