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
from collections import Counter, OrderedDict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
MAX_EVENT_BYTES = 256 * 1024
MAX_INGEST_BATCH = 256
MAX_INGEST_BATCH_BYTES = 4 * 1024 * 1024
MAX_QUERY_LIMIT = 5000
MAX_EVENT_DEPTH = 32
MAX_EVENT_NODES = 20_000
MAX_EVENT_CONTAINER_ITEMS = 4096
CLOCK_SYNC_WINDOW_SECONDS = 5 * 60
CLOCK_SKEW_WINDOW_SECONDS = 24 * 60 * 60
DEFAULT_TENANT_EVENTS_PER_SECOND = 2000.0
DEFAULT_TENANT_BURST = 4000
DEFAULT_DEVICE_EVENTS_PER_SECOND = 500.0
DEFAULT_DEVICE_BURST = 1000
MAX_RATE_BUCKETS = 50_000
_CLOCK_QUALITIES = frozenset({
    "synchronized", "skewed", "untrusted", "server-assigned",
})


class FleetRateLimitError(RuntimeError):
    def __init__(self, retry_after_ms: int) -> None:
        self.retry_after_ms = max(1, int(retry_after_ms))
        super().__init__("fleet ingestion rate limit exceeded")


class FleetIngestionRateLimiter:
    """Thread-safe bounded token buckets for valid tenant/device identities."""

    def __init__(
        self,
        *,
        tenant_rate: float = DEFAULT_TENANT_EVENTS_PER_SECOND,
        tenant_burst: int = DEFAULT_TENANT_BURST,
        device_rate: float = DEFAULT_DEVICE_EVENTS_PER_SECOND,
        device_burst: int = DEFAULT_DEVICE_BURST,
        max_buckets: int = MAX_RATE_BUCKETS,
        clock=time.monotonic,
    ) -> None:
        for value, label in (
            (tenant_rate, "tenant rate"), (device_rate, "device rate"),
            (tenant_burst, "tenant burst"), (device_burst, "device burst"),
        ):
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise ValueError(f"{label} must be finite and positive")
        self.tenant_rate = float(tenant_rate)
        self.tenant_burst = max(1, int(tenant_burst))
        self.device_rate = float(device_rate)
        self.device_burst = max(1, int(device_burst))
        self.max_buckets = max(100, min(int(max_buckets), 500_000))
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[
            tuple[str, str], tuple[float, float]
        ] = OrderedDict()
        self._stats: dict[str, list[int]] = {}

    def _refill(
        self,
        key: tuple[str, str],
        *,
        rate: float,
        burst: int,
        now: float,
    ) -> float:
        prior = self._buckets.pop(key, None)
        if prior is None:
            if len(self._buckets) >= self.max_buckets:
                raise FleetRateLimitError(1000)
            tokens = float(burst)
        else:
            tokens = min(float(burst), prior[0] + max(0.0, now - prior[1]) * rate)
        self._buckets[key] = (tokens, now)
        return tokens

    def consume(self, tenant_id: str, device_counts: Mapping[str, int]) -> None:
        total = sum(int(count) for count in device_counts.values())
        if total < 1 or any(int(count) < 1 for count in device_counts.values()):
            raise ValueError("rate-limit event counts must be positive")
        now = float(self._clock())
        if not math.isfinite(now):
            raise RuntimeError("fleet admission clock is unavailable")
        requirements = [(tenant_id, "", total, self.tenant_rate, self.tenant_burst)]
        requirements.extend(
            (tenant_id, device_id, int(count), self.device_rate, self.device_burst)
            for device_id, count in sorted(device_counts.items())
        )
        with self._lock:
            available: list[tuple[tuple[str, str], float, int, float]] = []
            retry_seconds = 0.0
            for tenant, device, required, rate, burst in requirements:
                key = (tenant, device)
                tokens = self._refill(key, rate=rate, burst=burst, now=now)
                available.append((key, tokens, required, rate))
                if tokens < required:
                    retry_seconds = max(
                        retry_seconds, (required - tokens) / rate
                    )
            stats = self._stats.setdefault(tenant_id, [0, 0])
            if retry_seconds > 0:
                stats[1] += total
                raise FleetRateLimitError(math.ceil(retry_seconds * 1000))
            for key, tokens, required, _rate in available:
                self._buckets[key] = (tokens - required, now)
            stats[0] += total

    def snapshot(self, tenant_id: str) -> Mapping[str, int | float]:
        with self._lock:
            accepted, rejected = self._stats.get(tenant_id, [0, 0])
            tracked = sum(1 for tenant, _device in self._buckets if tenant == tenant_id)
        return {
            "admitted_events": accepted,
            "rejected_events": rejected,
            "tracked_buckets": tracked,
            "tenant_events_per_second": self.tenant_rate,
            "tenant_burst": self.tenant_burst,
            "device_events_per_second": self.device_rate,
            "device_burst": self.device_burst,
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


@dataclass(frozen=True)
class _PreparedEvent:
    device_id: str
    event_id: str
    encoded_body: bytes
    event_hash: str
    observed_at: float
    clock_quality: str
    clock_skew_seconds: float


class FleetControlPlane:
    """Durable local store with mandatory tenant predicates on every operation."""

    def __init__(
        self,
        path: Path,
        tenant_keys: Mapping[str, bytes],
        *,
        clock=time.time,
        rate_limiter: FleetIngestionRateLimiter | None = None,
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
        self._rate_limiter = rate_limiter or FleetIngestionRateLimiter()
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
          batches INTEGER NOT NULL DEFAULT 0,
          batch_events INTEGER NOT NULL DEFAULT 0,
          largest_batch INTEGER NOT NULL DEFAULT 0,
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
        stats_additions = {
            "legacy": "INTEGER NOT NULL DEFAULT 0",
            "batches": "INTEGER NOT NULL DEFAULT 0",
            "batch_events": "INTEGER NOT NULL DEFAULT 0",
            "largest_batch": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, declaration in stats_additions.items():
            if name not in stats_columns:
                self._db.execute(
                    f"ALTER TABLE fleet_ingest_stats ADD COLUMN {name} {declaration}"
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
        return self.ingest_batch(tenant_id, ({
            "device_id": device_id,
            "event_id": event_id,
            "body": body,
            "observed_at": observed_at,
        },))[0]

    @staticmethod
    def _prepare_event(
        event: Mapping[str, Any], received_at: float,
    ) -> _PreparedEvent:
        if not isinstance(event, Mapping):
            raise TypeError("batch events must be mappings")
        allowed = {"device_id", "event_id", "body", "observed_at"}
        unknown = set(event) - allowed
        missing = {"device_id", "event_id", "body"} - set(event)
        if unknown:
            raise ValueError("event envelope contains unknown fields")
        if missing:
            raise ValueError("event envelope is missing required fields")
        device_id = _validate_id(event["device_id"], "device ID")
        event_id = _validate_id(event["event_id"], "event ID")
        body = event["body"]
        if not isinstance(body, Mapping):
            raise TypeError("event body must be a mapping")
        encoded = _canonical(_normalize_event_body(body))
        if len(encoded) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds ingestion byte budget")
        observed_at = event.get("observed_at")
        if observed_at is None:
            stamp = received_at
            quality = "server-assigned"
            skew = 0.0
        else:
            stamp = float(observed_at)
            if not math.isfinite(stamp) or stamp <= 0:
                raise ValueError("observed timestamp must be finite and positive")
            skew = stamp - received_at
            absolute_skew = abs(skew)
            if absolute_skew <= CLOCK_SYNC_WINDOW_SECONDS:
                quality = "synchronized"
            elif absolute_skew <= CLOCK_SKEW_WINDOW_SECONDS:
                quality = "skewed"
            else:
                quality = "untrusted"
        return _PreparedEvent(
            device_id=device_id,
            event_id=event_id,
            encoded_body=encoded,
            event_hash=hashlib.sha256(encoded).hexdigest(),
            observed_at=stamp,
            clock_quality=quality,
            clock_skew_seconds=skew,
        )

    def ingest_batch(
        self,
        tenant_id: str,
        events: Sequence[Mapping[str, Any]],
    ) -> tuple[IngestReceipt, ...]:
        """Atomically ingest one bounded batch and return signed receipts."""
        key = self._key(tenant_id)
        if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
            raise TypeError("events must be a sequence")
        if not 1 <= len(events) <= MAX_INGEST_BATCH:
            raise ValueError(
                f"batch must contain 1 to {MAX_INGEST_BATCH} events"
            )
        received_at = float(self._clock())
        if not math.isfinite(received_at) or received_at <= 0:
            raise RuntimeError("fleet ingestion clock is unavailable")
        prepared = tuple(
            self._prepare_event(event, received_at) for event in events
        )
        if sum(len(event.encoded_body) for event in prepared) > MAX_INGEST_BATCH_BYTES:
            raise ValueError("batch exceeds aggregate ingestion byte budget")

        receipt_cores: list[dict[str, Any]] = []
        stored_by_quality = {quality: 0 for quality in _CLOCK_QUALITIES}
        duplicates = 0
        touched_devices: set[str] = set()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                requested_devices = tuple(sorted({
                    item.device_id for item in prepared
                }))
                placeholders = ",".join("?" for _ in requested_devices)
                device_states = {
                    row[0]: row[1]
                    for row in self._db.execute(
                        "SELECT device_id,state FROM fleet_devices "
                        f"WHERE tenant_id=? AND device_id IN ({placeholders})",
                        (tenant_id, *requested_devices),
                    )
                }
                for device_id in requested_devices:
                    state = device_states.get(device_id)
                    if state is None:
                        raise PermissionError("device is not enrolled in tenant")
                    if state != "active":
                        raise PermissionError(f"device state is {state}")
                self._rate_limiter.consume(
                    tenant_id, Counter(item.device_id for item in prepared)
                )
                for item in prepared:
                    existing = self._db.execute(
                        "SELECT event_hash,device_id,observed_at,received_at,"
                        "clock_quality,clock_skew_seconds FROM fleet_events "
                        "WHERE tenant_id=? AND event_id=?",
                        (tenant_id, item.event_id),
                    ).fetchone()
                    duplicate = existing is not None
                    if existing:
                        if existing[0] != item.event_hash:
                            raise ValueError(
                                "event ID conflicts with different evidence"
                            )
                        if existing[1] != item.device_id:
                            raise ValueError(
                                "event ID is already bound to another device"
                            )
                        recorded_at = float(existing[2])
                        received_for_receipt = float(existing[3])
                        clock_quality = str(existing[4])
                        clock_skew = float(existing[5])
                        duplicates += 1
                    else:
                        self._db.execute(
                            "INSERT INTO fleet_events("
                            "tenant_id,event_id,device_id,observed_at,received_at,"
                            "clock_quality,clock_skew_seconds,event_hash,body_json"
                            ") VALUES(?,?,?,?,?,?,?,?,?)",
                            (
                                tenant_id, item.event_id, item.device_id,
                                item.observed_at, received_at, item.clock_quality,
                                item.clock_skew_seconds, item.event_hash,
                                item.encoded_body.decode("utf-8"),
                            ),
                        )
                        recorded_at = item.observed_at
                        received_for_receipt = received_at
                        clock_quality = item.clock_quality
                        clock_skew = item.clock_skew_seconds
                        stored_by_quality[clock_quality] += 1
                    touched_devices.add(item.device_id)
                    receipt_cores.append({
                        "tenant_id": tenant_id,
                        "device_id": item.device_id,
                        "event_id": item.event_id,
                        "accepted": True,
                        "duplicate": duplicate,
                        "recorded_at": recorded_at,
                        "received_at": received_for_receipt,
                        "clock_quality": clock_quality,
                        "clock_skew_seconds": clock_skew,
                        "event_hash": item.event_hash,
                    })
                self._db.executemany(
                    "UPDATE fleet_devices SET last_seen=? "
                    "WHERE tenant_id=? AND device_id=?",
                    (
                        (received_at, tenant_id, device_id)
                        for device_id in touched_devices
                    ),
                )
                self._record_ingest_stats(
                    tenant_id, stored_by_quality, duplicates, len(prepared),
                    received_at,
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

        return tuple(
            IngestReceipt(
                **core,
                receipt_hmac=hmac.new(
                    key, _canonical(core), hashlib.sha256
                ).hexdigest(),
            )
            for core in receipt_cores
        )

    def _record_ingest_stats(
        self,
        tenant_id: str,
        stored_by_quality: Mapping[str, int],
        duplicates: int,
        batch_size: int,
        received_at: float,
    ) -> None:
        if set(stored_by_quality) != _CLOCK_QUALITIES:
            raise ValueError("invalid clock quality counters")
        self._db.execute(
            "INSERT OR IGNORE INTO fleet_ingest_stats(tenant_id) VALUES(?)",
            (tenant_id,),
        )
        self._db.execute(
            "UPDATE fleet_ingest_stats SET stored=stored+?,"
            "duplicates=duplicates+?,synchronized=synchronized+?,"
            "skewed=skewed+?,untrusted=untrusted+?,"
            "server_assigned=server_assigned+?,batches=batches+1,"
            "batch_events=batch_events+?,largest_batch=MAX(largest_batch,?),"
            "last_received_at=? "
            "WHERE tenant_id=?",
            (
                sum(stored_by_quality.values()), duplicates,
                stored_by_quality["synchronized"],
                stored_by_quality["skewed"],
                stored_by_quality["untrusted"],
                stored_by_quality["server-assigned"],
                batch_size, batch_size, received_at, tenant_id,
            ),
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
                "server_assigned,legacy,batches,batch_events,largest_batch,"
                "last_received_at FROM fleet_ingest_stats "
                "WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone() or (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0)
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
            "batches": {
                "accepted": int(counters[7]),
                "event_attempts": int(counters[8]),
                "largest": int(counters[9]),
            },
            "last_received_at": float(counters[10]),
            "device_states": {str(state): int(count) for state, count in states},
            "admission": dict(self._rate_limiter.snapshot(tenant_id)),
        }

    def close(self) -> None:
        with self._lock:
            self._db.close()
