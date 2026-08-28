"""Bounded, authenticated, lease-based local delivery outbox.

The outbox provides at-least-once handoff semantics for optional exporters.
An EventBus cursor may advance only after its payloads are committed here.
Network success then acknowledges the durable row; failures retain it with
bounded exponential backoff.  Capacity exhaustion is explicit and fail-closed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping


MAX_ITEM_BYTES = 256 * 1024
_STATE_SIGNATURE_SCHEMA = "angerona.durable-outbox-state/v1"
_ROW_COLUMNS = (
    "item_id,payload_json,payload_sha256,signature,state,attempts,"
    "next_attempt,lease_owner,lease_until,last_error,created_at,size_bytes,"
    "state_signature"
)
_VALID_STATES = frozenset({"pending", "leased", "dead_letter", "delivered"})


class OutboxError(RuntimeError):
    """Base class for a safely refused outbox operation."""


class OutboxFull(OutboxError):
    """Pending/dead-letter retention reached its configured bound."""


class OutboxIntegrityError(OutboxError):
    """A retained row failed its authenticated content check."""


@dataclass(frozen=True)
class OutboxItem:
    item_id: str
    payload: Mapping[str, Any]
    created_at: float
    attempts: int


@dataclass(frozen=True)
class OutboxStats:
    pending: int
    leased: int
    dead_letter: int
    delivered_tombstones: int
    retained_bytes: int


@dataclass(frozen=True)
class _VerifiedRow:
    item_id: str
    payload_json: str
    payload_sha256: str
    payload_signature: str
    state: str
    attempts: int
    next_attempt: float
    lease_owner: str
    lease_until: float
    last_error: str
    created_at: float
    size_bytes: int
    state_signature: str
    payload: Mapping[str, Any]

    def as_item(self) -> OutboxItem:
        return OutboxItem(
            self.item_id, self.payload, self.created_at, self.attempts
        )


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def load_or_create_outbox_key(path: Path) -> bytes:
    """Load a protected 32-byte key, creating it without replacing a winner."""
    target = Path(path)
    from angerona.core.hardening import (
        ensure_sensitive_parent,
        key_acl_required,
        prepare_sensitive_key,
        secure_sensitive_file,
    )

    required = key_acl_required()
    target.parent.mkdir(parents=True, exist_ok=True)
    ensure_sensitive_parent(target, required=required)
    if prepare_sensitive_key(target, required=required):
        try:
            key = bytes.fromhex(target.read_text(encoding="ascii").strip())
        except Exception as exc:
            raise OutboxIntegrityError("outbox signing key is unreadable") from exc
        if len(key) != 32:
            raise OutboxIntegrityError("outbox signing key has invalid length")
        return key

    key = secrets.token_bytes(32)
    try:
        descriptor = os.open(
            str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        return load_or_create_outbox_key(target)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(key.hex())
            handle.flush()
            os.fsync(handle.fileno())
        secure_sensitive_file(target, required=required)
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return key


class DurableOutbox:
    """SQLite-backed bounded queue with atomic single-owner leases."""

    def __init__(
        self,
        path: Path,
        signing_key: bytes,
        *,
        max_items: int = 20_000,
        max_bytes: int = 128 * 1024 * 1024,
        max_attempts: int = 12,
        delivered_tombstones: int = 10_000,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("outbox signing key must contain at least 32 bytes")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = bytes(signing_key)
        self.max_items = max(100, min(int(max_items), 500_000))
        self.max_bytes = max(MAX_ITEM_BYTES, min(int(max_bytes), 2 * 1024**3))
        self.max_attempts = max(1, min(int(max_attempts), 100))
        self.delivered_tombstones = max(100, min(int(delivered_tombstones), 100_000))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS durable_outbox(
              item_id TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              signature TEXT NOT NULL,
              state TEXT NOT NULL,
              attempts INTEGER NOT NULL,
              next_attempt REAL NOT NULL,
              lease_owner TEXT NOT NULL,
              lease_until REAL NOT NULL,
              last_error TEXT NOT NULL,
              created_at REAL NOT NULL,
              size_bytes INTEGER NOT NULL,
              state_signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_durable_outbox_ready
              ON durable_outbox(state,next_attempt,created_at);
            """
        )
        self._db.commit()
        columns = {
            str(row[1])
            for row in self._db.execute("PRAGMA table_info(durable_outbox)").fetchall()
        }
        if "state_signature" not in columns:
            self._migrate_legacy_state_signatures()
        self._trusted_total_changes = -1
        self._trusted_data_version = -1
        self._verify_all_rows_locked()
        self._mark_database_trusted_locked()

    def _signature(self, item_id: str, payload_json: str, created_at: float) -> str:
        return hmac.new(
            self._key,
            _canonical({
                "item_id": item_id,
                "payload_json": payload_json,
                "created_at": created_at,
            }),
            hashlib.sha256,
        ).hexdigest()

    def _state_signature(self, row: _VerifiedRow) -> str:
        """Authenticate all mutable delivery authority plus its payload identity."""
        return hmac.new(
            self._key,
            _canonical({
                "schema": _STATE_SIGNATURE_SCHEMA,
                "item_id": row.item_id,
                "payload_sha256": row.payload_sha256,
                "payload_signature": row.payload_signature,
                "created_at": row.created_at,
                "state": row.state,
                "attempts": row.attempts,
                "next_attempt": row.next_attempt,
                "lease_owner": row.lease_owner,
                "lease_until": row.lease_until,
                "last_error": row.last_error,
                "size_bytes": row.size_bytes,
            }),
            hashlib.sha256,
        ).hexdigest()

    def _verify_row(
        self,
        raw: tuple[Any, ...],
        *,
        verify_state_signature: bool = True,
    ) -> _VerifiedRow:
        if len(raw) != 13:
            raise OutboxIntegrityError("outbox row has an invalid schema")
        (
            item_id, payload_json, digest, payload_signature, state, attempts,
            next_attempt, lease_owner, lease_until, last_error, created_at,
            size_bytes, state_signature,
        ) = raw
        text_fields = {
            "item identity": item_id,
            "payload": payload_json,
            "payload digest": digest,
            "payload signature": payload_signature,
            "state": state,
            "lease owner": lease_owner,
            "last error": last_error,
            "state signature": state_signature,
        }
        if any(not isinstance(value, str) for value in text_fields.values()):
            raise OutboxIntegrityError("outbox row contains an invalid text field")
        if not item_id or len(item_id) > 160:
            raise OutboxIntegrityError("outbox row has an invalid item identity")
        if state not in _VALID_STATES:
            raise OutboxIntegrityError(f"outbox item {item_id} has an invalid state")
        if type(attempts) is not int or not 0 <= attempts <= 100:
            raise OutboxIntegrityError(f"outbox item {item_id} has invalid attempts")
        if type(size_bytes) is not int or size_bytes < 0:
            raise OutboxIntegrityError(f"outbox item {item_id} has invalid retained size")
        numbers = (next_attempt, lease_until, created_at)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in numbers
        ):
            raise OutboxIntegrityError(f"outbox item {item_id} has an invalid timer")
        if len(lease_owner) > 160 or len(last_error) > 1000:
            raise OutboxIntegrityError(f"outbox item {item_id} has oversized state")
        if state == "leased":
            if not lease_owner:
                raise OutboxIntegrityError(f"outbox item {item_id} has no lease owner")
        elif lease_owner or float(lease_until) != 0.0:
            raise OutboxIntegrityError(f"outbox item {item_id} has a stray lease")
        if state == "delivered" and last_error:
            raise OutboxIntegrityError(
                f"outbox item {item_id} has invalid delivered state"
            )

        encoded = payload_json.encode("utf-8")
        if len(encoded) > MAX_ITEM_BYTES or size_bytes != len(encoded):
            raise OutboxIntegrityError(f"outbox item {item_id} failed its size check")
        if not hmac.compare_digest(hashlib.sha256(encoded).hexdigest(), digest):
            raise OutboxIntegrityError(f"outbox item {item_id} failed its content digest")
        expected = self._signature(item_id, payload_json, float(created_at))
        if not hmac.compare_digest(expected, payload_signature):
            raise OutboxIntegrityError(f"outbox item {item_id} failed authentication")
        try:
            payload = json.loads(payload_json)
        except Exception as exc:
            raise OutboxIntegrityError(f"outbox item {item_id} is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise OutboxIntegrityError(f"outbox item {item_id} payload is not an object")
        verified = _VerifiedRow(
            item_id=item_id,
            payload_json=payload_json,
            payload_sha256=digest,
            payload_signature=payload_signature,
            state=state,
            attempts=attempts,
            next_attempt=float(next_attempt),
            lease_owner=lease_owner,
            lease_until=float(lease_until),
            last_error=last_error,
            created_at=float(created_at),
            size_bytes=size_bytes,
            state_signature=state_signature,
            payload=payload,
        )
        if verify_state_signature and not hmac.compare_digest(
            self._state_signature(verified), state_signature
        ):
            raise OutboxIntegrityError(
                f"outbox item {item_id} failed mutable-state authentication"
            )
        return verified

    def _migrate_legacy_state_signatures(self) -> None:
        """One-time migration from payload-only authentication.

        Column absence is the migration marker. Legacy payload authority and
        state invariants are verified before the current state is signed; an
        existing but blank/tampered signature is never silently repaired.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "ALTER TABLE durable_outbox ADD COLUMN "
                    "state_signature TEXT NOT NULL DEFAULT ''"
                )
                rows = self._db.execute(
                    f"SELECT {_ROW_COLUMNS} FROM durable_outbox"
                ).fetchall()
                updates: list[tuple[str, str]] = []
                for raw in rows:
                    verified = self._verify_row(
                        raw, verify_state_signature=False
                    )
                    updates.append((self._state_signature(verified), verified.item_id))
                self._db.executemany(
                    "UPDATE durable_outbox SET state_signature=? WHERE item_id=?",
                    updates,
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def _data_version_locked(self) -> int:
        row = self._db.execute("PRAGMA data_version").fetchone()
        if row is None or type(row[0]) is not int:
            raise OutboxIntegrityError("outbox data-version state is unavailable")
        return int(row[0])

    def _mark_database_trusted_locked(self) -> None:
        self._trusted_total_changes = int(self._db.total_changes)
        self._trusted_data_version = self._data_version_locked()

    def _verify_all_rows_locked(self) -> None:
        rows = self._db.execute(
            f"SELECT {_ROW_COLUMNS} FROM durable_outbox"
        ).fetchall()
        for row in rows:
            self._verify_row(row)

    def _verify_if_database_changed_locked(self) -> None:
        """Audit all rows only after unobserved same/external DB mutation.

        Normal transitions update the trusted sentinels after commit. Direct
        use of this connection changes ``total_changes``; another connection
        changes SQLite's connection-local ``data_version``. Either condition
        forces a full signed-state audit before a readiness predicate, count,
        or transition can trust mutable columns.
        """
        total_changes = int(self._db.total_changes)
        data_version = self._data_version_locked()
        if (
            total_changes == self._trusted_total_changes
            and data_version == self._trusted_data_version
        ):
            return
        self._verify_all_rows_locked()
        self._trusted_total_changes = total_changes
        self._trusted_data_version = data_version

    def _update_state_locked(
        self,
        row: _VerifiedRow,
        **changes: Any,
    ) -> _VerifiedRow:
        unsigned = replace(row, **changes, state_signature="")
        updated_row = replace(
            unsigned, state_signature=self._state_signature(unsigned)
        )
        updated = self._db.execute(
            "UPDATE durable_outbox SET state=?,attempts=?,next_attempt=?,"
            "lease_owner=?,lease_until=?,last_error=?,state_signature=? "
            "WHERE item_id=? AND state_signature=?",
            (
                updated_row.state,
                updated_row.attempts,
                updated_row.next_attempt,
                updated_row.lease_owner,
                updated_row.lease_until,
                updated_row.last_error,
                updated_row.state_signature,
                updated_row.item_id,
                row.state_signature,
            ),
        ).rowcount
        if updated != 1:
            raise OutboxIntegrityError(
                f"outbox item {row.item_id} changed during its state transition"
            )
        return updated_row

    def _prune_tombstones_locked(self) -> None:
        rows = self._db.execute(
            f"SELECT {_ROW_COLUMNS} FROM durable_outbox WHERE state='delivered' "
            "ORDER BY created_at DESC LIMIT -1 OFFSET ?",
            (self.delivered_tombstones,),
        ).fetchall()
        for raw in rows:
            row = self._verify_row(raw)
            deleted = self._db.execute(
                "DELETE FROM durable_outbox WHERE item_id=? AND state_signature=?",
                (row.item_id, row.state_signature),
            ).rowcount
            if deleted != 1:
                raise OutboxIntegrityError(
                    f"outbox item {row.item_id} changed during tombstone pruning"
                )

    def enqueue(
        self,
        item_id: str,
        payload: Mapping[str, Any],
        *,
        now: float | None = None,
    ) -> bool:
        """Durably add an idempotent item; return ``False`` for an exact replay."""
        identifier = str(item_id).strip()
        if not identifier or len(identifier) > 160:
            raise ValueError("outbox item ID is empty or oversized")
        if not isinstance(payload, Mapping):
            raise TypeError("outbox payload must be a mapping")
        encoded = _canonical(dict(payload))
        if len(encoded) > MAX_ITEM_BYTES:
            raise ValueError("outbox item exceeds 256 KiB")
        serialized = encoded.decode("utf-8")
        stamp = time.time() if now is None else float(now)
        digest = hashlib.sha256(encoded).hexdigest()
        signature = self._signature(identifier, serialized, stamp)
        unsigned = _VerifiedRow(
            item_id=identifier,
            payload_json=serialized,
            payload_sha256=digest,
            payload_signature=signature,
            state="pending",
            attempts=0,
            next_attempt=0.0,
            lease_owner="",
            lease_until=0.0,
            last_error="",
            created_at=stamp,
            size_bytes=len(encoded),
            state_signature="",
            payload=json.loads(serialized),
        )
        state_signature = self._state_signature(unsigned)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_if_database_changed_locked()
                existing = self._db.execute(
                    f"SELECT {_ROW_COLUMNS} FROM durable_outbox WHERE item_id=?",
                    (identifier,),
                ).fetchone()
                if existing is not None:
                    verified = self._verify_row(existing)
                    if not hmac.compare_digest(verified.payload_json, serialized):
                        raise ValueError("outbox item ID conflicts with another payload")
                    self._db.commit()
                    self._mark_database_trusted_locked()
                    return False
                self._prune_tombstones_locked()
                count, retained_bytes = self._db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM durable_outbox "
                    "WHERE state!='delivered'"
                ).fetchone()
                if int(count) >= self.max_items or int(retained_bytes) + len(encoded) > self.max_bytes:
                    raise OutboxFull("outbox pending/dead-letter capacity is exhausted")
                self._db.execute(
                    "INSERT INTO durable_outbox("
                    "item_id,payload_json,payload_sha256,signature,state,attempts,"
                    "next_attempt,lease_owner,lease_until,last_error,created_at,"
                    "size_bytes,state_signature) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        identifier, serialized, digest, signature, "pending", 0,
                        0.0, "", 0.0, "", stamp, len(encoded), state_signature,
                    ),
                )
                self._db.commit()
                self._mark_database_trusted_locked()
                return True
            except Exception:
                self._db.rollback()
                raise

    def claim(
        self,
        owner: str,
        *,
        now: float | None = None,
        limit: int = 100,
        lease_seconds: float = 30.0,
    ) -> tuple[OutboxItem, ...]:
        """Atomically lease ready items to one worker."""
        worker = str(owner).strip()[:160]
        if not worker:
            raise ValueError("lease owner is required")
        stamp = time.time() if now is None else float(now)
        bounded_limit = max(1, min(int(limit), 1000))
        lease = max(1.0, min(float(lease_seconds), 3600.0))
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_if_database_changed_locked()
                expired = self._db.execute(
                    f"SELECT {_ROW_COLUMNS} FROM durable_outbox "
                    "WHERE state='leased' AND lease_until<=?",
                    (stamp,),
                ).fetchall()
                for raw in expired:
                    row = self._verify_row(raw)
                    self._update_state_locked(
                        row, state="pending", lease_owner="", lease_until=0.0
                    )
                ready = self._db.execute(
                    f"SELECT {_ROW_COLUMNS} FROM durable_outbox "
                    "WHERE state='pending' AND next_attempt<=? "
                    "ORDER BY created_at,item_id LIMIT ?",
                    (stamp, bounded_limit),
                ).fetchall()
                for raw in ready:
                    row = self._verify_row(raw)
                    self._update_state_locked(
                        row,
                        state="leased",
                        lease_owner=worker,
                        lease_until=stamp + lease,
                    )
                rows = self._db.execute(
                    f"SELECT {_ROW_COLUMNS} "
                    "FROM durable_outbox WHERE state='leased' AND lease_owner=? "
                    "ORDER BY created_at,item_id LIMIT ?",
                    (worker, bounded_limit),
                ).fetchall()
                verified = tuple(self._verify_row(row) for row in rows)
                self._db.commit()
                self._mark_database_trusted_locked()
            except Exception:
                self._db.rollback()
                raise
        return tuple(row.as_item() for row in verified)

    def is_delivered(self, item_id: str) -> bool:
        """Return whether an authenticated delivered tombstone exists."""
        with self._lock:
            self._verify_if_database_changed_locked()
            row = self._db.execute(
                f"SELECT {_ROW_COLUMNS} FROM durable_outbox WHERE item_id=?",
                (str(item_id),),
            ).fetchone()
        if row is None:
            return False
        return self._verify_row(row).state == "delivered"

    def _required_row_locked(self, item_id: str) -> _VerifiedRow:
        raw = self._db.execute(
            f"SELECT {_ROW_COLUMNS} FROM durable_outbox WHERE item_id=?",
            (str(item_id),),
        ).fetchone()
        if raw is None:
            raise KeyError(item_id)
        return self._verify_row(raw)

    def complete_pending(self, item_id: str) -> None:
        """Commit an inbox item after its local durable side effect succeeds."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_if_database_changed_locked()
                row = self._required_row_locked(str(item_id))
                if row.state not in {"pending", "leased"}:
                    raise KeyError(item_id)
                self._update_state_locked(
                    row,
                    state="delivered",
                    lease_owner="",
                    lease_until=0.0,
                    last_error="",
                )
                self._prune_tombstones_locked()
                self._db.commit()
                self._mark_database_trusted_locked()
            except Exception:
                self._db.rollback()
                raise

    def acknowledge(self, item_id: str, owner: str) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_if_database_changed_locked()
                row = self._required_row_locked(str(item_id))
                if row.state != "leased" or row.lease_owner != str(owner):
                    raise KeyError(item_id)
                self._update_state_locked(
                    row,
                    state="delivered",
                    lease_owner="",
                    lease_until=0.0,
                    last_error="",
                )
                self._prune_tombstones_locked()
                self._db.commit()
                self._mark_database_trusted_locked()
            except Exception:
                self._db.rollback()
                raise

    def retry(
        self,
        item_id: str,
        owner: str,
        error: str,
        *,
        now: float | None = None,
    ) -> None:
        stamp = time.time() if now is None else float(now)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_if_database_changed_locked()
                row = self._required_row_locked(str(item_id))
                if row.state != "leased" or row.lease_owner != str(owner):
                    raise KeyError(item_id)
                attempts = row.attempts + 1
                dead = attempts >= self.max_attempts
                delay = (
                    0.0
                    if dead
                    else min(3600.0, float(2 ** min(attempts, 12)))
                )
                self._update_state_locked(
                    row,
                    state="dead_letter" if dead else "pending",
                    attempts=attempts,
                    next_attempt=stamp + delay,
                    lease_owner="",
                    lease_until=0.0,
                    last_error=str(error)[:1000],
                )
                self._db.commit()
                self._mark_database_trusted_locked()
            except Exception:
                self._db.rollback()
                raise

    def stats(self) -> OutboxStats:
        with self._lock:
            for _attempt in range(3):
                self._verify_if_database_changed_locked()
                snapshot = self._db.execute(
                    "SELECT "
                    "COALESCE(SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END),0),"
                    "COALESCE(SUM(CASE WHEN state='leased' THEN 1 ELSE 0 END),0),"
                    "COALESCE(SUM(CASE WHEN state='dead_letter' THEN 1 ELSE 0 END),0),"
                    "COALESCE(SUM(CASE WHEN state='delivered' THEN 1 ELSE 0 END),0),"
                    "COALESCE(SUM(CASE WHEN state!='delivered' THEN size_bytes ELSE 0 END),0) "
                    "FROM durable_outbox"
                ).fetchone()
                if (
                    int(self._db.total_changes) == self._trusted_total_changes
                    and self._data_version_locked() == self._trusted_data_version
                ):
                    break
            else:
                raise OutboxIntegrityError(
                    "outbox changed repeatedly during its statistics snapshot"
                )
            pending, leased, dead_letter, delivered, retained = snapshot
        return OutboxStats(
            pending=int(pending),
            leased=int(leased),
            dead_letter=int(dead_letter),
            delivered_tombstones=int(delivered),
            retained_bytes=int(retained),
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()
