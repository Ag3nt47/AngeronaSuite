"""Durable, signed, privacy-reviewed offline interoperability queue."""
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

from angerona.core.data_governance import EgressPolicy

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SCHEMAS = {"ocsf-1.3", "stix-2.1", "otlp-1.0", "angerona-1"}
MAX_PAYLOAD = 256 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()


@dataclass(frozen=True)
class InteropEnvelope:
    envelope_id: str
    schema: str
    purpose: str
    destination: str
    created_at: float
    payload: Mapping[str, Any]
    payload_sha256: str
    signature: str


class OfflineInteropQueue:
    def __init__(
        self, path: Path, signing_key: bytes, privacy_salt: bytes,
        *, max_items: int = 50_000,
    ) -> None:
        if len(signing_key) < 32 or len(privacy_salt) < 16:
            raise ValueError("interop keys are too short")
        self._key = bytes(signing_key)
        self._salt = bytes(privacy_salt)
        self.max_items = max(100, min(int(max_items), 500_000))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS interop_queue(
          envelope_id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL,
          state TEXT NOT NULL, attempts INTEGER NOT NULL, next_attempt REAL NOT NULL,
          last_error TEXT NOT NULL, created_at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_interop_ready
          ON interop_queue(state,next_attempt,created_at);
        """)
        self._db.commit()

    def enqueue(
        self, envelope_id: str, schema: str, payload: Mapping[str, Any], *,
        purpose: str, destination: str, policy: EgressPolicy,
        external: bool, now: float | None = None,
    ) -> InteropEnvelope:
        if not _ID.fullmatch(envelope_id) or schema not in _SCHEMAS:
            raise ValueError("invalid envelope identity or schema")
        preview = policy.preview(
            payload, purpose=purpose, destination=destination,
            salt=self._salt, external=external,
        )
        if not preview.permitted:
            raise PermissionError("; ".join(preview.reasons) or "egress denied")
        minimized = dict(preview.minimized_payload)
        encoded = _canonical(minimized)
        if len(encoded) > MAX_PAYLOAD:
            raise ValueError("interop payload exceeds byte budget")
        stamp = time.time() if now is None else float(now)
        core = {
            "envelope_id": envelope_id, "schema": schema,
            "purpose": purpose[:256], "destination": destination[:256],
            "created_at": stamp, "payload": minimized,
            "payload_sha256": hashlib.sha256(encoded).hexdigest(),
        }
        envelope = InteropEnvelope(
            **core,
            signature=hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest(),
        )
        serialized = _canonical(asdict(envelope)).decode()
        with self._lock:
            existing = self._db.execute(
                "SELECT envelope_json FROM interop_queue WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone()
            if existing:
                if not hmac.compare_digest(existing[0], serialized):
                    raise ValueError("envelope ID conflicts with another payload")
                return envelope
            self._db.execute(
                "INSERT INTO interop_queue VALUES(?,?, 'pending',0,0,'',?)",
                (envelope_id, serialized, stamp),
            )
            self._db.execute(
                "DELETE FROM interop_queue WHERE envelope_id IN ("
                "SELECT envelope_id FROM interop_queue WHERE state='delivered' "
                "ORDER BY created_at DESC LIMIT -1 OFFSET ?)", (self.max_items,),
            )
            self._db.commit()
        return envelope

    def ready(
        self, *, now: float | None = None, limit: int = 100
    ) -> tuple[InteropEnvelope, ...]:
        stamp = time.time() if now is None else float(now)
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._db.execute(
                "SELECT envelope_json FROM interop_queue "
                "WHERE state='pending' AND next_attempt<=? "
                "ORDER BY created_at LIMIT ?", (stamp, limit),
            ).fetchall()
        return tuple(InteropEnvelope(**json.loads(row[0])) for row in rows)

    def disposition(
        self, envelope_id: str, *, delivered: bool, error: str = "",
        now: float | None = None,
    ) -> None:
        stamp = time.time() if now is None else float(now)
        with self._lock:
            row = self._db.execute(
                "SELECT attempts FROM interop_queue WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone()
            if row is None:
                raise KeyError(envelope_id)
            attempts = int(row[0]) + 1
            state = "delivered" if delivered else (
                "dead_letter" if attempts >= 8 else "pending"
            )
            delay = 0 if delivered else min(3600, 2 ** min(attempts, 12))
            self._db.execute(
                "UPDATE interop_queue SET state=?,attempts=?,next_attempt=?,"
                "last_error=? WHERE envelope_id=?",
                (state, attempts, stamp + delay, error[:1000], envelope_id),
            )
            self._db.commit()

    def verify(self, envelope: InteropEnvelope) -> bool:
        value = asdict(envelope)
        signature = value.pop("signature")
        digest = hashlib.sha256(_canonical(value["payload"])).hexdigest()
        return (
            hmac.compare_digest(digest, value["payload_sha256"])
            and hmac.compare_digest(
                signature,
                hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
            )
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()
