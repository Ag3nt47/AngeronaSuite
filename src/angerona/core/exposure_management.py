"""Durable local vulnerability and exposure-management lifecycle."""
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

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_CVE = re.compile(r"^CVE-[12][0-9]{3}-[0-9]{4,}$")
_STATES = {"open", "assigned", "mitigating", "accepted", "resolved", "closed"}
_SEVERITY = {"low", "medium", "high", "critical"}


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()


@dataclass(frozen=True)
class ManagedExposure:
    exposure_id: str
    asset_id: str
    vulnerability_id: str
    severity: str
    state: str
    owner: str
    due_at: float
    version: int
    first_seen: float
    updated_at: float
    exception_reason: str = ""
    exception_expires: float = 0
    closure_evidence: str = ""


class ExposureConflict(RuntimeError):
    pass


class ExposureManager:
    def __init__(self, path: Path, audit_key: bytes) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        self._key = bytes(audit_key)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS exposures(
          exposure_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL,
          vulnerability_id TEXT NOT NULL, severity TEXT NOT NULL,
          state TEXT NOT NULL, owner TEXT NOT NULL, due_at REAL NOT NULL,
          version INTEGER NOT NULL, first_seen REAL NOT NULL, updated_at REAL NOT NULL,
          exception_reason TEXT NOT NULL, exception_expires REAL NOT NULL,
          closure_evidence TEXT NOT NULL,
          UNIQUE(asset_id,vulnerability_id));
        CREATE TABLE IF NOT EXISTS exposure_audit(
          seq INTEGER PRIMARY KEY AUTOINCREMENT, exposure_id TEXT NOT NULL,
          action TEXT NOT NULL, actor TEXT NOT NULL, ts REAL NOT NULL,
          body_json TEXT NOT NULL, receipt_hmac TEXT NOT NULL);
        """)
        self._db.commit()

    @staticmethod
    def _validate(exposure: ManagedExposure) -> None:
        if not _ID.fullmatch(exposure.exposure_id) or not _ID.fullmatch(exposure.asset_id):
            raise ValueError("invalid exposure or asset ID")
        if not _CVE.fullmatch(exposure.vulnerability_id):
            raise ValueError("invalid CVE identifier")
        if exposure.severity not in _SEVERITY or exposure.state not in _STATES:
            raise ValueError("invalid severity or lifecycle state")
        if exposure.owner and not _ID.fullmatch(exposure.owner):
            raise ValueError("invalid exposure owner")

    def upsert(
        self, exposure_id: str, asset_id: str, vulnerability_id: str,
        severity: str, *, now: float | None = None, due_at: float = 0,
    ) -> ManagedExposure:
        stamp = time.time() if now is None else float(now)
        item = ManagedExposure(
            exposure_id, asset_id, vulnerability_id, severity, "open", "",
            float(due_at), 1, stamp, stamp,
        )
        self._validate(item)
        with self._lock:
            existing = self._db.execute(
                "SELECT exposure_id FROM exposures WHERE asset_id=? AND vulnerability_id=?",
                (asset_id, vulnerability_id),
            ).fetchone()
            if existing and existing[0] != exposure_id:
                raise ExposureConflict("asset vulnerability is already tracked")
            self._db.execute(
                "INSERT INTO exposures VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(exposure_id) DO UPDATE SET severity=excluded.severity,"
                "due_at=excluded.due_at,updated_at=excluded.updated_at,"
                "version=exposures.version+1",
                tuple(asdict(item).values()),
            )
            self._audit(exposure_id, "upsert", "system", stamp, {
                "severity": severity, "due_at": due_at,
            })
            self._db.commit()
        return self.get(exposure_id)

    def transition(
        self, exposure_id: str, expected_version: int, state: str, actor: str,
        *, owner: str | None = None, exception_reason: str = "",
        exception_expires: float = 0, closure_evidence: str = "",
        now: float | None = None,
    ) -> ManagedExposure:
        if state not in _STATES or not _ID.fullmatch(actor):
            raise ValueError("invalid state or actor")
        stamp = time.time() if now is None else float(now)
        current = self.get(exposure_id)
        new_owner = current.owner if owner is None else owner
        if new_owner and not _ID.fullmatch(new_owner):
            raise ValueError("invalid owner")
        if state == "accepted":
            if len(exception_reason.strip()) < 12:
                raise ValueError("risk acceptance requires a substantive reason")
            if not stamp < exception_expires <= stamp + 365 * 86400:
                raise ValueError("risk acceptance requires a bounded future expiry")
        else:
            exception_reason, exception_expires = "", 0
        if state in {"resolved", "closed"} and not re.fullmatch(
            r"sha256:[0-9a-f]{64}", closure_evidence
        ):
            raise ValueError("closure requires SHA-256 evidence")
        with self._lock:
            cursor = self._db.execute(
                "UPDATE exposures SET state=?,owner=?,version=version+1,"
                "updated_at=?,exception_reason=?,exception_expires=?,"
                "closure_evidence=? WHERE exposure_id=? AND version=?",
                (state, new_owner, stamp, exception_reason[:2000],
                 float(exception_expires), closure_evidence, exposure_id,
                 int(expected_version)),
            )
            if cursor.rowcount != 1:
                raise ExposureConflict("exposure version changed")
            self._audit(exposure_id, f"transition:{state}", actor, stamp, {
                "owner": new_owner, "exception_expires": exception_expires,
                "closure_evidence": closure_evidence,
            })
            self._db.commit()
        return self.get(exposure_id)

    def _audit(self, exposure_id, action, actor, stamp, body) -> None:
        core = {
            "exposure_id": exposure_id, "action": action,
            "actor": actor, "ts": stamp, "body": body,
        }
        signature = hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest()
        self._db.execute(
            "INSERT INTO exposure_audit(exposure_id,action,actor,ts,body_json,"
            "receipt_hmac) VALUES(?,?,?,?,?,?)",
            (exposure_id, action, actor, stamp,
             _canonical(body).decode(), signature),
        )

    def get(self, exposure_id: str) -> ManagedExposure:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM exposures WHERE exposure_id=?", (exposure_id,)
            ).fetchone()
        if row is None:
            raise KeyError(exposure_id)
        return ManagedExposure(*row)

    def due(self, *, now: float | None = None) -> tuple[ManagedExposure, ...]:
        stamp = time.time() if now is None else float(now)
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM exposures WHERE state NOT IN ('resolved','closed') "
                "AND ((due_at>0 AND due_at<=?) OR "
                "(state='accepted' AND exception_expires<=?)) "
                "ORDER BY severity DESC,due_at", (stamp, stamp),
            ).fetchall()
        return tuple(ManagedExposure(*row) for row in rows)

    def close(self) -> None:
        with self._lock:
            self._db.close()
