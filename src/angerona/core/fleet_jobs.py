"""Durable, typed fleet-job contracts for future authenticated transport.

This module does not dispatch over a network or execute actions. It provides a
bounded local state machine, targeting safety, replay resistance, and signed
endpoint result receipts.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from angerona.core.endpoint_identity import ConnectionEnvelope, EndpointIdentity

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_OPERATION = re.compile(r"^[a-z][a-z0-9_.-]{2,79}$")
_STATES = {
    "created", "staged", "approved", "dispatched", "running",
    "succeeded", "failed", "cancelled", "expired",
}
_TRANSITIONS = {
    "created": {"staged", "cancelled", "expired"},
    "staged": {"approved", "cancelled", "expired"},
    "approved": {"dispatched", "cancelled", "expired"},
    "dispatched": {"running", "failed", "cancelled", "expired"},
    "running": {"succeeded", "failed", "cancelled", "expired"},
}
_TERMINAL = {"succeeded", "failed", "cancelled", "expired"}
_MAX_SPEC_BYTES = 64 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


@dataclass(frozen=True)
class JobTarget:
    device_ids: tuple[str, ...] = ()
    group_ids: tuple[str, ...] = ()
    required_tags: tuple[str, ...] = ()
    max_hosts: int = 1

    def __post_init__(self) -> None:
        if not 1 <= int(self.max_hosts) <= 10_000:
            raise ValueError("max_hosts must be between 1 and 10000")
        if not self.device_ids and not self.group_ids:
            raise ValueError("at least one device or group target is required")
        for collection in (self.device_ids, self.group_ids, self.required_tags):
            if len(collection) > 256 or any(
                not _ID.fullmatch(str(value)) for value in collection
            ):
                raise ValueError("invalid or oversized job target")


@dataclass(frozen=True)
class FleetJob:
    job_id: str
    idempotency_key: str
    operation_id: str
    arguments: Mapping[str, Any]
    target: JobTarget
    created_at: float
    expires_at: float
    dry_run: bool = True
    approval_digest: str = ""

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.job_id) or not _ID.fullmatch(self.idempotency_key):
            raise ValueError("invalid job or idempotency identifier")
        if not _OPERATION.fullmatch(self.operation_id):
            raise ValueError("invalid operation identifier")
        if not isinstance(self.arguments, Mapping) or len(self.arguments) > 64:
            raise ValueError("arguments must be a bounded mapping")
        if not self.created_at < self.expires_at <= self.created_at + 7 * 86400:
            raise ValueError("job expiry must be within seven days")
        if not self.dry_run and not re.fullmatch(r"[a-f0-9]{64}", self.approval_digest):
            raise ValueError("non-dry-run jobs require a bound approval digest")
        if len(_canonical(self.to_dict())) > _MAX_SPEC_BYTES:
            raise ValueError("job specification exceeds 64 KiB")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["arguments"] = dict(self.arguments)
        return value

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class JobRecord:
    job: FleetJob
    state: str
    version: int
    updated_at: float
    result_receipt: Mapping[str, Any] = field(default_factory=dict)


class DurableJobStore:
    def __init__(self, path: Path, *, max_jobs: int = 50_000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_jobs = max(100, min(int(max_jobs), 500_000))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS fleet_jobs (
                job_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                spec_json TEXT NOT NULL,
                state TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at REAL NOT NULL,
                result_json TEXT NOT NULL DEFAULT '{}'
            )
        """)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_fleet_jobs_state "
            "ON fleet_jobs(state, updated_at)"
        )
        self._db.commit()

    def create(self, job: FleetJob) -> JobRecord:
        now = time.time()
        encoded = _canonical(job.to_dict()).decode("utf-8")
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO fleet_jobs "
                    "(job_id,idempotency_key,spec_json,state,version,updated_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (job.job_id, job.idempotency_key, encoded, "created", 1, now),
                )
                self._prune_locked()
                self._db.commit()
            except sqlite3.IntegrityError:
                existing = self.by_idempotency(job.idempotency_key)
                if existing is None or existing.job.digest != job.digest:
                    raise ValueError("idempotency key is already bound to another job")
                return existing
        return JobRecord(job, "created", 1, now)

    @staticmethod
    def _decode(row: tuple) -> JobRecord:
        raw = json.loads(row[0])
        raw["target"] = JobTarget(**raw["target"])
        job = FleetJob(**raw)
        return JobRecord(
            job, str(row[1]), int(row[2]), float(row[3]), json.loads(row[4]),
        )

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT spec_json,state,version,updated_at,result_json "
                "FROM fleet_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
        return self._decode(row) if row else None

    def by_idempotency(self, key: str) -> JobRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT spec_json,state,version,updated_at,result_json "
                "FROM fleet_jobs WHERE idempotency_key=?", (key,),
            ).fetchone()
        return self._decode(row) if row else None

    def transition(
        self, job_id: str, new_state: str, *, expected_version: int,
        now: float | None = None, result_receipt: Mapping[str, Any] | None = None,
    ) -> JobRecord:
        if new_state not in _STATES:
            raise ValueError("unknown job state")
        stamp = time.time() if now is None else float(now)
        with self._lock:
            current = self.get(job_id)
            if current is None:
                raise KeyError(job_id)
            if current.version != expected_version:
                raise RuntimeError("job version conflict")
            if stamp >= current.job.expires_at and new_state not in _TERMINAL:
                new_state = "expired"
            allowed = _TRANSITIONS.get(current.state, set())
            if new_state not in allowed:
                raise ValueError(f"invalid transition {current.state}->{new_state}")
            receipt = dict(result_receipt or current.result_receipt)
            encoded_receipt = _canonical(receipt)
            if len(encoded_receipt) > _MAX_SPEC_BYTES:
                raise ValueError("result receipt exceeds 64 KiB")
            cursor = self._db.execute(
                "UPDATE fleet_jobs SET state=?,version=version+1,updated_at=?,"
                "result_json=? WHERE job_id=? AND version=?",
                (new_state, stamp, encoded_receipt.decode("utf-8"),
                 job_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("job version conflict")
            self._db.commit()
        updated = self.get(job_id)
        assert updated is not None
        return updated

    def _prune_locked(self) -> None:
        self._db.execute(
            "DELETE FROM fleet_jobs WHERE job_id IN ("
            "SELECT job_id FROM fleet_jobs WHERE state IN "
            "('succeeded','failed','cancelled','expired') "
            "ORDER BY updated_at DESC LIMIT -1 OFFSET ?)", (self.max_jobs,)
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()


def signed_result_receipt(
    identity: EndpointIdentity, job: FleetJob, *, sequence: int,
    state: str, result: Mapping[str, Any], sent_at: float | None = None,
) -> ConnectionEnvelope:
    if state not in _TERMINAL:
        raise ValueError("result receipt requires a terminal state")
    payload = {
        "job_id": job.job_id, "job_digest": job.digest,
        "state": state, "result": dict(result),
    }
    return identity.sign_connection(
        sequence, "fleet_job_result", payload, sent_at=sent_at,
    )
