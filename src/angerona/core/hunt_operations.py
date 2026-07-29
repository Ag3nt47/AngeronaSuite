"""Durable bounded fleet-hunt progress and evidence-to-case promotion."""
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
from typing import Any

from angerona.core.case_management import (
    MAX_EVIDENCE, CaseStore, EvidenceReference,
)
from angerona.core.hunt_workspace import HuntWorkspace

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STATES = {"queued", "running", "offline", "succeeded", "failed", "cancelled"}
_TERMINAL = {"succeeded", "failed", "cancelled"}
_TRANSITIONS = {
    None: {"queued", "running", "offline", "failed", "cancelled"},
    "queued": {"running", "offline", "failed", "cancelled"},
    "running": {"offline", "succeeded", "failed", "cancelled"},
    "offline": {"queued", "running", "failed", "cancelled"},
}
MAX_PROGRESS_EVENTS = 50_000
MAX_PROGRESS_STORAGE_BYTES = 512 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


@dataclass(frozen=True)
class HuntProgressEvent:
    event_id: str
    hunt_id: str
    device_token: str
    state: str
    timestamp: float
    bytes_collected: int = 0
    error_code: str = ""
    result_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "result_ids", tuple(self.result_ids))
        object.__setattr__(self, "timestamp", float(self.timestamp))
        object.__setattr__(self, "bytes_collected", int(self.bytes_collected))
        if not _ID.fullmatch(self.event_id) or not _ID.fullmatch(self.hunt_id):
            raise ValueError("invalid hunt progress identity")
        if not _SHA256.fullmatch(self.device_token):
            raise ValueError("hunt progress requires a device privacy token")
        if self.state not in _STATES:
            raise ValueError("invalid hunt progress state")
        if not math.isfinite(float(self.timestamp)) or self.timestamp < 0:
            raise ValueError("invalid hunt progress timestamp")
        if not 0 <= self.bytes_collected <= 5 * 1024 * 1024 * 1024:
            raise ValueError("invalid hunt progress byte count")
        if self.error_code and not _ID.fullmatch(self.error_code):
            raise ValueError("hunt failures require a bounded error code")
        if self.state == "failed" and not self.error_code:
            raise ValueError("failed hunt progress requires an error code")
        if self.state != "failed" and self.error_code:
            raise ValueError("only failed progress may contain an error code")
        if len(self.result_ids) > 128 or any(
            not _ID.fullmatch(item) for item in self.result_ids
        ):
            raise ValueError("invalid hunt progress result references")
        if len(set(self.result_ids)) != len(self.result_ids):
            raise ValueError("duplicate hunt progress result reference")


@dataclass(frozen=True)
class HuntProgressSummary:
    hunt_id: str
    host_count: int
    state_counts: dict[str, int]
    bytes_collected: int
    failure_codes: dict[str, int]
    last_update: float
    event_count: int
    summary_hmac: str


@dataclass(frozen=True)
class HuntCasePromotion:
    hunt_id: str
    case_id: str
    workspace_revision: int
    evidence_count: int
    workspace_hmac: str
    promoted_at: float
    promotion_hmac: str


class HuntOperationsStore:
    def __init__(
        self,
        path: Path,
        audit_key: bytes,
        *,
        max_hosts: int = 10_000,
        max_total_bytes: int = 10 * 1024 * 1024 * 1024,
        clock=time.time,
    ) -> None:
        if len(audit_key) < 32:
            raise ValueError("hunt operations key must contain at least 32 bytes")
        if not 1 <= int(max_hosts) <= 10_000:
            raise ValueError("invalid hunt operations host budget")
        if not 1024 <= int(max_total_bytes) <= 10 * 1024 * 1024 * 1024:
            raise ValueError("invalid hunt operations byte budget")
        self._key = bytes(audit_key)
        self.max_hosts = int(max_hosts)
        self.max_total_bytes = int(max_total_bytes)
        self._clock = clock
        self._lock = threading.RLock()
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self._path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS hunt_progress(
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE,
          hunt_id TEXT NOT NULL,
          device_token TEXT NOT NULL,
          state TEXT NOT NULL,
          timestamp REAL NOT NULL,
          bytes_collected INTEGER NOT NULL,
          error_code TEXT NOT NULL,
          result_ids_json TEXT NOT NULL,
          event_hmac TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_hunt_progress
          ON hunt_progress(hunt_id,device_token,seq);
        """)
        self._db.commit()

    def record(self, event: HuntProgressEvent) -> bool:
        body = asdict(event)
        signature = hmac.new(
            self._key, _canonical(body), hashlib.sha256
        ).hexdigest()
        with self._lock:
            storage_bytes = sum(
                candidate.stat().st_size
                for candidate in (
                    self._path,
                    Path(str(self._path) + "-wal"),
                    Path(str(self._path) + "-shm"),
                )
                if candidate.exists()
            )
            if storage_bytes > MAX_PROGRESS_STORAGE_BYTES:
                raise ValueError("hunt progress storage budget exceeded")
            existing = self._db.execute(
                "SELECT hunt_id,device_token,state,timestamp,bytes_collected,"
                "error_code,result_ids_json,event_hmac FROM hunt_progress "
                "WHERE event_id=?", (event.event_id,),
            ).fetchone()
            if existing is not None:
                stored = self._row_event(event.event_id, existing)
                if stored != event or not hmac.compare_digest(existing[7], signature):
                    raise ValueError("hunt progress ID conflicts with another event")
                return False
            count = int(self._db.execute(
                "SELECT COUNT(*) FROM hunt_progress WHERE hunt_id=?",
                (event.hunt_id,),
            ).fetchone()[0])
            if count >= MAX_PROGRESS_EVENTS:
                raise ValueError("hunt progress event limit reached")
            latest = self._db.execute(
                "SELECT event_id,hunt_id,device_token,state,timestamp,"
                "bytes_collected,error_code,result_ids_json,event_hmac "
                "FROM hunt_progress "
                "WHERE hunt_id=? AND device_token=? ORDER BY seq DESC LIMIT 1",
                (event.hunt_id, event.device_token),
            ).fetchone()
            latest_event = None
            if latest is not None:
                latest_event = self._row_event(latest[0], latest[1:])
                if not hmac.compare_digest(
                    latest[8],
                    hmac.new(
                        self._key, _canonical(asdict(latest_event)), hashlib.sha256
                    ).hexdigest(),
                ):
                    raise ValueError("hunt progress authentication failed")
            current = None if latest_event is None else latest_event.state
            if current in _TERMINAL or event.state not in _TRANSITIONS.get(current, set()):
                raise ValueError(f"invalid hunt progress transition {current}->{event.state}")
            if latest_event is not None and (
                event.timestamp < latest_event.timestamp
                or event.bytes_collected < latest_event.bytes_collected
            ):
                raise ValueError("hunt progress counters cannot regress")
            if latest is None:
                hosts = int(self._db.execute(
                    "SELECT COUNT(DISTINCT device_token) FROM hunt_progress "
                    "WHERE hunt_id=?", (event.hunt_id,),
                ).fetchone()[0])
                if hosts >= self.max_hosts:
                    raise ValueError("hunt progress host budget exceeded")
            prior_bytes = (
                0 if latest_event is None else latest_event.bytes_collected
            )
            current_total = self._latest_total_bytes(event.hunt_id)
            if current_total - prior_bytes + event.bytes_collected > self.max_total_bytes:
                raise ValueError("hunt progress byte budget exceeded")
            self._db.execute(
                "INSERT INTO hunt_progress(event_id,hunt_id,device_token,state,"
                "timestamp,bytes_collected,error_code,result_ids_json,event_hmac)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    event.event_id, event.hunt_id, event.device_token, event.state,
                    event.timestamp, event.bytes_collected, event.error_code,
                    json.dumps(event.result_ids), signature,
                ),
            )
            self._db.commit()
        return True

    def summary(self, hunt_id: str) -> HuntProgressSummary:
        if not _ID.fullmatch(hunt_id):
            raise ValueError("invalid hunt identity")
        with self._lock:
            rows = self._db.execute(
                "SELECT event_id,hunt_id,device_token,state,timestamp,"
                "bytes_collected,error_code,result_ids_json,event_hmac "
                "FROM hunt_progress WHERE hunt_id=? ORDER BY seq",
                (hunt_id,),
            ).fetchall()
        latest: dict[str, HuntProgressEvent] = {}
        for row in rows:
            event = self._row_event(row[0], row[1:])
            signature = row[8]
            if not hmac.compare_digest(
                signature,
                hmac.new(
                    self._key, _canonical(asdict(event)), hashlib.sha256
                ).hexdigest(),
            ):
                raise ValueError("hunt progress authentication failed")
            latest[event.device_token] = event
        states = {state: 0 for state in sorted(_STATES)}
        failures: dict[str, int] = {}
        for event in latest.values():
            states[event.state] += 1
            if event.error_code:
                failures[event.error_code] = failures.get(event.error_code, 0) + 1
        core = {
            "hunt_id": hunt_id,
            "host_count": len(latest),
            "state_counts": states,
            "bytes_collected": sum(item.bytes_collected for item in latest.values()),
            "failure_codes": dict(sorted(failures.items())),
            "last_update": max((item.timestamp for item in latest.values()), default=0.0),
            "event_count": len(rows),
        }
        return HuntProgressSummary(
            **core, summary_hmac=hmac.new(
                self._key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_summary(self, summary: HuntProgressSummary) -> bool:
        value = asdict(summary)
        signature = value.pop("summary_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    def promote_to_case(
        self,
        hunt_id: str,
        workspace: HuntWorkspace,
        cases: CaseStore,
        *,
        actor: str,
        assignee: str = "",
    ) -> HuntCasePromotion:
        if not _ID.fullmatch(hunt_id) or not _ID.fullmatch(actor):
            raise ValueError("invalid hunt promotion identity")
        snapshot = workspace.snapshot(hunt_id)
        if not workspace.verify_snapshot(snapshot):
            raise ValueError("hunt workspace snapshot authentication failed")
        if not snapshot.results:
            raise ValueError("hunt has no evidence results to promote")
        if len(snapshot.results) > MAX_EVIDENCE:
            raise ValueError("hunt result count exceeds case evidence limit")
        case_id = "case-hunt-" + hashlib.sha256(
            hunt_id.encode("utf-8")
        ).hexdigest()[:32]
        try:
            case = cases.create_case(
                f"Fleet hunt {hunt_id}", assignee=assignee,
                tags=("fleet-hunt", hunt_id), now=float(self._clock()),
                case_id=case_id,
            )
        except sqlite3.IntegrityError:
            case = cases.get_case(case_id)
            if "fleet-hunt" not in case.tags or hunt_id not in case.tags:
                raise ValueError("deterministic hunt case ID conflicts")
        added = 0
        for result in snapshot.results:
            owner = cases.evidence_owner(result.evidence_id)
            if owner is not None:
                if owner != case.case_id:
                    raise ValueError("hunt evidence already belongs to another case")
                if not cases.verify_custody(result.evidence_id):
                    raise ValueError("existing hunt evidence custody is invalid")
                continue
            cases.add_evidence(
                case.case_id,
                EvidenceReference(
                    result.evidence_id,
                    result.artifact_id.replace(".", "_") + ".reference",
                    result.sha256,
                    result.size_bytes,
                    f"fleet-hunt:{hunt_id}",
                    result.provenance,
                    result.observed_at,
                    result.privacy_class,
                ),
                actor,
                now=float(self._clock()),
            )
            added += 1
        case = cases.get_case(case.case_id)
        if case.status == "open":
            case = cases.update_case(
                case.case_id, case.version, status="investigating",
                now=float(self._clock()),
            )
        core = {
            "hunt_id": hunt_id, "case_id": case.case_id,
            "workspace_revision": snapshot.revision,
            "evidence_count": len(snapshot.results),
            "workspace_hmac": snapshot.integrity_hmac,
            "promoted_at": float(self._clock()),
        }
        return HuntCasePromotion(
            **core, promotion_hmac=hmac.new(
                self._key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_promotion(self, promotion: HuntCasePromotion) -> bool:
        value = asdict(promotion)
        signature = value.pop("promotion_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    def _latest_total_bytes(self, hunt_id: str) -> int:
        row = self._db.execute(
            "SELECT COALESCE(SUM(bytes_collected),0) FROM hunt_progress p "
            "WHERE hunt_id=? AND seq=("
            "SELECT MAX(seq) FROM hunt_progress x "
            "WHERE x.hunt_id=p.hunt_id AND x.device_token=p.device_token)",
            (hunt_id,),
        ).fetchone()
        return int(row[0] or 0)

    @staticmethod
    def _row_event(event_id: str, row: tuple[Any, ...]) -> HuntProgressEvent:
        return HuntProgressEvent(
            event_id, row[0], row[1], row[2], float(row[3]), int(row[4]),
            row[5], tuple(json.loads(row[6])),
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()
