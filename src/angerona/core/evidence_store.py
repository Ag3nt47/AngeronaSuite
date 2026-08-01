"""Versioned, local-first normalized evidence storage and structured hunting.

This is intentionally separate from :mod:`angerona.core.storage`: the flight
recorder remains the authoritative signed alert ledger.  This store provides a
bounded normalization and read model for correlation and hunting.  Callers
submit ``HuntQuery`` objects; database text is never accepted as an API input.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from angerona.core.eventbus import Event

SCHEMA_NAME = "angerona.evidence"
SCHEMA_VERSION = "1.0"
_MAX_QUERY_LIMIT = 1000
_MAX_PREDICATES = 12
_MAX_VALUE_LENGTH = 1024
_OPERATORS = frozenset({"eq", "in", "contains", "prefix", "exists"})
_FIELDS = frozenset({
    "activity", "category", "confidence", "device.id", "event_id",
    "message", "module", "severity", "source", "subject.id", "subject.kind",
})


def _bounded_text(value: object, maximum: int = _MAX_VALUE_LENGTH) -> str:
    return str(value or "")[:maximum]


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    )


@dataclass(frozen=True)
class EvidenceEnvelope:
    """Portable normalized evidence with explicit schema and provenance."""

    event_id: str
    observed_at: float
    category: str
    activity: str
    severity: int
    message: str
    module: str
    source: str = "local"
    confidence: int = 50
    device: Mapping[str, Any] = field(default_factory=dict)
    subject: Mapping[str, Any] = field(default_factory=dict)
    attributes: Mapping[str, Any] = field(default_factory=dict)
    provenance: Mapping[str, Any] = field(default_factory=dict)
    schema: str = SCHEMA_NAME
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_NAME or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported evidence schema")
        if not self.event_id or len(self.event_id) > 128:
            raise ValueError("event_id must contain 1-128 characters")
        if not 0 <= int(self.severity) <= 4:
            raise ValueError("severity must be between 0 and 4")
        if not 0 <= int(self.confidence) <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if not self.category or not self.activity or not self.module:
            raise ValueError("category, activity, and module are required")
        for value in (self.device, self.subject, self.attributes, self.provenance):
            if not isinstance(value, Mapping):
                raise TypeError("structured evidence fields must be mappings")
        # Bound one envelope before it can consume material local storage.
        if len(_canonical(asdict(self)).encode("utf-8")) > 256 * 1024:
            raise ValueError("evidence envelope exceeds 256 KiB")

    @classmethod
    def from_event(
        cls,
        event: Event,
        *,
        category: str = "security_finding",
        activity: str = "observe",
        device_id: str = "",
    ) -> "EvidenceEnvelope":
        """Normalize a canonical Angerona event without mutating its details."""
        stable = _canonical({
            "module": event.module, "message": event.message, "ts": event.ts,
            "severity": int(event.severity), "details": event.details or {},
        })
        event_id = "evt-" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:32]
        details = dict(event.details or {})
        subject: dict[str, Any] = {}
        for key in ("pid", "path", "process", "user", "ip", "domain", "hash"):
            if key in details:
                subject[key] = details[key]
        if subject:
            subject.setdefault("kind", "observation")
            subject.setdefault("id", _bounded_text(
                subject.get("pid") or subject.get("path") or subject.get("ip")
                or subject.get("domain") or subject.get("hash")
            ))
        return cls(
            event_id=event_id,
            observed_at=float(event.ts),
            category=_bounded_text(category, 80),
            activity=_bounded_text(activity, 80),
            severity=int(event.severity),
            message=_bounded_text(event.message, 8192),
            module=_bounded_text(event.module, 256),
            confidence=int(details.get("confidence", 50))
            if str(details.get("confidence", 50)).isdigit() else 50,
            device={"id": _bounded_text(device_id, 256)} if device_id else {},
            subject=subject,
            attributes=details,
            provenance={
                "kind": "angerona_event",
                "integrity": "hmac" if event.hmac_sig else "unsigned",
                "source_signature": event.hmac_sig,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HuntPredicate:
    field: str
    operator: str
    value: Any = None

    def __post_init__(self) -> None:
        if self.field not in _FIELDS:
            raise ValueError(f"unsupported hunt field: {self.field}")
        if self.operator not in _OPERATORS:
            raise ValueError(f"unsupported hunt operator: {self.operator}")
        if self.operator == "in":
            if not isinstance(self.value, (list, tuple, set, frozenset)):
                raise ValueError("'in' requires a sequence")
            if not 1 <= len(self.value) <= 50:
                raise ValueError("'in' accepts 1-50 values")
        elif self.operator != "exists" and len(_bounded_text(self.value)) > _MAX_VALUE_LENGTH:
            raise ValueError("hunt value is too long")


@dataclass(frozen=True)
class HuntQuery:
    predicates: Sequence[HuntPredicate] = ()
    start_time: float | None = None
    end_time: float | None = None
    limit: int = 100
    newest_first: bool = True

    def __post_init__(self) -> None:
        if len(self.predicates) > _MAX_PREDICATES:
            raise ValueError(f"at most {_MAX_PREDICATES} predicates are allowed")
        if not 1 <= int(self.limit) <= _MAX_QUERY_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_QUERY_LIMIT}")
        if self.start_time is not None and self.end_time is not None:
            if float(self.start_time) > float(self.end_time):
                raise ValueError("start_time must not exceed end_time")


@dataclass(frozen=True)
class HuntResult:
    evidence: tuple[EvidenceEnvelope, ...]
    scanned: int
    truncated: bool
    elapsed_ms: float


class EvidenceStore:
    """Bounded SQLite evidence read model; local-origin writes by default."""

    def __init__(
        self,
        db_path: Path,
        *,
        max_rows: int = 100_000,
        retention_seconds: float = 30 * 24 * 3600,
        local_only: bool = True,
        candidate_limit: int = 5000,
    ) -> None:
        if max_rows < 1 or retention_seconds <= 0 or candidate_limit < 1:
            raise ValueError("retention limits must be positive")
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.max_rows = int(max_rows)
        self.retention_seconds = float(retention_seconds)
        self.local_only = bool(local_only)
        self.candidate_limit = min(int(candidate_limit), 20_000)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self._path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS normalized_evidence (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                observed_at REAL NOT NULL,
                category TEXT NOT NULL,
                activity TEXT NOT NULL,
                severity INTEGER NOT NULL,
                module TEXT NOT NULL,
                source TEXT NOT NULL,
                envelope_json TEXT NOT NULL
            )
        """)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_time ON normalized_evidence(observed_at)"
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_hunt "
            "ON normalized_evidence(category, severity, observed_at)"
        )
        self._db.commit()

    def append(self, evidence: EvidenceEnvelope) -> bool:
        """Insert one envelope. Duplicate event IDs are idempotently ignored."""
        if self.local_only and evidence.source != "local":
            raise ValueError("remote evidence is disabled for this local-only store")
        encoded = _canonical(evidence.to_dict())
        with self._lock:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO normalized_evidence "
                "(event_id,observed_at,category,activity,severity,module,source,envelope_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (evidence.event_id, evidence.observed_at, evidence.category,
                 evidence.activity, evidence.severity, evidence.module,
                 evidence.source, encoded),
            )
            inserted = cursor.rowcount == 1
            if inserted:
                self._prune_locked()
            self._db.commit()
        return inserted

    def append_many(
        self, evidence_items: Sequence[EvidenceEnvelope],
    ) -> tuple[int, int]:
        """Insert a bounded batch in one transaction.

        Returns ``(inserted, duplicates)``. Validation and local-origin checks
        finish before the transaction starts, so malformed input cannot produce
        a partial batch.
        """
        items = tuple(evidence_items)
        if len(items) > 1000:
            raise ValueError("evidence batch exceeds 1000 records")
        rows = []
        for evidence in items:
            if self.local_only and evidence.source != "local":
                raise ValueError("remote evidence is disabled for this local-only store")
            rows.append((
                evidence.event_id, evidence.observed_at, evidence.category,
                evidence.activity, evidence.severity, evidence.module,
                evidence.source, _canonical(evidence.to_dict()),
            ))
        if not rows:
            return 0, 0
        with self._lock:
            before = self._db.total_changes
            self._db.executemany(
                "INSERT OR IGNORE INTO normalized_evidence "
                "(event_id,observed_at,category,activity,severity,module,source,envelope_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                rows,
            )
            inserted = self._db.total_changes - before
            if inserted:
                self._prune_locked()
            self._db.commit()
        return int(inserted), len(rows) - int(inserted)

    def append_event(self, event: Event, **normalization: Any) -> bool:
        return self.append(EvidenceEnvelope.from_event(event, **normalization))

    def _prune_locked(self, now: float | None = None) -> None:
        cutoff = float(time.time() if now is None else now) - self.retention_seconds
        self._db.execute(
            "DELETE FROM normalized_evidence WHERE observed_at < ?", (cutoff,)
        )
        self._db.execute(
            "DELETE FROM normalized_evidence WHERE seq IN ("
            "SELECT seq FROM normalized_evidence ORDER BY observed_at DESC, seq DESC "
            "LIMIT -1 OFFSET ?)", (self.max_rows,)
        )

    def enforce_retention(self, *, now: float | None = None) -> None:
        with self._lock:
            self._prune_locked(now)
            self._db.commit()

    @staticmethod
    def _field(item: EvidenceEnvelope, name: str) -> Any:
        if name == "device.id":
            return item.device.get("id")
        if name == "subject.id":
            return item.subject.get("id")
        if name == "subject.kind":
            return item.subject.get("kind")
        return getattr(item, name)

    @classmethod
    def _matches(cls, item: EvidenceEnvelope, predicate: HuntPredicate) -> bool:
        actual = cls._field(item, predicate.field)
        if predicate.operator == "exists":
            return actual is not None and actual != ""
        if predicate.operator == "in":
            return actual in predicate.value
        if predicate.operator == "eq":
            return actual == predicate.value
        actual_text = _bounded_text(actual).casefold()
        wanted = _bounded_text(predicate.value).casefold()
        if predicate.operator == "contains":
            return wanted in actual_text
        return actual_text.startswith(wanted)

    def hunt(self, query: HuntQuery) -> HuntResult:
        """Execute a bounded structured query; never evaluates caller SQL."""
        started = time.perf_counter()
        clauses: list[str] = []
        params: list[Any] = []
        if query.start_time is not None:
            clauses.append("observed_at >= ?")
            params.append(float(query.start_time))
        if query.end_time is not None:
            clauses.append("observed_at <= ?")
            params.append(float(query.end_time))
        # Push safe scalar equality filters to SQLite; all other predicates are
        # evaluated over a hard-bounded candidate window.
        columns = {
            "event_id", "category", "activity", "severity", "module", "source",
        }
        residual: list[HuntPredicate] = []
        for predicate in query.predicates:
            if predicate.field in columns and predicate.operator == "eq":
                clauses.append(f"{predicate.field} = ?")
                params.append(predicate.value)
            else:
                residual.append(predicate)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        order = "DESC" if query.newest_first else "ASC"
        fetch_limit = min(self.candidate_limit, max(query.limit * 10, query.limit + 1))
        sql = (
            "SELECT envelope_json FROM normalized_evidence" + where  # nosec B608
            # Fields/operators above are closed allowlists; all caller-controlled
            # values remain parameterized.
            + f" ORDER BY observed_at {order}, seq {order} LIMIT ?"
        )
        params.append(fetch_limit + 1)
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        candidates = rows[:fetch_limit]
        matches: list[EvidenceEnvelope] = []
        for (encoded,) in candidates:
            item = EvidenceEnvelope(**json.loads(encoded))
            if all(self._matches(item, predicate) for predicate in residual):
                matches.append(item)
                if len(matches) >= query.limit:
                    break
        truncated = len(rows) > fetch_limit or (
            len(matches) >= query.limit and len(candidates) > len(matches)
        )
        return HuntResult(
            evidence=tuple(matches),
            scanned=len(candidates),
            truncated=truncated,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )

    def count(self) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) FROM normalized_evidence"
            ).fetchone()
        return int(row[0] if row else 0)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def new_evidence_id(prefix: str = "evidence") -> str:
    """Return a non-semantic random ID for producers without a stable source ID."""
    return f"{_bounded_text(prefix, 24)}-{uuid.uuid4().hex}"
