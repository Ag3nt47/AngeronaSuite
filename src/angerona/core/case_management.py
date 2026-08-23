"""Durable local incident cases and authenticated evidence custody metadata."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit

MAX_TAGS = 32
MAX_TIMELINE = 5000
MAX_EVIDENCE = 2000
MAX_TEXT = 8000
MAX_OBSERVABLES = 2000
MAX_RELATED_CASES = 100
MAX_RELATED_MATCH_ROWS = 10_000
_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
_PRIVACY = {"public", "system", "sensitive", "restricted"}
_OBSERVABLE_STATUSES = {"suggested", "approved", "rejected"}
_OBSERVABLE_KINDS = {
    "certificate_sha256",
    "domain",
    "email",
    "file_md5",
    "file_path",
    "file_sha256",
    "ipv4",
    "ipv6",
    "process_name",
    "registry_key",
    "url",
    "username",
}
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_DOMAIN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}$")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(?i)\b[A-Z]:\\(?:Users|Documents and Settings)\\[^\\\s]+(?:\\[^\s,;]+)*"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b"),
)


class CaseConflict(RuntimeError):
    pass


class ObservableIntegrityError(RuntimeError):
    """An observable row no longer matches its keyed integrity record."""


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    title: str
    status: str
    assignee: str
    tags: tuple[str, ...]
    version: int
    legal_hold: bool
    retention_until: float
    created_at: float
    updated_at: float


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    display_name: str
    sha256: str
    size: int
    source: str
    provenance: str
    collected_at: float
    privacy_class: str


@dataclass(frozen=True)
class CaseTimelineEntry:
    entry_id: int
    kind: str
    actor: str
    text: str
    timestamp: float


@dataclass(frozen=True)
class ObservableRecord:
    """A local-only case observable.

    ``value`` is sensitive and is intentionally available only through the
    authenticated local case store API. Sanitized exports never include it or
    its correlation digest.
    """

    observable_id: str
    case_id: str
    kind: str
    value: str
    status: str
    confidence: float
    source: str
    exclude_from_similarity: bool
    created_at: float


@dataclass(frozen=True)
class RelatedCase:
    case_id: str
    shared_observables: int
    shared_types: tuple[str, ...]


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _safe_text(value: str, limit: int = MAX_TEXT) -> str:
    return str(value).replace("\x00", "")[:limit]


def _safe_filename(value: str) -> str:
    name = PurePath(str(value).replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9_. -]", "_", name).strip(" .")
    if not name or name in {".", ".."}:
        raise ValueError("unsafe evidence display name")
    return name[:200]


def _redact_text(value: object, limit: int = MAX_TEXT) -> str:
    """Remove common credentials, identity, and user-profile paths from exports."""
    text = _safe_text(str(value), limit)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _normalize_observable(kind: str, value: str) -> tuple[str, str]:
    """Return the bounded raw value and a stable private-correlation value."""
    kind = str(kind).strip().lower()
    if kind not in _OBSERVABLE_KINDS:
        raise ValueError("unsupported observable kind")
    raw = _safe_text(value, 2048).strip()
    if not raw or len(str(value)) > 2048:
        raise ValueError("observable value is empty or too long")

    if kind in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(raw)
        if address.version != (4 if kind == "ipv4" else 6):
            raise ValueError("observable IP version does not match kind")
        normalized = address.compressed.lower()
    elif kind == "domain":
        try:
            normalized = raw.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("invalid observable domain") from exc
        if not _DOMAIN.fullmatch(normalized):
            raise ValueError("invalid observable domain")
    elif kind == "email":
        normalized = raw.casefold()
        if not _EMAIL.fullmatch(normalized):
            raise ValueError("invalid observable email")
    elif kind in {"file_sha256", "certificate_sha256"}:
        normalized = raw.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("invalid SHA-256 observable")
    elif kind == "file_md5":
        normalized = raw.lower()
        if not re.fullmatch(r"[0-9a-f]{32}", normalized):
            raise ValueError("invalid MD5 observable")
    elif kind == "url":
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("only absolute HTTP(S) observable URLs are supported")
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise ValueError("invalid observable URL") from exc
        ip_host = _is_ip_literal(host)
        if not _DOMAIN.fullmatch(host) and not ip_host:
            raise ValueError("invalid observable URL host")
        default_port = (parsed.scheme.lower() == "http" and port == 80) or (
            parsed.scheme.lower() == "https" and port == 443
        )
        display_host = f"[{host}]" if ip_host and ":" in host else host
        netloc = (
            display_host
            if port is None or default_port
            else f"{display_host}:{port}"
        )
        normalized = urlunsplit(SplitResult(
            parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""
        ))
    elif kind == "process_name":
        if "/" in raw or "\\" in raw or raw in {".", ".."} or len(raw) > 260:
            raise ValueError("process_name must be a basename")
        normalized = raw.casefold()
    elif kind in {"file_path", "registry_key"}:
        if len(raw) > 1024:
            raise ValueError("path-like observable is too long")
        normalized = re.sub(r"[\\/]+", r"\\", raw).rstrip("\\").casefold()
    else:  # username
        if len(raw) > 320:
            raise ValueError("username observable is too long")
        normalized = raw.casefold()
    return raw, normalized


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class CaseStore:
    def __init__(self, path: Path, custody_key: bytes) -> None:
        if len(custody_key) < 32:
            raise ValueError("custody key must be at least 32 bytes")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = bytes(custody_key)
        self._observable_index_key = hmac.new(
            self._key, b"angerona/case-observable-index/v1", hashlib.sha256
        ).digest()
        self._observable_record_key = hmac.new(
            self._key, b"angerona/case-observable-record/v1", hashlib.sha256
        ).digest()
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS cases(
          case_id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
          assignee TEXT NOT NULL, tags_json TEXT NOT NULL, version INTEGER NOT NULL,
          legal_hold INTEGER NOT NULL, retention_until REAL NOT NULL,
          created_at REAL NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS timeline(
          entry_id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
          kind TEXT NOT NULL, actor TEXT NOT NULL, text TEXT NOT NULL, ts REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(
          evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, display_name TEXT NOT NULL,
          sha256 TEXT NOT NULL, size INTEGER NOT NULL, source TEXT NOT NULL,
          provenance TEXT NOT NULL, collected_at REAL NOT NULL, privacy_class TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS custody(
          seq INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT NOT NULL,
          action TEXT NOT NULL, actor TEXT NOT NULL, ts REAL NOT NULL,
          previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, hmac TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS custody_heads(
          evidence_id TEXT PRIMARY KEY, event_count INTEGER NOT NULL,
          final_hash TEXT NOT NULL, hmac TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS retention_receipts(
          evidence_id TEXT PRIMARY KEY, event_count INTEGER NOT NULL,
          final_hash TEXT NOT NULL, purged_at REAL NOT NULL, hmac TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS case_observables(
          observable_id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
          kind TEXT NOT NULL, raw_value TEXT NOT NULL, status TEXT NOT NULL,
          confidence REAL NOT NULL, source TEXT NOT NULL,
          exclude_from_similarity INTEGER NOT NULL,
          similarity_hmac TEXT NOT NULL, created_at REAL NOT NULL,
          record_hmac TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_case_timeline ON timeline(case_id, entry_id);
        CREATE INDEX IF NOT EXISTS idx_case_evidence ON evidence(case_id);
        CREATE INDEX IF NOT EXISTS idx_case_observables_case
          ON case_observables(case_id, observable_id);
        CREATE INDEX IF NOT EXISTS idx_case_observables_similarity
          ON case_observables(similarity_hmac, status, exclude_from_similarity);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_case_observables_dedupe
          ON case_observables(case_id, kind, similarity_hmac);
        """)

    def _transaction(self):
        return self._db

    def create_case(
        self, title: str, *, assignee: str = "", tags: Sequence[str] = (),
        retention_until: float = 0, now: float | None = None,
        case_id: str | None = None,
    ) -> CaseRecord:
        tags = tuple(sorted({_safe_text(tag, 80) for tag in tags if tag}))
        if len(tags) > MAX_TAGS:
            raise ValueError("too many tags")
        stamp = time.time() if now is None else float(now)
        case_id = case_id or ("case-" + uuid.uuid4().hex)
        if not _SAFE_ID.fullmatch(case_id):
            raise ValueError("invalid case ID")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (case_id, _safe_text(title, 500), "open",
                     _safe_text(assignee, 128), json.dumps(tags), 1, 0,
                     float(retention_until), stamp, stamp),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_case(case_id)

    def evidence_owner(self, evidence_id: str) -> str | None:
        """Return the owning case for an evidence reference, if present."""
        if not _SAFE_ID.fullmatch(evidence_id):
            raise ValueError("invalid evidence ID")
        with self._lock:
            row = self._db.execute(
                "SELECT case_id FROM evidence WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
        return None if row is None else str(row[0])

    def get_case(self, case_id: str) -> CaseRecord:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM cases WHERE case_id=?", (case_id,)
            ).fetchone()
        if row is None:
            raise KeyError(case_id)
        return CaseRecord(
            row[0], row[1], row[2], row[3], tuple(json.loads(row[4])),
            int(row[5]), bool(row[6]), float(row[7]), float(row[8]), float(row[9]),
        )

    def list_cases(
        self, *, status: str | None = None, limit: int = 500,
        newest_first: bool = True,
    ) -> tuple[CaseRecord, ...]:
        """Return a bounded case queue for a local operator interface."""
        if status is not None and status not in _STATUSES:
            raise ValueError("invalid case status")
        limit = max(1, min(int(limit), 2000))
        direction = "DESC" if newest_first else "ASC"
        sql = "SELECT * FROM cases"
        params: list[Any] = []
        if status is not None:
            sql += " WHERE status=?"
            params.append(status)
        # ``direction`` is selected from the fixed literals above; all caller
        # values remain SQLite parameters.
        sql += f" ORDER BY updated_at {direction},case_id {direction} LIMIT ?"  # nosec B608
        params.append(limit)
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return tuple(CaseRecord(
            row[0], row[1], row[2], row[3], tuple(json.loads(row[4])),
            int(row[5]), bool(row[6]), float(row[7]), float(row[8]),
            float(row[9]),
        ) for row in rows)

    def timeline(
        self, case_id: str, *, limit: int = 1000,
        newest_first: bool = False,
    ) -> tuple[CaseTimelineEntry, ...]:
        """Return attributed local timeline entries without sanitizing them."""
        self.get_case(case_id)
        limit = max(1, min(int(limit), MAX_TIMELINE))
        query = (
            "SELECT entry_id,kind,actor,text,ts FROM timeline "
            "WHERE case_id=? ORDER BY entry_id DESC LIMIT ?"
            if newest_first
            else
            "SELECT entry_id,kind,actor,text,ts FROM timeline "
            "WHERE case_id=? ORDER BY entry_id ASC LIMIT ?"
        )
        with self._lock:
            rows = self._db.execute(query, (case_id, limit)).fetchall()
        return tuple(CaseTimelineEntry(
            int(row[0]), str(row[1]), str(row[2]), str(row[3]), float(row[4])
        ) for row in rows)

    def evidence(
        self, case_id: str, *, limit: int = 1000,
    ) -> tuple[EvidenceReference, ...]:
        """Return bounded evidence metadata; raw content is never stored here."""
        self.get_case(case_id)
        limit = max(1, min(int(limit), MAX_EVIDENCE))
        with self._lock:
            rows = self._db.execute(
                "SELECT evidence_id,display_name,sha256,size,source,provenance,"
                "collected_at,privacy_class FROM evidence WHERE case_id=? "
                "ORDER BY collected_at,evidence_id LIMIT ?",
                (case_id, limit),
            ).fetchall()
        return tuple(EvidenceReference(
            str(row[0]), str(row[1]), str(row[2]), int(row[3]), str(row[4]),
            str(row[5]), float(row[6]), str(row[7]),
        ) for row in rows)

    def evidence_counts(self) -> dict[str, int]:
        """Return all case evidence counts in one bounded aggregate query."""
        with self._lock:
            rows = self._db.execute(
                "SELECT case_id,COUNT(*) FROM evidence GROUP BY case_id"
            ).fetchall()
        return {str(case_id): int(count) for case_id, count in rows}

    def _observable_digest(self, kind: str, normalized_value: str) -> str:
        return hmac.new(
            self._observable_index_key,
            _canonical({"kind": kind, "value": normalized_value}),
            hashlib.sha256,
        ).hexdigest()

    def _observable_signature(self, values: dict[str, object]) -> str:
        return hmac.new(
            self._observable_record_key, _canonical(values), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _observable_body(row: Sequence[object]) -> dict[str, object]:
        return {
            "observable_id": str(row[0]),
            "case_id": str(row[1]),
            "kind": str(row[2]),
            "raw_value": str(row[3]),
            "status": str(row[4]),
            "confidence": float(row[5]),
            "source": str(row[6]),
            "exclude_from_similarity": int(row[7]),
            "similarity_hmac": str(row[8]),
            "created_at": float(row[9]),
        }

    def _observable_is_valid(self, row: Sequence[object]) -> bool:
        try:
            body = self._observable_body(row)
            raw, normalized = _normalize_observable(
                str(body["kind"]), str(body["raw_value"])
            )
            expected_digest = self._observable_digest(
                str(body["kind"]), normalized
            )
            expected_signature = self._observable_signature(body)
            return (
                raw == body["raw_value"]
                and body["status"] in _OBSERVABLE_STATUSES
                and 0.0 <= float(body["confidence"]) <= 1.0
                and int(body["exclude_from_similarity"]) in {0, 1}
                and hmac.compare_digest(
                    str(body["similarity_hmac"]), expected_digest
                )
                and hmac.compare_digest(str(row[10]), expected_signature)
            )
        except (TypeError, ValueError):
            return False

    def _observable_record(self, row: Sequence[object]) -> ObservableRecord:
        if not self._observable_is_valid(row):
            raise ObservableIntegrityError(
                f"observable integrity verification failed: {row[0]}"
            )
        return ObservableRecord(
            observable_id=str(row[0]), case_id=str(row[1]), kind=str(row[2]),
            value=str(row[3]), status=str(row[4]), confidence=float(row[5]),
            source=str(row[6]), exclude_from_similarity=bool(row[7]),
            created_at=float(row[9]),
        )

    def add_observable(
        self,
        case_id: str,
        kind: str,
        value: str,
        *,
        status: str = "suggested",
        confidence: float = 0.5,
        source: str = "operator",
        exclude_from_similarity: bool = False,
        now: float | None = None,
        observable_id: str | None = None,
    ) -> ObservableRecord:
        """Add a local observable, idempotently per case/type/value.

        Suggested and rejected values are retained for human review but are
        never considered by ``related_cases``. This store has no path into
        threat posture or SOAR; consumers must make a separate, explicit
        decision before taking action.
        """
        kind = str(kind).strip().lower()
        raw, normalized = _normalize_observable(kind, value)
        status = str(status).strip().lower()
        if status not in _OBSERVABLE_STATUSES:
            raise ValueError("invalid observable status")
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("observable confidence must be between 0 and 1")
        source = _safe_text(source, 300).strip()
        if not source:
            raise ValueError("observable source is required")
        observable_id = observable_id or ("obs-" + uuid.uuid4().hex)
        if not _SAFE_ID.fullmatch(observable_id):
            raise ValueError("invalid observable ID")
        stamp = time.time() if now is None else float(now)
        digest = self._observable_digest(kind, normalized)
        body: dict[str, object] = {
            "observable_id": observable_id,
            "case_id": case_id,
            "kind": kind,
            "raw_value": raw,
            "status": status,
            "confidence": confidence,
            "source": source,
            "exclude_from_similarity": int(bool(exclude_from_similarity)),
            "similarity_hmac": digest,
            "created_at": stamp,
        }
        signature = self._observable_signature(body)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if self._db.execute(
                    "SELECT 1 FROM cases WHERE case_id=?", (case_id,)
                ).fetchone() is None:
                    raise KeyError(case_id)
                count = int(self._db.execute(
                    "SELECT COUNT(*) FROM case_observables WHERE case_id=?",
                    (case_id,),
                ).fetchone()[0])
                if count >= MAX_OBSERVABLES:
                    existing = self._db.execute(
                        "SELECT * FROM case_observables WHERE case_id=? AND kind=? "
                        "AND similarity_hmac=?",
                        (case_id, kind, digest),
                    ).fetchone()
                    if existing is None:
                        raise ValueError("case observable bound reached")
                self._db.execute(
                    "INSERT OR IGNORE INTO case_observables VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        observable_id, case_id, kind, raw, status, confidence,
                        source, int(bool(exclude_from_similarity)), digest,
                        stamp, signature,
                    ),
                )
                row = self._db.execute(
                    "SELECT * FROM case_observables WHERE case_id=? AND kind=? "
                    "AND similarity_hmac=?",
                    (case_id, kind, digest),
                ).fetchone()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        if row is None:  # defensive: the unique row must exist after INSERT
            raise RuntimeError("observable insert did not persist")
        return self._observable_record(row)

    def observables(
        self, case_id: str, *, limit: int = 1000
    ) -> tuple[ObservableRecord, ...]:
        """Return local raw observable records after keyed integrity checks."""
        self.get_case(case_id)
        limit = max(1, min(int(limit), MAX_OBSERVABLES))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM case_observables WHERE case_id=? "
                "ORDER BY created_at,observable_id LIMIT ?",
                (case_id, limit),
            ).fetchall()
        return tuple(self._observable_record(row) for row in rows)

    def verify_observable(self, observable_id: str) -> bool:
        if not _SAFE_ID.fullmatch(observable_id):
            raise ValueError("invalid observable ID")
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM case_observables WHERE observable_id=?",
                (observable_id,),
            ).fetchone()
        return row is not None and self._observable_is_valid(row)

    def review_observable(
        self,
        observable_id: str,
        *,
        status: str,
        exclude_from_similarity: bool | None = None,
    ) -> ObservableRecord:
        """Record a human review decision without changing the raw value."""
        status = str(status).strip().lower()
        if status not in _OBSERVABLE_STATUSES:
            raise ValueError("invalid observable status")
        if not _SAFE_ID.fullmatch(observable_id):
            raise ValueError("invalid observable ID")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM case_observables WHERE observable_id=?",
                    (observable_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(observable_id)
                record = self._observable_record(row)
                excluded = (
                    record.exclude_from_similarity
                    if exclude_from_similarity is None
                    else bool(exclude_from_similarity)
                )
                body = self._observable_body(row)
                body["status"] = status
                body["exclude_from_similarity"] = int(excluded)
                signature = self._observable_signature(body)
                self._db.execute(
                    "UPDATE case_observables SET status=?,"
                    "exclude_from_similarity=?,record_hmac=? WHERE observable_id=?",
                    (status, int(excluded), signature, observable_id),
                )
                updated = self._db.execute(
                    "SELECT * FROM case_observables WHERE observable_id=?",
                    (observable_id,),
                ).fetchone()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self._observable_record(updated)

    def related_cases(
        self, case_id: str, *, limit: int = 20
    ) -> tuple[RelatedCase, ...]:
        """Find bounded case similarity using approved, non-excluded HMACs."""
        self.get_case(case_id)
        limit = max(1, min(int(limit), MAX_RELATED_CASES))
        with self._lock:
            own_rows = self._db.execute(
                "SELECT * FROM case_observables WHERE case_id=? AND status='approved' "
                "AND exclude_from_similarity=0 LIMIT ?",
                (case_id, MAX_OBSERVABLES),
            ).fetchall()
        own: dict[str, str] = {}
        for row in own_rows:
            if self._observable_is_valid(row):
                own[str(row[8])] = str(row[2])
        if not own:
            return ()

        matches: dict[str, dict[str, str]] = {}
        digests = tuple(own)
        # Stay below SQLite's conservative host-parameter bound.
        with self._lock:
            for offset in range(0, len(digests), 400):
                chunk = digests[offset:offset + 400]
                placeholders = ",".join("?" for _ in chunk)
                rows = self._db.execute(
                    "SELECT * FROM case_observables WHERE case_id<>? "
                    "AND status='approved' AND exclude_from_similarity=0 "
                    f"AND similarity_hmac IN ({placeholders}) "  # nosec B608
                    "ORDER BY case_id,observable_id LIMIT ?",
                    (case_id, *chunk, MAX_RELATED_MATCH_ROWS),
                ).fetchall()
                for row in rows:
                    if not self._observable_is_valid(row):
                        continue
                    candidate = str(row[1])
                    matches.setdefault(candidate, {})[str(row[8])] = str(row[2])
        related = [
            RelatedCase(
                candidate, len(shared), tuple(sorted(set(shared.values())))
            )
            for candidate, shared in matches.items()
        ]
        related.sort(key=lambda item: (-item.shared_observables, item.case_id))
        return tuple(related[:limit])

    def update_case(
        self, case_id: str, expected_version: int, *, status: str | None = None,
        assignee: str | None = None, tags: Sequence[str] | None = None,
        legal_hold: bool | None = None, retention_until: float | None = None,
        now: float | None = None,
    ) -> CaseRecord:
        current = self.get_case(case_id)
        new_status = current.status if status is None else status
        if new_status not in _STATUSES:
            raise ValueError("invalid case status")
        new_tags = current.tags if tags is None else tuple(sorted({
            _safe_text(tag, 80) for tag in tags if tag
        }))
        if len(new_tags) > MAX_TAGS:
            raise ValueError("too many tags")
        values = (
            new_status,
            current.assignee if assignee is None else _safe_text(assignee, 128),
            json.dumps(new_tags),
            int(current.legal_hold if legal_hold is None else legal_hold),
            current.retention_until if retention_until is None else float(retention_until),
            time.time() if now is None else float(now),
            case_id, int(expected_version),
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cursor = self._db.execute(
                    "UPDATE cases SET status=?,assignee=?,tags_json=?,legal_hold=?,"
                    "retention_until=?,updated_at=?,version=version+1 "
                    "WHERE case_id=? AND version=?", values,
                )
                if cursor.rowcount != 1:
                    raise CaseConflict("case version changed")
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_case(case_id)

    def add_comment(
        self, case_id: str, actor: str, text: str, *, now: float | None = None
    ) -> int:
        if not _SAFE_ID.fullmatch(actor):
            raise ValueError("invalid attributed actor")
        if not text:
            raise ValueError("empty comment")
        with self._lock:
            if self._db.execute(
                "SELECT 1 FROM cases WHERE case_id=?", (case_id,)
            ).fetchone() is None:
                raise KeyError(case_id)
            count = self._db.execute(
                "SELECT COUNT(*) FROM timeline WHERE case_id=?", (case_id,)
            ).fetchone()[0]
            if count >= MAX_TIMELINE:
                raise ValueError("case timeline bound reached")
            cursor = self._db.execute(
                "INSERT INTO timeline(case_id,kind,actor,text,ts) VALUES(?,?,?,?,?)",
                (case_id, "comment", actor, _safe_text(text),
                 time.time() if now is None else float(now)),
            )
        return int(cursor.lastrowid)

    def add_evidence(
        self, case_id: str, reference: EvidenceReference, actor: str,
        *, now: float | None = None,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", reference.sha256):
            raise ValueError("invalid SHA-256")
        if reference.size < 0 or reference.privacy_class not in _PRIVACY:
            raise ValueError("invalid evidence metadata")
        if not _SAFE_ID.fullmatch(reference.evidence_id) or not _SAFE_ID.fullmatch(actor):
            raise ValueError("invalid evidence or actor ID")
        with self._lock:
            if self._db.execute(
                "SELECT 1 FROM cases WHERE case_id=?", (case_id,)
            ).fetchone() is None:
                raise KeyError(case_id)
            count = self._db.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)
            ).fetchone()[0]
            if count >= MAX_EVIDENCE:
                raise ValueError("case evidence bound reached")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)",
                    (reference.evidence_id, case_id,
                     _safe_filename(reference.display_name), reference.sha256,
                     int(reference.size), _safe_text(reference.source, 300),
                     _safe_text(reference.provenance, 1000),
                     float(reference.collected_at), reference.privacy_class),
                )
                self._append_custody_locked(
                    reference.evidence_id, "collected", actor,
                    time.time() if now is None else float(now),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _append_custody_locked(
        self, evidence_id: str, action: str, actor: str, stamp: float
    ) -> None:
        previous = self._db.execute(
            "SELECT event_hash FROM custody WHERE evidence_id=? ORDER BY seq DESC LIMIT 1",
            (evidence_id,),
        ).fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        body = {
            "evidence_id": evidence_id, "action": action, "actor": actor,
            "ts": stamp, "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(_canonical(body)).hexdigest()
        signature = hmac.new(
            self._key, event_hash.encode("ascii"), hashlib.sha256
        ).hexdigest()
        self._db.execute(
            "INSERT INTO custody(evidence_id,action,actor,ts,previous_hash,event_hash,hmac)"
            " VALUES(?,?,?,?,?,?,?)",
            (evidence_id, action, actor, stamp, previous_hash, event_hash, signature),
        )
        count = int(self._db.execute(
            "SELECT COUNT(*) FROM custody WHERE evidence_id=?", (evidence_id,)
        ).fetchone()[0])
        head_body = {
            "evidence_id": evidence_id, "event_count": count,
            "final_hash": event_hash,
        }
        head_sig = hmac.new(self._key, _canonical(head_body), hashlib.sha256).hexdigest()
        self._db.execute(
            "INSERT INTO custody_heads(evidence_id,event_count,final_hash,hmac) "
            "VALUES(?,?,?,?) ON CONFLICT(evidence_id) DO UPDATE SET "
            "event_count=excluded.event_count,final_hash=excluded.final_hash,hmac=excluded.hmac",
            (evidence_id, count, event_hash, head_sig),
        )

    def transfer_custody(
        self, evidence_id: str, action: str, actor: str, *,
        now: float | None = None,
    ) -> None:
        if not _SAFE_ID.fullmatch(actor) or not action:
            raise ValueError("invalid custody event")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if self._db.execute(
                    "SELECT 1 FROM evidence WHERE evidence_id=?", (evidence_id,)
                ).fetchone() is None:
                    raise KeyError(evidence_id)
                self._append_custody_locked(
                    evidence_id, _safe_text(action, 200), actor,
                    time.time() if now is None else float(now),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def verify_custody(self, evidence_id: str) -> bool:
        with self._lock:
            rows = self._db.execute(
                "SELECT action,actor,ts,previous_hash,event_hash,hmac FROM custody "
                "WHERE evidence_id=? ORDER BY seq", (evidence_id,),
            ).fetchall()
            head = self._db.execute(
                "SELECT event_count,final_hash,hmac FROM custody_heads WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            if not rows or head is None:
                return False
            previous = "0" * 64
            for action, actor, stamp, stored_previous, event_hash, signature in rows:
                body = {
                    "evidence_id": evidence_id, "action": action, "actor": actor,
                    "ts": stamp, "previous_hash": stored_previous,
                }
                expected_hash = hashlib.sha256(_canonical(body)).hexdigest()
                expected_sig = hmac.new(
                    self._key, expected_hash.encode("ascii"), hashlib.sha256
                ).hexdigest()
                if stored_previous != previous or event_hash != expected_hash or not hmac.compare_digest(
                    signature, expected_sig
                ):
                    return False
                previous = event_hash
            count, final_hash, head_sig = int(head[0]), head[1], head[2]
            expected_head = hmac.new(
                self._key,
                _canonical({
                    "evidence_id": evidence_id, "event_count": count,
                    "final_hash": final_hash,
                }),
                hashlib.sha256,
            ).hexdigest()
            return (
                count == len(rows)
                and final_hash == previous
                and hmac.compare_digest(head_sig, expected_head)
            )

    def purge_expired(self, *, now: float | None = None) -> int:
        stamp = time.time() if now is None else float(now)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                ids = [row[0] for row in self._db.execute(
                    "SELECT case_id FROM cases WHERE legal_hold=0 "
                    "AND retention_until>0 AND retention_until<?", (stamp,)
                )]
                for case_id in ids:
                    evidence_ids = [row[0] for row in self._db.execute(
                        "SELECT evidence_id FROM evidence WHERE case_id=?", (case_id,)
                    )]
                    for evidence_id in evidence_ids:
                        head = self._db.execute(
                            "SELECT event_count,final_hash FROM custody_heads "
                            "WHERE evidence_id=?", (evidence_id,)
                        ).fetchone()
                        if head:
                            receipt_body = {
                                "evidence_id": evidence_id,
                                "event_count": int(head[0]),
                                "final_hash": head[1],
                                "purged_at": stamp,
                            }
                            receipt_sig = hmac.new(
                                self._key, _canonical(receipt_body), hashlib.sha256
                            ).hexdigest()
                            self._db.execute(
                                "INSERT OR REPLACE INTO retention_receipts VALUES(?,?,?,?,?)",
                                (evidence_id, int(head[0]), head[1], stamp, receipt_sig),
                            )
                        self._db.execute("DELETE FROM custody WHERE evidence_id=?",
                                         (evidence_id,))
                        self._db.execute("DELETE FROM custody_heads WHERE evidence_id=?",
                                         (evidence_id,))
                    self._db.execute("DELETE FROM evidence WHERE case_id=?", (case_id,))
                    self._db.execute(
                        "DELETE FROM case_observables WHERE case_id=?", (case_id,)
                    )
                    self._db.execute("DELETE FROM timeline WHERE case_id=?", (case_id,))
                    self._db.execute("DELETE FROM cases WHERE case_id=?", (case_id,))
                self._db.execute("COMMIT")
                return len(ids)
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def verify_retention_receipt(self, evidence_id: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT event_count,final_hash,purged_at,hmac FROM retention_receipts "
                "WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
        if row is None:
            return False
        body = {
            "evidence_id": evidence_id, "event_count": int(row[0]),
            "final_hash": row[1], "purged_at": float(row[2]),
        }
        expected = hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()
        return hmac.compare_digest(row[3], expected)

    def export_sanitized(self, case_id: str) -> bytes:
        case = self.get_case(case_id)
        with self._lock:
            comments = self._db.execute(
                "SELECT kind,actor,text,ts FROM timeline WHERE case_id=? ORDER BY entry_id",
                (case_id,),
            ).fetchall()
            evidence = self._db.execute(
                "SELECT evidence_id,display_name,sha256,size,source,provenance,"
                "collected_at,privacy_class FROM evidence WHERE case_id=? "
                "ORDER BY evidence_id",
                (case_id,),
            ).fetchall()
            observable_rows = self._db.execute(
                "SELECT * FROM case_observables WHERE case_id=? "
                "ORDER BY kind,status,observable_id",
                (case_id,),
            ).fetchall()
        # Restricted references and free-form comment bodies are excluded by
        # default. The export is a minimised exchange view, never a DB mutation.
        safe_evidence = []
        for row in evidence:
            if row[7] == "restricted":
                continue
            safe_evidence.append({
                "evidence_id": row[0],
                "display_name": _redact_text(row[1], 200),
                "sha256": row[2],
                "size": row[3],
                "source": _redact_text(row[4], 300),
                "provenance": _redact_text(row[5], 1000),
                "collected_at": row[6],
                "privacy_class": row[7],
            })
        observable_counts: dict[tuple[str, str], dict[str, int | str]] = {}
        invalid_observables = 0
        for row in observable_rows:
            if not self._observable_is_valid(row):
                invalid_observables += 1
                continue
            key = (str(row[2]), str(row[4]))
            summary = observable_counts.setdefault(key, {
                "type": key[0], "status": key[1], "count": 0,
                "excluded_from_similarity_count": 0,
            })
            summary["count"] = int(summary["count"]) + 1
            if bool(row[7]):
                summary["excluded_from_similarity_count"] = (
                    int(summary["excluded_from_similarity_count"]) + 1
                )
        value = {
            "export_format": "angerona-case-sanitized-v2",
            "sanitized": True,
            "raw_evidence_included": False,
            "raw_observables_included": False,
            "privacy_manifest": {
                "policy": "default-minimized-local-export",
                "restricted_references": "excluded",
                "comment_bodies": "excluded",
                "observable_values": "excluded",
                "observable_similarity_indexes": "excluded",
                "redaction": "credentials-identities-user-paths",
            },
            "case": {
                "case_id": case.case_id, "title": _redact_text(case.title, 500),
                "status": case.status,
                "assignee": _redact_text(case.assignee, 128),
                "tags": tuple(_redact_text(tag, 80) for tag in case.tags),
                "version": case.version,
                "legal_hold": case.legal_hold,
            },
            "timeline": [
                {"kind": row[0], "actor": _redact_text(row[1], 128),
                 "text": "[COMMENT EXCLUDED]", "ts": row[3]}
                for row in comments
            ],
            "evidence_references": safe_evidence,
            "observable_summary": list(observable_counts.values()),
            "observable_integrity_failures_excluded": invalid_observables,
        }
        return _canonical(value)

    def close(self) -> None:
        with self._lock:
            self._db.close()
