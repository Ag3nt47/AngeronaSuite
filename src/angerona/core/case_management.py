"""Durable local incident cases and authenticated evidence custody metadata."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Sequence

MAX_TAGS = 32
MAX_TIMELINE = 5000
MAX_EVIDENCE = 2000
MAX_TEXT = 8000
_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
_PRIVACY = {"public", "system", "sensitive", "restricted"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(?i)\b[A-Z]:\\(?:Users|Documents and Settings)\\[^\\\s]+(?:\\[^\s,;]+)*"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b"),
)


class CaseConflict(RuntimeError):
    pass


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


class CaseStore:
    def __init__(self, path: Path, custody_key: bytes) -> None:
        if len(custody_key) < 32:
            raise ValueError("custody key must be at least 32 bytes")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = bytes(custody_key)
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
        CREATE INDEX IF NOT EXISTS idx_case_timeline ON timeline(case_id, entry_id);
        CREATE INDEX IF NOT EXISTS idx_case_evidence ON evidence(case_id);
        """)

    def _transaction(self):
        return self._db

    def create_case(
        self, title: str, *, assignee: str = "", tags: Sequence[str] = (),
        retention_until: float = 0, now: float | None = None,
    ) -> CaseRecord:
        tags = tuple(sorted({_safe_text(tag, 80) for tag in tags if tag}))
        if len(tags) > MAX_TAGS:
            raise ValueError("too many tags")
        stamp = time.time() if now is None else float(now)
        case_id = "case-" + uuid.uuid4().hex
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
        comments = self._db.execute(
            "SELECT kind,actor,text,ts FROM timeline WHERE case_id=? ORDER BY entry_id",
            (case_id,),
        ).fetchall()
        evidence = self._db.execute(
            "SELECT evidence_id,display_name,sha256,size,source,provenance,"
            "collected_at,privacy_class FROM evidence WHERE case_id=? ORDER BY evidence_id",
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
        value = {
            "export_format": "angerona-case-sanitized-v1",
            "sanitized": True,
            "raw_evidence_included": False,
            "privacy_manifest": {
                "policy": "default-minimized-local-export",
                "restricted_references": "excluded",
                "comment_bodies": "excluded",
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
        }
        return _canonical(value)

    def close(self) -> None:
        with self._lock:
            self._db.close()
