"""Authenticated, non-executable notebooks and result references for fleet hunts.

The workspace deliberately stores typed queries, analyst notes, and immutable
evidence references.  It is not a code notebook and never accepts a command,
script, path, or callable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from angerona.core.atomic_io import replace_with_retry
from angerona.core.evidence_store import HuntPredicate, HuntQuery
from angerona.core.fleet_hunts import SAFE_ARTIFACTS
from angerona.core.privacy import redact_text

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KINDS = {"note", "query", "finding", "decision"}
_PRIVACY = {"system", "sensitive", "restricted"}
_FORBIDDEN_KEYS = {"command", "shell", "script", "path", "code", "executable"}
MAX_ENTRIES_PER_HUNT = 2_000
MAX_RESULTS_PER_HUNT = 10_000
MAX_WORKSPACE_BYTES = 32 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _query_dict(query: HuntQuery | None) -> dict[str, Any] | None:
    return asdict(query) if query is not None else None


def _restore_query(value: Mapping[str, Any] | None) -> HuntQuery | None:
    if value is None:
        return None
    raw = dict(value)
    predicates = tuple(HuntPredicate(**item) for item in raw.pop("predicates", ()))
    return HuntQuery(predicates=predicates, **raw)


def _validate_query(query: HuntQuery) -> None:
    encoded = _canonical(_query_dict(query))
    if len(encoded) > 64 * 1024:
        raise ValueError("typed hunt query exceeds 64 KiB")
    for predicate in query.predicates:
        if predicate.field.casefold() in _FORBIDDEN_KEYS:
            raise ValueError("executable query fields are forbidden")


@dataclass(frozen=True)
class NotebookEntry:
    entry_id: str
    hunt_id: str
    kind: str
    author: str
    created_at: float
    text: str = ""
    query: HuntQuery | None = None
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if any(not _ID.fullmatch(value) for value in (
            self.entry_id, self.hunt_id, self.author,
        )):
            raise ValueError("invalid notebook identity")
        if self.kind not in _KINDS:
            raise ValueError("invalid notebook entry kind")
        if not 0 <= len(self.text) <= 8_000:
            raise ValueError("notebook text exceeds 8000 characters")
        if not math.isfinite(float(self.created_at)) or self.created_at < 0:
            raise ValueError("invalid notebook timestamp")
        if self.kind == "query":
            if self.query is None:
                raise ValueError("query entries require a typed query")
            _validate_query(self.query)
            # Copy nested query values into a stable typed snapshot so callers
            # cannot mutate a frozen notebook entry through a list/dict alias.
            object.__setattr__(
                self, "query", _restore_query(_query_dict(self.query))
            )
        elif self.query is not None:
            raise ValueError("only query entries may contain a query")
        if len(self.evidence_ids) > 128:
            raise ValueError("notebook entry has too many evidence references")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("duplicate notebook evidence reference")
        if any(not _ID.fullmatch(value) for value in self.evidence_ids):
            raise ValueError("invalid notebook evidence reference")


@dataclass(frozen=True)
class HuntResultReference:
    result_id: str
    hunt_id: str
    artifact_id: str
    device_token: str
    evidence_id: str
    sha256: str
    size_bytes: int
    privacy_class: str
    observed_at: float
    provenance: str

    def __post_init__(self) -> None:
        if any(not _ID.fullmatch(value) for value in (
            self.result_id, self.hunt_id, self.evidence_id,
        )):
            raise ValueError("invalid hunt result identity")
        if self.artifact_id not in SAFE_ARTIFACTS:
            raise ValueError("hunt result uses an unregistered artifact")
        if not _SHA256.fullmatch(self.device_token):
            raise ValueError("device identity must be a privacy token")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("invalid hunt result digest")
        if not 0 <= int(self.size_bytes) <= SAFE_ARTIFACTS[self.artifact_id].max_item_bytes:
            raise ValueError("hunt result exceeds its artifact byte budget")
        if self.privacy_class not in _PRIVACY:
            raise ValueError("invalid hunt result privacy class")
        if not self.provenance or len(self.provenance) > 2_000:
            raise ValueError("bounded hunt result provenance is required")
        if not math.isfinite(float(self.observed_at)) or self.observed_at < 0:
            raise ValueError("invalid hunt result timestamp")


@dataclass(frozen=True)
class NotebookSnapshot:
    hunt_id: str
    revision: int
    entries: tuple[NotebookEntry, ...]
    results: tuple[HuntResultReference, ...]
    integrity_hmac: str


class HuntWorkspace:
    """Durable optimistic-concurrency workspace authenticated with HMAC."""

    def __init__(self, path: Path, audit_key: bytes) -> None:
        if len(audit_key) < 32:
            raise ValueError("hunt workspace key must contain at least 32 bytes")
        self._path = Path(path)
        self._key = bytes(audit_key)
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}
        self._load()

    def append_entry(
        self, entry: NotebookEntry, *, expected_revision: int,
    ) -> int:
        with self._lock:
            record = self._record(entry.hunt_id)
            self._check_revision(record, expected_revision)
            entries: list[NotebookEntry] = record["entries"]
            existing = next(
                (item for item in entries if item.entry_id == entry.entry_id), None
            )
            if existing is not None:
                if existing != entry:
                    raise ValueError("notebook entry ID conflicts with another entry")
                return int(record["revision"])
            if len(entries) >= MAX_ENTRIES_PER_HUNT:
                raise ValueError("notebook entry limit reached")
            entries.append(entry)
            record["revision"] += 1
            self._save()
            return int(record["revision"])

    def add_result(
        self, result: HuntResultReference, *, expected_revision: int,
    ) -> int:
        with self._lock:
            record = self._record(result.hunt_id)
            self._check_revision(record, expected_revision)
            results: list[HuntResultReference] = record["results"]
            existing = next(
                (item for item in results if item.result_id == result.result_id), None
            )
            if existing is not None:
                if existing != result:
                    raise ValueError("hunt result ID conflicts with another result")
                return int(record["revision"])
            if len(results) >= MAX_RESULTS_PER_HUNT:
                raise ValueError("hunt result limit reached")
            results.append(result)
            record["revision"] += 1
            self._save()
            return int(record["revision"])

    def snapshot(self, hunt_id: str) -> NotebookSnapshot:
        with self._lock:
            record = self._record(hunt_id)
            core = self._snapshot_core(hunt_id, record)
            return NotebookSnapshot(
                hunt_id=hunt_id,
                revision=int(record["revision"]),
                entries=tuple(record["entries"]),
                results=tuple(record["results"]),
                integrity_hmac=hmac.new(
                    self._key, _canonical(core), hashlib.sha256
                ).hexdigest(),
            )

    def verify_snapshot(self, snapshot: NotebookSnapshot) -> bool:
        core = {
            "hunt_id": snapshot.hunt_id,
            "revision": snapshot.revision,
            "entries": [self._entry_dict(item) for item in snapshot.entries],
            "results": [asdict(item) for item in snapshot.results],
        }
        return hmac.compare_digest(
            snapshot.integrity_hmac,
            hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest(),
        )

    def export_sanitized(self, hunt_id: str) -> bytes:
        """Return a minimized exchange view with no raw artifacts or commands."""
        snapshot = self.snapshot(hunt_id)
        entries = []
        for entry in snapshot.entries:
            query = _query_dict(entry.query)
            if query is not None:
                for predicate in query["predicates"]:
                    if "value" in predicate:
                        predicate["value"] = redact_text(
                            predicate["value"], limit=256
                        )
            entries.append({
                "entry_id": entry.entry_id,
                "kind": entry.kind,
                "author": redact_text(entry.author, limit=128),
                "created_at": entry.created_at,
                "text": redact_text(entry.text, limit=2_000),
                "query": query,
                "evidence_ids": entry.evidence_ids,
            })
        results = [
            {
                "result_id": item.result_id,
                "artifact_id": item.artifact_id,
                "evidence_id": item.evidence_id,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
                "privacy_class": item.privacy_class,
                "observed_at": item.observed_at,
                "provenance": redact_text(item.provenance, limit=500),
            }
            for item in snapshot.results if item.privacy_class != "restricted"
        ]
        value = {
            "format": "angerona-hunt-notebook-sanitized-v1",
            "sanitized": True,
            "raw_artifacts_included": False,
            "device_identifiers_included": False,
            "restricted_results": "excluded",
            "hunt_id": hunt_id,
            "revision": snapshot.revision,
            "entries": entries,
            "result_references": results,
            "source_snapshot_hmac": snapshot.integrity_hmac,
        }
        return _canonical(value)

    def _record(self, hunt_id: str) -> dict[str, Any]:
        if not _ID.fullmatch(hunt_id):
            raise ValueError("invalid hunt identity")
        return self._records.setdefault(
            hunt_id, {"revision": 0, "entries": [], "results": []},
        )

    @staticmethod
    def _check_revision(record: Mapping[str, Any], expected: int) -> None:
        if int(expected) != int(record["revision"]):
            raise ValueError("hunt workspace revision conflict")

    @staticmethod
    def _entry_dict(entry: NotebookEntry) -> dict[str, Any]:
        value = asdict(entry)
        value["query"] = _query_dict(entry.query)
        return value

    def _snapshot_core(
        self, hunt_id: str, record: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "hunt_id": hunt_id,
            "revision": int(record["revision"]),
            "entries": [self._entry_dict(item) for item in record["entries"]],
            "results": [asdict(item) for item in record["results"]],
        }

    def _serialize_records(self) -> dict[str, Any]:
        return {
            hunt_id: self._snapshot_core(hunt_id, record)
            for hunt_id, record in sorted(self._records.items())
        }

    def _save(self) -> None:
        records = self._serialize_records()
        signature = hmac.new(
            self._key, _canonical(records), hashlib.sha256
        ).hexdigest()
        encoded = _canonical({
            "schema_version": 1, "records": records, "hmac": signature,
        })
        if len(encoded) > MAX_WORKSPACE_BYTES:
            raise ValueError("hunt workspace exceeds its storage budget")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(
            self._path.suffix + f".{os.getpid()}.tmp"
        )
        try:
            with open(temporary, "xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temporary, self._path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _load(self) -> None:
        if not self._path.exists():
            return
        if self._path.stat().st_size > MAX_WORKSPACE_BYTES:
            raise ValueError("hunt workspace exceeds its storage budget")
        value = json.loads(self._path.read_text(encoding="utf-8"))
        records = value.get("records")
        if value.get("schema_version") != 1 or not isinstance(records, dict):
            raise ValueError("hunt workspace is invalid")
        expected = hmac.new(
            self._key, _canonical(records), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(str(value.get("hmac", "")), expected):
            raise ValueError("hunt workspace authentication failed")
        for hunt_id, raw in records.items():
            if raw.get("hunt_id") != hunt_id or not _ID.fullmatch(hunt_id):
                raise ValueError("hunt workspace identity is invalid")
            entries = []
            for item in raw.get("entries", ()):
                item = dict(item)
                item["query"] = _restore_query(item.get("query"))
                item["evidence_ids"] = tuple(item.get("evidence_ids", ()))
                entries.append(NotebookEntry(**item))
            results = [
                HuntResultReference(**item) for item in raw.get("results", ())
            ]
            revision = int(raw.get("revision", -1))
            if revision < 0 or revision != len(entries) + len(results):
                raise ValueError("hunt workspace revision is invalid")
            self._records[hunt_id] = {
                "revision": revision, "entries": entries, "results": results,
            }
