"""Ephemeral provenance for Angerona's own inert security exercises.

Practice artifacts intentionally look suspicious.  Their *names and contents*
must never be used as an allowlist, though: malware can copy either.  This
module records the exact paths, process tokens, and run identifiers generated
by an in-process drill immediately before/after creation.  Consumers may then
label matching evidence as practice without weakening the evidence severity.

The registry is deliberately memory-only, TTL-bounded, size-bounded and
thread-safe.  A lookalike artifact that was not registered by the running drill
remains ordinary hostile evidence.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path


_DEFAULT_TTL_S = 2 * 60 * 60.0
_MAX_RUNS = 128
_MAX_ARTIFACTS = 4096
_MAX_PROCESSES = 1024
_ID_MAX = 160
_TOKEN_MAX = 256


@dataclass(frozen=True)
class PracticeProvenance:
    run_id: str
    kind: str
    expires_at: float
    pid: int | None = None


_lock = threading.RLock()
_runs: dict[str, PracticeProvenance] = {}
_artifacts: dict[str, PracticeProvenance] = {}
_process_tokens: dict[str, PracticeProvenance] = {}


def _safe_id(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > _ID_MAX or any(ord(ch) < 32 for ch in text):
        return ""
    return text


def _safe_token(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > _TOKEN_MAX or any(ch.isspace() for ch in text):
        return ""
    return text


def _path_key(value: object) -> str:
    try:
        raw = os.fspath(value)
    except TypeError:
        return ""
    if not raw or "\x00" in raw or len(raw) > 4096:
        return ""
    try:
        path = Path(os.path.expandvars(os.path.expanduser(raw))).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return ""
    return os.path.normcase(str(path))


def _prune_locked(now: float) -> None:
    for table in (_runs, _artifacts, _process_tokens):
        expired = [key for key, value in table.items() if value.expires_at <= now]
        for key in expired:
            table.pop(key, None)


def _bounded_put(table: dict, key: str, value: PracticeProvenance,
                 maximum: int) -> None:
    if key not in table and len(table) >= maximum:
        oldest = min(table, key=lambda item: table[item].expires_at)
        table.pop(oldest, None)
    table[key] = value


def register_run(run_id: object, *, kind: str = "practice",
                 ttl: float = _DEFAULT_TTL_S) -> str:
    """Register one exact drill/verification run identifier."""
    rid = _safe_id(run_id)
    if not rid:
        return ""
    now = time.monotonic()
    record = PracticeProvenance(rid, _safe_id(kind) or "practice",
                                now + max(1.0, float(ttl)))
    with _lock:
        _prune_locked(now)
        _bounded_put(_runs, rid, record, _MAX_RUNS)
    return rid


def register_artifact(path: object, run_id: object, *, kind: str = "practice",
                      ttl: float = _DEFAULT_TTL_S) -> str:
    """Register exactly one path created by an already-authorized practice run."""
    key = _path_key(path)
    rid = register_run(run_id, kind=kind, ttl=ttl)
    if not key or not rid:
        return ""
    now = time.monotonic()
    record = PracticeProvenance(rid, _safe_id(kind) or "practice",
                                now + max(1.0, float(ttl)))
    with _lock:
        _prune_locked(now)
        _bounded_put(_artifacts, key, record, _MAX_ARTIFACTS)
    return key


def register_process(token: object, run_id: object, *, pid: int | None = None,
                     kind: str = "practice",
                     ttl: float = _DEFAULT_TTL_S) -> str:
    """Register one high-entropy command-line token and optional spawned PID."""
    value = _safe_token(token)
    rid = register_run(run_id, kind=kind, ttl=ttl)
    if not value or not rid:
        return ""
    try:
        process_id = int(pid) if pid is not None else None
    except (TypeError, ValueError):
        process_id = None
    if process_id is not None and process_id <= 0:
        process_id = None
    now = time.monotonic()
    record = PracticeProvenance(rid, _safe_id(kind) or "practice",
                                now + max(1.0, float(ttl)), process_id)
    with _lock:
        _prune_locked(now)
        _bounded_put(_process_tokens, value, record, _MAX_PROCESSES)
    return value


def unregister_artifact(path: object, *, run_id: object = "") -> bool:
    """Revoke one exact artifact registration, optionally bound to its run."""
    key = _path_key(path)
    expected = _safe_id(run_id)
    if not key:
        return False
    with _lock:
        record = _artifacts.get(key)
        if record is None or (expected and record.run_id != expected):
            return False
        _artifacts.pop(key, None)
        return True


def unregister_process(token: object, *, run_id: object = "") -> bool:
    """Revoke one exact process-token registration, optionally run-bound."""
    value = _safe_token(token)
    expected = _safe_id(run_id)
    if not value:
        return False
    with _lock:
        record = _process_tokens.get(value)
        if record is None or (expected and record.run_id != expected):
            return False
        _process_tokens.pop(value, None)
        return True


def unregister_run(run_id: object) -> int:
    """Revoke a completed practice run and every exact child registration.

    Cleanup should call this after its evidence snapshot has been generated.
    A deleted marker must not remain trusted for the registry's full TTL if an
    attacker later recreates the same suspicious-looking path.
    """
    rid = _safe_id(run_id)
    if not rid:
        return 0
    removed = 0
    with _lock:
        if _runs.pop(rid, None) is not None:
            removed += 1
        for table in (_artifacts, _process_tokens):
            keys = [key for key, record in table.items() if record.run_id == rid]
            for key in keys:
                table.pop(key, None)
                removed += 1
    return removed


def provenance_for_event(event: object) -> PracticeProvenance | None:
    """Return live provenance only for an exact registered event attribute.

    Event messages and filenames are intentionally never parsed.  Detector
    modules must expose paths/tokens as structured details for a match.
    """
    details = getattr(event, "details", None)
    if not isinstance(details, dict):
        return None
    now = time.monotonic()
    with _lock:
        _prune_locked(now)
        for field in ("artifact_path", "path", "file_path"):
            key = _path_key(details.get(field))
            record = _artifacts.get(key) if key else None
            if record is not None:
                return record

        # Multi-resource detections are practice only when every local artifact
        # is registered to the same live run.  A mixed real+practice Defender
        # alert must remain active.
        values = details.get("artifact_paths")
        if isinstance(values, (list, tuple)) and values:
            records = []
            for value in values[:65]:
                key = _path_key(value)
                record = _artifacts.get(key) if key else None
                if record is None:
                    records = []
                    break
                records.append(record)
            if (
                records
                and len(records) == len(values)
                and len({record.run_id for record in records}) == 1
            ):
                return records[0]

        token = _safe_token(details.get("correlation_token"))
        if token:
            record = _process_tokens.get(token)
            if record is not None:
                pid = details.get("pid")
                if record.pid is None or pid is None:
                    return record
                try:
                    if int(pid) == record.pid:
                        return record
                except (TypeError, ValueError):
                    pass

        command = str(details.get("cmdline") or details.get("command_line") or "")
        if command and len(command) <= 32768:
            for registered, record in _process_tokens.items():
                if registered in command:
                    pid = details.get("pid")
                    if record.pid is None or pid is None:
                        return record
                    try:
                        if int(pid) == record.pid:
                            return record
                    except (TypeError, ValueError):
                        continue

        for field in (
            "practice_run_id",
            "drill_run_id",
            "practice_verification_id",
            "run_id",
        ):
            rid = _safe_id(details.get(field))
            record = _runs.get(rid) if rid else None
            if record is not None:
                return record
    return None


def is_practice_event(event: object) -> bool:
    return provenance_for_event(event) is not None


def clear() -> None:
    """Clear all ephemeral provenance (primarily for process shutdown/tests)."""
    with _lock:
        _runs.clear()
        _artifacts.clear()
        _process_tokens.clear()
