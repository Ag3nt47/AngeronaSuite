"""Ephemeral provenance for Angerona's own inert security exercises.

Practice artifacts intentionally look suspicious.  Their *names and contents*
must never be used as an allowlist, though: malware can copy either.  This
module records exact file identities, process tokens, and run identifiers generated
by an in-process drill immediately before/after creation.  Consumers may then
label matching evidence as practice without weakening the evidence severity.

The registry is deliberately memory-only, TTL-bounded, size-bounded and
thread-safe.  A lookalike artifact that was not registered by the running drill
remains ordinary hostile evidence.
"""
from __future__ import annotations

import os
import hashlib
import stat
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
_ARTIFACT_HASH_MAX = 16 * 1024 * 1024


@dataclass(frozen=True)
class PracticeProvenance:
    run_id: str
    kind: str
    expires_at: float
    pid: int | None = None
    file_identity: tuple[int, int, int] | None = None
    content_sha256: str = ""


_lock = threading.RLock()
_runs: dict[str, PracticeProvenance] = {}
_artifacts: dict[str, PracticeProvenance] = {}
_artifact_original_keys: dict[str, str] = {}
_artifact_candidate_keys: set[str] = set()
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


def _lexical_path_key(value: object) -> str:
    """Normalize a candidate spelling without inspecting the filesystem.

    This is only a rejection filter.  A matching spelling still needs a fresh
    resolution before it can establish provenance, since a junction/symlink
    may have changed since registration.
    """
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or "\x00" in raw or len(raw) > 4096:
            return ""
        expanded = os.path.expandvars(os.path.expanduser(raw))
        return os.path.normcase(os.path.abspath(expanded))
    except (TypeError, OSError, RuntimeError, ValueError):
        return ""


def _file_identity(info: os.stat_result) -> tuple[int, int, int] | None:
    """A stable file ID; names, bytes, and mutable timestamps grant no trust."""
    if (
        not stat.S_ISREG(info.st_mode)
        or int(getattr(info, "st_nlink", 0)) != 1
        or int(getattr(info, "st_ino", 0)) <= 0
        or int(getattr(info, "st_file_attributes", 0)) & 0x400
    ):
        return None
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(getattr(info, "st_birthtime_ns", 0) or 0),
    )


def _artifact_identity(path: object, descriptor: int | None = None) -> tuple[int, int, int] | None:
    """Compare the named leaf with a held ordinary file, without following links."""
    opened: int | None = None
    try:
        leaf = Path(os.fspath(path))
        before = _file_identity(leaf.stat(follow_symlinks=False))
        if before is None:
            return None
        if descriptor is None:
            opened = os.open(
                leaf,
                os.O_RDONLY | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            descriptor = opened
        held = _file_identity(os.fstat(descriptor))
        after = _file_identity(leaf.stat(follow_symlinks=False))
        return before if before == held == after else None
    except (OSError, TypeError, ValueError, RuntimeError):
        return None
    finally:
        if opened is not None:
            os.close(opened)


def _artifact_digest(
    path: object, identity: tuple[int, int, int], descriptor: int | None,
) -> str:
    """Hash a bounded completed file while its created identity still owns the name."""
    opened: int | None = None
    saved_offset: int | None = None
    try:
        if descriptor is None:
            opened = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            reader = opened
        else:
            reader = descriptor
            saved_offset = os.lseek(reader, 0, os.SEEK_CUR)
            os.lseek(reader, 0, os.SEEK_SET)
        before = os.fstat(reader)
        if (
            _file_identity(before) != identity
            or before.st_size < 0
            or before.st_size > _ARTIFACT_HASH_MAX
        ):
            return ""
        digest = hashlib.sha256()
        remaining = _ARTIFACT_HASH_MAX
        while True:
            chunk = os.read(reader, min(65536, remaining + 1))
            if not chunk:
                break
            remaining -= len(chunk)
            if remaining < 0:
                return ""
            digest.update(chunk)
        after = os.fstat(reader)
        if (
            _file_identity(after) != identity
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or _artifact_identity(path, descriptor) != identity
        ):
            return ""
        return digest.hexdigest()
    except (OSError, TypeError, ValueError, RuntimeError):
        return ""
    finally:
        if saved_offset is not None and descriptor is not None:
            os.lseek(descriptor, saved_offset, os.SEEK_SET)
        if opened is not None:
            os.close(opened)


def _rebuild_artifact_candidates_locked() -> None:
    # Retain at most the original spelling and canonical path for each live
    # registration.  Unregistered aliases deliberately fail closed.
    for key in tuple(_artifact_original_keys):
        if key not in _artifacts:
            _artifact_original_keys.pop(key, None)
    _artifact_candidate_keys.clear()
    _artifact_candidate_keys.update(_artifacts)
    _artifact_candidate_keys.update(_artifact_original_keys.values())


def _prune_locked(now: float) -> None:
    for table in (_runs, _artifacts, _process_tokens):
        expired = [key for key, value in table.items() if value.expires_at <= now]
        for key in expired:
            table.pop(key, None)
        if table is _artifacts and expired:
            _rebuild_artifact_candidates_locked()


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
                      ttl: float = _DEFAULT_TTL_S,
                      descriptor: int | None = None) -> str:
    """Register only an existing ordinary file bound to its held file ID."""
    identity = _artifact_identity(path, descriptor)
    if identity is None:
        return ""
    digest = _artifact_digest(path, identity, descriptor)
    if not digest:
        return ""
    key = _path_key(path)
    if not key or _artifact_identity(path, descriptor) != identity:
        return ""
    rid = register_run(run_id, kind=kind, ttl=ttl)
    if not rid:
        return ""
    now = time.monotonic()
    record = PracticeProvenance(rid, _safe_id(kind) or "practice",
                                now + max(1.0, float(ttl)),
                                file_identity=identity,
                                content_sha256=digest)
    with _lock:
        _prune_locked(now)
        _bounded_put(_artifacts, key, record, _MAX_ARTIFACTS)
        _artifact_original_keys[key] = _lexical_path_key(path)
        _rebuild_artifact_candidates_locked()
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
        _rebuild_artifact_candidates_locked()
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
        _rebuild_artifact_candidates_locked()
    return removed


def _observed_file_proof(
    details: dict,
) -> tuple[tuple[int, int, int], str] | None:
    raw = details.get("observed_file_identity")
    digest = details.get("observed_content_sha256")
    if not isinstance(raw, dict) or not isinstance(digest, str):
        return None
    device, inode = raw.get("device"), raw.get("inode")
    birth = raw.get("birthtime_ns", 0)
    if (
        type(device) is not int or type(inode) is not int
        or type(birth) is not int or inode <= 0 or birth < 0
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        return None
    return (device, inode, birth), digest


def _registered_artifact(
    value: object, observed: tuple[int, int, int], digest: str,
) -> tuple[str, PracticeProvenance] | None:
    candidate = _lexical_path_key(value)
    with _lock:
        if not candidate or candidate not in _artifact_candidate_keys:
            return None

    # Filesystem calls can block on a detached device or network path.  Most
    # events never reach this point; do not hold the registry lock for those
    # that require an actual registered-path check.
    key = _path_key(value)
    with _lock:
        record = _artifacts.get(key) if key else None
    if record is None or record.expires_at <= time.monotonic():
        return None
    enrolled = record.file_identity
    if (
        enrolled is None
        or enrolled[:2] != observed[:2]
        or (observed[2] and enrolled[2] != observed[2])
        or record.content_sha256 != digest
    ):
        return None
    # Classify the object the detector observed, even if response has since
    # quarantined it. Reopening the current pathname cannot establish the
    # identity of an earlier observation and adds blocking filesystem work.
    with _lock:
        if (
            _artifacts.get(key) is record
            and record.expires_at > time.monotonic()
        ):
            return key, record
    return None


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
        if not (_runs or _artifacts or _process_tokens):
            return None
        has_artifacts = bool(_artifacts)

    path_values = [
        details[field]
        for field in ("artifact_path", "path", "file_path")
        if details.get(field)
    ]
    resources = details.get("artifact_paths")
    if resources is not None:
        if not isinstance(resources, (list, tuple)):
            return None
        path_values.extend(resources)
    if path_values:
        # Every stated file resource must be bound to this same live run. A
        # registered artifact beside a real file cannot suppress that file.
        proof = _observed_file_proof(details)
        if not has_artifacts or len(path_values) > 68 or proof is None:
            return None
        records = []
        for value in path_values:
            match = _registered_artifact(value, *proof)
            if match is None:
                return None
            records.append(match)
        if len({record.run_id for _, record in records}) != 1:
            return None
        with _lock:
            now = time.monotonic()
            if all(
                _artifacts.get(key) is record and record.expires_at > now
                for key, record in records
            ):
                return records[0][1]
        return None

    with _lock:
        _prune_locked(time.monotonic())
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
        _artifact_original_keys.clear()
        _artifact_candidate_keys.clear()
        _process_tokens.clear()
