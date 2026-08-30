"""Persistent, exact-match trusted-process policy.

The policy is deliberately operator-supervised.  Angerona can discover running
executables, but it never silently teaches itself that an observed process is
safe: malware present during a baseline window must not become trusted merely
because it stayed resident for a while.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Iterable

_LOCK = threading.RLock()
_CACHE: dict[str, tuple[int, list[dict]]] = {}
_DEFAULT_DATA_DIR: Path | None = None
_HASH_CACHE: OrderedDict[
    str,
    tuple[tuple[int, int, int, int, int], float, str],
] = OrderedDict()
_HASH_CACHE_TTL_SECONDS = 2.0
_HASH_CACHE_MAX = 256
_MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
_MAX_POLICY_BYTES = 2 * 1024 * 1024
_MAX_POLICY_ENTRIES = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENTRY_FIELDS = frozenset(
    {"id", "name", "path", "sha256", "publisher", "source", "added_at"}
)

# Immutable normalized rows are safe to reuse for a complete evaluation batch.
# Each item is ``(case-folded basename, normalized exact path, SHA-256)``.
# A blank digest is a legacy path-only approval and remains visible so the
# operator can re-approve it without silently changing existing policy.
PolicySnapshot = tuple[tuple[str, str, str], ...]


def _data_dir(data_dir=None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    global _DEFAULT_DATA_DIR
    with _LOCK:
        if _DEFAULT_DATA_DIR is None:
            try:
                from angerona.core.config import Config
                _DEFAULT_DATA_DIR = Path(Config.load().data_dir)
            except Exception:
                from angerona.core.data_paths import data_dir as canonical_data_dir
                _DEFAULT_DATA_DIR = canonical_data_dir()
        return _DEFAULT_DATA_DIR


def policy_path(data_dir=None) -> Path:
    return _data_dir(data_dir) / "shared_logs" / "process_allowlist.json"


def _normal_path(value: str) -> str:
    value = os.path.expandvars(os.path.expanduser(str(value or "").strip().strip('"')))
    return os.path.normcase(os.path.normpath(value)) if value else ""


def _normal_name(value: str) -> str:
    return Path(str(value or "").strip().strip('"')).name.casefold()


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        return path.is_symlink() or bool(
            attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except OSError:
        return True


def _hash_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(getattr(info, "st_ctime_ns", 0)),
    )


def executable_sha256(path: str | os.PathLike) -> str:
    """Hash one ordinary executable without following a reparse-point file.

    The cache is deliberately short lived and keyed by file identity, size,
    modification time, and change time. Hashing occurs only after an exact path
    matches a trusted entry, so ordinary untrusted process scans pay no digest
    cost.
    """
    candidate = Path(path)
    try:
        before = candidate.stat()
        if (
            not candidate.is_file()
            or _is_reparse(candidate)
            or not 0 < before.st_size <= _MAX_EXECUTABLE_BYTES
        ):
            raise ValueError("trusted executable must be an ordinary bounded file")
    except OSError as exc:
        raise ValueError("trusted executable is unavailable") from exc
    identity = _hash_identity(before)
    key = _normal_path(str(candidate))
    now = time.monotonic()
    with _LOCK:
        cached = _HASH_CACHE.get(key)
        if (
            cached is not None
            and cached[0] == identity
            and now - cached[1] <= _HASH_CACHE_TTL_SECONDS
        ):
            _HASH_CACHE.move_to_end(key)
            return cached[2]

    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    try:
        after = candidate.stat()
    except OSError as exc:
        raise ValueError("trusted executable changed during verification") from exc
    if _hash_identity(after) != identity:
        raise ValueError("trusted executable changed during verification")
    value = digest.hexdigest()
    with _LOCK:
        _HASH_CACHE[key] = (identity, now, value)
        _HASH_CACHE.move_to_end(key)
        while len(_HASH_CACHE) > _HASH_CACHE_MAX:
            _HASH_CACHE.popitem(last=False)
    return value


def _load(data_dir=None) -> list[dict]:
    path = policy_path(data_dir)
    key = str(path)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = -1
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] == stamp:
            return [dict(x) for x in cached[1]]
        try:
            if (
                path.stat().st_size > _MAX_POLICY_BYTES
                or _is_reparse(path)
                or _is_reparse(path.parent)
            ):
                raise ValueError("trusted-process policy path is unsafe")
            raw = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(raw, dict)
                or set(raw) != {"version", "updated_at", "entries"}
                or raw.get("version") not in (1, 2)
                or isinstance(raw.get("updated_at"), bool)
                or not isinstance(raw.get("updated_at"), (int, float))
                or not math.isfinite(float(raw["updated_at"]))
                or not isinstance(raw.get("entries"), list)
                or len(raw["entries"]) > _MAX_POLICY_ENTRIES
            ):
                raise ValueError("trusted-process policy schema is invalid")
            rows = []
            for item in raw["entries"]:
                if not isinstance(item, dict) or not set(item) <= _ENTRY_FIELDS:
                    raise ValueError("trusted-process entry schema is invalid")
                entry_id = str(item.get("id", ""))
                name = str(item.get("name", ""))
                entry_path = str(item.get("path", ""))
                digest = str(item.get("sha256", "")).casefold()
                publisher = str(item.get("publisher", ""))
                source = str(item.get("source", "legacy")).casefold()
                added_at = item.get("added_at", 0.0)
                if (
                    len(entry_id) != 32
                    or any(ch not in "0123456789abcdef" for ch in entry_id)
                    or not name
                    or len(name) > 260
                    or len(entry_path) > 1024
                    or "\x00" in name + entry_path + publisher
                    or any(ch in name + entry_path for ch in "*?")
                    or (digest and not _SHA256.fullmatch(digest))
                    or len(publisher) > 512
                    or source not in {
                        "legacy",
                        "manual",
                        "baseline",
                        "console",
                        "resolve",
                    }
                    or isinstance(added_at, bool)
                    or not isinstance(added_at, (int, float))
                    or not math.isfinite(float(added_at))
                    or float(added_at) < 0
                ):
                    raise ValueError("trusted-process entry is invalid")
                rows.append(
                    {
                        "id": entry_id,
                        "name": name,
                        "path": entry_path,
                        "sha256": digest,
                        "publisher": publisher,
                        "source": source,
                        "added_at": float(added_at),
                    }
                )
        except Exception:
            rows = []
        _CACHE[key] = (stamp, rows)
        return [dict(x) for x in rows]


def _write(rows: Iterable[dict], data_dir=None) -> None:
    path = policy_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    if _is_reparse(path.parent) or (path.exists() and _is_reparse(path)):
        raise ValueError("trusted-process policy path is unsafe")
    items = list(rows)
    if len(items) > _MAX_POLICY_ENTRIES:
        raise ValueError("trusted-process policy exceeds its entry bound")
    payload = {"version": 2, "updated_at": time.time(), "entries": items}
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    if len(encoded) > _MAX_POLICY_BYTES:
        raise ValueError("trusted-process policy exceeds its size bound")
    tmp = path.with_name(path.name + f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        from angerona.core.atomic_io import replace_with_retry

        replace_with_retry(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    with _LOCK:
        _CACHE.pop(str(path), None)


def entries(data_dir=None) -> list[dict]:
    return _load(data_dir)


def policy_snapshot(data_dir=None) -> PolicySnapshot:
    """Return one reusable, immutable view of the current trusted policy.

    Batch consumers should call this once, then pass it to :func:`is_allowed`
    or :func:`is_event_allowed`; this avoids a policy-path stat and row cloning
    for every process/event while retaining the existing mtime invalidation at
    the start of each batch.
    """
    return tuple(
        (
            _normal_name(row.get("name", "")),
            _normal_path(row.get("path", "")),
            str(row.get("sha256", "")).casefold(),
        )
        for row in _load(data_dir)
    )


def add(
    name: str = "",
    path: str = "",
    data_dir=None,
    *,
    sha256: str = "",
    publisher: str = "",
    source: str = "manual",
) -> dict:
    """Trust an exact executable path, or add a non-path basename hint.

    Basename-only entries are intentionally useful only when an event genuinely
    has no executable path.  A path-rich event must match an exact approved
    path, so a renamed executable in another directory cannot inherit trust.
    Existing local files are also bound to their current SHA-256; replacing the
    file at an approved path invalidates trust until explicit re-approval.
    """
    clean_path = str(path or "").strip().strip('"')
    clean_name = Path(clean_path).name if clean_path else Path(str(name or "").strip()).name
    if not clean_name:
        raise ValueError("Enter a process name or select an executable.")
    if (
        len(clean_name) > 260
        or len(clean_path) > 1024
        or "\x00" in clean_name + clean_path
    ):
        raise ValueError("Process names and paths must be bounded ordinary text.")
    if any(ch in clean_name + clean_path for ch in "*?"):
        raise ValueError("Wildcards are not allowed; trust an exact process name or path.")
    expected = str(sha256 or "").strip().casefold()
    if expected and not _SHA256.fullmatch(expected):
        raise ValueError("Executable SHA-256 must contain exactly 64 hexadecimal characters.")
    clean_publisher = str(publisher or "").strip()
    if len(clean_publisher) > 512 or "\x00" in clean_publisher:
        raise ValueError("Executable publisher metadata is invalid.")
    clean_source = str(source or "manual").strip().casefold()
    if clean_source not in {"manual", "baseline", "console", "resolve"}:
        raise ValueError("Trusted-process source is invalid.")

    actual = ""
    if clean_path:
        candidate = Path(clean_path)
        if candidate.exists():
            actual = executable_sha256(candidate)
        elif expected:
            raise ValueError("The baseline executable is no longer available.")
    if expected and actual != expected:
        raise ValueError("The executable changed after it was observed; review it again.")
    bound_digest = actual or expected

    rows = _load(data_dir)
    norm_path = _normal_path(clean_path)
    norm_name = _normal_name(clean_name)
    for row in rows:
        if _normal_name(row.get("name", "")) == norm_name and _normal_path(row.get("path", "")) == norm_path:
            # Re-approving an existing exact path upgrades legacy path-only
            # policy or accepts a deliberate publisher/version change.
            changed = False
            for key, value in (
                ("sha256", bound_digest),
                ("publisher", clean_publisher),
                ("source", clean_source),
            ):
                if value and row.get(key) != value:
                    row[key] = value
                    changed = True
            if changed:
                row["added_at"] = time.time()
                _write(rows, data_dir)
            return row
    row = {
        "id": uuid.uuid4().hex,
        "name": clean_name,
        "path": clean_path,
        "sha256": bound_digest,
        "publisher": clean_publisher,
        "source": clean_source,
        "added_at": time.time(),
    }
    rows.append(row)
    _write(rows, data_dir)
    return row


def remove(entry_id: str, data_dir=None) -> bool:
    rows = _load(data_dir)
    kept = [row for row in rows if str(row.get("id", "")) != str(entry_id)]
    if len(kept) == len(rows):
        return False
    _write(kept, data_dir)
    return True


def is_allowed(name: str = "", path: str = "", data_dir=None,
               policy: PolicySnapshot | None = None) -> bool:
    norm_name = _normal_name(name or path)
    norm_path = _normal_path(path)
    if not norm_name and not norm_path:
        return False
    rows = policy_snapshot(data_dir) if policy is None else policy
    for row in rows:
        # Accept historical two-field snapshots supplied by old in-process
        # consumers during an upgrade; new snapshots always carry the digest.
        row_name, row_path = row[0], row[1]
        row_digest = row[2] if len(row) >= 3 else ""
        if row_path:
            if norm_path and norm_path == row_path:
                if row_digest:
                    try:
                        return executable_sha256(path) == row_digest
                    except (OSError, ValueError):
                        return False
                return True
        # A basename-only row is a fallback for pathless telemetry, never a
        # wildcard over an observed path.  Exact-path entries (including the
        # Proton defaults) retain their existing behavior.
        elif not norm_path and norm_name and norm_name == row_name:
            return True
    return False


def is_digest_pinned_allowed(
    name: str = "",
    path: str = "",
    data_dir=None,
    policy: PolicySnapshot | None = None,
) -> bool:
    """Require an exact path whose approved row carries a matching digest.

    This stricter predicate is for privileged/local-service boundaries where a
    legacy path-only approval or basename hint is insufficient. It never
    upgrades observed software automatically.
    """
    norm_name = _normal_name(name or path)
    norm_path = _normal_path(path)
    if not norm_name or not norm_path:
        return False
    rows = policy_snapshot(data_dir) if policy is None else policy
    for row in rows:
        row_name, row_path = row[0], row[1]
        row_digest = row[2] if len(row) >= 3 else ""
        if (
            row_name == norm_name
            and row_path == norm_path
            and _SHA256.fullmatch(row_digest)
        ):
            try:
                return hmac.compare_digest(executable_sha256(path), row_digest)
            except (OSError, ValueError):
                return False
    return False


def event_process(event) -> tuple[str, str]:
    details = getattr(event, "details", None) or {}
    name = (
        details.get("proc_name")
        or details.get("process_name")
        or details.get("name")
        or ""
    )
    path = (details.get("exe") or details.get("process_path")
            or details.get("image") or "")
    return str(name), str(path)


def is_event_allowed(event, data_dir=None,
                     policy: PolicySnapshot | None = None) -> bool:
    name, path = event_process(event)
    return is_allowed(name, path, data_dir, policy) if (name or path) else False


def running_processes() -> list[dict]:
    """Return exact running executable candidates for supervised learning."""
    found: dict[tuple[str, str], dict] = {}
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = str(proc.info.get("name") or "")
                path = str(proc.info.get("exe") or "")
                if not name:
                    continue
                key = (_normal_name(name), _normal_path(path))
                found.setdefault(key, {"pid": int(proc.info.get("pid") or 0),
                                       "name": name, "path": path})
            except (OSError, ValueError):
                continue
    except Exception:
        return []
    return sorted(found.values(), key=lambda x: (x["name"].casefold(), x["path"].casefold()))
