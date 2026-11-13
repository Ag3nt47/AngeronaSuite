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
import ntpath
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Iterable

from angerona.core.executable_trust import _open_sealed
from angerona.core.source_sandbox import _hold_plain_directories, _validate_regular_file

_LOCK = threading.RLock()
_CACHE: dict[str, tuple[int, list[dict]]] = {}
_DEFAULT_DATA_DIR: Path | None = None
_MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
_HASH_READ_CHUNK_BYTES = 1024 * 1024
_HASH_READ_BUDGET_SECONDS = 5.0
_MAX_POLICY_BYTES = 2 * 1024 * 1024
_MAX_POLICY_ENTRIES = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENTRY_FIELDS = frozenset(
    {"id", "name", "path", "sha256", "publisher", "source", "added_at", "reviewed"}
)

# Immutable normalized rows are safe to reuse for a complete evaluation batch.
# Each item is ``(case-folded basename, normalized exact path, SHA-256)``.
# A blank digest is a legacy discovery row and remains visible so the
# operator can re-approve it without silently changing existing policy.
class PolicySnapshot(tuple):
    """Immutable policy rows and one batch's authentication key (not exported).

    The key shares the existing same-user bus.key boundary. It authenticates
    producer-supplied event evidence; no filesystem hashing occurs per UI event.
    """
    def __new__(cls, rows=(), *, event_key=None):
        result = super().__new__(cls, rows)
        result.event_key = event_key
        return result


_POLICY_DOMAIN = b"Angerona.ProcessAllowlist.v3\0"


def _policy_key(data_dir=None) -> bytes | None:
    try:
        path = _data_dir(data_dir) / "bus.key"
        if _is_reparse(path) or path.stat().st_size > 128 or path.stat().st_nlink != 1:
            return None
        with path.open("rb") as handle:
            encoded = handle.read(129)
        if len(encoded) > 128:
            return None
        key = bytes.fromhex(encoded.decode("ascii").strip())
        return key if len(key) == 32 else None
    except Exception:
        return None


def _canonical_policy(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _policy_authentic(doc: dict, data_dir=None) -> bool:
    key = _policy_key(data_dir)
    if not key or type(doc.get("hmac")) is not str:
        return False
    body = {name: value for name, value in doc.items() if name != "hmac"}
    expected = hmac.new(key, _POLICY_DOMAIN + _canonical_policy(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(doc["hmac"], expected)


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
    # Match literal observed paths; caller environment must not redirect an approval.
    value = str(value or "").strip().strip('"')
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
    # On CPython 3.12 Windows, named stat retains creation time in st_ctime
    # while descriptor stat can report change time there. Compare the explicit
    # birth timestamp on Windows; POSIX change time remains meaningful. These
    # stamps bind one retained read and never authorize cached digest reuse.
    stamp = (getattr(info, "st_birthtime_ns", info.st_ctime_ns)
             if os.name == "nt" else info.st_ctime_ns)
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(stamp),
    )


def _open_hash_stream(path: Path):
    if os.name == "nt":
        return _open_sealed(path)
    # A FIFO substituted after lstat must not block open before fstat can
    # reject its type. O_NONBLOCK has no effect on regular files.
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        return os.fdopen(descriptor, "rb", buffering=0)
    except Exception:
        os.close(descriptor)
        raise


def executable_sha256(path: str | os.PathLike) -> str:
    """Hash current bytes through a bounded, identity-bound ordinary file read.

    The opened descriptor must match both the initial and final named file.
    Windows denies write/delete sharing during this operation; no handle or
    lock survives the call. Metadata-only digest reuse is unsafe: a same-size
    edit with restored mtime can preserve Windows stat identity. Policy
    snapshots remain reusable, but every digest authorization proves bytes
    again. A read budget bounds cooperative work, not a stalled kernel I/O.
    """
    candidate = Path(os.path.abspath(os.fspath(path)))
    deadline = time.monotonic() + _HASH_READ_BUDGET_SECONDS
    try:
        with _hold_plain_directories(candidate.parent):
            _validate_regular_file(candidate)
            before = candidate.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 < before.st_size <= _MAX_EXECUTABLE_BYTES):
                raise ValueError("trusted executable must be an ordinary bounded single-link file")
            identity = _hash_identity(before)
            digest = hashlib.sha256()
            with _open_hash_stream(candidate) as handle:
                held = os.fstat(handle.fileno())
                if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                        or _hash_identity(held) != identity):
                    raise ValueError("trusted executable changed before its file was opened")
                remaining = int(held.st_size)
                while remaining:
                    if time.monotonic() >= deadline:
                        raise ValueError("trusted executable verification exceeded its read budget")
                    chunk = handle.read(min(_HASH_READ_CHUNK_BYTES, remaining))
                    if not chunk or len(chunk) > remaining:
                        raise ValueError("trusted executable changed during verification")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if time.monotonic() >= deadline:
                    raise ValueError("trusted executable verification exceeded its read budget")
                if handle.read(1):
                    raise ValueError("trusted executable grew during verification")
                after = os.fstat(handle.fileno())
                _validate_regular_file(candidate)
                named = candidate.lstat()
                if (after.st_nlink != 1 or named.st_nlink != 1
                        or _hash_identity(after) != identity
                        or _hash_identity(named) != identity):
                    raise ValueError("trusted executable changed during verification")
                if time.monotonic() >= deadline:
                    raise ValueError("trusted executable verification exceeded its read budget")
            return digest.hexdigest()
    except OSError as exc:
        raise ValueError("trusted executable is unavailable") from exc


def _load(data_dir=None) -> list[dict]:
    path = policy_path(data_dir)
    key = str(path)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = -1
    with _LOCK:
        # Authenticate current document bytes per batch. mtime alone cannot
        # authorize policy after an equal-size edit with restored timestamps.
        try:
            if (
                path.stat().st_size > _MAX_POLICY_BYTES
                or _is_reparse(path)
                or _is_reparse(path.parent)
            ):
                raise ValueError("trusted-process policy path is unsafe")
            with path.open("rb") as handle:
                encoded = handle.read(_MAX_POLICY_BYTES + 1)
            if len(encoded) > _MAX_POLICY_BYTES:
                raise ValueError("trusted-process policy grew beyond its byte bound")
            raw = json.loads(encoded)
            if (
                not isinstance(raw, dict)
                or set(raw) != ({"version", "updated_at", "entries", "hmac"}
                                if raw.get("version") == 3 else {"version", "updated_at", "entries"})
                or raw.get("version") not in (1, 2, 3)
                or isinstance(raw.get("updated_at"), bool)
                or not isinstance(raw.get("updated_at"), (int, float))
                or not math.isfinite(float(raw["updated_at"]))
                or not isinstance(raw.get("entries"), list)
                or len(raw["entries"]) > _MAX_POLICY_ENTRIES
            ):
                raise ValueError("trusted-process policy schema is invalid")
            authenticated = raw.get("version") == 3 and _policy_authentic(raw, data_dir)
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
                        "reviewed": bool(authenticated and item.get("reviewed") is True),
                        "_policy_authenticated": authenticated,
                        "review_required": not authenticated or item.get("reviewed") is not True,
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
    key = _policy_key(data_dir)
    if key is None:
        raise ValueError("Process policy signing key is unavailable; no approval was saved.")
    if path.exists():
        with path.open("rb") as handle:
            original = handle.read(_MAX_POLICY_BYTES + 1)
        if len(original) > _MAX_POLICY_BYTES:
            raise ValueError("Existing process policy exceeds its byte bound; it was preserved.")
        previous = json.loads(original)
        if previous.get("version") == 3 and not _policy_authentic(previous, data_dir):
            raise ValueError("Existing process policy integrity is unknown; preserve and review it.")
        if previous.get("version") in (1, 2):
            archive = path.with_name(path.name + ".legacy-" + hashlib.sha256(original).hexdigest() + ".json")
            if archive.exists():
                if archive.read_bytes() != original:
                    raise ValueError("Preserved process policy history changed.")
            else:
                with archive.open("xb") as handle:
                    handle.write(original); handle.flush(); os.fsync(handle.fileno())
    stored = []
    for row in items:
        item = {name: row[name] for name in _ENTRY_FIELDS if name in row}
        item["reviewed"] = bool(row.get("_reviewed_now") or
                                row.get("_policy_authenticated") and row.get("reviewed"))
        stored.append(item)
    payload = {"version": 3, "updated_at": time.time(), "entries": stored}
    payload["hmac"] = hmac.new(key, _POLICY_DOMAIN + _canonical_policy(payload), hashlib.sha256).hexdigest()
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

    Batch consumers call this once, then pass it to active predicates. Only
    authenticated, explicitly reviewed digest-bound rows enter the snapshot.
    Event checks verify signed producer evidence in memory; legacy rows remain
    visible through entries() for explicit review.
    """
    return PolicySnapshot((
        (
            _normal_name(row.get("name", "")),
            _normal_path(row.get("path", "")),
            str(row.get("sha256", "")).casefold(),
        )
        for row in _load(data_dir)
        if row.get("_policy_authenticated") and row.get("reviewed") and row.get("sha256") and row.get("path")
    ), event_key=_policy_key(data_dir))


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

    Basename-only and missing-file entries remain discovery hints. Active
    suppression requires a reviewed exact path, current digest and authenticated
    policy; pathless telemetry never inherits executable trust.
    Existing local files are also bound to their current SHA-256; replacing the
    file at an approved path invalidates trust until explicit re-approval.
    """
    clean_path = str(path or "").strip().strip('"')
    if clean_path and not (os.path.isabs(clean_path) or ntpath.isabs(clean_path)):
        clean_path = os.path.abspath(clean_path)
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
            changed = not row.get("_policy_authenticated") or not row.get("reviewed")
            row["_reviewed_now"] = bool(bound_digest and clean_path)
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
        "_reviewed_now": bool(bound_digest and clean_path),
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
    """Active trust requires the exact currently hashed executable.

    Basename/path-only and old two-field rows remain discovery history, not
    authorization. Use entries() for display and explicit reviewed reapproval.
    """
    return is_digest_pinned_allowed(name, path, data_dir, policy)


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
    if (not norm_name or not norm_path or not (os.path.isabs(path) or ntpath.isabs(path))):
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
    """Verify producer-bound digest/generation without per-event filesystem I/O."""
    rows = policy_snapshot(data_dir) if policy is None else policy
    key = getattr(rows, "event_key", None)
    if key is None:
        return False
    from angerona.core.eventbus import BusAuthority, is_remote_observe_only
    try:
        if is_remote_observe_only(event) or not BusAuthority(key).verify(event):
            return False
        details = event.details
        pid = details.get("pid")
        birth = details.get("process_birth_ticks", details.get("process_create_time"))
        digest = str(details.get("image_sha256") or details.get("process_sha256") or details.get("sha256") or "").lower()
        if (type(pid) is not int or pid <= 0 or type(birth) not in (int, float)
                or not math.isfinite(birth) or birth <= 0 or not _SHA256.fullmatch(digest)):
            return False
        name, path = event_process(event)
        if not (os.path.isabs(path) or ntpath.isabs(path)):
            return False
        norm_name, norm_path = _normal_name(name or path), _normal_path(path)
        return any(row_name == norm_name and row_path and row_path == norm_path
                   and hmac.compare_digest(row_digest, digest)
                   for row_name, row_path, row_digest in rows)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


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
