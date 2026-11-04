"""Base class every Angerona module inherits from.

A module is a self-contained security capability. Subclass ``BaseModule``,
set the class attributes, and implement ``run()``. The ModuleManager handles
threading, lifecycle, and event routing — you only write detection logic and
call ``self.emit(...)`` when something interesting happens.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import shutil
import stat
import sys
import threading
import time
import traceback
import types
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Optional

from angerona.core.eventbus import Event, EventBus, Severity


# ── Crash snapshot helpers ────────────────────────────────────────────────────

_CRASH_SNAPSHOT_DOMAIN = b"angerona/crash-snapshot/v1\x00"
_CRASH_SNAPSHOT_FIELDS = frozenset({
    "snapshot_schema", "module", "crashed_at", "error", "traceback",
    "memory", "last_50_events", "snapshot_hmac",
})

def _get_snapshot_dir() -> Path:
    """Return (and create) the crash-snapshot directory for this installation."""
    from angerona.core.data_paths import data_dir
    root = data_dir()
    _snapshot_plain_directory(root)
    snap = root
    for component in ("diagnostics", "crash_snapshots"):
        snap = snap / component
        try:
            snap.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _snapshot_plain_directory(snap)
    return snap


def _crash_snapshot_master_key() -> bytes | None:
    from angerona.core.data_paths import data_dir

    try:
        raw = (data_dir() / "bus.key").read_text(encoding="ascii").strip()
        key = bytes.fromhex(raw)
    except (OSError, UnicodeError, ValueError):
        return None
    return key if len(key) == 32 else None


def _crash_snapshot_body(document: dict) -> bytes:
    unsigned = {
        key: value for key, value in document.items() if key != "snapshot_hmac"
    }
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign_crash_snapshot_bundle(bundle: dict, *, key: bytes | None = None) -> dict:
    """Return an authenticated exact-schema crash bundle or raise."""
    authority = _crash_snapshot_master_key() if key is None else key
    if not isinstance(authority, bytes) or len(authority) != 32:
        raise ValueError("crash snapshot authority unavailable")
    document = dict(bundle)
    document["snapshot_schema"] = 1
    document.pop("snapshot_hmac", None)
    if set(document) | {"snapshot_hmac"} != _CRASH_SNAPSHOT_FIELDS:
        raise ValueError("crash snapshot schema is incomplete")
    document["snapshot_hmac"] = hmac.new(
        authority,
        _CRASH_SNAPSHOT_DOMAIN + _crash_snapshot_body(document),
        hashlib.sha256,
    ).hexdigest()
    return document


def verify_crash_snapshot_bundle(
    document: object, *, key: bytes | None = None,
) -> bool:
    """Verify one exact authenticated crash bundle without mutating it."""
    authority = _crash_snapshot_master_key() if key is None else key
    if (
        not isinstance(authority, bytes)
        or len(authority) != 32
        or not isinstance(document, dict)
        or set(document) != _CRASH_SNAPSHOT_FIELDS
        or document.get("snapshot_schema") != 1
        or not isinstance(document.get("snapshot_hmac"), str)
    ):
        return False
    try:
        body = _crash_snapshot_body(document)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False
    expected = hmac.new(
        authority, _CRASH_SNAPSHOT_DOMAIN + body, hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(str(document["snapshot_hmac"]), expected)


_CRASH_CAPTURE_POLICY = "angerona-crash-capture-v1"
_MAX_CRASH_RECORD_BYTES = 480 * 1024
_MAX_CRASH_RECORDS = 256
_MAX_CRASH_DIRECTORY_BYTES = 64 * 1024 * 1024
_MAX_CRASH_DIRECTORY_ENTRIES = 1_024
_MIN_CRASH_FREE_BYTES = 2 * 1024 * 1024 * 1024
_CRASH_SNAPSHOT_LEASE = ".crash_snapshot.lock"
_CRASH_SNAPSHOT_WRITE_LOCK = threading.Lock()
_CRASH_SNAPSHOT_CUSTODY_UNKNOWN: tuple[str, Path, object, int | None] | None = None


class _SnapshotCaptureError(ValueError):
    """The diagnostic copy could not be represented within its fixed policy."""


class _SnapshotStorageHeld(OSError):
    """Admission refused without changing any retained crash evidence."""


def _snapshot_hold_unknown_custody(
    phase: str, path: Path, wrapper: object, raw_handle: int | None,
) -> None:
    """Retain at most one ambiguous owner; never act on its numeric value."""
    global _CRASH_SNAPSHOT_CUSTODY_UNKNOWN
    # Production reaches this only while the process write lock is held. Keep
    # the wrapper alive too: its state may be unknown after interrupted Detach.
    if _CRASH_SNAPSHOT_CUSTODY_UNKNOWN is None:
        _CRASH_SNAPSHOT_CUSTODY_UNKNOWN = (phase, path, wrapper, raw_handle)


def _snapshot_acl_admitted(owner: str, user: str, aces: list[tuple[str, str]]) -> bool:
    """Accept source-user and historical admin ownership, never foreign grants."""
    trusted = {user, "S-1-5-18", "S-1-5-32-544"}
    return owner in trusted and bool(aces) and all(
        kind == "deny" or (kind == "allow" and sid in trusted)
        for kind, sid in aces
    )


def _snapshot_verify_windows_directory(path: Path) -> None:
    """Check existing custody without repairing a directory's owner or DACL."""
    try:
        import win32security
        from angerona.core.engine_transport import _windows_identity

        descriptor = win32security.GetFileSecurity(
            str(path),
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
        )
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None or not 1 <= acl.GetAceCount() <= 64:
            raise _SnapshotStorageHeld("held_directory")
        aces = []
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            kind = (
                "allow" if ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
                else "deny" if ace[0][0] == win32security.ACCESS_DENIED_ACE_TYPE
                else "unsupported"
            )
            aces.append((kind, win32security.ConvertSidToStringSid(ace[2])))
        if not _snapshot_acl_admitted(
            win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()),
            win32security.ConvertSidToStringSid(_windows_identity()), aces,
        ):
            raise _SnapshotStorageHeld("held_directory")
    except _SnapshotStorageHeld:
        raise
    except Exception as exc:
        raise _SnapshotStorageHeld("held_directory") from exc


def _snapshot_plain_directory(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or int(getattr(info, "st_file_attributes", 0) or 0) & 0x400
        or (
            os.name != "nt"
            and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022)
        )
    ):
        raise _SnapshotStorageHeld("held_directory")
    if os.name == "nt":
        _snapshot_verify_windows_directory(path)


def _snapshot_crop(
    value: object, byte_limit: int, *, max_chars: int | None = None,
    suffix: bool = False,
) -> tuple[str, dict]:
    """Bound the actual JSON string bytes without encoding an unbounded input."""
    if type(value) is not str:
        return "", {
            "original_chars": None, "retained_chars": 0,
            "omitted_chars": None, "unavailable": True,
        }
    original = len(value)
    high = min(original, byte_limit, max_chars if max_chars is not None else original)
    low = 0
    retained = ""
    while low <= high:
        count = (low + high) // 2
        candidate = value[-count:] if suffix and count else value[:count]
        try:
            size = len(json.dumps(candidate, ensure_ascii=False).encode("utf-8"))
        except UnicodeError as exc:
            raise _SnapshotCaptureError("held_capture_text") from exc
        if size <= byte_limit:
            retained = candidate
            low = count + 1
        else:
            high = count - 1
    return retained, {
        "original_chars": original, "retained_chars": len(retained),
        "omitted_chars": original - len(retained), "unavailable": False,
    }


def _snapshot_number(value: object) -> int | float | None:
    if type(value) is int:
        return value if -(2**63) <= value < 2**63 else None
    if type(value) is float and math.isfinite(value):
        return value
    return None


def _bounded_crash_snapshot_bundle(
    *, module: object, error: object, tb: object, memory: dict,
    memory_available: bool, events: object, crashed_at: float,
) -> dict:
    """Build an explicitly lossy diagnostic copy; original evidence is unchanged."""
    if (
        type(memory) is not dict or type(memory_available) is not bool
        or type(crashed_at) is not float or not math.isfinite(crashed_at)
        or crashed_at < 0
        or (
            memory_available and (
                set(memory) != {"rss_mb", "vms_mb", "percent"}
                or any(_snapshot_number(value) is None for value in memory.values())
            )
        )
    ):
        raise _SnapshotCaptureError("held_capture_type")
    module_text, module_counts = _snapshot_crop(module, 256, max_chars=128)
    error_text, error_counts = _snapshot_crop(error, 8 * 1024)
    full_tb, traceback_counts = _snapshot_crop(tb, 256 * 1024, max_chars=256_000)
    traceback_complete = bool(
        full_tb and not traceback_counts["unavailable"]
        and traceback_counts["omitted_chars"] == 0
    )
    excerpt = {"head": "", "tail": ""}
    if not traceback_complete:
        head, head_counts = _snapshot_crop(tb, 128 * 1024)
        tail, _ = _snapshot_crop(
            tb, 128 * 1024,
            max_chars=(len(tb) - len(head)) if type(tb) is str else 0,
            suffix=True,
        )
        excerpt = {"head": head, "tail": tail}
        traceback_counts = dict(head_counts)
        traceback_counts["retained_chars"] = len(head) + len(tail)
        if not traceback_counts["unavailable"]:
            traceback_counts["omitted_chars"] = len(tb) - len(head) - len(tail)
        # An old consumer must never select a source from cropped frames.
        full_tb = ""

    recent: list[dict] = []
    event_counts: list[dict] = []
    event_unavailable = type(events) not in (list, tuple) or len(events) > 50
    returned = None if event_unavailable else len(events)
    if not event_unavailable:
        for ev in events:
            if type(ev) is not Event:
                continue
            event_module, module_loss = _snapshot_crop(ev.module, 256, max_chars=128)
            severity, severity_loss = _snapshot_crop(
                ev.severity.name if type(ev.severity) is Severity else None,
                64, max_chars=32,
            )
            message, message_loss = _snapshot_crop(ev.message, 2 * 1024, max_chars=4096)
            stamp = _snapshot_number(ev.ts)
            event_counts.append({
                "index": len(recent), "module": module_loss,
                "severity": severity_loss, "message": message_loss,
                "timestamp_available": stamp is not None,
            })
            recent.append({
                "ts": stamp, "module": event_module,
                "severity": severity, "message": message,
            })
    capture = {
        "schema": 1, "policy": _CRASH_CAPTURE_POLICY,
        "traceback_complete": traceback_complete, "traceback_excerpt": excerpt,
        "text": {"module": module_counts, "error": error_counts, "traceback": traceback_counts},
        "events": {
            "requested": 50, "returned": returned, "retained": len(recent),
            "omitted": None if returned is None else returned - len(recent),
            "unavailable": event_unavailable, "text": event_counts,
        },
        "memory_available": memory_available, "byte_limit": _MAX_CRASH_RECORD_BYTES,
    }
    sampled_memory = dict(memory) if memory_available else {"note": "psutil unavailable"}
    sampled_memory["capture"] = capture
    return {
        "module": module_text, "crashed_at": crashed_at, "error": error_text,
        "traceback": full_tb, "memory": sampled_memory, "last_50_events": recent,
    }


def _snapshot_directory_admission(directory: Path, incoming: int) -> None:
    """Account bounded metadata only, preserving every existing directory entry."""
    count = 0
    total = 0
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries):
            if index >= _MAX_CRASH_DIRECTORY_ENTRIES:
                raise _SnapshotStorageHeld("held_accounting")
            if entry.name == _CRASH_SNAPSHOT_LEASE:
                continue  # The existing file-lease helper validates this exact entry.
            # Windows DirEntry metadata can leave link/identity fields unknown.
            # Request actual no-follow path metadata rather than interpreting
            # cached zeros as a measured broken file identity.
            info = Path(entry.path).lstat()
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or int(getattr(info, "st_file_attributes", 0) or 0) & 0x400
            ):
                raise _SnapshotStorageHeld("held_accounting")
            count += 1
            total += info.st_size
            if count >= _MAX_CRASH_RECORDS or total + incoming > _MAX_CRASH_DIRECTORY_BYTES:
                raise _SnapshotStorageHeld("held_storage_budget")


def _snapshot_create_private(path: Path) -> int:
    """Exclusively create a private temporary; never open a historical record."""
    if _CRASH_SNAPSHOT_CUSTODY_UNKNOWN is not None:
        raise _SnapshotStorageHeld("held_custody_unknown")
    flags = os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    if os.name != "nt":
        return os.open(path, flags | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    import msvcrt
    import win32api
    import win32con
    import win32file
    from angerona.core.engine_transport import _windows_private_attributes

    handle = win32file.CreateFile(
        str(path), win32con.GENERIC_WRITE, win32con.FILE_SHARE_READ,
        _windows_private_attributes(), win32con.CREATE_NEW,
        win32con.FILE_ATTRIBUTE_NORMAL, None,
    )
    try:
        raw_handle = handle.Detach()
    except BaseException:
        _snapshot_hold_unknown_custody("detach", path, handle, None)
        raise _SnapshotStorageHeld("held_custody_unknown") from None
    # Detach before transfer. Only the documented non-adopting OSError refusal
    # permits a raw close. An asynchronous exception can arrive after CRT
    # adoption but before Python observes the fd; its numeric handle is unsafe.
    try:
        return msvcrt.open_osfhandle(raw_handle, flags)
    except OSError:
        try:
            win32api.CloseHandle(raw_handle)
        except BaseException:
            _snapshot_hold_unknown_custody("refusal_close", path, handle, raw_handle)
            raise _SnapshotStorageHeld("held_custody_unknown") from None
        raise
    except BaseException:
        _snapshot_hold_unknown_custody("transfer", path, handle, raw_handle)
        raise _SnapshotStorageHeld("held_custody_unknown") from None


def _snapshot_free_space_admission(directory: Path, incoming: int) -> None:
    """One crash-only sample; no startup gate, reservation or physical quota."""
    try:
        free = shutil.disk_usage(directory).free
    except Exception as exc:
        raise _SnapshotStorageHeld("held_space_unknown") from exc
    if type(free) is not int or free < 0:
        raise _SnapshotStorageHeld("held_space_unknown")
    if free < _MIN_CRASH_FREE_BYTES + incoming:
        raise _SnapshotStorageHeld("held_free_space")


def _snapshot_publish_new(temporary: Path, destination: Path) -> None:
    """Publish complete bytes without a replacement operation on any platform."""
    if os.name == "nt":
        # Windows rename refuses an existing destination. POSIX rename replaces it.
        os.rename(temporary, destination)
    else:
        os.link(temporary, destination, follow_symlinks=False)


def _publish_crash_snapshot_bytes(directory: Path, encoded: bytes) -> str:
    """One crash-path-only, fail-fast admission and create-only publication."""
    from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError

    if _CRASH_SNAPSHOT_CUSTODY_UNKNOWN is not None:
        return "held_custody_unknown"
    if not encoded or len(encoded) > _MAX_CRASH_RECORD_BYTES:
        return "held_capture_bound"
    if not _CRASH_SNAPSHOT_WRITE_LOCK.acquire(blocking=False):
        return "held_busy"
    temporary: Path | None = None
    destination: Path | None = None
    owned_identity: tuple[int, int] | None = None
    published = False
    outcome = "held_write"
    try:
        if _CRASH_SNAPSHOT_CUSTODY_UNKNOWN is not None:
            return "held_custody_unknown"
        _snapshot_plain_directory(directory.parent)
        _snapshot_plain_directory(directory)
        with ExclusiveFileLease(directory / _CRASH_SNAPSHOT_LEASE):
            _snapshot_directory_admission(directory, len(encoded))
            _snapshot_free_space_admission(directory, len(encoded))
            token = uuid.uuid4().hex
            temporary = directory / f".crash.{time.time_ns()}.{token}.tmp"
            destination = directory / f"crash.{time.time_ns()}.{token}.json"
            descriptor = _snapshot_create_private(temporary)
            try:
                before = os.fstat(descriptor)
                candidate_identity = (before.st_dev, before.st_ino)
                named = temporary.lstat()
                if (
                    not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size != 0 or before.st_ino <= 0
                    or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                    or named.st_ino <= 0
                    or int(getattr(named, "st_file_attributes", 0) or 0) & 0x400
                    or candidate_identity != (named.st_dev, named.st_ino)
                ):
                    raise _SnapshotStorageHeld("held_directory")
                owned_identity = candidate_identity
                # Unbuffered descriptor I/O avoids a second fdopen ownership
                # handoff and its competing destructor/finally close paths.
                if os.write(descriptor, encoded) != len(encoded):
                    raise OSError("short crash snapshot write")
                os.fsync(descriptor)
                if os.fstat(descriptor).st_size != len(encoded):
                    raise OSError("crash snapshot size changed")
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            _snapshot_plain_directory(directory.parent)
            _snapshot_plain_directory(directory)
            named = temporary.lstat()
            if (
                (named.st_dev, named.st_ino) != owned_identity
                or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                or named.st_size != len(encoded)
                or int(getattr(named, "st_file_attributes", 0) or 0) & 0x400
            ):
                raise _SnapshotStorageHeld("held_directory")
            _snapshot_publish_new(temporary, destination)
            published = True
            outcome = "published"
            # Content was fsynced before publication. Do not claim Windows power-loss durability.
            if os.name != "nt":
                directory_descriptor = os.open(
                    directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
    except _SnapshotStorageHeld as exc:
        outcome = "published_finalization_gap" if published else str(exc)
    except ExclusiveFileLeaseError:
        outcome = "published_finalization_gap" if published else "held_busy"
    except Exception:
        outcome = "published_durability_gap" if published else "held_write"
    finally:
        if not published and destination is not None and owned_identity is not None:
            try:
                final_info = destination.lstat()
                if (
                    stat.S_ISREG(final_info.st_mode)
                    and not int(getattr(final_info, "st_file_attributes", 0) or 0) & 0x400
                    and (final_info.st_dev, final_info.st_ino) == owned_identity
                    and final_info.st_size == len(encoded)
                ):
                    # A failing publication call can have an ambiguous outcome.
                    # Retain this exact owned final record and never retry it.
                    published = True
                    outcome = "published_finalization_gap"
            except FileNotFoundError:
                pass
            except OSError:
                outcome = "held_publication_unknown"
        if temporary is not None and owned_identity is not None:
            try:
                named = temporary.lstat()
                if (named.st_dev, named.st_ino) != owned_identity:
                    outcome = "published_cleanup_gap" if published else "held_cleanup_gap"
                else:
                    temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                outcome = "published_cleanup_gap" if published else "held_cleanup_gap"
        _CRASH_SNAPSHOT_WRITE_LOCK.release()
    if not published and _CRASH_SNAPSHOT_CUSTODY_UNKNOWN is not None:
        return "held_custody_unknown"
    return outcome


_MAX_RESTARTS   = 3
_RESTART_DELAYS = (5, 30, 120)   # seconds to wait between successive restart attempts
_RESTART_JOIN_TIMEOUT = 0.25      # keep an operator restart responsive
_MAX_HEALTH_REASON = 1000
_MAX_HEALTH_SOURCE_BYTES = 512 * 1024
_MAX_PROVENANCE_OBJECTS = 8_192
_REPARSE_POINT = 0x400


@lru_cache(maxsize=2)
def _cached_source_checkout_root(frozen: bool) -> Optional[Path]:
    """Return the local source checkout root, never an installed-path guess.

    A wheel, frozen executable, or copied package may retain Python filenames
    which resemble local paths.  They are not sufficient evidence that source
    is present.  Requiring the exact checkout layout and its Git marker keeps
    health evidence honest and prevents an external module from advertising an
    arbitrary host path as an Angerona source location.
    """
    if frozen:
        return None
    try:
        this_file = Path(__file__).resolve(strict=True)
        root = this_file.parents[3]
        expected = root / "src" / "angerona" / "core" / "module_base.py"
        if not (root / ".git").exists():
            return None
        if expected.resolve(strict=True) != this_file:
            return None
        return root
    except (IndexError, OSError, RuntimeError):
        return None


def _source_checkout_root() -> Optional[Path]:
    """Cached checkout lookup keyed by the runtime's frozen state."""
    return _cached_source_checkout_root(bool(getattr(sys, "frozen", False)))


def _bounded_health_reason(note: object, health: int) -> str:
    """Return a non-empty, display-safe and JSON-safe diagnostic reason."""
    try:
        reason = str(note).replace("\x00", "").strip()
    except Exception:
        reason = ""
    if not reason:
        reason = f"Module reported {health}% health without a diagnostic reason."
    return reason[:_MAX_HEALTH_REASON]


@lru_cache(maxsize=512)
def _cached_health_source_identity(
    filename: str, frozen: bool,
) -> tuple[str, Optional[str]]:
    """Classify stable Python code filenames once; UI revalidates before read."""
    root = _cached_source_checkout_root(frozen)
    if root is None:
        return "unavailable", None
    try:
        candidate = Path(filename).resolve(strict=True)
        relative = candidate.relative_to(root)
        if not candidate.is_file() or candidate.suffix.casefold() != ".py":
            raise ValueError("not a Python source file")
        relative_posix = relative.as_posix()
        if not relative_posix.startswith("src/angerona/"):
            raise ValueError("outside Angerona source")
        return "available", relative_posix
    except (OSError, RuntimeError, TypeError, ValueError):
        return "untrusted-external", None


@lru_cache(maxsize=512)
def _cached_source_manifest(
    filename: str,
    device: int,
    inode: int,
    size: int,
    modified_ns: int,
) -> Optional[tuple[str, frozenset[types.CodeType]]]:
    """Compile one identity-pinned source into an immutable code manifest.

    Merely inserting a dynamically compiled function into mutable module
    globals is not declaration provenance.  The caller's immutable code object
    must instead be structurally identical to code compiled from the exact
    descriptor-bound canonical source bytes whose digest is displayed.
    """
    candidate = Path(filename)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(candidate, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or bool(getattr(before, "st_file_attributes", 0) & _REPARSE_POINT)
            or before.st_size > _MAX_HEALTH_SOURCE_BYTES
            or before.st_dev != device
            or before.st_ino != inode
            or before.st_size != size
            or before.st_mtime_ns != modified_ns
        ):
            return None
        chunks: list[bytes] = []
        remaining = _MAX_HEALTH_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > _MAX_HEALTH_SOURCE_BYTES
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            return None
        current = candidate.stat(follow_symlinks=False)
        if current.st_dev != after.st_dev or current.st_ino != after.st_ino:
            return None
        compiled = compile(
            raw,
            str(candidate.resolve(strict=True)),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
        pending = [compiled]
        admitted: list[types.CodeType] = []
        while pending:
            current_code = pending.pop()
            admitted.append(current_code)
            if len(admitted) > _MAX_PROVENANCE_OBJECTS:
                return None
            pending.extend(
                value
                for value in current_code.co_consts
                if isinstance(value, types.CodeType)
            )
        return hashlib.sha256(raw).hexdigest(), frozenset(admitted)
    except (OSError, RuntimeError, SyntaxError, TypeError, ValueError):
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _health_callsite(frame) -> dict[str, object]:
    """Describe a caller only with loaded-module and source-object provenance."""
    unavailable = {
        "source_state": "untrusted-external",
        "source_path": None,
        "source_line": None,
        "source_sha256": None,
        "source_provenance": "unverified-callsite",
    }
    if bool(getattr(sys, "frozen", False)):
        return {
            **unavailable,
            "source_state": "unavailable",
            "source_provenance": "source-less-runtime",
        }
    module_name = frame.f_globals.get("__name__")
    if not isinstance(module_name, str) or not module_name.startswith("angerona."):
        return unavailable
    module = sys.modules.get(module_name)
    if module is None or getattr(module, "__dict__", None) is not frame.f_globals:
        return unavailable
    state, relative = _cached_health_source_identity(
        str(frame.f_code.co_filename), bool(getattr(sys, "frozen", False))
    )
    if state != "available" or relative is None:
        if state == "unavailable":
            return {
                **unavailable,
                "source_state": "unavailable",
                "source_provenance": "source-less-runtime",
            }
        return unavailable
    root = _source_checkout_root()
    if root is None:
        return {
            **unavailable,
            "source_state": "unavailable",
            "source_provenance": "source-less-runtime",
        }
    try:
        candidate = root.joinpath(relative).resolve(strict=True)
        # Normal imports expose the same canonical absolute string in all
        # three places. Re-resolving that identical path repeats Windows path
        # I/O on every degraded-health tick without adding identity evidence.
        # Aliased or changed origins still receive the full strict resolution.
        candidate_name = str(candidate)
        module_filename = str(getattr(module, "__file__", ""))
        origin_name = str(module.__spec__.origin)
        module_file = (
            candidate if module_filename == candidate_name
            else Path(module_filename).resolve(strict=True)
        )
        spec_origin = (
            candidate if origin_name == candidate_name
            else Path(origin_name).resolve(strict=True)
        )
        if candidate != module_file or candidate != spec_origin:
            return unavailable
        info = candidate.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
        ):
            return unavailable
        manifest = _cached_source_manifest(
            str(candidate),
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_size),
            int(info.st_mtime_ns),
        )
        if manifest is None:
            return unavailable
        digest, admitted_code = manifest
        if frame.f_code not in admitted_code:
            return unavailable
        line: Optional[int] = max(1, int(frame.f_lineno))
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return unavailable
    return {
        "source_state": "available",
        "source_path": relative,
        "source_line": line,
        "source_sha256": digest,
        "source_provenance": "verified-loaded-implementation",
    }


def watchdog_fault_kind(snapshot: dict[str, object]) -> str | None:
    """Classify a worker fault from a lifecycle-bound watchdog sample."""
    status = snapshot.get("status")
    if status == "error":
        return "error"
    if status == "running" and not snapshot.get("thread_alive", False):
        return "thread_exit"
    if snapshot.get("watchdog_deadline_missed", False):
        return "deadline"
    return None


class BaseModule:
    # ── Override these in your subclass ─────────────────────────────────────
    name: str = "Unnamed Module"
    description: str = ""
    category: str = "General"
    version: str = "1.0.0"
    enabled_by_default: bool = True
    # Existing modules predate the platform contract and are therefore treated
    # as Windows-only until they explicitly opt into another platform.  This is
    # a safety property: an unavailable sensor must not inflate protection.
    supported_platforms = frozenset({"windows"})
    capability_mode: str = "unknown"
    platform_requirements: tuple[str, ...] = ()
    # A subclass may explicitly decline operator-approved Self-Test recovery.
    # The runner still requires a faulted generation and managed lifecycle.
    selftest_auto_repair: bool = False
    _RESTART_JOIN_TIMEOUT: float = _RESTART_JOIN_TIMEOUT
    # Every managed worker receives a supervisor-owned cadence contract.  The
    # default deliberately allows one full startup budget for work after the
    # module's declared/observed wait interval.  Modules with an unusually
    # long, legitimate blocking operation may raise this bounded value; setting
    # ``watchdog_liveness_enabled`` false is reserved for explicitly
    # event-driven workers which publish liveness through another authority.
    watchdog_liveness_enabled: bool = True
    watchdog_work_budget_seconds: float = 30.0
    # Automated load shedding is opt-in at the implementation type, never
    # inferred from a mutable display name/category.  Real-time sensors and
    # response paths therefore remain at their declared cadence by default.
    adaptive_throttle_allowed: bool = False
    adaptive_throttle_max: float = 1.0
    # UI/host responsiveness pacing is separate, default enabled, and only
    # applies to explicitly reviewed inventory workers or specific intervals.
    background_pacing_allowed: bool = False

    def __init__(self) -> None:
        self._bus: Optional[EventBus] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._startup_wake_event: Optional[threading.Event] = None
        # Lifecycle generations prevent a restarted module from clearing the
        # stop token underneath its exiting predecessor. ``stop()`` remains
        # non-blocking; ``start()`` performs only a short join and, when needed,
        # hands the restart to one daemon waiter.
        self._lifecycle_lock = threading.RLock()
        self._lifecycle_serial = 0
        self._lifecycle_generation = 0
        self._restart_request: Optional[tuple[int, float]] = None
        self._restart_waiter: Optional[threading.Thread] = None
        self._run_context = threading.local()
        self._health_lock = threading.RLock()
        self._status: str = "stopped"
        self.last_error: str = ""
        self.health: int = 100        # 0-100; how well the module is actually working
        self.health_note: str = ""    # why it's degraded, if it is
        self._health_evidence: Optional[dict[str, object]] = None
        self._initial_delay: float = 0.0   # first-poll stagger (set by the manager at boot)
        # Cadence policy is shared by the resource governor, Chill Mode, and
        # authenticated remote administration.  A dedicated re-entrant lock
        # lets a multi-module policy change hold every affected cadence stable
        # until its complete before/after state is known.
        self._throttle_lock = threading.RLock()
        self._throttle: float = 1.0   # loop-cadence multiplier (Adaptive Resource Governor)
        self._throttle_floor: float = 1.0  # persistent Chill Mode cadence floor
        self._priority_throttle: float = 1.0
        self._priority_throttle_until: float = 0.0
        # Readiness barrier used by staged Eco Mode wake-up. A module's first
        # cadence boundary proves it has actually run, rather than merely
        # having a live thread and stale pre-Eco health.
        self._first_cycle_complete = threading.Event()
        self._cycle_lock = threading.RLock()
        self._cycle_count: int = 0
        self._last_cycle_completed_at: float = 0.0
        self._last_sleep_interval_seconds: float = 0.0
        self._watchdog_deadline_at: float = 0.0
        # EventBus polling uses monotonic publication revisions rather than
        # timestamps. The bus ring is newest-first and multiple events may
        # legitimately share a timestamp; timestamp watermarks therefore lose
        # evidence during bursts. Independent cursors let every module consume
        # an oldest-first, bounded delta without reimplementing that contract.
        self._bus_revision: int = 0
        self._bus_priority_revision: int = 0
        self._bus_cursor_enrolled: dict[bool, bool] = {False: False, True: False}
        self._bus_overflow_count: int = 0
        self._last_reported_overflow_revision: dict[bool, int] = {}
        self._generation_started_at: float = 0.0
        self._crash_count: int = 0
        self._last_crash_at: float = 0.0

    # ── Wiring (called by ModuleManager) ────────────────────────────────────
    def bind(self, bus: EventBus) -> None:
        if self._bus is not None and self._bus is not bus:
            # Revisions are scoped to one EventBus instance. Rebinding to a new
            # bus creates a new ordering domain and therefore requires a fresh
            # explicit enrollment decision by the consumer.
            self._bus_revision = 0
            self._bus_priority_revision = 0
            self._bus_cursor_enrolled = {False: False, True: False}
        self._bus = bus

    # ── Health ───────────────────────────────────────────────────────────────
    @property
    def status(self) -> str:
        """Return lifecycle status under the health snapshot lock."""
        with self._health_lock:
            return self._status

    @status.setter
    def status(self, value: object) -> None:
        """Publish lifecycle transitions atomically with health snapshots."""
        rendered = str(value)[:80]
        with self._health_lock:
            self._status = rendered

    def set_health(self, pct: int, note: str = "") -> None:
        """Report health with mandatory, bounded evidence for degradation.

        The callsite is captured at the moment a module reports less than full
        health.  Only repository-relative paths inside the local Angerona
        checkout are retained; packaged and external modules receive an honest
        availability state without leaking or inventing a host path.
        """
        health = max(0, min(100, int(pct)))
        if health < 100:
            reason = _bounded_health_reason(note, health)
            try:
                frame = sys._getframe(1)
                source = _health_callsite(frame)
            except (AttributeError, ValueError):
                source = {
                    "source_state": "unavailable",
                    "source_path": None,
                    "source_line": None,
                    "source_sha256": None,
                    "source_provenance": "unavailable",
                }
            finally:
                # Never retain a live frame and its locals.
                try:
                    del frame
                except UnboundLocalError:
                    pass
            evidence: Optional[dict[str, object]] = {
                "reason": reason,
                **source,
            }
            display_note = reason
        else:
            evidence = None
            try:
                display_note = str(note).replace("\x00", "").strip()[:_MAX_HEALTH_REASON]
            except Exception:
                display_note = ""
        with self._health_lock:
            self.health = health
            self.health_note = display_note
            self._health_evidence = evidence

    @property
    def health_evidence(self) -> Optional[dict[str, object]]:
        """Return an independent JSON-safe copy of the current degradation."""
        with self._health_lock:
            return dict(self._health_evidence) if self._health_evidence else None

    @property
    def health_state(self) -> str:
        """Coarse state used for colour coding."""
        return self.health_summary()[2]

    def health_summary(self) -> tuple[str, int, str]:
        """Return one atomic, allocation-light status/health presentation row.

        High-frequency summary views do not need the full operational contract.
        Reading this tuple once avoids taking the health lock repeatedly while
        also preventing a UI row from combining lifecycle and health values
        observed at different instants.
        """
        with self._health_lock:
            status = str(self._status)
            health = int(self.health)
        if status == "stopped":
            state = "off"
        elif status == "error" or health <= 0:
            state = "failed"
        elif health >= 90:
            state = "ok"
        elif health >= 50:
            state = "degraded"
        else:
            state = "critical"
        return status, health, state

    def self_test(self) -> tuple[bool, str]:
        """Override to actively verify the module works. Default: readiness check.
        Returns (passed, detail)."""
        snapshot = self.operational_snapshot()
        status = str(snapshot["status"])
        health = int(snapshot["health"])
        if status == "running" and health >= 50:
            return True, f"running, health {health}%"
        note = str(snapshot["health_note"] or self.last_error)
        return False, f"status={status}, health={health}%" + (f" — {note}" if note else "")

    def _spawn_generation_locked(self, initial_delay: float) -> None:
        """Start one generation. Caller must hold ``_lifecycle_lock``."""
        self._lifecycle_generation += 1
        generation = self._lifecycle_generation
        stop_event = threading.Event()
        self._stop = stop_event
        self._initial_delay = initial_delay
        self._first_cycle_complete.clear()
        started_at = time.monotonic()
        with self._cycle_lock:
            self._cycle_count = 0
            self._last_cycle_completed_at = 0.0
            self._last_sleep_interval_seconds = 0.0
            self._watchdog_deadline_at = (
                started_at + self._watchdog_startup_budget_seconds()
            )
        self._generation_started_at = started_at
        self._restart_request = None
        thread = threading.Thread(
            target=self._wrapped_run,
            args=(generation, stop_event, initial_delay),
            name=self.name,
            daemon=True,
        )
        self._thread = thread
        self.status = "running"
        thread.start()

    def _await_stopped_generation(self, old_thread: threading.Thread) -> None:
        """Complete a deferred restart after the prior generation exits."""
        old_thread.join()
        with self._lifecycle_lock:
            if self._restart_waiter is threading.current_thread():
                self._restart_waiter = None
            if self._thread is not old_thread:
                return
            request = self._restart_request
            if request is None or request[0] != self._lifecycle_serial:
                return
            self._spawn_generation_locked(request[1])

    def _ensure_restart_waiter_locked(self, old_thread: threading.Thread) -> None:
        waiter = self._restart_waiter
        if waiter is not None and waiter.is_alive():
            return
        waiter = threading.Thread(
            target=self._await_stopped_generation,
            args=(old_thread,),
            name=f"{self.name}-restart",
            daemon=True,
        )
        self._restart_waiter = waiter
        waiter.start()

    def start(self, initial_delay: float = 0.0) -> None:
        """Start the module, or safely restart an exiting generation.

        A normal duplicate ``start()`` is still a no-op. If ``stop()`` has
        already signalled a live generation, wait briefly for its interruptible
        loop to finish. A slow blocking operation never holds the caller beyond
        the bounded join: one daemon waiter starts the requested generation only
        after the old main thread (and its generation-owned helpers) has exited.
        """
        delay = max(0.0, float(initial_delay))
        with self._lifecycle_lock:
            old_thread = self._thread
            if old_thread is None or not old_thread.is_alive():
                self._lifecycle_serial += 1
                self._spawn_generation_locked(delay)
                return
            if not self._stop.is_set():
                return
            self._lifecycle_serial += 1
            request_serial = self._lifecycle_serial
            self._restart_request = (request_serial, delay)
            self.status = "restarting"

        # Never join ourselves. The deferred waiter is safe for the uncommon
        # case where a module requests its own restart.
        if old_thread is not threading.current_thread():
            old_thread.join(timeout=max(0.0, float(self._RESTART_JOIN_TIMEOUT)))

        with self._lifecycle_lock:
            if self._thread is not old_thread:
                return
            request = self._restart_request
            if request is None or request[0] != request_serial:
                return
            if not old_thread.is_alive():
                self._spawn_generation_locked(request[1])
                return
            self._ensure_restart_waiter_locked(old_thread)

    def restart_if_generation(
        self,
        expected_generation: int,
        initial_delay: float = 0.0,
    ) -> bool:
        """Atomically request a restart of exactly one observed generation.

        A watchdog decision is necessarily made from an earlier snapshot.  A
        plain ``stop(); start()`` can therefore kill a healthy replacement or
        revive a module an operator disabled in the meantime.  This compare-
        and-restart primitive binds the request to the observed generation and
        uses the existing serial cancellation contract, so any newer lifecycle
        action wins.  ``True`` means the exact restart was accepted (possibly
        by the bounded deferred waiter), never that an unrelated generation was
        restarted.
        """
        return self._restart_generation(expected_generation, initial_delay, only_if_faulted=False)

    def restart_faulted_generation(self, expected_generation: int) -> bool:
        """Signal a restart only if the observed generation is still faulty."""
        return self._restart_generation(expected_generation, 0.0, only_if_faulted=True)

    def _restart_generation(
        self, expected_generation: int, initial_delay: float, *, only_if_faulted: bool,
    ) -> bool:
        delay = max(0.0, float(initial_delay))
        if not self._lifecycle_lock.acquire(blocking=not only_if_faulted):
            return False
        try:
            if self._lifecycle_generation != int(expected_generation):
                return False
            old_thread = self._thread
            if old_thread is None:
                return False
            # Order the fault check and stop signal against a worker's fresh
            # cycle or status publication, as well as competing lifecycle actions.
            with self._cycle_lock, self._health_lock:
                if only_if_faulted and watchdog_fault_kind(self.operational_snapshot()) is None:
                    return False
                self._lifecycle_serial += 1
                request_serial = self._lifecycle_serial
                self._restart_request = (request_serial, delay)
                self._stop.set()
                self.status = "restarting"
        finally:
            self._lifecycle_lock.release()

        if old_thread is not threading.current_thread():
            old_thread.join(timeout=max(0.0, float(self._RESTART_JOIN_TIMEOUT)))

        with self._lifecycle_lock:
            if self._thread is not old_thread:
                return False
            request = self._restart_request
            if (
                request is None
                or request[0] != request_serial
                or self._lifecycle_generation != int(expected_generation)
            ):
                return False
            if not old_thread.is_alive():
                self._spawn_generation_locked(request[1])
            else:
                self._ensure_restart_waiter_locked(old_thread)
            return True

    def stop(self) -> None:
        """Signal the active generation and return without waiting for it."""
        with self._lifecycle_lock:
            self._lifecycle_serial += 1
            self._restart_request = None
            self._stop.set()
            self.status = "stopped"

    # ── Helpers available to subclasses ─────────────────────────────────────
    @property
    def stopping(self) -> bool:
        return self.generation_stop_event().is_set()

    def generation_stop_event(self) -> threading.Event:
        """Return the immutable stop token for the calling run generation.

        The module's main thread receives a thread-local token. Helper threads
        should capture this value in ``run()`` and receive it explicitly; they
        must not consult the mutable ``self._stop`` after a restart.
        """
        return getattr(self._run_context, "stop_event", self._stop)

    @property
    def lifecycle_generation(self) -> int:
        """Monotonic generation identifier, useful for diagnostics/tests."""
        return self._lifecycle_generation

    def sleep(
        self, seconds: float, *, cycle_complete: bool = True,
        _wake_event: threading.Event | None = None,
        _background_pacing: bool = True,
    ) -> None:
        """Interruptible sleep — returns early if the module is stopping.

        The wait is scaled by ``self._throttle`` (default 1.0). The Adaptive
        Resource Governor raises this multiplier for heavy, non-security-critical
        modules when the host is under load, so their poll loops run less often
        (lower CPU) automatically — in both Eco and normal mode — and relaxes it
        back to 1.0 when things are idle. Modules that use ``self.sleep()`` for
        their loop cadence get this for free. A reviewed one-shot work retry
        may omit discretionary background pacing; the cadence multiplier,
        including its persistent Chill floor, still applies."""
        # Most legacy loops sleep after completing a poll/baseline. Sleep-first
        # loops must pass ``cycle_complete=False`` and explicitly publish the
        # boundary after their work; otherwise startup could attest readiness
        # before a sensor had observed anything.
        with self._throttle_lock:
            if self._priority_throttle_until and time.monotonic() >= self._priority_throttle_until:
                self._priority_throttle = 1.0
                self._priority_throttle_until = 0.0
            throttle = max(float(self._throttle), self._priority_throttle)
        wait_seconds = max(0.0, float(seconds)) * throttle
        if (
            _background_pacing
            and type(self).__dict__.get("background_pacing_allowed") is True
        ):
            # Independent cosmetic/governor settings never disable this policy.
            # Use the larger wait, not a product of two independent governors.
            wait_seconds = max(wait_seconds, self.background_interval(seconds))
        if cycle_complete:
            self.mark_cycle_complete(interval_seconds=wait_seconds)
        else:
            # Sleep-first loops publish their boundary explicitly after work.
            # Extending an already-proven generation across this declared wait
            # prevents the supervisor from treating intentional idle time as a
            # hang, while the fixed work budget still bounds the next cycle.
            now = time.monotonic()
            with self._cycle_lock:
                self._last_sleep_interval_seconds = wait_seconds
                if self._cycle_count > 0:
                    self._watchdog_deadline_at = (
                        now + wait_seconds + self._watchdog_work_budget_seconds()
                    )
        stop_event = self.generation_stop_event()
        if _wake_event is None:
            stop_event.wait(timeout=wait_seconds)
        else:
            # A local hint may shorten idle time, never attest completed work.
            # Retain this generation's immutable stop token; stop still wakes
            # immediately. Only opted-in workers pay the bounded hint checks.
            deadline = time.monotonic() + wait_seconds
            while not stop_event.is_set() and not _wake_event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                stop_event.wait(timeout=min(0.25, remaining))
        pacer = getattr(self._run_context, "routine_pacer", None)
        if pacer is not None:
            pacer.resume()

    def background_interval(self, seconds: float) -> float:
        """Pace an explicitly routine interval only in its running worker.

        Direct self-tests, response calls and GUI work do not inherit the wait.
        Mixed workers can opt in only a specific inventory interval with this
        helper, leaving their event-consumption and fast-response loops alone.
        """
        base = max(0.0, float(seconds))
        if self._thread is not threading.current_thread():
            return base
        from angerona.core.background_pacing import get_pacing_controller
        return get_pacing_controller().interval(base)

    def background_checkpoint(self, completed: int, *, batch_size: int = 32) -> bool:
        """Yield between routine batches without dropping work or marking ready.

        Returns false when this generation stopped. Callers keep their existing
        interrupted/incomplete-coverage path; no successful receipt is implied.
        """
        stop_event = self.generation_stop_event()
        if stop_event.is_set():
            return False
        if self._thread is not threading.current_thread():
            return True
        pacer = getattr(self._run_context, "routine_pacer", None)
        if pacer is None:
            from angerona.core.background_pacing import RoutineWorkPacer
            pacer = self._run_context.routine_pacer = RoutineWorkPacer()
        delay = pacer.pause_seconds(completed, batch_size=batch_size)
        if delay <= 0:
            return True
        started = time.monotonic()
        stopped = stop_event.wait(delay)
        elapsed = time.monotonic() - started
        pacer.resume()
        # Intentional yields are not missing work cycles. Extend only an
        # existing deadline, without advancing readiness or cycle counters.
        with self._cycle_lock:
            if self._watchdog_deadline_at > 0:
                self._watchdog_deadline_at += elapsed
        return not stopped

    def mark_cycle_complete(self, *, interval_seconds: Optional[float] = None) -> None:
        """Publish completion of one module work cycle."""
        now = time.monotonic()
        with self._cycle_lock:
            if interval_seconds is not None:
                self._last_sleep_interval_seconds = max(0.0, float(interval_seconds))
            self._cycle_count += 1
            self._last_cycle_completed_at = now
            self._watchdog_deadline_at = (
                now
                + self._last_sleep_interval_seconds
                + self._watchdog_work_budget_seconds()
            )
            self._first_cycle_complete.set()

    def _watchdog_startup_budget_seconds(self) -> float:
        """Return the bounded first-cycle deadline for this capability."""
        raw = getattr(self, "startup_cycle_timeout", 30.0)
        contract = getattr(self, "_angerona_contract", None)
        if contract is not None:
            raw = getattr(
                getattr(contract, "resource_budget", None),
                "startup_cycle_timeout_seconds",
                raw,
            )
        try:
            seconds = float(raw)
        except (TypeError, ValueError, OverflowError):
            seconds = 30.0
        return max(5.0, min(300.0, seconds))

    def _watchdog_work_budget_seconds(self) -> float:
        """Return a bounded allowance for work between cadence boundaries."""
        try:
            seconds = float(getattr(self, "watchdog_work_budget_seconds", 30.0))
        except (TypeError, ValueError, OverflowError):
            seconds = 30.0
        return max(5.0, min(900.0, seconds))

    def wait_for_first_cycle(self, timeout: Optional[float] = None) -> bool:
        """Wait until this start has completed its first work cycle."""
        return self._first_cycle_complete.wait(timeout=timeout)

    @property
    def first_cycle_complete(self) -> bool:
        return self._first_cycle_complete.is_set()

    def set_throttle(self, multiplier: float) -> None:
        """Set the loop-cadence multiplier (1.0 = normal, higher = slower/lighter).
        Clamped to [1.0, 8.0]. Called by the Adaptive Resource Governor."""
        with self._throttle_lock:
            try:
                requested = max(1.0, min(8.0, float(multiplier)))
                self._throttle = max(self._throttle_floor, requested)
            except (TypeError, ValueError):
                self._throttle = self._throttle_floor

    def set_throttle_floor(self, multiplier: float) -> None:
        """Set a persistent minimum cadence multiplier for Chill Mode.

        The adaptive governor may ask for a faster cadence when CPU load falls;
        it must not undo an operator-selected all-day low-I/O profile.
        """
        with self._throttle_lock:
            try:
                floor = max(1.0, min(8.0, float(multiplier)))
            except (TypeError, ValueError):
                floor = 1.0
            self._throttle_floor = floor
            self._throttle = max(floor, self._throttle)

    def set_priority_throttle(self, multiplier: float, expires_at: float = 0.0,
                              *, blocking: bool = True) -> bool:
        """Set a separate bounded temporary floor; preserve Chill/governor state."""
        requested, expiry = float(multiplier), float(expires_at)
        if (not math.isfinite(requested) or not 1 <= requested <= 8
                or not math.isfinite(expiry) or expiry < 0):
            raise ValueError("Invalid priority cadence lease.")
        if requested > 1 and expiry <= time.monotonic():
            raise ValueError("Priority cadence requires a future expiry.")
        if not self._throttle_lock.acquire(blocking=blocking):
            return False
        try:
            self._priority_throttle = requested
            self._priority_throttle_until = expiry if requested > 1 else 0.0
            return True
        finally:
            self._throttle_lock.release()

    def emit(self, message: str, severity: Severity = Severity.INFO, **details) -> None:
        self.publish_event(Event(self.name, message, severity, time.time(), details))

    def publish_event(self, event: Event) -> None:
        if self._bus is not None:
            publisher = getattr(self, "_mesh_publishers", {}).get(event.module)
            if publisher is not None:
                publisher(event)
            else:
                self._bus.publish(event)

    def seed_bus_cursor(self, *, priority: bool = False) -> int:
        """Ignore existing history and begin at the bus's current revision.

        Most detectors intentionally inspect bounded retained history on first
        start. Exporters that must never replay history can call this once after
        binding. A revision is an ordering token only; it carries no trust or
        wall-clock meaning.
        """
        if self._bus is None:
            return 0
        if priority:
            revision = self._bus.priority_revision()
            self._bus_priority_revision = revision
        else:
            revision = self._bus.revision()
            self._bus_revision = revision
        self._bus_cursor_enrolled[priority] = True
        return revision

    def bus_cursor_enrolled(self, *, priority: bool = False) -> bool:
        """Whether this instance already chose/committed a cursor origin."""
        return bool(self._bus_cursor_enrolled.get(priority, False))

    def read_bus_events(
        self, *, priority: bool = False
    ) -> tuple[int, list[Event], bool]:
        """Read, but do not acknowledge, one bounded EventBus delta.

        Durable consumers commit their payloads to an outbox before calling
        :meth:`commit_bus_cursor`. A failed durable write therefore leaves the
        delta replayable. Ordinary detectors can use :meth:`poll_bus_events`,
        which preserves the original immediate-advance behavior.
        """
        if self._bus is None:
            return 0, [], False
        previous = self._bus_priority_revision if priority else self._bus_revision
        if priority:
            revision, newest_first, overflow = self._bus.priority_since(previous)
        else:
            revision, newest_first, overflow = self._bus.recent_since(previous)
        if overflow and self._last_reported_overflow_revision.get(priority) != revision:
            self._last_reported_overflow_revision[priority] = revision
            self._bus_overflow_count += 1
            note = (
                "EventBus retention overflow; one or more events were unavailable "
                "to this polling cycle."
            )
            if self.health > 60:
                self.set_health(60, note)
            elif note not in self.health_note:
                self.set_health(
                    self.health,
                    f"{self.health_note}; {note}".strip("; "),
                )
            self.emit(
                "EventBus evidence gap detected; conclusions remain incomplete.",
                Severity.MEDIUM,
                finding_code="module.eventbus.retention_overflow",
                overflow_count=self._bus_overflow_count,
                priority_lane=priority,
                response_authorized=False,
            )
        return revision, list(reversed(newest_first)), overflow

    def commit_bus_cursor(self, revision: int, *, priority: bool = False) -> None:
        """Advance one cursor after a consumer reaches a durable disposition."""
        try:
            value = max(0, int(revision))
        except (TypeError, ValueError) as exc:
            raise ValueError("event revision must be an integer") from exc
        current = self._bus_priority_revision if priority else self._bus_revision
        if value < current:
            raise ValueError("event revision cannot move backwards")
        if priority:
            self._bus_priority_revision = value
        else:
            self._bus_revision = value
        self._bus_cursor_enrolled[priority] = True

    def poll_bus_events(self, *, priority: bool = False) -> tuple[list[Event], bool]:
        """Return and immediately acknowledge one bounded EventBus delta.

        EventBus delta APIs return newest-first for presentation compatibility.
        Stateful detectors must process the same delta oldest-first, so this
        helper reverses it and advances a monotonic cursor atomically.
        ``overflow`` stays explicit: retained events are returned, but absence
        of a match is no longer complete evidence.
        """
        revision, events, overflow = self.read_bus_events(priority=priority)
        self.commit_bus_cursor(revision, priority=priority)
        return events, overflow

    def try_watchdog_snapshot(self) -> dict[str, object] | None:
        """Bind the watchdog's worker, status and generation to one lifecycle.

        A start or retirement in progress is unknown. A sweep never waits for
        another thread holding the lifecycle lock, which some modules use to
        serialize host operations. Ordinary UI readers keep their existing view.
        """
        if not self._lifecycle_lock.acquire(blocking=False):
            return None
        try:
            with self._cycle_lock, self._health_lock:
                return self.operational_snapshot()
        finally:
            self._lifecycle_lock.release()

    def operational_snapshot(self) -> dict[str, object]:
        """Return a bounded, JSON-safe live contract snapshot for UI and API.

        Every module gets the same lifecycle, freshness, throttle and evidence-
        loss vocabulary. Consumers can therefore distinguish a live thread from
        a capability that has actually completed work, and a healthy result from
        one produced after retained evidence was lost.
        """
        now = time.monotonic()
        thread = self._thread
        thread_alive = bool(thread is not None and thread.is_alive())
        with self._cycle_lock:
            cycle_count = int(self._cycle_count)
            last_completed_at = float(self._last_cycle_completed_at)
            cadence_seconds = float(self._last_sleep_interval_seconds)
            deadline_at = float(self._watchdog_deadline_at)
        last_age = (
            max(0.0, now - last_completed_at)
            if last_completed_at > 0
            else None
        )
        uptime = (
            max(0.0, now - self._generation_started_at)
            if self._generation_started_at > 0 and thread_alive
            else None
        )
        with self._health_lock:
            status = str(self._status)
            health = int(self.health)
            health_note = str(self.health_note)[:_MAX_HEALTH_REASON]
            health_evidence = (
                dict(self._health_evidence) if self._health_evidence else None
            )
            if status == "stopped":
                health_state = "off"
            elif status == "error" or health <= 0:
                health_state = "failed"
            elif health >= 90:
                health_state = "ok"
            elif health >= 50:
                health_state = "degraded"
            else:
                health_state = "critical"
        return {
            "schema": "angerona.module-operational.v12",
            "status": status,
            "health": health,
            "health_state": health_state,
            "health_note": health_note,
            "health_evidence": health_evidence,
            "thread_alive": thread_alive,
            "lifecycle_generation": int(self._lifecycle_generation),
            "generation_uptime_seconds": uptime,
            "first_cycle_complete": self.first_cycle_complete,
            "cycle_count": cycle_count,
            "last_cycle_age_seconds": last_age,
            "declared_cycle_interval_seconds": cadence_seconds,
            "watchdog_liveness_enabled": bool(self.watchdog_liveness_enabled),
            "watchdog_deadline_remaining_seconds": (
                deadline_at - now if deadline_at > 0 and thread_alive else None
            ),
            "watchdog_deadline_missed": bool(
                self.watchdog_liveness_enabled
                and status in {"running", "restarting"}
                and thread_alive
                and deadline_at > 0
                and now > deadline_at
            ),
            "throttle_multiplier": float(self._throttle),
            "throttle_floor": float(self._throttle_floor),
            "priority_throttle_multiplier": float(self._priority_throttle)
                if self._priority_throttle_until > now else 1.0,
            "event_revision": int(self._bus_revision),
            "priority_event_revision": int(self._bus_priority_revision),
            "event_overflow_count": int(self._bus_overflow_count),
            "crash_count": int(self._crash_count),
            "last_crash_age_seconds": (
                max(0.0, now - self._last_crash_at) if self._last_crash_at > 0 else None
            ),
        }

    # ── Implement this ──────────────────────────────────────────────────────
    def run(self) -> None:
        raise NotImplementedError

    # ── Internal ────────────────────────────────────────────────────────────
    def _wrapped_run(
        self,
        generation: int,
        stop_event: threading.Event,
        initial_delay: float,
    ) -> None:
        """Fault-isolated run wrapper with 3-try throttled restart and crash snapshot.

        On each unhandled exception:
          attempt 1 → emit HIGH, wait 5s, restart
          attempt 2 → emit HIGH, wait 30s, restart
          attempt 3 → write diagnostic bundle, emit CRITICAL, quarantine module

        The bus and all other modules keep running regardless.
        """
        # First-poll stagger: at boot the manager gives each module a small,
        # increasing delay so ~40 sensor threads don't all fire their first
        # (often full process/connection scan) at t=0 — that simultaneous burst
        # is what made the window unresponsive right after launch. Interruptible
        # so stop() during the delay still exits cleanly.
        self._run_context.generation = generation
        self._run_context.stop_event = stop_event
        if initial_delay:
            wake = self._startup_wake_event
            if wake is None:
                stop_event.wait(timeout=initial_delay)
            else:
                deadline = time.monotonic() + initial_delay
                while not stop_event.is_set() and not wake.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    stop_event.wait(timeout=min(0.25, remaining))
            if stop_event.is_set():
                return
        for attempt in range(_MAX_RESTARTS):
            try:
                self.run()
                if stop_event.is_set():
                    return
                self.status = "error"
                self.set_health(0, "Module worker returned before stop was requested")
                self.emit(
                    "Module worker exited unexpectedly; capability is no longer live.",
                    Severity.HIGH,
                    finding_code="module.lifecycle.unexpected_exit",
                    response_authorized=False,
                )
                return
            except Exception as exc:
                tb = traceback.format_exc()
                self.last_error = str(exc)
                self._crash_count += 1
                self._last_crash_at = time.monotonic()

                if attempt < _MAX_RESTARTS - 1:
                    delay = _RESTART_DELAYS[attempt]
                    self.status = "restarting"
                    self.set_health(30, f"Crashed (attempt {attempt + 1}): {exc}")
                    self.emit(
                        f"Module crashed (attempt {attempt + 1}/{_MAX_RESTARTS}), "
                        f"restarting in {delay}s: {exc}",
                        Severity.HIGH,
                        traceback=tb[:500],
                    )
                    # Interruptible delay — respect stop() during the back-off period
                    stop_event.wait(timeout=delay)
                    if stop_event.is_set():
                        break
                    self.status = "running"
                else:
                    # All retries exhausted — quarantine and snapshot
                    self.status = "error"
                    self.set_health(0, f"Quarantined after {_MAX_RESTARTS} crashes: {exc}")
                    snapshot_outcome = self._write_crash_snapshot(exc, tb)
                    snapshot_note = (
                        "Crash snapshot published in diagnostics/."
                        if snapshot_outcome == "published"
                        else "Crash snapshot published; finalization remains unconfirmed."
                        if snapshot_outcome.startswith("published_")
                        else "Crash snapshot publication held for this process; native file-handle custody is unknown."
                        if snapshot_outcome == "held_custody_unknown"
                        else f"Crash snapshot publication held or unconfirmed ({snapshot_outcome})."
                    )
                    self.emit(
                        f"Module QUARANTINED after {_MAX_RESTARTS} crashes: {exc}. "
                        f"Sensor blind — {snapshot_note}",
                        Severity.CRITICAL,
                        traceback=tb[:500],
                        crash_snapshot_outcome=snapshot_outcome,
                    )

    def _write_crash_snapshot(self, exc: Exception, tb: str) -> str:
        """Publish one bounded authenticated diagnostic copy, preserving loss facts.

        Existing records are never rewritten or deleted. This is an application
        admission budget, not an OS quota, guaranteed reserve, or an enclave
        against an attacker controlling this user's process. Upstream exception
        formatting and native calls are outside the encoded-record bound.
        """
        if _CRASH_SNAPSHOT_CUSTODY_UNKNOWN is not None:
            return "held_custody_unknown"
        try:
            memory_available = True
            try:
                import psutil
                process = psutil.Process()
                mi = process.memory_info()
                mem = {
                    "rss_mb": round(mi.rss / 1024 / 1024, 2),
                    "vms_mb": round(mi.vms / 1024 / 1024, 2),
                    "percent": round(process.memory_percent(), 2),
                }
                if any(_snapshot_number(value) is None for value in mem.values()):
                    raise ValueError("memory sample unavailable")
            except Exception:
                mem = {"note": "psutil unavailable"}
                memory_available = False
            try:
                recent = self._bus.recent(50) if self._bus is not None else None
            except Exception:
                recent = None
            # _wrapped_run already captured the original exception text. Avoid
            # invoking arbitrary exception __str__ again in the capture path.
            error = self.last_error if type(self.last_error) is str else None
            bundle = _bounded_crash_snapshot_bundle(
                module=self.name, error=error, tb=tb, memory=mem,
                memory_available=memory_available, events=recent, crashed_at=time.time(),
            )
            document = sign_crash_snapshot_bundle(bundle)
            encoded = json.dumps(
                document, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded) > _MAX_CRASH_RECORD_BYTES:
                return "held_capture_bound"
            return _publish_crash_snapshot_bytes(_get_snapshot_dir(), encoded)
        except _SnapshotCaptureError:
            return "held_capture_text"
        except _SnapshotStorageHeld as capture_error:
            return str(capture_error)
        except Exception:
            # A small fixed result cannot hide the original exception behind a
            # new serialization/path failure or copy exception text into status.
            return "held_capture"
