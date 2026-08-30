r"""Ransomware Heuristics — G2-C.

Detects T1486 (Data Encrypted for Impact) through two complementary signals:

1. Shannon Entropy scan
   Reads every eligible file in watched directories without trusting mutable
   timestamps as an admission decision.  Files up to the explicit full-file
   bound are streamed in their entirety.  Larger files use identity-keyed,
   per-process unpredictable start/middle/end and strided ranges and are
   reported as incomplete coverage (never health 100).
   Declared packed formats remain in entropy scoring unless a future explicit,
   authenticated operator approval is implemented.  Magic bytes and repeated
   automated observations are descriptive evidence, never exclusion authority.

2. Rename-rate tracker
   Ransomware renames files en masse (often appending a custom extension).
   We watch a set of canary directories and record how many renames happen
   per 10-second window.  If the rate exceeds RENAME_THRESHOLD the module
   emits a HIGH alert; recent high-entropy evidence promotes it to CRITICAL and
   authorizes Maximum-mode host isolation.

Why Shannon entropy?
   Text, executables, and most documents have entropy ≤ 7.5 bits/byte.
   AES-256 (CTR/CBC) and ChaCha20 output is statistically indistinguishable
   from uniform random — entropy ≥ 7.9 bits/byte.  The threshold is tunable.

Watched paths (default):
   User profile sub-folders most targeted by ransomware:
   %USERPROFILE%\Documents, Desktop, Pictures, Downloads, Videos, Music

False positive mitigations:
   - Packed-format metadata is reported but never silently excluded.
   - Files smaller than MIN_FILE_BYTES (4096) skipped.
   - Per-file dedup: once a file is flagged it won't fire again for DEDUP_TTL.
"""
from __future__ import annotations

import ctypes
import hashlib
import heapq
import hmac
import json
import math
import os
import secrets
import stat
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Deque, Iterator, List

from angerona.core.module_base import BaseModule, Severity
from angerona.core.data_paths import data_dir
from angerona.core.durable_outbox import load_or_create_outbox_key
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError
from angerona.core.response_contract import deception_response, maximum_host_response

# ── GIL relief for the hot entropy path ───────────────────────────────────────
# Shannon entropy is computed on the first 64 KB of every recently-modified file
# in every watched directory, every scan tick. The old implementation counted
# bytes in a pure-Python ``for`` loop — 64 K iterations per file, all holding the
# GIL, which is exactly the kind of steady CPU load that starves the response
# path on a busy host. We build the 256-bin byte histogram with NumPy when it's
# available (one pass in C; the buffer work releases the GIL), and fall back to
# ``collections.Counter`` (whose element count runs in C via _collections) when
# it isn't. Either path holds the GIL far less than the per-byte loop did.
try:
    import numpy as _np
    _HAVE_NUMPY = True
except Exception:  # pragma: no cover - environment dependent
    _np = None
    _HAVE_NUMPY = False

# ── Tuning constants ──────────────────────────────────────────────────────────
ENTROPY_THRESHOLD = 7.9          # bits/byte; below this is almost never ransomware
MIN_FILE_BYTES    = 4096         # ignore tiny files (scripts, ini, etc.)
# Retained as a compatibility/tuning export.  It is deliberately not an
# admission authority: an attacker can restore last-write timestamps.
MTIME_WINDOW      = 120.0
SAMPLE_BYTES      = 65536        # one bounded range; not a completeness claim
CONTENT_FULL_FILE_MAX_BYTES = 8 * 1024 * 1024
CONTENT_RANGE_COUNT = 9
CONTENT_SCAN_MAX_BYTES = 64 * 1024 * 1024
CONTENT_WINDOW_BYTES = 64 * 1024
CONTENT_STRIDED_ALERT_FRACTION = 0.25
CHANGE_STATE_SCHEMA = "angerona.ransomware-content-state.v2"
CHANGE_STATE_LEGACY_SCHEMA = "angerona.ransomware-content-state.v1"
CHANGE_WITNESS_SCHEMA = "angerona.ransomware-content-witness.v1"
CHANGE_TRANSITION_SCHEMA = "angerona.ransomware-content-transition.v1"
CHANGE_STATE_MAX_RECORDS = 50_000
CHANGE_STATE_MAX_BYTES = 16 * 1024 * 1024
CHANGE_WITNESS_MAX_BYTES = 4096
CHANGE_TRANSITION_MAX_BYTES = 4096
CHANGE_AUTHORITY_MAX_DEPTH = 64
CHANGE_GENESIS_SCHEMA = "angerona.ransomware-content-genesis.v1"
CHANGE_GENESIS_MAX_BYTES = 1024
_CHANGE_TRANSITION_CONTEXT = b"angerona-ransomware-content-transition-v1\0"
RENAME_THRESHOLD  = 20           # renames per 10-second window → CRITICAL
RENAME_WINDOW_S   = 10.0         # rename-rate measurement window
DEDUP_TTL         = 300.0        # re-alert suppression per file (seconds)
TRAVERSAL_MAX_DEPTH = 12         # refuse attacker-controlled recursive depth
TRAVERSAL_MAX_FILES = 25_000     # per watched root and scan tick
TRAVERSAL_MAX_DIRS = 4_096       # bounds empty-directory fan-out and stack size
TRAVERSAL_MAX_S = 2.0            # wall-clock budget per watched root
DIRECTORY_NEXT_ADMISSION_S = 0.25

_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_ERROR_NO_MORE_FILES = 18
_WINDOWS_EPOCH_OFFSET_S = 11_644_473_600


class _FileTime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("last_access_time", _FileTime),
        ("last_write_time", _FileTime),
        ("volume_serial", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    )


class _FileIdBothDirectoryInfo(ctypes.Structure):
    _fields_ = (
        ("next_entry_offset", ctypes.c_uint32),
        ("file_index", ctypes.c_uint32),
        ("creation_time", ctypes.c_longlong),
        ("last_access_time", ctypes.c_longlong),
        ("last_write_time", ctypes.c_longlong),
        ("change_time", ctypes.c_longlong),
        ("end_of_file", ctypes.c_longlong),
        ("allocation_size", ctypes.c_longlong),
        ("file_attributes", ctypes.c_uint32),
        ("file_name_length", ctypes.c_uint32),
        ("ea_size", ctypes.c_uint32),
        ("short_name_length", ctypes.c_ubyte),
        ("short_name", ctypes.c_wchar * 12),
        ("file_id", ctypes.c_longlong),
        ("file_name", ctypes.c_wchar * 1),
    )


_WIN_DIRECTORY_API: tuple[object, object, object, object] | None = None

_CHANGE_WRITER_GUARD = threading.Lock()
_CHANGE_WRITER_LOCKS: dict[str, threading.RLock] = {}
_CHANGE_WRITER_LOCAL = threading.local()


def _bounded_change_json(
    payload: bytes, *, label: str, max_bytes: int
) -> object:
    """Parse a bounded authority object and normalize recursive parser bombs."""
    if not 0 < len(payload) <= max_bytes:
        raise OSError(f"{label} byte bound is invalid")
    depth = 0
    quoted = False
    escaped = False
    for byte in payload:
        character = chr(byte)
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > CHANGE_AUTHORITY_MAX_DEPTH:
                raise OSError(f"{label} is unreadable: nesting limit exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise OSError(f"{label} is unreadable")
    try:
        return json.loads(payload.decode("ascii"))
    except (
        MemoryError,
        RecursionError,
        json.JSONDecodeError,
        UnicodeError,
        TypeError,
        ValueError,
    ) as exc:
        raise OSError(f"{label} is unreadable") from exc


def _shared_change_writer_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve(strict=False)))
    with _CHANGE_WRITER_GUARD:
        return _CHANGE_WRITER_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _exclusive_change_writer_lease(path: Path) -> Iterator[None]:
    """Serialize one authority, while permitting same-thread recovery calls."""
    key = os.path.normcase(str(path.resolve(strict=False)))
    lock = _shared_change_writer_lock(path)
    if not lock.acquire(blocking=False):
        raise OSError("content-state writer lease is already held")
    depths = getattr(_CHANGE_WRITER_LOCAL, "depths", None)
    if depths is None:
        depths = {}
        _CHANGE_WRITER_LOCAL.depths = depths
    depth = int(depths.get(key, 0))
    if depth:
        depths[key] = depth + 1
        try:
            yield
        finally:
            depths[key] -= 1
            lock.release()
        return
    try:
        with ExclusiveFileLease(path):
            depths[key] = 1
            try:
                yield
            finally:
                depths.pop(key, None)
    except ExclusiveFileLeaseError as exc:
        raise OSError("content-state writer lease is unavailable") from exc
    finally:
        lock.release()


@dataclass(frozen=True)
class _TreeFile:
    path: str
    relative: str
    size: int
    modified: float
    modified_identity: int
    identity: tuple[str, int, int]
    root_path: str
    root_identity: tuple[str, int, int]
    sample_entropy: float | None
    sample_sha256: str | None
    sample_size: int
    sample_ranges: tuple[tuple[int, int], ...]
    content_complete: bool
    high_entropy_fraction: float
    declared_format_verified: bool
    change_transition: str


@dataclass(frozen=True)
class _EntropyCandidate:
    path: str
    identity: tuple[str, int, int]
    size: int
    modified_identity: int
    root_path: str
    root_identity: tuple[str, int, int]
    sample_entropy: float
    sample_sha256: str
    sample_size: int
    sample_ranges: tuple[tuple[int, int], ...]
    content_complete: bool
    high_entropy_fraction: float


@dataclass(frozen=True)
class _ContentSample:
    entropy: float
    sha256: str
    size: int
    ranges: tuple[tuple[int, int], ...]
    complete: bool
    max_window_entropy: float
    high_entropy_fraction: float
    prefix: bytes


def _windows_directory_api() -> tuple[object, object, object, object]:
    """Return fixed-System32 directory APIs with pointer-safe prototypes."""
    global _WIN_DIRECTORY_API
    if os.name != "nt":
        raise OSError("held Windows directory enumeration is unavailable")
    if _WIN_DIRECTORY_API is None:
        kernel = ctypes.WinDLL(
            "kernel32.dll", use_last_error=True, winmode=0x00000800
        )
        create_file = kernel.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        get_basic = kernel.GetFileInformationByHandle
        get_basic.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        get_basic.restype = ctypes.c_int
        get_extended = kernel.GetFileInformationByHandleEx
        get_extended.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        get_extended.restype = ctypes.c_int
        close_handle = kernel.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        _WIN_DIRECTORY_API = (create_file, get_basic, get_extended, close_handle)
    return _WIN_DIRECTORY_API

# File extensions that can legitimately be high entropy.  These values are
# descriptive only.  Neither a suffix, bounded magic bytes, nor an automated
# unchanged observation grants exclusion authority.
_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv",
    ".mp3", ".aac", ".flac", ".ogg", ".opus",
    ".pdf",
    ".docx", ".xlsx", ".pptx",  # already zipped internally
})

_FORMAT_MAGIC: dict[str, tuple[bytes, ...]] = {
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ".docx": (b"PK\x03\x04",),
    ".xlsx": (b"PK\x03\x04",),
    ".pptx": (b"PK\x03\x04",),
    ".gz": (b"\x1f\x8b",),
    ".bz2": (b"BZh",),
    ".xz": (b"\xfd7zXZ\x00",),
    ".7z": (b"7z\xbc\xaf\x27\x1c",),
    ".rar": (b"Rar!\x1a\x07",),
    ".zst": (b"\x28\xb5\x2f\xfd",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".pdf": (b"%PDF-",),
    ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
    ".flac": (b"fLaC",),
    ".ogg": (b"OggS",),
}


def _declared_packed_format_verified(extension: str, prefix: bytes) -> bool:
    """Return True only for a narrow suffix+magic agreement.

    Container formats whose identifying bytes are not at offset zero remain
    unproved and are scanned.  RIFF/ISO-media prefixes are intentionally not
    blanket trusted because the subtype lives later in the header.
    """
    extension = extension.lower()
    if extension == ".webp":
        return len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"WEBP"
    if extension == ".avi":
        return len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"AVI "
    if extension in {".mp4", ".mov", ".heic"}:
        return len(prefix) >= 12 and prefix[4:8] == b"ftyp"
    if extension == ".mkv":
        return prefix.startswith(b"\x1aE\xdf\xa3")
    signatures = _FORMAT_MAGIC.get(extension, ())
    return bool(signatures and any(prefix.startswith(item) for item in signatures))


def _byte_histogram(data: bytes):
    """256-bin byte-frequency histogram, computed off the pure-Python slow path.

    NumPy path does the whole count in one C pass (releasing the GIL for the
    buffer→bincount work) — measured ~4× faster than the per-byte Python loop,
    so it holds the GIL a quarter as long per file. When NumPy isn't installed
    we fall back to the original tight loop, which benchmarks as the fastest
    pure-Python option (bytes.count×256 and Counter both tested slower), so the
    no-NumPy path is never a regression versus the previous code."""
    if _HAVE_NUMPY:
        return _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256)
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return counts


def _shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of *data* in bits per byte (0.0–8.0).

    Only the final reduction over the 256 fixed bins stays in Python (constant
    work); the expensive per-byte counting is delegated to _byte_histogram so it
    no longer holds the GIL for the length of the file sample."""
    n = len(data)
    if not n:
        return 0.0
    return _entropy_from_histogram(_byte_histogram(data), n)


def _entropy_from_histogram(counts, n: int) -> float:
    """Return entropy from a bounded 256-bin histogram."""
    if not n:
        return 0.0
    inv_n = 1.0 / n
    ent = 0.0
    for c in counts:
        if c:
            p = c * inv_n
            ent -= p * math.log2(p)
    return ent


def _default_watch_dirs() -> List[Path]:
    home = Path.home()
    candidates = [
        home / "Documents",
        home / "Desktop",
        home / "Pictures",
        home / "Downloads",
        home / "Videos",
        home / "Music",
    ]
    admitted: list[Path] = []
    for candidate in candidates:
        try:
            info = candidate.lstat()
        except OSError:
            continue
        attributes = int(getattr(info, "st_file_attributes", 0) or 0)
        # Keep an existing redirected candidate in the scan set so the held-root
        # admission check reports it as incomplete.  Silently dropping a Known
        # Folder junction here could otherwise leave aggregate health at 100.
        if (
            stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            admitted.append(candidate)
    return admitted


def _rename_pair_count(disappeared: set[str], appeared: set[str]) -> int:
    """Conservatively pair filename changes that look like ransomware renames.

    Bulk creates or deletes are not renames.  Pair only an appended extension
    (``report.docx`` -> ``report.docx.locked``) or an extension replacement
    with the same stem, and consume each new name at most once.
    """
    available = set(appeared)
    paired = 0
    for old in sorted(disappeared):
        old_folded = old.casefold()
        old_stem = Path(old).stem.casefold()
        match = next((
            new for new in sorted(available)
            if (
                new.casefold().startswith(old_folded + ".")
                or old_folded.startswith(new.casefold() + ".")
                or (old_stem and Path(new).stem.casefold() == old_stem)
            )
        ), None)
        if match is not None:
            available.remove(match)
            paired += 1
    return paired


class RansomwareHeuristicsModule(BaseModule):
    CODE = "RANS"
    NAME = "Ransomware Heuristics"
    name = "Ransomware Heuristics"
    version = "1.13.0"
    description = (
        "Detects ransomware (T1486) via Shannon entropy scanning of recently "
        "modified files and rename-storm rate tracking in user directories."
    )
    category = "Ransomware"

    # Scan interval between directory sweeps (seconds)
    _SCAN_INTERVAL = 10.0

    def __init__(self) -> None:
        super().__init__()
        # (path_str) → last_alert_ts
        self._flagged: dict[str, float] = {}
        # Sliding window of (timestamp, exact directory) rename evidence.
        self._rename_times: Deque[tuple[float, str]] = deque()
        # Filesystem roots traversed through held no-follow directory objects.
        self._watch_dirs: List[Path] = []
        # Previous directory snapshots for rename detection:
        # {dir_str: {name_str: mtime}}
        self._dir_snapshot: dict[str, dict[str, float]] = {}
        self._coverage: dict[str, int | float | bool] = self._empty_coverage()
        # A pathname is never re-enrolled silently.  Once a watched root has a
        # stable object identity, replacement/redirection degrades coverage until
        # the module is explicitly restarted and the configured root is reviewed.
        self._watch_root_identities: dict[str, tuple[str, int, int]] = {}
        self._last_sample_error = ""
        # Offsets for large-file range proofs are not a public fixed bypass
        # surface.  The key lives only for this process; every proof still binds
        # the exact object identity, generation, size, offsets and bytes.
        self._range_key = secrets.token_bytes(32)
        self._change_state_root = data_dir() / "ransomware-heuristics"
        self._change_key_cache: bytes | None = None
        self._change_receipts: dict[str, dict[str, object]] = {}
        self._change_observations: dict[str, dict[str, object]] = {}
        self._change_state_sequence = 0
        self._change_scan_epoch = 0
        self._change_state_head = "0" * 64
        self._change_state_loaded = False
        self._change_cycle_active = False
        self._change_state_fault = ""
        self._change_enrollment_key_cache: bytes | None = None
        self._change_witness_verified = False
        self._change_local_freshness_only = True
        self._change_transition_counts = {
            "unchanged": 0,
            "changed": 0,
            "new": 0,
            "missing": 0,
            "incomplete": 0,
        }
        self._change_alerts_emitted = 0
        self._change_alerts_omitted = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def _change_key_path(self) -> Path:
        return self._change_state_root / "content-state.key"

    def _change_state_path(self) -> Path:
        return self._change_state_root / "content-state.json"

    def _change_enrollment_key_path(self) -> Path:
        # Deliberately outside the replaceable state bundle.  This catches
        # ordinary key+state deletion/re-enrollment and paired state rollback.
        return self._change_state_root.parent / ".ransomware-content-enrollment.key"

    def _change_witness_path(self) -> Path:
        return self._change_state_root.parent / ".ransomware-content-high-water.json"

    def _change_transition_path(self) -> Path:
        return self._change_state_root.parent / ".ransomware-content-transition.json"

    def _change_genesis_path(self) -> Path:
        return self._change_state_root.parent / ".ransomware-content-genesis.json"

    def _change_writer_lease_path(self) -> Path:
        return self._change_state_root.parent / ".ransomware-content.writer.lock"

    @contextmanager
    def _change_writer_lease(self) -> Iterator[None]:
        with _exclusive_change_writer_lease(self._change_writer_lease_path()):
            yield

    def _read_change_genesis_marker(self) -> dict[str, object] | None:
        path = self._change_genesis_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or not 0 < int(before.st_size) <= CHANGE_GENESIS_MAX_BYTES
            ):
                raise OSError("content-state genesis marker is unsafe")
            payload = os.read(descriptor, CHANGE_GENESIS_MAX_BYTES + 1)
            after = os.fstat(descriptor)
            current = os.lstat(path)
            if (
                len(payload) != int(before.st_size)
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or (current.st_dev, current.st_ino)
                != (after.st_dev, after.st_ino)
            ):
                raise OSError("content-state genesis marker changed while read")
        finally:
            os.close(descriptor)
        value = _bounded_change_json(
            payload,
            label="content-state genesis marker",
            max_bytes=CHANGE_GENESIS_MAX_BYTES,
        )
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "nonce"}
            or value.get("schema") != CHANGE_GENESIS_SCHEMA
            or not isinstance(value.get("nonce"), str)
            or len(str(value["nonce"])) != 32
            or any(
                character not in "0123456789abcdef"
                for character in str(value["nonce"])
            )
        ):
            raise OSError("content-state genesis marker is unreadable")
        return value

    def _ensure_change_genesis_marker(self) -> None:
        path = self._change_genesis_path()
        if self._read_change_genesis_marker() is not None:
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(
            {"schema": CHANGE_GENESIS_SCHEMA, "nonce": secrets.token_hex(16)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

    def _remove_change_genesis_marker(self) -> None:
        try:
            self._change_genesis_path().unlink()
        except FileNotFoundError:
            pass

    def _change_key(self) -> bytes:
        if self._change_key_cache is None:
            self._change_key_cache = load_or_create_outbox_key(
                self._change_key_path()
            )
        return self._change_key_cache

    def _change_enrollment_key(self) -> bytes:
        if self._change_enrollment_key_cache is None:
            self._change_enrollment_key_cache = load_or_create_outbox_key(
                self._change_enrollment_key_path()
            )
        return self._change_enrollment_key_cache

    def _change_witness_core(
        self, sequence: int, scan_epoch: int, state_head: str
    ) -> dict[str, object]:
        return {
            "schema": CHANGE_WITNESS_SCHEMA,
            "install_id": hashlib.sha256(self._change_enrollment_key()).hexdigest(),
            "sequence": sequence,
            "scan_epoch": scan_epoch,
            "state_hmac": state_head,
        }

    def _change_witness_mac(self, core: dict[str, object]) -> str:
        encoded = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(
            self._change_enrollment_key(), encoded, hashlib.sha256
        ).hexdigest()

    def _write_change_witness(
        self, sequence: int, scan_epoch: int, state_head: str
    ) -> None:
        path = self._change_witness_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        core = self._change_witness_core(sequence, scan_epoch, state_head)
        value = {**core, "hmac_sha256": self._change_witness_mac(core)}
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _read_change_witness(self) -> tuple[int, int, str]:
        path = self._change_witness_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or int(info.st_nlink) != 1
                or not 0 < int(info.st_size) <= CHANGE_WITNESS_MAX_BYTES
            ):
                raise OSError("content-state high-water witness is unsafe")
            payload = os.read(descriptor, CHANGE_WITNESS_MAX_BYTES + 1)
            if len(payload) != int(info.st_size):
                raise OSError("content-state high-water witness changed while read")
            value = _bounded_change_json(
                payload,
                label="content-state high-water witness",
                max_bytes=CHANGE_WITNESS_MAX_BYTES,
            )
            sequence = int(value["sequence"])
            scan_epoch = int(value["scan_epoch"])
            state_head = str(value["state_hmac"])
            supplied = str(value["hmac_sha256"])
        except (
            KeyError,
            MemoryError,
            RecursionError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            raise OSError("content-state high-water witness is unreadable") from exc
        finally:
            os.close(descriptor)
        core = self._change_witness_core(sequence, scan_epoch, state_head)
        if (
            set(value) != {*core, "hmac_sha256"}
            or sequence < 0
            or scan_epoch < sequence
            or len(state_head) != 64
            or any(character not in "0123456789abcdef" for character in state_head)
            or not hmac.compare_digest(self._change_witness_mac(core), supplied)
        ):
            raise OSError("content-state high-water witness authentication failed")
        return sequence, scan_epoch, state_head

    def _change_state_mac(self, core: dict[str, object]) -> str:
        encoded = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(self._change_key(), encoded, hashlib.sha256).hexdigest()

    def _change_state_document(
        self,
        sequence: int,
        records: dict[str, dict[str, object]],
        *,
        scan_epoch: int,
    ) -> tuple[str, bytes]:
        if len(records) > CHANGE_STATE_MAX_RECORDS:
            raise OSError("durable content-state record capacity exceeded")
        ordered = [records[key] for key in sorted(records)]
        core: dict[str, object] = {
            "schema": CHANGE_STATE_SCHEMA,
            "sequence": sequence,
            "scan_epoch": scan_epoch,
            "records": ordered,
        }
        state_head = self._change_state_mac(core)
        payload = json.dumps(
            {**core, "hmac_sha256": state_head},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(payload) > CHANGE_STATE_MAX_BYTES:
            raise OSError("durable content-state byte capacity exceeded")
        return state_head, payload

    def _write_change_state(
        self,
        sequence: int,
        records: dict[str, dict[str, object]],
        *,
        scan_epoch: int,
    ) -> str:
        state_head, payload = self._change_state_document(
            sequence, records, scan_epoch=scan_epoch
        )
        path = self._change_state_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return state_head

    def _change_transition_mac(self, core: dict[str, object]) -> str:
        payload = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(
            self._change_enrollment_key(),
            _CHANGE_TRANSITION_CONTEXT + payload,
            hashlib.sha256,
        ).hexdigest()

    def _write_change_transition(
        self,
        *,
        old_sequence: int,
        old_scan_epoch: int,
        old_state_head: str,
        new_sequence: int,
        new_scan_epoch: int,
        new_state_head: str,
    ) -> None:
        path = self._change_transition_path()
        if path.exists() or path.is_symlink():
            raise OSError("content-state transition is already pending")
        if old_sequence >= 0:
            observed_sequence, observed_epoch, observed_head = (
                self._read_change_witness()
            )
            if (
                observed_sequence != old_sequence
                or observed_epoch != old_scan_epoch
                or not hmac.compare_digest(observed_head, old_state_head)
            ):
                raise OSError(
                    "content-state writer predecessor changed before transition"
                )
        elif self._change_state_path().exists() or self._change_witness_path().exists():
            raise OSError("content-state genesis writer predecessor changed")
        core: dict[str, object] = {
            "schema": CHANGE_TRANSITION_SCHEMA,
            "install_id": hashlib.sha256(
                self._change_enrollment_key()
            ).hexdigest(),
            "old_sequence": old_sequence,
            "old_scan_epoch": old_scan_epoch,
            "old_state_hmac": old_state_head,
            "new_sequence": new_sequence,
            "new_scan_epoch": new_scan_epoch,
            "new_state_hmac": new_state_head,
        }
        if (
            old_sequence < -1
            or old_scan_epoch < -1
            or new_sequence != old_sequence + 1
            or new_scan_epoch != old_scan_epoch + 1
            or (old_sequence == -1) != (old_scan_epoch == -1)
            or (old_sequence >= 0 and old_scan_epoch < old_sequence)
            or new_scan_epoch < new_sequence
            or any(
                len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in (old_state_head, new_state_head)
            )
            or (old_sequence == -1 and old_state_head != "0" * 64)
        ):
            raise OSError("content-state transition values are invalid")
        value = {**core, "hmac_sha256": self._change_transition_mac(core)}
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(payload) > CHANGE_TRANSITION_MAX_BYTES:
            raise OSError("content-state transition exceeds its byte bound")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _read_change_transition(self) -> dict[str, object] | None:
        path = self._change_transition_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or not 0 < int(before.st_size) <= CHANGE_TRANSITION_MAX_BYTES
            ):
                raise OSError("content-state transition object is unsafe")
            payload = os.read(descriptor, CHANGE_TRANSITION_MAX_BYTES + 1)
            after = os.fstat(descriptor)
            if (
                len(payload) != int(before.st_size)
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
            ):
                raise OSError("content-state transition changed while read")
            value = _bounded_change_json(
                payload,
                label="content-state transition",
                max_bytes=CHANGE_TRANSITION_MAX_BYTES,
            )
        except (
            MemoryError,
            RecursionError,
            json.JSONDecodeError,
            UnicodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise OSError("content-state transition is unreadable") from exc
        finally:
            os.close(descriptor)
        fields = {
            "schema",
            "install_id",
            "old_sequence",
            "old_scan_epoch",
            "old_state_hmac",
            "new_sequence",
            "new_scan_epoch",
            "new_state_hmac",
            "hmac_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise OSError("content-state transition schema is invalid")
        core = {key: value[key] for key in fields - {"hmac_sha256"}}
        old_sequence = value["old_sequence"]
        old_epoch = value["old_scan_epoch"]
        new_sequence = value["new_sequence"]
        new_epoch = value["new_scan_epoch"]
        old_head = value["old_state_hmac"]
        new_head = value["new_state_hmac"]
        if (
            value["schema"] != CHANGE_TRANSITION_SCHEMA
            or value["install_id"]
            != hashlib.sha256(self._change_enrollment_key()).hexdigest()
            or type(old_sequence) is not int
            or type(old_epoch) is not int
            or type(new_sequence) is not int
            or type(new_epoch) is not int
            or old_sequence < -1
            or old_epoch < -1
            or new_sequence != old_sequence + 1
            or new_epoch != old_epoch + 1
            or (old_sequence == -1) != (old_epoch == -1)
            or (old_sequence >= 0 and old_epoch < old_sequence)
            or new_epoch < new_sequence
            or not isinstance(old_head, str)
            or not isinstance(new_head, str)
            or any(
                len(item) != 64
                or any(character not in "0123456789abcdef" for character in item)
                for item in (old_head, new_head)
            )
            or (old_sequence == -1 and old_head != "0" * 64)
            or not isinstance(value["hmac_sha256"], str)
            or not hmac.compare_digest(
                self._change_transition_mac(core), value["hmac_sha256"]
            )
        ):
            raise OSError("content-state transition authentication failed")
        return value

    def _remove_change_transition(self) -> None:
        try:
            self._change_transition_path().unlink()
        except FileNotFoundError as exc:
            raise OSError("content-state transition disappeared") from exc

    def _load_change_state(self) -> None:
        with self._change_writer_lease():
            self._load_change_state_under_lease()

    def _load_change_state_under_lease(self) -> None:
        bundle_exists = (
            self._change_key_path().exists(),
            self._change_state_path().exists(),
        )
        witness_exists = (
            self._change_enrollment_key_path().exists(),
            self._change_witness_path().exists(),
        )
        transition_exists = (
            self._change_transition_path().exists()
            or self._change_transition_path().is_symlink()
        )
        if transition_exists and not self._change_enrollment_key_path().exists():
            raise OSError("content-state transition lost its enrollment authority")
        pending = self._read_change_transition()
        genesis_marker = self._read_change_genesis_marker()
        genesis_pending = bool(
            pending is not None
            and pending["old_sequence"] == -1
            and pending["old_scan_epoch"] == -1
            and pending["old_state_hmac"] == "0" * 64
            and pending["new_sequence"] == 0
            and pending["new_scan_epoch"] == 0
        )
        pristine = (
            not any(bundle_exists)
            and not any(witness_exists)
            and pending is None
        )
        if pristine:
            self._ensure_change_genesis_marker()
            genesis_marker = self._read_change_genesis_marker()
        marker_genesis_pending = bool(
            genesis_marker is not None
            and pending is None
            and not bundle_exists[1]
            and not witness_exists[1]
        )
        if (
            any(bundle_exists)
            and not all(bundle_exists)
            and not genesis_pending
            and not marker_genesis_pending
        ):
            raise OSError("durable content-state authority is incomplete")
        if (
            any(witness_exists)
            and not all(witness_exists)
            and not genesis_pending
            and not marker_genesis_pending
        ):
            raise OSError("durable content-state high-water authority is incomplete")
        fresh_authority = pristine or marker_genesis_pending
        if (
            not any(bundle_exists)
            and any(witness_exists)
            and not genesis_pending
            and not marker_genesis_pending
        ):
            raise OSError("durable content-state bundle was deleted after enrollment")
        if fresh_authority:
            self._change_key()
            self._change_enrollment_key()
            state_head, _payload = self._change_state_document(
                0, {}, scan_epoch=0
            )
            self._write_change_transition(
                old_sequence=-1,
                old_scan_epoch=-1,
                old_state_head="0" * 64,
                new_sequence=0,
                new_scan_epoch=0,
                new_state_head=state_head,
            )
            pending = self._read_change_transition()
            genesis_pending = True
        if genesis_pending and not self._change_state_path().exists():
            if not self._change_key_path().exists():
                raise OSError("content-state genesis lost its signing authority")
            expected_head, _payload = self._change_state_document(
                0, {}, scan_epoch=0
            )
            if pending is None or pending["new_state_hmac"] != expected_head:
                raise OSError("content-state genesis transition is inconsistent")
            written = self._write_change_state(0, {}, scan_epoch=0)
            if not hmac.compare_digest(written, expected_head):
                raise OSError("content-state genesis commit changed identity")
        bundle_exists = (
            self._change_key_path().exists(),
            self._change_state_path().exists(),
        )
        witness_exists = (
            self._change_enrollment_key_path().exists(),
            self._change_witness_path().exists(),
        )
        if not all(bundle_exists):
            raise OSError("durable content-state authority is incomplete")
        path = self._change_state_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or int(info.st_nlink) != 1
                or not 0 < int(info.st_size) <= CHANGE_STATE_MAX_BYTES
            ):
                raise OSError("durable content-state object is unsafe")
            payload = os.read(descriptor, CHANGE_STATE_MAX_BYTES + 1)
            if len(payload) != int(info.st_size):
                raise OSError("durable content-state changed while read")
            value = _bounded_change_json(
                payload,
                label="durable content-state",
                max_bytes=CHANGE_STATE_MAX_BYTES,
            )
            schema = str(value["schema"])
            sequence = int(value["sequence"])
            scan_epoch = int(value.get("scan_epoch", sequence))
            rows = value["records"]
            supplied = str(value["hmac_sha256"])
        except (
            KeyError,
            MemoryError,
            RecursionError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            raise OSError("durable content-state is unreadable") from exc
        finally:
            os.close(descriptor)
        if (
            not isinstance(rows, list)
            or len(rows) > CHANGE_STATE_MAX_RECORDS
            or sequence < 0
            or scan_epoch < sequence
            or schema not in {CHANGE_STATE_SCHEMA, CHANGE_STATE_LEGACY_SCHEMA}
        ):
            raise OSError("durable content-state schema is invalid")
        records: dict[str, dict[str, object]] = {}
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "key",
                "identity",
                "path_sha256",
                "size",
                "modified_identity",
                "content_sha256",
                "content_complete",
            }:
                raise OSError("durable content-state record schema is invalid")
            key = str(row["key"])
            identity = row["identity"]
            if (
                len(key) != 64
                or any(character not in "0123456789abcdef" for character in key)
                or not isinstance(identity, list)
                or len(identity) != 3
                or key in records
                or len(str(row["path_sha256"])) != 64
                or len(str(row["content_sha256"])) != 64
                or type(row["content_complete"]) is not bool
                or int(row["size"]) < 0
            ):
                raise OSError("durable content-state record failed validation")
            records[key] = dict(row)
        core: dict[str, object] = {
            "schema": schema,
            "sequence": sequence,
            "records": rows,
        }
        if schema == CHANGE_STATE_SCHEMA:
            core["scan_epoch"] = scan_epoch
        if (
            set(value) != {*core, "hmac_sha256"}
            or any(value.get(key) != expected for key, expected in core.items())
            or not hmac.compare_digest(self._change_state_mac(core), supplied)
        ):
            raise OSError("durable content-state authentication failed")
        if schema == CHANGE_STATE_LEGACY_SCHEMA:
            if pending is not None:
                raise OSError("legacy content-state conflicts with pending transition")
            if any(witness_exists):
                raise OSError("legacy content-state conflicts with enrolled high-water")
            # One-time authenticated migration.  Once v2 exists, witness loss
            # is never treated as legacy or first enrollment again.
            self._change_enrollment_key()
            supplied = self._write_change_state(
                sequence, records, scan_epoch=scan_epoch
            )
            self._write_change_witness(sequence, scan_epoch, supplied)
        elif pending is not None:
            state_is_new = bool(
                sequence == pending["new_sequence"]
                and scan_epoch == pending["new_scan_epoch"]
                and hmac.compare_digest(
                    supplied, str(pending["new_state_hmac"])
                )
            )
            state_is_old = bool(
                int(pending["old_sequence"]) >= 0
                and sequence == pending["old_sequence"]
                and scan_epoch == pending["old_scan_epoch"]
                and hmac.compare_digest(
                    supplied, str(pending["old_state_hmac"])
                )
            )
            if not state_is_new and not state_is_old:
                raise OSError("content-state does not match pending transition")
            witness: tuple[int, int, str] | None = None
            if self._change_witness_path().exists():
                witness = self._read_change_witness()
            if state_is_new:
                witness_is_new = bool(
                    witness is not None
                    and witness[0] == sequence
                    and witness[1] == scan_epoch
                    and hmac.compare_digest(witness[2], supplied)
                )
                witness_is_old = bool(
                    witness is not None
                    and int(pending["old_sequence"]) >= 0
                    and witness[0] == pending["old_sequence"]
                    and witness[1] == pending["old_scan_epoch"]
                    and hmac.compare_digest(
                        witness[2], str(pending["old_state_hmac"])
                    )
                )
                if witness is not None and not witness_is_new and not witness_is_old:
                    raise OSError("content-state witness conflicts with transition")
                if not witness_is_new:
                    self._write_change_witness(sequence, scan_epoch, supplied)
            else:
                if witness is None or (
                    witness[0] != sequence
                    or witness[1] != scan_epoch
                    or not hmac.compare_digest(witness[2], supplied)
                ):
                    raise OSError("content-state predecessor witness is inconsistent")
            self._remove_change_transition()
            witness_exists = (True, True)
        elif not all(witness_exists):
            raise OSError("content-state high-water witness is missing after enrollment")
        witness_sequence, witness_epoch, witness_head = self._read_change_witness()
        if (
            witness_sequence != sequence
            or witness_epoch != scan_epoch
            or not hmac.compare_digest(witness_head, supplied)
        ):
            raise OSError("content-state rollback violates enrolled high-water")
        self._change_receipts = records
        self._change_state_sequence = sequence
        self._change_scan_epoch = scan_epoch
        self._change_state_head = supplied
        self._change_state_loaded = True
        self._change_witness_verified = True
        self._change_state_fault = ""
        if genesis_marker is not None:
            self._remove_change_genesis_marker()

    def _begin_change_cycle(self) -> None:
        self._change_observations = {}
        self._change_cycle_active = self._change_state_loaded
        self._change_transition_counts = {
            "unchanged": 0,
            "changed": 0,
            "new": 0,
            "missing": 0,
            "incomplete": 0,
        }
        self._change_alerts_emitted = 0
        self._change_alerts_omitted = 0

    def _record_change_observation(
        self,
        path: str,
        identity: tuple[str, int, int],
        size: int,
        modified_identity: int,
        sample: _ContentSample,
    ) -> str:
        if not self._change_cycle_active:
            return "untracked"
        path_digest = hashlib.sha256(
            os.path.normcase(os.path.abspath(path)).encode("utf-8", "surrogatepass")
        ).hexdigest()
        identity_value = [identity[0], identity[1], identity[2]]
        key = hashlib.sha256(
            json.dumps(
                [identity_value, path_digest], separators=(",", ":")
            ).encode("ascii")
        ).hexdigest()
        if len(self._change_observations) >= CHANGE_STATE_MAX_RECORDS:
            raise OSError("durable content-state observation capacity exceeded")
        observation: dict[str, object] = {
            "key": key,
            "identity": identity_value,
            "path_sha256": path_digest,
            "size": size,
            "modified_identity": modified_identity,
            "content_sha256": sample.sha256,
            "content_complete": sample.complete,
        }
        self._change_observations[key] = observation
        prior = self._change_receipts.get(key)
        if not sample.complete:
            transition = "incomplete"
        elif prior is not None:
            transition = (
                "unchanged"
                if (
                    prior.get("identity") == identity_value
                    and prior.get("path_sha256") == path_digest
                    and int(prior.get("size", -1)) == size
                    and prior.get("content_complete") is True
                    and hmac.compare_digest(
                        str(prior.get("content_sha256", "")), sample.sha256
                    )
                )
                else "changed"
            )
        else:
            same_object_or_path = any(
                row.get("identity") == identity_value
                or row.get("path_sha256") == path_digest
                for row in self._change_receipts.values()
            )
            transition = "changed" if same_object_or_path else "new"
        self._change_transition_counts[transition] += 1
        if transition == "changed":
            if self._change_alerts_emitted < 64:
                self.emit(
                    "Authenticated ransomware content transition detected",
                    Severity.HIGH,
                    path=path,
                    transition="changed",
                    identity_bound=True,
                    path_sha256=path_digest,
                    previous_receipt=True,
                    content_complete=sample.complete,
                    high_entropy_fraction=round(sample.high_entropy_fraction, 4),
                    mitre_tags=["T1486"],
                    active_attack=True,
                    detector_policy="authenticated-content-transition",
                    **deception_response(),
                )
                self._change_alerts_emitted += 1
            else:
                self._change_alerts_omitted += 1
        return transition

    def _commit_change_cycle(self, *, complete: bool) -> None:
        with self._change_writer_lease():
            self._commit_change_cycle_under_lease(complete=complete)

    def _commit_change_cycle_under_lease(self, *, complete: bool) -> None:
        if not self._change_cycle_active:
            return
        self._change_cycle_active = False
        witness_sequence, witness_epoch, witness_head = self._read_change_witness()
        if (
            witness_sequence != self._change_state_sequence
            or witness_epoch != self._change_scan_epoch
            or not hmac.compare_digest(witness_head, self._change_state_head)
        ):
            raise OSError("content-state changed under another writer")
        if complete:
            missing = set(self._change_receipts) - set(self._change_observations)
            self._change_transition_counts["missing"] = len(missing)
            records = self._change_observations
            if missing and self._change_state_sequence > 0:
                self.emit(
                    "Authenticated ransomware content-state objects are missing",
                    Severity.HIGH,
                    transition="missing",
                    missing_count=len(missing),
                    exact_receipts=True,
                    mitre_tags=["T1486"],
                    active_attack=True,
                    detector_policy="authenticated-content-transition",
                    **deception_response(),
                )
        else:
            # Incomplete collection never replaces the last complete receipt set,
            # but it still advances the authenticated fair-scan epoch so the same
            # directory-order prefix cannot be starved after every restart.
            records = self._change_receipts
        sequence = self._change_state_sequence + 1
        scan_epoch = self._change_scan_epoch + 1
        expected_head, _payload = self._change_state_document(
            sequence, records, scan_epoch=scan_epoch
        )
        self._write_change_transition(
            old_sequence=self._change_state_sequence,
            old_scan_epoch=self._change_scan_epoch,
            old_state_head=self._change_state_head,
            new_sequence=sequence,
            new_scan_epoch=scan_epoch,
            new_state_head=expected_head,
        )
        state_head = self._write_change_state(
            sequence, records, scan_epoch=scan_epoch
        )
        if not hmac.compare_digest(state_head, expected_head):
            raise OSError("content-state commit changed transition identity")
        self._write_change_witness(sequence, scan_epoch, state_head)
        self._remove_change_transition()
        if complete:
            self._change_receipts = dict(self._change_observations)
        self._change_state_sequence = sequence
        self._change_scan_epoch = scan_epoch
        self._change_state_head = state_head
        self._change_witness_verified = True

    def run(self) -> None:
        try:
            self._load_change_state()
        except OSError as exc:
            self._change_state_fault = str(exc)[:240]
        self._watch_dirs = _default_watch_dirs()
        if not self._watch_dirs:
            self.set_health(50, "No watched directories found in user profile")
            self.emit(
                "RansomwareHeuristics: no watchable directories found. "
                "Using Documents/Desktop/etc from %USERPROFILE%.",
                Severity.MEDIUM,
            )
        else:
            dirs_str = ", ".join(str(d) for d in self._watch_dirs)
            self.emit(
                f"Ransomware heuristics active — watching: {dirs_str}",
                Severity.INFO,
                watched_dirs=dirs_str,
            )
            self.set_health(100, "")

        # Seed bounded recursive snapshots so first pass doesn't flood rename alerts.
        seed_coverage = self._empty_coverage()
        self._begin_change_cycle()
        for d in self._watch_dirs:
            _candidates, snapshot, coverage = self._scan_root(d, time.time())
            self._dir_snapshot[self._directory_key(d)] = snapshot
            self._merge_coverage(seed_coverage, coverage)
        self._coverage = seed_coverage
        try:
            self._commit_change_cycle(
                complete=bool(seed_coverage["collection_complete"])
            )
        except OSError as exc:
            self._change_state_fault = str(exc)[:240]
            self._coverage["complete"] = False
            self._coverage["errors"] = int(self._coverage["errors"]) + 1
            self._coverage["last_error"] = self._change_state_fault
        self._update_coverage_health()

        while not self.stopping:
            self.sleep(self._SCAN_INTERVAL)
            self._tick()

    # ── Per-tick logic ────────────────────────────────────────────────────────
    def _tick(self) -> None:
        now = time.time()
        self._begin_change_cycle()
        # Collect exact bounded sample receipts across all watched roots, then
        # score only those identity-bound results. Mutable pathnames are never
        # sent to the optional process pool because it cannot retain filesystem
        # identity.
        candidates: list[_EntropyCandidate] = []
        coverage = self._empty_coverage()
        for directory in self._watch_dirs:
            if self.stopping:
                return
            try:
                root_candidates, snapshot, root_coverage = self._scan_root(
                    directory, now
                )
                candidates.extend(root_candidates)
                self._detect_renames_from_snapshot(directory, snapshot, now)
                self._merge_coverage(coverage, root_coverage)
            except Exception as exc:
                coverage["errors"] = int(coverage["errors"]) + 1
                coverage["skipped"] = int(coverage["skipped"]) + 1
                coverage["complete"] = False
                coverage["collection_complete"] = False
                coverage["last_error"] = str(exc)[:240]

        if candidates and not self.stopping:
            try:
                read_errors = self._evaluate_entropy(candidates, now)
                coverage["errors"] = int(coverage["errors"]) + read_errors
                coverage["skipped"] = int(coverage["skipped"]) + read_errors
                if read_errors:
                    coverage["complete"] = False
                    coverage["collection_complete"] = False
                    coverage["last_error"] = (
                        self._last_sample_error
                        or "entropy sample identity could not be verified"
                    )[:240]
            except Exception as exc:
                coverage["errors"] = int(coverage["errors"]) + len(candidates)
                coverage["skipped"] = int(coverage["skipped"]) + len(candidates)
                coverage["complete"] = False
                coverage["collection_complete"] = False
                coverage["last_error"] = str(exc)[:240]

        self._coverage = coverage
        try:
            self._commit_change_cycle(
                complete=bool(coverage["collection_complete"])
            )
        except OSError as exc:
            self._change_state_fault = str(exc)[:240]
            coverage["complete"] = False
            coverage["errors"] = int(coverage["errors"]) + 1
            coverage["last_error"] = self._change_state_fault
        self._update_coverage_health()
        self._check_rename_rate(now)
        self._evict_stale_dedup(now)

    # ── Entropy scan ──────────────────────────────────────────────────────────
    @staticmethod
    def _empty_coverage() -> dict[str, int | float | bool | str]:
        return {
            "roots": 0,
            "directories": 0,
            "visited": 0,
            "skipped": 0,
            "truncated": 0,
            "errors": 0,
            "content_analyzed": 0,
            "content_incomplete": 0,
            "content_bytes": 0,
            "content_budget_exhausted": 0,
            "unproved_exclusions": 0,
            "eligible_entries": 0,
            "selected_entries": 0,
            "oldest_unseen_epochs": 0,
            "elapsed_ms": 0.0,
            "collection_complete": True,
            "complete": True,
            "last_error": "",
        }

    @staticmethod
    def _directory_key(directory: Path) -> str:
        return os.path.normcase(os.path.abspath(str(directory)))

    @staticmethod
    def _merge_coverage(
        aggregate: dict[str, int | float | bool | str],
        item: dict[str, int | float | bool | str],
    ) -> None:
        for key in (
            "roots",
            "directories",
            "visited",
            "skipped",
            "truncated",
            "errors",
            "content_analyzed",
            "content_incomplete",
            "content_bytes",
            "content_budget_exhausted",
            "unproved_exclusions",
            "eligible_entries",
            "selected_entries",
        ):
            aggregate[key] = int(aggregate[key]) + int(item[key])
        aggregate["oldest_unseen_epochs"] = max(
            int(aggregate["oldest_unseen_epochs"]),
            int(item["oldest_unseen_epochs"]),
        )
        aggregate["elapsed_ms"] = round(
            float(aggregate["elapsed_ms"]) + float(item["elapsed_ms"]), 3
        )
        aggregate["complete"] = bool(aggregate["complete"]) and bool(item["complete"])
        aggregate["collection_complete"] = bool(
            aggregate["collection_complete"]
        ) and bool(item["collection_complete"])
        if item.get("last_error"):
            aggregate["last_error"] = str(item["last_error"])[:240]

    @staticmethod
    def _is_reparse(info: os.stat_result) -> bool:
        attributes = int(getattr(info, "st_file_attributes", 0) or 0)
        return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)

    def _open_held_directory(
        self, path: Path
    ) -> tuple[str, int, tuple[str, int, int]]:
        """Open *path* itself and return a stable directory-object identity."""
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or self._is_reparse(before)
            or not stat.S_ISDIR(before.st_mode)
        ):
            raise OSError("watched directory is a symlink, junction, or reparse point")

        if os.name == "nt":
            create_file, get_basic, _get_extended, close_handle = (
                _windows_directory_api()
            )
            handle = create_file(
                str(path),
                0x0001 | 0x0080,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
                0x0001 | 0x0002,  # share read/write; freeze directory rename
                None,
                3,  # OPEN_EXISTING
                0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if handle in {None, invalid}:
                error = ctypes.get_last_error()
                raise OSError(error, "failed to open watched directory without following it")
            try:
                opened = _ByHandleFileInformation()
                if not get_basic(ctypes.c_void_p(handle), ctypes.byref(opened)):
                    error = ctypes.get_last_error()
                    raise OSError(error, "failed to identify held watched directory")
                file_id = (int(opened.file_index_high) << 32) | int(
                    opened.file_index_low
                )
                after = path.lstat()
                if (
                    int(opened.attributes) & _FILE_ATTRIBUTE_REPARSE_POINT
                    or not int(opened.attributes) & _FILE_ATTRIBUTE_DIRECTORY
                    or self._is_reparse(after)
                    or stat.S_ISLNK(after.st_mode)
                    or int(before.st_ino) != file_id
                    or int(after.st_ino) != file_id
                ):
                    raise OSError("watched directory identity changed while opening")
                return (
                    "win",
                    int(handle),
                    ("win", int(opened.volume_serial), file_id),
                )
            except Exception:
                close_handle(ctypes.c_void_p(handle))
                raise

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            after = path.lstat()
            identity = ("posix", int(opened.st_dev), int(opened.st_ino))
            if (
                not stat.S_ISDIR(opened.st_mode)
                or self._is_reparse(after)
                or stat.S_ISLNK(after.st_mode)
                or ("posix", int(before.st_dev), int(before.st_ino)) != identity
                or ("posix", int(after.st_dev), int(after.st_ino)) != identity
            ):
                raise OSError("watched directory identity changed while opening")
            return "posix", descriptor, identity
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _close_held_directory(kind: str, handle: int) -> None:
        if kind == "win":
            _create, _basic, _extended, close_handle = _windows_directory_api()
            close_handle(ctypes.c_void_p(handle))
        else:
            os.close(handle)

    def _open_held_file(
        self,
        path: Path,
        expected_identity: tuple[str, int, int],
        expected_size: int,
        expected_modified_identity: int,
    ) -> tuple[str, int]:
        """Open one exact no-follow regular file and freeze Windows writers."""
        if os.name == "nt":
            create_file, get_basic, _get_extended, close_handle = (
                _windows_directory_api()
            )
            handle = create_file(
                str(path),
                0x80000000 | 0x0080,  # GENERIC_READ | FILE_READ_ATTRIBUTES
                0x0001,  # share read only; freeze write/rename/delete
                None,
                3,  # OPEN_EXISTING
                0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if handle in {None, invalid}:
                error = ctypes.get_last_error()
                raise OSError(error, "failed to open enumerated file without following it")
            try:
                opened = _ByHandleFileInformation()
                if not get_basic(ctypes.c_void_p(handle), ctypes.byref(opened)):
                    error = ctypes.get_last_error()
                    raise OSError(error, "failed to identify held entropy file")
                file_id = (int(opened.file_index_high) << 32) | int(
                    opened.file_index_low
                )
                identity = ("win", int(opened.volume_serial), file_id)
                size = (int(opened.file_size_high) << 32) | int(
                    opened.file_size_low
                )
                modified = (int(opened.last_write_time.high) << 32) | int(
                    opened.last_write_time.low
                )
                after = path.lstat()
                if (
                    int(opened.attributes) & _FILE_ATTRIBUTE_DIRECTORY
                    or int(opened.attributes) & _FILE_ATTRIBUTE_REPARSE_POINT
                    or self._is_reparse(after)
                    or stat.S_ISLNK(after.st_mode)
                    or int(after.st_ino) != file_id
                    or identity != expected_identity
                    or size != expected_size
                    or modified != expected_modified_identity
                ):
                    raise OSError("enumerated file identity changed before sampling")
                return "win", int(handle)
            except Exception:
                close_handle(ctypes.c_void_p(handle))
                raise

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            after = path.lstat()
            identity = ("posix", int(opened.st_dev), int(opened.st_ino))
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_ISLNK(after.st_mode)
                or self._is_reparse(after)
                or ("posix", int(after.st_dev), int(after.st_ino)) != identity
                or identity != expected_identity
                or int(opened.st_size) != expected_size
                or int(opened.st_mtime_ns) != expected_modified_identity
            ):
                raise OSError("enumerated file identity changed before sampling")
            return "posix", descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _content_ranges(
        self,
        identity: tuple[str, int, int],
        size: int,
        modified_identity: int,
    ) -> tuple[tuple[tuple[int, int], ...], bool]:
        """Return an exact bounded content contract for one file generation."""
        if size <= CONTENT_FULL_FILE_MAX_BYTES:
            return ((0, size),), True
        width = min(SAMPLE_BYTES, size)
        last = max(0, size - width)
        offsets = {0, last, max(0, min(last, (size - width) // 2))}
        seed = (
            f"{identity[0]}|{identity[1]}|{identity[2]}|{size}|"
            f"{modified_identity}"
        ).encode("ascii", "strict")
        counter = 0
        while len(offsets) < CONTENT_RANGE_COUNT and counter < 64:
            block = hmac.new(
                self._range_key,
                seed + counter.to_bytes(2, "big"),
                hashlib.sha256,
            ).digest()
            offset = int.from_bytes(block[:8], "big") % (last + 1)
            # Align to filesystem-sized boundaries without making the chosen
            # range predictable before this process' secret is known.
            offset = min(last, (offset // 4096) * 4096)
            offsets.add(offset)
            counter += 1
        return tuple((offset, width) for offset in sorted(offsets)), False

    @staticmethod
    def _read_content_sample(
        descriptor: int,
        ranges: tuple[tuple[int, int], ...],
        *,
        complete: bool,
    ) -> _ContentSample:
        """Stream and bind every byte in an explicit range contract."""
        digest = hashlib.sha256()
        aggregate_counts = [0] * 256
        aggregate_size = 0
        range_entropies: list[float] = []
        window_entropies: list[tuple[float, int]] = []
        prefix = b""
        for offset, length in ranges:
            if offset < 0 or length <= 0:
                raise ValueError("invalid content-proof range")
            os.lseek(descriptor, offset, os.SEEK_SET)
            remaining = length
            range_counts = [0] * 256
            range_size = 0
            window = bytearray()
            if not complete:
                digest.update(offset.to_bytes(8, "big"))
                digest.update(length.to_bytes(8, "big"))
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    raise OSError("content proof ended before its declared range")
                if offset == 0 and range_size == 0:
                    prefix = bytes(chunk[:32])
                digest.update(chunk)
                counts = _byte_histogram(chunk)
                for index, count in enumerate(counts):
                    value = int(count)
                    range_counts[index] += value
                    aggregate_counts[index] += value
                read_size = len(chunk)
                range_size += read_size
                aggregate_size += read_size
                remaining -= read_size
                window.extend(chunk)
                while len(window) >= CONTENT_WINDOW_BYTES:
                    fixed = bytes(window[:CONTENT_WINDOW_BYTES])
                    del window[:CONTENT_WINDOW_BYTES]
                    window_entropies.append(
                        (_shannon_entropy(fixed), CONTENT_WINDOW_BYTES)
                    )
            if len(window) >= MIN_FILE_BYTES:
                window_entropies.append((_shannon_entropy(bytes(window)), len(window)))
            range_entropies.append(_entropy_from_histogram(range_counts, range_size))
        aggregate_entropy = _entropy_from_histogram(aggregate_counts, aggregate_size)
        max_window_entropy = max(
            (value for value, _size in window_entropies), default=aggregate_entropy
        )
        measured_window_bytes = sum(size for _value, size in window_entropies)
        high_window_bytes = sum(
            size
            for value, size in window_entropies
            if value >= ENTROPY_THRESHOLD
        )
        high_entropy_fraction = (
            high_window_bytes / measured_window_bytes if measured_window_bytes else 0.0
        )
        if complete:
            entropy = (
                max_window_entropy
                if high_entropy_fraction >= CONTENT_STRIDED_ALERT_FRACTION
                else aggregate_entropy
            )
        else:
            entropy = max(max_window_entropy, *range_entropies, 0.0)
        return _ContentSample(
            entropy=entropy,
            sha256=digest.hexdigest(),
            size=aggregate_size,
            ranges=ranges,
            complete=complete,
            max_window_entropy=max_window_entropy,
            high_entropy_fraction=high_entropy_fraction,
            prefix=prefix,
        )

    def _sample_enumerated_file(
        self,
        path: Path,
        expected_identity: tuple[str, int, int],
        expected_size: int,
        expected_modified_identity: int,
    ) -> _ContentSample:
        """Read the explicit proof while exact object identity remains held."""
        kind, handle = self._open_held_file(
            path,
            expected_identity,
            expected_size,
            expected_modified_identity,
        )
        descriptor: int | None = None
        try:
            if kind == "win":
                import msvcrt

                descriptor = msvcrt.open_osfhandle(
                    handle,
                    os.O_RDONLY
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOINHERIT", 0),
                )
                handle = -1
            else:
                descriptor = handle
                handle = -1
            ranges, complete = self._content_ranges(
                expected_identity, expected_size, expected_modified_identity
            )
            sample = self._read_content_sample(
                descriptor, ranges, complete=complete
            )
            after = os.fstat(descriptor)
            if not stat.S_ISREG(after.st_mode) or int(after.st_size) != expected_size:
                raise OSError("held entropy file changed during bounded sampling")
            if kind == "win":
                import msvcrt

                _create, get_basic, _extended, _close = _windows_directory_api()
                verified = _ByHandleFileInformation()
                if not get_basic(
                    ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)),
                    ctypes.byref(verified),
                ):
                    raise OSError("held entropy file post-read identity is unavailable")
                identity = (
                    "win",
                    int(verified.volume_serial),
                    (int(verified.file_index_high) << 32)
                    | int(verified.file_index_low),
                )
                size = (int(verified.file_size_high) << 32) | int(
                    verified.file_size_low
                )
                modified = (int(verified.last_write_time.high) << 32) | int(
                    verified.last_write_time.low
                )
                if (
                    identity != expected_identity
                    or size != expected_size
                    or modified != expected_modified_identity
                ):
                    raise OSError("held entropy file changed during bounded sampling")
            elif (
                ("posix", int(after.st_dev), int(after.st_ino)) != expected_identity
                or int(after.st_mtime_ns) != expected_modified_identity
            ):
                raise OSError("held entropy file changed during bounded sampling")
            return sample
        finally:
            if descriptor is not None:
                os.close(descriptor)
            elif handle != -1:
                self._close_held_directory(kind, handle)

    def _hold_current_candidate(
        self, candidate: _EntropyCandidate
    ) -> tuple[list[tuple[Path, str, int, tuple[str, int, int]]], str, int]:
        """Hold the reviewed ancestry and exact file through publication.

        Windows directory handles intentionally omit delete sharing, so each
        accepted component is immovable while the next component and final file
        are opened.  POSIX callers get the same no-follow component review plus
        a post-read ancestry revalidation.  A mutable absolute pathname is never
        accepted as a substitute for this held chain.
        """
        held_directories: list[tuple[Path, str, int, tuple[str, int, int]]] = []
        file_kind: str | None = None
        file_handle: int | None = None
        try:
            root = Path(os.path.abspath(candidate.root_path))
            path = Path(os.path.abspath(candidate.path))
            relative = path.relative_to(root)
            if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
                raise OSError("entropy candidate escaped its watched root")

            current = root
            root_kind, root_handle, root_identity = self._open_held_directory(root)
            held_directories.append((root, root_kind, root_handle, root_identity))
            if root_identity != candidate.root_identity:
                raise OSError("entropy sample root identity changed")

            # Hold every directory component.  In particular, an intermediate
            # junction cannot redirect the final open to a hard-link alias.
            for component in relative.parts[:-1]:
                current = current / component
                kind, handle, identity = self._open_held_directory(current)
                held_directories.append((current, kind, handle, identity))

            file_kind, file_handle = self._open_held_file(
                path,
                candidate.identity,
                candidate.size,
                candidate.modified_identity,
            )
            self._revalidate_held_ancestry(held_directories)
            return held_directories, file_kind, file_handle
        except Exception:
            if file_kind is not None and file_handle is not None:
                self._close_held_directory(file_kind, file_handle)
            self._close_held_ancestry(held_directories)
            raise

    def _revalidate_held_ancestry(
        self,
        held: list[tuple[Path, str, int, tuple[str, int, int]]],
    ) -> None:
        for path, _kind, _handle, identity in held:
            if not self._reopen_identity_matches(path, identity):
                raise OSError("entropy sample ancestry changed while held")

    def _close_held_ancestry(
        self,
        held: list[tuple[Path, str, int, tuple[str, int, int]]],
    ) -> None:
        while held:
            _path, kind, handle, _identity = held.pop()
            self._close_held_directory(kind, handle)

    def _verify_held_candidate_sample(
        self,
        candidate: _EntropyCandidate,
        file_kind: str,
        file_handle: int,
    ) -> tuple[float, int]:
        """Re-read and authenticate the content proof from the held generation.

        The returned descriptor owns the original Windows handle (or is the
        original POSIX descriptor) and must stay open through event publication.
        """
        descriptor = file_handle
        if file_kind == "win":
            import msvcrt

            descriptor = msvcrt.open_osfhandle(
                file_handle,
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
            )
        try:
            expected_ranges, expected_complete = self._content_ranges(
                candidate.identity, candidate.size, candidate.modified_identity
            )
            if (
                candidate.sample_ranges != expected_ranges
                or candidate.content_complete is not expected_complete
            ):
                raise OSError("entropy content-range contract changed")
            sample = self._read_content_sample(
                descriptor,
                candidate.sample_ranges,
                complete=candidate.content_complete,
            )
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or int(after.st_size) != candidate.size
                or sample.size != candidate.sample_size
                or not math.isclose(
                    sample.high_entropy_fraction,
                    candidate.high_entropy_fraction,
                    rel_tol=0.0,
                    abs_tol=1e-12,
                )
                or not hmac.compare_digest(
                    sample.sha256, candidate.sample_sha256
                )
            ):
                raise OSError("entropy sample content generation changed")
            if file_kind == "win":
                _create, get_basic, _extended, _close = _windows_directory_api()
                verified = _ByHandleFileInformation()
                if not get_basic(
                    ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)),
                    ctypes.byref(verified),
                ):
                    raise OSError("held entropy sample identity is unavailable")
                identity = (
                    "win",
                    int(verified.volume_serial),
                    (int(verified.file_index_high) << 32)
                    | int(verified.file_index_low),
                )
                size = (int(verified.file_size_high) << 32) | int(
                    verified.file_size_low
                )
                if identity != candidate.identity or size != candidate.size:
                    raise OSError("held entropy sample identity changed")
            elif (
                ("posix", int(after.st_dev), int(after.st_ino))
                != candidate.identity
                or int(after.st_mtime_ns) != candidate.modified_identity
            ):
                raise OSError("held entropy sample identity changed")
            return sample.entropy, descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _held_directory_entries(
        self,
        kind: str,
        handle: int,
        current: Path,
        directory_identity: tuple[str, int, int],
    ):
        """Yield metadata obtained from the already-held directory object."""
        if kind == "posix":
            with os.scandir(handle) as iterator:
                for entry in iterator:
                    info = entry.stat(follow_symlinks=False)
                    yield (
                        entry.name,
                        stat.S_ISDIR(info.st_mode),
                        stat.S_ISREG(info.st_mode),
                        entry.is_symlink() or self._is_reparse(info),
                        int(info.st_size),
                        float(info.st_mtime),
                        int(info.st_mtime_ns),
                        ("posix", int(info.st_dev), int(info.st_ino)),
                    )
            return

        _create, _basic, get_extended, _close = _windows_directory_api()
        buffer_size = 64 * 1024
        buffer = ctypes.create_string_buffer(buffer_size)
        information_class = 11  # FileIdBothDirectoryRestartInfo
        name_offset = _FileIdBothDirectoryInfo.file_name.offset
        while True:
            if not get_extended(
                ctypes.c_void_p(handle),
                information_class,
                ctypes.byref(buffer),
                buffer_size,
            ):
                error = ctypes.get_last_error()
                if error == _ERROR_NO_MORE_FILES:
                    return
                raise OSError(error, "held directory enumeration failed")
            information_class = 10  # FileIdBothDirectoryInfo
            offset = 0
            while True:
                if offset < 0 or offset + name_offset > buffer_size:
                    raise OSError("held directory returned malformed metadata")
                item = _FileIdBothDirectoryInfo.from_buffer(buffer, offset)
                name_length = int(item.file_name_length)
                if (
                    name_length <= 0
                    or name_length % 2
                    or offset + name_offset + name_length > buffer_size
                ):
                    raise OSError("held directory returned an invalid file name")
                name = ctypes.wstring_at(
                    ctypes.addressof(buffer) + offset + name_offset,
                    name_length // 2,
                )
                if name not in {".", ".."}:
                    if not name or "\x00" in name or "/" in name or "\\" in name:
                        raise OSError("held directory returned an unsafe file name")
                    attributes = int(item.file_attributes)
                    file_id = int(item.file_id) & ((1 << 64) - 1)
                    yield (
                        name,
                        bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
                        not bool(attributes & _FILE_ATTRIBUTE_DIRECTORY),
                        bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT),
                        max(0, int(item.end_of_file)),
                        float(item.last_write_time) / 10_000_000
                        - _WINDOWS_EPOCH_OFFSET_S,
                        int(item.last_write_time),
                        ("win", directory_identity[1], file_id),
                    )
                next_offset = int(item.next_entry_offset)
                if next_offset == 0:
                    break
                if next_offset < name_offset or offset + next_offset >= buffer_size:
                    raise OSError("held directory returned an invalid entry offset")
                offset += next_offset

    def _reopen_identity_matches(
        self, path: Path, expected: tuple[str, int, int]
    ) -> bool:
        kind: str | None = None
        handle: int | None = None
        try:
            kind, handle, current = self._open_held_directory(path)
            return current == expected
        except OSError:
            return False
        finally:
            if kind is not None and handle is not None:
                self._close_held_directory(kind, handle)

    def _fair_directory_entries(
        self,
        kind: str,
        handle: int,
        current: Path,
        directory_identity: tuple[str, int, int],
        limit: int,
        *,
        deadline: float | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> tuple[list[tuple[object, ...]], bool, int]:
        """Return a bounded keyed reservoir over the complete directory stream.

        Selection happens *while* the full held namespace is enumerated, before
        the traversal budget truncates the chosen view.  The authenticated scan
        epoch changes every cycle, including incomplete cycles, and is mixed
        with a process-private key.  An attacker-controlled enumeration prefix
        therefore has no permanent selection privilege.  Memory remains
        ``O(limit)`` even when the directory itself is much larger.
        """
        if limit <= 0:
            return [], False, 0
        # Python exposes a min-heap.  Negative ranks keep the currently worst
        # (largest) keyed rank at index zero so it can be replaced in O(log n).
        reservoir: list[tuple[int, int, tuple[object, ...]]] = []
        eligible = 0
        interrupted = False
        selection_key = self._change_key_cache or self._range_key
        directory_token = (
            f"{directory_identity[0]}|{directory_identity[1]}|"
            f"{directory_identity[2]}|{self._change_scan_epoch}"
        ).encode("ascii", "strict")
        iterator = self._held_directory_entries(
            kind, handle, current, directory_identity
        )
        try:
            while True:
                # Cancellation and the deadline are admission authorities for
                # requesting the *next* held entry.  Keep a small reserve so a
                # synchronous platform iterator is never started at the edge
                # of its declared budget; an already-running OS call remains a
                # documented platform limit and cannot be pre-empted safely.
                now = time.monotonic()
                admission_reserve = min(
                    DIRECTORY_NEXT_ADMISSION_S,
                    max(0.0, TRAVERSAL_MAX_S / 2.0),
                )
                if (
                    (
                        deadline is not None
                        and deadline - now <= admission_reserve
                    )
                    or (should_stop is not None and should_stop())
                ):
                    interrupted = True
                    break
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                eligible += 1
                identity = entry[7]
                identity_token = (
                    f"{identity[0]}|{identity[1]}|{identity[2]}"
                ).encode("ascii", "strict")
                name = os.path.normcase(str(entry[0])).encode(
                    "utf-8", "surrogatepass"
                )
                digest = hmac.new(
                    selection_key,
                    directory_token + b"\0" + identity_token + b"\0" + name,
                    hashlib.sha256,
                ).digest()
                rank = int.from_bytes(digest[:16], "big")
                tie = int.from_bytes(digest[16:], "big")
                item = (-rank, -tie, entry)
                if len(reservoir) < limit:
                    heapq.heappush(reservoir, item)
                elif item > reservoir[0]:
                    heapq.heapreplace(reservoir, item)
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        selected = [item[2] for item in sorted(reservoir, reverse=True)]
        return selected, interrupted or eligible > limit, eligible

    def _bounded_tree(
        self, directory: Path, now: float
    ) -> tuple[
        list[_TreeFile],
        dict[str, int | float | bool | str],
    ]:
        """Enumerate one root recursively without following reparse points.

        Depth, directory, regular-file and wall-clock limits are independent.
        Any inaccessible, skipped or budget-truncated object is reflected in the
        returned coverage receipt and therefore prevents a 100% health claim.
        """
        started = time.monotonic()
        deadline = started + TRAVERSAL_MAX_S
        root = Path(os.path.abspath(str(directory)))
        rows: list[_TreeFile] = []
        coverage = self._empty_coverage()
        coverage["roots"] = 1
        stack: list[tuple[Path, int, tuple[str, int, int] | None]] = [
            (root, 0, None)
        ]
        stop_for_budget = False
        content_budget_remaining = CONTENT_SCAN_MAX_BYTES
        opened_root_identity: tuple[str, int, int] | None = None

        while stack and not stop_for_budget and not self.stopping:
            if time.monotonic() >= deadline:
                coverage["truncated"] = int(coverage["truncated"]) + max(1, len(stack))
                break
            current, depth, expected_identity = stack.pop()
            kind: str | None = None
            handle: int | None = None
            row_mark = len(rows)
            stack_mark = len(stack)
            try:
                kind, handle, current_identity = self._open_held_directory(current)
                if expected_identity is not None and current_identity != expected_identity:
                    raise OSError("queued directory identity changed before descent")
                if depth == 0:
                    root_key = self._directory_key(root)
                    enrolled = self._watch_root_identities.get(root_key)
                    if enrolled is None:
                        self._watch_root_identities[root_key] = current_identity
                    elif enrolled != current_identity:
                        raise OSError("watched root identity changed after enrollment")
                    opened_root_identity = current_identity
                coverage["directories"] = int(coverage["directories"]) + 1
                remaining_entry_capacity = max(
                    1,
                    TRAVERSAL_MAX_FILES
                    + TRAVERSAL_MAX_DIRS
                    - int(coverage["visited"])
                    - int(coverage["directories"]),
                )
                (
                    directory_entries,
                    directory_truncated,
                    directory_eligible,
                ) = self._fair_directory_entries(
                    kind,
                    handle,
                    current,
                    current_identity,
                    remaining_entry_capacity,
                    deadline=deadline,
                    should_stop=lambda: self.stopping,
                )
                coverage["eligible_entries"] = (
                    int(coverage["eligible_entries"]) + directory_eligible
                )
                coverage["selected_entries"] = (
                    int(coverage["selected_entries"]) + len(directory_entries)
                )
                if directory_truncated:
                    coverage["truncated"] = int(coverage["truncated"]) + 1
                    # A conservative, restart-persistent age: an unselected
                    # object may have waited since the first authenticated scan.
                    coverage["oldest_unseen_epochs"] = max(
                        int(coverage["oldest_unseen_epochs"]),
                        self._change_scan_epoch + 1,
                    )
                for (
                    name,
                    is_directory,
                    is_regular,
                    is_reparse,
                    size,
                    modified,
                    modified_identity,
                    entry_identity,
                ) in directory_entries:
                    if self.stopping:
                        break
                    if time.monotonic() >= deadline:
                        coverage["truncated"] = int(coverage["truncated"]) + 1
                        stop_for_budget = True
                        break
                    child = current / name
                    if is_reparse:
                        coverage["skipped"] = int(coverage["skipped"]) + 1
                        continue
                    if is_directory:
                        if depth >= TRAVERSAL_MAX_DEPTH:
                            coverage["skipped"] = int(coverage["skipped"]) + 1
                            coverage["truncated"] = int(coverage["truncated"]) + 1
                            continue
                        if (
                            int(coverage["directories"]) + len(stack)
                            >= TRAVERSAL_MAX_DIRS
                        ):
                            coverage["skipped"] = int(coverage["skipped"]) + 1
                            coverage["truncated"] = int(coverage["truncated"]) + 1
                            continue
                        stack.append((child, depth + 1, entry_identity))
                        continue
                    if not is_regular:
                        coverage["skipped"] = int(coverage["skipped"]) + 1
                        continue
                    if int(coverage["visited"]) >= TRAVERSAL_MAX_FILES:
                        coverage["truncated"] = int(coverage["truncated"]) + 1
                        stop_for_budget = True
                        break
                    coverage["visited"] = int(coverage["visited"]) + 1
                    if opened_root_identity is None:
                        raise OSError("watched root identity is unavailable")
                    path_str = str(child)
                    sample_entropy: float | None = None
                    sample_sha256: str | None = None
                    sample_size = 0
                    sample_ranges: tuple[tuple[int, int], ...] = ()
                    content_complete = False
                    high_entropy_fraction = 0.0
                    declared_format_verified = False
                    change_transition = "untracked"
                    if size >= MIN_FILE_BYTES:
                        estimated = (
                            size
                            if size <= CONTENT_FULL_FILE_MAX_BYTES
                            else min(size, CONTENT_RANGE_COUNT * SAMPLE_BYTES)
                        )
                        if estimated > content_budget_remaining:
                            coverage["skipped"] = int(coverage["skipped"]) + 1
                            coverage["truncated"] = int(coverage["truncated"]) + 1
                            coverage["content_budget_exhausted"] = (
                                int(coverage["content_budget_exhausted"]) + 1
                            )
                            coverage["last_error"] = (
                                "content-analysis byte budget exhausted"
                            )
                        else:
                            try:
                                sample = self._sample_enumerated_file(
                                    child,
                                    entry_identity,
                                    size,
                                    modified_identity,
                                )
                                sample_entropy = sample.entropy
                                sample_sha256 = sample.sha256
                                sample_size = sample.size
                                sample_ranges = sample.ranges
                                content_complete = sample.complete
                                high_entropy_fraction = sample.high_entropy_fraction
                                declared_format_verified = (
                                    _declared_packed_format_verified(
                                        child.suffix, sample.prefix
                                    )
                                )
                                content_budget_remaining -= sample.size
                                coverage["content_analyzed"] = (
                                    int(coverage["content_analyzed"]) + 1
                                )
                                coverage["content_bytes"] = (
                                    int(coverage["content_bytes"]) + sample.size
                                )
                                if not sample.complete:
                                    coverage["content_incomplete"] = (
                                        int(coverage["content_incomplete"]) + 1
                                    )
                                change_transition = self._record_change_observation(
                                    path_str,
                                    entry_identity,
                                    size,
                                    modified_identity,
                                    sample,
                                )
                            except (OSError, ValueError) as exc:
                                coverage["skipped"] = int(coverage["skipped"]) + 1
                                coverage["errors"] = int(coverage["errors"]) + 1
                                coverage["last_error"] = str(exc)[:240]
                    rows.append(
                        _TreeFile(
                            path=path_str,
                            relative=os.path.relpath(path_str, str(root)),
                            size=size,
                            modified=modified,
                            modified_identity=modified_identity,
                            identity=entry_identity,
                            root_path=str(root),
                            root_identity=opened_root_identity,
                            sample_entropy=sample_entropy,
                            sample_sha256=sample_sha256,
                            sample_size=sample_size,
                            sample_ranges=sample_ranges,
                            content_complete=content_complete,
                            high_entropy_fraction=high_entropy_fraction,
                            declared_format_verified=declared_format_verified,
                            change_transition=change_transition,
                        )
                    )
                # The path must still resolve to the held object after its
                # enumeration.  Otherwise none of its path-derived rows or queued
                # descendants can be claimed as covered.
                if not self._reopen_identity_matches(current, current_identity):
                    del rows[row_mark:]
                    del stack[stack_mark:]
                    raise OSError("directory identity changed during held traversal")
            except OSError as exc:
                coverage["skipped"] = int(coverage["skipped"]) + 1
                coverage["errors"] = int(coverage["errors"]) + 1
                coverage["last_error"] = str(exc)[:240]
            finally:
                if kind is not None and handle is not None:
                    self._close_held_directory(kind, handle)

        coverage["elapsed_ms"] = round((time.monotonic() - started) * 1000.0, 3)
        coverage["collection_complete"] = (
            not self.stopping
            and int(coverage["skipped"]) == 0
            and int(coverage["truncated"]) == 0
            and int(coverage["errors"]) == 0
            and int(coverage["content_incomplete"]) == 0
            and int(coverage["content_budget_exhausted"]) == 0
        )
        coverage["complete"] = bool(coverage["collection_complete"]) and int(
            coverage["unproved_exclusions"]
        ) == 0
        return rows, coverage

    def _scan_root(
        self, directory: Path, now: float
    ) -> tuple[
        list[_EntropyCandidate],
        dict[str, float],
        dict[str, int | float | bool | str],
    ]:
        rows, coverage = self._bounded_tree(directory, now)
        candidates: list[_EntropyCandidate] = []
        snapshot: dict[str, float] = {}
        for row in rows:
            snapshot[row.relative] = row.modified
            if row.size < MIN_FILE_BYTES:
                continue
            if now - self._flagged.get(row.path, 0.0) < DEDUP_TTL:
                continue
            if row.sample_entropy is None or row.sample_sha256 is None:
                continue
            candidates.append(
                _EntropyCandidate(
                    path=row.path,
                    identity=row.identity,
                    size=row.size,
                    modified_identity=row.modified_identity,
                    root_path=row.root_path,
                    root_identity=row.root_identity,
                    sample_entropy=row.sample_entropy,
                    sample_sha256=row.sample_sha256,
                    sample_size=row.sample_size,
                    sample_ranges=row.sample_ranges,
                    content_complete=row.content_complete,
                    high_entropy_fraction=row.high_entropy_fraction,
                )
            )
        return candidates, snapshot, coverage

    def _update_coverage_health(self) -> None:
        coverage = self._coverage
        note = (
            "recursive coverage: "
            f"visited={coverage['visited']}, skipped={coverage['skipped']}, "
            f"truncated={coverage['truncated']}, errors={coverage['errors']}, "
            f"directories={coverage['directories']}, roots={coverage['roots']}, "
            f"content_analyzed={coverage['content_analyzed']}, "
            f"content_bytes={coverage['content_bytes']}, "
            f"content_incomplete={coverage['content_incomplete']}, "
            f"content_budget_exhausted={coverage['content_budget_exhausted']}, "
            f"unproved_exclusions={coverage['unproved_exclusions']}, "
            f"eligible_entries={coverage['eligible_entries']}, "
            f"selected_entries={coverage['selected_entries']}, "
            f"oldest_unseen_epochs={coverage['oldest_unseen_epochs']}, "
            f"change_state_sequence={self._change_state_sequence}, "
            f"change_scan_epoch={self._change_scan_epoch}, "
            f"change_witness_verified={int(self._change_witness_verified)}, "
            "transitions="
            f"unchanged:{self._change_transition_counts['unchanged']},"
            f"changed:{self._change_transition_counts['changed']},"
            f"new:{self._change_transition_counts['new']},"
            f"missing:{self._change_transition_counts['missing']},"
            f"incomplete:{self._change_transition_counts['incomplete']}, "
            f"transition_alerts_omitted={self._change_alerts_omitted}, "
            f"change_state_fault={self._change_state_fault or 'none'}"
        )
        if int(coverage.get("roots", 0)) == 0:
            self.set_health(50, note + "; no watched directories are available")
            return
        if self._change_state_fault:
            self.set_health(60, note + "; durable identity-bound change tracking unavailable")
            return
        if self._change_alerts_omitted:
            self.set_health(65, note + "; transition alert publication cap reached")
            return
        if int(coverage.get("unproved_exclusions", 0)):
            self.set_health(
                75,
                note
                + "; packed-format identity/content receipt is awaiting unchanged review",
            )
            return
        if coverage.get("complete") is True:
            # HMAC files and a separately keyed local witness detect routine
            # rollback/deletion.  A same-host administrator can replace every
            # local authority component, so local freshness is never 100%.
            if self._change_state_loaded:
                self.set_health(
                    90,
                    note
                    + "; local-authenticity-only: TPM/remote monotonic witness not configured",
                )
            else:
                self.set_health(100, "")
            return
        if int(coverage.get("truncated", 0)):
            self.set_health(65, note)
        elif int(coverage.get("errors", 0)):
            self.set_health(70, note)
        elif int(coverage.get("content_incomplete", 0)):
            self.set_health(80, note + "; representative range proof only")
        else:
            self.set_health(80, note)

    def coverage_snapshot(self) -> dict[str, int | float | bool | str]:
        """Return a copy of the current truthful traversal receipt."""
        return dict(self._coverage)

    def _collect_entropy_candidates(self, directory: Path, now: float) -> List[str]:
        """Compatibility wrapper over the bounded recursive enumeration."""
        candidates, _snapshot, coverage = self._scan_root(directory, now)
        self._coverage = coverage
        self._update_coverage_health()
        return [candidate.path for candidate in candidates]

    def _evaluate_entropy(
        self, candidates: list[_EntropyCandidate], now: float
    ) -> int:
        """Score only exact bounded samples with current identity receipts."""
        errors = 0
        self._last_sample_error = ""
        for candidate in candidates:
            held_directories: list[
                tuple[Path, str, int, tuple[str, int, int]]
            ] = []
            descriptor: int | None = None
            if type(candidate) is not _EntropyCandidate:
                errors += 1
                self._last_sample_error = "untyped entropy sample refused"
                continue
            if (
                not math.isfinite(candidate.sample_entropy)
                or not 0.0 <= candidate.sample_entropy <= 8.0
                or not math.isfinite(candidate.high_entropy_fraction)
                or not 0.0 <= candidate.high_entropy_fraction <= 1.0
                or not 0 < candidate.sample_size <= max(
                    CONTENT_FULL_FILE_MAX_BYTES,
                    CONTENT_RANGE_COUNT * SAMPLE_BYTES,
                )
                or len(candidate.sample_sha256) != 64
                or not candidate.sample_ranges
                or candidate.sample_size
                != sum(length for _offset, length in candidate.sample_ranges)
                or any(
                    character not in "0123456789abcdef"
                    for character in candidate.sample_sha256
                )
            ):
                errors += 1
                self._last_sample_error = "invalid entropy sample receipt refused"
                continue
            try:
                held_directories, file_kind, file_handle = (
                    self._hold_current_candidate(candidate)
                )
                ent, descriptor = self._verify_held_candidate_sample(
                    candidate, file_kind, file_handle
                )
                file_handle = -1  # descriptor now owns the Windows handle.
                self._revalidate_held_ancestry(held_directories)
            except (OSError, ValueError) as exc:
                # _hold_current_candidate closes partial acquisition.  Once a
                # complete chain was returned, sample verification owns/closes
                # the file descriptor on failure; the ancestry remains ours.
                if descriptor is not None:
                    os.close(descriptor)
                self._close_held_ancestry(held_directories)
                errors += 1
                self._last_sample_error = (
                    f"entropy sample identity changed or content proof stale: "
                    f"{candidate.path}: {exc}"
                )
                continue
            try:
                if ent >= ENTROPY_THRESHOLD:
                    self._flagged[candidate.path] = now
                    self.emit(
                        f"High-entropy file detected: {os.path.basename(candidate.path)} "
                        f"(entropy={ent:.3f} bits/byte ≥ {ENTROPY_THRESHOLD}) — "
                        "possible ransomware encryption in progress (T1486)",
                        Severity.HIGH,
                        path=candidate.path,
                        entropy=round(ent, 4),
                        threshold=ENTROPY_THRESHOLD,
                        content_complete=candidate.content_complete,
                        content_bytes=candidate.sample_size,
                        max_window_high_entropy_fraction=round(
                            candidate.high_entropy_fraction, 4
                        ),
                        content_ranges=[
                            {"offset": offset, "length": length}
                            for offset, length in candidate.sample_ranges
                        ],
                        mitre_tags=["T1486"],
                        active_attack=True,
                        detector_policy="reviewed-semantic-indicator",
                        **deception_response(),
                    )
                # Publication was performed while both the exact sample and
                # every reviewed ancestor remained held.  A POSIX namespace
                # change at the boundary is still made fail-visible.
                self._revalidate_held_ancestry(held_directories)
            finally:
                os.close(descriptor)
                self._close_held_ancestry(held_directories)
        return errors

    # ── Rename-rate tracker ───────────────────────────────────────────────────
    def _snapshot(self, directory: Path) -> dict[str, float]:
        """Compatibility wrapper returning a bounded recursive snapshot."""
        _candidates, snapshot, coverage = self._scan_root(directory, time.time())
        self._coverage = coverage
        self._update_coverage_health()
        return snapshot

    def _detect_renames(self, directory: Path, now: float) -> None:
        """Compatibility wrapper around bounded recursive rename detection."""
        _candidates, snapshot, coverage = self._scan_root(directory, now)
        self._coverage = coverage
        self._update_coverage_health()
        self._detect_renames_from_snapshot(directory, snapshot, now)

    def _detect_renames_from_snapshot(
        self, directory: Path, new: dict[str, float], now: float
    ) -> None:
        """Compare per-subdirectory names without pairing across directories."""
        dkey = self._directory_key(directory)
        old = self._dir_snapshot.get(dkey, self._dir_snapshot.get(str(directory), {}))
        self._dir_snapshot[dkey] = new
        old_by_parent: dict[str, set[str]] = {}
        new_by_parent: dict[str, set[str]] = {}
        for relative in old:
            rel = Path(relative)
            old_by_parent.setdefault(str(rel.parent), set()).add(rel.name)
        for relative in new:
            rel = Path(relative)
            new_by_parent.setdefault(str(rel.parent), set()).add(rel.name)
        for parent in sorted(set(old_by_parent) | set(new_by_parent)):
            disappeared = old_by_parent.get(parent, set()) - new_by_parent.get(parent, set())
            appeared = new_by_parent.get(parent, set()) - old_by_parent.get(parent, set())
            rename_count = _rename_pair_count(disappeared, appeared)
            if not rename_count:
                continue
            observed_directory = self._directory_key(Path(dkey) / parent)
            self._rename_times.extend([(now, observed_directory)] * rename_count)

    def _check_rename_rate(self, now: float) -> None:
        """Emit a storm alert, promoting to CRITICAL only with entropy evidence."""
        cutoff = now - RENAME_WINDOW_S
        while self._rename_times and self._rename_times[0][0] < cutoff:
            self._rename_times.popleft()
        rates: dict[str, int] = {}
        # _detect_renames() stores normalized directory identities. Retain a
        # tiny compatibility normalization map for tests/restored state that
        # may contain raw paths, but normalize each distinct directory only
        # once instead of once per rename. During a mass-rename burst this
        # removes tens of thousands of repeated abspath/normcase calls without
        # changing the directory-bound correlation decision.
        normalized_directories: dict[str, str] = {}
        for _stamp, raw_directory in self._rename_times:
            directory = normalized_directories.get(raw_directory)
            if directory is None:
                directory = os.path.normcase(os.path.abspath(raw_directory))
                normalized_directories[raw_directory] = directory
            rates[directory] = rates.get(directory, 0) + 1
        if not rates:
            return
        directory, rate = max(rates.items(), key=lambda item: item[1])
        if rate >= RENAME_THRESHOLD:
            entropy_corroborated = any(
                os.path.normcase(os.path.abspath(str(Path(path).parent))) == directory
                and 0.0 <= now - stamp <= RENAME_WINDOW_S
                for path, stamp in self._flagged.items()
            )
            self.emit(
                f"RENAME STORM detected: {rate} file renames in {RENAME_WINDOW_S}s — "
                "ransomware mass-encryption likely in progress (T1486). "
                "Review watched directories immediately.",
                Severity.CRITICAL if entropy_corroborated else Severity.HIGH,
                rename_count=rate,
                window_s=RENAME_WINDOW_S,
                threshold=RENAME_THRESHOLD,
                watched_directory=directory,
                mitre_tags=["T1486"],
                active_attack=True,
                entropy_corroborated=entropy_corroborated,
                detector_policy=(
                    "multi-signal-ransomware-critical"
                    if entropy_corroborated
                    else "rename-pattern-high"
                ),
                **(
                    maximum_host_response()
                    if entropy_corroborated
                    else deception_response()
                ),
            )
            # Clear only this directory. Evidence for other watched roots must
            # remain independently attributable and independently actionable.
            self._rename_times = deque(
                item for item in self._rename_times
                if normalized_directories[item[1]] != directory
            )

    # ── Housekeeping ──────────────────────────────────────────────────────────
    def _evict_stale_dedup(self, now: float) -> None:
        cutoff = now - DEDUP_TTL
        stale  = [k for k, ts in self._flagged.items() if ts < cutoff]
        for k in stale:
            del self._flagged[k]

    def self_test(self) -> tuple[bool, str]:
        if not (
            0 < TRAVERSAL_MAX_DEPTH
            and 0 < TRAVERSAL_MAX_FILES
            and 0 < TRAVERSAL_MAX_DIRS
            and 0 < TRAVERSAL_MAX_S
            and SAMPLE_BYTES <= CONTENT_FULL_FILE_MAX_BYTES <= CONTENT_SCAN_MAX_BYTES
            and 3 <= CONTENT_RANGE_COUNT
            and 0 < CHANGE_STATE_MAX_RECORDS
            and 0 < CHANGE_STATE_MAX_BYTES
            and 0 < CONTENT_STRIDED_ALERT_FRACTION <= 1
            and CONTENT_WINDOW_BYTES == SAMPLE_BYTES
            and 0 < CHANGE_WITNESS_MAX_BYTES <= CHANGE_STATE_MAX_BYTES
        ):
            return False, "bounded held-directory traversal contract is invalid"
        if os.name == "nt":
            try:
                _windows_directory_api()
            except OSError as exc:
                return False, f"held-directory API unavailable: {exc}"
        # Run entropy on a synthetic block of random-like data
        synthetic = bytes(range(256)) * 4   # 1 KB, entropy ~8.0
        ent = _shannon_entropy(synthetic)
        if ent >= ENTROPY_THRESHOLD:
            return (
                True,
                f"Entropy function OK (test={ent:.3f} ≥ {ENTROPY_THRESHOLD}); "
                "timestamp-independent full/range proof, authenticated durable "
                "change transitions/high-water, fixed-window strided scoring, "
                "durable fair rotation, and held no-reparse traversal enabled",
            )
        return False, f"Entropy function returned {ent:.3f} — unexpected"


def register() -> RansomwareHeuristicsModule:
    return RansomwareHeuristicsModule()
