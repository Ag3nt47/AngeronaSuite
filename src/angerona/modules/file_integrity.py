"""File Integrity Monitoring (FIM).

Baselines a set of watched directories (SHA-256 per file) and reports any
create / modify / delete against that baseline. Ported from the original
Angerona FIM worker, cleaned into a self-contained module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from angerona.core.assurance_receipts import (
    DetectorReceiptIssuer,
    assurance_target_digest,
)
from angerona.core.data_paths import data_dir
from angerona.core.module_base import BaseModule, Severity
from angerona.core.atomic_io import replace_with_retry
# Ring 1 interlock (direct cross-module, no orchestrator): FIM asks INTL whether
# a dropped driver is known-vulnerable / the benign drill marker.
from angerona.modules.intel_sync import is_known_bad_driver

# Sensible high-value defaults; users can extend via a watchlist file later.
DEFAULT_WATCH = [
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers", "etc"),
    os.path.join(os.environ.get("USERPROFILE", str(Path.home())), "Documents"),
    os.path.join(os.environ.get("USERPROFILE", str(Path.home())), "Downloads"),
    str(data_dir() / "drill-sandbox"),
]
_RUNTIME_WATCH: set[str] = set()
_RUNTIME_WATCH_LOCK = threading.RLock()


def _combat_intervals() -> tuple[float, float]:
    """Return driver/file cadences for the selected standing-response policy.

    Maximum Adversary Combat is explicitly an availability-overhead tradeoff:
    it keeps FIM at a one-second detection cadence instead of the quiet 30-second
    maintenance cadence.
    """
    enabled = os.environ.get("ANGERONA_ADVERSARY_COMBAT_ENABLED", "0").strip().lower()
    mode = os.environ.get("ANGERONA_ADVERSARY_COMBAT_MODE", "").strip().lower()
    if enabled in {"1", "true", "yes", "on"} and mode == "maximum":
        return 0.5, 1.0
    if enabled in {"1", "true", "yes", "on"}:
        return 2.0, 5.0
    return 10.0, 30.0


def _registered_benign_noise(path: str) -> bool:
    """Ignore only the exact in-memory registered Red Team noise artifact."""
    name = os.path.basename(path).casefold()
    if not (name.startswith("_redteam_benign_note_") and name.endswith(".txt")):
        return False
    try:
        from types import SimpleNamespace

        from angerona.core.practice_scope import provenance_for_event

        provenance = provenance_for_event(SimpleNamespace(details={"path": path}))
        return provenance is not None and provenance.kind == "red-team"
    except Exception:
        return False


def _combat_file_contract(
    path: str,
    *,
    allow_host_isolation: bool = False,
    allow_deception: bool = False,
) -> dict:
    """Return authority only for the bundled deterministic driver verdicts.

    A generic Documents/Downloads change, or even an unexpected ``.sys`` name,
    is detection evidence rather than a known-bad classification.  Those
    events remain visible but cannot directly quarantine or isolate the host.
    """
    match = is_known_bad_driver(os.path.basename(str(path)))
    if match is None:
        return {}
    if match.get("drill"):
        try:
            from types import SimpleNamespace

            from angerona.core.practice_scope import provenance_for_event

            provenance = provenance_for_event(
                SimpleNamespace(details={"path": str(path)})
            )
            if provenance is None or provenance.kind != "red-team":
                return {}
        except Exception:
            return {}
    else:
        # The bundled legacy driver table is filename-oriented and therefore
        # detection evidence only. A same-name legitimate driver must never be
        # quarantined. Real-driver response remains closed until a reviewed,
        # signed exact-hash/version catalog can bind this file; ``sha256`` is
        # retained in the API for that future catalog without trusting an
        # operator-configured live IOC feed as mutation authority.
        return {}
    actions = ["quarantine_file"]
    targets: dict[str, object] = {"path": str(path)}
    if allow_host_isolation:
        actions.append("isolate_host")
        targets["host"] = "local"
    if allow_deception:
        actions.append("activate_honeypots")
        targets["deception"] = "Smart Deception"
    return {
        "response_authorized": True,
        "response_classification": (
            "reviewed-practice-byovd"
        ),
        "response_contract": {
            "version": 1,
            "actions": actions,
            "targets": targets,
        },
    }


def register_runtime_watch(path) -> bool:
    """Add a drill-selected directory for this process lifetime only."""
    if not path:
        return False
    try:
        root = os.path.normcase(os.path.abspath(os.path.expandvars(str(path))))
    except Exception:
        return False
    if not root or any(ch in root for ch in "*?"):
        return False
    with _RUNTIME_WATCH_LOCK:
        _RUNTIME_WATCH.add(root)
    return True


def unregister_runtime_watch(path) -> None:
    if not path:
        return
    try:
        root = os.path.normcase(os.path.abspath(os.path.expandvars(str(path))))
    except Exception:
        return
    with _RUNTIME_WATCH_LOCK:
        _RUNTIME_WATCH.discard(root)


def watch_roots() -> list[str]:
    # A bounded validation or incident-response session may deliberately scope
    # FIM to one path.  This is an explicit operator setting (never enabled by
    # the normal app) and keeps proof campaigns from spending minutes hashing
    # unrelated personal files before the first detector cycle is armed.
    only = os.environ.get("ANGERONA_FIM_WATCH_ONLY", "").strip()
    configured = [p.strip() for p in only.split(os.pathsep) if p.strip()]
    with _RUNTIME_WATCH_LOCK:
        extra = sorted(_RUNTIME_WATCH)
    roots, seen = [], set()
    for root in [*(configured or DEFAULT_WATCH), *extra]:
        key = os.path.normcase(os.path.abspath(str(root)))
        if key not in seen:
            roots.append(str(root))
            seen.add(key)
    return roots
# The kernel driver pool — watched by NAME only (cheap: no hashing of hundreds of
# MB of .sys every cycle). A new .sys appearing here is the classic BYOVD staging
# step, so it is treated as a CRITICAL Ring 1 event.
DRIVER_DIR = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers")
SKIP_EXT = {".tmp", ".log", ".lock"}
_BASELINE_SCHEMA = 2
_BASELINE_HMAC_FIELD = "hmac_sha256"
_BASELINE_KEY_DOMAIN = b"Angerona-FIM-Baseline-v2"
_MAX_BASELINE_BYTES = 32 * 1024 * 1024
_MAX_SCAN_FILES = 100_000
_MAX_FILE_BYTES = 1024 * 1024 * 1024
_MAX_SCAN_CONTENT_BYTES = 8 * 1024 * 1024 * 1024


def _fim_proof_digest(value: object) -> str:
    """Return the canonical digest used by internal FIM scan receipts."""
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class _FIMScanSnapshot(dict[str, str]):
    """One exact, single-evaluation result produced by ``_scan`` itself.

    A plain mapping remains valid input for ordinary change evaluation, but it
    cannot carry detector proof. Only the exact object retained by its producer
    can claim the generation, coverage, baseline, and object-identity receipt.
    """

    def __init__(
        self,
        values: dict[str, str],
        *,
        owner_token: object,
        identities: dict[str, tuple[int, int, int, int, int]],
        baseline: dict[str, str],
        receipt: dict[str, object],
        coverage_sha256: str,
    ) -> None:
        super().__init__(values)
        self._fim_owner_token = owner_token
        self._fim_identities = identities
        self._fim_baseline = baseline
        self._fim_receipt = receipt
        self._fim_coverage_sha256 = coverage_sha256
        self._fim_consumed = False


@dataclass(frozen=True, slots=True)
class _FIMScanCustody:
    """Producer-owned canonical bytes for one current scan generation.

    The evaluator-facing ``_FIMScanSnapshot`` is compatibility data only.  No
    receipt authority is reconstructed from its writable mapping or fields.
    """

    scan_generation: int
    producer_generation: int
    snapshot_items: tuple[tuple[str, str], ...]
    identity_items: tuple[tuple[str, tuple[int, int, int, int, int]], ...]
    baseline_items: tuple[tuple[str, str], ...]
    receipt_bytes: bytes
    coverage_sha256: str

# ── BL-13: paranoid content-hash for high-value paths ─────────────────────────
# The fast path in _scan() reuses a file's cached hash when (mtime, size) is
# unchanged. An attacker can rewrite a watched file while PRESERVING mtime+size
# to slip past that stat-only check. So high-value targets are ALWAYS re-read and
# re-hashed, ignoring the cache — you can't evade content hashing by faking stat.
_HIGH_VALUE_DIRS = [
    # the hosts / networks files — a classic silent-redirect target
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers", "etc"),
]
# Force EVERY watched path to always re-hash (max paranoia, higher CPU).
_FIM_PARANOID_ALL = os.environ.get("ANGERONA_FIM_PARANOID", "").strip().lower() in (
    "1", "true", "yes", "on")


def _extra_paranoid_dirs() -> "list[str]":
    """Operator-marked always-hash paths (os.pathsep-separated)."""
    raw = os.environ.get("ANGERONA_FIM_PARANOID_PATHS", "")
    return [p.strip() for p in raw.split(os.pathsep) if p.strip()]


class FileIntegrityModule(BaseModule):
    CODE = "FIM"
    name = "File Integrity Monitor"
    version = "1.12.1"
    description = "Detects unauthorized creation, modification, or deletion of watched files."
    category = "Integrity"

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, str] = {}
        self._driver_baseline: set = set()   # basenames of *.sys in DRIVER_DIR
        # path -> (mtime_ns, size) as of the last time we actually hashed it.
        # Lets _scan() skip re-hashing files that haven't changed, instead of
        # re-reading + SHA-256'ing every watched file on every single cycle.
        self._stat_cache: Dict[str, Tuple[int, int, int, int, int]] = {}
        self._assurance_issuer: DetectorReceiptIssuer | None = None
        self._last_scan_receipt: dict[str, object] = {
            "complete": False,
            "reason": "not scanned",
        }
        self._baseline_status = "not-loaded"
        self._baseline_path_override: Path | None = None
        self._baseline_key_override: bytes | None = None
        self._driver_collection_ok = False
        self._redteam_receipt_capability: object | None = None
        self._redteam_receipt_lock = threading.RLock()
        self._scan_proof_lock = threading.RLock()
        self._scan_owner_token = object()
        self._scan_generation = 0
        self._pending_scan_snapshot: _FIMScanSnapshot | None = None
        self._pending_scan_custody: _FIMScanCustody | None = None
        self._consumed_scan_generation = 0

    def bind_assurance_receipt_issuer(self, issuer: DetectorReceiptIssuer) -> None:
        self._assurance_issuer = issuer

    def bind_redteam_receipt_capability(
        self,
        capability: object | None,
        *,
        expected: object | None = None,
    ) -> None:
        """Bind/revoke one lease-owned receipt capability by exact identity."""
        with self._redteam_receipt_lock:
            if expected is not None and self._redteam_receipt_capability is not expected:
                return
            self._redteam_receipt_capability = capability

    @staticmethod
    def _assurance_path_is_watched(path: str) -> bool:
        candidate = os.path.normcase(os.path.abspath(path))
        for root in watch_roots():
            try:
                watched = os.path.normcase(os.path.abspath(root))
                if os.path.commonpath((candidate, watched)) == watched:
                    return True
            except (OSError, TypeError, ValueError):
                continue
        return False

    def _publish_assurance_receipts(self) -> None:
        issuer = self._assurance_issuer
        if issuer is None:
            return
        for challenge in issuer.active(self, "fim"):
            path = os.path.abspath(challenge.target_ref)
            if not self._assurance_path_is_watched(path):
                continue
            digest = self._hash(path)
            if not digest:
                continue
            target_digest = assurance_target_digest("fim", path, digest)
            receipt = issuer.issue(
                self,
                challenge.probe_id,
                observation="file_content_observed",
                observed_target_digest=target_digest,
            )
            if receipt is not None:
                self.emit(
                    "FIM object-bound assurance receipt: exact marker content observed.",
                    Severity.INFO,
                    **receipt,
                )

    @property
    def _baseline_path(self) -> Path:
        return self._baseline_path_override or (
            data_dir() / "sensor-baselines" / "file-integrity-v2.json"
        )

    def _baseline_key(self) -> bytes | None:
        key = self._baseline_key_override
        if key is None:
            try:
                key = bytes.fromhex(
                    (data_dir() / "bus.key").read_text(encoding="ascii").strip()
                )
            except (OSError, ValueError):
                return None
        if len(key) != 32:
            return None
        return hmac.new(key, _BASELINE_KEY_DOMAIN, hashlib.sha256).digest()

    @staticmethod
    def _baseline_body(value: dict[str, object]) -> bytes:
        unsigned = {
            key: item for key, item in value.items() if key != _BASELINE_HMAC_FIELD
        }
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _canonical_roots() -> list[str]:
        # Preserve the operating-system spelling for evidence and event paths.
        # Policy comparisons normalize separately; using normcase here leaked
        # Windows' lower-cased comparison form into baseline keys and alerts.
        return sorted(
            {
                os.path.abspath(os.path.expandvars(root))
                for root in watch_roots()
            }
        )

    @staticmethod
    def _root_policy_identity(roots: object) -> tuple[str, ...] | None:
        if not isinstance(roots, list) or any(
            not isinstance(root, str) or not root or len(root) > 32_768
            for root in roots
        ):
            return None
        return tuple(sorted(os.path.normcase(os.path.abspath(root)) for root in roots))

    def _load_approved_baseline(
        self,
    ) -> tuple[dict[str, str], set[str]] | None:
        path = self._baseline_path
        key = self._baseline_key()
        if key is None:
            self._baseline_status = "key-unavailable"
            return None
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            self._baseline_status = "approval-required"
            return None
        except OSError:
            self._baseline_status = "unreadable"
            return None
        try:
            if len(raw) > _MAX_BASELINE_BYTES:
                raise ValueError("baseline exceeds byte limit")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "schema",
                "approved_at",
                "roots",
                "files",
                "drivers",
                _BASELINE_HMAC_FIELD,
            }:
                raise ValueError("baseline schema mismatch")
            if value["schema"] != _BASELINE_SCHEMA:
                raise ValueError("baseline version mismatch")
            roots = value["roots"]
            files = value["files"]
            drivers = value["drivers"]
            if self._root_policy_identity(roots) != self._root_policy_identity(
                self._canonical_roots()
            ):
                raise ValueError("watch-root policy changed")
            if not isinstance(files, dict) or len(files) > _MAX_SCAN_FILES:
                raise ValueError("baseline file inventory invalid")
            if (
                not isinstance(drivers, list)
                or len(drivers) > 4096
                or any(
                    not isinstance(name, str)
                    or len(name) > 260
                    or not name.casefold().endswith(".sys")
                    for name in drivers
                )
            ):
                raise ValueError("baseline driver inventory invalid")
            clean: dict[str, str] = {}
            for path_text, digest in files.items():
                if (
                    not isinstance(path_text, str)
                    or not isinstance(digest, str)
                    or len(path_text) > 32_768
                    or len(digest) != 64
                ):
                    raise ValueError("baseline entry invalid")
                int(digest, 16)
                clean[path_text] = digest
            supplied = str(value[_BASELINE_HMAC_FIELD])
            expected = hmac.new(
                key, self._baseline_body(value), hashlib.sha256
            ).hexdigest()
            if len(supplied) != 64 or not hmac.compare_digest(supplied, expected):
                raise ValueError("baseline authentication failed")
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            self._baseline_status = "invalid"
            return None
        self._baseline_status = "approved"
        return clean, {name.casefold() for name in drivers}

    def approve_current_baseline(self, *, approved: bool = False) -> Path:
        """Persist the last complete scan only after explicit operator approval."""
        if not approved:
            raise PermissionError("explicit FIM baseline approval is required")
        if not bool(self._last_scan_receipt.get("complete")):
            raise RuntimeError("cannot approve an incomplete FIM scan")
        if not self._baseline:
            raise RuntimeError("cannot approve an empty FIM inventory")
        if self._baseline_status in {"invalid", "unreadable"}:
            raise RuntimeError("refusing to overwrite invalid baseline evidence")
        key = self._baseline_key()
        if key is None:
            raise RuntimeError("FIM baseline authentication key unavailable")
        document: dict[str, object] = {
            "schema": _BASELINE_SCHEMA,
            "approved_at": time.time(),
            "roots": self._canonical_roots(),
            "files": dict(sorted(self._baseline.items())),
            "drivers": sorted(self._driver_baseline),
        }
        document[_BASELINE_HMAC_FIELD] = hmac.new(
            key, self._baseline_body(document), hashlib.sha256
        ).hexdigest()
        body = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(body) > _MAX_BASELINE_BYTES:
            raise RuntimeError("FIM baseline exceeds its durable byte limit")
        destination = self._baseline_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("xb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, destination)
            try:
                destination.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        self._baseline_status = "approved"
        return destination

    @staticmethod
    def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_size),
            int(info.st_mtime_ns),
        )

    @staticmethod
    def _filesystem_change_token(path: str) -> int:
        """Return the filesystem-managed change time, not user-settable mtime.

        CPython on Windows exposes creation time as ``st_ctime``. NTFS also
        maintains a distinct ChangeTime that advances when content/metadata is
        changed and is not restored by ordinary ``SetFileTime``/``os.utime``.
        """
        if os.name != "nt":
            return int(os.lstat(path).st_ctime_ns)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            return FileIntegrityModule._handle_change_token(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _handle_change_token(descriptor: int) -> int:
        info_stat = os.fstat(descriptor)
        if os.name != "nt":
            return int(info_stat.st_ctime_ns)
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class FILE_BASIC_INFO(ctypes.Structure):
            _fields_ = [
                ("CreationTime", ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong),
                ("ChangeTime", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
            ]

        handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
        info = FILE_BASIC_INFO()
        get_info = ctypes.windll.kernel32.GetFileInformationByHandleEx
        get_info.restype = wintypes.BOOL
        get_info.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        if not get_info(handle, 0, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "GetFileInformationByHandleEx")
        return int(info.ChangeTime)

    def _hash(self, path: str) -> str:
        # Antivirus/indexer metadata touches can race the first identity sample
        # on Windows. Retry a small fixed number of times, but accept only one
        # individually stable, handle-bound read.
        for _attempt in range(3):
            digest = self._hash_once(path)
            if digest:
                return digest
        return ""

    def _hash_once(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            before = os.lstat(path)
            attributes = getattr(before, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or bool(attributes & reparse)
                or before.st_size > _MAX_FILE_BYTES
            ):
                return ""
            with open(path, "rb") as f:
                opened = os.fstat(f.fileno())
                if self._file_identity(opened) != self._file_identity(before):
                    return ""
                opened_change = self._handle_change_token(f.fileno())
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
                after = os.fstat(f.fileno())
                if self._file_identity(after) != self._file_identity(opened):
                    return ""
                if self._handle_change_token(f.fileno()) != opened_change:
                    return ""
            return h.hexdigest()
        except Exception:
            return ""

    def _stat(self, path: str) -> Optional[Tuple[int, int, int, int, int]]:
        try:
            return (*self._file_identity(os.lstat(path)), self._filesystem_change_token(path))
        except Exception:
            return None

    def _is_high_value(self, path: str) -> bool:
        """True if ``path`` must be content-hashed every scan (BL-13), ignoring the
        mtime/size fast-path. Covers the built-in high-value dirs, any operator-
        marked paranoid paths, and global paranoid mode."""
        if _FIM_PARANOID_ALL:
            return True
        try:
            cand = os.path.normcase(os.path.abspath(path))
        except Exception:
            return False
        for root in [*_HIGH_VALUE_DIRS, *_extra_paranoid_dirs()]:
            try:
                r = os.path.normcase(os.path.abspath(root))
                if os.path.commonpath((cand, r)) == r:
                    return True
            except (ValueError, TypeError):
                continue
        return False

    def _scan(self) -> Dict[str, str]:
        """Return a bounded recursive snapshot plus an honest coverage receipt.

        The fast path is bound to device/inode/size/mtime/ctime rather than only
        mtime+size. High-value roots always hash. Any missing root, denied item,
        link/reparse object, hash race, or resource limit makes the receipt
        incomplete and therefore prevents green health/baseline approval.
        """
        from angerona.core.data_paths import _is_reparse_point

        started_monotonic_ns = time.monotonic_ns()
        with self._scan_proof_lock:
            self._scan_generation += 1
            scan_generation = self._scan_generation
            baseline_at_start = dict(self._baseline)
            stat_cache_at_start = dict(self._stat_cache)

        snap: Dict[str, str] = {}
        new_stat_cache: Dict[str, Tuple[int, int, int, int, int]] = {}
        errors: list[str] = []
        error_count_total = 0
        covered_roots: list[str] = []
        visited = 0
        hashed = 0
        reused = 0
        content_bytes = 0
        stopped_for_budget = False

        def _error(message: str) -> None:
            nonlocal error_count_total
            error_count_total += 1
            if len(errors) < 32:
                errors.append(message[:500])

        scan_roots = self._canonical_roots()
        for root in scan_roots:
            root_path = Path(root)
            root_error_count = error_count_total
            try:
                if (
                    not root_path.is_dir()
                    or root_path.is_symlink()
                    or _is_reparse_point(root_path)
                ):
                    _error(f"watch root unavailable or unsafe: {root_path}")
                    continue
            except OSError as exc:
                _error(f"watch root unreadable: {root_path}: {exc}")
                continue

            def _walk_error(exc: OSError) -> None:
                _error(f"directory traversal failed: {exc}")

            for dirpath, directories, files in os.walk(
                root_path, followlinks=False, onerror=_walk_error
            ):
                directory = Path(dirpath)
                safe_directories: list[str] = []
                for name in directories:
                    child = directory / name
                    try:
                        if child.is_symlink() or _is_reparse_point(child):
                            _error(f"linked/reparse directory excluded: {child}")
                            continue
                        safe_directories.append(name)
                    except OSError as exc:
                        _error(f"directory identity failed: {child}: {exc}")
                directories[:] = safe_directories
                for fn in files:
                    full = os.path.join(dirpath, fn)
                    st = self._stat(full)
                    if st is None:
                        _error(f"file metadata unavailable: {full}")
                        continue
                    visited += 1
                    if visited > _MAX_SCAN_FILES:
                        _error(f"file inventory exceeded {_MAX_SCAN_FILES}")
                        stopped_for_budget = True
                        break
                    try:
                        info = os.lstat(full)
                        attributes = getattr(info, "st_file_attributes", 0)
                        reparse = getattr(
                            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                        )
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or stat.S_ISLNK(info.st_mode)
                            or bool(attributes & reparse)
                        ):
                            _error(f"non-regular/link file excluded: {full}")
                            continue
                        if info.st_size > _MAX_FILE_BYTES:
                            _error(f"file exceeds per-object hash budget: {full}")
                            continue
                    except OSError as exc:
                        _error(f"file identity failed: {full}: {exc}")
                        continue
                    cached_st = stat_cache_at_start.get(full)
                    if (cached_st == st and full in baseline_at_start
                            and not self._is_high_value(full)):
                        digest = baseline_at_start[full]
                        reused += 1
                    else:
                        if content_bytes + max(0, st[2]) > _MAX_SCAN_CONTENT_BYTES:
                            _error("scan content-byte budget exhausted")
                            stopped_for_budget = True
                            break
                        digest = self._hash(full)
                        content_bytes += max(0, st[2])
                        hashed += 1
                        if not digest:
                            _error(f"stable content hash unavailable: {full}")
                    if digest:
                        snap[full] = digest
                        new_stat_cache[full] = st
                if stopped_for_budget:
                    break
                if self.stopping:
                    _error("scan stopped before coverage completed")
                    stopped_for_budget = True
                    break
            if error_count_total == root_error_count and not stopped_for_budget:
                covered_roots.append(str(root_path))
            if stopped_for_budget:
                break

        completed_monotonic_ns = time.monotonic_ns()
        complete = not errors and not stopped_for_budget
        receipt: dict[str, object] = {
            "schema": "angerona.fim-scan-receipt.v1",
            "scan_generation": scan_generation,
            "producer_generation": int(self.lifecycle_generation),
            "started_monotonic_ns": started_monotonic_ns,
            "completed_monotonic_ns": completed_monotonic_ns,
            "watch_roots_sha256": _fim_proof_digest(scan_roots),
            "covered_roots": sorted(covered_roots),
            "complete": complete,
            "reason": "complete" if complete else errors[0],
            "files_visited": visited,
            "files_recorded": len(snap),
            "files_hashed": hashed,
            "hashes_reused": reused,
            "content_bytes_hashed": content_bytes,
            "errors": tuple(errors),
            "error_count": error_count_total,
            "errors_sha256": _fim_proof_digest(errors),
            "snapshot_sha256": _fim_proof_digest(dict(sorted(snap.items()))),
            "baseline_sha256": _fim_proof_digest(
                dict(sorted(baseline_at_start.items()))
            ),
            "cache_assurance": (
                "full-content" if _FIM_PARANOID_ALL else "identity-bound-cache"
            ),
        }
        coverage_sha256 = _fim_proof_digest(receipt)
        result = _FIMScanSnapshot(
            snap,
            owner_token=self._scan_owner_token,
            identities=dict(new_stat_cache),
            baseline=baseline_at_start,
            receipt=receipt,
            coverage_sha256=coverage_sha256,
        )
        custody = _FIMScanCustody(
            scan_generation=scan_generation,
            producer_generation=int(self.lifecycle_generation),
            snapshot_items=tuple(sorted(snap.items())),
            identity_items=tuple(sorted(new_stat_cache.items())),
            baseline_items=tuple(sorted(baseline_at_start.items())),
            receipt_bytes=json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8"),
            coverage_sha256=coverage_sha256,
        )
        with self._scan_proof_lock:
            self._stat_cache = new_stat_cache
            self._last_scan_receipt = {
                **receipt,
                "coverage_sha256": coverage_sha256,
            }
            self._pending_scan_snapshot = result
            self._pending_scan_custody = custody
        return result

    # ── Ring 1: driver-shield classifier + cheap driver-pool scan ────────────
    def _driver_alert(self, path: str):
        """Classify a path for the Driver-Intel Shield. Returns (Severity, msg)
        or None. Pure — no I/O — so it is unit-testable. A known-vulnerable or
        drill driver, or ANY unexpected .sys write, is CRITICAL (BYOVD staging)."""
        base = os.path.basename(str(path)).lower()
        hit = is_known_bad_driver(base)
        if hit:
            kind = "BYOVD drill marker" if hit.get("drill") else "KNOWN-VULNERABLE driver"
            return (Severity.CRITICAL, f"{kind} written: {base} — {hit['reason']}")
        if base.endswith(".sys"):
            return (Severity.CRITICAL,
                    f"Unexpected kernel driver written: {base} "
                    f"(review — possible BYOVD staging)")
        return None

    def _list_driver_names(self) -> set:
        """Names of *.sys in the driver pool — listing only, never hashed."""
        try:
            names = {e.name.lower() for e in os.scandir(DRIVER_DIR)
                     if e.is_file() and e.name.lower().endswith(".sys")}
            self._driver_collection_ok = True
            return names
        except Exception:
            self._driver_collection_ok = False
            return set()

    def _sweep_drivers(self) -> None:
        """BL-13: cheap name-only sweep of the kernel driver pool. Run more often
        than the full FIM cycle so BYOVD staging (a new *.sys) is caught fast."""
        cur_drivers = self._list_driver_names()
        if not self._driver_collection_ok:
            self.set_health(35, "driver inventory unavailable; prior baseline retained")
            return
        for name in cur_drivers - self._driver_baseline:
            alert = self._driver_alert(name)
            sev, msg = alert if alert else (Severity.HIGH, f"New driver present: {name}")
            path = os.path.join(DRIVER_DIR, name)
            self.emit(
                msg,
                sev,
                driver=name,
                path=path,
                **_combat_file_contract(
                    path,
                    allow_host_isolation=True,
                    allow_deception=True,
                ),
            )
        self._driver_baseline = cur_drivers

    def _set_coverage_health(self) -> None:
        receipt = self._last_scan_receipt
        if not bool(receipt.get("complete")):
            self.set_health(
                35,
                "FIM coverage incomplete: " + str(receipt.get("reason", "unknown")),
            )
            return
        if not self._driver_collection_ok:
            self.set_health(55, "file scan complete; driver inventory unavailable")
            return
        if self._baseline_status != "approved":
            self.set_health(
                45,
                f"complete candidate captured; reviewed baseline {self._baseline_status}",
            )
            return
        self.set_health(
            100,
            "approved baseline; complete change-token-bound content coverage",
        )

    def _claim_scan_evaluation(
        self, current: object
    ) -> dict[str, object] | None:
        """Consume the exact current producer-owned scan generation once."""
        if type(current) is not _FIMScanSnapshot:
            return None
        snapshot = current
        with self._scan_proof_lock:
            custody = self._pending_scan_custody
            if (
                self._pending_scan_snapshot is not snapshot
                or custody is None
                or snapshot._fim_owner_token is not self._scan_owner_token
            ):
                return None
            try:
                receipt = json.loads(custody.receipt_bytes.decode("utf-8"))
                canonical_snapshot = dict(custody.snapshot_items)
                canonical_identities = dict(custody.identity_items)
                canonical_baseline = dict(custody.baseline_items)
                valid = (
                    isinstance(receipt, dict)
                    and receipt.get("schema") == "angerona.fim-scan-receipt.v1"
                    and type(receipt.get("scan_generation")) is int
                    and receipt.get("scan_generation")
                    == custody.scan_generation
                    == self._scan_generation
                    and custody.scan_generation > self._consumed_scan_generation
                    and receipt.get("producer_generation")
                    == custody.producer_generation
                    == int(self.lifecycle_generation)
                    and type(receipt.get("started_monotonic_ns")) is int
                    and type(receipt.get("completed_monotonic_ns")) is int
                    and 0 < int(receipt["started_monotonic_ns"])
                    <= int(receipt["completed_monotonic_ns"])
                    <= time.monotonic_ns()
                    and receipt.get("snapshot_sha256")
                    == _fim_proof_digest(canonical_snapshot)
                    and dict(snapshot) == canonical_snapshot
                    and receipt.get("baseline_sha256")
                    == _fim_proof_digest(dict(sorted(self._baseline.items())))
                    == _fim_proof_digest(canonical_baseline)
                    and custody.coverage_sha256
                    == _fim_proof_digest(receipt)
                    and isinstance(receipt.get("covered_roots"), list)
                )
            except (
                AttributeError,
                MemoryError,
                RecursionError,
                TypeError,
                UnicodeError,
                ValueError,
            ):
                valid = False
            # Burn the issuer generation whether validation succeeds or fails;
            # a mutated public view can never be repaired and replayed.
            self._consumed_scan_generation = max(
                self._consumed_scan_generation,
                custody.scan_generation,
            )
            snapshot._fim_consumed = True
            self._pending_scan_snapshot = None
            self._pending_scan_custody = None
            if not valid:
                return None
            return {
                "receipt": {
                    **receipt,
                    "covered_roots": list(receipt["covered_roots"]),
                    "errors": tuple(receipt.get("errors") or ()),
                },
                "coverage_sha256": custody.coverage_sha256,
                "identities": canonical_identities,
                "baseline": canonical_baseline,
            }

    def _scan_path_proof(
        self,
        context: dict[str, object] | None,
        *,
        path: str,
        digest: str,
        change_kind: str,
    ) -> dict[str, object]:
        """Bind one changed path to the claimed scan's identity and coverage."""
        if context is None:
            return {}
        try:
            receipt = context["receipt"]
            identities = context["identities"]
            baseline = context["baseline"]
            if (
                not isinstance(receipt, dict)
                or not isinstance(identities, dict)
                or not isinstance(baseline, dict)
            ):
                return {}
            identity = identities.get(path)
            if (
                not isinstance(identity, tuple)
                or len(identity) != 5
                or any(type(value) is not int for value in identity)
                or self._stat(path) != identity
            ):
                return {}
            old_digest = baseline.get(path)
            expected_kind = "created" if old_digest is None else "modified"
            if (
                expected_kind != change_kind
                or (old_digest is not None and old_digest == digest)
            ):
                return {}
            candidate = os.path.normcase(os.path.abspath(path))
            coverage_root = ""
            for raw_root in receipt.get("covered_roots", []):
                root = os.path.normcase(os.path.abspath(str(raw_root)))
                try:
                    if os.path.commonpath((candidate, root)) == root and len(root) > len(
                        coverage_root
                    ):
                        coverage_root = root
                except (OSError, TypeError, ValueError):
                    continue
            if not coverage_root:
                return {}
            path_identity: dict[str, object] = {
                "path": str(Path(path).resolve(strict=False)),
                "device": identity[0],
                "inode": identity[1],
                "size": identity[2],
                "mtime_ns": identity[3],
                "change_token": identity[4],
                "observed_content_sha256": digest,
                "baseline_content_sha256": str(old_digest or ""),
            }
            return {
                "fim_scan_receipt": receipt,
                "fim_scan_coverage_sha256": str(context["coverage_sha256"]),
                "fim_scan_coverage_root": coverage_root,
                "fim_scan_path_identity": path_identity,
                "fim_scan_path_identity_sha256": _fim_proof_digest(path_identity),
            }
        except (OSError, RuntimeError, TypeError, ValueError):
            return {}

    def _evaluate_snapshot(self, current: Dict[str, str]) -> None:
        """Emit exact create/delete/change results against the retained baseline."""
        scan_context = self._claim_scan_evaluation(current)
        current_view = dict(current)
        active_roots = [
            os.path.normcase(os.path.abspath(root)) for root in watch_roots()
        ]

        def _still_watched(path: str) -> bool:
            candidate = os.path.normcase(os.path.abspath(path))
            for root in active_roots:
                try:
                    if os.path.commonpath((candidate, root)) == root:
                        return True
                except ValueError:
                    continue
            return False

        def _redteam_scan_receipt(
            path: str,
            digest: str,
            change_kind: str,
            message: str,
            severity: Severity,
        ) -> dict[str, object]:
            try:
                with self._redteam_receipt_lock:
                    capability = self._redteam_receipt_capability
                issue = getattr(capability, "issue_fim_observation", None)
                if not callable(issue):
                    return {}
                return issue(
                    self,
                    message=message,
                    severity=severity,
                    path=path,
                    observed_content_sha256=digest,
                    change_kind=change_kind,
                    scan_proof=self._scan_path_proof(
                        scan_context,
                        path=path,
                        digest=digest,
                        change_kind=change_kind,
                    ),
                )
            except Exception:
                # Receipt metadata must never suppress the underlying FIM
                # security event when a simulation lease has degraded.
                return {}

        base_keys = {path for path in self._baseline if _still_watched(path)}
        cur_keys = set(current_view)
        for path in cur_keys - base_keys:
            if _registered_benign_noise(path):
                continue
            alert = self._driver_alert(path)
            if alert:
                receipt = _redteam_scan_receipt(
                    path, current_view[path], "created", alert[1], alert[0]
                )
                self.emit(
                    alert[1],
                    alert[0],
                    path=path,
                    **_combat_file_contract(
                        path,
                        allow_host_isolation=True,
                        allow_deception=True,
                    ),
                    **receipt,
                )
            else:
                message = f"New file created: {path}"
                receipt = _redteam_scan_receipt(
                    path, current_view[path], "created", message, Severity.MEDIUM
                )
                self.emit(
                    message,
                    Severity.MEDIUM,
                    path=path,
                    **_combat_file_contract(path),
                    **receipt,
                )
        for path in base_keys - cur_keys:
            self.emit(
                f"Watched file deleted: {path}",
                Severity.HIGH,
                path=path,
                **_combat_file_contract(path, allow_host_isolation=True),
            )
        for path in base_keys & cur_keys:
            if self._baseline[path] == current_view[path]:
                continue
            alert = self._driver_alert(path)
            if alert:
                receipt = _redteam_scan_receipt(
                    path, current_view[path], "modified", alert[1], alert[0]
                )
                self.emit(
                    alert[1],
                    alert[0],
                    path=path,
                    **_combat_file_contract(
                        path,
                        allow_host_isolation=True,
                        allow_deception=True,
                    ),
                    **receipt,
                )
            else:
                message = f"Watched file modified: {path}"
                receipt = _redteam_scan_receipt(
                    path, current_view[path], "modified", message, Severity.HIGH
                )
                self.emit(
                    message,
                    Severity.HIGH,
                    path=path,
                    **_combat_file_contract(path, allow_host_isolation=True),
                    **receipt,
                )

    def self_test(self) -> tuple[bool, str]:
        a = self._driver_alert(r"C:\x\rtcore64.sys")                # known-vulnerable
        b = self._driver_alert(r"C:\x\angerona_byovd_drill.sys")    # benign drill
        c = self._driver_alert(r"C:\Users\me\notes.txt")           # benign non-driver
        ok = (a and a[0] == Severity.CRITICAL
              and b and b[0] == Severity.CRITICAL and c is None)
        # BL-13: an operator-marked paranoid path is always content-hashed.
        import tempfile
        _prev = os.environ.get("ANGERONA_FIM_PARANOID_PATHS")
        try:
            d = tempfile.mkdtemp(prefix="fim_hv_")
            os.environ["ANGERONA_FIM_PARANOID_PATHS"] = d
            hv = self._is_high_value(os.path.join(d, "sub", "secret.bin"))
            nv = self._is_high_value(os.path.join(tempfile.gettempdir(), "unrelated", "x.txt"))
        finally:
            if _prev is None:
                os.environ.pop("ANGERONA_FIM_PARANOID_PATHS", None)
            else:
                os.environ["ANGERONA_FIM_PARANOID_PATHS"] = _prev
        ok = bool(ok and hv and not nv)
        return (ok, "driver-shield classifier + BL-13 paranoid high-value hashing verified"
                if ok else f"failed: a={a} b={b} c={c} hv={hv} nv={nv}")

    def run(self) -> None:
        self.emit("Loading reviewed file-integrity baseline…", Severity.INFO)
        approved = self._load_approved_baseline()
        if approved is not None:
            self._baseline, self._driver_baseline = approved
        else:
            self._baseline = {}
            self._driver_baseline = set()

        current = self._scan()
        self._publish_assurance_receipts()
        current_drivers = self._list_driver_names()
        if approved is not None and bool(self._last_scan_receipt.get("complete")):
            self._evaluate_snapshot(current)
            if self._driver_collection_ok:
                for name in current_drivers - self._driver_baseline:
                    alert = self._driver_alert(name)
                    severity, message = alert if alert else (
                        Severity.HIGH,
                        f"New driver present at startup: {name}",
                    )
                    self.emit(
                        message,
                        severity,
                        driver=name,
                        path=os.path.join(DRIVER_DIR, name),
                    )
        else:
            # Candidate state is useful for immediate change detection but is
            # never described as trusted and is never persisted automatically.
            self.emit(
                "FIM captured a candidate inventory; explicit reviewed approval "
                "is required before it becomes a trusted baseline.",
                Severity.MEDIUM,
                baseline_status=self._baseline_status,
            )
        if bool(self._last_scan_receipt.get("complete")):
            self._baseline = dict(current)
        if self._driver_collection_ok:
            self._driver_baseline = current_drivers
        self._set_coverage_health()
        self.emit(
            f"FIM armed: {len(self._baseline)} files, "
            f"{len(self._driver_baseline)} drivers; baseline={self._baseline_status}.",
            Severity.INFO,
            baseline_status=self._baseline_status,
            coverage=dict(self._last_scan_receipt),
        )

        while not self.stopping:
            _DRIVER_INTERVAL, _FILE_INTERVAL = _combat_intervals()
            # Sweep the (cheap, name-only) driver pool every _DRIVER_INTERVAL for a
            # fast BYOVD catch, while the full file-integrity scan runs every
            # _FILE_INTERVAL. BL-13: shorter driver-pool interval.
            slept = 0.0
            while slept < _FILE_INTERVAL and not self.stopping:
                self.sleep(_DRIVER_INTERVAL)
                slept += _DRIVER_INTERVAL
                if not self.stopping:
                    self._sweep_drivers()
                    self._publish_assurance_receipts()
            if self.stopping:
                break
            current = self._scan()
            self._publish_assurance_receipts()
            if bool(self._last_scan_receipt.get("complete")):
                self._evaluate_snapshot(current)
                self._baseline = dict(current)
            self._set_coverage_health()
