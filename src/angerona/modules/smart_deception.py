"""smart_deception.py — Hyper-contextual AI honeytokens (CODE: SDEC).

Upgrades the static canary approach in deception.py: instead of fixed decoy
names, it samples the *shape* of the user's Documents folder and asks the local
Ollama model to invent decoy filenames that blend in with the real ones, then
drops those honeytokens into high-value locations. Any process that touches one
triggers an immediate CRITICAL alert.

Privacy: only file/folder *names* are sampled and sent to the LOCAL Ollama
(loopback :11434, zero egress) — never file contents. If Ollama is unavailable,
a static fallback name list is used so honeytokens still deploy.

Detection uses the same proven mechanism as deception.py: each decoy carries an
anchor token; deletion, token loss (encryption/overwrite), or an exclusive lock
(active encryptor holding the handle) trips the trap. Tripped decoys are
re-staged immediately to prevent alert spam.

Standard library only (os, json, time, ctypes, random, urllib) — Windows hidden
attributes are applied to the already-open decoy handle, never by reopening a
mutable pathname.
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import sqlite3
import stat
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from angerona.core.durable_outbox import load_or_create_outbox_key
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.hardening import (
    key_acl_required,
    secure_sensitive_file,
    sensitive_file_is_protected,
)
from angerona.core.independent_high_water import (
    SCHEMA as HIGH_WATER_SCHEMA,
    CUSTODY_DOMAIN,
    ZERO_DIGEST,
    HighWaterHead,
    HighWaterAssessment,
    HighWaterTransition,
    HighWaterUnavailable,
    IndependentHighWater,
    assess_high_water,
    validate_head,
    validate_installation_id,
)
from angerona.core.module_base import BaseModule, Severity
from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    local_service_url,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import effective_keep_alive


ANCHOR_TOKEN = "UDE_DECOY_TOKEN::CONFIDENTIAL_DATA_DO_NOT_MODIFY_OR_ENCRYPT"

_OLLAMA_HOST  = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_OLLAMA_MODEL = os.environ.get("ANGERONA_MODEL", "llama3")
_GEN_TIMEOUT_S = 20.0
_MAX_SAMPLE   = 60      # names sampled from Documents
_DECOYS_PER_TARGET = 3
_ANCHOR_BYTES = ANCHOR_TOKEN.encode("utf-8")
_MAX_ANCHOR_READ = len(_ANCHOR_BYTES) + 1
_TRIP_DEDUP_S = 300.0
_TRIP_ALERT_MAX = 256
_QUARANTINE_PREFIX = "sdec-"
_QUARANTINE_SUFFIX = ".evidence"
_QUARANTINE_NAME = re.compile(
    r"\Asdec-([0-9]{13})-[0-9a-f]{24}-([0-9a-f]{64})\.evidence\Z"
)
_QUARANTINE_PENDING = re.compile(r"\Asdec-pending-[0-9a-f]{24}\.tmp\Z")
_QUARANTINE_MAX_FILES = 8
_QUARANTINE_MAX_BYTES = 1024 * 1024
_QUARANTINE_MAX_ITEM_BYTES = 256 * 1024
_QUARANTINE_MAX_AGE_S = 24 * 3600.0
_QUARANTINE_SCAN_MAX = 64
_QUARANTINE_AUDIT_S = 300.0
_CUSTODY_COUNTER_MAX = 1_000_000
_CUSTODY_LEDGER_SCHEMA = "angerona.smart-deception-custody.v1"
_CUSTODY_GENESIS = "0" * 64
_CUSTODY_EVIDENCE_EVENTS = frozenset(
    {"commit", "evict_intent", "evict", "alias", "topology"}
)
_CUSTODY_STATE_EVENTS = frozenset(
    {"pending_loss", "refuse", "continuity_loss"}
)
_CUSTODY_EVENTS = _CUSTODY_EVIDENCE_EVENTS | _CUSTODY_STATE_EVENTS
_CUSTODY_LEDGER_MAX_EVENTS = 4096
_CUSTODY_TERMINAL_RESERVE = 32
_CUSTODY_ARCHIVE_EVENT_BUDGET = 3
_CUSTODY_STATE_NAME = "sdec-state"
_CUSTODY_WITNESS_SCHEMA = "angerona.smart-deception-custody-witness.v1"
_CUSTODY_WITNESS_MAX_BYTES = 4096
_CUSTODY_HEAD_MAX_BYTES = 8192
_CUSTODY_AUTHORITY_MAX_DEPTH = 64
_CUSTODY_LOCAL_GENESIS_SCHEMA = (
    "angerona.smart-deception-local-genesis.v1"
)
_CUSTODY_LOCAL_GENESIS_MAX_BYTES = 1024
_CUSTODY_EXTERNAL_DOMAIN = CUSTODY_DOMAIN
_CUSTODY_OUTBOX_SCHEMA = "angerona.smart-deception-external-transition.v1"
_CUSTODY_OUTBOX_MAX_BYTES = 8192

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_CUSTODY_API: tuple[object, object, object, object, object] | None = None


def _bounded_custody_json(
    payload: bytes, *, label: str, max_bytes: int
) -> object:
    """Parse one bounded authority object without recursive parser escape."""
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
            if depth > _CUSTODY_AUTHORITY_MAX_DEPTH:
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


@dataclass(frozen=True)
class CustodyCaptureOutcome:
    """Typed operational result; never an immutability claim."""

    state: str
    reason: str
    evidence_name: str = ""
    evidence_sha256: str = ""
    source_retired: bool = False
    namespace_protected: bool = False
    independently_fresh: bool = False


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = (("delete_file", ctypes.c_ubyte),)


class _IoStatusBlock(ctypes.Structure):
    _fields_ = (
        ("status", ctypes.c_void_p),
        ("information", ctypes.c_size_t),
    )


def _custody_api() -> tuple[object, object, object, object, object]:
    """Load only fixed-System32 APIs used for exact-object custody changes."""
    global _CUSTODY_API
    if os.name != "nt":
        raise OSError("exact Windows file-object custody is unavailable")
    if _CUSTODY_API is None:
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
        set_information = kernel.SetFileInformationByHandle
        set_information.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        set_information.restype = ctypes.c_int
        close_handle = kernel.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        native = ctypes.WinDLL(
            "ntdll.dll", use_last_error=False, winmode=0x00000800
        )
        set_native_information = native.NtSetInformationFile
        set_native_information.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_IoStatusBlock),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
        ]
        set_native_information.restype = ctypes.c_long
        status_to_error = native.RtlNtStatusToDosError
        status_to_error.argtypes = [ctypes.c_long]
        status_to_error.restype = ctypes.c_uint32
        _CUSTODY_API = (
            create_file,
            set_information,
            close_handle,
            set_native_information,
            status_to_error,
        )
    return _CUSTODY_API


class _FileBasicInfo(ctypes.Structure):
    _fields_ = (
        ("CreationTime", ctypes.c_longlong),
        ("LastAccessTime", ctypes.c_longlong),
        ("LastWriteTime", ctypes.c_longlong),
        ("ChangeTime", ctypes.c_longlong),
        ("FileAttributes", ctypes.c_uint32),
    )


def _hide_decoy_handle(descriptor: int) -> None:
    """Best-effort HIDDEN|SYSTEM attributes on the exact opened file object."""
    if os.name != "nt":
        return
    try:
        import msvcrt

        kernel = ctypes.WinDLL(
            "kernel32.dll", use_last_error=True, winmode=0x00000800
        )
        get_info = kernel.GetFileInformationByHandleEx
        get_info.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        get_info.restype = ctypes.c_int
        set_info = kernel.SetFileInformationByHandle
        set_info.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        set_info.restype = ctypes.c_int
        handle = ctypes.c_void_p(msvcrt.get_osfhandle(descriptor))
        info = _FileBasicInfo()
        size = ctypes.sizeof(info)
        if not get_info(handle, 0, ctypes.byref(info), size):
            return
        info.FileAttributes |= 0x2 | 0x4
        set_info(handle, 0, ctypes.byref(info), size)
    except (AttributeError, OSError, ValueError):
        return

_FALLBACK_NAMES = [
    "Tax_Return_2024_FINAL.xlsx", "Passwords_backup.docx", "Q4_Payroll.xlsx",
    "Bank_Statements_Q1.pdf", "Employee_SSN_master.csv", "Wallet_seed_phrase.txt",
    "VPN_credentials.docx", "Client_Contracts_signed.pdf", "Crypto_keys_cold.txt",
]

_GEN_SYSTEM_PROMPT = (
    "You generate decoy (honeytoken) filenames for a security deception system. "
    "Given a sample of real filenames from a user's Documents folder, invent "
    "convincing high-value decoy filenames that blend in (finance, credentials, "
    "personal records). Respond with ONLY a JSON array of filename strings, no "
    "prose, e.g. [\"Tax_2024.xlsx\", \"vault_keys.txt\"]. 8-12 names, each with a "
    "realistic extension."
)


def _user_folder_deception_enabled() -> bool:
    return os.environ.get("ANGERONA_USER_FOLDER_DECEPTION", "0").strip().casefold() in {
        "1", "true", "yes", "on",
    }


def _runtime_deception_root() -> Path:
    from angerona.core.data_paths import data_dir

    return data_dir() / "deception" / "smart"


def _personal_deception_targets() -> tuple[Path, ...]:
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    appdata = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
    return home / "Desktop", home / "Documents", appdata


class SmartDeception(BaseModule):
    name = "Smart Deception"
    CODE = "SDEC"
    description = "AI-generated contextual honeytokens; CRITICAL alert on tamper."
    category = "Deception"
    version = "1.13.0"

    MONITOR_S = 2.5          # decoy tamper-check cadence. 2.5s (was 1s) roughly
                             # halves idle wake-ups; a token-loss/lock is still
                             # caught within a couple seconds. The Adaptive Resource
                             # Governor can widen this further under load.
    REFRESH_S = 24 * 3600.0  # regenerate decoy set daily

    def __init__(self, *, high_water: IndependentHighWater | None = None) -> None:
        super().__init__()
        self._user_scope = _user_folder_deception_enabled()
        self._runtime_root = _runtime_deception_root()
        self._sample_root = (
            _personal_deception_targets()[1] if self._user_scope else None
        )
        self._targets = (
            _personal_deception_targets()
            if self._user_scope
            else (self._runtime_root,)
        )
        self._manifest = self._runtime_root.parent / "smart_manifest.json"
        self._decoys: list[str] = []      # deployed decoy file paths
        self._decoy_identity: dict[str, tuple[int, int]] = {}
        self._unresolved_trips: set[str] = set()
        self._trip_alerts: dict[str, float] = {}
        self._last_refresh = 0.0
        self._trips = 0
        self._deploy_failures = 0
        self._monitor_errors = 0
        self._generation_degraded = False
        self._quarantine_root_identity: tuple[int, int] | None = None
        self._quarantine_count = 0
        self._quarantine_bytes = 0
        self._quarantine_saturated = False
        self._quarantine_dropped = 0
        self._quarantine_alias_residue = 0
        self._custody_degraded = False
        self._custody_loss = 0
        self._custody_ledger_sequence = 0
        self._custody_ledger_head = _CUSTODY_GENESIS
        self._custody_key_cache: bytes | None = None
        self._custody_enrollment_key_cache: bytes | None = None
        self._custody_authority_initialized = False
        self._custody_witness_verified = False
        self._custody_high_water = high_water
        self._custody_freshness = HighWaterAssessment(
            "local-authenticity-only",
            "no independent high-water authority is configured",
            False,
        )
        self._custody_external_revision = 0
        self._custody_external_digest = ZERO_DIGEST
        self._custody_external_head = ZERO_DIGEST
        self._custody_namespace_protected: bool | None = None
        self._custody_prior_history_uncertain = high_water is None
        self._last_capture_outcome = CustodyCaptureOutcome(
            "not_attempted", "no custody capture has been attempted"
        )
        self._custody_capacity_exhausted = False
        self._custody_remaining_events = _CUSTODY_LEDGER_MAX_EVENTS
        self._custody_pending_evictions: set[str] = set()
        self._custody_alias_events: set[str] = set()
        self._custody_topology_events: set[str] = set()
        self._custody_topology_uncertain = 0
        self._custody_refusals = 0
        self._custody_evictions = 0
        self._last_quarantine_audit = 0.0
        self._trip_alert_evictions = 0
        self._trip_alert_saturated = False

    def bind_high_water(self, authority: IndependentHighWater) -> None:
        """Bind the application-owned independent custody authority pre-start.

        Module discovery may inject this after ordinary zero-argument
        construction.  Rebinding after local custody has been opened would make
        the installation identity and predecessor ambiguous, so it is refused.
        """
        if self._custody_authority_initialized:
            raise RuntimeError("custody authority cannot be rebound after enrollment")
        installation_id = validate_installation_id(authority.installation_id)
        if not callable(getattr(authority, "read_head", None)) or not callable(
            getattr(authority, "compare_and_advance", None)
        ):
            raise TypeError("independent custody authority contract is incomplete")
        self._custody_high_water = authority
        self._custody_freshness = HighWaterAssessment(
            "configured-unverified",
            "independent custody authority is configured but not yet verified",
            False,
            state_digest=ZERO_DIGEST,
        )
        self._custody_prior_history_uncertain = True
        # Retain the validated value in the assessment path without treating the
        # property read as a remote freshness proof.
        if installation_id != authority.installation_id:
            raise RuntimeError("independent custody installation identity changed")

    # ── Generation ────────────────────────────────────────────────────────────
    def _sample_documents(self) -> list[str]:
        names: list[str] = []
        if self._sample_root is None:
            return names
        try:
            for root, dirs, files in os.walk(self._sample_root):
                for fn in files:
                    names.append(fn)
                    if len(names) >= _MAX_SAMPLE:
                        return names
        except Exception:
            pass
        return names

    def _generate_names(self) -> list[str]:
        """Ask Ollama for blended decoy names; fall back to a static list."""
        sample = self._sample_documents()
        if not sample:
            self._generation_degraded = False
            return list(_FALLBACK_NAMES)
        user = "Real filenames sample:\n" + json.dumps(sample)
        payload = json.dumps({
            "model": _OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _GEN_SYSTEM_PROMPT},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "format": "json",
            "keep_alive": effective_keep_alive("30m"),
        }).encode("utf-8")
        req = urllib.request.Request(
            local_service_url(_OLLAMA_HOST, "/api/chat"), data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with safe_urlopen(
                req, policy=OLLAMA_SERVICE_POLICY, timeout=_GEN_TIMEOUT_S,
            ) as resp:
                data = json.loads(read_bounded(resp).decode("utf-8"))
            content = (data.get("message", {}) or {}).get("content", "")
            names = json.loads(content)
            names = [self._safe_name(n) for n in names if isinstance(n, str)]
            names = [n for n in names if n]
            self._generation_degraded = not bool(names)
            return names or list(_FALLBACK_NAMES)
        except Exception as exc:
            self._generation_degraded = True
            self.set_health(80, f"AI name-gen unavailable ({exc}); using fallback names.")
            return list(_FALLBACK_NAMES)

    @staticmethod
    def _safe_name(name: str) -> str:
        """Strip path separators / traversal so a model can't redirect the drop."""
        base = os.path.basename(name.strip().replace("\\", "/"))
        return "".join(c for c in base if c not in '<>:"|?*').strip()

    # ── Deployment ────────────────────────────────────────────────────────────
    def _allowed_decoy_path(self, path: Path) -> bool:
        try:
            candidate = path.resolve(strict=False)
            if path.is_symlink():
                return False
            return any(
                os.path.commonpath((str(candidate), str(root.resolve(strict=False))))
                == str(root.resolve(strict=False))
                for root in self._targets
            )
        except (OSError, RuntimeError, ValueError):
            return False

    def _manifest_entries(self) -> dict[str, tuple[Path, tuple[int, int]]]:
        try:
            if self._manifest.is_symlink() or self._manifest.stat().st_size > 256 * 1024:
                return {}
            value = json.loads(self._manifest.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, ValueError, TypeError):
            return {}
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "decoys"}
            or value.get("schema") != "angerona.smart-decoy-manifest.v2"
            or not isinstance(value.get("decoys"), list)
            or len(value["decoys"]) > 256
        ):
            return {}
        entries: dict[str, tuple[Path, tuple[int, int]]] = {}
        for item in value["decoys"]:
            if not isinstance(item, dict) or set(item) != {"path", "device", "inode"}:
                return {}
            path = item.get("path")
            device = item.get("device")
            inode = item.get("inode")
            if (
                not isinstance(path, str)
                or len(path) > 32_767
                or type(device) is not int
                or type(inode) is not int
                or device < 0
                or inode < 0
            ):
                return {}
            candidate = Path(path)
            if not self._allowed_decoy_path(candidate):
                return {}
            key = self._path_key(candidate)
            if key in entries:
                return {}
            entries[key] = candidate, (device, inode)
        return entries

    def _write_manifest(self) -> None:
        self._manifest.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for path in sorted(set(self._decoys), key=self._path_key):
            identity = self._decoy_identity.get(self._path_key(path))
            if identity is None:
                continue
            rows.append({"path": path, "device": identity[0], "inode": identity[1]})
        payload = json.dumps(
            {"schema": "angerona.smart-decoy-manifest.v2", "decoys": rows},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        temp = self._manifest.with_suffix(f".tmp.{os.getpid()}")
        try:
            temp.write_text(payload, encoding="utf-8")
            os.replace(temp, self._manifest)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def _cleanup_deployed_decoys(self) -> None:
        # Only handle-derived identities (live or retained in the protected,
        # closed-schema v2 manifest) are deletion authority. Legacy pathname-only
        # manifests are intentionally ignored.
        retained = self._manifest_entries()
        for key, (_path, identity) in retained.items():
            self._decoy_identity.setdefault(key, identity)
        candidates = {Path(item) for item in self._decoys}
        candidates.update(item[0] for item in retained.values())
        survivors: list[str] = []
        survivor_identities: dict[str, tuple[int, int]] = {}
        for path in candidates:
            if not self._allowed_decoy_path(path):
                continue
            key = self._path_key(path)
            expected = self._decoy_identity.get(key)
            if expected is None:
                continue
            if not self._delete_exact_decoy(path, expected, require_anchor=True):
                survivors.append(str(path))
                survivor_identities[key] = expected
        self._decoys = survivors
        self._decoy_identity = survivor_identities
        self._unresolved_trips.clear()
        if survivors:
            self._write_manifest()
        else:
            try:
                self._manifest.unlink()
            except OSError:
                pass

    def _deploy(self, names: list[str]) -> None:
        # Remove previously-deployed decoys first so the daily REFRESH_S
        # regeneration doesn't leave orphaned, unmonitored honeytokens piling up
        # in Documents/Desktop/APPDATA.
        self._cleanup_deployed_decoys()
        self._refresh_quarantine_limits()
        self._last_quarantine_audit = time.time()
        self._deploy_failures = 0
        for target_path in self._targets:
            try:
                target_path.mkdir(parents=True, exist_ok=True)
            except OSError:
                self._deploy_failures += _DECOYS_PER_TARGET
                continue
            target = str(target_path)
            for name in random.sample(names, min(_DECOYS_PER_TARGET, len(names))):
                path = os.path.join(target, name)
                if self._write_decoy(path):
                    self._decoys.append(path)
                else:
                    self._deploy_failures += 1
        self._write_manifest()
        self.emit(f"Deployed {len(self._decoys)} AI honeytokens across "
                  f"{len(self._targets)} explicitly allowed location(s).", Severity.INFO)
        self._update_health()

    @staticmethod
    def _path_key(path: str | Path) -> str:
        return os.path.normcase(os.path.abspath(str(path)))

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, int]:
        return int(info.st_dev), int(info.st_ino)

    @staticmethod
    def _is_reparse(info: os.stat_result) -> bool:
        attributes = int(getattr(info, "st_file_attributes", 0) or 0)
        return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))

    def _open_existing_nofollow(self, path: Path) -> tuple[int, tuple[int, int]]:
        before = path.lstat()
        if (
            self._is_reparse(before)
            or stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
        ):
            raise OSError("decoy is not a no-follow regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            after = path.lstat()
            identity = self._identity(opened)
            if (
                self._is_reparse(after)
                or stat.S_ISLNK(after.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or self._identity(before) != identity
                or self._identity(after) != identity
            ):
                raise OSError("decoy identity changed while opening")
            return descriptor, identity
        except Exception:
            os.close(descriptor)
            raise

    def _path_identity(self, path: Path) -> tuple[int, int] | None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if (
            self._is_reparse(info)
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
        ):
            return None
        return self._identity(info)

    def _open_custody_path(
        self,
        path: Path,
        *,
        expected: tuple[int, int] | None = None,
        directory: bool = False,
    ) -> tuple[int, tuple[int, int]]:
        """Open an exact no-follow object with rights retained for mutation."""
        if os.name != "nt":
            raise OSError("exact held-object custody requires Windows")
        before = path.lstat()
        valid_type = (
            stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode)
        )
        if self._is_reparse(before) or stat.S_ISLNK(before.st_mode) or not valid_type:
            raise OSError("custody target is a reparse point or has the wrong type")

        import msvcrt

        create_file, _set_information, close_handle, _native, _status = _custody_api()
        if directory:
            desired_access = 0x0001 | 0x0080  # LIST_DIRECTORY | READ_ATTRIBUTES
            share_mode = 0x0001 | 0x0002  # freeze root rename/delete
            flags = 0x02000000 | 0x00200000
        else:
            desired_access = 0x80000000 | 0x00010000 | 0x0080
            # No FILE_SHARE_WRITE: the held object cannot be modified while its
            # identity is being retired.
            share_mode = 0x0001  # freeze write/rename/delete while held
            flags = 0x00200000
        handle = create_file(
            str(path),
            desired_access,
            share_mode,
            None,
            3,  # OPEN_EXISTING
            flags,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            error = ctypes.get_last_error()
            raise OSError(error, "failed to acquire exact-object custody")
        descriptor: int | None = None
        try:
            descriptor = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
            )
            handle = None
            opened = os.fstat(descriptor)
            after = path.lstat()
            identity = self._identity(opened)
            opened_type = (
                stat.S_ISDIR(opened.st_mode)
                if directory
                else stat.S_ISREG(opened.st_mode)
            )
            if (
                not opened_type
                or self._is_reparse(after)
                or stat.S_ISLNK(after.st_mode)
                or self._identity(before) != identity
                or self._identity(after) != identity
                or (expected is not None and identity != expected)
            ):
                raise OSError("custody target identity changed while opening")
            return descriptor, identity
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            elif handle not in {None, invalid}:
                close_handle(ctypes.c_void_p(handle))
            raise

    @staticmethod
    def _rename_held(
        descriptor: int, root_descriptor: int, destination_name: str
    ) -> None:
        """Rename the exact object relative to an exact held destination root."""
        if os.name != "nt":
            raise OSError("exact handle rename is unavailable")
        if (
            _QUARANTINE_NAME.fullmatch(destination_name) is None
            or not 0 < len(destination_name) <= 255
        ):
            raise OSError("quarantine destination is invalid")

        import msvcrt

        (
            _create_file,
            _set_information,
            _close_handle,
            set_native_information,
            status_to_error,
        ) = _custody_api()
        character_count = len(destination_name)

        class FileRenameInfo(ctypes.Structure):
            _fields_ = (
                ("replace_if_exists", ctypes.c_ubyte),
                ("root_directory", ctypes.c_void_p),
                ("file_name_length", ctypes.c_uint32),
                ("file_name", ctypes.c_wchar * character_count),
            )

        value = FileRenameInfo()
        value.replace_if_exists = 0
        value.root_directory = ctypes.c_void_p(
            msvcrt.get_osfhandle(root_descriptor)
        )
        value.file_name_length = len(destination_name.encode("utf-16-le"))
        value.file_name = destination_name
        size = FileRenameInfo.file_name.offset + value.file_name_length
        io_status = _IoStatusBlock()
        status = set_native_information(
            ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)),
            ctypes.byref(io_status),
            ctypes.byref(value),
            size,
            10,  # FileRenameInformation
        )
        if status < 0:
            error = int(status_to_error(status))
            raise OSError(error, "exact-object quarantine rename failed")

    @staticmethod
    def _delete_held(descriptor: int) -> None:
        """Mark the exact open file object for deletion when its handle closes."""
        if os.name != "nt":
            raise OSError("exact handle deletion is unavailable")

        import msvcrt

        (
            _create_file,
            set_information,
            _close_handle,
            _native,
            _status,
        ) = _custody_api()
        value = _FileDispositionInfo(1)
        if not set_information(
            ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)),
            4,  # FileDispositionInfo
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "exact-object deletion failed")

    def _quarantine_directory(self) -> Path:
        return self._runtime_root.parent / "smart-quarantine"

    def _custody_key_path(self) -> Path:
        return self._runtime_root / "custody" / "evidence-ledger.key"

    def _custody_ledger_path(self) -> Path:
        return self._runtime_root / "custody" / "evidence-ledger.sqlite3"

    def _custody_head_path(self) -> Path:
        return self._runtime_root / "custody" / "evidence-ledger.head.json"

    def _custody_enrollment_key_path(self) -> Path:
        # This witness deliberately lives outside the create-on-missing custody
        # bundle.  Losing key+ledger+head therefore cannot silently look like a
        # first installation while the independently enrolled witness remains.
        return self._runtime_root.parent / ".smart-custody-enrollment.key"

    def _custody_witness_path(self) -> Path:
        return self._runtime_root.parent / ".smart-custody-high-water.json"

    def _custody_transition_path(self) -> Path:
        return self._runtime_root / "custody" / "external-transition.json"

    def _custody_local_genesis_path(self) -> Path:
        # Kept outside the create-on-missing custody bundle so a crash after
        # key creation is distinguishable from an ordinary partial install.
        return self._runtime_root.parent / ".smart-custody-local-genesis.json"

    def _custody_lease_path(self) -> Path:
        return self._runtime_root / "custody" / "authority.lock"

    def _read_local_genesis_marker(self) -> dict[str, object] | None:
        path = self._custody_local_genesis_path()
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
                or not 0 < int(before.st_size) <= _CUSTODY_LOCAL_GENESIS_MAX_BYTES
            ):
                raise OSError("local custody genesis marker is unsafe")
            payload = os.read(descriptor, _CUSTODY_LOCAL_GENESIS_MAX_BYTES + 1)
            after = os.fstat(descriptor)
            current = os.lstat(path)
            if (
                len(payload) != int(before.st_size)
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or (current.st_dev, current.st_ino)
                != (after.st_dev, after.st_ino)
            ):
                raise OSError("local custody genesis marker changed while read")
        finally:
            os.close(descriptor)
        value = _bounded_custody_json(
            payload,
            label="local custody genesis marker",
            max_bytes=_CUSTODY_LOCAL_GENESIS_MAX_BYTES,
        )
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "nonce"}
            or value.get("schema") != _CUSTODY_LOCAL_GENESIS_SCHEMA
            or not isinstance(value.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{32}", str(value["nonce"])) is None
        ):
            raise OSError("local custody genesis marker is unreadable")
        return value

    def _ensure_local_genesis_marker(self) -> None:
        path = self._custody_local_genesis_path()
        existing = self._read_local_genesis_marker()
        if existing is not None:
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "schema": _CUSTODY_LOCAL_GENESIS_SCHEMA,
                "nonce": secrets.token_hex(16),
            },
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

    def _remove_local_genesis_marker(self) -> None:
        try:
            self._custody_local_genesis_path().unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def _custody_state_digest(sequence: int, head: str) -> str:
        payload = json.dumps(
            {
                "schema": _CUSTODY_LEDGER_SCHEMA,
                "sequence": sequence,
                "head_hmac": head,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def _custody_transition_mac(self, core: dict[str, object]) -> str:
        encoded = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(
            self._custody_enrollment_key(),
            b"angerona-smart-custody-external-transition-v1\0" + encoded,
            hashlib.sha256,
        ).hexdigest()

    def _pending_transition_core(
        self,
        *,
        installation_id: str,
        previous_revision: int,
        previous_state_digest: str,
        previous_head: str,
        local_sequence: int,
        local_head: str,
    ) -> dict[str, object]:
        return {
            "schema": _CUSTODY_OUTBOX_SCHEMA,
            "installation_id": installation_id,
            "domain": _CUSTODY_EXTERNAL_DOMAIN,
            "previous_revision": previous_revision,
            "previous_state_digest": previous_state_digest,
            "previous_head": previous_head,
            "revision": local_sequence + 1,
            "state_digest": self._custody_state_digest(local_sequence, local_head),
            "local_sequence": local_sequence,
            "local_head": local_head,
        }

    @staticmethod
    def _digest_is_valid(value: object, *, allow_zero: bool = True) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
            and (allow_zero or value != ZERO_DIGEST)
        )

    def _write_pending_transition(
        self,
        *,
        installation_id: str,
        previous_revision: int,
        previous_state_digest: str,
        previous_head: str,
        local_sequence: int,
        local_head: str,
    ) -> None:
        path = self._custody_transition_path()
        if path.exists() or path.is_symlink():
            raise OSError("pending custody transition already exists")
        core = self._pending_transition_core(
            installation_id=installation_id,
            previous_revision=previous_revision,
            previous_state_digest=previous_state_digest,
            previous_head=previous_head,
            local_sequence=local_sequence,
            local_head=local_head,
        )
        if (
            previous_revision < 0
            or local_sequence < 0
            or local_sequence + 1 != previous_revision + 1
            or not self._digest_is_valid(local_head)
            or not self._digest_is_valid(previous_state_digest)
            or not self._digest_is_valid(previous_head)
            or (
                previous_revision == 0
                and (
                    previous_state_digest != ZERO_DIGEST
                    or previous_head != ZERO_DIGEST
                )
            )
            or (
                previous_revision > 0
                and (
                    previous_state_digest == ZERO_DIGEST
                    or previous_head == ZERO_DIGEST
                )
            )
        ):
            raise OSError("pending custody transition predecessor is invalid")
        value = {**core, "hmac_sha256": self._custody_transition_mac(core)}
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(payload) > _CUSTODY_OUTBOX_MAX_BYTES:
            raise OSError("pending custody transition exceeds its byte bound")
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

    def _read_pending_transition(self) -> dict[str, object] | None:
        path = self._custody_transition_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or int(info.st_nlink) != 1
                or not 0 < int(info.st_size) <= _CUSTODY_OUTBOX_MAX_BYTES
            ):
                raise OSError("pending custody transition object is unsafe")
            payload = os.read(descriptor, _CUSTODY_OUTBOX_MAX_BYTES + 1)
            after = os.fstat(descriptor)
            if (
                len(payload) != int(info.st_size)
                or (int(after.st_dev), int(after.st_ino), int(after.st_size))
                != (int(info.st_dev), int(info.st_ino), int(info.st_size))
            ):
                raise OSError("pending custody transition changed while read")
            value = _bounded_custody_json(
                payload,
                label="pending custody transition",
                max_bytes=_CUSTODY_OUTBOX_MAX_BYTES,
            )
        except (
            MemoryError,
            RecursionError,
            json.JSONDecodeError,
            UnicodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise OSError("pending custody transition is unreadable") from exc
        finally:
            os.close(descriptor)
        if not isinstance(value, dict):
            raise OSError("pending custody transition schema is invalid")
        expected_keys = {
            "schema",
            "installation_id",
            "domain",
            "previous_revision",
            "previous_state_digest",
            "previous_head",
            "revision",
            "state_digest",
            "local_sequence",
            "local_head",
            "hmac_sha256",
        }
        if set(value) != expected_keys:
            raise OSError("pending custody transition schema is invalid")
        try:
            installation_id = validate_installation_id(value["installation_id"])
            previous_revision = value["previous_revision"]
            revision = value["revision"]
            local_sequence = value["local_sequence"]
            previous_digest = value["previous_state_digest"]
            previous_head = value["previous_head"]
            state_digest = value["state_digest"]
            local_head = value["local_head"]
            supplied = value["hmac_sha256"]
            core = {key: value[key] for key in expected_keys - {"hmac_sha256"}}
        except (KeyError, TypeError, ValueError) as exc:
            raise OSError("pending custody transition values are invalid") from exc
        if (
            value["schema"] != _CUSTODY_OUTBOX_SCHEMA
            or value["domain"] != _CUSTODY_EXTERNAL_DOMAIN
            or type(previous_revision) is not int
            or type(revision) is not int
            or type(local_sequence) is not int
            or previous_revision < 0
            or revision != previous_revision + 1
            or local_sequence < 0
            or revision != local_sequence + 1
            or not self._digest_is_valid(previous_digest)
            or not self._digest_is_valid(previous_head)
            or not self._digest_is_valid(state_digest, allow_zero=False)
            or not self._digest_is_valid(local_head)
            or state_digest != self._custody_state_digest(local_sequence, local_head)
            or (
                previous_revision == 0
                and (previous_digest != ZERO_DIGEST or previous_head != ZERO_DIGEST)
            )
            or (
                previous_revision > 0
                and (previous_digest == ZERO_DIGEST or previous_head == ZERO_DIGEST)
            )
            or not isinstance(supplied, str)
            or not hmac.compare_digest(self._custody_transition_mac(core), supplied)
        ):
            raise OSError("pending custody transition authentication failed")
        value["installation_id"] = installation_id
        return value

    def _remove_pending_transition(self) -> None:
        path = self._custody_transition_path()
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise OSError("pending custody transition disappeared") from exc

    @staticmethod
    def _head_matches_transition(
        observed: HighWaterHead | None,
        pending: dict[str, object],
        *,
        new: bool,
    ) -> bool:
        if new:
            return bool(
                observed is not None
                and observed.revision == pending["revision"]
                and observed.state_digest == pending["state_digest"]
                and observed.previous_head == pending["previous_head"]
            )
        if pending["previous_revision"] == 0:
            return observed is None
        return bool(
            observed is not None
            and observed.revision == pending["previous_revision"]
            and observed.state_digest == pending["previous_state_digest"]
            and observed.head == pending["previous_head"]
        )

    def _read_external_head(self, installation_id: str) -> HighWaterHead | None:
        authority = self._custody_high_water
        if authority is None:
            raise OSError("independent custody authority is not configured")
        try:
            if validate_installation_id(authority.installation_id) != installation_id:
                self._custody_freshness = HighWaterAssessment(
                    "installation-mismatch",
                    "independent custody installation identity changed",
                    False,
                )
                raise OSError("independent custody installation identity changed")
            observed = authority.read_head(_CUSTODY_EXTERNAL_DOMAIN)
            if observed is None:
                return None
            return validate_head(
                observed,
                installation_id=installation_id,
                domain=_CUSTODY_EXTERNAL_DOMAIN,
            )
        except HighWaterUnavailable as exc:
            self._custody_freshness = HighWaterAssessment(
                "provisional-offline",
                "independent custody authority is unavailable",
                False,
            )
            raise OSError(
                "RECOVERY_REQUIRED: independent custody authority is unavailable"
            ) from exc
        except OSError:
            raise
        except Exception as exc:
            self._custody_freshness = HighWaterAssessment(
                "authority-rejected",
                "independent custody authority returned an invalid result",
                False,
            )
            raise OSError(
                "RECOVERY_REQUIRED: independent custody authority was rejected"
            ) from exc

    def _accept_external_head(
        self,
        observed: HighWaterHead,
        *,
        state_digest: str,
        remove_pending: bool,
    ) -> None:
        if remove_pending:
            self._remove_pending_transition()
        self._custody_external_revision = observed.revision
        self._custody_external_digest = observed.state_digest
        self._custody_external_head = observed.head
        self._custody_freshness = HighWaterAssessment(
            "verified",
            "local custody matches the independently authenticated high-water head",
            True,
            head=observed.head,
            state_digest=state_digest,
        )
        self._custody_prior_history_uncertain = False

    def _reconcile_external_custody(
        self, sequence: int, head: str, *, fresh_authority: bool
    ) -> None:
        authority = self._custody_high_water
        digest = self._custody_state_digest(sequence, head)
        if authority is None:
            self._custody_freshness = HighWaterAssessment(
                "local-authenticity-only",
                "prior custody may have been erased because every authority is local",
                False,
                state_digest=digest,
            )
            self._custody_external_revision = 0
            self._custody_external_digest = ZERO_DIGEST
            self._custody_external_head = ZERO_DIGEST
            self._custody_prior_history_uncertain = True
            return
        installation_id = validate_installation_id(authority.installation_id)
        try:
            pending = self._read_pending_transition()
        except OSError:
            self._custody_freshness = HighWaterAssessment(
                "transition-invalid",
                "pending independent custody transition is invalid",
                False,
                state_digest=digest,
            )
            raise
        if pending is None:
            readiness = assess_high_water(
                authority,
                domain=_CUSTODY_EXTERNAL_DOMAIN,
                installation_id=installation_id,
                revision=0 if fresh_authority else sequence + 1,
                state_digest=digest,
            )
            self._custody_freshness = readiness
            if readiness.independently_fresh:
                observed = self._read_external_head(installation_id)
                if observed is None:
                    raise OSError("RECOVERY_REQUIRED: verified custody head disappeared")
                self._accept_external_head(
                    observed, state_digest=digest, remove_pending=False
                )
                return
            if fresh_authority and readiness.state == "ready-first-enrollment":
                self._write_pending_transition(
                    installation_id=installation_id,
                    previous_revision=0,
                    previous_state_digest=ZERO_DIGEST,
                    previous_head=ZERO_DIGEST,
                    local_sequence=sequence,
                    local_head=head,
                )
                pending = self._read_pending_transition()
            else:
                raise OSError(
                    f"RECOVERY_REQUIRED: independent custody freshness is {readiness.state}"
                )
        if pending is None:
            raise OSError("RECOVERY_REQUIRED: pending custody transition is unavailable")
        if pending["installation_id"] != installation_id:
            self._custody_freshness = HighWaterAssessment(
                "installation-mismatch",
                "pending custody transition belongs to another installation",
                False,
                state_digest=digest,
            )
            raise OSError("RECOVERY_REQUIRED: custody transition installation changed")
        local_is_new = (
            pending["local_sequence"] == sequence
            and pending["local_head"] == head
            and pending["state_digest"] == digest
        )
        local_is_predecessor = (
            pending["previous_revision"] > 0
            and sequence + 1 == pending["previous_revision"]
            and digest == pending["previous_state_digest"]
        )
        if not local_is_new and not local_is_predecessor:
            self._custody_freshness = HighWaterAssessment(
                "transition-conflict",
                "local custody does not match the authenticated pending transition",
                False,
                state_digest=digest,
            )
            raise OSError(
                "RECOVERY_REQUIRED: local custody does not match pending transition"
            )
        observed = self._read_external_head(installation_id)
        if local_is_predecessor:
            if not self._head_matches_transition(observed, pending, new=False):
                self._custody_freshness = HighWaterAssessment(
                    "local-behind",
                    "authority advanced without the corresponding local custody commit",
                    False,
                    state_digest=digest,
                )
                raise OSError(
                    "RECOVERY_REQUIRED: authority advanced without the local custody commit"
                )
            if observed is None:
                raise OSError("RECOVERY_REQUIRED: custody predecessor is unavailable")
            self._remove_pending_transition()
            self._accept_external_head(
                observed, state_digest=digest, remove_pending=False
            )
            return
        if self._head_matches_transition(observed, pending, new=True):
            if observed is None:  # narrowed by the predicate; keeps type explicit
                raise OSError("RECOVERY_REQUIRED: committed custody head is unavailable")
            self._accept_external_head(
                observed, state_digest=digest, remove_pending=True
            )
            return
        if not self._head_matches_transition(observed, pending, new=False):
            self._custody_freshness = HighWaterAssessment(
                "fork-detected",
                "independent custody authority has a conflicting revision or head",
                False,
                state_digest=digest,
            )
            raise OSError("RECOVERY_REQUIRED: custody authority fork or gap detected")
        transition = HighWaterTransition(
            HIGH_WATER_SCHEMA,
            installation_id,
            _CUSTODY_EXTERNAL_DOMAIN,
            int(pending["previous_revision"]),
            str(pending["previous_state_digest"]),
            str(pending["previous_head"]),
            int(pending["revision"]),
            str(pending["state_digest"]),
        )
        try:
            returned = validate_head(
                authority.compare_and_advance(transition),
                installation_id=installation_id,
                domain=_CUSTODY_EXTERNAL_DOMAIN,
            )
        except HighWaterUnavailable:
            returned = self._read_external_head(installation_id)
            if returned is None:
                raise OSError(
                    "RECOVERY_REQUIRED: independent custody CAS outcome is unavailable"
                )
        except Exception:
            returned = self._read_external_head(installation_id)
            if returned is None:
                raise OSError("RECOVERY_REQUIRED: independent custody CAS was rejected")
        if not self._head_matches_transition(returned, pending, new=True):
            self._custody_freshness = HighWaterAssessment(
                "advance-rejected",
                "independent custody CAS result is ambiguous",
                False,
                state_digest=digest,
            )
            raise OSError("RECOVERY_REQUIRED: independent custody CAS result is ambiguous")
        self._accept_external_head(
            returned,
            state_digest=digest,
            remove_pending=True,
        )

    def _establish_external_custody(
        self, sequence: int, head: str, *, fresh_authority: bool
    ) -> None:
        self._reconcile_external_custody(
            sequence, head, fresh_authority=fresh_authority
        )

    def _advance_external_custody(self, sequence: int, head: str) -> None:
        authority = self._custody_high_water
        if authority is None:
            self._establish_external_custody(
                sequence, head, fresh_authority=False
            )
            return
        self._reconcile_external_custody(
            sequence, head, fresh_authority=False
        )

    def _prepare_external_custody(self, sequence: int, head: str) -> bool:
        authority = self._custody_high_water
        if authority is None:
            return False
        installation_id = validate_installation_id(authority.installation_id)
        if (
            self._custody_external_revision != sequence
            or self._custody_external_digest
            != self._custody_state_digest(sequence - 1, self._custody_ledger_head)
            or self._custody_external_head == ZERO_DIGEST
        ):
            raise OSError(
                "RECOVERY_REQUIRED: custody CAS predecessor is not the loaded local head"
            )
        try:
            self._write_pending_transition(
                installation_id=installation_id,
                previous_revision=self._custody_external_revision,
                previous_state_digest=self._custody_external_digest,
                previous_head=self._custody_external_head,
                local_sequence=sequence,
                local_head=head,
            )
        except OSError:
            self._custody_freshness = HighWaterAssessment(
                "transition-unavailable",
                "pending independent custody transition could not be committed",
                False,
                state_digest=self._custody_state_digest(sequence, head),
            )
            raise
        return True

    def custody_freshness_snapshot(self) -> dict[str, object]:
        return {
            "authority_configured": self._custody_high_water is not None,
            "state": self._custody_freshness.state,
            "reason": self._custody_freshness.reason,
            "independently_fresh": self._custody_freshness.independently_fresh,
            "revision": self._custody_external_revision,
            "state_digest": self._custody_freshness.state_digest,
            "pending_transition": self._custody_transition_path().exists(),
            "prior_history_may_have_been_erased": self._custody_prior_history_uncertain,
        }

    def last_capture_outcome(self) -> CustodyCaptureOutcome:
        return self._last_capture_outcome

    def _custody_key(self) -> bytes:
        if self._custody_key_cache is None:
            self._custody_key_cache = load_or_create_outbox_key(
                self._custody_key_path()
            )
        return self._custody_key_cache

    def _custody_enrollment_key(self) -> bytes:
        if self._custody_enrollment_key_cache is None:
            self._custody_enrollment_key_cache = load_or_create_outbox_key(
                self._custody_enrollment_key_path()
            )
        return self._custody_enrollment_key_cache

    def _custody_witness_core(self, sequence: int, head: str) -> dict[str, object]:
        return {
            "schema": _CUSTODY_WITNESS_SCHEMA,
            "install_id": hashlib.sha256(
                self._custody_enrollment_key()
            ).hexdigest(),
            "sequence": sequence,
            "head_hmac": head,
        }

    def _custody_witness_mac(self, core: dict[str, object]) -> str:
        encoded = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(
            self._custody_enrollment_key(), encoded, hashlib.sha256
        ).hexdigest()

    def _read_custody_witness(self) -> tuple[int, str]:
        path = self._custody_witness_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or int(info.st_nlink) != 1
                or not 0 < int(info.st_size) <= _CUSTODY_WITNESS_MAX_BYTES
            ):
                raise OSError("custody witness object is unsafe")
            payload = os.read(descriptor, _CUSTODY_WITNESS_MAX_BYTES + 1)
            if len(payload) != int(info.st_size):
                raise OSError("custody witness changed while read")
            value = _bounded_custody_json(
                payload,
                label="custody witness",
                max_bytes=_CUSTODY_WITNESS_MAX_BYTES,
            )
            sequence = int(value["sequence"])
            head = str(value["head_hmac"])
            supplied = str(value["hmac_sha256"])
        except (
            KeyError,
            MemoryError,
            RecursionError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            raise OSError("custody witness is unreadable") from exc
        finally:
            os.close(descriptor)
        core = self._custody_witness_core(sequence, head)
        if (
            set(value) != {*core, "hmac_sha256"}
            or any(value.get(key) != expected for key, expected in core.items())
            or sequence < 0
            or len(head) != 64
            or not hmac.compare_digest(
                self._custody_witness_mac(core), supplied
            )
        ):
            raise OSError("custody witness authentication failed")
        return sequence, head

    def _write_custody_witness(self, sequence: int, head: str) -> None:
        path = self._custody_witness_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        core = self._custody_witness_core(sequence, head)
        value = {**core, "hmac_sha256": self._custody_witness_mac(core)}
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
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _custody_core(
        sequence: int,
        event: str,
        name: str,
        identity: tuple[int, int],
        size: int,
        digest: str,
        root_identity: tuple[int, int],
        previous_hmac: str,
    ) -> dict[str, object]:
        return {
            "schema": _CUSTODY_LEDGER_SCHEMA,
            "sequence": sequence,
            "event": event,
            "name": name,
            "device": identity[0],
            "inode": identity[1],
            "size": size,
            "sha256": digest,
            "root_device": root_identity[0],
            "root_inode": root_identity[1],
            "previous_hmac": previous_hmac,
        }

    def _custody_mac(self, core: dict[str, object]) -> str:
        encoded = json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(self._custody_key(), encoded, hashlib.sha256).hexdigest()

    def _open_custody_ledger(
        self, *, create: bool, allow_genesis_repair: bool = False
    ) -> sqlite3.Connection:
        path = self._custody_ledger_path()
        key_existed = self._custody_key_path().exists()
        ledger_existed = path.exists()
        head_existed = self._custody_head_path().exists()
        self._custody_key()
        if not create and not (ledger_existed and head_existed):
            raise OSError("authenticated custody ledger is missing")
        if key_existed and (not ledger_existed or not head_existed):
            if not (
                allow_genesis_repair
                and create
                and not head_existed
            ):
                raise OSError("custody ledger/high-water continuity is missing")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=2.0, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS custody_events (
                    sequence INTEGER PRIMARY KEY,
                    event TEXT NOT NULL,
                    name TEXT NOT NULL,
                    device TEXT NOT NULL,
                    inode TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    root_device TEXT NOT NULL,
                    root_inode TEXT NOT NULL,
                    previous_hmac TEXT NOT NULL,
                    record_hmac TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS custody_events_no_update
                BEFORE UPDATE ON custody_events BEGIN
                    SELECT RAISE(ABORT, 'custody ledger is append-only');
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS custody_events_no_delete
                BEFORE DELETE ON custody_events BEGIN
                    SELECT RAISE(ABORT, 'custody ledger is append-only');
                END
                """
            )
            return connection
        except Exception:
            connection.close()
            raise

    def _read_custody_head(self) -> tuple[int, str]:
        path = self._custody_head_path()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or not 0 < int(before.st_size) <= _CUSTODY_HEAD_MAX_BYTES
            ):
                raise OSError("custody high-water object has an unsafe byte bound")
            payload = os.read(descriptor, _CUSTODY_HEAD_MAX_BYTES + 1)
            after = os.fstat(descriptor)
            current = os.lstat(path)
            if (
                len(payload) != int(before.st_size)
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or (current.st_dev, current.st_ino)
                != (after.st_dev, after.st_ino)
            ):
                raise OSError("custody high-water changed while read")
            value = _bounded_custody_json(
                payload,
                label="custody high-water",
                max_bytes=_CUSTODY_HEAD_MAX_BYTES,
            )
            sequence = int(value["sequence"])
            head = str(value["head_hmac"])
            supplied = str(value["hmac_sha256"])
        except Exception as exc:
            raise OSError("custody high-water is unreadable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        core = {
            "schema": _CUSTODY_LEDGER_SCHEMA,
            "sequence": sequence,
            "head_hmac": head,
        }
        expected = self._custody_mac(core)
        if (
            sequence < 0
            or len(head) != 64
            or set(value) != {*core, "hmac_sha256"}
            or any(value.get(key) != expected for key, expected in core.items())
            or not hmac.compare_digest(expected, supplied)
        ):
            raise OSError("custody high-water authentication failed")
        return sequence, head

    def _write_custody_head(self, sequence: int, head: str) -> None:
        path = self._custody_head_path()
        core = {
            "schema": _CUSTODY_LEDGER_SCHEMA,
            "sequence": sequence,
            "head_hmac": head,
        }
        value = {**core, "hmac_sha256": self._custody_mac(core)}
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _load_custody_state(
        self, *, create: bool = True, _lease_held: bool = False
    ) -> tuple[
        sqlite3.Connection,
        dict[str, tuple[tuple[int, int], int, str, tuple[int, int]]],
    ]:
        if not _lease_held:
            with ExclusiveFileLease(self._custody_lease_path()):
                return self._load_custody_state(
                    create=create, _lease_held=True
                )
        bundle_exists = (
            self._custody_key_path().exists(),
            self._custody_ledger_path().exists(),
            self._custody_head_path().exists(),
        )
        witness_exists = (
            self._custody_enrollment_key_path().exists(),
            self._custody_witness_path().exists(),
        )
        transition_exists = (
            self._custody_transition_path().exists()
            or self._custody_transition_path().is_symlink()
        )
        if transition_exists and not self._custody_enrollment_key_path().exists():
            raise OSError("pending custody transition lost its signing authority")
        pending = self._read_pending_transition()
        local_genesis_marker = self._read_local_genesis_marker()
        genesis_pending = bool(
            pending is not None
            and pending["previous_revision"] == 0
            and pending["previous_state_digest"] == ZERO_DIGEST
            and pending["previous_head"] == ZERO_DIGEST
            and pending["local_sequence"] == 0
            and pending["local_head"] == _CUSTODY_GENESIS
            and pending["state_digest"]
            == self._custody_state_digest(0, _CUSTODY_GENESIS)
        )
        pristine = not any(bundle_exists) and not any(witness_exists) and pending is None
        if pristine and self._custody_high_water is None:
            # This durable pre-key marker makes a crash inside key/ledger
            # creation restart-reconcilable without treating arbitrary partial
            # bundles as a fresh installation.
            self._ensure_local_genesis_marker()
            local_genesis_marker = self._read_local_genesis_marker()
        local_genesis_pending = bool(
            local_genesis_marker is not None
            and self._custody_high_water is None
            and pending is None
            and not bundle_exists[1]
            and not bundle_exists[2]
            and not any(witness_exists)
        )
        external_first_candidate = bool(
            not any(bundle_exists)
            and not witness_exists[1]
            and pending is None
            and self._custody_high_water is not None
        )
        fresh_authority = (
            pristine
            or external_first_candidate
            or genesis_pending
            or local_genesis_pending
        )
        if fresh_authority and not create:
            raise OSError("custody authority is not enrolled")
        if external_first_candidate:
            installation_id = validate_installation_id(
                self._custody_high_water.installation_id
            )
            readiness = assess_high_water(
                self._custody_high_water,
                domain=_CUSTODY_EXTERNAL_DOMAIN,
                installation_id=installation_id,
                revision=0,
                state_digest=self._custody_state_digest(0, _CUSTODY_GENESIS),
            )
            if readiness.state != "ready-first-enrollment":
                self._custody_freshness = readiness
                raise OSError(
                    "RECOVERY_REQUIRED: independent custody history forbids re-enrollment"
                )
            self._write_pending_transition(
                installation_id=installation_id,
                previous_revision=0,
                previous_state_digest=ZERO_DIGEST,
                previous_head=ZERO_DIGEST,
                local_sequence=0,
                local_head=_CUSTODY_GENESIS,
            )
            pending = self._read_pending_transition()
            genesis_pending = True
            witness_exists = (True, self._custody_witness_path().exists())
        if genesis_pending:
            if self._custody_high_water is None or pending is None:
                raise OSError(
                    "RECOVERY_REQUIRED: first-enrollment authority is unavailable"
                )
            installation_id = validate_installation_id(
                self._custody_high_water.installation_id
            )
            if pending["installation_id"] != installation_id:
                raise OSError(
                    "RECOVERY_REQUIRED: first-enrollment installation changed"
                )
        if (
            any(bundle_exists)
            and not all(bundle_exists)
            and not genesis_pending
            and not local_genesis_pending
        ):
            raise OSError("custody authority bundle is incomplete")
        if (
            any(witness_exists)
            and not all(witness_exists)
            and not genesis_pending
            and not local_genesis_pending
        ):
            raise OSError("custody enrollment witness is incomplete")
        if not fresh_authority and (
            not all(bundle_exists) or not all(witness_exists)
        ):
            raise OSError("custody authority deletion or unenrolled rollback detected")

        connection = self._open_custody_ledger(
            create=create,
            allow_genesis_repair=genesis_pending or local_genesis_pending,
        )
        active: dict[str, tuple[tuple[int, int], int, str, tuple[int, int]]] = {}
        sequence = 0
        previous = _CUSTODY_GENESIS
        pending_evictions: set[str] = set()
        alias_events: set[str] = set()
        topology_events: set[str] = set()
        durable_loss = 0
        durable_aliases = 0
        durable_topology = 0
        durable_refusals = 0
        durable_evictions = 0
        try:
            rows = connection.execute(
                "SELECT sequence,event,name,device,inode,size,sha256,"
                "root_device,root_inode,previous_hmac,record_hmac "
                "FROM custody_events ORDER BY sequence LIMIT ?",
                (_CUSTODY_LEDGER_MAX_EVENTS + 1,),
            )
            saw_rows = False
            for row in rows:
                current = int(row[0])
                saw_rows = True
                if current > _CUSTODY_LEDGER_MAX_EVENTS:
                    raise OSError("custody ledger event capacity exceeded")
                event = str(row[1])
                name = str(row[2])
                identity = (int(row[3]), int(row[4]))
                size = int(row[5])
                digest = str(row[6])
                root_identity = (int(row[7]), int(row[8]))
                prior = str(row[9])
                supplied = str(row[10])
                core = self._custody_core(
                    current,
                    event,
                    name,
                    identity,
                    size,
                    digest,
                    root_identity,
                    prior,
                )
                evidence_event = event in _CUSTODY_EVIDENCE_EVENTS
                state_event = event in _CUSTODY_STATE_EVENTS
                if (
                    current != sequence + 1
                    or event not in _CUSTODY_EVENTS
                    or not 0 <= size <= _QUARANTINE_MAX_ITEM_BYTES
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                    or prior != previous
                    or not hmac.compare_digest(self._custody_mac(core), supplied)
                    or (
                        evidence_event
                        and _QUARANTINE_NAME.fullmatch(name) is None
                    )
                    or (
                        state_event
                        and (
                            name != _CUSTODY_STATE_NAME
                            or identity != (0, 0)
                            or not 1 <= size <= _CUSTODY_COUNTER_MAX
                        )
                    )
                ):
                    raise OSError("custody ledger authentication failed")
                if event == "commit":
                    if name in active:
                        raise OSError("custody ledger duplicated an active record")
                    active[name] = (identity, size, digest, root_identity)
                elif event == "evict_intent":
                    if active.get(name) != (identity, size, digest, root_identity):
                        raise OSError("custody eviction intent did not match active evidence")
                    pending_evictions.add(name)
                elif event == "evict":
                    if active.get(name) != (identity, size, digest, root_identity):
                        raise OSError("custody eviction did not match an active record")
                    active.pop(name)
                    pending_evictions.discard(name)
                    durable_evictions = min(
                        _CUSTODY_COUNTER_MAX, durable_evictions + 1
                    )
                    durable_loss = min(_CUSTODY_COUNTER_MAX, durable_loss + 1)
                elif event == "alias":
                    if active.get(name) != (identity, size, digest, root_identity):
                        raise OSError("custody alias event did not match active evidence")
                    durable_aliases = min(
                        _CUSTODY_COUNTER_MAX, durable_aliases + 1
                    )
                    alias_events.add(name)
                elif event == "topology":
                    if active.get(name) != (identity, size, digest, root_identity):
                        raise OSError("custody topology event did not match active evidence")
                    durable_topology = min(
                        _CUSTODY_COUNTER_MAX, durable_topology + 1
                    )
                    topology_events.add(name)
                elif event in {"pending_loss", "continuity_loss"}:
                    durable_loss = min(_CUSTODY_COUNTER_MAX, durable_loss + size)
                elif event == "refuse":
                    durable_refusals = min(
                        _CUSTODY_COUNTER_MAX, durable_refusals + size
                    )
                    durable_loss = min(_CUSTODY_COUNTER_MAX, durable_loss + size)
                sequence = current
                previous = supplied

            head_path = self._custody_head_path()
            head_value = self._read_custody_head() if head_path.exists() else None
            witness_value = (
                self._read_custody_witness()
                if self._custody_witness_path().exists()
                else None
            )
            if pending is None:
                if head_value is None:
                    if saw_rows or self._custody_key_path().exists() and not create:
                        raise OSError("custody high-water is missing")
                    self._write_custody_head(sequence, previous)
                    head_value = (sequence, previous)
                if (
                    head_value[0] != sequence
                    or not hmac.compare_digest(head_value[1], previous)
                ):
                    raise OSError("custody ledger rolled back or is incomplete")
                if fresh_authority and witness_value is None:
                    self._write_custody_witness(sequence, previous)
                    witness_value = (sequence, previous)
                if witness_value is None or (
                    witness_value[0] != sequence
                    or not hmac.compare_digest(witness_value[1], previous)
                ):
                    raise OSError(
                        "custody authority rolled back behind enrolled witness"
                    )
            else:
                ledger_is_new = bool(
                    pending["local_sequence"] == sequence
                    and pending["local_head"] == previous
                    and pending["state_digest"]
                    == self._custody_state_digest(sequence, previous)
                )
                ledger_is_old = bool(
                    int(pending["previous_revision"]) > 0
                    and sequence + 1 == pending["previous_revision"]
                    and pending["previous_state_digest"]
                    == self._custody_state_digest(sequence, previous)
                )
                if not ledger_is_new and not ledger_is_old:
                    raise OSError(
                        "custody ledger does not match pending transition"
                    )

                def metadata_is_new(value: tuple[int, str] | None) -> bool:
                    return bool(
                        value is not None
                        and value[0] == sequence
                        and hmac.compare_digest(value[1], previous)
                    )

                def metadata_is_old(value: tuple[int, str] | None) -> bool:
                    return bool(
                        value is not None
                        and int(pending["previous_revision"]) > 0
                        and value[0] + 1 == pending["previous_revision"]
                        and pending["previous_state_digest"]
                        == self._custody_state_digest(value[0], value[1])
                    )

                if ledger_is_old:
                    if not metadata_is_new(head_value) or not metadata_is_new(
                        witness_value
                    ):
                        raise OSError(
                            "custody predecessor metadata conflicts with transition"
                        )
                else:
                    head_is_new = metadata_is_new(head_value)
                    head_is_old = metadata_is_old(head_value)
                    witness_is_new = metadata_is_new(witness_value)
                    witness_is_old = metadata_is_old(witness_value)
                    if head_value is None:
                        if not genesis_pending or witness_value is not None:
                            raise OSError(
                                "custody head is missing outside genesis recovery"
                            )
                        self._write_custody_head(sequence, previous)
                        head_is_new = True
                    elif head_is_old:
                        if not witness_is_old:
                            raise OSError(
                                "custody witness advanced before local head"
                            )
                        self._write_custody_head(sequence, previous)
                        head_is_new = True
                    elif not head_is_new:
                        raise OSError("custody head conflicts with transition")
                    if head_is_new:
                        if witness_value is None:
                            if not genesis_pending:
                                raise OSError(
                                    "custody witness is missing outside genesis recovery"
                                )
                            self._write_custody_witness(sequence, previous)
                            witness_is_new = True
                        elif witness_is_old:
                            self._write_custody_witness(sequence, previous)
                            witness_is_new = True
                        elif not witness_is_new:
                            raise OSError(
                                "custody witness conflicts with transition"
                            )
                    if not witness_is_new:
                        raise OSError("custody metadata repair is incomplete")
            self._establish_external_custody(
                sequence, previous, fresh_authority=fresh_authority
            )
            self._custody_ledger_sequence = sequence
            self._custody_ledger_head = previous
            self._custody_pending_evictions = pending_evictions
            self._custody_alias_events = alias_events
            self._custody_topology_events = topology_events
            self._custody_loss = max(self._custody_loss, durable_loss)
            self._quarantine_alias_residue = max(
                self._quarantine_alias_residue, durable_aliases
            )
            self._custody_topology_uncertain = max(
                self._custody_topology_uncertain, durable_topology
            )
            self._custody_refusals = max(self._custody_refusals, durable_refusals)
            self._custody_evictions = max(self._custody_evictions, durable_evictions)
            self._quarantine_dropped = max(
                self._quarantine_dropped, durable_refusals
            )
            self._custody_degraded = self._custody_degraded or bool(
                durable_loss
                or durable_aliases
                or durable_topology
                or durable_refusals
                or durable_evictions
                or pending_evictions
            )
            self._custody_remaining_events = max(
                0, _CUSTODY_LEDGER_MAX_EVENTS - sequence
            )
            self._custody_capacity_exhausted = (
                self._custody_remaining_events
                < _CUSTODY_TERMINAL_RESERVE + _CUSTODY_ARCHIVE_EVENT_BUDGET
            )
            self._custody_authority_initialized = True
            self._custody_witness_verified = True
            if self._custody_high_water is None:
                self._remove_local_genesis_marker()
            return connection, active
        except Exception:
            connection.close()
            raise

    def _append_custody_event(
        self,
        event: str,
        name: str,
        identity: tuple[int, int],
        size: int,
        digest: str,
        root_identity: tuple[int, int],
        *,
        _lease_held: bool = False,
    ) -> None:
        if not _lease_held:
            with ExclusiveFileLease(self._custody_lease_path()):
                self._append_custody_event(
                    event,
                    name,
                    identity,
                    size,
                    digest,
                    root_identity,
                    _lease_held=True,
                )
                return
        if event not in _CUSTODY_EVENTS:
            raise ValueError("unsupported custody event")
        connection, _active = self._load_custody_state(
            create=True, _lease_held=True
        )
        sequence = self._custody_ledger_sequence + 1
        if sequence > _CUSTODY_LEDGER_MAX_EVENTS:
            connection.close()
            raise OSError("custody ledger capacity reached; evidence retained")
        if (
            event == "commit"
            and sequence
            > _CUSTODY_LEDGER_MAX_EVENTS - _CUSTODY_TERMINAL_RESERVE
        ):
            connection.close()
            raise OSError("custody terminal-event reserve reached; capture refused")
        core = self._custody_core(
            sequence,
            event,
            name,
            identity,
            size,
            digest,
            root_identity,
            self._custody_ledger_head,
        )
        record_hmac = self._custody_mac(core)
        try:
            # Persist the exact predecessor/new-state CAS before the local
            # transaction.  A crash can therefore be classified as
            # pre-commit, local-ahead, or committed-but-response-lost.
            self._prepare_external_custody(sequence, record_hmac)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO custody_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    sequence,
                    event,
                    name,
                    str(identity[0]),
                    str(identity[1]),
                    size,
                    digest,
                    str(root_identity[0]),
                    str(root_identity[1]),
                    self._custody_ledger_head,
                    record_hmac,
                ),
            )
            connection.execute("COMMIT")
            self._write_custody_head(sequence, record_hmac)
            self._write_custody_witness(sequence, record_hmac)
            # Reconcile the pre-committed transition.  A lost response is
            # accepted only when a fresh authenticated read returns the exact
            # new revision/digest/predecessor tuple.
            self._advance_external_custody(sequence, record_hmac)
            self._custody_ledger_sequence = sequence
            self._custody_ledger_head = record_hmac
            self._custody_remaining_events = max(
                0, _CUSTODY_LEDGER_MAX_EVENTS - sequence
            )
            self._custody_capacity_exhausted = (
                self._custody_remaining_events
                < _CUSTODY_TERMINAL_RESERVE + _CUSTODY_ARCHIVE_EVENT_BUDGET
            )
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            # Keep every authenticated pending transition through an ambiguous
            # COMMIT result.  Restart reconciliation classifies the exact local
            # predecessor/new-ledger state before it removes or advances it.
            raise
        finally:
            connection.close()

    def _append_custody_state_event(
        self,
        event: str,
        reason: str,
        root_identity: tuple[int, int],
        *,
        count: int = 1,
    ) -> None:
        if event not in _CUSTODY_STATE_EVENTS or not 1 <= count <= _CUSTODY_COUNTER_MAX:
            raise ValueError("invalid custody state event")
        digest = hashlib.sha256(
            f"{event}|{reason[:240]}".encode("utf-8", "strict")
        ).hexdigest()
        self._append_custody_event(
            event,
            _CUSTODY_STATE_NAME,
            (0, 0),
            count,
            digest,
            root_identity,
        )
        self._custody_degraded = True
        self._custody_loss = min(
            _CUSTODY_COUNTER_MAX, self._custody_loss + count
        )
        if event == "refuse":
            self._custody_refusals = min(
                _CUSTODY_COUNTER_MAX, self._custody_refusals + count
            )

    def _allowed_quarantine_path(self, path: Path) -> bool:
        root = self._quarantine_directory()
        return (
            self._path_key(path.parent) == self._path_key(root)
            and _QUARANTINE_NAME.fullmatch(path.name) is not None
        )

    def _protect_custody_path(self, path: Path) -> bool:
        """Apply and verify the service/admin-only custody boundary."""
        required = key_acl_required()
        if os.name != "nt" and path.is_dir():
            path.chmod(0o700)
            protected = (path.stat().st_mode & 0o077) == 0
        else:
            applied = secure_sensitive_file(path, required=required)
            protected = applied and (
                os.name != "nt" or sensitive_file_is_protected(path)
            )
        if required and not protected:
            raise OSError("custody namespace ACL could not be verified")
        if self._custody_namespace_protected is None:
            self._custody_namespace_protected = protected
        else:
            self._custody_namespace_protected = (
                self._custody_namespace_protected and protected
            )
        return protected

    def _open_quarantine_directory(self) -> tuple[int, tuple[int, int]]:
        root = self._quarantine_directory()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._protect_custody_path(root)
        descriptor, identity = self._open_custody_path(root, directory=True)
        enrolled = self._quarantine_root_identity
        if enrolled is None:
            self._quarantine_root_identity = identity
        elif enrolled != identity:
            os.close(descriptor)
            raise OSError("quarantine root identity changed after enrollment")
        return descriptor, identity

    def _quarantine_inventory(
        self, root_descriptor: int, root_identity: tuple[int, int]
    ) -> list[tuple[Path, tuple[int, int], int, float]]:
        root = self._quarantine_directory()
        ledger, expected_records = self._load_custody_state(create=True)
        ledger.close()
        records: list[tuple[Path, tuple[int, int], int, float]] = []
        observed: dict[
            str, tuple[tuple[int, int], int, str, tuple[int, int]]
        ] = {}
        scanned = 0
        with os.scandir(root) as iterator:
            for entry in iterator:
                scanned += 1
                if scanned > _QUARANTINE_SCAN_MAX:
                    raise OSError("quarantine inventory scan bound exceeded")
                name_match = _QUARANTINE_NAME.fullmatch(entry.name)
                if name_match is None:
                    if _QUARANTINE_PENDING.fullmatch(entry.name) is not None:
                        pending = root / entry.name
                        descriptor: int | None = None
                        try:
                            info = pending.lstat()
                            if (
                                entry.is_symlink()
                                or self._is_reparse(info)
                                or not stat.S_ISREG(info.st_mode)
                                or int(info.st_nlink) != 1
                                or not 0
                                <= int(info.st_size)
                                <= _QUARANTINE_MAX_ITEM_BYTES
                            ):
                                raise OSError("pending custody object is unsafe")
                            descriptor, _identity = self._open_custody_path(
                                pending, expected=self._identity(info)
                            )
                            self._append_custody_state_event(
                                "pending_loss",
                                "incomplete pending evidence recovered",
                                root_identity,
                            )
                            self._delete_held(descriptor)
                            self._custody_degraded = True
                            continue
                        finally:
                            if descriptor is not None:
                                os.close(descriptor)
                    raise OSError("quarantine contains an unrecognized object")
                # DirEntry's Windows fast-path can report a zero file index.
                # lstat obtains the full identity used for the later held open.
                info = (root / entry.name).lstat()
                if entry.is_symlink() or self._is_reparse(info) or not stat.S_ISREG(
                    info.st_mode
                ):
                    raise OSError("quarantine contains an invalid custody object")
                if not 0 <= int(info.st_size) <= _QUARANTINE_MAX_ITEM_BYTES:
                    raise OSError("quarantine evidence exceeds its custody bound")
                evidence_path = root / entry.name
                self._protect_custody_path(evidence_path)
                if int(info.st_nlink) != 1:
                    expected_alias = expected_records.get(entry.name)
                    if (
                        expected_alias is not None
                        and entry.name not in self._custody_alias_events
                    ):
                        self._append_custody_event(
                            "alias", entry.name, *expected_alias
                        )
                    raise OSError("quarantine evidence has an untrusted hard-link alias")
                descriptor: int | None = None
                try:
                    descriptor, held_identity = self._open_custody_path(
                        evidence_path, expected=self._identity(info)
                    )
                    before = os.fstat(descriptor)
                    payload_parts: list[bytes] = []
                    remaining = int(before.st_size)
                    while remaining:
                        chunk = os.read(descriptor, min(64 * 1024, remaining))
                        if not chunk:
                            raise OSError("quarantine evidence ended before its receipt")
                        payload_parts.append(chunk)
                        remaining -= len(chunk)
                    if os.read(descriptor, 1):
                        raise OSError("quarantine evidence exceeded its receipt")
                    payload = b"".join(payload_parts)
                    after = os.fstat(descriptor)
                    if (
                        held_identity != self._identity(info)
                        or self._identity(before) != held_identity
                        or self._identity(after) != held_identity
                        or int(before.st_nlink) != 1
                        or int(after.st_nlink) != 1
                        or int(before.st_size) != len(payload)
                        or int(after.st_size) != len(payload)
                        or not hmac.compare_digest(
                            hashlib.sha256(payload).hexdigest(), name_match.group(2)
                        )
                    ):
                        expected_alias = expected_records.get(entry.name)
                        if (
                            expected_alias is not None
                            and (
                                int(before.st_nlink) != 1
                                or int(after.st_nlink) != 1
                            )
                            and entry.name not in self._custody_alias_events
                        ):
                            self._append_custody_event(
                                "alias", entry.name, *expected_alias
                            )
                        raise OSError("quarantine evidence custody digest changed")
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                records.append(
                    (
                        evidence_path,
                        self._identity(info),
                        max(0, int(info.st_size)),
                        int(name_match.group(1)) / 1000.0,
                    )
                )
                observed[entry.name] = (
                    self._identity(info),
                    max(0, int(info.st_size)),
                    str(name_match.group(2)),
                    root_identity,
                )
        # Enumeration used a path only for discovery.  No discovered pathname is
        # mutation authority, and the root must still be the held enrolled object
        # before any exact-object deletions are attempted.
        after = root.lstat()
        if (
            self._is_reparse(after)
            or stat.S_ISLNK(after.st_mode)
            or self._identity(after) != root_identity
            or self._identity(os.fstat(root_descriptor)) != root_identity
        ):
            raise OSError("quarantine root identity changed during inventory")
        if observed != expected_records:
            self._custody_degraded = True
            missing = sorted(set(expected_records) - set(observed))
            foreign = sorted(set(observed) - set(expected_records))
            substituted = sorted(
                name
                for name in set(observed) & set(expected_records)
                if observed[name] != expected_records[name]
            )
            if self._custody_loss == 0:
                self._append_custody_state_event(
                    "continuity_loss",
                    f"inventory mismatch missing={len(missing)} "
                    f"foreign={len(foreign)} substituted={len(substituted)}",
                    root_identity,
                )
            raise OSError(
                "quarantine custody continuity lost "
                f"(missing={len(missing)}, foreign={len(foreign)}, "
                f"substituted={len(substituted)})"
            )
        return records

    @staticmethod
    def _record_receipt(
        record: tuple[Path, tuple[int, int], int, float],
        root_identity: tuple[int, int],
    ) -> tuple[str, tuple[int, int], int, str, tuple[int, int]]:
        match = _QUARANTINE_NAME.fullmatch(record[0].name)
        if match is None:
            raise OSError("custody record name is invalid")
        return (
            record[0].name,
            record[1],
            record[2],
            str(match.group(2)),
            root_identity,
        )

    def _delete_quarantine_record(
        self, path: Path, expected: tuple[int, int]
    ) -> bool:
        if not self._allowed_quarantine_path(path):
            return False
        descriptor: int | None = None
        try:
            descriptor, _identity = self._open_custody_path(path, expected=expected)
            self._delete_held(descriptor)
            return True
        except (OSError, sqlite3.Error, ValueError):
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _refresh_quarantine_limits(
        self, *, reserve_files: int = 0, reserve_bytes: int = 0
    ) -> bool:
        """Prune retained evidence to explicit count, byte, age, and scan caps."""
        if (
            reserve_files < 0
            or reserve_bytes < 0
            or reserve_files > _QUARANTINE_MAX_FILES
            or reserve_bytes > _QUARANTINE_MAX_ITEM_BYTES
        ):
            self._quarantine_saturated = True
            return False
        root_descriptor: int | None = None
        failed = False
        try:
            root_descriptor, root_identity = self._open_quarantine_directory()
            records = self._quarantine_inventory(root_descriptor, root_identity)
            now = time.time()
            retained: list[tuple[Path, tuple[int, int], int, float]] = []
            for record in sorted(records, key=lambda item: (item[3], item[0].name)):
                if record[3] > now + 5.0 or now - record[3] > _QUARANTINE_MAX_AGE_S:
                    receipt = self._record_receipt(record, root_identity)
                    try:
                        if record[0].name not in self._custody_pending_evictions:
                            if self._custody_remaining_events < 2:
                                raise OSError(
                                    "custody ledger lacks eviction terminal capacity"
                                )
                            self._append_custody_event("evict_intent", *receipt)
                        if self._custody_remaining_events < 1:
                            raise OSError(
                                "custody ledger lacks eviction completion capacity"
                            )
                    except (OSError, sqlite3.Error, ValueError):
                        failed = True
                        retained.append(record)
                        continue
                    if not self._delete_quarantine_record(record[0], record[1]):
                        failed = True
                        retained.append(record)
                    else:
                        try:
                            self._append_custody_event("evict", *receipt)
                        except (OSError, sqlite3.Error, ValueError):
                            failed = True
                            self._custody_degraded = True
                else:
                    retained.append(record)
            total_bytes = sum(item[2] for item in retained)
            # Capacity pressure never selects an unresolved legitimate record
            # for deletion.  The incoming archive is refused and the bounded
            # drop/saturation counters make that evidence loss explicit.
            over_capacity = (
                len(retained) + reserve_files > _QUARANTINE_MAX_FILES
                or total_bytes + reserve_bytes > _QUARANTINE_MAX_BYTES
                or self._custody_capacity_exhausted
                or (
                    reserve_files > 0
                    and self._custody_ledger_sequence
                    + _CUSTODY_ARCHIVE_EVENT_BUDGET
                    > _CUSTODY_LEDGER_MAX_EVENTS - _CUSTODY_TERMINAL_RESERVE
                )
            )
            self._quarantine_count = len(retained)
            self._quarantine_bytes = total_bytes
            self._quarantine_saturated = failed or over_capacity
            return not self._quarantine_saturated
        except OSError:
            self._quarantine_saturated = True
            return False
        finally:
            if root_descriptor is not None:
                os.close(root_descriptor)

    @staticmethod
    def _create_evidence_file(path: Path) -> int:
        """Create one new evidence inode with write/delete sharing denied."""
        if os.name != "nt" or _QUARANTINE_PENDING.fullmatch(path.name) is None:
            raise OSError("exclusive evidence creation is unavailable")

        import msvcrt

        create_file, _set, close_handle, _native, _status = _custody_api()
        handle = create_file(
            str(path),
            0x80000000 | 0x40000000 | 0x00010000 | 0x0080,
            0x0001,  # share read only while sealing custody
            None,
            1,  # CREATE_NEW
            0x00200000 | 0x08000000,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            error = ctypes.get_last_error()
            raise OSError(error, "exclusive evidence creation failed")
        try:
            descriptor = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDWR
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
            )
            handle = None
            return descriptor
        finally:
            if handle not in {None, invalid}:
                close_handle(ctypes.c_void_p(handle))

    @staticmethod
    def _copy_and_verify_evidence(
        source_descriptor: int, evidence_descriptor: int, expected_size: int
    ) -> tuple[str, int]:
        """Copy a frozen source into a new inode, then reread and verify it."""
        source_before = os.fstat(source_descriptor)
        source_identity = (int(source_before.st_dev), int(source_before.st_ino))
        source_links = int(source_before.st_nlink)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source_links < 1
            or int(source_before.st_size) != expected_size
            or not 0 <= expected_size <= _QUARANTINE_MAX_ITEM_BYTES
        ):
            raise OSError("source evidence custody is invalid")

        os.lseek(source_descriptor, 0, os.SEEK_SET)
        os.lseek(evidence_descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(source_descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise OSError("source evidence ended before its held size")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(evidence_descriptor, chunk[offset:])
                if written <= 0:
                    raise OSError("short evidence write")
                offset += written
            remaining -= len(chunk)
        if os.read(source_descriptor, 1):
            raise OSError("source evidence exceeded its held size")
        os.fsync(evidence_descriptor)

        source_after = os.fstat(source_descriptor)
        if (
            (int(source_after.st_dev), int(source_after.st_ino)) != source_identity
            or int(source_after.st_size) != expected_size
            or int(source_after.st_nlink) != source_links
            or int(source_after.st_mtime_ns) != int(source_before.st_mtime_ns)
        ):
            raise OSError("source evidence changed during held copy")

        evidence_before = os.fstat(evidence_descriptor)
        evidence_identity = (
            int(evidence_before.st_dev),
            int(evidence_before.st_ino),
        )
        if (
            not stat.S_ISREG(evidence_before.st_mode)
            or int(evidence_before.st_nlink) != 1
            or int(evidence_before.st_size) != expected_size
        ):
            raise OSError("new evidence inode is not exclusively linked")
        os.lseek(evidence_descriptor, 0, os.SEEK_SET)
        verify = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(evidence_descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise OSError("sealed evidence ended before its held size")
            verify.update(chunk)
            remaining -= len(chunk)
        if os.read(evidence_descriptor, 1):
            raise OSError("sealed evidence exceeded its held size")
        evidence_after = os.fstat(evidence_descriptor)
        if (
            (int(evidence_after.st_dev), int(evidence_after.st_ino))
            != evidence_identity
            or int(evidence_after.st_nlink) != 1
            or int(evidence_after.st_size) != expected_size
            or not hmac.compare_digest(digest.digest(), verify.digest())
        ):
            raise OSError("sealed evidence failed digest revalidation")
        return digest.hexdigest(), source_links

    @staticmethod
    def _audit_held_evidence(
        descriptor: int,
        expected_identity: tuple[int, int],
        expected_size: int,
        expected_digest: str,
    ) -> int:
        """Reconcile the exact evidence object immediately before publication."""
        before = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise OSError("evidence ended during publication reconciliation")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("evidence grew during publication reconciliation")
        after = os.fstat(descriptor)
        if (
            (int(before.st_dev), int(before.st_ino)) != expected_identity
            or (int(after.st_dev), int(after.st_ino)) != expected_identity
            or int(before.st_size) != expected_size
            or int(after.st_size) != expected_size
            or int(before.st_nlink) != int(after.st_nlink)
            or not hmac.compare_digest(digest.hexdigest(), expected_digest)
        ):
            raise OSError("evidence changed at the publication boundary")
        return int(after.st_nlink)

    def _archive_held(self, descriptor: int, size: int) -> bool:
        self._last_capture_outcome = CustodyCaptureOutcome(
            "refused",
            "capture did not reach a durable source-retirement boundary",
        )
        if size > _QUARANTINE_MAX_ITEM_BYTES or not self._refresh_quarantine_limits(
            reserve_files=1, reserve_bytes=size
        ):
            return False
        root_descriptor: int | None = None
        evidence_descriptor: int | None = None
        committed = False
        source_retired = False
        name = ""
        digest = ""
        try:
            root_descriptor, root_identity = self._open_quarantine_directory()
            root = self._quarantine_directory()
            token = secrets.token_hex(12)
            pending_name = f"{_QUARANTINE_PREFIX}pending-{token}.tmp"
            pending = root / pending_name
            if self._identity(root.lstat()) != root_identity:
                return False
            evidence_descriptor = self._create_evidence_file(pending)
            if self._identity(root.lstat()) != root_identity:
                return False
            source_identity = self._identity(os.fstat(descriptor))
            digest, source_links = self._copy_and_verify_evidence(
                descriptor, evidence_descriptor, size
            )
            name = (
                f"{_QUARANTINE_PREFIX}{int(time.time() * 1000):013d}-{token}-"
                f"{digest}{_QUARANTINE_SUFFIX}"
            )
            destination = root / name
            if not self._allowed_quarantine_path(destination):
                return False
            evidence_identity = self._identity(os.fstat(evidence_descriptor))
            self._rename_held(evidence_descriptor, root_descriptor, name)
            self._protect_custody_path(destination)
            if (
                self._identity(os.fstat(evidence_descriptor)) != evidence_identity
                or self._path_identity(destination) != evidence_identity
                or int(os.fstat(evidence_descriptor).st_nlink) != 1
            ):
                return False
            self._append_custody_event(
                "commit",
                name,
                evidence_identity,
                size,
                digest,
                root_identity,
            )
            committed = True
            evidence_receipt = (
                name,
                evidence_identity,
                size,
                digest,
                root_identity,
            )
            # A race-free NTFS hard-link topology seal is not provided by the
            # reviewed userspace API.  Persist that limitation before reporting
            # archive success so restart can never promote it back to green.
            self._append_custody_event("topology", *evidence_receipt)
            evidence_links = self._audit_held_evidence(
                evidence_descriptor, evidence_identity, size, digest
            )
            if evidence_links != 1:
                self._append_custody_event("alias", *evidence_receipt)
                raise OSError("evidence hard-link topology changed before publication")
            # Only after the independent sealed evidence inode is durable do we
            # retire the original decoy link.  Any pre-existing alias remains a
            # non-evidence object and cannot mutate the retained copy.
            final_source = os.fstat(descriptor)
            final_links = int(final_source.st_nlink)
            if (
                self._identity(final_source) != source_identity
                or int(final_source.st_size) != size
            ):
                raise OSError("source custody changed before retirement")
            self._delete_held(descriptor)
            source_retired = True
            post_delete_links = int(os.fstat(descriptor).st_nlink)
            if source_links > 1 or final_links > 1 or post_delete_links > 1:
                self._append_custody_event("alias", *evidence_receipt)
            final_evidence_links = self._audit_held_evidence(
                evidence_descriptor, evidence_identity, size, digest
            )
            if final_evidence_links != 1:
                if name not in self._custody_alias_events:
                    self._append_custody_event("alias", *evidence_receipt)
                raise OSError("evidence alias appeared before archive completion")
            self._last_capture_outcome = CustodyCaptureOutcome(
                "captured_unverified",
                (
                    "evidence digest and current link count were verified, but "
                    "userspace cannot prove future topology against a local "
                    "administrator; ordinary-user ACL protection="
                    f"{int(bool(self._custody_namespace_protected))}, independent "
                    f"freshness={int(self._custody_freshness.independently_fresh)}"
                ),
                evidence_name=name,
                evidence_sha256=digest,
                source_retired=True,
                namespace_protected=bool(self._custody_namespace_protected),
                independently_fresh=self._custody_freshness.independently_fresh,
            )
        except (OSError, sqlite3.Error, ValueError) as exc:
            if source_retired and committed:
                self._last_capture_outcome = CustodyCaptureOutcome(
                    "captured_unverified",
                    f"source retired but final custody proof is uncertain: {str(exc)[:180]}",
                    evidence_name=name,
                    evidence_sha256=digest,
                    source_retired=True,
                    namespace_protected=bool(self._custody_namespace_protected),
                    independently_fresh=self._custody_freshness.independently_fresh,
                )
                return True
            self._last_capture_outcome = CustodyCaptureOutcome(
                "refused", str(exc)[:240]
            )
            return False
        finally:
            if evidence_descriptor is not None:
                if not committed:
                    try:
                        self._delete_held(evidence_descriptor)
                    except OSError:
                        self._quarantine_saturated = True
                os.close(evidence_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)
        self._refresh_quarantine_limits()
        return True

    def _delete_exact_decoy(
        self, path: Path, expected: tuple[int, int], *, require_anchor: bool
    ) -> bool:
        descriptor: int | None = None
        try:
            descriptor, _identity = self._open_custody_path(path, expected=expected)
            if require_anchor:
                info = os.fstat(descriptor)
                data = os.read(descriptor, _MAX_ANCHOR_READ)
                if int(info.st_size) != len(_ANCHOR_BYTES) or data != _ANCHOR_BYTES:
                    return False
            self._delete_held(descriptor)
            return True
        except OSError:
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _create_decoy_file(path: Path) -> int:
        """Exclusively create a decoy while retaining exact delete authority."""
        if os.name != "nt":
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            return os.open(path, flags, 0o600)

        import msvcrt

        create_file, _set, close_handle, _native, _status = _custody_api()
        handle = create_file(
            str(path),
            0x80000000 | 0x40000000 | 0x00010000 | 0x0080,
            0x0001 | 0x0004,
            None,
            1,  # CREATE_NEW
            0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            error = ctypes.get_last_error()
            raise OSError(error, "exclusive honeytoken creation failed")
        try:
            descriptor = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDWR
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
            )
            handle = None
            return descriptor
        finally:
            if handle not in {None, invalid}:
                close_handle(ctypes.c_void_p(handle))

    def _write_decoy(self, path: str) -> bool:
        descriptor: int | None = None
        try:
            candidate = Path(path)
            if not self._allowed_decoy_path(candidate):
                return False
            parent_before = candidate.parent.lstat()
            if (
                self._is_reparse(parent_before)
                or stat.S_ISLNK(parent_before.st_mode)
                or not stat.S_ISDIR(parent_before.st_mode)
            ):
                return False
            descriptor = self._create_decoy_file(candidate)
            written = 0
            while written < len(_ANCHOR_BYTES):
                count = os.write(descriptor, _ANCHOR_BYTES[written:])
                if count <= 0:
                    raise OSError("short honeytoken write")
                written += count
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            after = candidate.lstat()
            parent_after = candidate.parent.lstat()
            identity = self._identity(opened)
            if (
                not stat.S_ISREG(opened.st_mode)
                or self._is_reparse(after)
                or self._identity(after) != identity
                or self._identity(parent_before) != self._identity(parent_after)
            ):
                raise OSError("honeytoken identity changed during exclusive creation")
            self._decoy_identity[self._path_key(candidate)] = identity
            _hide_decoy_handle(descriptor)
            return True
        except Exception:
            # If exclusive creation succeeded but a later invariant failed,
            # dispose only that same held object. Never unlink a pathname.
            if descriptor is not None:
                try:
                    if os.name == "nt":
                        self._delete_held(descriptor)
                except OSError:
                    pass
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    # ── Monitoring ────────────────────────────────────────────────────────────
    def _inspect_decoy(self, path: str) -> tuple[Optional[str], tuple[int, int] | None]:
        """Read at most anchor-length+1 bytes from one stable no-follow object."""
        candidate = Path(path)
        expected = self._decoy_identity.get(self._path_key(candidate))
        try:
            descriptor, identity = self._open_existing_nofollow(candidate)
        except FileNotFoundError:
            return "deleted/wiped", None
        except OSError as exc:
            return f"object unavailable or exclusively locked: {str(exc)[:160]}", None
        try:
            if expected is None:
                return "deployment identity unavailable", identity
            if identity != expected:
                return "object identity replaced", identity
            info = os.fstat(descriptor)
            data = os.read(descriptor, _MAX_ANCHOR_READ)
            if int(info.st_size) != len(_ANCHOR_BYTES) or data != _ANCHOR_BYTES:
                return "anchor token missing (encrypted/overwritten)", identity
            return None, identity
        except OSError as exc:
            return f"bounded anchor read failed: {str(exc)[:160]}", identity
        finally:
            os.close(descriptor)

    def _check_decoy(self, path: str) -> Optional[str]:
        """Return a tamper reason if compromised, else None."""
        reason, _identity = self._inspect_decoy(path)
        return reason

    def _record_custody_refusal(self, reason: str) -> None:
        root_descriptor: int | None = None
        try:
            root_descriptor, root_identity = self._open_quarantine_directory()
            self._append_custody_state_event(
                "refuse", reason, root_identity
            )
        except (OSError, sqlite3.Error, ValueError):
            self._custody_degraded = True
            self._custody_loss = min(
                _CUSTODY_COUNTER_MAX, self._custody_loss + 1
            )
        finally:
            if root_descriptor is not None:
                os.close(root_descriptor)
        self._quarantine_dropped = min(
            _CUSTODY_COUNTER_MAX, self._quarantine_dropped + 1
        )

    def _retire_tampered_decoy(self, path: str) -> bool:
        """Retire only the exact opened object before exclusive restaging."""
        candidate = Path(path)
        key = self._path_key(candidate)
        expected = self._decoy_identity.get(key)
        descriptor: int | None = None
        try:
            if expected is None:
                return False
            descriptor, current = self._open_custody_path(
                candidate, expected=expected
            )
        except FileNotFoundError:
            self._record_custody_refusal("tampered decoy disappeared before capture")
            self._decoy_identity.pop(key, None)
            return True
        except OSError:
            return False
        try:
            if current != expected:
                return False
            size = max(0, int(os.fstat(descriptor).st_size))
            if not self._archive_held(descriptor, size):
                # No source retirement occurs without a durable evidence
                # commit and reserved terminal capacity.  The exact tampered
                # object remains held/in place for retry and manual collection.
                self._record_custody_refusal(
                    "tampered decoy capture refused before source retirement"
                )
                return False
            self._decoy_identity.pop(key, None)
            return True
        except OSError:
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _restage_tripped_decoy(self, path: str) -> bool:
        if not self._retire_tampered_decoy(path):
            return False
        return self._write_decoy(path)

    def _trip_key(self, path: str, now: float) -> str:
        # One logical slot has one alert identity per bounded attack epoch.  A
        # newly restaged inode cannot manufacture a fresh incident.
        epoch = int(now // _TRIP_DEDUP_S)
        return hashlib.sha256(
            f"{self._path_key(path)}|{epoch}".encode("utf-8")
        ).hexdigest()

    def _prune_trip_alerts(self, now: float) -> None:
        """Expire and hard-cap dedup state independently of the run loop."""
        cutoff = now - _TRIP_DEDUP_S
        retained: list[tuple[str, float]] = []
        evicted = 0
        saturated = False
        for key, stamp in self._trip_alerts.items():
            if (
                not isinstance(key, str)
                or len(key) != 64
                or type(stamp) not in {int, float}
                or not math.isfinite(float(stamp))
                or float(stamp) > now + 5.0
            ):
                evicted += 1
                saturated = True
                continue
            if float(stamp) < cutoff:
                evicted += 1
                continue
            retained.append((key, float(stamp)))
        retained.sort(key=lambda item: (item[1], item[0]), reverse=True)
        if len(retained) > _TRIP_ALERT_MAX:
            evicted += len(retained) - _TRIP_ALERT_MAX
            retained = retained[:_TRIP_ALERT_MAX]
            saturated = True
        self._trip_alerts = dict(retained)
        self._trip_alert_evictions = min(
            _CUSTODY_COUNTER_MAX, self._trip_alert_evictions + evicted
        )
        self._trip_alert_saturated = self._trip_alert_saturated or saturated

    def _trip(self, path: str, reason: str) -> None:
        now = time.time()
        self._prune_trip_alerts(now)
        incident = self._trip_key(path, now)
        last_alert = self._trip_alerts.get(incident, 0.0)
        if now - last_alert >= _TRIP_DEDUP_S:
            self._trip_alerts[incident] = now
            self._prune_trip_alerts(now)
            self._trips += 1
            self.emit(
                f"HONEYTOKEN TRIPPED: {os.path.basename(path)} — {reason}",
                Severity.CRITICAL,
                path=path,
                reason=reason,
                incident_id=incident,
                deduplicated=False,
                bounded_anchor_read_bytes=_MAX_ANCHOR_READ,
            )
        # Recovery is retried even while duplicate alerts are suppressed. The
        # exact tampered object must be retired before exclusive restaging.
        if self._restage_tripped_decoy(path):
            self._unresolved_trips.discard(self._path_key(path))
        else:
            self._unresolved_trips.add(self._path_key(path))

    def _update_health(self) -> None:
        live = max(0, len(self._decoys) - len(self._unresolved_trips))
        note = (
            f"live={live}, failed={self._deploy_failures + self._monitor_errors}, "
            f"tripped={self._trips}, unresolved={len(self._unresolved_trips)}, "
            f"quarantine={self._quarantine_count}/{self._quarantine_bytes}B, "
            f"dropped={self._quarantine_dropped}, "
            f"aliases={self._quarantine_alias_residue}, "
            f"custody_degraded={int(self._custody_degraded)}, "
            f"custody_loss={self._custody_loss}, "
            f"custody_sequence={self._custody_ledger_sequence}, "
            f"custody_remaining={self._custody_remaining_events}, "
            f"custody_capacity_exhausted={int(self._custody_capacity_exhausted)}, "
            f"custody_topology_uncertain={self._custody_topology_uncertain}, "
            f"custody_refusals={self._custody_refusals}, "
            f"custody_evictions={self._custody_evictions}, "
            f"custody_witness_verified={int(self._custody_witness_verified)}, "
            f"authority_configured={int(self._custody_high_water is not None)}, "
            f"freshness={self._custody_freshness.state}, "
            f"independently_fresh={int(self._custody_freshness.independently_fresh)}, "
            f"external_transition_pending={int(self._custody_transition_path().exists())}, "
            f"namespace_protected={int(bool(self._custody_namespace_protected))}, "
            f"prior_history_may_have_been_erased={int(self._custody_prior_history_uncertain)}, "
            f"capture_outcome={self._last_capture_outcome.state}, "
            f"saturated={int(self._quarantine_saturated)}, "
            f"dedup={len(self._trip_alerts)}/{_TRIP_ALERT_MAX}, "
            f"dedup_evicted={self._trip_alert_evictions}, "
            f"dedup_saturated={int(self._trip_alert_saturated)}"
        )
        if not self._decoys:
            self.set_health(30, note)
        elif self._unresolved_trips:
            self.set_health(55, note)
        elif (
            self._quarantine_saturated
            or self._custody_capacity_exhausted
            or self._quarantine_dropped
            or self._custody_degraded
            or self._custody_loss
            or self._trip_alert_saturated
            or self._custody_namespace_protected is False
        ):
            self.set_health(65, note)
        elif self._deploy_failures or self._monitor_errors:
            self.set_health(70, note)
        elif self._generation_degraded:
            self.set_health(80, note + "; local model name generation unavailable")
        elif self._custody_high_water is not None and not self._custody_authority_initialized:
            self.set_health(
                80,
                note + "; independent custody authority is not yet verified",
            )
        elif self._custody_authority_initialized:
            if self._custody_freshness.independently_fresh:
                # An external monotonic head proves rollback freshness, but the
                # evidence bytes are still local rather than WORM storage.
                self.set_health(95, note + "; local evidence is not remote/WORM replicated")
            else:
                self.set_health(
                    70,
                    note
                    + "; local-authenticity-only: prior custody may have been erased",
                )
        else:
            self.set_health(100, note if self._trip_alert_evictions else "")

    # ── Loop ──────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._deploy(self._generate_names())
        self._last_refresh = time.time()

        while not self.stopping:
            self._monitor_errors = 0
            for path in list(self._decoys):
                try:
                    reason = self._check_decoy(path)
                    if reason:
                        self._trip(path, reason)
                    else:
                        self._unresolved_trips.discard(self._path_key(path))
                except Exception:
                    self._monitor_errors += 1
                    self._unresolved_trips.add(self._path_key(path))

            if time.time() - self._last_refresh >= self.REFRESH_S:
                self._deploy(self._generate_names())
                self._last_refresh = time.time()

            now = time.time()
            self._prune_trip_alerts(now)
            if now - self._last_quarantine_audit >= _QUARANTINE_AUDIT_S:
                self._refresh_quarantine_limits()
                self._last_quarantine_audit = now
            self._update_health()
            self.sleep(self.MONITOR_S)

    def stop(self) -> None:
        # Best-effort cleanup so we don't leave decoys behind on shutdown.
        self._cleanup_deployed_decoys()
        super().stop()

    def self_test(self) -> tuple[bool, str]:
        if _MAX_ANCHOR_READ != len(_ANCHOR_BYTES) + 1:
            return False, "bounded honeytoken read contract is invalid"
        if not (
            0 < _QUARANTINE_MAX_ITEM_BYTES <= _QUARANTINE_MAX_BYTES
            and 0 < _QUARANTINE_MAX_FILES <= _QUARANTINE_SCAN_MAX
            and _QUARANTINE_MAX_AGE_S > 0
            and 0 < _TRIP_ALERT_MAX <= _CUSTODY_COUNTER_MAX
            and _QUARANTINE_MAX_FILES * 2 < _CUSTODY_LEDGER_MAX_EVENTS
            and 0 < _CUSTODY_ARCHIVE_EVENT_BUDGET < _CUSTODY_TERMINAL_RESERVE
            and _CUSTODY_TERMINAL_RESERVE < _CUSTODY_LEDGER_MAX_EVENTS
        ):
            return False, "bounded quarantine contract is invalid"
        if os.name == "nt":
            try:
                _custody_api()
            except OSError as exc:
                return False, f"exact-object custody API unavailable: {exc}"
        return (
            True,
            f"{len(self._decoys)} honeytokens; {_MAX_ANCHOR_READ}-byte read cap; "
            f"{len(self._unresolved_trips)} unresolved trips; "
            f"authenticated custody ledger sequence={self._custody_ledger_sequence}; "
            f"remaining={self._custody_remaining_events}; external-local-witness="
            f"{int(self._custody_witness_verified)}; "
            f"freshness={self._custody_freshness.state}; namespace-protected="
            f"{int(bool(self._custody_namespace_protected))}; capture="
            f"{self._last_capture_outcome.state}; "
            f"digest-sealed quarantine cap={_QUARANTINE_MAX_FILES}/"
            f"{_QUARANTINE_MAX_BYTES}B; dedup cap={_TRIP_ALERT_MAX}",
        )


def register(
    *, high_water: IndependentHighWater | None = None
) -> SmartDeception:
    return SmartDeception(high_water=high_water)
