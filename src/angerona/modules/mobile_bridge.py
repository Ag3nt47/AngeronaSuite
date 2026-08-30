"""mobile_bridge.py — Mobile Response Bridge (CODE: MOB_BRDG).

State-gated, End-to-End-Encrypted remote orchestration over Signal (via signal-cli).
The operator's phone can query posture and issue containment commands; every
state-changing command is gated by a short-lived 4-digit token AND the DPAPI-wrapped
hardware PIN, and unknown/failed input is silently discarded + logged as a spoof
attempt.

Design contract
---------------
  * OFF by default. Does nothing unless ``config.mobile_enabled`` is True and a
    signal-cli binary + host/destination numbers are configured.
  * NON-BLOCKING. All signal-cli calls are short subprocess invocations run from
    THIS module's daemon thread — never the Qt UI loop.
  * NON-REPLAYABLE. Tokens are random, single-use, and expire in 10 minutes; an
    expired token is audit-only and notifies the phone without authorizing action.
  * FAIL-OPEN for the suite. Any error here degrades health, never crashes.

Outbound metadata leaves the host (module/PID/severity/category) over the Signal
E2EE channel — the Settings tab shows the required security-posture warning.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Optional

from angerona.core.eventbus import Event, is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity

try:
    import psutil
except Exception:  # pragma: no cover - commands fail closed without identity data
    psutil = None

try:
    from angerona.engines.ai_guardrail import neutralize_telemetry
except Exception:   # pragma: no cover
    def neutralize_telemetry(text: str, max_len: int = 4000) -> str:  # type: ignore
        return str(text)[:max_len].replace("\n", " ")

# Entropy must match what the Settings save used when DPAPI-wrapping the PIN.
_PIN_ENTROPY = b"Angerona-MOBILE-PIN-v1"
_PIN_ENV = "ANGERONA_MOBILE_PIN_DPAPI"     # legacy base64(DPAPI blob) from OS store
_PORTABLE_PIN_ENV = "ANGERONA_MOBILE_PIN"  # delivered by the protected OS store

_TTL_SECONDS = 600.0        # token lifetime (10 min)
_TTL_SWEEP_S = 10.0         # cleanup cadence
_FLOOD_WINDOW = 60.0        # rate-limit window
_FLOOD_MAX = 3              # >this many alerts in the window → aggregate to a digest
_COMMAND_FRESHNESS_SECONDS = 120.0
_COMMAND_FUTURE_SKEW_SECONDS = 30.0
_ADMIN_NONCE_TTL_SECONDS = 120.0
_AUTH_FAILURE_WINDOW_SECONDS = 300.0
_AUTH_FAILURE_LIMIT = 5
_AUTH_LOCKOUT_SECONDS = 900.0
_MAX_REPLAY_IDENTITIES = 512
_MAX_PENDING_COMBAT_REQUESTS = 128
_PENDING_COMBAT_TTL_SECONDS = 900.0
_MAX_CLI_BYTES = 512 * 1024 * 1024
_MAX_CLI_OUTPUT = 256 * 1024
_CLI_RECEIPT_CONTEXT = b"Angerona/mobile-signal-cli-receipt/v1\0"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class _CliIdentity:
    path: str
    sha256: str
    publisher: str
    object_id: tuple[int, int, int, int]


@dataclass(slots=True)
class _SealedCli:
    identity: _CliIdentity
    handle: int

    def close(self) -> None:
        if not self.handle:
            return
        try:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            close = kernel.CloseHandle
            close.argtypes = [ctypes.wintypes.HANDLE]
            close.restype = ctypes.wintypes.BOOL
            close(self.handle)
        finally:
            self.handle = 0


@dataclass(frozen=True, slots=True)
class _CliReceipt:
    nonce: str
    purpose: str
    binary_sha256: str
    returncode: int
    output_sha256: str
    output_bytes: int
    state: str
    auth_tag: str


@dataclass(frozen=True, slots=True)
class _CliResult:
    output: bytes
    receipt: _CliReceipt
    verified: bool
    error: str = ""


@dataclass(frozen=True, slots=True)
class _IncomingCommand:
    sender: str
    body: str
    message_id: str
    sent_at: float


@dataclass(frozen=True, slots=True)
class _AdminChallenge:
    token: str
    sender: str
    issued_monotonic: float
    expires_monotonic: float
    request_message_id: str
    allowed_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PendingCombatRequest:
    request_id: str
    command: str
    token: str
    trigger_ts: float
    expected_action: str
    target_pid: int | None
    created_monotonic: float
    expires_monotonic: float

_HELP_TEXT = (
    "🛡️ ANGERONA MOBILE COMMAND CONSOLE 🛡️\n"
    "Available Commands:\n"
    "-----------------------------------------\n"
    "❓ HELP - Display this guide\n"
    "📊 STATUS - View Threat Posture & Active KEVs\n"
    "🔐 ARM - Issue one fresh 2-minute administrative nonce\n"
    "🌿 ECO ON/OFF <NONCE> <PIN> - Change Governor throttling\n"
    "🚨 LOCKDOWN <NONCE> <PIN> - Request receipt-verified host isolation\n"
    "🛠️ DIAG - Export Black Box diagnostic package\n"
    "🚫 KILL <TOKEN> <PIN> - Terminate an exact bound process instance\n"
    "⏸️ SUSPEND <TOKEN> <PIN> - Suspend an exact bound process instance\n"
    "🔄 ROLLBACK <TOKEN> <PIN> - Restore one exact Shadow Shield version\n"
    "📕 MUTE <TOKEN> <PIN> - Suppress alert module rules for 15m\n"
    "-----------------------------------------\n"
    "Note: Token-based commands expire in 10 minutes.\n"
)


def _signal_identity(value: object) -> str:
    """Canonicalize the configured phone identity or fail closed.

    The end-user setup contract accepts an international phone number. Signal's
    JSON envelope may add spaces, dashes, or parentheses; no missing/ambiguous
    sender identity is ever treated as the configured operator.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    compact = re.sub(r"[\s().-]+", "", text)
    if not re.fullmatch(r"\+[1-9][0-9]{6,14}", compact):
        return ""
    return compact


def _has_link_or_reparse(path: Path) -> bool:
    """Reject every existing symlink/reparse component in an executable path."""
    try:
        resolved = path.absolute()
        for candidate in reversed((resolved, *resolved.parents)):
            info = candidate.lstat()
            attributes = int(getattr(info, "st_file_attributes", 0))
            if stat.S_ISLNK(info.st_mode) or attributes & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                return True
        return False
    except (OSError, RuntimeError):
        return True


def _windows_fixed_volume(path: Path) -> bool:
    if sys.platform != "win32":
        return False
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        volume_path = kernel.GetVolumePathNameW
        volume_path.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPWSTR,
            ctypes.wintypes.DWORD,
        ]
        volume_path.restype = ctypes.wintypes.BOOL
        drive_type = kernel.GetDriveTypeW
        drive_type.argtypes = [ctypes.wintypes.LPCWSTR]
        drive_type.restype = ctypes.wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        if not volume_path(str(path), buffer, len(buffer)):
            return False
        return int(drive_type(buffer.value)) == 3  # DRIVE_FIXED
    except (AttributeError, OSError, ValueError):
        return False


def _windows_acl_trusted(path: Path) -> bool:
    """Require a protected owner and no untrusted write-capable DACL entry."""
    if sys.platform != "win32":
        return False
    try:
        from ctypes import wintypes

        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        class ACE_HEADER(ctypes.Structure):
            _fields_ = [
                ("AceType", ctypes.c_ubyte),
                ("AceFlags", ctypes.c_ubyte),
                ("AceSize", wintypes.WORD),
            ]

        class ACCESS_ALLOWED_ACE(ctypes.Structure):
            _fields_ = [
                ("Header", ACE_HEADER),
                ("Mask", wintypes.DWORD),
                ("SidStart", wintypes.DWORD),
            ]

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_security = advapi.GetNamedSecurityInfoW
        get_security.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_security.restype = wintypes.DWORD
        convert_sid = advapi.ConvertStringSidToSidW
        convert_sid.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
        convert_sid.restype = wintypes.BOOL
        equal_sid = advapi.EqualSid
        equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
        equal_sid.restype = wintypes.BOOL
        get_acl_info = advapi.GetAclInformation
        get_acl_info.argtypes = [
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        get_acl_info.restype = wintypes.BOOL
        get_ace = advapi.GetAce
        get_ace.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_ace.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel.LocalFree.restype = wintypes.HLOCAL

        owner = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        descriptor = wintypes.LPVOID()
        trusted_sids = [wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPVOID()]
        try:
            error = get_security(
                str(path),
                1,  # SE_FILE_OBJECT
                0x00000005,  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            if error or not descriptor or not owner or not dacl:
                return False
            for index, sid_text in enumerate(
                (
                    "S-1-5-18",  # SYSTEM
                    "S-1-5-32-544",  # BUILTIN\\Administrators
                    # NT SERVICE\\TrustedInstaller
                    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                )
            ):
                if not convert_sid(sid_text, ctypes.byref(trusted_sids[index])):
                    return False
            if not any(equal_sid(owner, sid) for sid in trusted_sids):
                return False

            acl_info = ACL_SIZE_INFORMATION()
            if not get_acl_info(
                dacl, ctypes.byref(acl_info), ctypes.sizeof(acl_info), 2
            ):
                return False
            write_mask = (
                0x10000000  # GENERIC_ALL
                | 0x40000000  # GENERIC_WRITE
                | 0x00010000  # DELETE
                | 0x00040000  # WRITE_DAC
                | 0x00080000  # WRITE_OWNER
                | 0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
                | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
                | 0x00000010  # FILE_WRITE_EA
                | 0x00000040  # FILE_DELETE_CHILD
                | 0x00000100  # FILE_WRITE_ATTRIBUTES
            )
            for ace_index in range(int(acl_info.AceCount)):
                ace_pointer = wintypes.LPVOID()
                if not get_ace(dacl, ace_index, ctypes.byref(ace_pointer)):
                    return False
                header = ctypes.cast(
                    ace_pointer, ctypes.POINTER(ACE_HEADER)
                ).contents
                if header.AceType == 1:  # ACCESS_DENIED_ACE_TYPE
                    continue
                if header.AceType != 0:  # Unknown allow/callback/object ACE.
                    return False
                ace = ctypes.cast(
                    ace_pointer, ctypes.POINTER(ACCESS_ALLOWED_ACE)
                ).contents
                if not int(ace.Mask) & write_mask:
                    continue
                sid_pointer = wintypes.LPVOID(
                    int(ace_pointer.value) + ACCESS_ALLOWED_ACE.SidStart.offset
                )
                if not any(equal_sid(sid_pointer, sid) for sid in trusted_sids):
                    return False
            return True
        finally:
            for sid in trusted_sids:
                if sid:
                    kernel.LocalFree(sid)
            if descriptor:
                kernel.LocalFree(descriptor)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _trusted_path_acl(path: Path) -> bool:
    """Prove custody of the file and each directory below the fixed root."""
    anchor = Path(path.anchor)
    candidates = [path, *path.parents]
    for candidate in candidates:
        if candidate == anchor:
            break
        if not _windows_acl_trusted(candidate):
            return False
    return True


def _authenticode_publisher(path: Path) -> tuple[str, str]:
    """Return trusted PowerShell's bounded Authenticode status and subject."""
    if sys.platform != "win32":
        return "Unsupported", ""
    try:
        from angerona.core.privilege import (
            sanitized_child_environment,
            trusted_powershell_path,
            trusted_windows_directories,
        )

        powershell = trusted_powershell_path()
        _windows, system = trusted_windows_directories()
        if not powershell.is_file():
            return "Unavailable", ""
        environment = sanitized_child_environment(source={})
        environment["ANGERONA_SIGNAL_CLI_PATH"] = str(path)
        script = (
            "$s=Get-AuthenticodeSignature -LiteralPath "
            "$env:ANGERONA_SIGNAL_CLI_PATH -ErrorAction Stop;"
            "$p=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
            "[pscustomobject]@{status=[string]$s.Status;publisher=$p}"
            "|ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            cwd=str(system),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            return "Unavailable", ""
        payload = json.loads(result.stdout.decode("utf-8", errors="strict"))
        status = str(payload.get("status") or "")[:64]
        publisher = str(payload.get("publisher") or "")[:512]
        return status, publisher
    except (
        AttributeError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ):
        return "Unavailable", ""


class MobileResponseBridge(BaseModule):
    name = "Mobile Response Bridge"
    CODE = "MOB_BRDG"
    description = ("E2EE (Signal) state-gated remote orchestration: posture queries "
                   "and token+PIN-gated containment from the operator's phone.")
    category = "Response"
    version = "1.12.1"
    # The thread always runs but self-gates on config.mobile_enabled (idles cheaply
    # when off) so flipping the Settings toggle takes effect without a restart.
    enabled_by_default = True

    POLL_S = 2.0

    def __init__(self) -> None:
        super().__init__()
        self._manager = None
        self._config = None
        self.pending_alerts: dict[str, dict] = {}
        self._muted: dict[str, float] = {}          # module name → mute-until epoch
        self._alert_times: list[float] = []          # for rate-limit window
        # A digest renders only its first 15 samples. Keep those plus a scalar
        # total instead of retaining every full alert line during a flood.
        self._digest: list[str] = []
        self._digest_count = 0
        self._last_sweep = 0.0
        self._last_digest_flush = 0.0
        self._aria_handler = None                    # optional ARIA chat handler
        self._cli_receipt_key = secrets.token_bytes(32)
        self._last_cli_receipt_at = 0.0
        self._last_cli_error = "no verified signal-cli round trip"
        self._cli_failures: dict[str, str] = {}
        self._admin_challenge: _AdminChallenge | None = None
        self._auth_failures: list[float] = []
        self._auth_locked_until = 0.0
        self._seen_command_ids: OrderedDict[str, float] = OrderedDict()
        self._pending_combat_requests: OrderedDict[
            str, _PendingCombatRequest
        ] = OrderedDict()
        self._receipt_authority_fault = ""

    def bind_manager(self, manager) -> None:
        self._manager = manager
        self._config = getattr(manager, "config", None)

    def set_aria_handler(self, fn) -> None:
        """Route non-command Signal messages to ARIA for a conversational answer.
        Only the already-sender-verified operator reaches this path; ARIA's
        state-changing actions are deliberately NOT exposed here — remote
        mutations go through the PIN+token-gated commands (KILL/SUSPEND/…)."""
        self._aria_handler = fn

    # ── Config resolution ──────────────────────────────────────────────────────
    def _enabled(self) -> bool:
        return bool(getattr(self._config, "mobile_enabled", False))

    def _cfg(self) -> dict:
        c = self._config
        return {
            "cli":  getattr(c, "mobile_signal_cli", "") or "",
            "host": getattr(c, "mobile_host_number", "") or "",
            "dest": getattr(c, "mobile_dest_number", "") or "",
            "sha256": getattr(c, "mobile_signal_cli_sha256", "") or "",
            "publisher": getattr(c, "mobile_signal_cli_publisher", "") or "",
        }

    def _pin(self) -> Optional[str]:
        """Read a four-digit PIN delivered by the protected OS credential store.

        The legacy nested-DPAPI value remains readable for existing Windows
        installations. Linux Secret Service and macOS Keychain use the canonical
        value so the mobile gate has the same semantics on every platform.
        """
        portable = os.environ.get(_PORTABLE_PIN_ENV, "").strip()
        if re.fullmatch(r"[0-9]{4}", portable):
            return portable
        blob_b64 = os.environ.get(_PIN_ENV, "")
        if not blob_b64:
            return None
        try:
            import base64
            from angerona.modules.hardware_crypto import unprotect
            raw = unprotect(base64.b64decode(blob_b64), _PIN_ENTROPY)
            value = raw.decode("utf-8").strip() if raw else ""
            return value if re.fullmatch(r"[0-9]{4}", value) else None
        except Exception:
            return None

    # ── sealed signal-cli I/O (never touches the GUI thread) ─────────────────
    @staticmethod
    def _handle_state(handle: int) -> tuple[tuple[int, int, int, int], int, int]:
        """Return object identity, link count, and attributes from one handle."""

        class FILETIME(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", ctypes.wintypes.DWORD),
                ("dwHighDateTime", ctypes.wintypes.DWORD),
            ]

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", ctypes.wintypes.DWORD),
                ("ftCreationTime", FILETIME),
                ("ftLastAccessTime", FILETIME),
                ("ftLastWriteTime", FILETIME),
                ("dwVolumeSerialNumber", ctypes.wintypes.DWORD),
                ("nFileSizeHigh", ctypes.wintypes.DWORD),
                ("nFileSizeLow", ctypes.wintypes.DWORD),
                ("nNumberOfLinks", ctypes.wintypes.DWORD),
                ("nFileIndexHigh", ctypes.wintypes.DWORD),
                ("nFileIndexLow", ctypes.wintypes.DWORD),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_info = kernel.GetFileInformationByHandle
        get_info.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
        ]
        get_info.restype = ctypes.wintypes.BOOL
        info = BY_HANDLE_FILE_INFORMATION()
        if not get_info(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
        file_index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        write_time = (
            int(info.ftLastWriteTime.dwHighDateTime) << 32
        ) | int(info.ftLastWriteTime.dwLowDateTime)
        return (
            (int(info.dwVolumeSerialNumber), file_index, size, write_time),
            int(info.nNumberOfLinks),
            int(info.dwFileAttributes),
        )

    @staticmethod
    def _hash_handle(handle: int, size: int) -> str:
        if not 0 < size <= _MAX_CLI_BYTES:
            raise ValueError("signal-cli executable size is outside its bound")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        seek = kernel.SetFilePointerEx
        seek.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            ctypes.wintypes.DWORD,
        ]
        seek.restype = ctypes.wintypes.BOOL
        read = kernel.ReadFile
        read.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.LPVOID,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.DWORD),
            ctypes.wintypes.LPVOID,
        ]
        read.restype = ctypes.wintypes.BOOL
        if not seek(handle, 0, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        digest = hashlib.sha256()
        total = 0
        buffer = ctypes.create_string_buffer(1024 * 1024)
        while total < size:
            request = min(len(buffer), size - total)
            received = ctypes.wintypes.DWORD()
            if not read(handle, buffer, request, ctypes.byref(received), None):
                raise ctypes.WinError(ctypes.get_last_error())
            count = int(received.value)
            if count <= 0:
                break
            digest.update(buffer.raw[:count])
            total += count
        if total != size:
            raise OSError("signal-cli executable read was incomplete")
        return digest.hexdigest()

    @classmethod
    def _acquire_cli(cls, cfg: dict) -> _SealedCli:
        """Open and pin one exact Windows executable until its child exits."""
        if sys.platform != "win32":
            raise OSError("sealed signal-cli launch is available only on Windows")
        raw_path = str(cfg.get("cli") or "").strip()
        expected_digest = str(cfg.get("sha256") or "").strip().casefold()
        expected_publisher = str(cfg.get("publisher") or "").strip()
        if not _SHA256_RE.fullmatch(expected_digest):
            raise ValueError("signal-cli SHA-256 pin is missing or invalid")
        if not expected_publisher or len(expected_publisher) > 512 or "\x00" in expected_publisher:
            raise ValueError("signal-cli publisher pin is missing or invalid")
        if (
            not raw_path
            or len(raw_path) > 32767
            or "\x00" in raw_path
            or raw_path.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\"))
        ):
            raise ValueError("signal-cli must be an ordinary absolute local path")
        pure = PureWindowsPath(raw_path)
        if not pure.is_absolute() or not pure.drive or pure.suffix.casefold() != ".exe":
            raise ValueError("signal-cli must be an absolute native .exe path")
        candidate = Path(raw_path)
        resolved = candidate.resolve(strict=True)
        if (
            os.path.normcase(os.path.normpath(str(candidate.absolute())))
            != os.path.normcase(os.path.normpath(str(resolved)))
            or not resolved.is_file()
            or _has_link_or_reparse(candidate)
            or not _windows_fixed_volume(resolved)
            or not _trusted_path_acl(resolved)
        ):
            raise PermissionError(
                "signal-cli path is not fixed-local, ordinary, and protected"
            )

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPVOID,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
        ]
        create.restype = ctypes.wintypes.HANDLE
        handle = create(
            str(resolved),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ; deny write/delete replacement
            None,
            3,  # OPEN_EXISTING
            0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if not handle or int(handle) == invalid:
            raise ctypes.WinError(ctypes.get_last_error())
        sealed = _SealedCli(
            _CliIdentity(str(resolved), "", "", (0, 0, 0, 0)), int(handle)
        )
        try:
            object_id, links, attributes = cls._handle_state(sealed.handle)
            if (
                links != 1
                or attributes & 0x00000400  # FILE_ATTRIBUTE_REPARSE_POINT
                or attributes & 0x00000010  # FILE_ATTRIBUTE_DIRECTORY
            ):
                raise PermissionError("signal-cli must be a single-link ordinary file")
            digest = cls._hash_handle(sealed.handle, object_id[2])
            if not hmac.compare_digest(digest, expected_digest):
                raise PermissionError("signal-cli SHA-256 does not match its pin")
            status, publisher = _authenticode_publisher(resolved)
            if status.casefold() != "valid" or not hmac.compare_digest(
                publisher, expected_publisher
            ):
                raise PermissionError(
                    "signal-cli Authenticode publisher does not match its pin"
                )
            sealed.identity = _CliIdentity(
                str(resolved), digest, publisher, object_id
            )
            return sealed
        except Exception:
            sealed.close()
            raise

    @classmethod
    def _seal_still_valid(cls, sealed: _SealedCli) -> bool:
        try:
            path = Path(sealed.identity.path)
            object_id, links, attributes = cls._handle_state(sealed.handle)
            return bool(
                object_id == sealed.identity.object_id
                and links == 1
                and not attributes & (0x00000400 | 0x00000010)
                and hmac.compare_digest(
                    cls._hash_handle(sealed.handle, object_id[2]),
                    sealed.identity.sha256,
                )
                and not _has_link_or_reparse(path)
                and _windows_fixed_volume(path)
                and _trusted_path_acl(path)
            )
        except Exception:
            return False

    @staticmethod
    def _read_bounded_child(
        process: subprocess.Popen[bytes], timeout: float
    ) -> tuple[str, bytes]:
        if process.stdout is None:
            return "io-error", b""
        captured = bytearray()
        done = threading.Event()
        overflow = threading.Event()
        failed = threading.Event()

        def reader() -> None:
            try:
                while True:
                    chunk = process.stdout.read(4096)
                    if not chunk:
                        break
                    available = _MAX_CLI_OUTPUT - len(captured)
                    if len(chunk) > available:
                        if available > 0:
                            captured.extend(chunk[:available])
                        overflow.set()
                        break
                    captured.extend(chunk)
            except (OSError, ValueError):
                failed.set()
            finally:
                done.set()

        thread = threading.Thread(
            target=reader, name="angerona-signal-cli-reader", daemon=True
        )
        thread.start()
        deadline = time.monotonic() + timeout
        while not done.wait(0.02):
            if overflow.is_set() or time.monotonic() >= deadline:
                try:
                    process.kill()
                except OSError:
                    pass
                thread.join(timeout=2.0)
                return (
                    "overflow" if overflow.is_set() else "timeout",
                    bytes(captured),
                )
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            return "timeout", bytes(captured)
        thread.join(timeout=2.0)
        if thread.is_alive() or failed.is_set():
            return "io-error", bytes(captured)
        return "complete", bytes(captured)

    @classmethod
    def _launch_cli(
        cls, sealed: _SealedCli, arguments: list[str], timeout: float
    ) -> tuple[str, int, bytes]:
        from angerona.core.privilege import sanitized_child_environment
        from angerona.resilience._selftest_environment import (
            _assign_windows_kill_job,
            _resume_windows_process,
            _stop_process_custody,
        )

        argv = [sealed.identity.path, *[str(value) for value in arguments]]
        if (
            sum(len(value) for value in argv) > 32768
            or any("\x00" in value for value in argv)
        ):
            return "arguments-invalid", -1, b""
        environment = sanitized_child_environment(source={})
        if _PIN_ENV in environment or _PORTABLE_PIN_ENV in environment:
            return "environment-invalid", -1, b""
        process: subprocess.Popen[bytes] | None = None
        job = None
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(Path(sealed.identity.path).parent),
                env=environment,
                close_fds=True,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
                ),
            )
            try:
                job = _assign_windows_kill_job(process)
                _resume_windows_process(process)
            except OSError:
                process.kill()
                process.wait(timeout=2.0)
                raise
            state, output = cls._read_bounded_child(process, timeout)
            return state, int(process.returncode or 0), output
        finally:
            _stop_process_custody(process, job)

    def _make_receipt(
        self,
        *,
        nonce: str,
        purpose: str,
        binary_sha256: str,
        returncode: int,
        output: bytes,
        state: str,
    ) -> _CliReceipt:
        core = {
            "nonce": nonce,
            "purpose": purpose,
            "binary_sha256": binary_sha256,
            "returncode": int(returncode),
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_bytes": len(output),
            "state": state,
        }
        canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        tag = hmac.new(
            self._cli_receipt_key,
            _CLI_RECEIPT_CONTEXT + canonical,
            hashlib.sha256,
        ).hexdigest()
        return _CliReceipt(**core, auth_tag=tag)

    def _receipt_valid(self, receipt: _CliReceipt) -> bool:
        if (
            not re.fullmatch(r"[0-9a-f]{64}", receipt.nonce)
            or receipt.purpose not in {"send", "receive", "self-test"}
            or not _SHA256_RE.fullmatch(receipt.binary_sha256)
            or receipt.state != "complete"
            or receipt.returncode != 0
            or not 0 <= receipt.output_bytes <= _MAX_CLI_OUTPUT
            or not _SHA256_RE.fullmatch(receipt.output_sha256)
            or not _SHA256_RE.fullmatch(receipt.auth_tag)
        ):
            return False
        core = {
            "nonce": receipt.nonce,
            "purpose": receipt.purpose,
            "binary_sha256": receipt.binary_sha256,
            "returncode": receipt.returncode,
            "output_sha256": receipt.output_sha256,
            "output_bytes": receipt.output_bytes,
            "state": receipt.state,
        }
        canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        expected_tag = hmac.new(
            self._cli_receipt_key,
            _CLI_RECEIPT_CONTEXT + canonical,
            hashlib.sha256,
        ).hexdigest()
        return bool(receipt.auth_tag) and hmac.compare_digest(
            expected_tag, receipt.auth_tag
        )

    def _result_valid(self, result: _CliResult, purpose: str) -> bool:
        return bool(
            result.verified
            and result.receipt.purpose == purpose
            and len(result.output) == result.receipt.output_bytes
            and hmac.compare_digest(
                hashlib.sha256(result.output).hexdigest(),
                result.receipt.output_sha256,
            )
            and self._receipt_valid(result.receipt)
        )

    def _record_cli_result(self, purpose: str, verified: bool, error: str = "") -> None:
        if verified:
            self._cli_failures.pop(purpose, None)
            self._last_cli_receipt_at = time.monotonic()
            if not self._cli_failures:
                self._last_cli_error = ""
            return
        detail = str(error or "unverified signal-cli invocation")[:320]
        self._cli_failures[purpose] = detail
        self._last_cli_error = detail

    def _invoke_cli(
        self, purpose: str, arguments: list[str], *, timeout: float
    ) -> _CliResult:
        nonce = secrets.token_hex(32)
        sealed: _SealedCli | None = None
        output = b""
        binary_digest = ""
        state = "identity-error"
        returncode = -1
        error = "signal-cli identity could not be proven"
        try:
            sealed = self._acquire_cli(self._cfg())
            binary_digest = sealed.identity.sha256
            state, returncode, output = self._launch_cli(
                sealed, arguments, timeout
            )
            identity_valid = self._seal_still_valid(sealed)
            receipt = self._make_receipt(
                nonce=nonce,
                purpose=purpose,
                binary_sha256=binary_digest,
                returncode=returncode,
                output=output,
                state=state,
            )
            verified = bool(
                identity_valid
                and state == "complete"
                and returncode == 0
                and len(output) <= _MAX_CLI_OUTPUT
                and self._receipt_valid(receipt)
            )
            if verified:
                self._record_cli_result(purpose, True)
                return _CliResult(output, receipt, True)
            if not identity_valid:
                error = "signal-cli identity changed during launch"
            elif state != "complete":
                error = f"signal-cli IPC {state}"
            else:
                error = f"signal-cli exited with code {returncode}"
            self._record_cli_result(purpose, False, error)
            return _CliResult(output, receipt, False, error)
        except Exception as exc:
            error = f"signal-cli rejected: {type(exc).__name__}: {str(exc)[:240]}"
            self._record_cli_result(purpose, False, error)
            receipt = self._make_receipt(
                nonce=nonce,
                purpose=purpose,
                binary_sha256=binary_digest,
                returncode=returncode,
                output=output,
                state=state,
            )
            return _CliResult(output, receipt, False, error)
        finally:
            if sealed is not None:
                sealed.close()

    def _send(self, message: str) -> bool:
        cfg = self._cfg()
        if not (cfg["cli"] and cfg["host"] and cfg["dest"]):
            self._record_cli_result(
                "send", False, "signal-cli path/account/destination is incomplete"
            )
            return False
        bounded = str(message)[:4000]
        result = self._invoke_cli(
            "send",
            ["-a", cfg["host"], "send", "-m", bounded, cfg["dest"]],
            timeout=30.0,
        )
        if not self._result_valid(result, "send"):
            self.set_health(40, result.error)
            return False
        return True

    def _receive(self) -> list[_IncomingCommand]:
        """Return messages only from a sealed, receipt-verified CLI round trip."""
        cfg = self._cfg()
        if not (cfg["cli"] and cfg["host"]):
            self._record_cli_result(
                "receive", False, "signal-cli path/account is incomplete"
            )
            return []
        result = self._invoke_cli(
            "receive",
            ["-o", "json", "-a", cfg["host"], "receive", "--timeout", "2"],
            timeout=20.0,
        )
        if not self._result_valid(result, "receive"):
            self.set_health(40, result.error)
            return []
        msgs: list[_IncomingCommand] = []
        for line in result.output.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
                env = env.get("envelope", env)
                sender = str(env.get("source") or env.get("sourceNumber") or "")
                body = ((env.get("dataMessage") or {}).get("message")
                        or env.get("message") or "")
                timestamp_ms = env.get("timestamp")
                sent_at = float(timestamp_ms) / 1000.0
                source_device = str(env.get("sourceDevice") or "")
                server_guid = str(env.get("serverGuid") or env.get("guid") or "")
                identity_body = json.dumps(
                    {
                        "sender": _signal_identity(sender),
                        "source_device": source_device,
                        "timestamp_ms": int(timestamp_ms),
                        "server_guid": server_guid,
                        "body": str(body),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                message_id = hashlib.sha256(identity_body).hexdigest()
                if body and _signal_identity(sender):
                    msgs.append(_IncomingCommand(
                        sender=sender,
                        body=str(body),
                        message_id=message_id,
                        sent_at=sent_at,
                    ))
            except Exception:
                continue
        return msgs

    # ── Alert gating → phone ───────────────────────────────────────────────────
    def _poll_alerts(self) -> None:
        if self._bus is None:
            return
        try:
            events, _overflow = self.poll_bus_events(priority=True)
        except Exception:
            return
        now = time.time()
        for ev in events:
            if ev.severity < Severity.HIGH or ev.module in ("Console", "Self-Test"):
                continue
            if self._is_muted(ev.module):
                continue
            self._gate_alert(ev)

    def _gate_alert(self, ev) -> None:
        details = ev.details if isinstance(ev.details, dict) else {}
        pid = details.get("pid")
        module = neutralize_telemetry(str(ev.module), 80)
        threat = neutralize_telemetry(str(ev.message), 200)
        process_target = self._bind_process_target(pid, details)
        rollback_artifact = self._prepare_rollback_artifact(ev)
        response_eligible = (
            not is_remote_observe_only(ev)
            and self._bus is not None
            and getattr(self._bus, "integrity_enabled", False)
        )
        if response_eligible:
            try:
                response_eligible = bool(self._bus.verify(ev))
            except Exception:
                response_eligible = False
        action = "RESPOND" if response_eligible and (process_target or rollback_artifact) else "REVIEW"
        token = self._new_token()
        self.pending_alerts[token] = {
            "pid": process_target.get("pid") if process_target else None,
            "process_create_time": (
                process_target.get("process_create_time") if process_target else None
            ),
            "exe": process_target.get("exe") if process_target else None,
            "process_name": process_target.get("name") if process_target else None,
            "rollback_artifact": rollback_artifact,
            "response_eligible": response_eligible,
            "source_event_hmac": str(getattr(ev, "hmac_sig", "") or ""),
            "action": action,
            "module": ev.module,
            "timestamp": time.time(),
            "operator_identity": _signal_identity(self._cfg().get("dest", "")),
        }
        commands = []
        if response_eligible and process_target:
            commands.extend(("KILL", "SUSPEND"))
        if response_eligible and rollback_artifact:
            commands.append("ROLLBACK")
        allowed_actions = tuple((*commands, "MUTE"))
        self.pending_alerts[token]["allowed_actions"] = allowed_actions
        self.pending_alerts[token]["expires_monotonic"] = (
            time.monotonic() + _TTL_SECONDS
        )
        command_text = (
            "/".join(commands) + f" {token} <PIN>"
            if commands
            else "REVIEW ONLY — no exact response target"
        )
        line = (f"🚨 [{ev.severity.label}] {module} (PID {pid}) — {threat}\n"
                f"Token {token}: {command_text}  ·  MUTE {token} <PIN>")

        # Rate-limit: >_FLOOD_MAX alerts in the window → aggregate into a digest.
        now = time.time()
        self._alert_times = [t for t in self._alert_times if now - t <= _FLOOD_WINDOW]
        self._alert_times.append(now)
        if len(self._alert_times) > _FLOOD_MAX:
            self._digest_count += 1
            if len(self._digest) < 15:
                self._digest.append(line)
        else:
            self._send(line)

    def _flush_digest(self) -> None:
        if not self._digest:
            return
        if time.time() - self._last_digest_flush < _FLOOD_WINDOW:
            return
        self._last_digest_flush = time.time()
        n = self._digest_count
        body = (f"📥 Angerona digest — {n} alert(s) in the last minute "
                "(individual texts suppressed to avoid flooding):\n\n"
                + "\n".join(self._digest))
        self._digest.clear()
        self._digest_count = 0
        self._send(body)

    def _new_token(self) -> str:
        for _ in range(50):
            t = secrets.token_hex(32)
            if t not in self.pending_alerts:
                return t
        raise RuntimeError("unable to allocate a unique mobile authorization token")

    # ── TTL sweep ───────────────────────────────────────────────────────────────
    def _sweep_tokens(self) -> None:
        now = time.time()
        for token, info in list(self.pending_alerts.items()):
            expires_monotonic = float(info.get("expires_monotonic", 0.0) or 0.0)
            not_expired = (
                expires_monotonic > time.monotonic()
                if expires_monotonic > 0.0
                else now - float(info.get("timestamp", 0.0) or 0.0) < _TTL_SECONDS
            )
            if not_expired:
                continue
            self.pending_alerts.pop(token, None)
            pid = info.get("pid")
            if pid:
                self._emit_mitigation(
                    "SUSPEND",
                    pid,
                    reason=f"token {token} expired",
                    directive_authorized=False,
                    event_type="mobile_token_expiry",
                )
                self._send(
                    f"Token [{token}] expired. No action taken; request a fresh "
                    "alert token before responding."
                )
            else:
                self._send(f"Token [{token}] expired. No action taken (review-only alert).")
        # expire mutes
        for m, until in list(self._muted.items()):
            if now >= until:
                self._muted.pop(m, None)

    def _is_muted(self, module: str) -> bool:
        until = self._muted.get(module)
        return bool(until and time.time() < until)

    # ── Replay-resistant command authorization ───────────────────────────────
    def _prune_command_authority(self) -> None:
        now = time.monotonic()
        cutoff = now - _AUTH_FAILURE_WINDOW_SECONDS
        self._auth_failures = [value for value in self._auth_failures if value >= cutoff]
        while self._seen_command_ids:
            first_key = next(iter(self._seen_command_ids))
            if (
                len(self._seen_command_ids) <= _MAX_REPLAY_IDENTITIES
                and self._seen_command_ids[first_key] >= cutoff
            ):
                break
            self._seen_command_ids.popitem(last=False)
        challenge = self._admin_challenge
        if challenge is not None and now >= challenge.expires_monotonic:
            self._admin_challenge = None

    def _lockout_remaining(self) -> float:
        return max(0.0, self._auth_locked_until - time.monotonic())

    def _record_auth_failure(self, body: str, reason: str) -> None:
        now = time.monotonic()
        self._prune_command_authority()
        self._auth_failures.append(now)
        if len(self._auth_failures) >= _AUTH_FAILURE_LIMIT:
            self._auth_locked_until = max(
                self._auth_locked_until, now + _AUTH_LOCKOUT_SECONDS
            )
            reason = (
                f"{reason}; mobile mutations locked for "
                f"{int(_AUTH_LOCKOUT_SECONDS)} seconds"
            )
        self._spoof(body, reason)

    def _consume_fresh_message(
        self,
        *,
        message_id: str,
        sent_at: float | None,
        body: str,
    ) -> bool:
        """Consume one authenticated transport envelope identity exactly once."""
        self._prune_command_authority()
        if self._lockout_remaining() > 0:
            self._spoof(body, "mobile mutation authorization is locked")
            return False
        if not _SHA256_RE.fullmatch(str(message_id or "").casefold()):
            self._record_auth_failure(body, "missing authenticated message identity")
            return False
        try:
            sent = float(sent_at)
        except (TypeError, ValueError, OverflowError):
            self._record_auth_failure(body, "missing authenticated message time")
            return False
        now_wall = time.time()
        if not (sent > 0.0) or sent < now_wall - _COMMAND_FRESHNESS_SECONDS:
            self._record_auth_failure(body, "stale command envelope")
            return False
        if sent > now_wall + _COMMAND_FUTURE_SKEW_SECONDS:
            self._record_auth_failure(body, "future-dated command envelope")
            return False
        normalized = str(message_id).casefold()
        if normalized in self._seen_command_ids:
            self._record_auth_failure(body, "replayed command envelope")
            return False
        self._seen_command_ids[normalized] = time.monotonic()
        self._seen_command_ids.move_to_end(normalized)
        self._prune_command_authority()
        return True

    def _issue_admin_challenge(
        self,
        *,
        sender: str,
        message_id: str,
        sent_at: float | None,
        body: str,
    ) -> None:
        if not self._consume_fresh_message(
            message_id=message_id, sent_at=sent_at, body=body
        ):
            return
        now = time.monotonic()
        token = secrets.token_hex(32)
        self._admin_challenge = _AdminChallenge(
            token=token,
            sender=_signal_identity(sender),
            issued_monotonic=now,
            expires_monotonic=now + _ADMIN_NONCE_TTL_SECONDS,
            request_message_id=str(message_id).casefold(),
            allowed_actions=("ECO_ON", "ECO_OFF", "LOCKDOWN"),
        )
        self._send(
            f"Fresh administrative nonce (single-use, "
            f"{int(_ADMIN_NONCE_TTL_SECONDS)}s): {token}"
        )

    def _pin_authorized(self, pin: str, *, body: str) -> bool:
        if not self._pin_ok(pin):
            self._record_auth_failure(body, "mobile PIN verification failed")
            return False
        self._auth_failures.clear()
        return True

    def _authorize_admin_change(
        self,
        action: str,
        token: str,
        pin: str,
        *,
        sender: str,
        message_id: str,
        sent_at: float | None,
        body: str,
    ) -> bool:
        challenge = self._admin_challenge
        now = time.monotonic()
        if challenge is None or now >= challenge.expires_monotonic:
            self._admin_challenge = None
            self._record_auth_failure(body, "missing or expired administrative nonce")
            return False
        if action not in challenge.allowed_actions:
            self._record_auth_failure(body, "administrative nonce action mismatch")
            return False
        if not hmac.compare_digest(_signal_identity(sender), challenge.sender):
            self._record_auth_failure(body, "administrative nonce sender mismatch")
            return False
        if not hmac.compare_digest(token.casefold(), challenge.token):
            self._record_auth_failure(body, "administrative nonce mismatch")
            return False
        if not self._consume_fresh_message(
            message_id=message_id, sent_at=sent_at, body=body
        ):
            return False
        if not self._pin_authorized(pin, body=body):
            return False
        if self._bus is None or not getattr(self._bus, "integrity_enabled", False):
            self._record_auth_failure(body, "signed change receipt authority unavailable")
            return False
        self._admin_challenge = None
        return True

    def _authorize_alert_change(
        self,
        action: str,
        token: str,
        pin: str,
        *,
        sender: str,
        message_id: str,
        sent_at: float | None,
        body: str,
    ) -> bool:
        info = self.pending_alerts.get(token)
        if not isinstance(info, dict):
            self._record_auth_failure(body, "unknown alert authorization token")
            return False
        allowed = tuple(str(value) for value in info.get("allowed_actions", ()))
        expires = float(info.get("expires_monotonic", 0.0) or 0.0)
        if action not in allowed or time.monotonic() >= expires:
            self._record_auth_failure(body, "expired or out-of-scope alert token")
            return False
        operator = str(info.get("operator_identity") or "")
        if not operator or not hmac.compare_digest(_signal_identity(sender), operator):
            self._record_auth_failure(body, "alert token sender mismatch")
            return False
        if not self._consume_fresh_message(
            message_id=message_id, sent_at=sent_at, body=body
        ):
            return False
        if not self._pin_authorized(pin, body=body):
            return False
        if self._bus is None or not getattr(self._bus, "integrity_enabled", False):
            self._record_auth_failure(body, "signed change receipt authority unavailable")
            return False
        return True

    def _emit_change_receipt(
        self,
        command: str,
        token: str,
        *,
        outcome: str,
        details: dict | None = None,
    ) -> tuple[str, bool]:
        """Emit and independently verify one exact HMAC-bound change result.

        A state transition and its audit proof are separate facts.  Callers may
        describe a receipt as signed only when the exact newly published event
        is still bound to the same authority object and that authority verifies
        its HMAC.  Authority loss never rewrites the host outcome as rejected.
        """
        receipt_id = secrets.token_hex(16)
        bus = self._bus
        authority = getattr(bus, "_authority", None) if bus is not None else None
        if (
            bus is None
            or authority is None
            or not getattr(bus, "integrity_enabled", False)
        ):
            self._receipt_authority_fault = (
                "mobile change receipt authority unavailable; manual outcome "
                "verification required"
            )
            self.set_health(0, self._receipt_authority_fault)
            return "", False
        try:
            revision = int(bus.revision())
        except (AttributeError, TypeError, ValueError):
            self._receipt_authority_fault = (
                "mobile change receipt revision unavailable; manual outcome "
                "verification required"
            )
            self.set_health(0, self._receipt_authority_fault)
            return "", False
        receipt_details = {
            **dict(details or {}),
            "event_type": "mobile_change_receipt",
            "disposition": "audit",
            "audit_only": True,
            "response_authorized": False,
            "operator_authenticated": True,
            "receipt_id": receipt_id,
            "command": command,
            "outcome": outcome,
            "authorization_nonce_sha256": hashlib.sha256(
                token.encode("ascii", "strict")
            ).hexdigest(),
        }
        self.emit(
            f"Mobile change result {command}: {outcome} "
            f"(receipt {receipt_id}).",
            (
                Severity.INFO
                if outcome in {"applied", "pending"}
                else Severity.HIGH
                if outcome == "indeterminate"
                else Severity.MEDIUM
            ),
            **receipt_details,
        )
        verified = False
        try:
            _current, events, _overflow = bus.recent_since(revision)
            event = next(
                candidate
                for candidate in events
                if candidate.module == self.name
                and candidate.details.get("event_type") == "mobile_change_receipt"
                and hmac.compare_digest(
                    str(candidate.details.get("receipt_id") or ""), receipt_id
                )
            )
            verified = bool(
                getattr(bus, "_authority", None) is authority
                and getattr(bus, "integrity_enabled", False)
                and re.fullmatch(r"[0-9a-f]{64}", str(event.hmac_sig or ""))
                and authority.verify(event)
            )
        except (AttributeError, RuntimeError, StopIteration, TypeError, ValueError):
            verified = False
        if not verified:
            self._receipt_authority_fault = (
                "mobile change receipt HMAC could not be reverified; manual "
                "outcome verification required"
            )
            self.set_health(0, self._receipt_authority_fault)
        return receipt_id, verified

    @staticmethod
    def _receipt_phrase(proof: tuple[str, bool]) -> str:
        receipt_id, verified = proof
        if verified:
            return f"signed receipt {receipt_id}"
        if receipt_id:
            return f"receipt {receipt_id} failed HMAC reverification"
        return "signed receipt unavailable"

    # ── Command parser ─────────────────────────────────────────────────────────
    def _handle(
        self,
        sender: str,
        body: str,
        *,
        message_id: str = "",
        sent_at: float | None = None,
    ) -> None:
        cfg = self._cfg()
        # Only accept commands from an explicit, unambiguous configured operator
        # identity. Missing sender metadata must never inherit operator authority.
        expected_sender = _signal_identity(cfg["dest"])
        actual_sender = _signal_identity(sender)
        if (
            not expected_sender
            or not actual_sender
            or not hmac.compare_digest(actual_sender, expected_sender)
        ):
            return self._spoof(body, "missing or unauthorized sender identity")

        parts = body.strip().split()
        if not parts:
            return
        cmd = parts[0].upper()
        args = parts[1:]

        if cmd == "HELP":
            return self._send(_HELP_TEXT)
        if cmd == "STATUS":
            return self._send(self._status_text())
        if cmd == "DIAG":
            return self._send(self._diag_text())
        if cmd == "ARM":
            if args:
                return self._record_auth_failure(body, "ARM takes no arguments")
            return self._issue_admin_challenge(
                sender=sender,
                message_id=message_id,
                sent_at=sent_at,
                body=body,
            )
        if cmd == "ECO":
            state = args[0].upper() if args else ""
            if len(args) != 3 or state not in ("ON", "OFF"):
                return self._record_auth_failure(body, "bad ECO authorization shape")
            if self._authorize_admin_change(
                f"ECO_{state}",
                args[1],
                args[2],
                sender=sender,
                message_id=message_id,
                sent_at=sent_at,
                body=body,
            ):
                return self._eco(state == "ON", args[1])
            return None
        if cmd == "LOCKDOWN":
            if len(args) != 2:
                return self._record_auth_failure(body, "bad LOCKDOWN authorization shape")
            if self._authorize_admin_change(
                "LOCKDOWN",
                args[0],
                args[1],
                sender=sender,
                message_id=message_id,
                sent_at=sent_at,
                body=body,
            ):
                return self._lockdown(args[0])
            return None
        if cmd in ("KILL", "SUSPEND", "ROLLBACK"):
            if len(args) == 2 and self._authorize_alert_change(
                cmd,
                args[0],
                args[1],
                sender=sender,
                message_id=message_id,
                sent_at=sent_at,
                body=body,
            ):
                return self._gated(cmd, args[0])
            if len(args) != 2:
                return self._record_auth_failure(body, f"bad {cmd} authorization shape")
            return None
        if cmd == "MUTE":
            if len(args) == 2 and self._authorize_alert_change(
                "MUTE",
                args[0],
                args[1],
                sender=sender,
                message_id=message_id,
                sent_at=sent_at,
                body=body,
            ):
                return self._mute(args[0])
            if len(args) != 2:
                return self._record_auth_failure(body, "bad MUTE authorization shape")
            return None
        # Not a built-in command → hand it to ARIA for a conversational answer.
        # The sender is already verified as the operator (checked at the top), so
        # this is the operator chatting with ARIA from their phone. ARIA's
        # state-changing actions are NOT reachable here — only reads/conversation.
        if self._aria_handler is not None:
            try:
                reply = self._aria_handler(body.strip())
            except Exception as exc:
                reply = f"(ARIA error: {exc})"
            if reply:
                return self._send(f"🤖 ARIA: {str(reply)[:1200]}")
        return self._spoof(body, "unknown command")

    def _pin_ok(self, given: str) -> bool:
        pin = self._pin()
        return bool(pin) and hmac.compare_digest(given.strip(), pin)

    def _token_ok(self, token: str) -> bool:
        return token in self.pending_alerts

    def _spoof(self, body: str, why: str) -> None:
        h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
        self.emit(
            f"Spoof/Unauthorized Access Attempt ({why}) — msg_sha={h}",
            Severity.HIGH,
            reason=why,
            msg_sha256=h,
            disposition="health",
            event_type="mobile_auth_failure",
            response_authorized=False,
            audit_only=True,
        )

    # ── Command implementations ────────────────────────────────────────────────
    def _status_text(self) -> str:
        try:
            from angerona.core.posture import posture
            p = posture(self._bus, self._manager, self._config)
            f = p.get("factors", {})
            return (f"📊 Threat Posture {p['score']}/100 — {p['label']}\n"
                    f"Active threats(10m): {f.get('active_threats', 0)}\n"
                    f"Degraded modules: {f.get('degraded_modules', 0)}\n"
                    f"Host-applicable KEV CVEs: {f.get('kev_exposure', 0)}\n"
                    f"ATT&CK heat: {f.get('attack_heat', 0)}")
        except Exception as exc:
            return f"STATUS unavailable: {exc}"

    def _diag_text(self) -> str:
        try:
            import psutil
            p = psutil.Process()
            with p.oneshot():
                cpu = p.cpu_percent(interval=0.0)
                rss = p.memory_info().rss / (1024 * 1024)
                threads = p.num_threads()
            vm = psutil.virtual_memory()
            return (f"🛠️ DIAG snapshot\nProc CPU {cpu:.0f}% · RSS {rss:.0f} MB · "
                    f"{threads} threads\nHost RAM {vm.percent:.0f}% used\n"
                    "(Full Black Box bundle available on the host tray app.)")
        except Exception as exc:
            return f"DIAG unavailable: {exc}"

    def _eco(self, on: bool, token: str) -> None:
        """Interface the Adaptive Resource Governor: ON = heavy throttle (passive),
        OFF = restore full cadence."""
        level = 6.0 if on else 1.0
        prior: list[tuple[str, BaseModule, float]] = []
        gov = None
        prior_governor: float | None = None
        try:
            manager = self._manager
            modules = getattr(manager, "modules", None)
            if not isinstance(modules, dict):
                raise RuntimeError("managed module inventory unavailable")
            with ExitStack() as locks:
                manager_lock = getattr(manager, "_module_control_lock", None)
                if hasattr(manager_lock, "__enter__"):
                    locks.enter_context(manager_lock)
                gov = modules.get("Adaptive Resource Governor")
                governor_lock = getattr(gov, "_level_lock", None)
                if hasattr(governor_lock, "__enter__"):
                    locks.enter_context(governor_lock)
                eligible = [
                    (str(name), mod)
                    for name, mod in sorted(
                        modules.items(), key=lambda item: str(item[0]).casefold()
                    )
                    if name != "Adaptive Resource Governor"
                    and isinstance(mod, BaseModule)
                    and getattr(mod, "category", "") != "Response"
                    and hasattr(getattr(mod, "_throttle_lock", None), "__enter__")
                ]
                if not eligible:
                    raise RuntimeError("no eligible trusted managed modules")
                for _name, mod in eligible:
                    locks.enter_context(mod._throttle_lock)
                prior = [
                    (name, mod, float(mod.__dict__.get("_throttle", 1.0)))
                    for name, mod in eligible
                ]
                if gov is not None:
                    prior_governor = float(getattr(gov, "_level", 1.0))
                try:
                    for _name, mod, _prior_level in prior:
                        floor = float(mod.__dict__.get("_throttle_floor", 1.0))
                        object.__setattr__(mod, "_throttle", max(floor, level))
                    if gov is not None:
                        object.__setattr__(gov, "_level", level)
                    if any(
                        float(mod.__dict__.get("_throttle", 0.0))
                        != max(
                            float(mod.__dict__.get("_throttle_floor", 1.0)),
                            level,
                        )
                        for _name, mod, _prior_level in prior
                    ) or (
                        gov is not None
                        and float(getattr(gov, "_level", 0.0)) != level
                    ):
                        raise RuntimeError("cadence postcondition mismatch")
                except Exception:
                    for _name, mod, prior_level in reversed(prior):
                        object.__setattr__(mod, "_throttle", prior_level)
                    if gov is not None and prior_governor is not None:
                        object.__setattr__(gov, "_level", prior_governor)
                    raise
        except Exception as exc:
            proof = self._emit_change_receipt(
                f"ECO_{'ON' if on else 'OFF'}",
                token,
                outcome="rejected",
                details={"reason": f"transaction failed: {type(exc).__name__}"},
            )
            self._send(
                f"🌿 ECO rejected — no cadence change "
                f"({self._receipt_phrase(proof)})."
            )
            return
        prior_digest = hashlib.sha256(json.dumps(
            [(name, value) for name, _module, value in prior],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        proof = self._emit_change_receipt(
            f"ECO_{'ON' if on else 'OFF'}",
            token,
            outcome="applied",
            details={
                "module_count": len(prior),
                "new_throttle": level,
                "prior_state_sha256": prior_digest,
            },
        )
        self._send(
            f"🌿 ECO {'ON' if on else 'OFF'} — "
            f"{'throttled' if on else 'restored'} {len(prior)} non-critical "
            f"module(s) ({self._receipt_phrase(proof)})."
        )

    @staticmethod
    def _bind_process_target(pid, details: dict) -> dict | None:
        """Capture one live PID/create-time/executable identity or fail closed."""
        if not isinstance(pid, int) or pid <= 0 or psutil is None:
            return None
        try:
            process = psutil.Process(pid)
            created = float(process.create_time())
            exe = os.path.normcase(os.path.realpath(str(process.exe() or "")))
            name = str(process.name() or "")
            if not exe:
                return None
            supplied_created = details.get("process_create_time")
            if supplied_created is not None and abs(float(supplied_created) - created) > 0.001:
                return None
            supplied_exe = details.get("exe") or details.get("process_path") or details.get("image")
            if supplied_exe:
                expected_exe = os.path.normcase(os.path.realpath(str(supplied_exe)))
                if expected_exe != exe:
                    return None
            if abs(float(process.create_time()) - created) > 0.001:
                return None
        except Exception:
            return None
        return {
            "pid": pid,
            "process_create_time": created,
            "exe": exe,
            "name": name,
        }

    def _prepare_rollback_artifact(self, ev) -> dict | None:
        if is_remote_observe_only(ev):
            return None
        details = ev.details if isinstance(ev.details, dict) else {}
        raw_path = details.get("path") or details.get("artifact_path")
        if not isinstance(raw_path, str) or not raw_path:
            return None
        try:
            shadow = (
                getattr(self._manager, "modules", {}).get("Shadow Shield")
                if self._manager is not None
                else None
            )
            prepare = getattr(shadow, "prepare_rollback_artifact", None)
            if not callable(prepare):
                return None
            artifact = prepare(raw_path, before_ts=float(ev.ts))
            return dict(artifact) if isinstance(artifact, dict) else None
        except Exception:
            return None

    def _combat_consumer(self):
        try:
            combat = (
                getattr(self._manager, "modules", {}).get("Adversary Combat")
                if self._manager is not None
                else None
            )
        except Exception:
            combat = None
        if combat is None or getattr(combat, "status", "stopped") != "running":
            return None
        if not callable(getattr(combat, "list_actions", None)):
            return None
        return combat

    def _source_event_valid(self, info: dict) -> bool:
        """Rebind a mobile token to its still-live authenticated source alert."""
        source_hmac = str(info.get("source_event_hmac") or "")
        if (
            self._bus is None
            or not getattr(self._bus, "integrity_enabled", False)
            or not re.fullmatch(r"[0-9a-f]{64}", source_hmac)
        ):
            return False
        try:
            events = self._bus.recent(500)
        except Exception:
            return False
        for event in events:
            if not hmac.compare_digest(str(event.hmac_sig or ""), source_hmac):
                continue
            try:
                if not self._bus.verify(event) or is_remote_observe_only(event):
                    return False
            except Exception:
                return False
            details = event.details if isinstance(event.details, dict) else {}
            return details.get("pid") == info.get("pid")
        return False

    @staticmethod
    def _receipt_ids(
        combat,
        *,
        trigger_ts: float,
        expected_action: str,
        request_id: str = "",
    ) -> set[str]:
        found: set[str] = set()
        try:
            rows = combat.list_actions(limit=250)
        except Exception:
            return found
        for row in rows:
            try:
                same_ts = abs(float(row.get("trigger_ts")) - trigger_ts) < 0.000001
            except (TypeError, ValueError, OverflowError):
                same_ts = False
            row_details = row.get("details", {})
            row_request_id = (
                str(row_details.get("queue_request_id") or "").casefold()
                if isinstance(row_details, dict)
                else ""
            )
            request_matches = not request_id or not row_request_id or hmac.compare_digest(
                row_request_id, request_id.casefold()
            )
            if (
                same_ts
                and request_matches
                and row.get("trigger_module") == "Mobile Response Bridge"
                and row.get("action") == expected_action
                and row.get("status") == "applied"
                and row.get("integrity_status") == "verified"
                and isinstance(row_details, dict)
                and row_details.get("postcondition_verified") is True
            ):
                action_id = str(row.get("action_id") or "")
                if action_id:
                    found.add(action_id)
        return found

    def _combat_outcome(
        self,
        combat,
        *,
        trigger_ts: float,
        expected_action: str,
        request_id: str,
    ) -> tuple[str, str]:
        """Return only a verified applied/rejected result or ``pending``."""
        action_ids = self._receipt_ids(
            combat,
            trigger_ts=trigger_ts,
            expected_action=expected_action,
            request_id=request_id,
        )
        if action_ids:
            return "applied", sorted(action_ids)[0]
        try:
            rows = combat.list_actions(limit=250)
        except Exception:
            rows = []
        for row in rows:
            try:
                same_ts = abs(float(row.get("trigger_ts")) - trigger_ts) < 0.000001
            except (AttributeError, TypeError, ValueError, OverflowError):
                continue
            if (
                same_ts
                and row.get("trigger_module") == self.name
                and row.get("action") == expected_action
                and row.get("integrity_status") == "verified"
                and row.get("status") in {"orphaned", "recovery_required"}
            ):
                return "indeterminate", "Combat reported recovery-required state"

        bus = self._bus
        if bus is None or not getattr(bus, "integrity_enabled", False):
            return "pending", ""
        try:
            events = bus.recent(500)
        except Exception:
            return "pending", ""
        for event in events:
            details = event.details if isinstance(event.details, dict) else {}
            if (
                event.module != getattr(combat, "name", "Adversary Combat")
                or not hmac.compare_digest(
                    str(details.get("queue_request_id") or "").casefold(),
                    request_id.casefold(),
                )
            ):
                continue
            try:
                if not event.hmac_sig or not bus.verify(event):
                    continue
            except Exception:
                continue
            if (
                details.get("action_succeeded") is True
                and details.get("postcondition_verified") is True
                and expected_action in tuple(details.get("actions") or ())
            ):
                ids = [str(value) for value in details.get("action_ids") or () if value]
                if ids:
                    return "applied", sorted(ids)[0]
            if details.get("action_succeeded") is False:
                return "rejected", "verified Combat completion found no eligible action"
        return "pending", ""

    def _execute_combat(
        self,
        cmd: str,
        info: dict,
        *,
        token: str = "",
    ) -> tuple[bool | None, str]:
        """Publish one authenticated exact contract and await its Combat receipt."""
        combat = self._combat_consumer()
        if combat is None:
            return False, "authenticated Combat consumer unavailable"
        if self._bus is None or not getattr(self._bus, "integrity_enabled", False):
            return False, "EventBus response authentication is unavailable"
        if len(self._pending_combat_requests) >= _MAX_PENDING_COMBAT_REQUESTS:
            return False, "pending Combat reconciliation capacity exhausted"

        request_id = secrets.token_hex(16)

        if cmd == "LOCKDOWN":
            try:
                policy = combat.policy()
            except Exception:
                return False, "Combat policy unavailable"
            if not policy.isolate_host or policy.mode != "maximum":
                return False, "Combat policy does not authorize host isolation"
            expected_action = "isolate_host"
            details = {
                "active_attack": True,
                "operator_authenticated": True,
                "response_authorized": True,
                "response_contract": {
                    "version": 1,
                    "actions": [expected_action],
                    "targets": {"host": "local"},
                },
            }
        else:
            if info.get("response_eligible") is not True:
                return False, "alert is not eligible for local response"
            if not self._source_event_valid(info):
                return False, "source alert authentication expired or changed"
            bound = self._bind_process_target(info.get("pid"), info)
            if bound is None:
                return False, "process identity changed or PID was reused"
            try:
                policy = combat.policy()
            except Exception:
                return False, "Combat policy unavailable"
            if cmd == "KILL":
                if policy.process_action != "terminate" or policy.mode == "contain":
                    return False, "Combat policy does not authorize termination"
                expected_action = "terminate_process"
            elif cmd == "SUSPEND":
                if policy.process_action != "suspend" and policy.mode != "contain":
                    return False, "Combat policy does not authorize suspension"
                expected_action = "suspend_process"
            else:
                return False, "unsupported mobile response command"
            details = {
                "pid": bound["pid"],
                "process_create_time": bound["process_create_time"],
                "exe": bound["exe"],
                "operator_authenticated": True,
                "source_event_hmac": str(info.get("source_event_hmac") or ""),
                "response_authorized": True,
                "response_contract": {
                    "version": 1,
                    "actions": [expected_action],
                    "targets": {
                        "pid": bound["pid"],
                        "process_create_time": bound["process_create_time"],
                    },
                },
            }

        trigger_ts = time.time()
        details["queue_request_id"] = request_id
        details["mobile_request_id"] = request_id
        try:
            self._bus.publish(Event(
                self.name,
                f"Authenticated mobile {cmd} request for exact local target.",
                Severity.CRITICAL,
                trigger_ts,
                details,
            ))
        except Exception as exc:
            return False, f"directive publication failed ({exc})"

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            outcome, result = self._combat_outcome(
                combat,
                trigger_ts=trigger_ts,
                expected_action=expected_action,
                request_id=request_id,
            )
            if outcome == "applied":
                return True, result
            if outcome == "rejected":
                return False, result
            if outcome == "indeterminate":
                break
            time.sleep(0.05)
        now = time.monotonic()
        self._pending_combat_requests[request_id] = _PendingCombatRequest(
            request_id=request_id,
            command=cmd,
            token=token,
            trigger_ts=trigger_ts,
            expected_action=expected_action,
            target_pid=(info.get("pid") if isinstance(info.get("pid"), int) else None),
            created_monotonic=now,
            expires_monotonic=now + _PENDING_COMBAT_TTL_SECONDS,
        )
        return None, request_id

    def _reconcile_pending_combat(self) -> None:
        """Finalize delayed Combat requests without ever guessing host outcome."""
        if not self._pending_combat_requests:
            return
        combat = self._combat_consumer()
        now = time.monotonic()
        for request_id, request in list(self._pending_combat_requests.items()):
            if combat is None:
                outcome, result = "pending", ""
            else:
                outcome, result = self._combat_outcome(
                    combat,
                    trigger_ts=request.trigger_ts,
                    expected_action=request.expected_action,
                    request_id=request_id,
                )
            if outcome == "pending" and now < request.expires_monotonic:
                continue
            if outcome == "pending":
                outcome = "indeterminate"
                result = "no verified terminal Combat result before reconciliation TTL"
            proof = self._emit_change_receipt(
                request.command,
                request.token,
                outcome=outcome,
                details={
                    "mobile_request_id": request_id,
                    "combat_receipt_id": result if outcome == "applied" else "",
                    "reason": "" if outcome == "applied" else result[:240],
                    "target_pid": request.target_pid,
                    "reconciled": True,
                },
            )
            label = "🚫 KILL" if request.command == "KILL" else (
                "⏸️ SUSPEND" if request.command == "SUSPEND" else "🚨 LOCKDOWN"
            )
            if outcome == "applied":
                self._soar_event(
                    request.command,
                    request.target_pid,
                    f"delayed mobile request {request_id}",
                    applied=True,
                    receipt_id=result,
                )
                self._send(
                    f"{label} request {request_id} later completed and its "
                    f"postcondition was verified (Combat receipt {result}; "
                    f"{self._receipt_phrase(proof)})."
                )
            elif outcome == "rejected":
                self._soar_event(
                    request.command,
                    request.target_pid,
                    f"delayed mobile request {request_id} rejected",
                    applied=False,
                    error=result,
                )
                self._send(
                    f"{label} request {request_id} reached a verified rejection: "
                    f"{result} ({self._receipt_phrase(proof)})."
                )
            else:
                self._send(
                    f"{label} request {request_id} remains indeterminate: {result}. "
                    "Inspect the host and Combat journal before assuming either "
                    f"outcome ({self._receipt_phrase(proof)})."
                )
            self._pending_combat_requests.pop(request_id, None)

    def _lockdown(self, token: str = "") -> None:
        ok, receipt = self._execute_combat("LOCKDOWN", {}, token=token)
        if ok is True:
            proof = self._emit_change_receipt(
                "LOCKDOWN",
                token,
                outcome="applied",
                details={"combat_receipt_id": receipt},
            )
            self._soar_event(
                "MACRO_ISOLATE", None, "operator LOCKDOWN (mobile)",
                applied=True, receipt_id=receipt,
            )
            self._send(
                f"🚨 LOCKDOWN applied and postcondition-verified "
                f"(Combat receipt {receipt}; {self._receipt_phrase(proof)})."
            )
        elif ok is None:
            proof = self._emit_change_receipt(
                "LOCKDOWN",
                token,
                outcome="pending",
                details={"mobile_request_id": receipt},
            )
            self._send(
                f"🚨 LOCKDOWN request {receipt} was admitted; completion is "
                "pending. Do not assume action or no action until reconciliation "
                f"({self._receipt_phrase(proof)})."
            )
        else:
            proof = self._emit_change_receipt(
                "LOCKDOWN",
                token,
                outcome="rejected",
                details={"reason": str(receipt)[:240]},
            )
            self._soar_event(
                "MACRO_ISOLATE", None, "operator LOCKDOWN rejected",
                applied=False, error=receipt,
            )
            self._send(
                f"🚨 LOCKDOWN rejected — no host action: {receipt} "
                f"({self._receipt_phrase(proof)})."
            )

    def _gated(self, cmd: str, token: str) -> None:
        info = self.pending_alerts.pop(token, None)   # single-use
        if not info:
            return
        pid = info.get("pid")
        if cmd == "ROLLBACK":
            ok, result = self._rollback(info)
            proof = self._emit_change_receipt(
                cmd,
                token,
                outcome="applied" if ok else "rejected",
                details={
                    "artifact_receipt_id": str(result)[:240] if ok else "",
                    "reason": "" if ok else str(result)[:240],
                },
            )
            if ok:
                self._send(
                    f"🔄 ROLLBACK {token} — one exact Shadow Shield version "
                    f"restored ({result}; {self._receipt_phrase(proof)})."
                )
            else:
                self._send(
                    f"🔄 ROLLBACK {token} rejected — no file restored: {result} "
                    f"({self._receipt_phrase(proof)})."
                )
            return
        # KILL / SUSPEND
        ok, result = self._execute_combat(cmd, info, token=token)
        outcome = "applied" if ok is True else "pending" if ok is None else "rejected"
        proof = self._emit_change_receipt(
            cmd,
            token,
            outcome=outcome,
            details={
                "combat_receipt_id": str(result)[:240] if ok is True else "",
                "mobile_request_id": str(result) if ok is None else "",
                "reason": "" if ok is not False else str(result)[:240],
                "target_pid": pid,
                "target_process_create_time": info.get("process_create_time"),
            },
        )
        label = "🚫 KILL" if cmd == "KILL" else "⏸️ SUSPEND"
        if ok is True:
            self._soar_event(
                cmd, pid, f"operator {cmd} token {token}",
                applied=True, receipt_id=result,
            )
            self._send(
                f"{label} {token} — applied and postcondition-verified "
                f"(Combat receipt {result}; {self._receipt_phrase(proof)})."
            )
        elif ok is None:
            self._send(
                f"{label} request {result} was admitted; completion is pending. "
                "Do not assume process action or no action until reconciliation "
                f"({self._receipt_phrase(proof)})."
            )
        else:
            self._soar_event(
                cmd, pid, f"operator {cmd} rejected",
                applied=False, error=result,
            )
            self._send(
                f"{label} {token} rejected — no process action: {result} "
                f"({self._receipt_phrase(proof)})."
            )

    def _rollback(self, info: dict) -> tuple[bool, str]:
        if info.get("response_eligible") is not True:
            return False, "alert is not eligible for local rollback"
        if not self._source_event_valid(info):
            return False, "source alert authentication expired or changed"
        artifact = info.get("rollback_artifact")
        if not isinstance(artifact, dict):
            return False, "token has no exact authorized rollback artifact"
        try:
            shdw = self._manager.modules.get("Shadow Shield") if self._manager else None
            restore = getattr(shdw, "restore_rollback_artifact", None)
            if not callable(restore):
                return False, "scoped Shadow Shield consumer unavailable"
            result = restore(dict(artifact))
        except Exception as exc:
            return False, f"scoped Shadow Shield failure ({exc})"
        restored = result.get("restored") if isinstance(result, dict) else None
        failed = result.get("failed") if isinstance(result, dict) else None
        expected = str(artifact.get("source_path") or "")
        if restored == [expected] and not failed:
            return True, str(artifact.get("artifact_id") or "")
        return False, "exact artifact postcondition was not verified"

    def _mute(self, token: str) -> None:
        info = self.pending_alerts.pop(token, None) or {}
        module = info.get("module", "")
        if module:
            self._muted[module] = time.time() + 15 * 60
            proof = self._emit_change_receipt(
                "MUTE",
                token,
                outcome="applied",
                details={"module": str(module)[:120], "duration_seconds": 900},
            )
            self._send(
                f"📕 MUTE {token} — suppressing '{module}' alerts for 15 minutes "
                f"({self._receipt_phrase(proof)})."
            )
        else:
            proof = self._emit_change_receipt(
                "MUTE", token, outcome="rejected", details={"reason": "unknown module"}
            )
            self._send(
                f"MUTE {token} — could not resolve originating module "
                f"({self._receipt_phrase(proof)})."
            )

    # ── Mitigation directive helpers ────────────────────────────────────────────
    def _emit_mitigation(
        self,
        action: str,
        pid,
        reason: str,
        *,
        directive_authorized: bool,
        event_type: str = "mobile_response_directive",
    ) -> None:
        # This bus record is an audit/directive envelope, not detector evidence.
        # Its authority is deliberately scoped to an exact directive consumer;
        # generic response tiers must not turn KILL/SUSPEND into host isolation.
        self.emit(
            f"[MOBILE-DIRECTIVE] {action} requested (pid={pid}) — {reason}",
            Severity.CRITICAL,
            soar_action=action,
            target_pid=pid,
            origin="mobile_bridge",
            reason=reason,
            disposition="health" if not directive_authorized else "directive",
            event_type=event_type,
            response_authorized=False,
            directive_authorized=directive_authorized,
            response_scope="mobile-directive-only",
        )

    def _soar_event(
        self,
        action: str,
        pid,
        reason: str,
        *,
        applied: bool = False,
        receipt_id: str = "",
        error: str = "",
    ) -> None:
        try:
            from pathlib import Path
            from angerona.core.data_paths import data_dir
            repo = data_dir()
            d = repo / "shared_logs"
            d.mkdir(parents=True, exist_ok=True)
            ev = {"ts": time.time(), "type": action, "severity": "Critical",
                  "pid": pid, "reason": reason, "origin": "mobile_bridge",
                  "auto_applied": bool(applied), "receipt_id": receipt_id,
                  "error": error[:500]}
            with open(d / "soar_events.json", "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass

    # ── Loop ────────────────────────────────────────────────────────────────────
    @staticmethod
    def _trust_config_error(cfg: dict) -> str:
        if not (cfg["cli"] and cfg["host"] and cfg["dest"]):
            return "signal-cli path/account/destination is incomplete"
        if not _SHA256_RE.fullmatch(str(cfg.get("sha256") or "").casefold()):
            return "mobile_signal_cli_sha256 must pin exactly 64 hexadecimal digits"
        publisher = str(cfg.get("publisher") or "").strip()
        if not publisher or len(publisher) > 512 or "\x00" in publisher:
            return "mobile_signal_cli_publisher must pin the exact Authenticode subject"
        if sys.platform != "win32":
            return "sealed signal-cli execution is unavailable on this platform"
        return ""

    def run(self) -> None:
        while not self.stopping:
            if not self._enabled():
                self.set_health(100, "disabled (enable in Settings ▸ Mobile Integration)")
                self.sleep(5.0)
                continue
            cfg = self._cfg()
            trust_error = self._trust_config_error(cfg)
            if trust_error:
                self.set_health(20, f"mobile response inert: {trust_error}")
                self.sleep(5.0)
                continue

            try:
                self._reconcile_pending_combat()
                self._poll_alerts()
                for command in self._receive():
                    self._handle(
                        command.sender,
                        command.body,
                        message_id=command.message_id,
                        sent_at=command.sent_at,
                    )
                now = time.time()
                if now - self._last_sweep >= _TTL_SWEEP_S:
                    self._last_sweep = now
                    self._sweep_tokens()
                self._flush_digest()
                if self._receipt_authority_fault:
                    self.set_health(0, self._receipt_authority_fault)
                elif self._cli_failures:
                    failures = "; ".join(
                        f"{purpose}: {detail}"
                        for purpose, detail in sorted(self._cli_failures.items())
                    )
                    self.set_health(40, failures[:500])
                elif time.monotonic() - self._last_cli_receipt_at > max(
                    30.0, self.POLL_S * 5
                ):
                    self.set_health(60, "sealed CLI but no recent verified IPC receipt")
                else:
                    self.set_health(
                        100,
                        f"sealed identity + verified IPC receipt; "
                        f"{len(self.pending_alerts)} pending token(s)",
                    )
            except Exception as exc:
                self.set_health(50, f"bridge loop error: {exc}")
            self.sleep(self.POLL_S)

    def self_test(self) -> tuple[bool, str]:
        if not self._enabled():
            return True, "disabled (opt-in)"
        cfg = self._cfg()
        trust_error = self._trust_config_error(cfg)
        if trust_error:
            return False, trust_error
        result = self._invoke_cli("self-test", ["--version"], timeout=10.0)
        if not self._result_valid(result, "self-test"):
            return False, result.error
        return True, (
            "signal-cli identity, job custody, return code, bounded output, and "
            "authenticated nonce receipt verified"
        )


def register() -> BaseModule:
    return MobileResponseBridge()
