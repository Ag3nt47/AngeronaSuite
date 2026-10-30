"""Read-only, bounded disk-version leads for Windows servicing rollback review.

The pending queue is untrusted input. Only recognized replacement operations
targeting fixed critical images are compared; this is not a full POQ interpreter,
signature verification, a loaded-image measurement, or a reboot blocker.
Windows.old is a recovery source, not evidence that a downgrade was scheduled.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import math
import ntpath
import os
from pathlib import Path
import stat
import time
from typing import Callable

from defusedxml import ElementTree as SafeET

from .werfault_guard import windows_arguments


MAX_XML_BYTES = 2 * 1024 * 1024
MAX_ELEMENTS = 8192
MAX_OPERATIONS = 128
MAX_IMAGE_BYTES = 128 * 1024 * 1024
CRITICAL_IMAGES = (
    "System32\\ntoskrnl.exe", "System32\\ci.dll", "System32\\securekernel.exe",
    "System32\\skci.dll", "System32\\hvix64.exe", "System32\\hvax64.exe",
    "System32\\lsaiso.exe", "System32\\drivers\\win32k.sys",
    "System32\\drivers\\afd.sys", "System32\\drivers\\tcpip.sys",
)
_REPLACEMENTS = frozenset({"HardlinkFile", "MoveFile", "CopyFile"})
_ALIASES = frozenset({"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                      *(f"lpt{i}" for i in range(1, 10))})
Version = tuple[int, int, int, int]


def local_path(value: object, windows: str) -> str:
    """Normalize only documented DOS/SystemRoot spellings; never expand env."""
    if type(value) is not str or not 3 <= len(value) <= 4096:
        raise ValueError("invalid path size")
    value = value.replace("/", "\\")
    if value.casefold().startswith("\\systemroot\\"):
        value = windows + value[len("\\SystemRoot"):]
    elif value.startswith("\\??\\"):
        value = value[4:]
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or not drive[0].isascii() or not drive[0].isalpha()
            or drive[1] != ":" or not tail.startswith("\\") or tail.startswith("\\\\")):
        raise ValueError("only absolute local DOS paths are sampled")
    parts = tail[1:].split("\\")
    if any(not part or part in {".", ".."} or part.endswith((" ", "."))
           or any(ord(c) < 32 or ord(c) == 127 or c in ':*?<>|"' for c in part)
           or part.split(".")[0].casefold() in _ALIASES for part in parts):
        raise ValueError("path has an unsupported alias")
    return value


@dataclass(frozen=True)
class Replacement:
    source: str
    destination: str
    operation: str


@dataclass(frozen=True)
class PendingQueue:
    replacements: tuple[Replacement, ...]
    unsupported: int
    ignored_targets: int


def parse_pending(raw: bytes, windows: str) -> PendingQueue:
    """Extract bounded direct POQ replacement leads, never execute any action."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_XML_BYTES:
        raise ValueError("pending XML size is unavailable or exceeds the bound")
    targets = {ntpath.join(windows, image).casefold() for image in CRITICAL_IMAGES}
    replacements, unsupported, ignored, depth, seen, actions = [], 0, 0, 0, 0, 0
    stack: list[str] = []
    root = ""
    for event, element in SafeET.iterparse(io.BytesIO(raw), events=("start", "end"),
                                         forbid_dtd=True, forbid_entities=True,
                                         forbid_external=True):
        tag = element.tag
        if type(tag) is not str or "}" in tag or ":" in tag:
            raise ValueError("pending XML namespace is unsupported")
        if event == "start":
            seen += 1
            depth += 1
            if seen > MAX_ELEMENTS or depth > 24:
                raise ValueError("pending XML work bound exceeded")
            if not root:
                root = tag
                if root != "PendingTransaction":
                    raise ValueError("pending XML root is unsupported")
            stack.append(tag)
            continue
        # Only the current action list is interpreted. RollbackInformation and
        # similarly named nested elements cannot masquerade as scheduled work.
        if len(stack) == 3 and stack[:2] == ["PendingTransaction", "POQ"]:
            actions += 1
            if actions > MAX_OPERATIONS:
                raise ValueError("pending action bound exceeded")
            if tag in _REPLACEMENTS:
                try:
                    source = local_path(element.attrib.get("source"), windows)
                    destination = local_path(element.attrib.get("destination"), windows)
                except ValueError:
                    unsupported += 1
                else:
                    if destination.casefold() in targets:
                        replacements.append(Replacement(source, destination, tag))
                    else:
                        ignored += 1
            else:
                unsupported += 1
        stack.pop()
        depth -= 1
        element.clear()
    return PendingQueue(tuple(replacements), unsupported, ignored)


def _version(value: object) -> Version:
    if (type(value) is not tuple or len(value) != 4
            or any(type(v) is not int or not 0 <= v <= 65535 for v in value)):
        raise ValueError("version resource is unavailable")
    return value


@dataclass(frozen=True)
class VersionLead:
    token: str
    origin: str
    current: Version
    candidate: Version


@dataclass(frozen=True)
class RollbackAudit:
    pending_state: str
    compared: int
    unavailable: int
    unsupported: int
    ignored_targets: int
    leads: tuple[VersionLead, ...]
    budget_exhausted: bool
    queue_reference: str = "canonical-default"

    def event_details(self) -> dict:
        return {
            "schema": "angerona.windows-rollback-audit.v1",
            "pending_state": self.pending_state, "compared_count": self.compared,
            "queue_reference": self.queue_reference,
            "unavailable_count": self.unavailable,
            "unsupported_operation_count": self.unsupported,
            "out_of_scope_target_count": self.ignored_targets,
            "budget_exhausted": self.budget_exhausted,
            "leads": [dict(image_token=x.token, origin=x.origin,
                           current_version=list(x.current), candidate_version=list(x.candidate))
                      for x in self.leads],
            "scope": "fixed-critical-image-disk-version-samples",
            "loaded_image_binding": False, "signature_verified": False,
            "full_queue_coverage": False, "active_attack": False,
            "response_authorized": False, "reboot_blocked": False,
            "reason": ("Scheduled lower versions need servicing/change review; Windows.old "
                       "candidates alone are expected recovery data, not a scheduled downgrade."),
        }


def audit_versions(*, windows: str, pending: bytes | None,
                   version_reader: Callable[[str], Version],
                   old_present: bool, clock=time.monotonic, budget: float = 5.0) -> RollbackAudit:
    """Cooperative worker budget; a single local native file read is not preempted."""
    windows = local_path(windows, windows)
    if (type(old_present) is not bool or type(budget) not in (int, float)
            or not math.isfinite(budget) or not 0 < budget <= 10):
        raise ValueError("invalid audit controls")
    deadline = clock() + budget
    pending_state, unsupported, ignored = "absent", 0, 0
    operations: tuple[Replacement, ...] = ()
    if pending is not None:
        try:
            queue = parse_pending(pending, windows)
        except Exception:
            pending_state, unsupported = "unavailable-or-unsupported", 1
        else:
            pending_state = "sampled"
            operations, unsupported, ignored = queue.replacements, queue.unsupported, queue.ignored_targets
    compared, unavailable, leads, exhausted = 0, 0, [], False
    candidates = [(item.source, item.destination, "pending-queue") for item in operations]
    if old_present:
        old_windows = ntpath.join(ntpath.splitdrive(windows)[0] + "\\", "Windows.old", "Windows")
        candidates.extend((ntpath.join(old_windows, image), ntpath.join(windows, image),
                           "recovery-copy-only") for image in CRITICAL_IMAGES)
    for source, destination, origin in candidates:
        if clock() >= deadline:
            exhausted = True
            break
        try:
            current = _version(version_reader(destination))
            if clock() >= deadline:
                exhausted = True
                break
            candidate = _version(version_reader(source))
        except Exception:
            unavailable += 1
            continue
        compared += 1
        if candidate < current:
            token = hashlib.sha256(destination.casefold().encode("utf-8")).hexdigest()
            leads.append(VersionLead(token, origin, current, candidate))
    return RollbackAudit(pending_state, compared, unavailable, unsupported, ignored,
                         tuple(leads), exhausted)


def _regular_local(path: str) -> os.stat_result:
    """Best-effort named-path sample checks; deliberately no custody claim."""
    from ctypes import WinDLL, c_uint, c_wchar_p
    path = local_path(path, path)
    drive_type = WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    drive_type.argtypes, drive_type.restype = [c_wchar_p], c_uint
    if drive_type(ntpath.splitdrive(path)[0] + "\\") != 3:
        raise ValueError("fixed local volume required")
    value = Path(path)
    for part in (*reversed(value.parents), value):
        info = part.lstat()
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("reparse sample is unavailable")
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_IMAGE_BYTES:
        raise ValueError("regular bounded image required")
    return info


def read_disk_version(path: str) -> Version:
    """Read VERSIONINFO only. No LoadLibrary, subprocess, signer or trust verdict."""
    before = _regular_local(path)
    import win32api
    values = win32api.GetFileVersionInfo(path, "\\")
    after = _regular_local(path)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("named image changed during version sampling")
    ms, ls = values["FileVersionMS"], values["FileVersionLS"]
    return _version((ms >> 16, ms & 65535, ls >> 16, ls & 65535))


def pending_reference(value: object, windows: str) -> tuple[str, str]:
    """Review one registry-selected queue without executing the command line."""
    if type(value) is not list or len(value) != 1 or type(value[0]) is not str:
        raise ValueError("servicing command must be one bounded REG_MULTI_SZ item")
    args = windows_arguments(value[0])
    expected = ntpath.join(windows, "System32", "poqexec.exe")
    if len(args) not in (2, 3) or local_path(args[0], windows).casefold() != expected.casefold():
        raise ValueError("unsupported servicing command")
    if len(args) == 3 and args[1] != "/display_progress":
        raise ValueError("unsupported servicing command option")
    path = local_path(args[-1], windows)
    if not path.casefold().endswith(".xml"):
        raise ValueError("servicing queue must be a local XML file")
    canonical = ntpath.join(windows, "WinSxS", "pending.xml")
    return path, "canonical-reference" if path.casefold() == canonical.casefold() else "custom-local-reference"


def read_pending_reference(windows: str) -> tuple[str, str]:
    import ctypes as c
    from ctypes import wintypes as w
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration",
                             0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        with key:
            # Query into a fixed buffer, including the size-only admission.
            # QueryValueEx would allocate an attacker-selected registry length.
            query = c.WinDLL("advapi32", use_last_error=True).RegQueryValueExW
            query.argtypes = [w.HANDLE, w.LPCWSTR, w.LPVOID, c.POINTER(w.DWORD),
                              w.LPVOID, c.POINTER(w.DWORD)]
            query.restype = w.LONG
            kind, size = w.DWORD(), w.DWORD()
            status = query(int(key), "PoqexecCmdline", None, c.byref(kind), None, c.byref(size))
            if status == 2:
                raise FileNotFoundError("servicing command is absent")
            if status or kind.value != winreg.REG_MULTI_SZ or not 4 <= size.value <= 16384:
                raise ValueError("servicing registry value is unavailable or exceeds its bound")
            buffer = c.create_string_buffer(16384)
            size.value = len(buffer)
            status = query(int(key), "PoqexecCmdline", None, c.byref(kind), buffer, c.byref(size))
            if status or kind.value != winreg.REG_MULTI_SZ or not 4 <= size.value <= len(buffer):
                raise ValueError("servicing registry value changed or is unavailable")
            raw = buffer.raw[:size.value]
            if len(raw) % 2 or not raw.endswith(b"\0\0\0\0"):
                raise ValueError("servicing registry value is unterminated")
            value = raw.decode("utf-16-le", errors="strict")[:-2].split("\0")
    except FileNotFoundError:
        return ntpath.join(windows, "WinSxS", "pending.xml"), "canonical-default"
    return pending_reference(value, windows)


class WindowsRollbackAuditProvider:
    def collect(self) -> RollbackAudit:
        from .privilege import trusted_windows_directories
        windows, _system = trusted_windows_directories()
        try:
            selected, reference = read_pending_reference(str(windows))
        except Exception:
            selected, reference = "", "unavailable-or-unsupported"
        try:
            if not selected:
                raise ValueError("servicing queue reference is unavailable")
            pending_path = Path(selected)
            _regular_local(str(pending_path))
            with pending_path.open("rb") as stream:
                pending = stream.read(MAX_XML_BYTES + 1)
        except FileNotFoundError:
            pending = None if reference == "canonical-default" else b""
        except Exception:
            pending = b""  # unavailability must not be confused with absence
        old = windows.parent / "Windows.old"
        old_gap = False
        try:
            info = old.lstat()
            old_present = stat.S_ISDIR(info.st_mode) and not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
            old_gap = not old_present
        except FileNotFoundError:
            old_present = False
        except OSError:
            # Do not read redirected/uncertain old roots; record the gap below.
            result = audit_versions(windows=str(windows), pending=pending,
                                    version_reader=read_disk_version, old_present=False)
            return RollbackAudit(result.pending_state, result.compared, result.unavailable + 1,
                                 result.unsupported, result.ignored_targets, result.leads,
                                 result.budget_exhausted, reference)
        result = audit_versions(windows=str(windows), pending=pending,
                                version_reader=read_disk_version, old_present=old_present)
        return RollbackAudit(result.pending_state, result.compared, result.unavailable + int(old_gap),
                             result.unsupported, result.ignored_targets, result.leads,
                             result.budget_exhausted, reference)
