"""Pinned optional scanners, supervised outside Angerona's interpreter.

The curated adapter is distinct from the nonexecuting GitHub source library.
Results are external leads and coverage records, never response authority.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
import uuid

from angerona.core.data_paths import data_dir, resource_root
from angerona.core.executable_trust import _open_sealed
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.source_sandbox import (
    _absolute, _atomic_bytes_write as _sandbox_atomic_bytes_write,
    _hold_plain_directories, _validate_chain,
)
from angerona.core.startup_recovery import private_directory, private_repair_file


ZERO_BREACH = {
    "id": "zero-breach", "name": "Zero Breach Toolkit", "version": "0.1.10",
    "repository": "https://github.com/interplains/Zero-Breach-Toolkit",
    "url": "https://github.com/interplains/Zero-Breach-Toolkit",
    "release": "https://github.com/interplains/Zero-Breach-Toolkit/releases/tag/v0.1.10",
    "commit": "81bd556ba604685dbd1c0ecb48138c10f43cccf8",
    "sha256": "075b2a0ac20f285fa4385d6b6c5cda2cedd410364c4f4686db3c1b8b033265d3",
    "bytes": 968987, "license": "Apache-2.0",
}
_ASSET = ZERO_BREACH["repository"] + "/releases/download/v0.1.10/zero-breach-toolkit.py"
_SOURCE = "https://raw.githubusercontent.com/interplains/Zero-Breach-Toolkit/" + ZERO_BREACH["commit"] + "/"
_RELEASE_BASE = ZERO_BREACH["repository"] + "/releases/download/v0.1.10/"
_BUNDLE_FILES = frozenset((
    "engine.py", "LICENSE", "NOTICE", "PRIVACY.md", "iocs/LICENSE.md",
    "third_party/candiru/README.md", "third_party/candiru/LICENSE-DRL-1.1.txt",
    "third_party/candiru/LICENSE-CC-BY-SA-4.0.txt", "third_party/candiru/PROVENANCE.json",
    "third_party/candiru/apt_candiru.yar", "third_party/candiru/win_devilstongue_auto.yar",
    "verification/SHA256SUMS.txt", "verification/SHA256SUMS.txt.asc",
    "verification/zero-breach-toolkit.py.asc", "verification/archivegenocide-signing-key.asc",
))
_CREDITS = (
    {"name": "archivegenocide.com / interplains", "url": ZERO_BREACH["repository"],
     "version": "0.1.10", "license": "Apache-2.0", "notice": "Toolkit code: LICENSE and NOTICE."},
    {"name": "Zero Breach indicator collection", "url": _SOURCE + "iocs/LICENSE.md",
     "license": "CC0-1.0", "notice": "Curated indicator data; original research providers retain their credits."},
    {"name": "Microsoft Threat Intelligence Center (MSTIC)",
     "url": "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_candiru.yar",
     "license": "DRL-1.1", "notice": "Optional MAL_DevilsTongue_HijackDll rule. Author attribution must remain in matches."},
    {"name": "Felix Bilstein", "url": "https://malpedia.caad.fkie.fraunhofer.de/details/win.devilstongue",
     "license": "CC-BY-SA-4.0", "notice": "Optional win_devilstongue_auto rule; retain attribution and its license."},
)
MAX_ENGINE_BYTES = 16 * 1024**2
MAX_LOG_BYTES = 2 * 1024**2
MAX_JSON_BYTES = 8 * 1024**2
MAX_TEXT_BYTES = 8 * 1024**2
MAX_SUMMARY_BYTES = 1024**2
MAX_ENTRIES = 4096
MAX_REPORTS = 8
_REPORT_NAMES = frozenset(("report.json", "report.txt", "summary.json", "stdout.log", "stderr.log", "receipt.json", "request.json"))
_SINGLE_JOB = threading.Lock()
_HELD_CUSTODY = []
_HEX = re.compile(r"[0-9a-f]{32}")
_SHA = re.compile(r"[0-9a-f]{64}")
_UPSTREAM_VERSIONS = frozenset(("0.1.10", "0.1.10 (single-file build)"))


class ToolError(RuntimeError):
    """An optional tool operation could not complete with its stated guarantees."""


class ToolCancelled(ToolError):
    pass


class ToolOperation:
    def __init__(self, timeout: float = 300) -> None:
        self.cancelled = threading.Event()
        self.deadline = time.monotonic() + min(900.0, max(1.0, float(timeout)))

    def cancel(self) -> None:
        self.cancelled.set()

    def check(self) -> None:
        if self.cancelled.is_set():
            raise ToolCancelled("Tool operation cancelled; incomplete coverage is preserved.")
        if time.monotonic() >= self.deadline:
            raise ToolCancelled("Tool deadline reached; incomplete coverage is preserved.")


@dataclass(frozen=True)
class ToolScanRequest:
    mode: str = "default"
    targets: tuple[str, ...] = ()
    phone: bool = False
    ios_input: str = "backup"
    extended_windows: bool = False
    quick: bool = False
    preview: bool = False
    include_feeds: bool = False
    iocs: tuple[str, ...] = ()
    priority: str = "above-normal"
    max_cpu_percent: int = 50
    max_memory_mib: int = 512


def credits() -> tuple[dict, ...]:
    """Cheap fixed attribution data; no filesystem or network access."""
    return tuple(dict(row) for row in _CREDITS)


def _plain(value, limit=2048) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(c if c in "\n\t" or unicodedata.category(c)[0] != "C" else "\ufffd" for c in value[:limit])


def _identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _private(path: Path) -> None:
    _validate_chain(path, allow_missing_tail=True)
    if not path.exists():
        _private(path.parent) if not path.parent.exists() else _validate_chain(path.parent)
        if not private_directory(path, create=True):
            raise ToolError("Optional tool storage could not be created privately.")
    if not private_directory(path, create=False):
        raise ToolError("Optional tool storage is not private current-user storage.")


def _atomic_bytes_write(path: Path, content: bytes, *, root: Path) -> None:
    """Create private tool files before publication; never repair existing ACLs."""
    _sandbox_atomic_bytes_write(path, content, root=root, private=True)


def _read(path: Path, limit: int, *, private=False) -> bytes:
    _validate_chain(path)
    with _hold_plain_directories(path.parent), _open_sealed(path) as stream:
        before = os.fstat(stream.fileno())
        named = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or _identity(before) != _identity(named) or before.st_size > limit
                or getattr(before, "st_file_attributes", 0) & 0x400):
            raise ToolError("Tool data is not the expected bounded regular file.")
        if private and not private_repair_file(path):
            raise ToolError("Tool report lacks private current-user custody.")
        raw = stream.read(limit + 1)
        if len(raw) != before.st_size or _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ToolError("Tool data changed during its bounded read.")
        return raw


class _ReportDeletion:
    """Keep the verified report object in custody until exact-object deletion.

    Windows denies both writers and pathname replacement, and deletion uses
    that same read/DELETE handle. POSIX retains the read descriptor and its
    original identity; same-user writers are outside a mandatory-lock boundary.
    """
    def __init__(self, path: Path, limit: int):
        self.path, self.limit = path, limit
        self._stack = ExitStack()

    def __enter__(self):
        try:
            self._stack.enter_context(_hold_plain_directories(self.path.parent))
            if os.name == "nt":
                import msvcrt
                from ctypes import wintypes as w
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
                kernel.CreateFileW.restype = w.HANDLE
                kernel.CloseHandle.argtypes = (w.HANDLE,)
                handle = kernel.CreateFileW(str(self.path), 0x80010000, 1, None, 3, 0x08200000, None)
                if handle == w.HANDLE(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
                except BaseException:
                    kernel.CloseHandle(handle)
                    raise
                try:
                    stream = os.fdopen(descriptor, "rb", buffering=0)
                except BaseException:
                    os.close(descriptor)
                    raise
            else:
                stream = _open_sealed(self.path)
            self.stream = self._stack.enter_context(stream)
            before = os.fstat(stream.fileno())
            self.identity = _identity(before)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > self.limit or getattr(before, "st_file_attributes", 0) & 0x400
                    or not private_repair_file(self.path)):
                raise ToolError("Scanner report deletion lacks bounded private regular-file custody.")
            self.raw = stream.read(self.limit + 1)
            if len(self.raw) != before.st_size:
                raise ToolError("Scanner report changed during its deletion verification.")
            self.check()
            return self
        except BaseException:
            self._stack.close()
            raise

    def check(self):
        if (_identity(os.fstat(self.stream.fileno())) != self.identity
                or _identity(self.path.lstat()) != self.identity):
            raise ToolError("A scanner output changed after verification; it was preserved.")

    def delete(self):
        self.check()
        if os.name == "nt":
            import msvcrt
            from ctypes import wintypes as w
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.SetFileInformationByHandle.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
            disposition = w.DWORD(1 | 0x10)  # DELETE | IGNORE_READONLY_ATTRIBUTE.
            handle = msvcrt.get_osfhandle(self.stream.fileno())
            if not kernel.SetFileInformationByHandle(handle, 21, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            self.path.unlink()

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)


@dataclass
class _JobState:
    native_state: str = "not-started"
    native_started: bool | None = False
    directories: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)
    outcome: dict = field(default_factory=dict)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def _json(raw: bytes):
    return json.loads(raw, object_pairs_hook=_unique_object)


def _inventory(root: Path, *, limit=MAX_ENTRIES, byte_limit=None) -> tuple[list, int]:
    """Bounded, non-following inventory only under an exact owned root."""
    _validate_chain(root)
    pending = [root]
    rows, total = [], 0
    while pending:
        current = pending.pop()
        with os.scandir(current) as children:
            for entry in children:
                if len(rows) >= limit:
                    raise ToolError("Optional tool storage inventory reached its entry limit; existing data was preserved.")
                path = Path(entry.path)
                # Windows DirEntry caches omit link/inode fields. Custody
                # requires a fresh native stat rather than treating zeros as
                # proof that an ordinary file is unsafe (or single-linked).
                info = path.lstat()
                if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                        or (not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
                    raise ToolError("Optional tool storage contains a redirected, linked or unknown entry; it was preserved.")
                rows.append((path, info))
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    total += info.st_size
                    if byte_limit is not None and total > byte_limit:
                        raise ToolError("Optional tool storage reached its byte budget; existing data was preserved.")
    return rows, total


def _windows_node(path: Path, expected=None, *, delete=False):
    """Observe/delete one exact native node without following a reparse point."""
    from ctypes import wintypes as w

    class Info(ctypes.Structure):
        _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                    ("written", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD),
                    ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
    kernel.CreateFileW.restype = w.HANDLE
    kernel.GetFileInformationByHandle.argtypes = (w.HANDLE, ctypes.POINTER(Info))
    kernel.SetFileInformationByHandle.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    handle = kernel.CreateFileW(str(path), 0x80 | (0x10000 if delete else 0), 3, None, 3, 0x02200000, None)
    if handle == w.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = Info()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        directory = bool(info.attributes & 0x10)
        if info.attributes & 0x400 or (not directory and info.links != 1):
            raise ToolError("Managed cleanup encountered a redirected or linked node; it was preserved.")
        observed = (info.volume, info.index_high, info.index_low, info.created.dwHighDateTime,
                    info.created.dwLowDateTime, directory)
        if not directory:
            observed += (info.size_high, info.size_low, info.written.dwHighDateTime, info.written.dwLowDateTime)
        if expected is not None and observed != expected:
            raise ToolError("Managed cleanup identity changed; the entry was preserved.")
        if delete:
            if directory:
                with os.scandir(path) as entries:
                    if next(entries, None) is not None:
                        raise ToolError("Managed directory contains retained or new entries.")
            disposition = w.DWORD(1 | 0x10)  # DELETE | IGNORE_READONLY_ATTRIBUTE.
            if not kernel.SetFileInformationByHandle(handle, 21, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
        return observed
    finally:
        kernel.CloseHandle(handle)


def _retire_owned_tree(path: Path, *, job: Path) -> dict:
    """Only generated child trees of this exact UUID job; never source evidence."""
    if path.parent != job or path.name not in {"scratch", "cache", "profile"} or not _HEX.fullmatch(job.name):
        raise ToolError("Managed cleanup left its exact generated job scope.")
    _rows, _bytes = _inventory(path, limit=MAX_ENTRIES, byte_limit=3 * 1024**3)
    rows = [*_rows, (path, path.lstat())]
    planned = []
    for item, info in rows:
        _validate_chain(item)
        if os.name == "nt":
            with _hold_plain_directories(item.parent):
                expected = _windows_node(item)
        else:
            expected = _identity(info) if not stat.S_ISDIR(info.st_mode) else (info.st_dev, info.st_ino)
        planned.append((item, info, expected))
    removed, retained = 0, 0
    for item, info, expected in sorted(planned, key=lambda row: len(row[0].parts), reverse=True):
        try:
            with _hold_plain_directories(item.parent):
                if os.name == "nt":
                    _windows_node(item, expected, delete=True)
                else:
                    now = item.lstat()
                    actual = _identity(now) if not stat.S_ISDIR(now.st_mode) else (now.st_dev, now.st_ino)
                    if actual != expected:
                        raise ToolError("Managed cleanup identity changed.")
                    item.rmdir() if stat.S_ISDIR(now.st_mode) else item.unlink()
            removed += 1
        except (OSError, ValueError, ToolError):
            retained += 1
    return {"removed_entries": removed, "retained_entries": retained, "generated_bytes": _bytes}


def _sealed_engine(stack: ExitStack, path: Path):
    stack.enter_context(_hold_plain_directories(path.parent))
    stream = stack.enter_context(_open_sealed(path))
    info, named = os.fstat(stream.fileno()), path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _identity(info) != _identity(named)
            or info.st_size != ZERO_BREACH["bytes"]):
        raise ToolError("The installed scanner has changed; use verified preparation or Revert.")
    raw = stream.read(ZERO_BREACH["bytes"] + 1)
    if hashlib.sha256(raw).hexdigest() != ZERO_BREACH["sha256"] or _identity(os.fstat(stream.fileno())) != _identity(info):
        raise ToolError("The installed scanner hash does not match the reviewed catalog.")
    return stream


def _admin_state() -> dict:
    result = {"verified": False, "process_pid": os.getpid(), "elevated": False,
              "integrity": "unavailable", "creation_filetime": ""}
    if os.name != "nt":
        result.update(verified=True, elevated=os.geteuid() == 0, user_id=os.geteuid(), integrity="POSIX user")
        return result
    try:
        import win32api
        import win32con
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            user, _attrs = win32security.GetTokenInformation(token, win32security.TokenUser)
            result["user_sid"] = win32security.ConvertSidToStringSid(user)
            result["elevated"] = bool(win32security.GetTokenInformation(token, win32security.TokenElevation))
            integrity = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
            sid = integrity[0] if isinstance(integrity, tuple) else integrity
            result["integrity"] = win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
        result["creation_filetime"] = _windows_birth(None)
        result["verified"] = True
    except (OSError, ValueError, AttributeError, ImportError, TypeError):
        pass
    return result


def _require_user() -> dict:
    state = _admin_state()
    if not state["verified"] or state["elevated"]:
        raise PermissionError("Curated scanners require a verified ordinary-user session; elevation metadata grants no execution authority.")
    return state


def _windows_birth(handle) -> str:
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = (w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4))
    values = [w.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(handle or kernel.GetCurrentProcess(), *(ctypes.byref(v) for v in values)):
        raise ctypes.WinError(ctypes.get_last_error())
    return str((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime)


def _catalog(bundle: Path) -> dict:
    document = _json(_read(bundle / "catalog.json", 128 * 1024))
    if (type(document) is not dict or document.get("schema") != 1
            or document.get("tool_id") != ZERO_BREACH["id"]
            or document.get("version") != ZERO_BREACH["version"]
            or document.get("commit") != ZERO_BREACH["commit"]
            or document.get("repository") != ZERO_BREACH["repository"]):
        raise ToolError("The bundled curated catalog identity is invalid.")
    entries = document.get("files")
    if type(entries) is not list or len(entries) != len(_BUNDLE_FILES):
        raise ToolError("The curated bundle file inventory is incomplete.")
    names = set()
    for item in entries:
        if type(item) is not dict or item.get("path") not in _BUNDLE_FILES or item["path"] in names:
            raise ToolError("The curated catalog contains an unknown or duplicate file.")
        names.add(item["path"])
        size = item.get("bytes", item.get("size"))
        if type(size) is not int or not 0 < size <= 2 * 1024**2 or not _SHA.fullmatch(str(item.get("sha256", ""))):
            raise ToolError("The curated catalog file bounds are invalid.")
        if item["path"] == "engine.py" and (size != ZERO_BREACH["bytes"] or item["sha256"] != ZERO_BREACH["sha256"]):
            raise ToolError("The curated scanner pin changed.")
    return document


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _new):
        return None


def _download(item: dict, operation: ToolOperation) -> bytes:
    name = item["path"]
    url = item.get("source_url", item.get("download_url", ""))
    expected = _ASSET if name == "engine.py" else (
        _RELEASE_BASE + PurePosixPath(name).name if name.startswith("verification/") else _SOURCE + name
    )
    if url != expected:
        raise ToolError("The optional download is outside the fixed reviewed release.")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    original = url
    limit = item.get("bytes", item.get("size"))
    for _attempt in range(4):
        operation.check()
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port not in (None, 443)
                or parsed.hostname not in {"github.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com"}):
            raise ToolError("Unapproved curated artifact endpoint.")
        request = urllib.request.Request(url, headers={"User-Agent": "Angerona-Curated-Tools/1", "Accept-Encoding": "identity"})
        try:
            response = opener.open(request, timeout=min(10, max(.1, operation.deadline - time.monotonic())))
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                target = urllib.parse.urljoin(url, exc.headers.get("Location", ""))
                if urllib.parse.urlsplit(url).hostname != "github.com" or urllib.parse.urlsplit(target).hostname != "release-assets.githubusercontent.com":
                    exc.close()
                    raise ToolError("Curated artifact redirected outside its fixed release delivery endpoint.") from None
                exc.close()
                url = target
                continue
            exc.close()
            raise ToolError(f"Curated artifact download failed (HTTP {exc.code}).") from None
        with response:
            if response.status != 200 or response.geturl() != url:
                raise ToolError("Unexpected curated artifact response.")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) != limit):
                raise ToolError("The reviewed artifact size changed.")
            chunks, total = [], 0
            while True:
                operation.check()
                chunk = response.read1(min(64 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ToolError("The reviewed artifact exceeded its download bound.")
                chunks.append(chunk)
        raw = b"".join(chunks)
        if len(raw) != limit or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ToolError("The reviewed artifact checksum changed; no scanner was installed.")
        return raw
    raise ToolError("Too many redirects for the fixed reviewed artifact: " + urllib.parse.urlsplit(original).hostname)


def _request_arguments(request: ToolScanRequest, job: Path) -> list[str]:
    if type(request) is not ToolScanRequest or request.mode not in {"default", "full", "targeted", "browser"}:
        raise ValueError("Choose a supported curated scan mode.")
    if request.include_feeds:
        raise ValueError("Native scans use bundled offline indicators. Feed updates require the explicit advanced toolkit workflow.")
    if request.priority not in {"normal", "above-normal", "high"} or type(request.max_cpu_percent) is not int or not 10 <= request.max_cpu_percent <= 90:
        raise ValueError("Scanner priority or CPU limit is outside the supported range.")
    if type(request.max_memory_mib) is not int or not 128 <= request.max_memory_mib <= 2048:
        raise ValueError("Scanner memory limit must be between 128 and 2048 MiB.")
    for values in (request.targets, request.iocs):
        if type(values) is not tuple or len(values) > 16:
            raise ValueError("Choose at most sixteen local inputs.")
        for value in values:
            if type(value) is not str or len(value) > 4096 or "\x00" in value or not Path(value).is_absolute() or value.startswith(("\\\\", "//")):
                raise ValueError("Scanner inputs must be bounded absolute local paths.")
            if os.name == "nt":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.GetDriveTypeW.argtypes = (ctypes.c_wchar_p,)
                if kernel.GetDriveTypeW(Path(value).anchor) != 3:
                    raise ValueError("Scanner inputs require a fixed local drive; mapped network drives are excluded.")
            _validate_chain(Path(value))
    if request.phone:
        if len(request.targets) != 1 or request.mode != "default" or request.ios_input not in {"backup", "filesystem", "sysdiagnose"}:
            raise ValueError("Phone evidence requires one local input and the default mode.")
    elif bool(request.targets) != (request.mode == "targeted"):
        raise ValueError("Selected-target mode requires targets; other modes use their documented scope.")
    if request.quick and request.mode == "targeted":
        raise ValueError("Quick mode cannot be combined with selected targets.")
    args = ["--no-menu", "--no-pause", "--no-banner", "--scan-type", request.mode,
            "--indicator-cache", str(job / "cache"), "--no-feeds"]
    if request.phone:
        args += ["--phone", request.targets[0], "--ios-input", request.ios_input]
    else:
        for target in request.targets:
            args += ["--target", target]
    for path in request.iocs:
        args += ["--iocs", path]
    for enabled, flag in ((request.quick, "--quick"), (request.preview, "--preview"), (request.extended_windows, "--extended-windows")):
        if type(enabled) is not bool:
            raise ValueError("Scanner switches must be Boolean values.")
        if enabled:
            args.append(flag)
    if not request.preview:
        args += ["--json", str(job / "report.json"), "--report", str(job / "report.txt"),
                 "--share-json", str(job / "summary.json")]
    return args


class _WindowsJob:
    def __init__(self, process, request):
        import win32api
        import win32job
        import win32process
        self.api, self.handle = win32job, win32job.CreateJobObject(None, "")
        self.members = {}
        self.observation_gaps = 0
        self.birth = _windows_birth(process._handle)
        try:
            info = win32job.QueryInformationJobObject(self.handle, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] = (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY | win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            )
            info["BasicLimitInformation"]["ActiveProcessLimit"] = 16
            info["ProcessMemoryLimit"] = request.max_memory_mib * 1024**2
            info["JobMemoryLimit"] = request.max_memory_mib * 1024**2
            win32job.SetInformationJobObject(self.handle, win32job.JobObjectExtendedLimitInformation, info)
            win32job.AssignProcessToJobObject(self.handle, int(process._handle))
            self.retain_members()
            win32process.SetPriorityClass(int(process._handle), {"normal": 0x20, "above-normal": 0x8000, "high": 0x80}[request.priority])
            # Native job CPU hard cap, not a change to Angerona's priority.
            class Rate(ctypes.Structure):
                _fields_ = [("flags", ctypes.c_uint32), ("rate", ctypes.c_uint32)]
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.SetInformationJobObject.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
            rate = Rate(1 | 4, request.max_cpu_percent * 100)
            if not kernel.SetInformationJobObject(int(self.handle), 15, ctypes.byref(rate), ctypes.sizeof(rate)):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            try:
                win32api.TerminateProcess(int(process._handle), 1)
            finally:
                import win32event
                if win32event.WaitForSingleObject(int(process._handle), 5000) == win32event.WAIT_OBJECT_0:
                    self.close()
                else:
                    _HELD_CUSTODY.append((self, process, (), None))
            raise

    def retain_members(self):
        import win32api
        rows = self.api.QueryInformationJobObject(self.handle, self.api.JobObjectBasicProcessIdList)
        identifiers = rows["ProcessIdList"] if isinstance(rows, dict) else rows
        if len(identifiers) > 16:
            raise ToolError("Owned scanner job exceeded its fixed process inventory.")
        for pid in identifiers:
            try:
                held = win32api.OpenProcess(0x101000, False, pid)
            except OSError:
                self.observation_gaps += 1
                continue  # A short-lived member can finish before retention.
            try:
                if not self.api.IsProcessInJob(held, self.handle):
                    raise ToolError("Owned scanner job membership changed.")
                birth = _windows_birth(int(held))
                key = (pid, birth)
                if key not in self.members:
                    if len(self.members) >= 256:
                        self.observation_gaps += 1
                    else:
                        self.members[key] = (held, birth)
                        held = None
            finally:
                if held is not None:
                    held.Close()

    def terminate(self):
        try:
            self.retain_members()
        except (OSError, ValueError, ToolError):
            self.observation_gaps += 1
        self.api.TerminateJobObject(self.handle, 1)

    def wait_empty(self, timeout=5):
        deadline = time.monotonic() + timeout
        while self.api.QueryInformationJobObject(self.handle, self.api.JobObjectBasicAccountingInformation)["ActiveProcesses"]:
            if time.monotonic() >= deadline:
                raise ToolError("Scanner process-tree retirement remains unresolved.")
            time.sleep(.02)
        import win32event
        for handle, _birth in self.members.values():
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            if win32event.WaitForSingleObject(handle, remaining) != win32event.WAIT_OBJECT_0:
                raise ToolError("A retained native scanner generation has not completed retirement.")

    def close(self):
        for handle, _birth in self.members.values():
            handle.Close()
        self.members.clear()
        self.handle.Close()

    def receipt(self):
        return [{"pid": pid, "creation_filetime": birth, "native_retired": True}
                for pid, birth in self.members]

    def resource(self, process):
        self.retain_members()
        state = self.api.QueryInformationJobObject(self.handle, self.api.JobObjectBasicAndIoAccountingInformation)
        basic = state.get("BasicInfo", state.get("BasicAccountingInformation", {}))
        io = state.get("IoInfo", {})
        extended = self.api.QueryInformationJobObject(self.handle, self.api.JobObjectExtendedLimitInformation)
        rss = None
        try:
            import psutil
            rss = psutil.Process(process.pid).memory_info().rss / 1024**2
        except Exception:
            # Optional resource observation cannot turn a normally exited
            # owned process into a failed scanner result.
            pass
        return {"cpu_time": (basic.get("TotalUserTime", 0) + basic.get("TotalKernelTime", 0)) / 10_000_000,
                "rss_mib": rss, "peak_commit_mib": extended.get("PeakJobMemoryUsed", 0) / 1024**2,
                "memory_measurement": "worker RSS; separate job peak committed memory", "read_bytes": io.get("ReadTransferCount", 0),
                "write_bytes": io.get("WriteTransferCount", 0)}


class _OutputPump:
    def __init__(self, stream, path):
        self.stream, self.path, self.dropped, self.error = stream, path, 0, ""
        self.thread = threading.Thread(target=self._run, name="Angerona curated output", daemon=True)
        self.thread.start()

    def _run(self):
        from angerona.core.engine_transport import EngineError, create_private_file

        kept = 0
        try:
            descriptor = create_private_file(self.path)
            try:
                # Keep unambiguous ownership even if fdopen fails: closefd=False
                # leaves this exact descriptor with this owner until finally.
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    while True:
                        raw = self.stream.read(8192)
                        if not raw:
                            break
                        count = min(len(raw), MAX_LOG_BYTES - kept)
                        if count:
                            output.write(raw[:count]); output.flush(); kept += count
                        self.dropped += len(raw) - count
            finally:
                os.close(descriptor)
        except (OSError, ValueError, EngineError) as exc:
            self.error = type(exc).__name__
            # Drain after a failed optional sink so a live producer cannot block.
            try:
                while raw := self.stream.read(8192):
                    self.dropped += len(raw)
            except (OSError, ValueError):
                pass
        finally:
            self.stream.close()

    def finish(self):
        self.thread.join(5)
        if self.thread.is_alive():
            raise ToolError("Scanner output-reader retirement remains unresolved.")


class CuratedToolService:
    """One optional scanner job; construction performs no I/O."""
    def __init__(self, root: Path | None = None, *, cfg=None, bundle: Path | None = None):
        self._configured_root, self.cfg, self._bundle_override = root, cfg, bundle
        self._operations: set[ToolOperation] = set()
        self._lock = threading.Lock()
        self._resource = {}
        self._retained_allowances = {}
        self._job_states = {}
        self._closed = False

    def _root(self) -> Path:
        return _absolute(Path(self._configured_root) if self._configured_root is not None else data_dir() / "curated-tools")

    def _bundle(self) -> Path:
        return _absolute(self._bundle_override if self._bundle_override is not None else resource_root() / "assets" / "integrations" / "zero_breach")

    def _limit(self, name, default, minimum, maximum):
        value = getattr(self.cfg, "github_tools_" + name, default)
        return min(maximum, max(minimum, value)) if type(value) is int else default

    def _enabled(self):
        return getattr(self.cfg, "github_tools_enabled", True) is True

    def resource_snapshot(self) -> dict:
        with self._lock:
            return dict(self._resource, native_custody_held=True) if _HELD_CUSTODY else dict(self._resource)

    def cancel_all(self) -> None:
        with self._lock:
            for operation in self._operations:
                operation.cancel()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for operation in self._operations:
                operation.cancel()

    def wait_for_shutdown(self, timeout=5) -> bool:
        """Call off Qt; completion requires native custody as well as workers."""
        deadline = time.monotonic() + max(0.0, min(30.0, float(timeout)))
        while True:
            with self._lock:
                active = bool(self._operations)
            if not active:
                return not bool(_HELD_CUSTODY)
            if time.monotonic() >= deadline:
                return False
            time.sleep(.02)

    @contextmanager
    def _transaction(self, operation):
        if type(operation) is not ToolOperation:
            raise ValueError("Use an actual tool operation owner.")
        if not _SINGLE_JOB.acquire(blocking=False):
            raise ToolError("Another curated-tool operation is active.")
        try:
            with self._lock:
                if self._closed:
                    raise ToolCancelled("Curated-tool controller has stopped.")
                self._operations.add(operation)
            if _HELD_CUSTODY:
                raise ToolError("A previous scanner's exact native retirement remains unresolved; its custody is retained.")
            operation.check()
            root = self._root()
            _private(root)
            with _hold_plain_directories(root), ExclusiveFileLease(root / "curated-tools.lock"):
                yield root
        finally:
            with self._lock:
                self._operations.discard(operation)
            _SINGLE_JOB.release()

    def _engine(self, root):
        return root / "engines" / ZERO_BREACH["version"] / "engine.py"

    def _verify_installed(self, root):
        destination = self._engine(root).parent
        marker = _json(_read(destination / "prepared.json", 4096, private=True))
        if marker != {"schema": 1, "version": ZERO_BREACH["version"], "sha256": ZERO_BREACH["sha256"]}:
            raise ToolError("The scanner preparation record is incomplete.")
        with ExitStack() as stack:
            _sealed_engine(stack, destination / "engine.py")
        catalog = _catalog(self._bundle())
        for item in catalog["files"]:
            raw = _read(destination / item["path"], item["bytes"], private=True)
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ToolError("A prepared scanner or license file changed; the original was preserved.")

    def status(self) -> dict:
        root = self._root()
        state = {"installed": False, "verified": False, "state": "not-installed", "message": "Optional scanner has not been prepared.",
                 "version": ZERO_BREACH["version"], "disk_bytes": 0, "latest_report": None,
                 "resource_usage": self.resource_snapshot(), "admin_state": _admin_state()}
        admin = state["admin_state"]
        state["enabled"] = self._enabled()
        state["execution_available"] = bool(state["enabled"] and admin["verified"] and not admin["elevated"])
        state["execution_hold_reason"] = "" if state["execution_available"] else "A verified ordinary-user worker is required; elevated execution is held."
        if not state["enabled"]:
            state.update(state="disabled", message="Curated scanners are disabled in settings.",
                         execution_hold_reason="Curated scanners are disabled in settings.")
        if _HELD_CUSTODY:
            state.update(state="held", execution_available=False,
                         execution_hold_reason="A previous scanner's exact native retirement remains unresolved; its custody is retained.")
            state["message"] = state["execution_hold_reason"]
        if not root.exists():
            return state
        try:
            _validate_chain(root)
            _rows, state["disk_bytes"] = _inventory(root, byte_limit=self._limit("job_limit_mib", 256, 64, 1024) * 1024**2 + MAX_ENGINE_BYTES)
            engine = self._engine(root)
            state["installed"] = engine.exists()
            if state["installed"]:
                self._verify_installed(root)
                state.update(verified=True, state="ready", message="Reviewed scanner prepared. A scan starts only when requested.")
                if not state["execution_available"]:
                    state.update(state="held", message=state["execution_hold_reason"])
            receipt = root / "latest.json"
            if receipt.exists():
                state["latest_report"] = _json(_read(receipt, 256 * 1024, private=True))
        except (OSError, ValueError, ToolError) as exc:
            state.update(state="needs-review", message=_plain(str(exc), 512))
        return state

    def prepare(self, operation: ToolOperation, progress=lambda _message: None, allow_download=True) -> dict:
        if not self._enabled():
            raise ToolError("Curated scanners are disabled in settings.")
        allow_download = allow_download is True and getattr(self.cfg, "github_tools_allow_download", True) is True
        with self._transaction(operation) as root:
            progress("Verifying the bundled scanner and its license notices…")
            catalog = _catalog(self._bundle())
            engines = root / "engines"
            _private(engines)
            rows, _total = _inventory(engines, limit=128, byte_limit=MAX_ENGINE_BYTES)
            preserved = root / "preserved"
            preserved_size = 0
            if preserved.exists():
                _preserved_rows, preserved_size = _inventory(preserved, limit=128, byte_limit=MAX_ENGINE_BYTES)
                preserved_roots = [path for path, _info in _preserved_rows if path.parent == preserved]
                if len(preserved_roots) > 1 or any(not _HEX.fullmatch(path.name) or not path.is_dir() for path in preserved_roots):
                    raise ToolError("Unknown preserved tool data requires review before preparation.")
                if _total + preserved_size > MAX_ENGINE_BYTES:
                    raise ToolError("The two-version managed scanner cache reached its byte limit.")
            versions = [path for path, _info in rows if path.parent == engines]
            if any(path.name not in {ZERO_BREACH["version"]} for path in versions):
                raise ToolError("Unknown or previous tool files are preserved; review them before preparing another version.")
            destination = engines / ZERO_BREACH["version"]
            if destination.exists():
                expected = {item["path"]: item for item in catalog["files"]}
                existing, _size = _inventory(destination, limit=128, byte_limit=MAX_ENGINE_BYTES)
                for path, info in existing:
                    if stat.S_ISDIR(info.st_mode):
                        continue
                    name = path.relative_to(destination).as_posix()
                    if name == "prepared.json":
                        continue
                    if name not in expected:
                        raise ToolError("Unknown scanner files were preserved; review them before preparation.")
                    raw = _read(path, expected[name]["bytes"], private=True)
                    if len(raw) != expected[name]["bytes"] or hashlib.sha256(raw).hexdigest() != expected[name]["sha256"]:
                        raise ToolError("An edited scanner file was preserved. Revert or review it before restoration.")
            if shutil.disk_usage(root).free < 64 * 1024**2:
                raise ToolError("Optional scanner preparation needs 64 MiB free; dashboard startup is unaffected.")
            contents = []
            for item in catalog["files"]:
                operation.check()
                try:
                    raw = _read(self._bundle() / item["path"], item["bytes"])
                    if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                        raise ToolError("Bundled tool file checksum changed.")
                except FileNotFoundError:
                    if not allow_download:
                        raise ToolError("The bundled tool is unavailable and optional downloads are disabled.") from None
                    progress("Downloading the exact reviewed release file…")
                    raw = _download(item, operation)
                contents.append((item["path"], raw))
            if sum(len(raw) for _name, raw in contents) > MAX_ENGINE_BYTES:
                raise ToolError("The curated bundle exceeds its cache budget.")
            new_bytes = sum(len(raw) for name, raw in contents if not (destination / name).exists())
            if _total + preserved_size + new_bytes + 4096 > MAX_ENGINE_BYTES:
                raise ToolError("The two-version managed scanner cache reached its byte limit.")
            _private(destination)
            for name, raw in contents:
                target = destination / name
                _private(target.parent)
                operation.check()
                if not target.exists():
                    _atomic_bytes_write(target, raw, root=root)
            operation.check()
            with ExitStack() as stack:
                _sealed_engine(stack, destination / "engine.py")
            marker = json.dumps({"schema": 1, "version": ZERO_BREACH["version"], "sha256": ZERO_BREACH["sha256"]}).encode()
            _atomic_bytes_write(destination / "prepared.json", marker, root=root)
            return self.status()

    def _new_job(self, root):
        jobs = root / "jobs"
        _private(jobs)
        rows, total = _inventory(jobs, byte_limit=self._limit("report_limit_mib", 64, 8, 256) * 1024**2)
        roots = [path for path, _info in rows if path.parent == jobs]
        if len(roots) >= MAX_REPORTS or any(not _HEX.fullmatch(path.name) or not path.is_dir() for path in roots):
            raise ToolError("Retained scanner jobs reached their limit. Review or export them before another scan; nothing was deleted.")
        if total + 1024**2 > self._limit("report_limit_mib", 64, 8, 256) * 1024**2:
            raise ToolError("Retained scanner reports reached their aggregate storage limit.")
        remaining = self._limit("report_limit_mib", 64, 8, 256) * 1024**2 - total
        if remaining < 5 * 1024**2:
            raise ToolError("Retained scanner reports need review before another bounded output set can be admitted.")
        job = jobs / uuid.uuid4().hex
        _validate_chain(job.parent)
        if not private_directory(job, create=True):
            raise ToolError("A fresh private scanner job could not be created exclusively.")
        state = self._job_states[job.name] = _JobState()
        try:
            for name in ("", "scratch", "cache", "profile", "profile/local", "profile/roaming", "profile/config"):
                path = job / name
                if name:
                    _private(path)
                info = path.lstat()
                state.directories[path] = _windows_node(path) if os.name == "nt" else (info.st_dev, info.st_ino)
            self._retained_allowances[job.name] = remaining
        except BaseException as exc:
            self._finalize_failed_job(root, job, exc)
            self._job_states.pop(job.name, None)
            raise
        return job

    @contextmanager
    def _owned_job(self, root, operation):
        # Reject an absent/edited installation before consuming a report slot.
        # The runner repeats verification and holds its seals through launch.
        operation.check()
        self._verify_installed(root)
        operation.check()
        job = self._new_job(root)
        try:
            yield job
        except BaseException as exc:
            self._finalize_failed_job(root, job, exc)
            raise
        finally:
            self._job_states.pop(job.name, None)
            self._retained_allowances.pop(job.name, None)

    def _retire_never_started_job(self, job, state):
        """Retire only this attempt's unchanged files and empty known dirs."""
        if job not in state.directories:
            raise ToolError("The never-started job directory lacks its creation identity.")
        rows, _size = _inventory(job, byte_limit=MAX_ENGINE_BYTES)
        if any(path not in state.directories and path not in state.files for path, _info in rows):
            raise ToolError("Unexpected never-started job data was preserved for review.")
        with ExitStack() as seals:
            files = []
            for path, record in state.files.items():
                held = seals.enter_context(_ReportDeletion(path, record["bytes"]))
                if hashlib.sha256(held.raw).hexdigest() != record["sha256"]:
                    raise ToolError("An edited never-started job request was preserved.")
                files.append(held)
            for path, identity in state.directories.items():
                info = path.lstat()
                observed = _windows_node(path) if os.name == "nt" else (info.st_dev, info.st_ino)
                if not stat.S_ISDIR(info.st_mode) or observed != identity:
                    raise ToolError("A never-started job directory changed; it was preserved.")
            for held in files:
                held.check()
            for held in files:
                held.delete()
        for path, identity in sorted(state.directories.items(), key=lambda row: len(row[0].parts), reverse=True):
            with _hold_plain_directories(path.parent):
                if os.name == "nt":
                    _windows_node(path, identity, delete=True)
                else:
                    info = path.lstat()
                    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                        raise ToolError("A never-started job directory changed; it was preserved.")
                    path.rmdir()

    def _finalize_failed_job(self, root, job, exc):
        """Record failure without mistaking task failure for native retirement."""
        state = self._job_states[job.name]
        result = dict(state.outcome, state="not-started" if not state.native_started else "incomplete",
                      message="Scanner attempt failed; no complete scan verdict was accepted.",
                      details=_plain(str(exc), 1024), coverage="Not scanned." if not state.native_started else "Incomplete.",
                      findings=[], native_started=state.native_started,
                      native_retired=state.native_state in {"not-started", "retired"},
                      job_id=job.name, tool=dict(ZERO_BREACH), created_at=time.time(),
                      authority="External scanner leads only; no automatic trust, response or baseline changes.")
        if state.native_state == "retired":
            try:
                self._save(root, job, result)
                return
            except (OSError, ValueError, ToolError):
                result["message"] = "Retired scanner output requires storage review; existing data was preserved."
        elif state.native_state == "not-started":
            try:
                self._retire_never_started_job(job, state)
                result["job_retained"] = False
            except (OSError, ValueError, ToolError):
                result.update(job_retained=True, message="Never-started scanner data changed or needs storage review; it was preserved.")
        else:
            result.update(state="held", coverage="Incomplete; native launch or retirement is unresolved.",
                          message="Scanner native retirement is unresolved; all job data and custody are preserved.")
        # A removed never-started job leaves one bounded last-attempt record,
        # rather than consuming one of the eight retained scan report slots.
        raw = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()
        try:
            if job.exists():
                _atomic_bytes_write(job / "receipt.json", raw, root=root)
            _atomic_bytes_write(root / "latest.json", raw, root=root)
        except (OSError, ValueError, ToolError):
            # Preserve the original failure and custody. A full/unavailable
            # volume can also prevent diagnostics from being persisted.
            pass

    def _preflight_scan(self, root):
        if not self._enabled():
            raise ToolError("Curated scanners are disabled in settings.")
        _require_user()
        self._python()
        if shutil.disk_usage(root).free < (3 * 1024**3 + self._limit("job_limit_mib", 256, 64, 1024) * 1024**2):
            raise ToolError("Optional scanner work needs 3 GiB plus its working allowance free. Dashboard startup is unaffected.")

    def _environment(self, job, *, metadata_only=False):
        from angerona.core.privilege import sanitized_child_environment
        environment = sanitized_child_environment(source=os.environ)
        for key in tuple(environment):
            if key.startswith("ANGERONA_"):
                del environment[key]
        environment.update(TEMP=str(job / "scratch"), TMP=str(job / "scratch"), TMPDIR=str(job / "scratch"),
                           PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTHONUTF8="1")
        if metadata_only:
            environment.update(HOME=str(job / "profile"), USERPROFILE=str(job / "profile"),
                               LOCALAPPDATA=str(job / "profile/local"), APPDATA=str(job / "profile/roaming"),
                               XDG_CONFIG_HOME=str(job / "profile/config"))
        return environment

    def _python(self):
        image = _absolute(Path(sys.executable if getattr(sys, "frozen", False) else getattr(sys, "_base_executable", sys.executable)))
        _validate_chain(image)
        return image

    def _command(self, image, request_path):
        if getattr(sys, "frozen", False):
            return [str(image), "--curated-tool-worker", str(request_path)]
        source_root = str(Path(__file__).resolve().parents[2])
        bootstrap = "import sys;sys.path.insert(0," + repr(source_root) + ");from angerona.core.curated_tool_worker import main;raise SystemExit(main(sys.argv[1:]))"
        return [str(image), "-I", "-S", "-B", "-X", "utf8", "-c", bootstrap, str(request_path)]

    def _run(self, engine, args, job, operation, request, *, metadata_only=False, interactive=False):
        _require_user()
        image = self._python()
        # A bursty upstream snapshot can otherwise exceed the monitored limit
        # before the next poll. Reserve optional scan working capacity and also
        # apply a conservative bounded Python writer/copy shim in the child.
        if shutil.disk_usage(job).free < (3 * 1024**3 + self._limit("job_limit_mib", 256, 64, 1024) * 1024**2):
            raise ToolError("Optional scanner work needs 3 GiB plus its working allowance free. Dashboard startup is unaffected.")
        nonce = secrets.token_hex(32)
        document = dict(schema=1, job_id=job.name, version=ZERO_BREACH["version"], engine_sha256=ZERO_BREACH["sha256"],
                        nonce=nonce, parent_pid=os.getpid(), parent_birth=_windows_birth(None) if os.name == "nt" else "",
                        kind="interactive" if interactive else "describe" if metadata_only else "scan",
                        request=asdict(request), limits={"working_bytes": self._limit("job_limit_mib", 256, 64, 1024) * 1024**2,
                                                       "retained_bytes": self._retained_allowances.get(job.name, 8 * 1024**2),
                                                       "cpu_seconds": min(900, max(1, int(operation.deadline - time.monotonic())))})
        request_path = job / "request.json"
        request_raw = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()
        if len(request_raw) > 64 * 1024:
            raise ToolError("Curated scanner launch request exceeds its bound.")
        _atomic_bytes_write(request_path, request_raw, root=self._root())
        state = self._job_states[job.name]
        state.files[request_path] = {"bytes": len(request_raw), "sha256": hashlib.sha256(request_raw).hexdigest()}
        command = self._command(image, request_path)
        env = self._environment(job, metadata_only=metadata_only or request.phone or request.mode == "targeted")
        if os.name != "nt" and not all(hasattr(os, key) for key in ("waitid", "WNOWAIT", "WEXITED")):
            raise ToolError("This platform cannot retain unreaped process-group identity for the scanner.")
        kwargs = dict(cwd=job, env=env, stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      close_fds=True, bufsize=0)
        if os.name == "nt":
            kwargs["creationflags"] = 0x4 | (0x10 if interactive else 0x08000000) | 0x200
        else:
            if interactive:
                raise ToolError("Open the pinned toolkit from a private terminal on this platform; automatic terminal selection is unavailable.")
            kwargs["start_new_session"] = True
        process = None
        job_owner = None
        pumps = []
        reason, gap = "complete", ""
        native_generations, native_observation_gaps = [], 0
        started = time.monotonic()
        last_cpu = (started, 0.0)
        with ExitStack() as seals:
            self._verify_installed(self._root())
            _sealed_engine(seals, engine)
            seals.enter_context(_open_sealed(request_path))
            seals.enter_context(_hold_plain_directories(image.parent))
            seals.enter_context(_open_sealed(image))
            try:
                operation.check()
                try:
                    process = subprocess.Popen(command, **kwargs)
                except (OSError, ValueError, subprocess.SubprocessError):
                    # A failed stdlib constructor did not return a native
                    # process generation to this owner.
                    raise
                except BaseException:
                    state.native_started, state.native_state = None, "unresolved"
                    _HELD_CUSTODY.append((None, None, pumps, seals.pop_all()))
                    raise
                state.native_started, state.native_state = True, "active"
                if os.name == "nt":
                    job_owner = _WindowsJob(process, request)
                    from angerona.resilience._selftest_environment import _resume_windows_process
                    operation.check()
                    _resume_windows_process(process)
                pumps = [_OutputPump(process.stdout, job / "stdout.log"), _OutputPump(process.stderr, job / "stderr.log")]
                handshake = dict(nonce=nonce, pid=process.pid, birth=job_owner.birth if job_owner else "",
                                 request_sha256=hashlib.sha256(request_raw).hexdigest())
                operation.check()
                process.stdin.write(json.dumps(handshake, ensure_ascii=True).encode() + b"\n")
                process.stdin.flush(); process.stdin.close()
                while True:
                    try:
                        operation.check()
                        _rows, used = _inventory(job, byte_limit=self._limit("job_limit_mib", 256, 64, 1024) * 1024**2)
                        if job_owner is not None:
                            exited = process.poll() is not None
                            try:
                                sample = job_owner.resource(process)
                            except (OSError, ValueError, TypeError):
                                sample = {"cpu_time": last_cpu[1], "rss_mib": None,
                                          "resource_gap": "Owned job resource sample unavailable."}
                        else:
                            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
                            sample = {"cpu_time": None, "rss_mib": None, "read_bytes": None, "write_bytes": None,
                                      "priority": "unavailable", "requested_priority": request.priority,
                                      "resource_gap": "POSIX child limits are per process; aggregate CPU rate and scheduling priority are not attested."}
                            try:
                                import psutil
                                observed = psutil.Process(process.pid)
                                times = observed.cpu_times()
                                sample.update(cpu_time=times.user + times.system, rss_mib=observed.memory_info().rss / 1024**2,
                                              priority=f"nice {observed.nice()}")
                            except Exception:
                                pass
                        now = time.monotonic()
                        cpu_time = sample.pop("cpu_time", None)
                        sample.update(cpu_percent=None if cpu_time is None else max(0, (cpu_time - last_cpu[1]) / max(.01, now - last_cpu[0]) * 100),
                                      pid=process.pid, creation_filetime=job_owner.birth if job_owner else "",
                                      elapsed=round(now - started, 2), priority=sample.get("priority", request.priority),
                                      admin_state="ordinary-user", working_bytes=used, process_alive=not exited)
                        if cpu_time is not None:
                            last_cpu = (now, cpu_time)
                        with self._lock:
                            self._resource = sample
                        if exited:
                            break
                    except ToolCancelled as exc:
                        reason, gap = "cancelled", str(exc)
                        break
                    except (OSError, ValueError, ToolError) as exc:
                        reason, gap = "incomplete", _plain(str(exc), 512)
                        break
                    operation.cancelled.wait(1.0)
            finally:
                if process is not None:
                    try:
                        if os.name == "nt" and job_owner is not None:
                            job_owner.terminate()
                            job_owner.wait_empty()
                            process.wait(timeout=5)
                            native_generations = job_owner.receipt()
                            native_observation_gaps = job_owner.observation_gaps
                            job_owner.close()
                        elif os.name == "nt":
                            # A failed assignment leaves only the exact
                            # retained, never-resumed process.
                            process.kill()
                            process.wait(timeout=5)
                        else:
                            # Keep the unreaped session leader pinned until
                            # its exact process group receives retirement.
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait(timeout=5)
                        for pump in pumps:
                            pump.finish()
                    except BaseException:
                        state.native_state = "unresolved"
                        # Every platform/error branch retains its kernel
                        # witnesses and seals until retirement is resolved.
                        _HELD_CUSTODY.append((job_owner, process, pumps, seals.pop_all()))
                        raise
                    state.native_state = "retired"
                    with self._lock:
                        self._resource = dict(self._resource, process_alive=False, cpu_percent=0.0,
                                              state="stopped", retirement="Exact owned process tree retired.")
        outcome = {"exit_code": process.returncode, "state": reason, "gap": gap, "native_started": True,
                   "output_dropped": sum(pump.dropped for pump in pumps),
                   "output_errors": [pump.error for pump in pumps if pump.error],
                   "native_retired": True, "native_generations": native_generations,
                   "native_observation_gaps": native_observation_gaps,
                   "resource_usage": self.resource_snapshot()}
        state.outcome = outcome
        return outcome

    def _save(self, root, job, result):
        cleanup = []
        for name in ("scratch", "cache", "profile"):
            path = job / name
            if path.exists():
                try:
                    cleanup.append(_retire_owned_tree(path, job=job))
                except (OSError, ValueError, ToolError):
                    cleanup.append({"retained_entries": 1, "reason": "Generated scratch requires storage review."})
        retained_files = {}
        for name in _REPORT_NAMES - {"receipt.json"}:
            path = job / name
            if not path.exists():
                continue
            limit = {"report.json": MAX_JSON_BYTES, "report.txt": MAX_TEXT_BYTES,
                     "summary.json": MAX_SUMMARY_BYTES, "request.json": 64 * 1024}.get(name, MAX_LOG_BYTES)
            try:
                raw_file = _read(path, limit, private=True)
                retained_files[name] = {"bytes": len(raw_file), "sha256": hashlib.sha256(raw_file).hexdigest()}
            except (OSError, ValueError, ToolError):
                result = dict(result, state="incomplete", message="Scanner output requires storage review; its existing data was preserved.")
        result = dict(result, job_id=job.name, tool=dict(ZERO_BREACH), created_at=time.time(),
                      retained_files=retained_files, cleanup=cleanup,
                      authority="External scanner leads only; no automatic trust, response or baseline changes.")
        raw = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > 256 * 1024:
            raise ToolError("The scanner receipt exceeds its bounded display schema.")
        _atomic_bytes_write(job / "receipt.json", raw, root=root)
        _atomic_bytes_write(root / "latest.json", raw, root=root)
        self._retained_allowances.pop(job.name, None)
        return result

    def clear_reports(self, operation: ToolOperation, progress=lambda _message: None):
        """Explicit cleanup of unchanged recorded outputs, never source inputs."""
        with self._transaction(operation) as root:
            jobs = root / "jobs"
            if not jobs.exists():
                return {"state": "complete", "message": "No managed scanner reports to delete."}
            rows, _total = _inventory(jobs, byte_limit=1024**3)
            candidates = [path for path, _info in rows if path.parent == jobs]
            if len(candidates) > MAX_REPORTS or any(not _HEX.fullmatch(path.name) or not path.is_dir() for path in candidates):
                raise ToolError("Unknown scanner directories were preserved for review.")
            removed, retained = 0, 0
            for job in candidates:
                operation.check()
                progress("Checking recorded scanner report identities before deletion…")
                try:
                    with ExitStack() as seals:
                        receipt_file = seals.enter_context(_ReportDeletion(job / "receipt.json", 256 * 1024))
                        receipt_raw = receipt_file.raw
                        receipt = _json(receipt_raw)
                        if receipt.get("job_id") != job.name or receipt.get("native_retired") is not True or type(receipt.get("retained_files")) is not dict:
                            raise ToolError("Scanner retirement record is incomplete.")
                        for name in ("scratch", "cache", "profile"):
                            if (job / name).exists():
                                result = _retire_owned_tree(job / name, job=job)
                                if result["retained_entries"]:
                                    raise ToolError("Generated scratch has retained entries.")
                        files = list(job.iterdir())
                        expected = receipt["retained_files"]
                        if any(path.name not in _REPORT_NAMES for path in files) or set(path.name for path in files) != set(expected) | {"receipt.json"}:
                            raise ToolError("Unknown scanner outputs were preserved.")
                        planned = []
                        for name, record in sorted(expected.items()):
                            if name not in _REPORT_NAMES or name == "receipt.json" or type(record) is not dict or type(record.get("bytes")) is not int or not 0 <= record["bytes"] <= MAX_TEXT_BYTES:
                                raise ToolError("Scanner output inventory is invalid.")
                            held = seals.enter_context(_ReportDeletion(job / name, record["bytes"]))
                            if hashlib.sha256(held.raw).hexdigest() != record.get("sha256"):
                                raise ToolError("An edited scanner output was preserved.")
                            planned.append(held)
                        latest_file = None
                        latest = root / "latest.json"
                        if latest.exists():
                            latest_file = seals.enter_context(_ReportDeletion(latest, 256 * 1024))
                            if latest_file.raw != receipt_raw:
                                latest_file = None
                        for held in [*planned, receipt_file]:
                            held.check()
                        for held in planned:
                            held.delete()
                        receipt_file.delete()
                        if latest_file is not None:
                            latest_file.delete()
                    job.rmdir()
                    removed += 1
                except (OSError, ValueError, KeyError, ToolError):
                    retained += 1
            return {"state": "complete" if not retained else "needs-review", "message": f"Deleted {removed} unchanged managed report sets; preserved {retained} sets requiring review.",
                    "removed_reports": removed, "retained_reports": retained}

    def scan(self, request: ToolScanRequest, operation: ToolOperation, progress=lambda _message: None):
        with self._transaction(operation) as root:
            self._preflight_scan(root)
            _request_arguments(request, root / "jobs" / ("0" * 32))
            with self._owned_job(root, operation) as job:
                args = _request_arguments(request, job)
                progress("Running the pinned scanner against the selected local evidence…")
                outcome = self._run(self._engine(root), args, job, operation, request)
                if request.preview:
                    raw = _read(job / "stdout.log", MAX_LOG_BYTES, private=True)
                    try:
                        preview = _json(raw)
                        details = json.dumps(preview, ensure_ascii=True)[:32000]
                    except (ValueError, TypeError):
                        details = "The scanner did not return a valid bounded preview."
                    return self._save(root, job, dict(outcome, message="Scope preview only; no scan verdict.", details=details,
                                                      coverage="Not scanned.", findings=[], report=None, state="preview"))
                result = _validate_report(job, outcome)
                return self._save(root, job, result)

    def self_test(self, operation: ToolOperation, progress=lambda _message: None):
        with self._transaction(operation) as root:
            self._preflight_scan(root)
            with self._owned_job(root, operation) as job:
                progress("Checking the pinned engine's metadata in a private synthetic profile…")
                outcome = self._run(self._engine(root), ["--describe", "--no-pause"], job, operation,
                                    ToolScanRequest(priority="normal"), metadata_only=True)
                document = _json(_read(job / "stdout.log", MAX_LOG_BYTES, private=True))
                valid = (type(document) is dict and document.get("schema_version") == "1.6"
                         and type(document.get("tool")) is dict and document["tool"].get("version") in _UPSTREAM_VERSIONS)
                if outcome["exit_code"] != 0 or outcome["state"] != "complete" or not valid:
                    raise ToolError("The pinned scanner did not return its expected metadata contract.")
                return self._save(root, job, dict(outcome, state="verified", message="Pinned scanner metadata verified; no host scan was run.",
                                                  details="Verified schema 1.6 and toolkit version 0.1.10 in a synthetic profile.", coverage="Not scanned.", findings=[]))

    def open_tool(self, operation: ToolOperation, progress=lambda _message: None):
        operation.check()
        progress("Reviewing advanced toolkit availability…")
        return {"state": "held", "message": "Advanced interactive execution needs separately reviewed dependency and acquisition adapters.",
                "details": "The full pinned toolkit source and credits are available. Its menus can install optional packages, download collectors or change device state. "
                           "Angerona does not run those actions in its Core/base Python environment. Use the official standalone project in a separate environment; "
                           "native fixed-scope read-only checks remain available.",
                "url": ZERO_BREACH["repository"], "coverage": "Not scanned.", "findings": []}

    def revert(self, operation: ToolOperation, progress=lambda _message: None):
        with self._transaction(operation) as root:
            progress("Retiring only the exact verified managed scanner files…")
            destination = self._engine(root).parent
            if not destination.exists():
                return self.status()
            catalog = _catalog(self._bundle())
            expected = {item["path"]: item for item in catalog["files"]}
            known_directories = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents if parent.as_posix() != "."}
            rows, _size = _inventory(destination, limit=128, byte_limit=MAX_ENGINE_BYTES)
            native_plan = {}
            changed = False
            for path, info in rows:
                if os.name == "nt":
                    native_plan[path] = _windows_node(path)
                if stat.S_ISDIR(info.st_mode):
                    if path.relative_to(destination).as_posix() not in known_directories:
                        changed = True
                    continue
                name = path.relative_to(destination).as_posix()
                if name == "prepared.json":
                    try:
                        marker = _json(_read(path, 4096, private=True))
                    except (OSError, ValueError, ToolError):
                        marker = None
                    if marker != {"schema": 1, "version": ZERO_BREACH["version"], "sha256": ZERO_BREACH["sha256"]}:
                        changed = True
                    continue
                if name not in expected or hashlib.sha256(_read(path, MAX_ENGINE_BYTES, private=True)).hexdigest() != expected[name]["sha256"]:
                    changed = True
            if changed:
                preserved = root / "preserved"
                _private(preserved)
                prior, prior_size = _inventory(preserved, limit=128, byte_limit=MAX_ENGINE_BYTES)
                if prior or prior_size + _size > MAX_ENGINE_BYTES:
                    raise ToolError("A previous modified scanner copy is preserved; review it before another Revert.")
                target = preserved / uuid.uuid4().hex
                if not target.is_relative_to(root) or not destination.is_relative_to(root):
                    raise ToolError("Scanner preservation left its fixed managed root.")
                source_identity = (destination.stat().st_dev, destination.stat().st_ino)
                with _hold_plain_directories(destination.parent, preserved):
                    if (destination.stat().st_dev, destination.stat().st_ino) != source_identity:
                        raise ToolError("Scanner preservation identity changed.")
                    os.rename(destination, target)
                    if (target.stat().st_dev, target.stat().st_ino) != source_identity:
                        raise ToolError("Scanner preservation outcome requires review.")
                return dict(self.status(), state="reverted", preserved_path=str(target),
                            message="Modified scanner files were preserved; the active managed scanner was removed. Preferences and reports remain.")
            for path, info in sorted(rows, key=lambda row: len(row[0].parts), reverse=True):
                operation.check()
                current = path.lstat()
                same = ((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
                        if stat.S_ISDIR(info.st_mode) else _identity(current) == _identity(info))
                if not same:
                    raise ToolError("A managed tool entry changed during Revert; remaining files were preserved.")
                if stat.S_ISDIR(info.st_mode):
                    with _hold_plain_directories(path.parent):
                        _windows_node(path, native_plan[path], delete=True) if os.name == "nt" else path.rmdir()
                else:
                    with _hold_plain_directories(path.parent):
                        if _identity(path.lstat()) != _identity(info):
                            raise ToolError("A managed tool entry changed before retirement.")
                        if os.name == "nt":
                            _windows_node(path, native_plan[path], delete=True)
                        else:
                            path.unlink()
            destination.rmdir()
            return dict(self.status(), state="reverted", message="Managed scanner removed. Angerona preferences and scanner reports were preserved.")


def _validate_report(job: Path, outcome: dict) -> dict:
    gap = outcome.get("gap", "")
    base = dict(outcome, state="incomplete", message="Scanner coverage is incomplete.", findings=[], coverage=[], report=str(job / "report.json"))
    if outcome.get("state") != "complete":
        return dict(base, state="cancelled" if outcome.get("state") == "cancelled" else "incomplete",
                    message="Scanner stopped; coverage is incomplete.",
                    details=gap or "Scanner was stopped before a complete report was accepted.")
    if outcome.get("exit_code") == 4:
        return dict(base, state="not-scanned", message="Toolkit closed without a scan.", details="No scan verdict was accepted.")
    try:
        raw = _read(job / "report.json", MAX_JSON_BYTES, private=True)
        document = _json(raw)
    except (OSError, ValueError, ToolError):
        return dict(base, state="error", message="Scanner did not return a valid bounded private report.", details="No scan verdict was accepted.")
    if (type(document) is not dict or document.get("schema_version") != "1.6"
            or type(document.get("tool")) is not dict or document["tool"].get("name") != "zero-breach-toolkit"
            or document["tool"].get("version") not in _UPSTREAM_VERSIONS):
        return dict(base, state="error", message="Scanner report identity or schema does not match the pinned adapter.", details="No scan verdict was accepted.")
    scope, verdict = document.get("scope"), document.get("verdict")
    if (type(scope) is not dict or scope.get("scanned") is not True
            or document.get("scan_state") not in {"completed", "partial"} or type(verdict) is not dict):
        return dict(base, details="Scanner reported an interrupted or unperformed scan; coverage remains incomplete.")
    modules = document.get("modules")
    if type(modules) is not dict or len(modules) > 128:
        return dict(base, state="error", details="Scanner module schema exceeded its bounds.")
    counts = [verdict.get(name) for name in ("hits_total", "findings_total", "references_total", "withdrawn_total")]
    if any(type(value) is not int or not 0 <= value <= 4000 for value in counts):
        return dict(base, state="error", details="Scanner verdict counts are invalid.")
    hits = []
    for module_name, module in modules.items():
        if type(module_name) is not str or type(module) is not dict or type(module.get("hits", [])) is not list:
            return dict(base, state="error", details="Scanner module findings are invalid.")
        for item in module.get("hits", []):
            if type(item) is not dict:
                return dict(base, state="error", details="Scanner finding schema is invalid.")
            hits.append(dict(item, module=module_name))
            if len(hits) > 4000:
                return dict(base, state="error", details="Scanner finding schema exceeded its bounds.")
    # Never render upstream instructions, HTML, suggested commands or trust
    # decisions. Detail text retains original author attribution on pattern hits.
    display = []
    display_bytes = 0
    for item in hits[:200]:
        if type(item) is dict:
            row = {key: _plain(item.get(key), 4096) for key in
                   ("check", "module", "indicator", "family", "evidence", "detail", "author", "source", "license", "location") if isinstance(item.get(key), str)}
        elif isinstance(item, str):
            row = {"detail": _plain(item, 4096)}
        else:
            continue
        count = len(json.dumps(row, ensure_ascii=True).encode())
        if display_bytes + count > 128 * 1024:
            break
        display_bytes += count
        display.append(row)
    coverage = document.get("coverage", {})
    if type(coverage) is not dict:
        coverage = {}
    gaps = verdict.get("gaps", [])
    has_gaps = bool(gaps or coverage.get("not_checked") or outcome.get("output_dropped") or outcome.get("output_errors")
                    or scope.get("cancelled") is True or document.get("scan_state") == "partial")
    code = outcome.get("exit_code")
    if code == 2 and counts[1] > 0:
        state, message = "findings", "External scanner findings require investigation."
    elif code == 3 or has_gaps:
        state, message = "incomplete", "Scanner returned coverage gaps; a clean result was not established."
    elif code == 0 and counts[1] == 0:
        if counts[3]:
            state, message = "withdrawn", "Scanner reported withdrawn indicators; they are not active findings."
        elif counts[2]:
            state, message = "references", "Scanner reported referenced indicators requiring context; no active finding was established."
        else:
            state, message = "complete", "No known indicators reported within this scan's recorded coverage."
    else:
        state, message = "error", "Scanner ended with an error or inconsistent verdict."
    return dict(base, state=state, message=message, findings=display, display_omitted=max(0, len(hits) - len(display)),
                coverage={"checked": _plain(json.dumps(coverage.get("checked", []), ensure_ascii=True), 8192),
                          "not_checked": _plain(json.dumps(coverage.get("not_checked", []), ensure_ascii=True), 8192)},
                details="A known-indicator check cannot establish that a device is infection-free. "
                        "References, withdrawn items and unavailable collectors remain separate from active findings.")
