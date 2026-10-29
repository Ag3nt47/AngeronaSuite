"""Bounded source-only startup recovery; independent of Angerona imports.

The supervising launcher owns its exclusive repair lease, process-retirement
proof and dashboard readiness receipt. This helper records those explicit
caller assertions; its snapshots are recovery copies, never trust baselines.
"""
from __future__ import annotations

import argparse
import ast
import configparser
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import ssl
import stat
import sys
import time
import urllib.request
import zipfile


CANONICAL = "https://github.com/Ag3nt47/AngeronaSuite.git"
API = "https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/"
CODELOAD = "https://codeload.github.com/Ag3nt47/AngeronaSuite/zip/"
SCRIPT_ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 4096
MAX_ENTRIES = 16384
MAX_FILE = 2 * 1024**2
MAX_BYTES = 64 * 1024**2
MAX_METADATA = 2 * 1024**2
MAX_REPORT = 64 * 1024
MAX_PATH = 240
MIN_FREE = 2 * 1024**3
_HEX = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
OPERATIONAL_SOURCE = frozenset({"src/angerona/startup.py", "src/angerona/core/startup_recovery.py",
                                "src/angerona/core/startup_diagnostics.py"})
STOP_CONTRACT_SOURCE = "src/angerona/resilience/shutdown_token.py"
STOP_CONTRACT_SYMBOL = "OPERATOR_STOP_CONTRACT_VERSION"
MIN_STOP_CONTRACT = 1


class Held(RuntimeError):
    pass


def require_stop_contract(files):
    """Reject known legacy rollback generations; this grants no trust authority."""
    raw = files.get(STOP_CONTRACT_SOURCE)
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
        raise Held("Source candidate predates the required STOP lifecycle contract; preserve edits and use an updated candidate")
    try:
        module = ast.parse(raw, filename=STOP_CONTRACT_SOURCE)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise Held("Source candidate STOP lifecycle contract is unavailable; no legacy restoration was selected") from error
    declarations = []
    for node in module.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id == STOP_CONTRACT_SYMBOL for target in targets):
            declarations.append(node.value)
    if (len(declarations) != 1 or not isinstance(declarations[0], ast.Constant)
            or type(declarations[0].value) is not int or declarations[0].value < MIN_STOP_CONTRACT):
        raise Held("Source candidate predates or ambiguously declares the required STOP lifecycle contract; originals remain preserved")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def allowed(name):
    if not isinstance(name, str) or len(name) > MAX_PATH or "\\" in name or ":" in name:
        return False
    path = PurePosixPath(name)
    return (name not in OPERATIONAL_SOURCE and not path.is_absolute() and ".." not in path.parts and path.suffix == ".py"
            and len(path.parts) >= 3 and path.parts[:2] in {("src", "angerona"), ("src", "srt")}
            and not any(part in {".git", ".tmp", "__pycache__", "external_modules", "external-modules"}
                        for part in path.parts))


def plain(info, directory=False):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
        raise Held("Linked or redirected recovery input is refused")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise Held("A recovery directory is not plain")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Held("Recovery files must be plain single-link regular files")


def absolute(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise Held("An absolute local recovery path is required")
    path = Path(os.path.abspath(path))
    for parent in (*reversed(path.parents), path):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        plain(info, directory=parent != path or stat.S_ISDIR(info.st_mode))
    return path


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


class FileLease:
    def __init__(self, path, *, mutation=False):
        self.path = absolute(path)
        self.fd = -1
        before = self.path.lstat()
        plain(before)
        if os.name == "nt":
            import msvcrt
            from ctypes import wintypes as w
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
            kernel.CreateFileW.restype = w.HANDLE
            kernel.CloseHandle.argtypes = (w.HANDLE,)
            handle = kernel.CreateFileW(str(self.path), 0x80000000 | (0x10000 if mutation else 0),
                                        1, None, 3, 0x00200000, None)
            if handle == w.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                self.fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                kernel.CloseHandle(handle)
                raise
        else:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = os.fstat(self.fd)
            plain(opened)
            if identity(before) != identity(opened) or identity(before) != identity(self.path.lstat()):
                raise Held("Recovery file changed while opening")
            self.initial = identity(opened)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def read(self, limit):
        if self.initial[2] > limit:
            raise Held("Recovery input exceeds its byte limit")
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks, remaining = [], limit + 1
        while remaining:
            part = os.read(self.fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        data = b"".join(chunks)
        named, final = self.path.lstat(), os.fstat(self.fd)
        plain(named)
        plain(final)
        if len(data) > limit or identity(named) != self.initial or identity(final) != self.initial:
            raise Held("Recovery input changed during reading")
        return data

    def information(self, kind, value):
        import msvcrt
        from ctypes import wintypes as w
        setter = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
        setter.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
        setter.restype = w.BOOL
        if not setter(msvcrt.get_osfhandle(self.fd), kind, ctypes.byref(value), ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())

    def rename(self, target):
        target = absolute(target)
        if target.exists():
            raise Held("A concurrent source file appeared before publication")
        if identity(self.path.lstat()) != self.initial:
            raise Held("Source identity changed before publication")
        if os.name == "nt":
            from ctypes import wintypes as w
            encoded = str(target).encode("utf-16-le")
            class Rename(ctypes.Structure):
                _fields_ = [("replace", w.BOOLEAN), ("root", w.HANDLE), ("length", w.DWORD),
                            ("name", ctypes.c_byte * (len(encoded) + 2))]
            value = Rename()
            value.length = len(encoded)
            value.name[:len(encoded)] = encoded
            self.information(3, value)
        else:
            # A no-replace link publishes the retained inode, then retires only
            # its old name. A concurrently created target is never overwritten.
            os.link(self.path, target, follow_symlinks=False)
            if identity(target.lstat()) != self.initial:
                raise Held("Source changed during no-replace publication")
            os.unlink(self.path)
        self.path = target
        if identity(self.path.lstat()) != self.initial:
            raise Held("Published source identity changed")

    def delete(self):
        if identity(self.path.lstat()) != self.initial:
            raise Held("Source backup changed before retirement")
        if os.name == "nt":
            from ctypes import wintypes as w
            class Disposition(ctypes.Structure):
                _fields_ = [("flags", w.DWORD)]
            self.information(21, Disposition(0x11))
        else:
            os.unlink(self.path)


def read(path, limit=MAX_METADATA):
    with FileLease(path) as held:
        return held.read(limit)


def closed_json(raw):
    def pairs(values):
        result = {}
        for name, value in values:
            if name in result:
                raise Held("Duplicate recovery metadata fields")
            result[name] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Held("Recovery metadata is malformed") from error


def _windows_private(path, *, create=False):
    from ctypes import wintypes as w
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    kernel.LocalFree.argtypes = (w.LPVOID,)
    adv.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
    adv.GetTokenInformation.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
    adv.ConvertSidToStringSidW.argtypes = (w.LPVOID, ctypes.POINTER(w.LPWSTR))
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID)
    adv.GetNamedSecurityInfoW.argtypes = (w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(w.LPVOID),
                                        w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID))
    adv.GetNamedSecurityInfoW.restype = w.DWORD
    token, sid_text, descriptor, actual = w.HANDLE(), w.LPWSTR(), w.LPVOID(), w.LPVOID()
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise Held("Cannot establish recovery state ownership")
        size = w.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 0 < size.value < 32768:
            raise Held("Unexpected recovery token metadata")
        user = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, user, size, ctypes.byref(size)):
            raise Held("Cannot inspect recovery state owner")
        user_sid = ctypes.cast(user, ctypes.POINTER(w.LPVOID))[0]
        if not adv.ConvertSidToStringSidW(user_sid, ctypes.byref(sid_text)):
            raise Held("Cannot inspect recovery state SID")
        sid = sid_text.value
        if create:
            sddl = f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
                raise Held("Cannot create private recovery state")
            class Attributes(ctypes.Structure):
                _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]
            attrs = Attributes(ctypes.sizeof(Attributes), descriptor, False)
            kernel.CreateDirectoryW.argtypes = (w.LPCWSTR, ctypes.POINTER(Attributes))
            if not kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)):
                raise ctypes.WinError(ctypes.get_last_error())
        owner, acl = w.LPVOID(), w.LPVOID()
        if adv.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(acl), None,
                                     ctypes.byref(actual)) or not owner or not acl:
            raise Held("Cannot verify private recovery directory")
        owner_text = w.LPWSTR()
        if not adv.ConvertSidToStringSidW(owner, ctypes.byref(owner_text)):
            raise Held("Cannot inspect recovery directory owner")
        try:
            if owner_text.value != sid:
                raise Held("Recovery state belongs to another account")
        finally:
            kernel.LocalFree(owner_text)
        count = ctypes.cast(acl.value + 4, ctypes.POINTER(w.WORD))[0]
        if count != 3:
            raise Held("Recovery state has unexpected access grants")
        seen, offset = set(), 8
        for _ in range(count):
            header = ctypes.string_at(acl.value + offset, 8)
            length = int.from_bytes(header[2:4], "little")
            if header[0] != 0 or header[1] & ~0x13 or int.from_bytes(header[4:8], "little") != 0x1F01FF:
                raise Held("Recovery state is not private")
            value = w.LPWSTR()
            if not adv.ConvertSidToStringSidW(acl.value + offset + 8, ctypes.byref(value)):
                raise Held("Recovery access grant is unavailable")
            try:
                seen.add(value.value)
            finally:
                kernel.LocalFree(value)
            offset += length
        if seen != {sid, "S-1-5-18", "S-1-5-32-544"}:
            raise Held("Recovery state has unrelated access grants")
    finally:
        for value in (sid_text, descriptor, actual):
            if value:
                kernel.LocalFree(value)
        if token:
            kernel.CloseHandle(token)


def private_directory(path):
    path = absolute(path)
    if not path.exists():
        if not path.parent.is_dir():
            raise Held("The recovery state parent must already exist")
        if os.name == "nt":
            _windows_private(path, create=True)
        else:
            path.mkdir(mode=0o700)
    plain(path.lstat(), directory=True)
    if os.name == "nt":
        _windows_private(path)
    elif path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise Held("Recovery state must be owned by this account with mode 0700")
    return path


def state_namespace(path):
    path = absolute(path)
    if path.name != "startup-recovery":
        raise Held("Source recovery state must use its dedicated startup-recovery directory")
    return path


def canonical_root(root):
    root = absolute(root)
    if root != SCRIPT_ROOT:
        raise Held("Recovery must target this fixed source checkout")
    if os.name == "nt" and ctypes.windll.shell32.IsUserAnAdmin():
        raise Held("Source recovery requires an unelevated user session")
    if os.name == "nt":
        from ctypes import wintypes as w
        get_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
        get_type.argtypes, get_type.restype = (w.LPCWSTR,), w.UINT
        if get_type(root.anchor) != 3:
            raise Held("Source recovery requires a fixed local drive")
    parser = configparser.RawConfigParser(strict=True)
    parser.read_string(read(root / ".git" / "config", 512 * 1024).decode("utf-8"))
    if any(section.lower().startswith("include") for section in parser.sections()):
        raise Held("Included Git configuration is not recovery authority")
    if parser.get('remote "origin"', "url", fallback="") != CANONICAL:
        raise Held("The canonical AngeronaSuite HTTPS origin is required")
    if not (root / "src" / "angerona").is_dir():
        raise Held("The first-party source root is unavailable")
    return root


def local_head(root):
    raw = read(root / ".git" / "HEAD", 1024).decode("ascii").strip()
    if _HEX.fullmatch(raw):
        return raw
    if not raw.startswith("ref: refs/") or ".." in raw or "\\" in raw:
        raise Held("Local HEAD is not an exact known Git reference")
    name = raw[5:]
    ref = root / ".git" / name
    if ref.exists():
        value = read(ref, 1024).decode("ascii").strip()
    else:
        value = ""
        for line in read(root / ".git" / "packed-refs", 1024**2).decode("ascii").splitlines():
            if line.startswith(("#", "^")):
                continue
            parts = line.split(" ")
            if len(parts) == 2 and parts[1] == name:
                if value:
                    raise Held("Git HEAD has duplicate packed references")
                value = parts[0]
    if not _HEX.fullmatch(value):
        raise Held("Local HEAD cannot be resolved exactly")
    return value


def inventory(root):
    result, total, visited, folded = {}, 0, 0, set()
    deadline = time.monotonic() + 30
    for prefix in ("src/angerona", "src/srt"):
        start = root / prefix
        if not start.exists():
            if prefix == "src/angerona":
                raise Held("Application source root is missing")
            continue
        pending = [start]
        while pending:
            directory = pending.pop()
            plain(directory.lstat(), directory=True)
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > MAX_ENTRIES or time.monotonic() > deadline:
                        raise Held("Source inventory exceeded its entry or time bound")
                    path = Path(entry.path)
                    name = path.relative_to(root).as_posix()
                    if entry.name in {"__pycache__", "external_modules", "external-modules"}:
                        continue
                    info = path.lstat()
                    if stat.S_ISDIR(info.st_mode):
                        plain(info, directory=True)
                        pending.append(path)
                    elif allowed(name):
                        plain(info)
                        if name.casefold() in folded:
                            raise Held("Source paths collide under Windows case rules")
                        folded.add(name.casefold())
                        data = read(path, MAX_FILE)
                        total += len(data)
                        if len(result) >= MAX_FILES or total > MAX_BYTES:
                            raise Held("Source inventory exceeds its file or byte bound")
                        result[name] = data
    return result


def manifest(files):
    return {name: dict(sha256=sha(data), size=len(data)) for name, data in sorted(files.items())}


def digest(files):
    return sha(json.dumps(manifest(files), sort_keys=True, separators=(",", ":")).encode())


def empty_summary():
    return dict(schema=1, report_id="", pending_decision=False, changed=False,
                changed_files=[], changed_file_count=0, actions=[], action_summary="", strategy="", launch_held=False)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise Held("A recovery download attempted a redirect")


def github_bytes(url, limit):
    if not (url.startswith(API) or url.startswith(CODELOAD)):
        raise Held("A recovery URL escaped the fixed canonical repository")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "Angerona-Source-Recovery",
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    deadline = time.monotonic() + 90
    with opener.open(request, timeout=30) as response:
        if response.status != 200:
            raise Held("The canonical recovery download was not successful")
        pieces, remaining = [], limit + 1
        while remaining:
            if time.monotonic() > deadline:
                raise Held("Recovery download exceeded its elapsed-time bound")
            part = response.read1(min(65536, remaining))
            if not part:
                break
            pieces.append(part)
            remaining -= len(part)
        data = b"".join(pieces)
    if len(data) > limit:
        raise Held("Recovery download exceeds its byte bound")
    return data


def github_candidate(root, strategy, transport=github_bytes):
    revision = local_head(root)
    commit = closed_json(transport(API + "commits/" + revision, MAX_METADATA))
    if commit.get("sha") != revision:
        raise Held("GitHub did not confirm the exact local HEAD")
    if strategy == "github-parent":
        parents = commit.get("parents")
        if not isinstance(parents, list) or not parents or not _HEX.fullmatch(str(parents[0].get("sha", ""))):
            raise Held("An exact canonical parent commit is unavailable")
        revision = parents[0]["sha"]
        commit = closed_json(transport(API + "commits/" + revision, MAX_METADATA))
        if commit.get("sha") != revision:
            raise Held("GitHub parent identity changed")
    tree_id = commit.get("tree", {}).get("sha", "")
    if not _HEX.fullmatch(tree_id):
        raise Held("GitHub commit tree identity is unavailable")
    tree = closed_json(transport(API + "trees/" + tree_id + "?recursive=1", 8 * 1024**2))
    rows = tree.get("tree")
    if tree.get("sha") != tree_id or tree.get("truncated") is not False or not isinstance(rows, list) or len(rows) > MAX_ENTRIES:
        raise Held("GitHub source tree is incomplete or mismatched")
    expected, total, folded = {}, 0, set()
    for row in rows:
        name = row.get("path")
        if allowed(name):
            size = row.get("size")
            if (row.get("type") != "blob" or row.get("mode") not in {"100644", "100755"}
                    or type(size) is not int or not 0 <= size <= MAX_FILE
                    or not _HEX.fullmatch(str(row.get("sha", ""))) or name in expected
                    or name.casefold() in folded):
                raise Held("GitHub source entry is unsafe or duplicated")
            expected[name] = row
            folded.add(name.casefold())
            total += size
    if not expected or len(expected) > MAX_FILES or total > MAX_BYTES:
        raise Held("GitHub source exceeds its bounded coherence scope")
    raw = transport(CODELOAD + revision, MAX_BYTES)
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist()) > MAX_ENTRIES:
            raise Held("GitHub archive exceeds its entry bound")
        for item in archive.infolist():
            parts = PurePosixPath(item.filename).parts
            if (not parts or parts[0] != "AngeronaSuite-" + revision or ".." in parts
                    or "\\" in item.filename or item.filename.startswith("/")):
                raise Held("GitHub archive contains an unexpected path")
            name = "/".join(parts[1:])
            if name in expected:
                mode = item.external_attr >> 16
                if (name in files or item.file_size != expected[name]["size"]
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}):
                    raise Held("GitHub archive source identity is duplicated or changed")
                data = archive.read(item)
                if blob_sha(data) != expected[name]["sha"]:
                    raise Held("GitHub source blob hash did not verify")
                files[name] = data
    if set(files) != set(expected):
        raise Held("GitHub archive did not contain the complete selected source tree")
    return files, revision


class RecoveryStore:
    def __init__(self, root, state_root, *, transport=github_bytes):
        self.root = canonical_root(root)
        self.state = private_directory(state_namespace(state_root))
        if self.state == self.root or self.state.is_relative_to(self.root / "src") or self.state.is_relative_to(self.root / ".git"):
            raise Held("Recovery state must be outside application source and Git metadata")
        self.transport = transport

    @contextlib.contextmanager
    def locked(self):
        path = self.state / "state.lock"
        absolute(path)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            plain(path.lstat()); plain(os.fstat(fd))
            if identity(path.lstat()) != identity(os.fstat(fd)):
                raise Held("Recovery state lock changed identity")
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with os.scandir(self.state) as entries:
                for position, entry in enumerate(entries):
                    if position >= 16:
                        raise Held("Recovery state entry capacity requires review")
                    if entry.name.startswith(".state-"):
                        raise Held("An interrupted recovery metadata publication requires review")
            yield
        finally:
            os.close(fd)

    def load(self, name, default=None):
        path = self.state / name
        return closed_json(read(path)) if os.path.lexists(path) else default

    def write(self, name, value):
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > MAX_METADATA:
            raise Held("Recovery state metadata exceeds its bound")
        target = self.state / name
        absolute(target)
        temporary = self.state / (".state-" + secrets.token_hex(16) + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)

    def archive(self, files, kind):
        if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES:
            raise Held("Recovery capture exceeds its capacity")
        self.capacity(kind)
        self.space(sum(map(len, files.values())) + MAX_METADATA)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest(files), sort_keys=True))
            for name, data in sorted(files.items()):
                archive.writestr(name, data)
        raw = buffer.getvalue()
        if len(raw) > MAX_BYTES:
            raise Held("Recovery archive exceeds its capacity")
        token = secrets.token_hex(16)
        path = self.state / (kind + "-" + token + ".zip")
        with path.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        entry = dict(id=token, file=path.name, sha256=sha(raw), source_digest=digest(files))
        if self.unarchive(entry) != files:
            raise Held("Captured source bytes did not verify")
        return entry

    def space(self, additional=0):
        for directory in (self.state, self.root):
            if shutil.disk_usage(directory).free < MIN_FREE + additional:
                raise Held("Source recovery requires its free-space reserve plus staging capacity")

    def capacity(self, kind):
        counts = {"ready": 0, "failed": 0}
        with os.scandir(self.state) as entries:
            for position, entry in enumerate(entries):
                if position >= 16:
                    raise Held("Recovery state entry capacity requires review")
                match = re.fullmatch(r"(ready|failed)-[0-9a-f]{32}\.zip", entry.name)
                if match:
                    plain(Path(entry.path).lstat())
                    counts[match[1]] += 1
                elif entry.name.startswith(".state-"):
                    raise Held("An interrupted recovery metadata publication requires review")
        if counts[kind] >= (2 if kind == "ready" else 1):
            raise Held("Recovery capture capacity is full; preserved revisions require review")

    def unarchive(self, entry):
        if (not isinstance(entry, dict) or not _ID.fullmatch(str(entry.get("id", "")))
                or entry.get("file") not in {"ready-" + entry["id"] + ".zip", "failed-" + entry["id"] + ".zip"}):
            raise Held("Recovery capture reference is not recognized")
        raw = read(self.state / entry["file"], MAX_BYTES)
        if sha(raw) != entry.get("sha256"):
            raise Held("Recovery capture bytes changed")
        result, total = {}, 0
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if len(archive.infolist()) > MAX_FILES + 1:
                raise Held("Recovery capture exceeds its entry limit")
            metadata = None
            for item in archive.infolist():
                if item.filename == "manifest.json" and metadata is None and item.file_size <= MAX_METADATA:
                    metadata = closed_json(archive.read(item))
                elif allowed(item.filename) and item.filename not in result and item.file_size <= MAX_FILE:
                    data = archive.read(item); total += len(data)
                    if total > MAX_BYTES:
                        raise Held("Recovery capture exceeds its total byte limit")
                    result[item.filename] = data
                else:
                    raise Held("Recovery capture contains unexpected data")
        if metadata != manifest(result) or digest(result) != entry.get("source_digest"):
            raise Held("Recovery capture manifest did not verify")
        return result

    def report(self):
        path = self.state / "report.json"
        value = closed_json(read(path, MAX_REPORT)) if os.path.lexists(path) else {}
        if not isinstance(value, dict):
            raise Held("Recovery report is malformed")
        return value

    def output(self, report):
        raw = json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        while len(raw) > MAX_REPORT - 2048 and report.get("changed_files"):
            report["changed_files"] = report["changed_files"][:-1]
            raw = json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > MAX_REPORT - 2048:
            raise Held("Recovery report exceeds its bound")
        self.write("report.json", report)
        return report

    def guard_pending(self):
        if os.path.lexists(self.state / "transaction.pending.json"):
            raise Held("An interrupted source transaction requires review; preserved bytes and its journal remain intact")

    def progress(self, token, plan_digest, row=None):
        path = self.state / "transaction.progress.jsonl"
        if row is not None:
            raw = json.dumps(dict(row, transaction_id=token, plan_sha256=plan_digest),
                             sort_keys=True, separators=(",", ":")).encode() + b"\n"
            before = path.lstat()
            plain(before)
            if before.st_size + len(raw) > MAX_METADATA:
                raise Held("Source transaction progress exceeds its bound")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
            try:
                if identity(os.fstat(fd)) != identity(before) or identity(path.lstat()) != identity(before):
                    raise Held("Source progress journal changed identity")
                os.write(fd, raw); os.fsync(fd)
            finally:
                os.close(fd)
            return
        rows = []
        for line in read(path).splitlines():
            if len(rows) >= MAX_FILES:
                raise Held("Source progress journal exceeds its row bound")
            value = closed_json(line)
            if value.get("transaction_id") != token or value.get("plan_sha256") != plan_digest:
                raise Held("Source progress journal binding changed")
            rows.append(value)
        return rows

    def snapshot(self, *, ready_observed=False, expected_source_digest=None):
        if not ready_observed:
            raise Held("A genuine dashboard-ready observation must precede snapshot capture")
        self.guard_pending()
        files = inventory(self.root)
        require_stop_contract(files)
        if (not isinstance(expected_source_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_source_digest)
                or digest(files) != expected_source_digest):
            raise Held("Source changed from its pre-launch fingerprint; it cannot be labeled a ready revision")
        index = self.load("index.json", dict(schema=1, ready=[], failed=None))
        if not isinstance(index, dict) or not isinstance(index.get("ready"), list) or len(index["ready"]) > 2:
            raise Held("Recovery snapshot inventory is malformed")
        existing = next((entry for entry in index["ready"] if entry.get("source_digest") == digest(files)), None)
        if existing is not None:
            if self.unarchive(existing) != files:
                raise Held("A retained ready snapshot failed fresh verification")
        else:
            if len(index["ready"]) >= 2:
                raise Held("Two ready snapshots are retained; review capacity before capturing another revision")
            entry = self.archive(files, "ready")
            if inventory(self.root) != files:
                raise Held("An editor changed source during ready capture")
            index["ready"].append(entry)
            self.write("index.json", index)
        report = self.report()
        if report and report.get("working_digest") == digest(files):
            report["phase"] = "ready-confirmed"
            report["message"] = "The parent observed dashboard readiness after source recovery. Protection coverage is evaluated separately."
            report["action_summary"] = "Dashboard readiness confirmed for the recovered source; protection coverage is reported separately."
            if report.get("strategy") == "restore-edits":
                report["pending_decision"] = False
            self.output(report)
        return dict(empty_summary(), **dict(report, outcome="snapshot-recorded", changed=False, snapshot_reused=existing is not None,
                    snapshot_count=len(index["ready"])))

    def _publish(self, current, target, report, index):
        require_stop_contract(target)
        changes = sorted(name for name in set(current) | set(target) if current.get(name) != target.get(name))
        if inventory(self.root) != current:
            raise Held("An editor changed source before recovery publication")
        self.space(MAX_FILE + MAX_METADATA)
        token = secrets.token_hex(16)
        observed = {}
        for name in current:
            info = (self.root / name).lstat()
            plain(info)
            observed[name] = list(identity(info))
        plan = dict(schema=1, id=token, report_id=report["report_id"], before=manifest(current),
                    after=manifest(target), before_ids=observed, failed=index["failed"])
        self.write("transaction.plan.json", plan)
        plan_digest = sha(read(self.state / "transaction.plan.json"))
        progress_path = self.state / "transaction.progress.jsonl"
        if progress_path.exists():
            last = self.load("transaction.last.json", {})
            if sha(read(progress_path)) != last.get("progress_sha256"):
                raise Held("An unclosed source progress journal requires review")
            os.replace(progress_path, self.state / "transaction.last-progress.jsonl")
        with progress_path.open("xb") as stream:
            stream.flush(); os.fsync(stream.fileno())
        base = dict(schema=1, id=token, report_id=report["report_id"], plan_sha256=plan_digest,
                    before_digest=digest(current), target_digest=digest(target))
        self.write("transaction.pending.json", dict(base, next_file=0, phase="prepared"))
        try:
            for position, name in enumerate(changes):
                if not allowed(name):
                    raise Held("A source recovery path escaped the first-party whitelist")
                path = self.root / name
                if not path.parent.exists():
                    path.parent.mkdir(parents=True, exist_ok=True)
                absolute(path)
                backup = path.with_name(".angerona-recovery-" + token + ".old")
                stage = path.with_name(".angerona-recovery-" + token + ".tmp")
                journal = dict(base, next_file=position,
                    source=name, backup=backup.relative_to(self.root).as_posix(),
                    stage=stage.relative_to(self.root).as_posix())
                self.write("transaction.pending.json", dict(journal, phase="publishing"))
                with contextlib.ExitStack() as stack:
                    old = None
                    if name in current:
                        old = stack.enter_context(FileLease(path, mutation=True))
                        if old.read(MAX_FILE) != current[name]:
                            raise Held("An editor changed a source file before recovery")
                        old.rename(backup)
                    elif path.exists():
                        raise Held("An editor created a source file before recovery")
                    self.write("transaction.pending.json", dict(journal, phase="old-preserved"))
                    published_identity = None
                    if name in target:
                        with stage.open("xb") as stream:
                            stream.write(target[name]); stream.flush(); os.fsync(stream.fileno())
                        # Timestamp-based bytecode caches include only whole
                        # seconds and source size. A same-size quick rollback
                        # must not reuse bytecode compiled from the failed file.
                        modified = int(time.time()) + 2
                        if old is not None and (modified & 0xFFFFFFFF) == ((old.initial[3] // 1_000_000_000) & 0xFFFFFFFF):
                            modified += 1
                        os.utime(stage, ns=(time.time_ns(), modified * 1_000_000_000))
                        new = stack.enter_context(FileLease(stage, mutation=True))
                        if new.read(MAX_FILE) != target[name]:
                            raise Held("Staged recovery source failed verification")
                        published_identity = list(new.initial)
                        self.write("transaction.pending.json", dict(journal, phase="new-staged", new_identity=published_identity))
                        new.rename(path)
                    if old is not None:
                        old.delete()
                self.progress(token, plan_digest, dict(path=name, new_identity=published_identity))
                self.write("transaction.pending.json", dict(journal, phase="file-complete", next_file=position + 1))
            if inventory(self.root) != target:
                raise Held("Recovered source changed before final verification")
            original = self.unarchive(index["failed"])
            shown = (changes if report.get("strategy") in {"restore-edits", "interrupted-original-restore"} else
                     sorted(name for name in set(original) | set(target) if original.get(name) != target.get(name)))
            history = list(report.get("history", []))[-7:]
            history.append(dict(strategy=report.get("strategy"), target_revision=report.get("target_revision"),
                                changed_file_count=len(changes), transaction_id=token))
            report.update(working_digest=digest(target), changed=bool(changes), changed_files=shown[:64], launch_held=False,
                          changed_file_count=len(shown), history=history, pending_decision=True, phase="recovered-candidate",
                          outcome="candidate-restored", actions=["Preserved the original failed source revision", "Restored only scoped first-party Python source"],
                          action_summary="Source candidate restored; a fresh dashboard-ready observation is still required.")
            self.write("index.json", index)
            self.output(report)
            pending = self.state / "transaction.pending.json"
            complete = self.load("transaction.pending.json")
            if (complete.get("id") != token or complete.get("report_id") != report["report_id"]
                    or complete.get("target_digest") != digest(target)
                    or complete.get("before_digest") != digest(current)):
                raise Held("Source transaction journal changed before completion")
            self.write("transaction.last.json", dict(complete, phase="complete", progress_sha256=sha(read(progress_path))))
            with FileLease(pending, mutation=True) as held:
                if closed_json(held.read(MAX_METADATA)) != complete:
                    raise Held("Source transaction journal changed before retirement")
                held.delete()
            return report
        except BaseException:
            # Never overwrite a partial journal or attempt a silent rollback
            # over newly edited source. Complete originals remain in the archive.
            raise

    def recover(self, strategy, *, exclusive_startup=False, expected_id=None, failure_detail=""):
        if not exclusive_startup:
            raise Held("The parent must hold its startup lease and prove runtime retirement before source restoration")
        self.guard_pending()
        current = inventory(self.root)
        index = self.load("index.json", dict(schema=1, ready=[], failed=None))
        report = self.report()
        failed = index.get("failed")
        retired = None
        resolved = bool(report and report.get("pending_decision") is False and (
            report.get("decision") == "keep-working" or (
                report.get("decision") == "restore-edits" and report.get("phase") == "ready-confirmed")))
        if failed and resolved and not os.path.lexists(self.state / "edits.pending.json"):
            self.space(sum(map(len, current.values())) + MAX_METADATA)
            self.unarchive(failed)
            if failed.get("file") != "failed-" + failed.get("id", "") + ".zip":
                raise Held("Only an exact resolved failed capture may rotate")
            with FileLease(self.state / failed["file"], mutation=True) as held:
                if sha(held.read(MAX_BYTES)) != failed.get("sha256"):
                    raise Held("Resolved source capture changed before bounded rotation")
                held.delete()
            retired = failed["id"]
            index["failed"] = None
            self.write("index.json", index)
            failed, report = None, {}
        if failed:
            original = self.unarchive(failed)
            if not report:
                raise Held("Preserved failed source has no completed report; review the existing capture")
            if report and (expected_id != report.get("report_id") or digest(current) not in {
                    report.get("working_digest"), digest(original)}):
                raise Held("Another recovery or editor change requires review before continuing strategies")
        else:
            failed = self.archive(current, "failed")
            if inventory(self.root) != current:
                raise Held("An editor changed failed source during preservation")
            index["failed"] = failed
            self.write("index.json", index)
            report = dict(empty_summary(), report_id=secrets.token_hex(16), pending_decision=True,
                          protection_status="unknown", failed_candidate_id=failed["id"], decision="pending")
            report.update(phase="failed-source-preserved", working_digest=digest(current), changed=False,
                          changed_files=[], changed_file_count=0, actions=["Preserved the original failed source revision"],
                          action_summary="Original source bytes are preserved; no replacement candidate is selected yet.",
                          message="Failed source is preserved while verified recovery candidates are checked.",
                          startup_error=str(failure_detail)[:4096])
            self.output(report)
            if retired:
                report["resolved_capture_rotated"] = retired
                self.output(report)
        if strategy == "last-ready":
            ready = index.get("ready", [])
            if not ready:
                raise Held("No genuinely ready source snapshot is retained")
            target, revision = self.unarchive(ready[-1]), "ready-" + ready[-1]["id"]
        elif strategy in {"github-head", "github-parent"}:
            self.space(MAX_BYTES + MAX_METADATA)
            target, revision = github_candidate(self.root, strategy, self.transport)
        else:
            raise Held("Unknown source recovery strategy")
        report.update(strategy=strategy, target_revision=revision,
                      startup_error=str(report.get("startup_error") or failure_detail)[:4096],
                      message="A source recovery candidate is available; preserved edits can be reviewed after a verified launch.")
        return self._publish(current, target, report, index)

    def decision(self, choice, *, expected_id):
        report = self.report()
        if not _ID.fullmatch(str(expected_id)) or report.get("report_id") != expected_id:
            raise Held("The source recovery decision no longer matches its displayed report")
        if choice not in {"keep-working", "restore-edits"}:
            raise Held("Unknown source recovery decision")
        self.guard_pending()
        index = self.load("index.json")
        original = self.unarchive(index["failed"])
        if choice == "restore-edits":
            require_stop_contract(original)
            self.write("edits.pending.json", dict(schema=1, report_id=expected_id,
                candidate=index["failed"]["id"], working_digest=report.get("working_digest")))
        else:
            pending = self.state / "edits.pending.json"
            if pending.exists():
                value = self.load("edits.pending.json")
                if value.get("report_id") != expected_id:
                    raise Held("A different deferred source decision requires review")
                pending.unlink()
        report.update(decision=choice, pending_decision=False, phase="decision-recorded",
                      outcome="decision-recorded", action_summary=("Preserved edits are scheduled for the next exclusive startup; no hot edit occurred."
                        if choice == "restore-edits" else "The working revision remains selected; original failed edits are preserved."))
        return self.output(report)

    def apply_pending(self, *, exclusive_startup=False):
        if not exclusive_startup:
            raise Held("Exclusive pre-launch custody is required to apply deferred source edits")
        if os.path.lexists(self.state / "transaction.pending.json"):
            return self.reconcile_own_transaction()
        pending = self.load("edits.pending.json")
        if pending is None:
            return dict(empty_summary(), **dict(self.report(), outcome="no-pending-edits", changed=False))
        report, index = self.report(), self.load("index.json")
        if (pending.get("report_id") != report.get("report_id") or
                pending.get("candidate") != index["failed"]["id"]):
            raise Held("Deferred source decision changed identity")
        current = inventory(self.root)
        if digest(current) != pending.get("working_digest"):
            raise Held("Working source changed after the deferred decision")
        target = self.unarchive(index["failed"])
        result = self._publish(current, target, dict(report, strategy="restore-edits"), index)
        (self.state / "edits.pending.json").unlink()
        return result

    def reconcile_own_transaction(self):
        """Restore preserved originals only from an unambiguous owned partial tree.

        New or edited application bytes are never overwritten. Original journal,
        plan and progress are retained; old .old/.tmp artifacts remain untouched.
        This restores source coherence, not dashboard/security readiness.
        """
        pending, report, index = self.load("transaction.pending.json"), self.report(), self.load("index.json")
        receipt = self.load("transaction.interrupted.json")
        plan_raw = read(self.state / "transaction.plan.json")
        plan = closed_json(plan_raw)
        if sha(plan_raw) != pending.get("plan_sha256") and isinstance(receipt, dict) and receipt.get("pending") == pending:
            plan = receipt.get("plan")
            plan_raw = json.dumps(plan, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        if (pending.get("schema") != 1 or not _ID.fullmatch(str(pending.get("id", "")))
                or pending.get("report_id") != report.get("report_id")
                or plan.get("id") != pending["id"] or plan.get("report_id") != pending["report_id"]
                or sha(plan_raw) != pending.get("plan_sha256") or plan.get("failed") != index.get("failed")):
            raise Held("Source transaction plan, report or original capture binding is unknown")
        before, after, before_ids = plan.get("before"), plan.get("after"), plan.get("before_ids")
        if not all(isinstance(value, dict) for value in (before, after, before_ids)):
            raise Held("Source transaction manifests are unavailable")
        for listing in (before, after):
            if len(listing) > MAX_FILES or any(not allowed(name) for name in listing):
                raise Held("Source transaction manifest escaped its scope")
        if (sha(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()) != pending.get("before_digest")
                or sha(json.dumps(after, sort_keys=True, separators=(",", ":")).encode()) != pending.get("target_digest")):
            raise Held("Source transaction manifest digests changed")
        if isinstance(receipt, dict) and receipt.get("pending") == pending:
            rows = receipt.get("progress")
            if not isinstance(rows, list):
                raise Held("Interrupted progress evidence is unavailable")
        else:
            rows = self.progress(pending["id"], pending["plan_sha256"])
        completed = {}
        for row in rows:
            name = row.get("path")
            if name in completed or name not in set(before) | set(after):
                raise Held("Source transaction progress is duplicated or unknown")
            completed[name] = row.get("new_identity")
        active_name = pending.get("source")
        active_identity = pending.get("new_identity")
        current = inventory(self.root)
        if set(current) - (set(before) | set(after)):
            raise Held("An editor added source outside the interrupted transaction")
        changed = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
        for name in set(before) | set(after):
            if name not in current:
                if name not in before:
                    if name in completed:
                        raise Held("An editor deleted a source file after its owned publication")
                    if name != active_name or pending.get("phase") in {"prepared", "publishing", "old-preserved"}:
                        continue  # An unprocessed addition still has its observed before-state.
                    if pending.get("phase") == "new-staged":
                        stage = (self.root / name).with_name(".angerona-recovery-" + pending["id"] + ".tmp")
                        if pending.get("stage") != stage.relative_to(self.root).as_posix():
                            raise Held("The active source stage path changed")
                        try:
                            with FileLease(stage) as held:
                                data = held.read(MAX_FILE)
                                if (list(held.initial) != active_identity
                                        or dict(sha256=sha(data), size=len(data)) != after.get(name)):
                                    raise Held("The active addition stage generation changed")
                        except OSError as error:
                            raise Held("A source addition is absent without its owned staged generation") from error
                        continue
                    raise Held("A source addition has unknown absence after publication")
                if name in completed and completed[name] is None and name not in after:
                    continue  # A durable progress row proves this exact deletion.
                if name == active_name and pending.get("phase") in {"publishing", "old-preserved", "new-staged"}:
                    source_path = self.root / name
                    backup = source_path.with_name(".angerona-recovery-" + pending["id"] + ".old")
                    if pending.get("backup") != backup.relative_to(self.root).as_posix():
                        raise Held("The active source backup path changed")
                    try:
                        with FileLease(backup) as held:
                            data = held.read(MAX_FILE)
                            if (list(held.initial) != before_ids.get(name)
                                    or dict(sha256=sha(data), size=len(data)) != before[name]):
                                raise Held("The active source backup generation changed")
                        if pending.get("phase") == "new-staged":
                            stage = source_path.with_name(".angerona-recovery-" + pending["id"] + ".tmp")
                            if pending.get("stage") != stage.relative_to(self.root).as_posix():
                                raise Held("The active source stage path changed")
                            with FileLease(stage) as held:
                                data = held.read(MAX_FILE)
                                if (list(held.initial) != active_identity
                                        or dict(sha256=sha(data), size=len(data)) != after.get(name)):
                                    raise Held("The active source stage generation changed")
                    except OSError as error:
                        raise Held("Active source absence is not proved by its owned artifacts") from error
                    continue
                raise Held("An editor deleted source outside a completed owned operation")
            item = dict(sha256=sha(current[name]), size=len(current[name]))
            actual = list(identity((self.root / name).lstat()))
            if item == before.get(name) and actual == before_ids.get(name):
                continue
            expected_after = completed.get(name, active_identity if name == active_name else None)
            if item == after.get(name) and expected_after is not None and actual == expected_after:
                continue
            raise Held("Source contains editor changes or an unknown process generation; originals remain preserved")
        original = self.unarchive(index["failed"])
        if receipt is not None and receipt.get("pending") != pending:
            raise Held("A prior interrupted transaction receipt requires review before another reconciliation")
        preserved = dict(schema=1, pending=pending, plan=plan, progress=rows)
        if receipt is None:
            self.write("transaction.interrupted.json", preserved)
        if self.load("transaction.interrupted.json") != preserved:
            raise Held("Interrupted source evidence did not persist")
        if self.load("transaction.pending.json") != pending:
            raise Held("Source transaction journal changed before reconciliation")
        progress_path = self.state / "transaction.progress.jsonl"
        if progress_path.exists():
            with FileLease(progress_path, mutation=True) as held:
                actual_rows = held.read(MAX_METADATA).splitlines()
                expected_rows = [json.dumps(value, sort_keys=True, separators=(",", ":")).encode() for value in rows]
                if actual_rows not in (expected_rows, []):
                    raise Held("Source progress changed before reconciliation")
                held.delete()
        # The old pending marker remains continuously present until _publish
        # atomically replaces it with the new original-restoration transaction.
        report.update(strategy="interrupted-original-restore", target_revision="preserved-" + index["failed"]["id"])
        result = self._publish(current, original, report, index)
        result.update(outcome="own-interruption-reconciled", action_summary="Restored complete preserved original source after a verified own interruption; staging evidence remains retained.",
                      launch_held=False)
        return self.output(result)


def inspect_state(root, state_root):
    """Inspect safety holds without creating state, locks or applying a choice."""
    canonical_root(root)
    state = state_namespace(state_root)
    result = dict(empty_summary(), outcome="no-source-state", reason_code="source-state-absent",
                  requires_mutation=False, pending_kind="none")
    if not os.path.lexists(state):
        return result
    plain(state.lstat(), directory=True)
    if os.name == "nt":
        _windows_private(state)
    elif state.stat().st_uid != os.geteuid() or stat.S_IMODE(state.stat().st_mode) & 0o077:
        raise Held("Recovery state privacy cannot be verified")
    with os.scandir(state) as entries:
        for position, entry in enumerate(entries):
            if position >= 16:
                raise Held("Recovery state entry capacity requires review")
            plain(Path(entry.path).lstat())
            if entry.name.startswith(".state-"):
                raise Held("An interrupted recovery metadata publication requires review")
    report = state / "report.json"
    if report.exists():
        value = closed_json(read(report, MAX_REPORT))
        if not isinstance(value, dict):
            raise Held("Source recovery report is malformed")
        result.update(value)
    if os.path.lexists(state / "transaction.pending.json"):
        result.update(outcome="held", launch_held=True, reason_code="source-transaction-unresolved",
                      requires_mutation=True, pending_kind="transaction",
                      message="An interrupted source transaction requires exclusive reconciliation before application startup.")
    elif os.path.lexists(state / "edits.pending.json"):
        result.update(outcome="source-state-inspected", launch_held=False, reason_code="source-edits-pending",
                      requires_mutation=True, pending_kind="edits")
    else:
        result.update(outcome="source-state-inspected", launch_held=False, reason_code="no-source-transaction",
                      requires_mutation=False, pending_kind="none")
    return result


def emit_record(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(raw.encode("utf-8")) > MAX_REPORT:
        print(json.dumps(dict(schema=1, outcome="held", changed=False, launch_held=True,
                              reason_code="source-report-capacity", message="The source recovery report exceeds its output bound.")))
        return False
    print(raw)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--action", required=True, choices=("inspect", "fingerprint", "snapshot", "recover", "decision", "apply-pending"))
    parser.add_argument("--strategy", choices=("last-ready", "github-head", "github-parent"), default="last-ready")
    parser.add_argument("--choice", choices=("keep-working", "restore-edits"))
    parser.add_argument("--expected-id", "--expected-report-id", dest="expected_id")
    parser.add_argument("--exclusive-startup", action="store_true")
    parser.add_argument("--ready-observed", action="store_true")
    parser.add_argument("--expected-source-digest")
    parser.add_argument("--failure-detail", default="")
    options = parser.parse_args(argv)
    try:
        if options.action == "inspect":
            result = inspect_state(options.root, options.state_root)
            emitted = emit_record(result)
            return 1 if result["launch_held"] or not emitted else 0
        store = RecoveryStore(options.root, options.state_root)
        with store.locked():
            if options.action == "fingerprint":
                first = inventory(store.root)
                if inventory(store.root) != first:
                    raise Held("An editor changed source during its pre-launch fingerprint")
                result = dict(empty_summary(), outcome="source-fingerprinted", source_digest=digest(first), file_count=len(first))
            elif options.action == "snapshot":
                result = store.snapshot(ready_observed=options.ready_observed, expected_source_digest=options.expected_source_digest)
            elif options.action == "recover":
                result = store.recover(options.strategy, exclusive_startup=options.exclusive_startup,
                                       expected_id=options.expected_id, failure_detail=options.failure_detail)
            elif options.action == "decision":
                result = store.decision(options.choice, expected_id=options.expected_id)
            else:
                result = store.apply_pending(exclusive_startup=options.exclusive_startup)
        return 0 if emit_record(result) else 1
    except Exception as error:
        message = str(error)[:1500] if isinstance(error, Held) else type(error).__name__ + ": recovery operation unavailable"
        saved = empty_summary()
        try:
            saved.update(store.report())
        except Exception:
            pass
        saved.update(schema=1, outcome="held", changed=False, message=message,
                     action_summary="Source and preserved originals require review; no trust baseline was changed.")
        unresolved = False
        try:
            unresolved = os.path.lexists(store.state / "transaction.pending.json")
        except Exception:
            pass
        saved["launch_held"] = unresolved or options.action in {"apply-pending", "inspect"}
        saved["reason_code"] = "source-transaction-unresolved" if unresolved else "source-recovery-unavailable"
        emit_record(saved)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
