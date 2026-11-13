"""Bounded legacy-canary file I/O; no privilege acquisition or trust promotion.

Windows new directory/file/attribute mutations are held until an object-relative
provider can prove the effect boundary. Read sharing does not exclude metadata-
only reparse writers. Existing exact static canaries remain read-only observable;
these local safeguards are not a same-user process/kernel trust boundary.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import stat


MAX_BYTES = 64 * 1024
MAX_DEPTH = 128
_CLOSE_HOLDS: list[object] = []


class CanaryHeld(RuntimeError):
    pass


class CanaryCollision(CanaryHeld):
    pass


@dataclass(frozen=True)
class Snapshot:
    path: Path
    mtime: float
    evidence: tuple[int, int, int, int, str]
    created: bool = False


class _Owned:
    def __init__(self, value, close):
        self.value, self._close, self.closed = value, close, False

    def close(self):
        if self.closed:
            return
        self.closed = True  # Never retry a numeric handle after an uncertain close.
        try:
            self._close(self.value)
        except BaseException as error:
            _CLOSE_HOLDS.append(self)
            raise CanaryHeld("Canary resource retirement is unproven; further I/O is held") from error


def _available():
    if _CLOSE_HOLDS:
        raise CanaryHeld("A prior canary resource retirement remains unproven")


def _absolute(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise CanaryHeld("Canaries require a plain absolute local path")
    if len(path.parts) > MAX_DEPTH:
        raise CanaryHeld("Canary directory depth exceeds its bound")
    return Path(os.path.abspath(path))


def _name(value):
    if (type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?", value)
            or len(value) > 120):
        raise CanaryHeld("Canary name is outside the fixed leaf schema")
    return value


def _ordinary(facts):
    if (type(facts) is not dict or facts.get("elevated") is not False
            or type(facts.get("integrity")) is not int or not 0 <= facts["integrity"] < 0x3000
            or facts.get("impersonated") is not False):
        raise CanaryHeld("New canary writes require a verified ordinary non-impersonating token")


def _metadata(info, *, directory=False):
    if (type(info) is not dict or type(info.get("attributes")) is not int
            or info["attributes"] & 0x400 or bool(info["attributes"] & 0x10) != directory
            or any(type(info.get(key)) is not int for key in ("device", "inode", "size", "mtime_ns", "links"))
            or info["inode"] <= 0 or (not directory and (info["links"] != 1 or not 0 <= info["size"] <= MAX_BYTES))):
        raise CanaryHeld("Canary object type, identity or byte bound is unavailable")
    return (info["device"], info["inode"], info["size"], info["mtime_ns"])


def _snapshot(session, leaf, path, *, created=False, expected=None):
    before = session.info(leaf)
    stamp = _metadata(before)
    raw = session.read(leaf, MAX_BYTES + 1)
    if expected is not None and raw != expected:
        raise CanaryCollision("Existing user file differs from the exact static canary; preserved without attribute changes")
    after = session.info(leaf)
    if (len(raw) != before["size"] or len(raw) > MAX_BYTES or _metadata(after) != stamp):
        raise CanaryHeld("Canary changed during its held identity/content sample")
    session.validate_leaf(leaf, path)
    return Snapshot(path, before["mtime_ns"] / 1_000_000_000,
                    (*stamp, hashlib.sha256(raw).hexdigest()), created)


def _close_all(resources):
    failure = None
    for resource in reversed(resources):
        try:
            resource.close()
        except CanaryHeld as error:
            failure = error
    if failure is not None:
        raise failure


class _WindowsApi:
    """Lazy native boundary. Tests replace this facade; import performs no I/O."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        import win32api
        import win32con
        import win32file
        import win32security
        import pywintypes
        from win32com.shell import shell
        self.ctypes, self.w = ctypes, w
        self.api, self.con, self.file, self.security = win32api, win32con, win32file, win32security
        self.pywintypes, self.shell = pywintypes, shell
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        # Load only the OS COM library, never an inherited DLL search directory.
        self.ole = ctypes.WinDLL("ole32.dll", use_last_error=True, winmode=0x00000800)
        self.ole.CoInitializeEx.argtypes = [w.LPVOID, w.DWORD]
        self.ole.CoInitializeEx.restype = ctypes.c_long  # HRESULT (Windows LONG).
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoUninitialize.restype = None

        class Info(ctypes.Structure):
            _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                        ("modified", w.FILETIME), ("volume", w.DWORD), ("size_hi", w.DWORD),
                        ("size_lo", w.DWORD), ("links", w.DWORD), ("index_hi", w.DWORD), ("index_lo", w.DWORD)]
        class Basic(ctypes.Structure):
            _fields_ = [("created", ctypes.c_longlong), ("accessed", ctypes.c_longlong),
                        ("modified", ctypes.c_longlong), ("changed", ctypes.c_longlong), ("attributes", w.DWORD)]
        self.Info, self.Basic = Info, Basic
        self.kernel.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
        self.kernel.GetFileInformationByHandle.restype = w.BOOL
        self.kernel.SetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
        self.kernel.SetFileInformationByHandle.restype = w.BOOL

    def close(self, handle):
        original = int(handle)
        try:
            handle.Close()
        except BaseException:
            # PyHANDLE finalization must not retry an uncertain native close.
            try:
                handle.Detach()
            except BaseException:
                pass
            self._uncertain_handle = (handle, original)
            raise

    def _query(self, token):
        get = lambda kind: self.security.GetTokenInformation(token, kind)
        user = self.security.ConvertSidToStringSid(get(self.security.TokenUser)[0])
        elevation = get(getattr(self.security, "TokenElevation", 20))
        integrity = get(getattr(self.security, "TokenIntegrityLevel", 25))
        if isinstance(integrity, tuple):
            integrity = integrity[0]
        level = self.security.ConvertSidToStringSid(integrity)
        if not re.fullmatch(r"S-1-16-[0-9]{1,10}", level) or type(elevation) not in (int, bool) or elevation not in (0, 1):
            raise CanaryHeld("Effective token elevation/integrity is unknown")
        statistics = get(self.security.TokenStatistics)
        identity = tuple(str(statistics[key]) for key in ("TokenId", "AuthenticationId", "ModifiedId"))
        if any(len(value) > 128 for value in identity):
            raise CanaryHeld("Token identity exceeded its bound")
        return dict(sid=user, elevated=bool(elevation), integrity=int(level.rsplit("-", 1)[1]),
                    impersonated=False, identity=identity)

    def token(self, resources):
        try:
            thread = self.security.OpenThreadToken(self.api.GetCurrentThread(), 8, True)
        except self.pywintypes.error as error:
            if error.winerror != 1008:  # ERROR_NO_TOKEN is the sole ordinary fallback.
                raise CanaryHeld("Thread token custody is unknown") from error
        else:
            owned = _Owned(thread, self.close)
            resources.append(owned)
            owned.close()
            raise CanaryHeld("Legacy canary I/O does not admit an impersonating thread")
        # KnownFolder hToken admission can require QUERY|DUPLICATE|IMPERSONATE.
        # These are rights on this retained ordinary token, not elevation.
        token = self.security.OpenProcessToken(self.api.GetCurrentProcess(), 0x0E)
        owned = _Owned(token, self.close)
        resources.append(owned)
        return owned, self._query(token)

    def documents(self, token):
        _available()
        try:
            # Direct ole32 calls own a real per-call reference even if pywin32
            # remembers an already initialized main thread. STA2 is explicit;
            # an incompatible existing MTA is held, never silently borrowed.
            result = self.ole.CoInitializeEx(None, 2)
        except Exception as error:
            raise CanaryHeld("Documents resolution requires an admitted current-thread COM apartment") from error
        if type(result) is not int or result not in (0, 1):  # S_OK / S_FALSE
            raise CanaryHeld("Documents COM apartment admission failed or changed mode")
        apartment = _Owned(None, lambda _value: self.ole.CoUninitialize())
        try:
            folder = self.pywintypes.IID("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}")
            try:
                return Path(self.shell.SHGetKnownFolderPath(folder, 0, token))
            except Exception as error:
                raise CanaryHeld("Token-bound Documents resolution is unavailable") from error
        finally:
            # Both S_OK and S_FALSE require exactly one close on this same
            # calling thread. Unknown retirement holds all subsequent I/O.
            apartment.close()

    def attributes(self, sid, *, directory=False):
        attributes = self.pywintypes.SECURITY_ATTRIBUTES()
        attributes.bInheritHandle = False
        inherit = "OICI" if directory else ""
        attributes.SECURITY_DESCRIPTOR = self.security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            f"O:{sid}D:P(A;{inherit};FA;;;{sid})(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)", 1)
        return attributes

    def directory(self, path):
        return self.file.CreateFile(str(path), 0x81, 1, None, 3, 0x02200000, None)

    def mkdir(self, path, sid):
        raise CanaryHeld("Windows canary directory creation is held: object-relative provider unavailable")

    def leaf(self, path, sid, *, create):
        if create:
            raise CanaryHeld("Windows canary file creation is held: object-relative provider unavailable")
        return self.file.CreateFile(str(path), 0x80000000, 1, None, 3, 0x00200080, None)

    def missing(self, error):
        return isinstance(error, self.pywintypes.error) and error.winerror in (2, 3)

    def collision(self, error):
        return isinstance(error, self.pywintypes.error) and error.winerror in (80, 183)

    def info(self, handle):
        if self.file.GetFileType(handle) != 1:
            raise CanaryHeld("Canary handle is not a disk object")
        value = self.Info()
        if not self.kernel.GetFileInformationByHandle(int(handle), self.ctypes.byref(value)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        ticks = (value.modified.dwHighDateTime << 32) | value.modified.dwLowDateTime
        return dict(attributes=int(value.attributes), device=int(value.volume),
            inode=(int(value.index_hi) << 32) | int(value.index_lo),
            size=(int(value.size_hi) << 32) | int(value.size_lo), links=int(value.links),
            mtime_ns=(ticks - 116444736000000000) * 100)

    def final(self, handle):
        value = self.file.GetFinalPathNameByHandle(handle, 0)
        if value.startswith("\\\\?\\"):
            value = value[4:]
        return _absolute(value)

    def read(self, handle, maximum):
        self.file.SetFilePointer(handle, 0, 0)
        _error, raw = self.file.ReadFile(handle, maximum)
        return raw

    def write(self, handle, raw):
        raise CanaryHeld("Windows canary content mutation is held: object-relative provider unavailable")

    def hide(self, handle):
        raise CanaryHeld("Windows canary attribute mutation is held: object-relative provider unavailable")


class _WindowsSession:
    def __init__(self, base, *, personal=False, create_parents=False, api=None):
        self.requested, self.personal, self.create_parents = base, personal, create_parents
        self.api = api
        self.resources, self.directories = [], []

    def __enter__(self):
        _available()
        try:
            self.api = self.api or _WindowsApi()
            self.token, self.facts = self.api.token(self.resources)
            self.base = _absolute(self.api.documents(self.token.value) if self.personal else self.requested)
            if not PureWindowsPath(str(self.base)).drive or PureWindowsPath(str(self.base)).drive.startswith("\\\\"):
                raise CanaryHeld("Documents requires a local drive with verifiable custody")
            for path in (*reversed(self.base.parents), self.base):
                try:
                    handle = self.api.directory(path)
                except Exception as error:
                    if not self.api.missing(error) or not self.create_parents or self.personal:
                        raise CanaryHeld("Canary directory custody is unavailable") from error
                    self.check_write()
                    self.api.mkdir(path, self.facts["sid"])
                    handle = self.api.directory(path)
                owned = _Owned(handle, self.api.close)
                self.resources.append(owned)
                info = self.api.info(handle)
                _metadata(info, directory=True)
                if os.path.normcase(str(self.api.final(handle))) != os.path.normcase(str(path)):
                    raise CanaryHeld("Canary directory handle differs from its admitted path")
                self.directories.append((path, owned, (info["device"], info["inode"])))
            return self
        except BaseException:
            _close_all(self.resources)
            raise

    def __exit__(self, *_args):
        _close_all(self.resources)

    def check_write(self):
        _available()
        # FILE_SHARE_READ does not exclude FILE_WRITE_ATTRIBUTES handles or a
        # reparse conversion after the last check. Absolute mkdir/CREATE_NEW is
        # already an effect before post-open validation can detect redirection.
        # No injected facade/flag grants production mutation authority here.
        raise CanaryHeld("Windows canary new mutations are held: object-relative provider unavailable")

    @contextmanager
    def leaf(self, name, *, create=False):
        if create:
            self.check_write()
        path = self.base / _name(name)
        try:
            handle = self.api.leaf(path, self.facts["sid"], create=create)
        except Exception as error:
            if self.api.missing(error):
                raise FileNotFoundError(str(path)) from error
            if self.api.collision(error):
                raise CanaryCollision("Existing canary-name collision was preserved") from error
            raise CanaryHeld("Canary leaf custody is unavailable") from error
        owned = _Owned(handle, self.api.close)
        self.resources.append(owned)
        try:
            _metadata(self.api.info(handle))
            self.validate_leaf(owned, path)
            yield owned
        finally:
            owned.close()

    def info(self, leaf):
        return self.api.info(leaf.value)

    def read(self, leaf, maximum):
        return self.api.read(leaf.value, maximum)

    def validate_leaf(self, leaf, path):
        if os.path.normcase(str(self.api.final(leaf.value))) != os.path.normcase(str(path)):
            raise CanaryHeld("Held canary leaf differs from its admitted path")

    def write(self, leaf, raw):
        self.check_write()
        self.api.write(leaf.value, raw)

    def hide(self, leaf):
        self.check_write()
        self.api.hide(leaf.value)


class _PosixSession:
    def __init__(self, base, *, personal=False, create_parents=False):
        if personal:
            import pwd
            base = Path(pwd.getpwuid(os.getuid()).pw_dir) / "Documents"
        self.base, self.create_parents = _absolute(base), create_parents and not personal
        self.resources, self.directories = [], []
        self.uid = (os.getuid(), os.geteuid())

    def __enter__(self):
        _available()
        try:
            parent = None
            for path in (*reversed(self.base.parents), self.base):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                try:
                    fd = os.open(str(path) if parent is None else path.name, flags,
                                 **({} if parent is None else {"dir_fd": parent}))
                except FileNotFoundError:
                    if not self.create_parents or parent is None:
                        raise CanaryHeld("Canary directory is unavailable")
                    self.check_write()
                    os.mkdir(path.name, 0o700, dir_fd=parent)
                    fd = os.open(path.name, flags, dir_fd=parent)
                owned = _Owned(fd, os.close)
                self.resources.append(owned)
                info = os.fstat(fd)
                if not stat.S_ISDIR(info.st_mode):
                    raise CanaryHeld("Canary parent is not a directory")
                self.directories.append((path, owned, (info.st_dev, info.st_ino)))
                parent = fd
            self.parent = parent
            return self
        except BaseException:
            _close_all(self.resources)
            raise

    def __exit__(self, *_args):
        _close_all(self.resources)

    def check_write(self):
        _available()
        if self.uid != (os.getuid(), os.geteuid()) or self.uid[0] == 0 or self.uid[0] != self.uid[1]:
            raise CanaryHeld("New canary writes require an ordinary unchanged local user")
        for path, owned, identity in self.directories:
            named, held = os.lstat(path), os.fstat(owned.value)
            if (not stat.S_ISDIR(named.st_mode) or stat.S_ISLNK(named.st_mode)
                    or (named.st_dev, named.st_ino) != identity or (held.st_dev, held.st_ino) != identity):
                raise CanaryHeld("Canary parent changed before mutation")

    @contextmanager
    def leaf(self, name, *, create=False):
        if create:
            self.check_write()
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        flags |= os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(_name(name), flags, 0o600, dir_fd=self.parent)
        except FileExistsError as error:
            raise CanaryCollision("Existing canary-name collision was preserved") from error
        owned = _Owned(fd, os.close)
        self.resources.append(owned)
        try:
            _metadata(self.info(owned))
            yield owned
        finally:
            owned.close()

    def info(self, leaf):
        value = os.fstat(leaf.value)
        if not stat.S_ISREG(value.st_mode):
            raise CanaryHeld("Canary leaf is not regular")
        return dict(attributes=0, device=value.st_dev, inode=value.st_ino, size=value.st_size,
                    mtime_ns=value.st_mtime_ns, links=value.st_nlink)

    def read(self, leaf, maximum):
        os.lseek(leaf.value, 0, os.SEEK_SET)
        return os.read(leaf.value, maximum)

    def validate_leaf(self, leaf, path):
        value, named = os.fstat(leaf.value), os.stat(path.name, dir_fd=self.parent, follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or (value.st_dev, value.st_ino) != (named.st_dev, named.st_ino)):
            raise CanaryHeld("Canary leaf identity changed")

    def write(self, leaf, raw):
        self.check_write()
        offset = 0
        while offset < len(raw):
            written = os.write(leaf.value, raw[offset:])
            if written <= 0:
                raise CanaryHeld("Canary write did not complete")
            offset += written
        os.fsync(leaf.value)

    def hide(self, leaf):
        pass  # No pathname attributes are changed on POSIX.


def _session(base, *, personal=False, create_parents=False):
    _available()
    cls = _WindowsSession if os.name == "nt" else _PosixSession
    return cls(base, personal=personal, create_parents=create_parents)


def create_canary(base, name, raw, *, personal=False, adopt_static=False, on_admitted=None):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise CanaryHeld("Canary payload exceeds its fixed byte contract")
    _name(name)
    try:
        with _session(base, personal=personal, create_parents=True) as session:
            path = session.base / name
            if adopt_static:
                try:
                    with session.leaf(name) as leaf:
                        observed = _snapshot(session, leaf, path, expected=raw)
                        if on_admitted is not None:
                            on_admitted(observed)
                        return observed
                except FileNotFoundError:
                    pass
            with session.leaf(name, create=True) as leaf:
                session.write(leaf, raw)
                session.hide(leaf)  # Only a freshly, exclusively created file.
                observed = _snapshot(session, leaf, path, created=True, expected=raw)
                if on_admitted is not None:
                    on_admitted(observed)
                return observed
    except CanaryHeld:
        raise
    except Exception as error:
        raise CanaryHeld("Canary creation/adoption was held; existing files were preserved") from error


def snapshot(path):
    path = _absolute(path)
    try:
        with _session(path.parent) as session:
            with session.leaf(path.name) as leaf:
                return _snapshot(session, leaf, path)
    except (CanaryHeld, FileNotFoundError):
        raise
    except Exception as error:
        raise CanaryHeld("Canary observation custody is unavailable") from error
