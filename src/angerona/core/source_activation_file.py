"""Retained file-object primitives for an explicit source update transaction.

These primitives grant no update, process-retirement or installed authority.
They mirror the source recovery helper's native no-replace publication contract.
"""
from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path

_CLOSE_HOLDS = []


class ActivationFileError(RuntimeError):
    pass


class ActivationFileCloseHeld(ActivationFileError):
    pass


def plain_path(value, *, directory=False):
    path = Path(os.path.abspath(value))
    if '..' in Path(value).parts:
        raise ActivationFileError('Source update path contains traversal')
    for node in (*reversed(path.parents), path):
        try:
            info = node.lstat()
        except FileNotFoundError:
            if node == path:
                break
            raise ActivationFileError('Source update ancestor disappeared') from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ActivationFileError('Source update path is redirected')
        if node != path and not stat.S_ISDIR(info.st_mode):
            raise ActivationFileError('Source update ancestor is not a directory')
        if node == path:
            if directory and not stat.S_ISDIR(info.st_mode):
                raise ActivationFileError('Source update directory is not plain')
            if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise ActivationFileError('Source update file is not single-link regular data')
    return path


def identity(info):
    return {'device': str(info.st_dev), 'inode': str(info.st_ino),
            'bytes': info.st_size, 'modified_ns': str(info.st_mtime_ns),
            'birth_ns': (str(getattr(info, 'st_birthtime_ns', info.st_ctime_ns))
                         if os.name == 'nt' else None)}


def directory_identity(path):
    path = plain_path(path, directory=True)
    info = path.lstat()
    return {'device': str(info.st_dev), 'inode': str(info.st_ino)}


class RetainedFile:
    """Hold the exact file; never replace a raced destination or retry close."""
    def __init__(self, path, *, mutation=False, writable=False):
        if _CLOSE_HOLDS:
            raise ActivationFileCloseHeld('Prior source update resource retirement remains held')
        self.path = plain_path(path)
        self.fd = -1
        self.close_held = False
        before = self.path.lstat()
        if os.name == 'nt':
            import msvcrt
            from ctypes import wintypes as w
            api = ctypes.WinDLL('kernel32', use_last_error=True)
            api.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID,
                                       w.DWORD, w.DWORD, w.HANDLE)
            api.CreateFileW.restype = w.HANDLE
            api.CloseHandle.argtypes = (w.HANDLE,)
            api.CloseHandle.restype = w.BOOL
            access = 0x80000000  # GENERIC_READ
            if writable:
                access |= 0x40000000  # GENERIC_WRITE
            if mutation:
                access |= 0x10000 | 0x100  # DELETE and FILE_WRITE_ATTRIBUTES
            raw = api.CreateFileW(str(self.path), access, 1, None, 3, 0x00200000, None)
            if raw == w.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                self.fd = msvcrt.open_osfhandle(raw, (os.O_RDWR if writable else os.O_RDONLY) | os.O_BINARY)
            except OSError:
                if not api.CloseHandle(raw):
                    self.close_held = True
                    _CLOSE_HOLDS.append((self, api, raw))
                raise
            except BaseException:
                # Adoption may have occurred before an asynchronous exception.
                # Never close an ambiguous numeric handle a second time.
                self.close_held = True
                _CLOSE_HOLDS.append((self, api, raw))
                raise
        else:
            flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            self.fd = os.open(self.path, flags)
        try:
            self.initial = identity(os.fstat(self.fd))
            self.check()
            if identity(before) != self.initial:
                raise ActivationFileError('Source update file changed while opening')
        except BaseException:
            self.close()
            raise

    def check(self):
        self._check_snapshot()

    def _check_snapshot(self, *, windows_rename_completed=False):
        if self.fd < 0 or self.close_held:
            raise ActivationFileError('Source update file custody is unavailable')
        plain_path(self.path)
        opened, named = os.fstat(self.fd), self.path.lstat()
        opened_stamp, named_stamp = identity(opened), identity(named)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or getattr(opened, 'st_file_attributes', 0) & 0x400
                or opened_stamp != named_stamp):
            raise ActivationFileError('Source update file identity changed')
        if opened_stamp == self.initial:
            return
        # NTFS can inherit the vacated destination's creation timestamp after a
        # rename. Restore only that metadata on the still-held, otherwise exact
        # file and recheck the original snapshot before returning to the journal.
        if (not windows_rename_completed
                or dict(opened_stamp, birth_ns=self.initial['birth_ns']) != self.initial):
            raise ActivationFileError('Source update file identity changed')
        self._restore_windows_birth()
        self.check()

    def _restore_windows_birth(self):
        import msvcrt
        from ctypes import wintypes as w
        ticks, remainder = divmod(int(self.initial['birth_ns']), 100)
        ticks += 116444736000000000  # FILETIME ticks from 1601 to the Unix epoch
        if remainder or not 0 < ticks < 2**63:
            raise ActivationFileError('Source update creation timestamp is not a valid FILETIME')
        creation = w.FILETIME(ticks & 0xffffffff, ticks >> 32)
        setter = ctypes.WinDLL('kernel32', use_last_error=True).SetFileTime
        setter.argtypes = (w.HANDLE, ctypes.POINTER(w.FILETIME), w.LPVOID, w.LPVOID)
        setter.restype = w.BOOL
        if not setter(msvcrt.get_osfhandle(self.fd), ctypes.byref(creation), None, None):
            raise ctypes.WinError(ctypes.get_last_error())

    def read(self, limit):
        self.check()
        if self.initial['bytes'] > limit:
            raise ActivationFileError('Source update file exceeds its byte bound')
        os.lseek(self.fd, 0, os.SEEK_SET)
        parts, remaining = [], limit + 1
        while remaining:
            part = os.read(self.fd, min(65536, remaining))
            if not part:
                break
            parts.append(part)
            remaining -= len(part)
        raw = b''.join(parts)
        self.check()
        if len(raw) != self.initial['bytes'] or len(raw) > limit:
            raise ActivationFileError('Source update file read is incomplete')
        return raw

    def digest(self, limit):
        """Hash a complete held file with at most64KiB payload allocation."""
        import hashlib
        self.check()
        if self.initial['bytes'] > limit:
            raise ActivationFileError('Source update file exceeds its digest bound')
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest, total = hashlib.sha256(), 0
        while True:
            raw = os.read(self.fd, min(65536, limit + 1 - total))
            if not raw:
                break
            total += len(raw)
            if total > limit:
                raise ActivationFileError('Source update file grew during digest')
            digest.update(raw)
        self.check()
        if total != self.initial['bytes']:
            raise ActivationFileError('Source update digest read was incomplete')
        return digest.hexdigest(), total

    def append(self, raw, limit):
        self.check()
        if self.initial['bytes'] + len(raw) > limit:
            raise ActivationFileError('Source update journal exceeds its bound')
        os.lseek(self.fd, 0, os.SEEK_END)
        offset = 0
        while offset < len(raw):
            count = os.write(self.fd, raw[offset:offset + 65536])
            if count <= 0:
                raise ActivationFileError('Source update journal write was incomplete')
            offset += count
        os.fsync(self.fd)
        info = os.fstat(self.fd)
        if (str(info.st_dev), str(info.st_ino)) != (self.initial['device'], self.initial['inode']):
            raise ActivationFileError('Source update journal identity changed')
        self.initial = identity(info)
        self.check()

    def _information(self, kind, value):
        import msvcrt
        from ctypes import wintypes as w
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        setter = api.SetFileInformationByHandle
        setter.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
        setter.restype = w.BOOL
        if not setter(msvcrt.get_osfhandle(self.fd), kind, ctypes.byref(value), ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())

    def rename(self, target):
        self.check()
        target = Path(os.path.abspath(target))
        plain_path(target.parent, directory=True)
        if os.path.lexists(target):
            raise ActivationFileError('A source update destination appeared')
        if os.name == 'nt':
            from ctypes import wintypes as w
            encoded = str(target).encode('utf-16-le')
            class Rename(ctypes.Structure):
                _fields_ = [('replace', w.BOOLEAN), ('root', w.HANDLE), ('length', w.DWORD),
                            ('name', ctypes.c_byte * (len(encoded) + 2))]
            request = Rename()
            request.length = len(encoded)
            request.name[:len(encoded)] = encoded
            self._information(3, request)
        else:
            os.link(self.path, target, follow_symlinks=False)
            if identity(target.lstat()) != self.initial:
                raise ActivationFileError('Source update publication changed identity')
            os.unlink(self.path)
        self.path = target
        self._check_snapshot(windows_rename_completed=os.name == 'nt')

    def delete(self):
        self.check()
        if os.name == 'nt':
            from ctypes import wintypes as w
            class Disposition(ctypes.Structure):
                _fields_ = [('flags', w.DWORD)]
            self._information(21, Disposition(0x11))
        else:
            os.unlink(self.path)

    def close(self):
        if self.close_held:
            raise ActivationFileCloseHeld('Source update descriptor close remains held')
        if self.fd < 0:
            return
        descriptor, self.fd = self.fd, -1
        try:
            os.close(descriptor)
        except BaseException as error:
            self.close_held = True
            _CLOSE_HOLDS.append((self, descriptor))
            raise ActivationFileCloseHeld('Source update descriptor close remains held') from error

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def read_exact(path, limit):
    with RetainedFile(path) as held:
        return held.read(limit)


def write_new(path, raw):
    if _CLOSE_HOLDS:
        raise ActivationFileCloseHeld('Prior source update resource retirement remains held')
    path = Path(os.path.abspath(path))
    plain_path(path.parent, directory=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:offset + 65536])
            if written <= 0:
                raise ActivationFileError('Source update write was incomplete')
            offset += written
        os.fsync(fd)
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            _CLOSE_HOLDS.append(('exclusive-write', path, fd))
            raise ActivationFileCloseHeld('Source update write descriptor close remains held') from error
    if read_exact(path, len(raw)) != raw:
        raise ActivationFileError('Source update staged write did not verify')


def _matches_owner_rights_acl(*, owner_matches_current, protected, entries):
    # Exact CPython Windows mkdir(mode=0o700) profile; no subset acceptance.
    expected = ((0, 3, 2032127, 'S-1-3-4'), (0, 3, 2032127, 'S-1-5-18'),
                (0, 3, 2032127, 'S-1-5-32-544'))
    return (owner_matches_current is True and protected is True
            and type(entries) is tuple and len(entries) == 3
            and all(type(entry) is tuple and len(entry) == 4
                    and all(type(value) is int for value in entry[:3])
                    and type(entry[3]) is str for entry in entries)
            and sorted(entries) == sorted(expected))


def private_owner_rights_directory(path):
    # Exact current-owner protected CPython directory profile; never modify ACLs.
    path = plain_path(path, directory=True)
    if os.name != 'nt':
        return False
    import ctypes
    from ctypes import wintypes as w

    class AclSize(ctypes.Structure):
        _fields_ = [('count', w.DWORD), ('used', w.DWORD), ('free', w.DWORD)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    kernel.LocalFree.argtypes = [w.LPVOID]
    kernel.LocalFree.restype = w.LPVOID
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID)]
    advapi.GetNamedSecurityInfoW.restype = w.DWORD
    advapi.IsValidSecurityDescriptor.argtypes = [w.LPVOID]
    advapi.IsValidSecurityDescriptor.restype = w.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [w.LPVOID, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = w.BOOL
    advapi.EqualSid.argtypes = [w.LPVOID, w.LPVOID]
    advapi.EqualSid.restype = w.BOOL
    advapi.IsValidSid.argtypes = [w.LPVOID]
    advapi.IsValidSid.restype = w.BOOL
    advapi.GetLengthSid.argtypes = [w.LPVOID]
    advapi.GetLengthSid.restype = w.DWORD
    advapi.IsValidAcl.argtypes = [w.LPVOID]
    advapi.IsValidAcl.restype = w.BOOL
    advapi.GetAclInformation.argtypes = [w.LPVOID, w.LPVOID, w.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = w.BOOL
    advapi.GetAce.argtypes = [w.LPVOID, w.DWORD, ctypes.POINTER(w.LPVOID)]
    advapi.GetAce.restype = w.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = w.BOOL
    token, descriptor = w.HANDLE(), w.LPVOID()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = w.DWORD()
        ctypes.set_last_error(0)
        initial = advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if initial or ctypes.get_last_error() != 122 or not ctypes.sizeof(w.LPVOID) <= size.value <= 4096:
            raise ValueError('Current token user sizing was not bounded and exact')
        user = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, user, size.value, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not ctypes.sizeof(w.LPVOID) <= size.value <= len(user):
            raise ValueError('Current token user result exceeded its retained buffer')
        user_sid = ctypes.cast(user, ctypes.POINTER(w.LPVOID))[0]
        start = ctypes.addressof(user)
        if (not user_sid or not start + ctypes.sizeof(w.LPVOID) <= user_sid <= start + size.value - 8
                or not advapi.IsValidSid(user_sid)
                or advapi.GetLengthSid(user_sid) > start + size.value - user_sid):
            raise ValueError('Current token user SID lacked retained-buffer custody')
        owner, acl = w.LPVOID(), w.LPVOID()
        result = advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None,
                                              ctypes.byref(acl), None, ctypes.byref(descriptor))
        if result:
            raise ctypes.WinError(result)
        if not descriptor or not owner or not acl or not advapi.IsValidSecurityDescriptor(descriptor):
            return False
        control, revision = w.WORD(), w.DWORD()
        if not advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        protected = bool(control.value & 0x1000) and bool(control.value & 0x0004)
        owner_matches = bool(advapi.IsValidSid(owner) and advapi.EqualSid(owner, user_sid))
        if not protected or not owner_matches or not advapi.IsValidAcl(acl):
            return False
        info = AclSize()
        if not advapi.GetAclInformation(acl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.count != 3 or not 8 <= info.used <= 4096:
            return False
        entries = []
        for index in range(3):
            ace = w.LPVOID()
            if not advapi.GetAce(acl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not ace or not acl.value + 8 <= ace.value <= acl.value + info.used - 8:
                return False
            header = ctypes.string_at(ace, 4)
            ace_size = int.from_bytes(header[2:4], 'little')
            if (header[0] != 0 or header[1] != 3 or not 20 <= ace_size <= 68
                    or ace.value + ace_size > acl.value + info.used):
                return False
            raw = ctypes.string_at(ace, ace_size)
            sid = w.LPVOID(ace.value + 8)
            if not advapi.IsValidSid(sid) or advapi.GetLengthSid(sid) != ace_size - 8:
                return False
            text = w.LPWSTR()
            try:
                if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                    raise ctypes.WinError(ctypes.get_last_error())
                entries.append((header[0], header[1], int.from_bytes(raw[4:8], 'little'), text.value))
            finally:
                if text and kernel.LocalFree(text):
                    _CLOSE_HOLDS.append(('acl-sid', kernel, text))
                    raise OSError('Query-only ACE SID allocation cleanup was not proven')
        return _matches_owner_rights_acl(owner_matches_current=owner_matches,
                                                protected=protected, entries=tuple(entries))
    finally:
        cleanup_failed = []
        if descriptor and kernel.LocalFree(descriptor):
            _CLOSE_HOLDS.append(('acl-descriptor', kernel, descriptor))
            cleanup_failed.append('security descriptor')
        if token and not kernel.CloseHandle(token):
            _CLOSE_HOLDS.append(('acl-token', kernel, token))
            cleanup_failed.append('query-only token')
        if cleanup_failed:
            raise OSError('One-shot query cleanup was not proven: ' + ', '.join(cleanup_failed))



class ActivationLock:
    """One purpose-specific fail-fast lock for a private activation operation."""
    def __init__(self, path):
        self.retained = None
        path = plain_path(path)
        if not os.path.lexists(path):
            try:
                write_new(path, b'\0')
            except FileExistsError:
                pass
        self.retained = RetainedFile(path, writable=True)
        try:
            if self.retained.initial['bytes'] != 1 or self.retained.read(1) != b'\0':
                raise ActivationFileError('Source activation lock is invalid')
            os.lseek(self.retained.fd, 0, os.SEEK_SET)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.retained.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.retained.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.retained.close()
            raise

    def close(self):
        if self.retained is not None:
            retained, self.retained = self.retained, None
            try:
                os.lseek(retained.fd, 0, os.SEEK_SET)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(retained.fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(retained.fd, fcntl.LOCK_UN)
            finally:
                retained.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
