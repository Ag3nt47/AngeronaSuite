"""Read-only admission for the separately installed protection service.

The signed installer must provision the exact virtual account, restricted SID,
process policy and private state tree. This module never installs a service,
rewrites an ACL, enrolls a publisher, or repairs rejected key material. A service
SID separates the desktop account; it does not resist administrators or provide
PPL/ELAM protection. MSIX service metadata alone cannot provision this profile.
"""
from __future__ import annotations

from dataclasses import dataclass
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys

SERVICE_NAME = "AngeronaProtection"
SERVICE_ACCOUNT = "NT SERVICE\\" + SERVICE_NAME
_SERVICE_SID = re.compile(r"S-1-5-80-(?:[0-9]+-){4}[0-9]+\Z")
_SYSTEM = "S-1-5-18"
_ADMINISTRATORS = "S-1-5-32-544"
_ACTIVE = None
_NATIVE_RETIREMENT_HOLD = None


class ServiceCustodyCleanupError(PermissionError):
    """An owned native query resource did not prove a successful close."""


def _close_auxiliary(handles):
    global _NATIVE_RETIREMENT_HOLD

    uncertain = []
    for handle in reversed(handles):
        try:
            handle.Close()
        except BaseException:
            uncertain.append(handle)
            try:
                handle.Detach()
            except BaseException:
                pass  # Retain the exact owner; no reused-number retry.
    if uncertain:
        _NATIVE_RETIREMENT_HOLD = (*(_NATIVE_RETIREMENT_HOLD or ()), *uncertain)
        raise ServiceCustodyCleanupError("Protection native auxiliary retirement remains unproven")


@dataclass(frozen=True)
class AccessDescriptor:
    owner: str
    protected: bool
    # ACE type, flags, mask, canonical SID. Unsupported ACEs are refused.
    entries: tuple[tuple[int, int, int, str], ...]


@dataclass(frozen=True)
class ServiceRegistration:
    pid: int
    state: int
    service_type: int
    command: str
    account: str
    sid_type: int
    descriptor: AccessDescriptor


@dataclass(frozen=True)
class TokenObservation:
    user: str
    owner: str
    session: int
    groups: tuple[tuple[str, int], ...]
    restricted: tuple[tuple[str, int], ...]


def _local_path(path: Path) -> Path:
    value = str(path)
    parsed = PureWindowsPath(value)
    if (not parsed.is_absolute() or len(parsed.drive) != 2 or parsed.drive[1] != ":"
            or not parsed.drive[0].isascii() or not parsed.drive[0].isalpha()
            or ".." in parsed.parts or ":" in value[2:]
            or any(ord(char) < 32 for char in value)):
        raise PermissionError("Protection custody requires an absolute local DOS path")
    return Path(path)


def check_descriptor(descriptor: AccessDescriptor, trusted: frozenset[str], *,
                     outside_allowed: int = 0, protected: bool = False,
                     service_sid: str | None = None) -> None:
    """Conservative grant inspection; deny ACEs never supply authority."""
    if (type(descriptor) is not AccessDescriptor or descriptor.owner not in trusted
            or type(descriptor.protected) is not bool or protected and not descriptor.protected
            or type(descriptor.entries) is not tuple or not 1 <= len(descriptor.entries) <= 64):
        raise PermissionError("Protection object owner or protected DACL is unavailable")
    service_full = service_sid is None
    for entry in descriptor.entries:
        if (type(entry) is not tuple or len(entry) != 4
                or any(type(value) is not int for value in entry[:3])
                or not 0 <= entry[2] <= 0xFFFFFFFF or type(entry[3]) is not str):
            raise PermissionError("Protection DACL has malformed grants")
        kind, flags, mask, sid = entry
        if not 0 <= flags <= 0xFF:
            raise PermissionError("Protection DACL has malformed ACE flags")
        if flags & 0x08:  # INHERIT_ONLY_ACE does not grant this object access.
            continue
        if kind == 1:  # ACCESS_DENIED_ACE_TYPE
            continue
        if kind != 0:
            raise PermissionError("Protection DACL has unsupported grants")
        if sid not in trusted and mask & ~outside_allowed:
            raise PermissionError("Protection object grants access outside its service boundary")
        if sid == service_sid and (mask & 0x10000000 or mask & 0x1F01FF == 0x1F01FF):
            service_full = True
    if not service_full:
        raise PermissionError("Private protection state lacks a service SID full-control grant")


def verify_registration(value: ServiceRegistration, *, pid: int, image: Path,
                        service_sid: str, installed_writers: frozenset[str]) -> None:
    from .werfault_guard import windows_arguments

    if (type(value) is not ServiceRegistration or any(type(field) is not int for field in
            (value.pid, value.state, value.service_type, value.sid_type)) or value.pid != pid or value.state != 4
            or value.service_type != 0x10 or value.sid_type != 3
            or type(value.account) is not str or value.account.casefold() != SERVICE_ACCOUNT.casefold()):
        raise PermissionError("Protection SCM PID, own-process account or restricted SID policy differs")
    try:
        arguments = windows_arguments(value.command)
        command_image = _local_path(Path(arguments[0])) if arguments else None
    except (ValueError, TypeError, PermissionError) as exc:
        raise PermissionError("Protection SCM command is malformed") from exc
    if (len(arguments) != 2 or arguments[1] != "--engine-service"
            or ntpath.normcase(str(command_image)) != ntpath.normcase(str(image))):
        raise PermissionError("Protection SCM command is not the exact installed engine invocation")
    # Public query/interrogate/read-control are harmless; start/stop/configure,
    # generic-execute/write/all, deletion and owner/DACL changes are forbidden.
    check_descriptor(value.descriptor, installed_writers, outside_allowed=0x8012008D)
    if not _SERVICE_SID.fullmatch(service_sid):
        raise PermissionError("Protection service SID is unavailable")


def verify_token(value: TokenObservation, service_sid: str) -> None:
    if (type(value) is not TokenObservation or value.user != service_sid
            or value.owner != service_sid or type(value.session) is not int or value.session != 0
            or type(value.groups) is not tuple or type(value.restricted) is not tuple
            or len(value.groups) > 256 or len(value.restricted) > 256):
        raise PermissionError("Protection process is not the dedicated Session 0 virtual account")
    for rows in (value.groups, value.restricted):
        if any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
               or type(row[1]) is not int for row in rows):
            raise PermissionError("Protection token group observation is malformed")
    if not any(sid == service_sid and not flags & 0x10 for sid, flags in value.restricted):
        raise PermissionError("Protection process lacks its actual restricted service SID")
    if any(sid == _ADMINISTRATORS and flags & 4 and not flags & 0x10 for sid, flags in value.groups):
        raise PermissionError("Protection virtual account unexpectedly has enabled Administrator membership")


def _descriptor(value) -> AccessDescriptor:
    import win32security

    owner = value.GetSecurityDescriptorOwner()
    acl = value.GetSecurityDescriptorDacl()
    if owner is None or acl is None or acl.GetAceCount() > 64:
        raise PermissionError("Protection object has no bounded owner/DACL")
    entries = []
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if len(ace) != 3 or ace[0][0] not in (0, 1):
            raise PermissionError("Protection DACL contains unsupported ACEs")
        entries.append((int(ace[0][0]), int(ace[0][1]), int(ace[1]),
                        win32security.ConvertSidToStringSid(ace[2])))
    return AccessDescriptor(win32security.ConvertSidToStringSid(owner),
                            bool(value.GetSecurityDescriptorControl()[0] & 0x1000), tuple(entries))


def fixed_state_root() -> Path:
    """Native machine known-folder query; no environment or user profile."""
    from .privilege import _windows_known_folder

    return _local_path(_windows_known_folder(0x23)) / "Angerona" / "Protection"


class _NativeCustody:
    def __init__(self, pid: int | None = None):
        from .windows_process_lease import _Native

        if _NATIVE_RETIREMENT_HOLD is not None:
            raise ServiceCustodyCleanupError("Protection native observer retirement remains held")
        self.native = _Native()
        self.process = self.native.open(os.getpid() if pid is None else pid, 0x121000, False)
        self._close_error = ""

    def identity(self):
        if self.process is None or self.native.wait(self.process, 0):
            raise PermissionError("Protection process generation is no longer live")
        return self.native.identity(self.process)

    def service_sid(self):
        import win32security

        sid, _domain, _kind = win32security.LookupAccountName(None, SERVICE_ACCOUNT)
        result = win32security.ConvertSidToStringSid(sid)
        if not _SERVICE_SID.fullmatch(result):
            raise PermissionError("Protection service SID has not been provisioned")
        return result

    def installed_writers(self):
        import win32security

        sid, _domain, _kind = win32security.LookupAccountName(None, "NT SERVICE\\TrustedInstaller")
        return frozenset({_SYSTEM, _ADMINISTRATORS, win32security.ConvertSidToStringSid(sid)})

    def registration(self):
        import win32service

        scm = service = None
        owned = []
        try:
            scm = win32service.OpenSCManager(None, None, 1)
            owned.append(scm)
            service = win32service.OpenService(scm, SERVICE_NAME, 0x20005)
            owned.append(service)
            status = win32service.QueryServiceStatusEx(service)
            config = win32service.QueryServiceConfig(service)
            return ServiceRegistration(status.get("ProcessId"), status.get("CurrentState"), config[0],
                config[3], config[7], win32service.QueryServiceConfig2(service, 5),
                _descriptor(win32service.QueryServiceObjectSecurity(service, 0x5)))
        finally:
            _close_auxiliary(owned)

    def token(self):
        import win32security

        token = win32security.OpenProcessToken(int(self.process), 8)
        try:
            get = lambda kind: win32security.GetTokenInformation(token, kind)
            rows = lambda kind: tuple((win32security.ConvertSidToStringSid(sid), int(flags)) for sid, flags in get(kind))
            return TokenObservation(win32security.ConvertSidToStringSid(get(win32security.TokenUser)[0]),
                win32security.ConvertSidToStringSid(get(win32security.TokenOwner)), get(win32security.TokenSessionId),
                rows(win32security.TokenGroups), rows(win32security.TokenRestrictedSids))
        finally:
            _close_auxiliary([token])

    def process_descriptor(self):
        import win32security

        return _descriptor(win32security.GetSecurityInfo(int(self.process), win32security.SE_KERNEL_OBJECT, 0x5))

    def package_root(self):
        from .privileged_pipe import _native_package_string, _package_path
        from . import windows_package_identity as pins

        family = _native_package_string("GetPackageFamilyName", self.process)
        full = _native_package_string("GetPackageFullName", self.process)
        authority = pins.verify_current_msix_authority(query=lambda: pins.NativePackageIdentity(full, family))
        if not authority.trusted:
            raise PermissionError(authority.reason)
        return _local_path(_package_path(full))

    def path_descriptor(self, path):
        import win32security

        return _descriptor(win32security.GetFileSecurity(str(path), 0x5))

    def verify_path(self, path, *, directory, service_sid, installed_writers, private=False):
        target = _local_path(Path(path))
        private_writers = frozenset({_SYSTEM, _ADMINISTRATORS, service_sid})
        private_root = fixed_state_root() if private else None
        if private and not target.is_relative_to(private_root):
            raise PermissionError("Protection private path is outside the fixed machine state root")
        for index, item in enumerate((target, *target.parents)):
            observed = item.lstat()
            if stat.S_ISLNK(observed.st_mode) or getattr(observed, "st_file_attributes", 0) & 0x400:
                raise PermissionError("Protection custody cannot traverse reparse points")
            if index == 0 and not (stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode)):
                raise PermissionError("Protection object has an unexpected type")
            if index == 0 and not directory and observed.st_nlink != 1:
                raise PermissionError("Protection file has multiple links")
            descriptor = self.path_descriptor(item)
            if private and item.is_relative_to(private_root):
                check_descriptor(descriptor, private_writers, protected=item == private_root,
                                 service_sid=service_sid)
            else:
                # Read/execute outside installed authority is allowed. A parent
                # may offer unrelated create slots, but cannot delete/replace
                # its existing protected child or change owner/DACL.
                forbidden = 0xD0040 if index else (0xD0156 if directory else 0xD0116)
                for kind, flags, mask, sid in descriptor.entries:
                    if not flags & 8 and kind == 0 and sid not in installed_writers and mask & (forbidden | 0x50000000):
                        raise PermissionError("Protection installed ancestry permits untrusted replacement")
                if descriptor.owner not in installed_writers or not descriptor.entries:
                    raise PermissionError("Protection installed ancestry has an untrusted owner or empty DACL")
        return target

    def close(self):
        global _NATIVE_RETIREMENT_HOLD

        if self._close_error:
            raise ServiceCustodyCleanupError("Protection native observer retirement remains unproven")
        process, self.process = self.process, None
        if process is not None:
            try:
                self.native.close(process)  # Discard an ambiguous number; never retry.
            except BaseException as exc:
                self._close_error = type(exc).__name__
                _NATIVE_RETIREMENT_HOLD = (*(_NATIVE_RETIREMENT_HOLD or ()), self)
                raise ServiceCustodyCleanupError("Protection native observer retirement remains unproven") from exc


class EngineCustody:
    """One retained admitted generation; no wire/exported credential."""
    def __init__(self, native, identity, service_sid, root, installed_writers):
        self._native, self._identity, self._service_sid = native, identity, service_sid
        self._root, self._installed_writers = root, installed_writers
        self._closed = False
        self._close_error = ""

    @property
    def identity(self):
        return self._identity

    @property
    def service_sid(self):
        return self._service_sid

    @property
    def root(self):
        return self._root

    def verify_private_path(self, path: Path, *, directory=False) -> Path:
        target = _local_path(Path(path))
        if self._closed or not target.is_relative_to(self.root) or self._native.identity() != self.identity:
            raise PermissionError("Protection private path is outside this live admitted service")
        return self._native.verify_path(target, directory=directory, service_sid=self.service_sid,
                                        installed_writers=self._installed_writers, private=True)

    def close(self):
        global _ACTIVE
        if _ACTIVE is self:
            _ACTIVE = None
        if not self._closed:
            self._closed = True
            try:
                self._native.close()
            except Exception as exc:
                self._close_error = type(exc).__name__
                raise PermissionError("Protection custody cleanup remains unproven") from exc
        elif self._close_error:
            raise PermissionError("Protection custody cleanup remains unproven: " + self._close_error)


def active_engine_custody() -> EngineCustody | None:
    """Memory-only profile selection; no environment string enables it."""
    return _ACTIVE if _ACTIVE is not None and not _ACTIVE._closed and _ACTIVE.identity.pid == os.getpid() else None


def _verify_native(native, *, include_state: bool):
    from .windows_process_lease import ProcessObjectIdentity

    identity = native.identity()
    if type(identity) is not ProcessObjectIdentity:
        raise PermissionError("Protection native process identity is unavailable")
    image = _local_path(Path(identity.image))
    service_sid, writers = native.service_sid(), native.installed_writers()
    verify_registration(native.registration(), pid=identity.pid, image=image,
                        service_sid=service_sid, installed_writers=writers)
    verify_token(native.token(), service_sid)
    # Outside callers may query identity/read security metadata, never read VM,
    # write VM, duplicate handles, suspend, terminate or change process security.
    check_descriptor(native.process_descriptor(), frozenset({_SYSTEM, _ADMINISTRATORS, service_sid}),
                     outside_allowed=0x121000)
    package = native.package_root()
    if not image.is_relative_to(package):
        raise PermissionError("Protection image is outside its OS-bound installed package")
    native.verify_path(package, directory=True, service_sid=service_sid, installed_writers=writers)
    native.verify_path(image, directory=False, service_sid=service_sid, installed_writers=writers)
    root = fixed_state_root() if include_state else None
    if include_state:
        native.verify_path(root, directory=True, service_sid=service_sid, installed_writers=writers, private=True)
    if native.identity() != identity:
        raise PermissionError("Protection process changed during custody admission")
    return identity, service_sid, writers, root


def prepare_engine_custody(*, _native=None) -> EngineCustody:
    """Verify before importing Config, reading keys or constructing sensors."""
    global _ACTIVE
    from .engine_windows_service import require_package_service

    require_package_service()
    if tuple(sys.argv[1:]) != ("--engine-service",) or _ACTIVE is not None:
        raise PermissionError("Protection service requires one exact fresh SCM invocation")
    native = _NativeCustody() if _native is None else _native
    try:
        identity, sid, writers, root = _verify_native(native, include_state=True)
        if identity.pid != os.getpid():
            raise PermissionError("Protection admission did not observe the actual current process")
        custody = EngineCustody(native, identity, sid, root, writers)
        _ACTIVE = custody
        return custody
    except BaseException:
        native.close()
        raise


def verify_protection_service_process(process, pid):
    """Status client proves retained peer generation before sending a request."""
    from .windows_process_lease import _Native

    expected = _Native().identity(int(process))
    native = _NativeCustody(pid)
    try:
        identity, _sid, _writers, _root = _verify_native(native, include_state=False)
        if identity != expected or identity.pid != pid:
            raise PermissionError("Protection pipe peer differs from its retained native process")
    finally:
        native.close()
