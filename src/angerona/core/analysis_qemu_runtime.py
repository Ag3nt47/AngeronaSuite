"""Exact catalog and protected namespace custody for the Windows Lab emulator.

The distributor's installer checksum is an explicit catalog trust decision,
not an Authenticode claim. Runtime files additionally require administrator
ownership, restrictive ACLs, and held read-only file handles for the entire VM.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import platform
from pathlib import Path

from angerona.core.executable_trust import _open_sealed
from angerona.core.github_tool_catalog import _require_unprivileged
from angerona.core.source_sandbox import _hold_plain_directories, _validate_regular_file

RUNTIME_DIRECTORY = 'AngeronaAnalysisQEMU-11.1.0'
_OWNERS = frozenset({'S-1-5-18', 'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'})
# File/directory write, append, attributes, delete-child, delete, DACL and owner.
_WRITE_ACCESS = 0x00000156 | 0x000D0000 | 0x50000000


def require_user_session() -> None:
    try:
        _require_unprivileged()
    except PermissionError:
        raise PermissionError('Analysis Lab requires a normal, non-administrator Angerona session.') from None


def installation() -> Path:
    if os.name != 'nt' or platform.machine().lower() not in {'amd64', 'x86_64'}:
        raise ValueError('Analysis Lab currently requires 64-bit Windows on an Intel or AMD processor.')
    from angerona.core.privilege import _windows_known_folder
    path = _windows_known_folder(0x26) / RUNTIME_DIRECTORY
    if not path.is_dir():
        raise ValueError('Set up the optional Analysis Lab emulator, then prepare its reviewed runtime.')
    return path


def _protected_acl(path: Path) -> None:
    """Reject every non-administrator write authority, including object ACEs."""
    import win32security
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in _OWNERS:
        raise ValueError('The Lab emulator must be owned by Windows administrators.')
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise ValueError('The Lab emulator has an unrestricted access list.')
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if ace[0][1] & 0x08:  # INHERIT_ONLY: no rights on this object.
            continue
        kind = ace[0][0]
        if kind == win32security.ACCESS_DENIED_ACE_TYPE:
            continue  # Deny entries cannot create write authority.
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise ValueError('The Lab emulator has an unsupported access-control entry.')
        if ace[1] & _WRITE_ACCESS and win32security.ConvertSidToStringSid(ace[2]) not in _OWNERS:
            raise ValueError('The Lab emulator directory permits non-administrator changes.')


@contextlib.contextmanager
def trusted_installation():
    from angerona.core.analysis_qemu_catalog import FILES
    require_user_session()
    directory = installation()
    with contextlib.ExitStack() as stack:
        stack.enter_context(_hold_plain_directories(directory / 'share'))
        # The Program Files directory and emulator namespace must both deny
        # planting new DLLs/modules, not just replacement of existing files.
        for path in (directory.parent, directory, directory / 'share'):
            _protected_acl(path)
        if not FILES or len(FILES) > 200:
            raise ValueError('The reviewed emulator file catalog is unavailable.')
        names = set()
        for parent in (directory, directory / 'share'):
            for path in parent.iterdir():
                if path == directory / 'share':
                    continue
                names.add(path.relative_to(directory).as_posix())
                if len(names) > len(FILES):
                    raise ValueError('Unexpected files in the protected Lab emulator directory.')
        if names != set(FILES):
            raise ValueError('The protected Lab emulator file set differs from its reviewed catalog.')
        for name, expected in FILES.items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts or len(relative.parts) > 2:
                raise ValueError('Invalid emulator catalog path.')
            path = directory / relative
            _validate_regular_file(path)
            _protected_acl(path)
            handle = stack.enter_context(_open_sealed(path))
            held = os.fstat(handle.fileno())
            if held.st_nlink != 1 or held.st_size != expected['size']:
                raise ValueError('The Lab emulator file identity changed; repeat setup.')
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
            if digest.hexdigest() != expected['sha256']:
                raise ValueError('The Lab emulator differs from its reviewed catalog; repeat setup.')
        yield directory
