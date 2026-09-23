"""Catalog custody must cover the loader namespace as well as the executable."""
from __future__ import annotations

import hashlib
import sys
from types import SimpleNamespace

import pytest

from angerona.core import analysis_qemu_runtime as runtime


@pytest.fixture
def native_acl(monkeypatch):
    state = {'owner': 'S-1-5-32-544', 'aces': [((0, 0), 0x1F01FF, 'S-1-5-32-544'),
                                          ((0, 0), 0x1200A9, 'S-1-5-32-545')]}
    class Descriptor:
        def GetSecurityDescriptorOwner(self):
            return state['owner']
        def GetSecurityDescriptorDacl(self):
            if state['aces'] is None:
                return None
            return SimpleNamespace(GetAceCount=lambda: len(state['aces']),
                                   GetAce=lambda index: state['aces'][index])
    monkeypatch.setitem(sys.modules, 'win32security', SimpleNamespace(
        SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1, DACL_SECURITY_INFORMATION=4,
        ACCESS_ALLOWED_ACE_TYPE=0, ACCESS_DENIED_ACE_TYPE=1,
        ConvertSidToStringSid=lambda value: value,
        GetNamedSecurityInfo=lambda *_args: Descriptor(),
    ))
    return state


def test_users_may_read_admin_owned_runtime(native_acl, tmp_path):
    runtime._protected_acl(tmp_path)


def test_program_files_creator_owner_template_is_not_effective_write(native_acl, tmp_path):
    native_acl['aces'].append(((0, 0x0B), 0x1F01FF, 'S-1-3-0'))
    runtime._protected_acl(tmp_path)


@pytest.mark.parametrize('mask', [2, 4, 16, 64, 256, 0x10000, 0x40000, 0x80000,
                                  0x10000000, 0x40000000])
def test_any_non_admin_write_authority_rejected(native_acl, tmp_path, mask):
    native_acl['aces'].append(((0, 0), mask, 'S-1-5-21-123'))
    with pytest.raises(ValueError, match='non-administrator'):
        runtime._protected_acl(tmp_path)


@pytest.mark.parametrize('case', ['owner', 'null', 'object-ace'])
def test_ambiguous_or_user_owned_namespace_rejected(native_acl, tmp_path, case):
    if case == 'owner':
        native_acl['owner'] = 'S-1-5-21-123'
    elif case == 'null':
        native_acl['aces'] = None
    else:
        native_acl['aces'].append(((5, 0), 0x1F01FF, 'S-1-5-21-123'))
    with pytest.raises(ValueError):
        runtime._protected_acl(tmp_path)


@pytest.fixture
def installed(monkeypatch, tmp_path):
    directory = tmp_path / 'runtime'
    (directory / 'share').mkdir(parents=True)
    content = b'reviewed test artifact'
    (directory / 'qemu-system-x86_64.exe').write_bytes(content)
    catalog = {'qemu-system-x86_64.exe': {'size': len(content),
                                       'sha256': hashlib.sha256(content).hexdigest()}}
    monkeypatch.setitem(sys.modules, 'angerona.core.analysis_qemu_catalog', SimpleNamespace(FILES=catalog))
    monkeypatch.setattr(runtime, 'installation', lambda: directory)
    monkeypatch.setattr(runtime, '_require_unprivileged', lambda: None)
    monkeypatch.setattr(runtime, '_protected_acl', lambda _path: None)
    return directory


def test_exact_file_set_verified_and_held(installed):
    with runtime.trusted_installation() as actual:
        assert actual == installed


@pytest.mark.parametrize('name', ['injected.dll', 'share/linuxboot_dma.bin', 'lib'])
def test_unlisted_loader_namespace_entry_rejected(installed, name):
    (installed / name).write_bytes(b'untrusted')
    with pytest.raises(ValueError, match='Unexpected|file set'):
        with runtime.trusted_installation():
            pytest.fail('Unexpected loader input was accepted')


def test_changed_same_size_executable_rejected(installed):
    path = installed / 'qemu-system-x86_64.exe'
    path.write_bytes(b'x' * path.stat().st_size)
    with pytest.raises(ValueError, match='catalog'):
        with runtime.trusted_installation():
            pytest.fail('Modified executable was accepted')


def test_missing_firmware_does_not_fall_back(installed):
    (installed / 'qemu-system-x86_64.exe').unlink()
    with pytest.raises(ValueError, match='file set'):
        with runtime.trusted_installation():
            pytest.fail('Incomplete runtime was accepted')
