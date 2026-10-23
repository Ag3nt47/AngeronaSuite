"""Compatible directory custody must not weaken leaf-file write authority."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import source_sandbox
from angerona.core.executable_trust import _open_sealed


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows directory sharing composition')


def _challenge(parent: Path) -> None:
    moved = parent.with_name(parent.name + '-unexpected-move')
    try:
        parent.rename(moved)
    except OSError as exc:
        assert exc.winerror in (5, 32), exc
    else:
        moved.rename(parent)
        pytest.fail('Writer directory guard did not retain rename custody')


def test_atomic_directory_denial_does_not_retry_delete_or_weaker_access(tmp_path, monkeypatch):
    """Inert API doubles refuse the first open and every later operation."""
    calls = []

    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    def denied(path, access, share, security, disposition, flags, template):
        calls.append((path, access, share, security, disposition, flags, template))
        ctypes.set_last_error(5)
        return ctypes.c_void_p(-1).value

    def forbidden(*_args):
        pytest.fail('An operation followed denied directory custody')

    kernel = SimpleNamespace(CreateFileW=Function(denied))
    for name in ('CloseHandle', 'GetFinalPathNameByHandleW', 'WriteFile', 'FlushFileBuffers',
                 'MoveFileExW', 'SetFileInformationByHandle', 'GetFileInformationByHandle'):
        setattr(kernel, name, Function(forbidden))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *_args, **_kwargs: kernel)
    with pytest.raises(OSError):
        source_sandbox._atomic_bytes_write(tmp_path / 'refused.bin', b'fixture', root=tmp_path)
    assert calls == [(str(tmp_path), 0x81, 3, None, 3, 0x02200000, None)]
    assert not (tmp_path / 'refused.bin').exists()


def test_nested_directory_guards_allow_exact_atomic_file_write(tmp_path):
    root = tmp_path / 'owned-root'
    parent = root / 'nested'
    parent.mkdir(parents=True)
    target = parent / 'fixture.bin'
    with source_sandbox._hold_plain_directories(root, parent):
        source_sandbox._atomic_bytes_write(target, b'bounded fixture', root=root)
        assert target.read_bytes() == b'bounded fixture'
        _challenge(root)
        _challenge(parent)
    parent.rename(root / 'nested-released')
    root.rename(tmp_path / 'owned-root-released')
    assert (tmp_path / 'owned-root-released/nested-released/fixture.bin').read_bytes() == b'bounded fixture'


def test_atomic_writer_alone_denies_directory_rename_before_temp_file_open(tmp_path, monkeypatch):
    root = tmp_path / 'owned-root'
    parent = root / 'nested'
    parent.mkdir(parents=True)
    target = parent / 'fixture.bin'
    token = source_sandbox.secrets.token_hex
    challenged = []

    def before_temp_open(length):
        # The writer has acquired only its directory handles at this point.
        # No outer read guard or leaf-file handle can supply the protection.
        assert not target.exists() and not list(parent.iterdir())
        _challenge(root)
        _challenge(parent)
        challenged.append(True)
        return token(length)

    monkeypatch.setattr(source_sandbox.secrets, 'token_hex', before_temp_open)
    source_sandbox._atomic_bytes_write(target, b'bounded fixture', root=root)
    assert challenged == [True] and target.read_bytes() == b'bounded fixture'
    parent.rename(root / 'nested-released')
    root.rename(tmp_path / 'owned-root-released')


def test_compatible_directory_guard_never_bypasses_sealed_leaf(tmp_path):
    root = tmp_path / 'owned-root'
    root.mkdir()
    target = root / 'fixture.bin'
    target.write_bytes(b'original fixture')
    with source_sandbox._hold_plain_directories(root), _open_sealed(target) as held:
        with pytest.raises(OSError):
            source_sandbox._atomic_bytes_write(target, b'replacement fixture', root=root)
        assert held.read() == b'original fixture'
        assert target.read_bytes() == b'original fixture'
        assert sorted(path.name for path in root.iterdir()) == ['fixture.bin']
    source_sandbox._atomic_bytes_write(target, b'replacement fixture', root=root)
    assert target.read_bytes() == b'replacement fixture'
