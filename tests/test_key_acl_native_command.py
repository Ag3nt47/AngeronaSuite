"""Inert native key-ACL trust and completion failures; no real ACL commands."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import hardening, privilege, windows_engine_custody


@pytest.fixture
def native_key(tmp_path, monkeypatch):
    native = tmp_path / "trusted-system"
    native.mkdir()
    (native / "icacls.exe").write_bytes(b"inert")
    target = tmp_path / "bus.key"
    target.write_bytes(b"inert unchanged key")
    calls, environment_calls = [], []
    state = SimpleNamespace(code=0, fail_command=None, readback=True)
    monkeypatch.setattr(hardening, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_engine_custody, "active_engine_custody", lambda: None)
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path, native))

    def environment(*, source):
        environment_calls.append(source)
        return {"SystemRoot": str(tmp_path), "PATH": str(native)}

    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=state.code if len(calls) == state.fail_command else 0)

    monkeypatch.setattr(privilege, "sanitized_child_environment", environment)
    monkeypatch.setattr(hardening.subprocess, "run", command)
    monkeypatch.setattr(hardening, "sensitive_file_is_protected", lambda _path: state.readback)
    return native, target, calls, environment_calls, state


def test_key_acl_uses_os_directory_empty_source_environment_and_readback(native_key, monkeypatch):
    native, target, calls, environments, _state = native_key
    monkeypatch.setenv("SystemRoot", str(target.parent / "attacker"))
    monkeypatch.setenv("USERNAME", "untrusted-principal")
    monkeypatch.setenv("ANGERONA_API_KEY", "inert-secret")
    assert hardening.secure_sensitive_file(target, required=True)
    assert environments == [{}]
    assert len(calls) == 2
    for argv, kwargs in calls:
        assert Path(argv[0]) == native / "icacls.exe"
        assert kwargs["cwd"] == str(native)
        assert kwargs["env"] == {"SystemRoot": str(target.parent), "PATH": str(native)}
        assert kwargs["stdin"] == hardening.subprocess.DEVNULL
        assert kwargs["creationflags"] == getattr(hardening.subprocess, "CREATE_NO_WINDOW", 0)
        assert not any("untrusted-principal" in value for value in argv)
    assert target.read_bytes() == b"inert unchanged key"


@pytest.mark.parametrize("failure", ["owner", "dacl", "readback", "native-path", "missing-utility"])
def test_failed_native_acl_proof_never_claims_key_protection(native_key, monkeypatch, failure):
    native, target, calls, _environments, state = native_key
    if failure in {"owner", "dacl"}:
        state.code = 5
        state.fail_command = 1 if failure == "owner" else 2
    elif failure == "readback":
        state.readback = False
    elif failure == "native-path":
        def unavailable():
            raise OSError("inert missing native Windows directory")
        monkeypatch.setattr(privilege, "trusted_windows_directories", unavailable)
    else:
        (native / "icacls.exe").unlink()
    with pytest.raises(PermissionError, match="protected key custody"):
        hardening.secure_sensitive_file(target, required=True)
    assert len(calls) == (1 if failure == "owner" else 2 if failure in {"dacl", "readback"} else 0)
    assert target.read_bytes() == b"inert unchanged key"
