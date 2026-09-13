from __future__ import annotations

import os
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

from angerona.core import ollama_lifecycle, privilege


def _registry(monkeypatch, records=None):
    """A registry fixture which only exposes the official installer key."""
    registry = SimpleNamespace(
        HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2, KEY_WOW64_64KEY=256,
        KEY_WOW64_32KEY=512, KEY_READ=1, REG_SZ=1, REG_EXPAND_SZ=2,
    )
    queried = []

    def open_key(hive, name, reserved, access):
        queried.append((hive, name, reserved, access))
        assert name == ollama_lifecycle._OLLAMA_UNINSTALL_KEY
        if records is None or hive not in records:
            raise FileNotFoundError(name)
        return nullcontext(records[hive])

    registry.OpenKey = open_key
    registry.QueryValueEx = lambda key, name: key[name]
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(ollama_lifecycle, "_windows_fixed_drive", lambda _anchor: True)
    return queried


def _record(location="D:\\Ollama\\"):
    return {
        "DisplayName": ("Ollama version 0.33.3", 1),
        "Publisher": ("Ollama", 1),
        "InstallLocation": (location, 1),
    }


def test_fixed_official_registry_key_discovers_custom_install(monkeypatch):
    queried = _registry(monkeypatch, {1: _record(), 2: _record()})
    assert ollama_lifecycle._registered_ollama_paths() == (Path(r"D:\Ollama\ollama.exe"),)
    assert len(queried) == 4


def test_absent_registry_has_no_custom_candidate(monkeypatch):
    _registry(monkeypatch)
    assert ollama_lifecycle._registered_ollama_paths() == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("DisplayName", ("Other program", 1)),
        ("DisplayName", ("Ollama version " + "1" * 129, 1)),
        ("Publisher", ("Attacker", 1)),
        ("Publisher", ("Ollama Inc.", 1)),
        ("InstallLocation", (r"D:\Ollama", 2)),
        ("InstallLocation", (1234, 1)),
    ],
)
def test_registry_wrong_metadata_or_types_are_rejected(monkeypatch, field, value):
    record = _record()
    record[field] = value
    _registry(monkeypatch, {1: record})
    assert ollama_lifecycle._registered_ollama_paths() == ()


@pytest.mark.parametrize(
    "value",
    [
        r"\\server\share\Ollama", r"\\?\D:\Ollama", r"\\.\D:\Ollama",
        r"D:Ollama", r"D:\Apps\..\Ollama", r"D:\Apps\.\Ollama",
        r"D:\Ollama:stream", r"D:\Ollama\NUL", r"D:\NUL\Ollama", r"D:\Ollama. ",
        r"D:\Ollama.", r"D:\\Ollama", r"D:\Ollama/other", "D:\\Ollama\x00",
        "D:\\" + "x" * 1024, "", None,
    ],
)
def test_registry_malformed_locations_cannot_become_candidates(monkeypatch, value):
    _registry(monkeypatch, {1: _record(value)})
    assert ollama_lifecycle._registered_ollama_paths() == ()


def test_registry_mapped_drive_is_rejected(monkeypatch):
    _registry(monkeypatch, {1: _record(r"Z:\Ollama")})
    monkeypatch.setattr(ollama_lifecycle, "_windows_fixed_drive", lambda _anchor: False)
    assert ollama_lifecycle._registered_ollama_paths() == ()


def test_install_location_allows_spaces_without_expanding_expressions():
    value = r"D:\Local Apps\Ollama $program"
    assert ollama_lifecycle._windows_install_location(value) == PureWindowsPath(value)


def _windows_image_fixture(tmp_path, monkeypatch, *, registered=True):
    image = tmp_path / "Custom Ollama" / "ollama.exe"
    image.parent.mkdir()
    image.write_bytes(b"fixture-image")
    monkeypatch.setattr(ollama_lifecycle, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(privilege, "_windows_known_folder", lambda _csidl: tmp_path / "defaults")
    monkeypatch.setattr(
        ollama_lifecycle, "_registered_ollama_paths", lambda: (image,) if registered else ()
    )
    return image


@pytest.mark.parametrize("signed", [True, False])
def test_custom_candidate_still_requires_ollama_signature(tmp_path, monkeypatch, signed):
    image = _windows_image_fixture(tmp_path, monkeypatch)
    calls = []

    def signature(path_text, *identity):
        calls.append((path_text, identity))
        return signed

    monkeypatch.setattr(ollama_lifecycle, "_windows_image_signature_valid", signature)
    assert ollama_lifecycle._trusted_ollama_image(image) is signed
    assert calls == [(str(image.resolve()), ollama_lifecycle._image_identity(image.stat()))]


def test_unregistered_executable_is_rejected_without_signature_probe(tmp_path, monkeypatch):
    image = _windows_image_fixture(tmp_path, monkeypatch, registered=False)
    monkeypatch.setenv("PATH", str(image.parent))
    monkeypatch.setenv("OLLAMA_EXE", str(image))
    monkeypatch.setattr(
        ollama_lifecycle, "_windows_image_signature_valid",
        lambda *_args: pytest.fail("unregistered image must be rejected first"),
    )
    assert not ollama_lifecycle._trusted_ollama_image(image)


def test_reparse_parent_cannot_register_a_trusted_image(tmp_path, monkeypatch):
    image = _windows_image_fixture(tmp_path, monkeypatch)
    original_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        original = original_lstat(path, *args, **kwargs)
        if path == image.parent:
            return SimpleNamespace(st_mode=original.st_mode, st_file_attributes=0x400)
        return original

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(
        ollama_lifecycle, "_windows_image_signature_valid",
        lambda *_args: pytest.fail("reparse image must be rejected first"),
    )
    assert not ollama_lifecycle._trusted_ollama_image(image)


def test_image_replaced_during_signature_probe_is_rejected(tmp_path, monkeypatch):
    image = _windows_image_fixture(tmp_path, monkeypatch)

    def signature(*_args):
        replacement = image.with_suffix(".replacement")
        replacement.write_bytes(image.read_bytes())
        info = image.stat()
        os.utime(replacement, ns=(info.st_atime_ns, info.st_mtime_ns))
        os.replace(replacement, image)
        return True

    monkeypatch.setattr(ollama_lifecycle, "_windows_image_signature_valid", signature)
    assert not ollama_lifecycle._trusted_ollama_image(image)


@pytest.mark.parametrize("returncode", [0, 1])
def test_publisher_verification_uses_inbox_powershell_and_literal_path(
    tmp_path, monkeypatch, returncode
):
    powershell = tmp_path / "powershell.exe"
    powershell.write_bytes(b"inbox-fixture")
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: powershell)
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path, tmp_path))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_kwargs: {"SAFE": "1"})
    captured = []

    def run(command, **kwargs):
        captured.append((command, kwargs))
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(ollama_lifecycle.subprocess, "run", run)
    verify = ollama_lifecycle._windows_image_signature_valid
    verify.cache_clear()
    path_text = r"D:\A $special; path\ollama.exe"
    try:
        assert verify(path_text, 1, 2, 3, 4, 5) is (returncode == 0)
        command, kwargs = captured[0]
        assert command[:4] == [str(powershell), "-NoProfile", "-NonInteractive", "-Command"]
        assert path_text not in command[-1]
        assert "-LiteralPath $env:ANGERONA_NATIVE_PATH" in command[-1]
        assert "$s.Status -ne 'Valid'" in command[-1]
        assert "'Ollama Inc.'" in command[-1]
        assert "::Equals(" in command[-1] and "::SimpleName" in command[-1]
        assert kwargs["env"] == {"SAFE": "1", "ANGERONA_NATIVE_PATH": path_text}
        assert kwargs["cwd"] == str(tmp_path)
        assert kwargs["timeout"] == 15
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        # Unchanged identity reuses a signature result; every identity field invalidates it.
        verify(path_text, 1, 2, 3, 4, 5)
        for index in range(5):
            identity = [1, 2, 3, 4, 5]
            identity[index] += 10
            verify(path_text, *identity)
        assert len(captured) == 6
    finally:
        verify.cache_clear()


def test_signature_timeout_fails_closed(tmp_path, monkeypatch):
    powershell = tmp_path / "powershell.exe"
    powershell.write_bytes(b"inbox-fixture")
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: powershell)
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path, tmp_path))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_kwargs: {})

    def timed_out(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("powershell", 15)

    monkeypatch.setattr(ollama_lifecycle.subprocess, "run", timed_out)
    verify = ollama_lifecycle._windows_image_signature_valid
    verify.cache_clear()
    try:
        assert not verify(str(tmp_path / "ollama.exe"), 1, 2, 3, 4, 5)
    finally:
        verify.cache_clear()
