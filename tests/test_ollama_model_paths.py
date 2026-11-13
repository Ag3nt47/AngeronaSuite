"""Inert model-directory admission tests; no Windows APIs or real models."""
from __future__ import annotations

import stat
from types import SimpleNamespace

import pytest

from angerona.core import ollama_model_paths as paths


def _dir(*, attributes=0):
    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=attributes)


@pytest.fixture
def windows(monkeypatch):
    entries = {"C:\\": _dir(), r"C:\Safe": _dir()}
    reads = []
    monkeypatch.setattr(paths, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(paths, "_windows_fixed_drive", lambda anchor: anchor == "C:\\")

    def lstat(name):
        reads.append(name)
        value = entries.get(name)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise FileNotFoundError(name)
        return value

    monkeypatch.setattr(paths, "_lstat", lstat)
    return entries, reads


@pytest.mark.parametrize("value", [
    r"\\server\share\models", r"\\?\C:\models", r"\\.\C:\models", r"\??\C:\models",
    r"C:models", "/models", r"C:\Safe\..\models", r"C:\Safe\.\models",
    r"C:\Safe\\models", r"C:\Safe\models:stream", r"C:\Safe\folder.\models",
    r"C:\Safe\folder \models", r"C:\Safe\NUL.txt", r"C:\Safe\COM¹.txt",
    r"C:\Safe\CONIN$", r"C:\Safe\a|b", "C:\\Safe\\bad\npath", "C:\\Safe\\bad\x7fpath",
    "C:\\" + "a\\" * 129 + "models",
])
def test_windows_aliases_and_ambiguous_inputs_fail_before_metadata(windows, value):
    _entries, reads = windows
    with pytest.raises(paths.ModelDirectoryError):
        paths.validate_model_directory(value)
    assert reads == []


@pytest.mark.parametrize("value", [None, False, 77, "", " C:\\Safe", "C:\\Safe ", "x" * 4097])
def test_invalid_types_and_bounds_never_probe_storage(windows, value):
    _entries, reads = windows
    with pytest.raises(paths.ModelDirectoryError):
        paths.validate_model_directory(value)
    assert reads == []


def test_existing_plain_ancestor_allows_missing_suffix_and_preserves_spelling(windows):
    _entries, reads = windows
    value = "C:/Safe/$model & data/new store"
    assert paths.validate_model_directory(value) == value
    assert reads == ["C:\\", r"C:\Safe", r"C:\Safe\$model & data"]


def test_mapped_or_unknown_fixed_drive_is_refused_before_metadata(windows, monkeypatch):
    _entries, reads = windows
    monkeypatch.setattr(paths, "_windows_fixed_drive", lambda _: False)
    with pytest.raises(paths.ModelDirectoryError, match="fixed local drive"):
        paths.validate_model_directory(r"C:\Safe\models")
    assert reads == []


@pytest.mark.parametrize("info", [
    SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_file_attributes=0),
    _dir(attributes=0x400),
    SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_file_attributes=0),
])
def test_every_existing_ancestor_must_be_a_plain_directory(windows, info):
    entries, _reads = windows
    entries[r"C:\Safe"] = info
    with pytest.raises(paths.ModelDirectoryError, match="link, reparse point or non-directory"):
        paths.validate_model_directory(r"C:\Safe\models")


def test_unavailable_ancestor_is_visible_and_original_setting_unchanged(windows):
    entries, _reads = windows
    entries[r"C:\Safe"] = PermissionError("inert denial")
    configured = {"OLLAMA_MODELS": r"C:\Safe\models"}
    original = dict(configured)
    with pytest.raises(paths.ModelDirectoryError, match="custody is unavailable"):
        paths.validate_model_directory(configured["OLLAMA_MODELS"])
    assert configured == original


def test_missing_drive_root_has_no_verified_ancestor(windows):
    entries, _reads = windows
    entries.clear()
    with pytest.raises(paths.ModelDirectoryError, match="existing local ancestor"):
        paths.validate_model_directory(r"C:\Safe\models")


@pytest.mark.parametrize("targets", [
    (), (r"\??\C:\substituted",), (r"\Device\LanmanRedirector\share",),
    (r"\Device\Mup\share",), (r"\Device\HarddiskVolume3\subfolder",),
    (r"\Device\HarddiskVolume3", r"\Device\HarddiskVolume4"),
])
def test_dos_device_admission_refuses_subst_network_and_ambiguous_mappings(targets):
    assert paths._direct_volume_mapping(targets) is False


def test_one_direct_local_volume_mapping_is_accepted():
    assert paths._direct_volume_mapping((r"\Device\HarddiskVolume12",)) is True


def test_default_uses_only_supplied_sanitized_profile_and_validates_hidden_directory(windows):
    entries, _reads = windows
    entries.update({r"C:\Users": _dir(), r"C:\Users\Fixture": _dir()})
    env = {"USERPROFILE": r"C:\Users\Fixture"}
    assert paths.default_model_directory(env) == r"C:\Users\Fixture\.ollama\models"
    assert env == {"USERPROFILE": r"C:\Users\Fixture"}
    entries[r"C:\Users\Fixture\.ollama"] = _dir(attributes=0x400)
    with pytest.raises(paths.ModelDirectoryError, match="reparse"):
        paths.default_model_directory(env)
    with pytest.raises(paths.ModelDirectoryError):
        paths.default_model_directory({})


def test_posix_plain_paths_and_default_use_no_windows_probe(monkeypatch):
    monkeypatch.setattr(paths, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(paths, "_windows_fixed_drive", lambda *_: pytest.fail("Windows drive probe"))
    entries = {"/": _dir(), "/safe": _dir()}

    def lstat(name):
        if name not in entries:
            raise FileNotFoundError(name)
        return entries[name]

    monkeypatch.setattr(paths, "_lstat", lstat)
    assert paths.validate_model_directory("/safe/models") == "/safe/models"
    assert paths.default_model_directory({"HOME": "/safe"}) == "/safe/.ollama/models"
    entries["/safe/.ollama"] = SimpleNamespace(st_mode=stat.S_IFLNK | 0o700)
    with pytest.raises(paths.ModelDirectoryError, match="link"):
        paths.default_model_directory({"HOME": "/safe"})
    for value in ("//server/share", "/safe/../models", "/safe//models", "/safe/./models"):
        with pytest.raises(paths.ModelDirectoryError):
            paths.validate_model_directory(value)


def test_missing_parent_ends_metadata_probes_before_any_descendant(windows, monkeypatch):
    entries, _reads = windows
    observed = []
    missing = r"C:\Safe\missing"
    child = missing + r"\unobserved\models"

    def lstat(name):
        observed.append(name)
        if name == missing:
            raise FileNotFoundError(name)
        if name.startswith(missing + "\\"):
            pytest.fail("metadata probe crossed an unobserved missing parent")
        return entries[name]

    monkeypatch.setattr(paths, "_lstat", lstat)
    assert paths.validate_model_directory(child) == child
    assert observed == ["C:\\", r"C:\Safe", missing]
