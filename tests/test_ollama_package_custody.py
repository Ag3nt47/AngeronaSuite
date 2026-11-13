"""Inert metadata trees and fake native ACL providers only; no installed Ollama."""
from __future__ import annotations

import os
import stat
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path, PureWindowsPath
from types import ModuleType, SimpleNamespace

import pytest

from angerona.core import ollama_package_custody as custody


@pytest.fixture
def package(tmp_path, monkeypatch):
    root = tmp_path / "owned-fixture" / "Ollama"
    root.mkdir(parents=True)
    image = root / "ollama.exe"
    image.write_bytes(b"inert image fixture")
    (root / "library.dll").write_bytes(b"inert DLL fixture")
    runner = root / "runners"
    runner.mkdir()
    (runner / "runner.dll").write_bytes(b"inert runner fixture")
    (root.parent / "outside.txt").write_bytes(b"outside install tree")
    calls = []
    now = [1000.0]
    monkeypatch.setattr(custody, "os", SimpleNamespace(fspath=os.fspath, scandir=os.scandir))
    monkeypatch.setattr(custody, "_is_windows", lambda: True)
    # POSIX fake metadata fixtures deliberately replace only the lexical/drive
    # boundaries. Their production versions have separate pure/fake tests below.
    monkeypatch.setattr(custody, "_validate_image_path", lambda value: Path(value))
    monkeypatch.setattr(custody, "_fixed_local_drive", lambda _root: True)
    monkeypatch.setattr(custody, "_windows_ancestor_custody", lambda path: calls.append((path, True, True)) or True)
    monkeypatch.setattr(custody, "_windows_object_custody", lambda path, directory: calls.append((path, directory, False)) or True)
    monkeypatch.setattr(custody, "time", SimpleNamespace(monotonic=lambda: now[0]))
    return SimpleNamespace(root=root, image=image, calls=calls, now=now)


def test_snapshot_covers_dlls_runners_image_and_ancestors_without_external_enumeration(package, monkeypatch):
    p = package
    real_scandir = custody.os.scandir
    enumerated = []

    def scandir(path):
        path = Path(path)
        assert path == p.root or path.is_relative_to(p.root)
        enumerated.append(path)
        return real_scandir(path)

    monkeypatch.setattr(custody.os, "scandir", scandir)
    result = custody.assess_package(p.image)
    assert result.accepted
    strict = {path for path, _directory, ancestor in p.calls if not ancestor}
    assert strict == {p.root, p.image, p.root / "library.dll", p.root / "runners", p.root / "runners/runner.dll"}
    assert [path for path, _directory, ancestor in p.calls if ancestor] == list(reversed(tuple(p.root.parents)))
    assert result.entries == len(p.calls)
    assert enumerated.count(p.root) == 2
    with pytest.raises(FrozenInstanceError):
        result.accepted = False


@pytest.mark.parametrize("reject", ["root", "image", "dll", "runner"])
def test_writable_install_object_never_accepts_package(package, monkeypatch, reject):
    p = package
    bad = {"root": p.root, "image": p.image, "dll": p.root / "library.dll", "runner": p.root / "runners/runner.dll"}[reject]
    monkeypatch.setattr(custody, "_windows_object_custody", lambda path, directory: path != bad)
    result = custody.assess_package(p.image)
    assert not result.accepted
    assert "administrator-only write custody" in result.reason


def test_unverified_ancestor_refuses_before_install_tree_enumeration(package, monkeypatch):
    monkeypatch.setattr(custody, "_windows_ancestor_custody", lambda _path: False)
    monkeypatch.setattr(custody.os, "scandir", lambda _path: pytest.fail("enumerated after failed ancestry"))
    assert not custody.assess_package(package.image).accepted


def test_unrelated_ancestor_create_slot_does_not_change_protected_child_identity(package, monkeypatch):
    def ancestor_check(path):
        if path == package.root.parent:
            (path / "unrelated-owned-slot").mkdir()
        return True

    monkeypatch.setattr(custody, "_windows_ancestor_custody", ancestor_check)
    assert custody.assess_package(package.image).accepted


def test_nonboolean_native_admission_is_not_accepted(package, monkeypatch):
    monkeypatch.setattr(custody, "_windows_object_custody", lambda *_a, **_k: 1)
    assert not custody.assess_package(package.image).accepted


def test_entry_limit_is_finite_and_does_not_accept_partial_inventory(package):
    for index in range(512):
        (package.root / f"inert-{index}.dll").touch()
    result = custody.assess_package(package.image)
    assert not result.accepted and "entry limit" in result.reason
    assert result.entries == 512
    assert len(package.calls) == 512


def test_entry_limit_refuses_513th_unique_metadata_before_lstat(package, monkeypatch):
    for index in range(512):
        (package.root / f"bounded-{index}.dll").touch()
    original = Path.lstat
    unobserved_after_limit = []

    def lstat(path, *args, **kwargs):
        known = {item for item, _directory, _ancestor in package.calls}
        if len(known) >= 512 and path not in known:
            unobserved_after_limit.append(path)
            pytest.fail("513th unique object reached metadata before the entry guard")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    result = custody.assess_package(package.image)
    assert not result.accepted and "entry limit" in result.reason
    assert result.entries == 512 and len(package.calls) == 512
    assert unobserved_after_limit == []


def test_depth_limit_refuses_recursive_runner_tree(package):
    current = package.root
    for index in range(9):
        current = current / f"level-{index}"
        current.mkdir()
    result = custody.assess_package(package.image)
    assert not result.accepted and "depth limit" in result.reason


def test_deadline_is_checked_after_native_provider_returns(package, monkeypatch):
    def slow(_path, directory):
        package.now[0] += 3.0
        return True

    monkeypatch.setattr(custody, "_windows_object_custody", slow)
    result = custody.assess_package(package.image)
    assert not result.accepted and "budget expired" in result.reason


@pytest.mark.parametrize("deadline", [999.0, 1000.0, True, float("nan"), float("inf")])
def test_invalid_or_expired_deadline_makes_no_native_observations(package, deadline):
    assert not custody.assess_package(package.image, deadline=deadline).accepted
    assert package.calls == []


def test_caller_cannot_extend_the_fixed_budget(package, monkeypatch):
    def slow(_root):
        package.now[0] += 2.1
        return True

    monkeypatch.setattr(custody, "_fixed_local_drive", slow)
    assert not custody.assess_package(package.image, deadline=10_000).accepted
    assert package.calls == []


def test_missing_image_and_metadata_provider_errors_are_held(package, monkeypatch):
    package.image.unlink()
    result = custody.assess_package(package.image)
    assert not result.accepted
    assert "unavailable" in result.reason


def test_file_hardlinks_are_rejected_before_native_file_admission(package):
    try:
        os.link(package.image, package.root / "second-image.exe")
    except OSError as exc:
        pytest.skip(f"owned fixture filesystem does not permit hardlinks: {type(exc).__name__}")
    result = custody.assess_package(package.image)
    assert not result.accepted and "linked" in result.reason
    assert not any(path == package.image for path, _directory, _ancestor in package.calls)


@pytest.mark.parametrize("kind", ["reparse", "symlink", "special"])
def test_redirected_or_special_child_is_never_descended(package, monkeypatch, kind):
    original = Path.lstat
    bad = package.root / "runners"

    def lstat(path):
        value = original(path)
        if path != bad:
            return value
        fields = {name: getattr(value, name) for name in (
            "st_dev", "st_ino", "st_mode", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns",
        )}
        fields["st_file_attributes"] = 0x400 if kind == "reparse" else 0
        if kind != "reparse":
            fields["st_mode"] = stat.S_IFLNK if kind == "symlink" else stat.S_IFIFO
        return SimpleNamespace(**fields)

    monkeypatch.setattr(Path, "lstat", lstat)
    result = custody.assess_package(package.image)
    assert not result.accepted
    assert not any(path == bad for path, _directory, _ancestor in package.calls)


def test_metadata_change_during_native_check_is_not_accepted(package, monkeypatch):
    bad = package.root / "library.dll"

    def custody_check(path, directory):
        if path == bad:
            path.write_bytes(b"changed inert fixture")
        return True

    monkeypatch.setattr(custody, "_windows_object_custody", custody_check)
    result = custody.assess_package(package.image)
    assert not result.accepted and "changed" in result.reason


def test_final_name_snapshot_detects_new_package_file(package, monkeypatch):
    real_scandir = custody.os.scandir
    root_scans = [0]

    def scandir(path):
        if Path(path) == package.root:
            root_scans[0] += 1
            if root_scans[0] == 2:
                (package.root / "late.dll").touch()
        return real_scandir(path)

    monkeypatch.setattr(custody.os, "scandir", scandir)
    result = custody.assess_package(package.image)
    assert not result.accepted and "directory changed" in result.reason


@pytest.mark.parametrize("value", [
    r"relative\ollama.exe", r"C:relative\ollama.exe", r"\rooted\ollama.exe",
    r"\\server\share\Ollama\ollama.exe", r"\\?\C:\Ollama\ollama.exe", r"\\.\C:\Ollama\ollama.exe",
    r"C:\Ollama\..\ollama.exe", r"C:\Ollama\.\ollama.exe", r"C:\Ollama\\ollama.exe",
    r"C:\Ollama\ollama.exe:stream", r"C:\Ollama\NUL.exe", r"C:\Ollama\COM¹.exe",
    "C:\\Ollama\\ollama.exe.", "C:\\Ollama\\ollama.exe ", "C:\\Ollama\\bad\x00.exe",
    r"C:\PROGRA~1\Ollama\ollama.exe", r"C:\ollama.exe", r"Å:\Ollama\ollama.exe",
])
def test_production_lexical_boundary_rejects_aliases_without_filesystem_access(value):
    with pytest.raises(custody._Held):
        custody._validate_image_path(value)


def test_production_lexical_boundary_accepts_explicit_long_local_path():
    result = custody._validate_image_path("C:/Program Files/Ollama/ollama.exe")
    assert PureWindowsPath(str(result)) == PureWindowsPath(r"C:\Program Files\Ollama\ollama.exe")


class _Acl:
    def __init__(self, entries):
        self.entries = entries

    def GetAceCount(self):
        return len(self.entries)

    def GetAce(self, index):
        return self.entries[index]


class _Descriptor:
    def __init__(self, owner="S-1-5-32-544", entries=None, *, null=False, control=0x1004):
        self.owner = owner
        self.acl = None if null else _Acl(entries if entries is not None else [((0, 0), 0x1F01FF, owner)])
        self.control = control

    def GetSecurityDescriptorOwner(self):
        return self.owner

    def GetSecurityDescriptorDacl(self):
        return self.acl

    def GetSecurityDescriptorControl(self):
        return self.control, 1


@pytest.fixture
def native(monkeypatch):
    monkeypatch.setattr(custody, "os", SimpleNamespace(fspath=os.fspath, scandir=os.scandir))

    class Handle:
        closes = 0
        fail_close = False

        def __int__(self):
            return 101

        def Close(self):
            self.closes += 1
            if self.fail_close:
                raise OSError("inert close uncertainty")

    handle = Handle()
    state = SimpleNamespace(
        descriptor=_Descriptor(), handle=handle, creates=[], security_calls=[], drive_calls=[], device_calls=[],
        info=(0x80, None, None, None, 5, 0, 0, 1, 0, 123),
        device=r"\Device\HarddiskVolume5" + "\0\0", drive_type=3,
    )
    file_module = ModuleType("win32file")
    security_module = ModuleType("win32security")

    def create(*arguments):
        state.creates.append(arguments)
        return handle

    def get_security(*arguments):
        state.security_calls.append(arguments)
        return state.descriptor

    def get_drive(root):
        state.drive_calls.append(root)
        return state.drive_type

    def get_device(drive):
        state.device_calls.append(drive)
        return state.device

    file_module.CreateFile = create
    file_module.GetFileType = lambda _handle: 1
    file_module.GetFileInformationByHandle = lambda _handle: state.info
    file_module.GetDriveType = get_drive
    file_module.QueryDosDevice = get_device
    security_module.SE_FILE_OBJECT = 1
    security_module.OWNER_SECURITY_INFORMATION = 1
    security_module.DACL_SECURITY_INFORMATION = 4
    security_module.GetSecurityInfo = get_security
    security_module.ConvertSidToStringSid = lambda sid: sid
    monkeypatch.setitem(sys.modules, "win32file", file_module)
    monkeypatch.setitem(sys.modules, "win32security", security_module)
    monkeypatch.setattr(custody, "_is_windows", lambda: True)
    monkeypatch.setattr(custody, "_RETIREMENT_HOLD", None)
    return state


def test_native_acl_is_read_by_handle_with_no_write_or_delete_access(native):
    assert custody._windows_object_custody(Path(r"C:\Program Files\Ollama\ollama.exe"), directory=False)
    assert native.creates[0][1:6] == (0x20080, 1, None, 3, 0x200080)
    assert native.security_calls == [(101, 1, 5)]
    assert native.handle.closes == 1


@pytest.mark.parametrize("owner", ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"])
def test_native_trust_is_fixed_to_system_admins_and_trustedinstaller(native, owner):
    native.descriptor = _Descriptor(owner=owner)
    assert custody._windows_object_custody(Path(r"C:\Ollama\ollama.exe"), directory=False)


def test_interactive_owner_is_not_enrolled_even_if_it_might_be_an_admin(native):
    native.descriptor = _Descriptor(owner="S-1-5-21-111-222-333-1001")
    assert not custody._windows_object_custody(Path(r"C:\Ollama\ollama.exe"), directory=False)
    assert native.handle.closes == 1


@pytest.mark.parametrize("descriptor", [
    _Descriptor(null=True), _Descriptor(entries=[]), _Descriptor(control=0x1000), _Descriptor(owner=None),
    _Descriptor(entries=[((5, 0), 0x1200A9, "S-1-1-0")]),
    _Descriptor(entries=[((0, 0), 0x1F01FF, "S-1-1-0")]),
    _Descriptor(entries=[((0, 0), 0x20000, "S-1-5-32-544")] * 65),
])
def test_null_unknown_empty_or_untrusted_write_dacl_refuses(native, descriptor):
    native.descriptor = descriptor
    assert not custody._windows_object_custody(Path(r"C:\Ollama\ollama.exe"), directory=False)
    assert native.handle.closes == 1


def test_untrusted_read_execute_does_not_grant_write_authority(native):
    native.descriptor = _Descriptor(entries=[
        ((0, 0), 0x1F01FF, "S-1-5-32-544"), ((0, 0), 0x1200A9, "S-1-1-0"),
    ])
    assert custody._windows_object_custody(Path(r"C:\Ollama\ollama.exe"), directory=False)


def test_ancestor_create_slot_is_allowed_but_install_directory_create_slot_is_not(native):
    native.info = (0x10, None, None, None, 5, 0, 0, 1, 0, 123)
    native.descriptor = _Descriptor(entries=[
        ((0, 0), 0x1F01FF, "S-1-5-32-544"), ((0, 0), 0x4, "S-1-5-11"),
    ])
    assert custody._windows_ancestor_custody(Path("C:\\"))
    assert not custody._windows_object_custody(Path(r"C:\Ollama"), directory=True)


@pytest.mark.parametrize("mask", [0x10000, 0x40000, 0x80000, 0x40, 0x10000000, 0x40000000])
def test_ancestor_untrusted_replacement_rights_refuse(native, mask):
    native.info = (0x10, None, None, None, 5, 0, 0, 1, 0, 123)
    native.descriptor = _Descriptor(entries=[((0, 0), mask, "S-1-5-11")])
    assert not custody._windows_ancestor_custody(Path("C:\\"))


@pytest.mark.parametrize("info", [
    (0x480, None, None, None, 5, 0, 0, 1, 0, 123),
    (0x10, None, None, None, 5, 0, 0, 1, 0, 123),
    (0x80, None, None, None, 5, 0, 0, 2, 0, 123),
    (0x80, None, None, None, 5, 0, 0, 1, 0, 0),
])
def test_native_type_link_and_identity_must_be_observable(native, info):
    native.info = info
    assert not custody._windows_object_custody(Path(r"C:\Ollama\ollama.exe"), directory=False)
    assert native.handle.closes == 1


def test_native_close_uncertainty_holds_one_owner_and_refuses_further_allocations(native):
    native.handle.fail_close = True
    assert not custody._windows_object_custody(Path(r"C:\Ollama\ollama.exe"), directory=False)
    assert custody._RETIREMENT_HOLD is native.handle
    assert not custody._windows_object_custody(Path(r"C:\Ollama\library.dll"), directory=False)
    assert len(native.creates) == 1 and native.handle.closes == 1


@pytest.mark.parametrize("mapping", [
    r"\??\C:\UserWritable", r"\Device\Mup\server\share", "",
    r"\Device\HarddiskVolumeShadowCopy1", "x" * 32769,
], ids=["subst", "network", "empty", "shadow", "oversized"])
def test_fixed_drive_boundary_refuses_subst_network_unknown_and_shadow_aliases(native, mapping):
    native.device = mapping
    assert not custody._fixed_local_drive(Path("C:\\"))


def test_fixed_drive_boundary_accepts_one_ordinary_volume_and_refuses_remote_type(native):
    assert custody._fixed_local_drive(Path("C:\\"))
    native.device = (r"\Device\HarddiskVolume5",)
    assert custody._fixed_local_drive(Path("C:\\"))
    native.device = (r"\Device\HarddiskVolume5", r"\??\C:\UserWritable")
    assert not custody._fixed_local_drive(Path("C:\\"))
    native.device = (r"\Device\HarddiskVolume5",)
    native.drive_type = 4
    assert not custody._fixed_local_drive(Path("C:\\"))


def test_native_seam_never_uses_ambient_cwd_for_relative_paths(native):
    assert not custody._windows_object_custody(Path("ollama.exe"), directory=False)
    assert native.creates == []


def test_location_admission_does_no_metadata_tree_or_acl_queries(native, monkeypatch):
    monkeypatch.setattr(Path, "lstat", lambda *_a, **_k: pytest.fail("location guard queried metadata"))
    monkeypatch.setattr(custody.os, "scandir", lambda *_a, **_k: pytest.fail("location guard enumerated a directory"))
    assert custody.image_location_allowed(Path(r"C:\Program Files\Ollama\ollama.exe"))
    assert native.drive_calls and native.device_calls
    assert native.creates == [] and native.security_calls == []


@pytest.mark.parametrize("image", [
    r"\\server\share\Ollama\ollama.exe", r"\\?\C:\Ollama\ollama.exe",
    r"C:relative\ollama.exe", r"C:\PROGRA~1\Ollama\ollama.exe",
])
def test_location_guard_rejects_lexical_alias_before_even_volume_query(native, image):
    assert not custody.image_location_allowed(Path(image))
    assert native.drive_calls == [] and native.device_calls == []
    assert native.creates == [] and native.security_calls == []


@pytest.mark.parametrize("drive,mapping", [
    (4, r"\Device\Mup\server\share"), (3, r"\??\C:\UserWritable"),
])
def test_location_guard_refuses_network_and_subst_without_metadata(native, monkeypatch, drive, mapping):
    native.drive_type, native.device = drive, mapping
    monkeypatch.setattr(Path, "lstat", lambda *_a, **_k: pytest.fail("unadmitted drive queried metadata"))
    assert not custody.image_location_allowed(Path(r"C:\Ollama\ollama.exe"))
    assert native.creates == [] and native.security_calls == []
