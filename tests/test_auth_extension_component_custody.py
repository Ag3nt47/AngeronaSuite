"""Confined path-custody contracts; native cases require a separate private gate."""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import PureWindowsPath
import stat
import sys
import time
from types import SimpleNamespace

import pytest

from angerona.core import windows_auth_extensions as auth

COMPONENT = "component:v1:" + "a" * 32
PATH_TOKEN = "path:v1:" + "b" * 32
LEAF = r"C:\trusted\providers\fixture.dll"
PAYLOAD = b"MZ-inert-fixture"


def info(inode, *, directory=False, **changes):
    return SimpleNamespace(**{
        "st_mode": (stat.S_IFDIR if directory else stat.S_IFREG) | 0o700,
        "st_dev": 7, "st_ino": inode, "st_size": 0 if directory else len(PAYLOAD),
        "st_mtime_ns": 100, "st_file_attributes": 0, "st_nlink": 1, **changes,
    })


def provider(*, clock=lambda: 0.0, probe=None):
    # Bypass __init__: never discover a registry module or WinAPI directories.
    result = object.__new__(auth.WindowsAuthExtensionEvidenceProvider)
    result.privacy_key = b"p" * 32
    result.monotonic = clock
    result.signature_probe = probe
    return result


@pytest.fixture
def model(monkeypatch):
    state = SimpleNamespace(events=[], held={}, closed=[], hook=None, clock=0.0, offset=0,
                            names={}, next_fd=100, fail_gate=False)

    def emit(action, *args):
        event = (action, *args)
        state.events.append(event)
        if state.hook is not None:
            state.hook(event)

    class Path(PureWindowsPath):
        def stat(self, *, follow_symlinks=True):
            assert follow_symlinks is False
            emit("leaf-stat", str(self))
            return state.names[str(self)]

    path = Path(LEAF)
    for number, parent in enumerate(reversed(path.parents), 1):
        state.names[str(parent)] = info(number, directory=True)
    state.names[str(path)] = info(10)

    def gate(candidate):
        emit("fixed-local", str(candidate))
        if state.fail_gate:
            raise OSError("inert non-fixed drive rejected")

    def lstat(candidate):
        emit("directory-stat", str(candidate))
        return state.names[str(candidate)]

    def guard(candidate, *, deny_write=False):
        emit("directory-open", str(candidate), deny_write)
        state.next_fd += 1
        state.held[state.next_fd] = (str(candidate), state.names[str(candidate)])
        return state.next_fd

    def file_open(candidate, flags):
        emit("file-open", str(candidate))
        state.next_fd += 1
        state.held[state.next_fd] = (str(candidate), state.names[str(candidate)])
        return state.next_fd

    def fstat(descriptor):
        emit("handle-stat", descriptor)
        return state.held[descriptor][1]

    def matches(descriptor, expected):
        emit("final-path", descriptor, expected)
        return state.held[descriptor][0] == expected

    def read(descriptor, length):
        emit("read", descriptor, length)
        result = PAYLOAD[state.offset:state.offset + length]
        state.offset += len(result)
        return result

    def close(descriptor):
        state.closed.append(descriptor)
        del state.held[descriptor]
        emit("close", descriptor)

    def security(descriptor, key):
        emit("security", descriptor)
        return "owner:v1:" + "c" * 32, "acl:v1:" + "d" * 32, "observed"

    def probe(candidate, descriptor):
        emit("signature", candidate, descriptor)
        return dict(authenticode_state="verified", catalog_state="not-found",
                    signer_thumbprint="e" * 64, file_version="1.0")

    state.original_guard = auth._open_windows_directory_guard
    state.original_gate = auth._require_fixed_local_path
    monkeypatch.setattr(auth, "Path", Path)
    monkeypatch.setattr(auth, "os", SimpleNamespace(
        name="nt", O_RDONLY=os.O_RDONLY, O_BINARY=getattr(os, "O_BINARY", 0),
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0), O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
        lstat=lstat, open=file_open, fstat=fstat, read=read, close=close, fspath=os.fspath,
    ))
    monkeypatch.setattr(auth, "_require_fixed_local_path", gate)
    monkeypatch.setattr(auth, "_open_windows_directory_guard", guard)
    monkeypatch.setattr(auth, "_windows_handle_matches_path", matches)
    monkeypatch.setattr(auth, "_file_security_from_handle", security)
    state.path, state.Path, state.emit = path, Path, emit
    state.provider = provider(clock=lambda: state.clock, probe=probe)
    state.budget = auth._CollectionBudget(0.0, 10.0)
    state.run = lambda target=LEAF: state.provider._inspect_component(
        COMPONENT, target, PATH_TOKEN, "inert resolved component", state.budget,
    )[0]
    return state


def assert_unknown(result, state):
    assert result.evidence_status == "unknown" and not result.sha256
    assert not state.held


def test_nonfixed_gate_precedes_every_path_stat_open_or_probe(model):
    model.fail_gate = True
    result = model.run(r"Z:\configured\fixture.dll")
    assert_unknown(result, model)
    assert model.events == [("fixed-local", r"Z:\configured\fixture.dll")]


@pytest.mark.parametrize("reparse_parent", ["C:\\", r"C:\trusted", r"C:\trusted\providers"])
def test_reparse_ancestor_is_rejected_before_addressing_descendants(model, reparse_parent):
    old = model.names[reparse_parent]
    model.names[reparse_parent] = info(old.st_ino, directory=True, st_file_attributes=auth._REPARSE_POINT)
    result = model.run()
    assert_unknown(result, model)
    assert not any(event[0] in {"leaf-stat", "file-open", "read", "signature"} for event in model.events)
    assert not any(event[:2] == ("directory-open", reparse_parent) for event in model.events)


def test_safe_hardlinked_component_keeps_hash_and_complete_assurance(model):
    model.names[LEAF] = info(10, st_nlink=2)
    result = model.run()
    assert result.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert result.evidence_status == "complete" and result.resolution_status == "resolved"
    assert model.budget.total_bytes == len(PAYLOAD) and not model.held
    opens = [event for event in model.events if event[0] == "directory-open"]
    assert [event[1] for event in opens] == ["C:\\", r"C:\trusted", r"C:\trusted\providers"]
    assert all(event[2] is True for event in opens)
    assert model.closed == [104, 103, 102, 101]


@pytest.mark.parametrize("mode", ["named-swap", "opened-reparse", "final-path"])
def test_ancestor_identity_or_attributes_cannot_change_before_descent(model, mode):
    def hook(event):
        if event[:2] == ("directory-open", r"C:\trusted") and mode == "named-swap":
            model.names[r"C:\trusted"] = info(999, directory=True)
        if event[:2] == ("handle-stat", 102) and mode == "opened-reparse":
            name, _old = model.held[102]
            model.held[102] = (name, info(2, directory=True, st_file_attributes=auth._REPARSE_POINT))
        if event[:2] == ("final-path", 102) and mode == "final-path":
            _name, old = model.held[102]
            model.held[102] = (r"C:\elsewhere", old)
    model.hook = hook
    assert_unknown(model.run(), model)
    assert not any(event[0] == "leaf-stat" for event in model.events)


@pytest.mark.parametrize("stage", ["read", "security", "signature"])
def test_ancestor_replacement_after_hash_or_probe_is_never_complete(model, stage):
    def hook(event):
        if event[0] == stage:
            model.names[r"C:\trusted"] = info(900, directory=True)
    model.hook = hook
    assert_unknown(model.run(), model)
    if stage != "signature":
        assert not any(event[0] == "signature" for event in model.events)


@pytest.mark.parametrize("stage", ["file-open", "read", "signature"])
@pytest.mark.parametrize("change", ["identity", "reparse", "mtime"])
def test_leaf_rebinding_or_attributes_cannot_mix_hash_and_assurance(model, stage, change):
    changes = {"identity": {"st_ino": 99}, "reparse": {"st_file_attributes": auth._REPARSE_POINT},
               "mtime": {"st_mtime_ns": 999}}[change]
    def hook(event):
        if event[0] == stage:
            model.names[LEAF] = info(10, **changes)
    model.hook = hook
    assert_unknown(model.run(), model)


@pytest.mark.parametrize("stage", ["file-open", "read", "signature"])
def test_open_file_handle_reparse_attribute_is_rejected(model, stage):
    def hook(event):
        if stage == "file-open" and event[0] == "handle-stat" and event[1] == 104:
            model.held[104] = (LEAF, info(10, st_file_attributes=auth._REPARSE_POINT))
        elif stage != "file-open" and event[0] == stage:
            model.held[104] = (LEAF, info(10, st_file_attributes=auth._REPARSE_POINT))
    model.hook = hook
    assert_unknown(model.run(), model)


def test_partial_directory_open_failure_releases_every_acquired_guard(model):
    def hook(event):
        if event[:2] == ("directory-open", r"C:\trusted\providers"):
            raise PermissionError("inert guard denied")
    model.hook = hook
    assert_unknown(model.run(), model)
    assert model.closed == [102, 101]


@pytest.mark.parametrize("failed_fd", [103, 104])
def test_one_close_error_still_attempts_all_other_releases(model, failed_fd):
    def hook(event):
        if event == ("close", failed_fd):
            raise OSError("inert close failure")
    model.hook = hook
    assert_unknown(model.run(), model)
    assert model.closed == [104, 103, 102, 101]


@pytest.mark.parametrize("stage", ["directory-stat", "leaf-stat", "read", "security", "signature"])
def test_late_work_is_unknown_and_does_not_start_a_further_assurance_probe(model, stage):
    def hook(event):
        if event[0] == stage:
            model.clock = 11.0
    model.hook = hook
    result = model.run()
    assert_unknown(result, model)
    assert result.resolution_status == "rejected"
    if stage != "signature":
        assert not any(event[0] == "signature" for event in model.events)


def test_depth_and_hash_bounds_fail_closed_without_read_or_signature(model, monkeypatch):
    monkeypatch.setattr(auth, "_MAX_COMPONENT_PARENT_DEPTH", 2)
    assert_unknown(model.run(), model)
    assert model.events == [("fixed-local", LEAF)]


@pytest.mark.parametrize("aggregate", [False, True])
def test_existing_hash_byte_bounds_keep_guard_cleanup_and_no_read(model, aggregate):
    if aggregate:
        model.budget.total_bytes = auth.MAX_TOTAL_COMPONENT_BYTES
    else:
        model.names[LEAF] = info(10, st_size=auth.MAX_COMPONENT_BYTES + 1)
    result = model.run()
    assert_unknown(result, model)
    assert result.resolution_status == "rejected"
    assert not any(event[0] in {"file-open", "read", "signature"} for event in model.events)


def test_signature_failure_remains_partial_evidence_not_complete(model):
    model.provider.signature_probe = lambda *_args: (_ for _ in ()).throw(OSError("inert probe failure"))
    result = model.run()
    assert result.evidence_status == "partial" and result.authenticode_state == "error"
    assert result.sha256 == hashlib.sha256(PAYLOAD).hexdigest() and not model.held


@pytest.mark.parametrize("kind", ["directory", "reparse", "missing"])
def test_unusable_leaf_never_reaches_hash_or_probe(model, kind):
    if kind == "directory":
        model.names[LEAF] = info(10, directory=True)
    elif kind == "reparse":
        model.names[LEAF] = info(10, st_file_attributes=auth._REPARSE_POINT)
    else:
        def hook(event):
            if event[0] == "leaf-stat":
                raise FileNotFoundError("inert missing component")
        model.hook = hook
    result = model.run()
    assert_unknown(result, model)
    assert not any(event[0] in {"file-open", "read", "signature"} for event in model.events)
    if kind == "missing":
        assert result.resolution_status == "missing"


@pytest.mark.parametrize("expired", [False, True])
def test_existing_component_attempt_and_time_bounds_do_not_touch_paths(model, expired):
    if expired:
        model.clock = 11.0
    else:
        model.budget.components = auth.MAX_COMPONENTS
    result = model.run()
    assert_unknown(result, model)
    assert result.resolution_status == "rejected" and model.events == []


@pytest.mark.parametrize("drive_type", [0, 1, 2, 4, 5, 6])
def test_real_fixed_drive_gate_rejects_nonfixed_before_target_access(model, monkeypatch, drive_type):
    class DriveType:
        def __call__(self, anchor):
            model.emit("drive-type", anchor)
            return drive_type
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: SimpleNamespace(GetDriveTypeW=DriveType()), raising=False)
    monkeypatch.setattr(auth, "_require_fixed_local_path", model.original_gate)
    assert_unknown(model.run(r"Z:\configured\fixture.dll"), model)
    assert model.events == [("drive-type", "Z:\\")]


@pytest.mark.parametrize("deny_write,sharing,access", [(None, 3, 0x81), (False, 3, 0x81), (True, 1, 0x81)])
def test_native_directory_adapter_keeps_default_and_stronger_component_share_flags(model, monkeypatch, deny_write, sharing, access):
    calls = []
    class Function:
        def __init__(self, result):
            self.result = result
        def __call__(self, *args):
            calls.append(args)
            return self.result
    kernel = SimpleNamespace(CreateFileW=Function(900), CloseHandle=Function(1))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel, raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=lambda *_args: 901))
    descriptor = (model.original_guard(model.path.parent) if deny_write is None
                  else model.original_guard(model.path.parent, deny_write=deny_write))
    assert descriptor == 901
    assert calls[0][1] == access
    assert calls[0][2] == sharing
    assert calls[0][4] == 3  # OPEN_EXISTING
    assert calls[0][5] == 0x02000000 | 0x00200000
    assert calls[0][3] is None and calls[0][6] is None


NATIVE_ENABLED = os.name == "nt" and os.environ.get("ANGERONA_PRIVATE_AUTH_NATIVE") == "1"


@pytest.mark.skipif(not NATIVE_ENABLED, reason="requires separately authorized private native gate")
def test_native_owned_hardlinked_file_is_hashed_without_execution(tmp_path, monkeypatch):
    leaf = tmp_path / "owned" / "fixture.dll"
    leaf.parent.mkdir()
    leaf.write_bytes(PAYLOAD)
    os.link(leaf, leaf.parent / "fixture-alias.dll")
    monkeypatch.setattr(auth, "_file_security_from_handle", lambda *_args: ("", "", "unknown"))
    instance = provider(clock=time.monotonic)
    budget = auth._CollectionBudget(time.monotonic(), time.monotonic() + 10)
    result, _detail = instance._inspect_component(COMPONENT, str(leaf), PATH_TOKEN, "owned inert fixture", budget)
    assert result.resolution_status == "resolved"
    assert result.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert result.evidence_status == "partial" and leaf.stat().st_nlink == 2


@pytest.mark.skipif(not NATIVE_ENABLED, reason="requires separately authorized private native gate")
def test_native_owned_parent_rename_is_denied_while_held_and_allowed_after_release(tmp_path):
    parent = tmp_path / "held"
    parent.mkdir()
    leaf = parent / "fixture.dll"
    leaf.write_bytes(PAYLOAD)
    budget = auth._CollectionBudget(time.monotonic(), time.monotonic() + 10)
    with auth._component_directory_custody(leaf, budget, time.monotonic) as revalidate:
        revalidate()
        with pytest.raises(OSError):
            parent.rename(tmp_path / "renamed")
    renamed = parent.rename(tmp_path / "renamed")
    assert (renamed / "fixture.dll").read_bytes() == PAYLOAD


@pytest.mark.skipif(not NATIVE_ENABLED, reason="requires separately authorized private native gate")
@pytest.mark.parametrize("explicit_false", [False, True], ids=["omitted-default", "explicit-false"])
def test_native_owned_baseline_directory_rename_is_denied_and_released(tmp_path, explicit_false):
    # Directory only: this proves the default guard's access/sharing behavior,
    # without introducing a stronger baseline leaf adapter or mutation policy.
    parent = tmp_path / "baseline-parent"
    parent.mkdir()
    descriptor = (auth._open_windows_directory_guard(parent, deny_write=False) if explicit_false
                  else auth._open_windows_directory_guard(parent))
    try:
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
        with pytest.raises(OSError):
            parent.rename(tmp_path / "released-parent")
    finally:
        os.close(descriptor)
    renamed = parent.rename(tmp_path / "released-parent")
    assert renamed.is_dir()
