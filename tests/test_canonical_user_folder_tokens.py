"""Inert native lifecycle seams; these tests never launch a process or UI."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from angerona import __main__ as entry
from tools import windows_publication_runtime as publication


class NativeCall:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


@pytest.fixture
def native_folder(monkeypatch, tmp_path):
    events = []
    state = {"mode": "success"}
    canonical = tmp_path / "canonical-user-data"
    buffer = ctypes.create_unicode_buffer(str(canonical))

    def open_token(process, rights, output):
        events.append("open")
        assert process == 0xABC and rights == 0x000C
        output._obj.value = 0 if state["mode"] == "open-failed" else 0x123
        return state["mode"] != "open-failed"

    def query(_guid, flags, token, output):
        events.append("query")
        assert flags == 0 and token.value == 0x123
        if state["mode"] == "query-raised":
            raise OSError("query failed before allocation")
        if state["mode"] != "empty":
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = ctypes.addressof(buffer)
        return -1 if state["mode"] == "query-failed" else 0

    def free(pointer):
        events.append("free")
        assert pointer.value == ctypes.addressof(buffer)
        if state["mode"] == "free-raised":
            raise RuntimeError("allocation release failed")

    def close(token):
        events.append("close")
        assert token.value == 0x123
        return state["mode"] != "close-failed"

    libraries = {
        "kernel32": SimpleNamespace(GetCurrentProcess=NativeCall(lambda: 0xABC), CloseHandle=NativeCall(close)),
        "advapi32": SimpleNamespace(OpenProcessToken=NativeCall(open_token)),
        "shell32": SimpleNamespace(SHGetKnownFolderPath=NativeCall(query)),
        "ole32": SimpleNamespace(CoTaskMemFree=NativeCall(free)),
    }
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **_kwargs: libraries[name], raising=False)
    monkeypatch.setattr(ctypes, "WinError", lambda *_args: OSError("native open failed"), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    # This exercises the Windows-only binding without calling native functions
    # on Linux/macOS CI, where the publication module omits Windows constants.
    monkeypatch.setattr(publication, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(publication, "wintypes", wintypes, raising=False)
    monkeypatch.setattr(publication, "_TOKEN_QUERY", 0x0008, raising=False)
    monkeypatch.setattr(publication, "_FOLDERID_LOCAL_APP_DATA", ctypes.c_int(1), raising=False)
    return state, events, canonical


@pytest.mark.parametrize("helper", [entry._source_storage_known_folder, publication._token_local_app_data],
    ids=["source-guard", "publication"])
def test_explicit_process_token_is_closed_after_allocation_release(native_folder, helper):
    _state, events, canonical = native_folder
    assert helper() == canonical
    assert events == ["open", "query", "free", "close"]


@pytest.mark.parametrize("helper", [entry._source_storage_known_folder, publication._token_local_app_data],
    ids=["source-guard", "publication"])
@pytest.mark.parametrize("mode,expected", [
    ("open-failed", ["open"]),
    ("query-raised", ["open", "query", "close"]),
    ("query-failed", ["open", "query", "free", "close"]),
    ("empty", ["open", "query", "close"]),
    ("free-raised", ["open", "query", "free", "close"]),
    ("close-failed", ["open", "query", "free", "close"]),
])
def test_native_failure_never_returns_a_folder_or_retries_a_handle(native_folder, helper, mode, expected):
    state, events, _canonical = native_folder
    state["mode"] = mode
    with pytest.raises((OSError, RuntimeError)):
        helper()
    assert events == expected


def test_non_windows_source_guard_does_not_load_windows_libraries(monkeypatch):
    monkeypatch.setattr(entry, "sys", SimpleNamespace(platform="linux", frozen=False))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: pytest.fail("No Windows API on this platform"), raising=False)
    assert entry._source_activation_pending_guard() is False


def test_non_windows_publication_folder_is_explicitly_unavailable(monkeypatch):
    monkeypatch.setattr(publication, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: pytest.fail("No Windows API on this platform"), raising=False)
    with pytest.raises(publication.WindowsRuntimeError, match="unavailable"):
        publication._token_local_app_data()


@pytest.mark.parametrize("mode,operation,code", [
    ("open-failed", "token-open", 5), ("query-failed", "folder-query", 0xffffffff),
    ("close-failed", "token-close", 5)])
def test_source_folder_failures_preserve_only_closed_operation_and_numeric_code(native_folder, mode, operation, code):
    state, _events, _canonical = native_folder
    state["mode"] = mode
    with pytest.raises(OSError) as failure:
        entry._source_storage_known_folder()
    assert failure.value.source_storage_operation == operation
    assert failure.value.source_storage_code == code


def test_quiet_guard_reports_safe_operation_code_without_exception_text(monkeypatch, capsys):
    monkeypatch.setattr(entry, "sys", SimpleNamespace(platform="win32", frozen=False,
        argv=["angerona", "--community-tool-probe"], stderr=sys.stderr))
    def failed():
        error = entry._source_storage_lookup_error("folder-query", -2147024894)
        error.args = ("do not expose private path or injected instructions",)
        raise error
    monkeypatch.setattr(entry, "_source_storage_known_folder", failed)
    assert entry._source_activation_pending_guard() is True
    output = capsys.readouterr().err
    assert "folder-query" in output and "0x80070002" in output
    assert "private path" not in output and "injected" not in output


def test_publication_keeps_existing_alias_and_fixed_drive_checks(tmp_path, monkeypatch):
    base = tmp_path / "canonical"
    (base / "Temp").mkdir(parents=True)
    monkeypatch.setattr(publication, "_token_local_app_data", lambda: base)
    checked = []
    monkeypatch.setattr(publication, "_require_fixed_local_path", lambda path: checked.append(path))
    assert publication._trusted_temp_root() == base / "Temp"
    assert checked == [base / "Temp"]
    monkeypatch.setattr(Path, "resolve", lambda _self, **_kwargs: tmp_path / "different-parent")
    with pytest.raises(publication.WindowsRuntimeError, match="alias"):
        publication._trusted_temp_root()


@pytest.mark.skipif(os.name != "nt", reason="Real Windows process-token folder regression")
def test_private_profile_never_selects_publication_or_source_storage(tmp_path):
    from angerona.core.privilege import sanitized_child_environment
    from angerona.core.windows_child_job import launch_windows_child
    expected = entry._source_storage_known_folder()
    assert publication._token_local_app_data() == expected
    profile = tmp_path / "private-profile"
    (profile / "AppData" / "Local").mkdir(parents=True)
    environment = sanitized_child_environment(source={})
    environment.update({key: str(profile) for key in (
        "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "ANGERONA_DATA", "TEMP", "TMP")})
    output = tmp_path / "known-folders.json"
    repository = Path(__file__).absolute().parents[1]
    code = (
        "import json,sys;from pathlib import Path;sys.path.insert(0,sys.argv[2]);"
        "from angerona import __main__ as e;from tools import windows_publication_runtime as p;"
        "Path(sys.argv[1]).write_text(json.dumps([str(e._source_storage_known_folder()),"
        "str(p._token_local_app_data())]),encoding='utf-8')"
    )
    child = None
    try:
        child = launch_windows_child([sys.executable, "-I", "-B", "-c", code, str(output), str(repository)],
            environment, cwd=str(tmp_path), deadline=time.monotonic() + 15, window="hidden")
        assert child.wait(timeout=12) == 0
        child.wait_tree(timeout=2)
        assert [Path(value) for value in json.loads(output.read_text(encoding="utf-8"))] == [expected, expected]
        assert profile not in expected.parents
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            child.wait_tree(timeout=2)
            child.close()
