"""Directory custody is proved before opening any stronger leaf-file handle."""
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

from angerona.core import analysis_vmware_setup as setup, live_debug, source_sandbox
from angerona.core.eventbus import EventBus


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing contract")


@pytest.fixture
def summary():
    path = Path(__file__).resolve().parents[1] / "tools/summarize_live_debug.py"
    spec = importlib.util.spec_from_file_location("directory_custody_summary_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rename_is_denied(parent: Path) -> None:
    moved = parent.with_name(parent.name + "-unexpected-move")
    try:
        parent.rename(moved)
    except OSError as exc:
        assert exc.winerror in (5, 32), exc
    else:
        # Restore only the exact owned fixture if the regression is present.
        moved.rename(parent)
        pytest.fail("Held directory could be renamed before a leaf handle was opened")
    assert parent.is_dir() and not moved.exists()


def _rename_after_release(parent: Path) -> None:
    moved = parent.with_name(parent.name + "-released")
    parent.rename(moved)
    assert moved.is_dir() and not parent.exists()


def test_source_guard_requests_sharing_relevant_access_and_closes_reverse(tmp_path, monkeypatch):
    """Inert CreateFile/CloseHandle doubles exercise the actual shared helper."""
    parent = tmp_path / "owned"
    parent.mkdir()
    calls, closed = [], []

    def create(name, access, share, security, disposition, flags, template):
        calls.append((name, access, share, security, disposition, flags, template))
        return len(calls) + 100

    def close(handle):
        closed.append(handle)
        return 1

    monkeypatch.setattr(ctypes.windll.kernel32, "CreateFileW", create)
    monkeypatch.setattr(ctypes.windll.kernel32, "CloseHandle", close)
    with source_sandbox._hold_plain_directories(parent, parent):
        assert calls and not closed
        assert len(calls) == len(source_sandbox._chain(parent))
        assert all(row[1:] == (0x81, 3, None, 3, 0x02200000, None) for row in calls)
    assert closed == list(reversed(range(101, 101 + len(calls))))


def test_source_guard_denial_closes_existing_handles_without_metadata_fallback(tmp_path, monkeypatch):
    parent = tmp_path / "owned"
    parent.mkdir()
    access_modes, closed = [], []

    def create(_name, access, *_args):
        access_modes.append(access)
        if len(access_modes) == 2:
            ctypes.set_last_error(5)
            return ctypes.c_void_p(-1).value
        return 101

    def close(handle):
        closed.append(handle)
        return 1

    monkeypatch.setattr(ctypes.windll.kernel32, "CreateFileW", create)
    monkeypatch.setattr(ctypes.windll.kernel32, "CloseHandle", close)
    with pytest.raises(OSError):
        with source_sandbox._hold_plain_directories(parent):
            pytest.fail("Denied custody yielded a trusted scope")
    assert access_modes == [0x81, 0x81]
    assert closed == [101]


def test_log_parent_denial_is_unavailable_and_does_not_fallback(tmp_path, monkeypatch):
    import win32file

    calls = []
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs/crash.log").write_bytes(b"unread fixture content\n")

    def denied(_name, access, share, *_args):
        calls.append((access, share))
        raise PermissionError("inert directory access denial")

    monkeypatch.setattr(win32file, "CreateFile", denied)
    service = live_debug.LiveDebugService(EventBus(), tmp_path)
    service._tail_log("logs/crash.log")
    rows = service.recent()["records"]
    assert calls == [(0x81, 3)]
    assert rows[-1]["kind"] == "coverage" and rows[-1]["state"] == "unavailable"
    assert "unread fixture content" not in json.dumps(rows)


def test_summary_parent_denial_propagates_without_metadata_fallback(tmp_path, monkeypatch, summary):
    import win32file

    calls = []

    def denied(_name, access, share, *_args):
        calls.append((access, share))
        raise PermissionError("inert directory access denial")

    monkeypatch.setattr(win32file, "CreateFile", denied)
    with pytest.raises(PermissionError):
        with summary._parent_chain(tmp_path / "absent-leaf.jsonl"):
            pytest.fail("Denied capture custody yielded a trusted scope")
    assert calls == [(0x81, 3)]


def test_attribute_only_negative_control_allows_owned_directory_rename(tmp_path):
    """READ_ATTRIBUTES alone does not establish a delete-sharing constraint."""
    import win32file

    parent = tmp_path / "attribute-only"
    parent.mkdir()
    moved = parent.with_name(parent.name + "-moved")
    handle = win32file.CreateFile(str(parent), 0x80, 3, None, 3, 0x02200000, None)
    try:
        parent.rename(moved)
        assert moved.is_dir() and not parent.exists()
    finally:
        handle.Close()


def test_source_directory_only_guard_denies_rename_until_release(tmp_path):
    parent = tmp_path / "source-parent"
    parent.mkdir()
    # There is no child file or leaf-file handle in this fixture.
    with source_sandbox._hold_plain_directories(parent):
        _rename_is_denied(parent)
    _rename_after_release(parent)


def test_summary_directory_only_guard_denies_rename_until_release(tmp_path, summary):
    parent = tmp_path / "capture-parent"
    parent.mkdir()
    # The chosen leaf is absent: _parent_chain must supply all custody itself.
    with summary._parent_chain(parent / "absent-leaf.jsonl"):
        _rename_is_denied(parent)
    _rename_after_release(parent)


def test_log_parent_guard_denies_rename_before_leaf_open(tmp_path, monkeypatch):
    import win32con
    import win32file

    parent = tmp_path / "logs"
    parent.mkdir()
    path = parent / "crash.log"
    path.write_bytes(b"bounded fixture\n")
    original = win32file.CreateFile
    directory_calls, leaf_challenges = [], []

    def checked(name, access, share, *args):
        if name == str(path):
            assert access == win32con.GENERIC_READ and share == 7
            # Perform the challenge BEFORE the original CreateFile can supply
            # a leaf handle. A passing test therefore proves directory custody.
            _rename_is_denied(parent)
            leaf_challenges.append(True)
        else:
            directory_calls.append((access, share))
            assert access == 0x81 and share == 3
        return original(name, access, share, *args)

    monkeypatch.setattr(win32file, "CreateFile", checked)
    service = live_debug.LiveDebugService(EventBus(), tmp_path)
    with service._open_log("logs/crash.log") as (stream, info):
        assert stream.read() == b"bounded fixture\n" and info.st_nlink == 1
    assert directory_calls and leaf_challenges == [True]
    _rename_after_release(parent)


def _service_directory_segment() -> str:
    start = setup._CONFIGURE_SCRIPT.index("    Add-Type -Namespace Angerona -Name SetupDirectoryCustody")
    stop = setup._CONFIGURE_SCRIPT.index("    $serviceItem =", start)
    segment = setup._CONFIGURE_SCRIPT[start:stop]
    assert "CreateFileW($parentPath, 0x81, 3," in segment
    for forbidden in ("Get-CimInstance", "Set-Service", "Start-Service", "Get-AuthenticodeSignature", "OpenBaseKey"):
        assert forbidden not in segment
    return segment


def test_vmware_directory_body_is_mirrored_and_has_no_host_actions():
    script = (Path(__file__).resolve().parents[1] / "tools/enable_analysis_lab_vmware.ps1").read_text(encoding="utf-8")
    assert script.endswith(setup._CONFIGURE_SCRIPT)
    _service_directory_segment()


def test_vmware_extracted_directory_only_guard_denies_rename_until_release(tmp_path):
    """Execute only the unchanged custody segment; never execute service setup."""
    import psutil
    from angerona.core.privilege import (
        sanitized_child_environment, trusted_powershell_path, trusted_windows_directories,
    )

    parent = tmp_path / "vmware-directory-only"
    parent.mkdir()
    temporary = tmp_path / "powershell-temp"
    temporary.mkdir()
    program = r'''
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1"
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1"
$directoryGuards = New-Object 'System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
$expectedDirectory = $env:ANGERONA_DIRECTORY_CUSTODY_FIXTURE
try {
'''
    program += _service_directory_segment()
    program += r'''
    $denied = $false
    try { [IO.Directory]::Move($expectedDirectory, $expectedDirectory + '-unexpected-move') }
    catch [IO.IOException] { $denied = $true }
    catch [UnauthorizedAccessException] { $denied = $true }
    if (-not $denied) { throw 'Owned fixture rename succeeded while directory guards were held.' }
} finally { foreach ($guard in $directoryGuards) { $guard.Dispose() } }
[IO.Directory]::Move($expectedDirectory, $expectedDirectory + '-released')
exit 0
'''
    environment = sanitized_child_environment(source={})
    environment.update({
        "TEMP": str(temporary), "TMP": str(temporary),
        "PSModuleAnalysisCachePath": str(temporary / "ModuleAnalysisCache"),
        "PSModulePath": str(trusted_powershell_path().parent / "Modules"),
        "ANGERONA_DIRECTORY_CUSTODY_FIXTURE": str(parent),
    })
    process = subprocess.Popen(
        [str(trusted_powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand", setup._encoded(program)],
        cwd=str(trusted_windows_directories()[1]), env=environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    birth = psutil.Process(process.pid).create_time()
    try:
        _stdout, stderr = process.communicate(timeout=90)
    finally:
        if process.poll() is None:
            process.kill()  # Exact fixture-owned Popen handle only.
            process.wait(timeout=10)
        try:
            retired = psutil.Process(process.pid).create_time() != birth
        except psutil.NoSuchProcess:
            retired = True
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        wait = kernel32.WaitForSingleObject
        wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        wait.restype = wintypes.DWORD
        kernel_wait_status = int(wait(wintypes.HANDLE(int(process._handle)), 0))
        audit = os.environ.get("ANGERONA_DIRECTORY_CUSTODY_AUDIT")
        if audit:
            with open(audit, "a", encoding="utf-8") as stream:
                stream.write(json.dumps({"pid": process.pid, "birth": birth, "retired": retired,
                    "native_exit": process.returncode, "kernel_wait_status": kernel_wait_status,
                    "pid_enumeration_advisory_only": True,
                    "program_sha256": hashlib.sha256(program.encode()).hexdigest()}) + "\n")
    assert kernel_wait_status == 0  # WAIT_OBJECT_0 on the retained actual PowerShell handle.
    assert process.returncode == 0, stderr.decode(errors="replace")[-2000:]
    assert parent.with_name(parent.name + "-released").is_dir() and not parent.exists()
