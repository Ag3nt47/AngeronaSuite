"""Inert child-launch selection tests: no executable is ever started."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import privilege
from angerona.modules import kernel_posture_ledger as ledger


@pytest.fixture
def inbox(tmp_path, monkeypatch):
    # The fixture files are inert bytes, not executables. Every child call is
    # intercepted; touching one never provides launch authority to this test.
    windows = tmp_path / "trusted-windows"
    system = windows / "System32"
    powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    for path in (powershell, system / "bcdedit.exe", system / "wevtutil.exe"):
        path.write_bytes(b"inert fixture; never execute")
    monkeypatch.setattr(ledger, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(privilege, "_windows_api_directory", lambda name: {
        "GetWindowsDirectoryW": windows, "GetSystemDirectoryW": system,
    }[name])
    calls = []

    def record(argv, **kwargs):
        calls.append((argv, kwargs))
        name = Path(argv[0]).name
        stdout = "true" if name == "powershell.exe" else ""
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(ledger, "run_hidden", record)
    return windows, system, powershell, calls


@pytest.mark.parametrize("poison", ["cwd", "path", "systemroot", "all"])
def test_all_three_launchers_ignore_local_and_environment_decoys(
    inbox, tmp_path, monkeypatch, poison,
):
    windows, system, powershell, calls = inbox
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    for name in ("powershell.exe", "bcdedit.exe", "wevtutil.exe"):
        (decoy / name).write_bytes(b"not a PE; never execute")
    if poison in {"cwd", "all"}:
        monkeypatch.chdir(decoy)
    if poison in {"path", "all"}:
        monkeypatch.setenv("PATH", str(decoy))
    if poison in {"systemroot", "all"}:
        monkeypatch.setenv("SystemRoot", str(decoy))
        monkeypatch.setenv("WINDIR", str(decoy))
    assert ledger._powershell_json("[bool](Confirm-SecureBootUEFI)", timeout=2.25) is True
    assert ledger._boot_flags() == dict(testsigning=False, debug=False, nointegritychecks=False)
    assert ledger._code_integrity_log() is True
    assert [call[0][0] for call in calls] == [
        str(powershell), str(system / "bcdedit.exe"), str(system / "wevtutil.exe"),
    ]
    assert all(Path(call[0][0]).is_absolute() for call in calls)
    assert calls[0][0][1:] == [
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
        "$ErrorActionPreference='Stop'; [bool](Confirm-SecureBootUEFI) | ConvertTo-Json -Compress",
    ]
    assert calls[0][1] == dict(capture_output=True, text=True, timeout=2.25, check=False)
    assert calls[1][0][1:] == ["/enum", "{current}"]
    assert calls[2][0][1:] == ["gli", "Microsoft-Windows-CodeIntegrity/Operational"]
    assert calls[1][1] == calls[2][1] == dict(
        capture_output=True, text=True, timeout=6, check=False,
    )
    assert privilege.trusted_windows_directories() == (windows, system)


@pytest.mark.parametrize("tool", ["powershell", "bcdedit", "wevtutil"])
@pytest.mark.parametrize("failure", ["api-failed", "missing-tool"])
def test_no_bare_fallback_on_trusted_resolution_or_tool_failure(
    inbox, monkeypatch, tool, failure,
):
    _windows, system, powershell, calls = inbox
    if failure == "api-failed":
        def unavailable(_name):
            raise OSError("Windows directory API unavailable")
        monkeypatch.setattr(privilege, "_windows_api_directory", unavailable)
    else:
        (powershell if tool == "powershell" else system / (tool + ".exe")).unlink()
    if tool == "powershell":
        assert ledger._powershell_json("1") is None
    elif tool == "bcdedit":
        assert ledger._boot_flags() == dict(testsigning=None, debug=None, nointegritychecks=None)
    else:
        assert ledger._code_integrity_log() is None
    assert calls == []


@pytest.mark.parametrize("tool", ["powershell", "bcdedit", "wevtutil"])
def test_absolute_tool_launch_failure_remains_unknown_without_retry(inbox, monkeypatch, tool):
    _windows, system, powershell, calls = inbox

    def missing(argv, **kwargs):
        calls.append((argv, kwargs))
        raise FileNotFoundError("trusted file disappeared before CreateProcess")

    monkeypatch.setattr(ledger, "run_hidden", missing)
    if tool == "powershell":
        assert ledger._powershell_json("1") is None
        expected = powershell
    elif tool == "bcdedit":
        assert ledger._boot_flags() == dict(testsigning=None, debug=None, nointegritychecks=None)
        expected = system / "bcdedit.exe"
    else:
        assert ledger._code_integrity_log() is None
        expected = system / "wevtutil.exe"
    assert len(calls) == 1 and calls[0][0][0] == str(expected)


def test_nonwindows_collectors_never_resolve_or_launch(monkeypatch):
    monkeypatch.setattr(ledger, "os", SimpleNamespace(name="posix"))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("non-Windows provider tried resolving or launching a tool")

    monkeypatch.setattr(ledger, "trusted_powershell_path", forbidden)
    monkeypatch.setattr(ledger, "trusted_windows_directories", forbidden)
    monkeypatch.setattr(ledger, "run_hidden", forbidden)
    assert ledger._powershell_json("1") is None
    assert ledger._boot_flags() == dict(testsigning=None, debug=None, nointegritychecks=None)
    assert ledger._code_integrity_log() is None


@pytest.mark.skipif(privilege.sys.platform != "win32", reason="native Windows directory API")
def test_native_windows_root_selection_survives_all_decoys(tmp_path, monkeypatch):
    # These calls resolve OS roots only; all potential process launches below
    # remain intercepted. This independently exercises the real WinAPI seam.
    windows, system = privilege.trusted_windows_directories()
    powershell = privilege.trusted_powershell_path()
    expected = [powershell, system / "bcdedit.exe", system / "wevtutil.exe"]
    decoy = tmp_path / "native-decoys"
    decoy.mkdir()
    for name in ("powershell.exe", "bcdedit.exe", "wevtutil.exe"):
        (decoy / name).write_bytes(b"inert decoy; never execute")
    monkeypatch.chdir(decoy)
    monkeypatch.setenv("PATH", str(decoy))
    monkeypatch.setenv("SystemRoot", str(decoy))
    monkeypatch.setenv("WINDIR", str(decoy))
    calls = []

    def record(argv, **_kwargs):
        calls.append(Path(argv[0]))
        return SimpleNamespace(returncode=0, stdout="true")

    monkeypatch.setattr(ledger, "run_hidden", record)
    ledger._powershell_json("1")
    ledger._boot_flags()
    ledger._code_integrity_log()
    assert privilege.trusted_windows_directories() == (windows, system)
    assert privilege.trusted_powershell_path() == powershell
    assert calls == [path for path in expected if path.is_file()]
    assert all(path.is_absolute() and decoy not in path.parents for path in calls)
