"""Inert WLAN collector command-admission checks; no native utility is run."""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from angerona.core import privilege
from angerona.modules import wlan_monitor


_CONNECTED = (
    "    State : connected\n    SSID : fixture-network\n"
    "    BSSID : 02:11:22:33:44:55\n    Signal : 75%\n"
    "    Authentication : WPA3-Personal\n    Cipher : CCMP\n"
)


@pytest.fixture
def command_boundary(monkeypatch):
    native = Path("Q:/Windows/System32")
    clean = {"SystemRoot": str(native.parent), "PATH": str(native)}
    calls, sources = [], []
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (native.parent, native))

    def environment(overrides=None, *, source=None):
        assert overrides is None
        sources.append(source)
        return dict(clean)

    def capture(argv, **options):
        calls.append((argv, options))
        return _CONNECTED

    monkeypatch.setattr(privilege, "sanitized_child_environment", environment)
    monkeypatch.setattr(subprocess, "check_output", capture)
    return native, clean, calls, sources


@pytest.mark.parametrize("query_name", ("_query_netsh", "_query_wlan"))
def test_wlan_queries_use_fixed_native_command_without_ambient_loading(monkeypatch, command_boundary, query_name):
    native, clean, calls, sources = command_boundary
    for name in ("PATH", "SystemRoot", "WINDIR", "PYTHONPATH", "PSModulePath", "ANGERONA_API_KEY"):
        monkeypatch.setenv(name, "untrusted ambient value")

    result = getattr(wlan_monitor, query_name)()
    if query_name == "_query_wlan":
        assert result.status == "connected"
        result = result.state
    assert result["ssid"] == "fixture-network"
    assert result["bssid"] == "02:11:22:33:44:55"
    assert result["signal"] == 75
    assert len(calls) == 1
    argv, options = calls[0]
    assert argv == [str(native / "netsh.exe"), "wlan", "show", "interfaces"]
    assert options["cwd"] == str(native)
    assert options["env"] == clean
    assert sources == [{}, clean]  # Explicit empty source, then the hidden helper's recheck.
    assert options["stdin"] == subprocess.DEVNULL
    assert options["stderr"] == subprocess.DEVNULL
    assert options["close_fds"] is True
    assert options["shell"] is False
    assert options["timeout"] == 10
    assert options["text"] is True and options["errors"] == "replace"
    if wlan_monitor.os.name == "nt":
        assert options["creationflags"] & 0x08000000
        assert options["startupinfo"].wShowWindow == 0


@pytest.mark.parametrize("query_name", ("_query_netsh", "_query_wlan"))
@pytest.mark.parametrize("boundary", ("native-directory", "environment"))
def test_wlan_command_admission_failure_never_falls_back_to_path(monkeypatch, command_boundary, query_name, boundary):
    _native, _clean, calls, _sources = command_boundary

    def unavailable(*_args, **_kwargs):
        raise OSError("inert " + boundary + " unavailable")

    symbol = "trusted_windows_directories" if boundary == "native-directory" else "sanitized_child_environment"
    monkeypatch.setattr(privilege, symbol, unavailable)
    result = getattr(wlan_monitor, query_name)()
    if query_name == "_query_wlan":
        assert result.status == "error" and result.state is None
        assert boundary in result.reason and "unavailable" in result.reason
    else:
        assert result is None
    assert calls == []


@pytest.mark.parametrize("output", ("There is no wireless interface on the system.\n", "unrecognized interface output\n"))
def test_wlan_unknown_or_missing_interface_never_claims_disconnected(monkeypatch, command_boundary, output):
    monkeypatch.setattr(subprocess, "check_output", lambda *_args, **_kwargs: output)
    result = wlan_monitor._query_wlan()
    assert result.status == "error" and result.state is None
    assert "no parseable interface state" in result.reason


@pytest.mark.parametrize("failure", ("exit", "timeout"))
def test_wlan_native_collection_failure_stays_unavailable(monkeypatch, command_boundary, failure):
    def fail(argv, **_options):
        if failure == "exit":
            raise subprocess.CalledProcessError(1, argv)
        raise subprocess.TimeoutExpired(argv, 10)

    monkeypatch.setattr(subprocess, "check_output", fail)
    result = wlan_monitor._query_wlan()
    assert result.status == "error" and result.state is None
    assert result.reason
