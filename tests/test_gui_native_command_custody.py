"""Extract only two read helpers; all process adapters are inert fakes."""
import ast
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
import pytest
from angerona.core import privilege

ROOT = Path(__file__).resolve().parents[1]


def load_helper(relative, name, **namespace):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name)
    code = ast.Module(body=[node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(code), relative, "exec"), namespace)
    return namespace[name]


def native_fixture(monkeypatch):
    native = Path("Q:/Windows/System32")
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (native.parent, native))
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: native / "WindowsPowerShell/v1.0/powershell.exe")
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda: {"PATH": "fixed", "PSModulePath": "fixed"})
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    return native


def test_authenticode_read_uses_native_absolute_command_and_clean_environment(monkeypatch):
    native = native_fixture(monkeypatch)
    calls = []
    def capture(argv, **kwargs):
        calls.append((argv, kwargs))
        return "Valid\n"
    monkeypatch.setattr(subprocess, "check_output", capture)
    helper = load_helper("src/angerona/gui/pages.py", "_authenticode_status", os=os,
                         subprocess=subprocess, _AUTHENTICODE_SCRIPT="fixed literal script")
    path = "Q:/private/file'\u2019.exe"
    assert helper(path) == "Valid"
    argv, options = calls[0]
    assert argv[0] == str(native / "WindowsPowerShell/v1.0/powershell.exe")
    assert argv[-1] == "fixed literal script" and path not in argv[-1]
    assert options["env"] == {"PATH": "fixed", "PSModulePath": "fixed", "ANGERONA_AUTHENTICODE_PATH": path}
    assert options["cwd"] == str(native)
    assert options["creationflags"] == 0x08000000


def test_wifi_read_uses_native_absolute_command_and_clean_environment(monkeypatch):
    native = native_fixture(monkeypatch)
    calls = []
    def capture(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout=" Signal : 75%\n", returncode=0)
    monkeypatch.setattr(subprocess, "run", capture)
    helper = load_helper("src/angerona/gui/system_pulse.py", "_wifi_signal_windows",
                         sys=SimpleNamespace(platform="win32"), subprocess=subprocess, re=re)
    assert helper() == 75
    argv, options = calls[0]
    assert argv == [str(native / "netsh.exe"), "wlan", "show", "interfaces"]
    assert options["env"] == {"PATH": "fixed", "PSModulePath": "fixed"}
    assert options["cwd"] == str(native)
    assert options["creationflags"] == 0x08000000
