"""Inert Black Box/source-stop boundaries: no UAC, kills or firewall calls."""
from __future__ import annotations

import ast
import builtins
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import blackbox_recorder as blackbox

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("identifier", ["rule'quoted", "rule\u2018; Start-Process payload;#\u2019", "rule\u201a\u201b", "name * ? [literal]"])
@pytest.mark.parametrize("display", [False, True])
def test_blackbox_firewall_detail_passes_identifier_as_data_to_constant_query(monkeypatch, identifier, display):
    calls = []

    def read(command, **kwargs):
        calls.append((command, kwargs))
        return '{"Description":"inert detail","Program":"inert.exe"}'

    monkeypatch.setattr(blackbox, "_read_firewall_command", read)
    worker = blackbox._FwDetailWorker(identifier, display)
    results = []
    worker.done.connect(results.append)
    worker.run()
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[-1] == blackbox._FW_DETAIL_SCRIPT
    assert identifier not in command[-1]
    assert kwargs["query_environment"] == {
        "ANGERONA_BB_RULE_ID": identifier, "ANGERONA_BB_RULE_MATCH": "display" if display else "name"}
    assert results[0]["description"] == "inert detail"
    assert results[0]["program"] == "inert.exe"


def test_blackbox_detail_uses_native_binary_minimal_environment_and_system_cwd(monkeypatch):
    import subprocess
    from angerona.core import privilege

    native = Path("Q:/Windows/System32")
    monkeypatch.setattr(blackbox, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (native.parent, native))
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: native / "WindowsPowerShell/v1.0/powershell.exe")
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_: {"PATH": "fixed", "PSModulePath": "fixed"})
    for name, value in (("CREATE_NO_WINDOW", 0x08000000), ("BELOW_NORMAL_PRIORITY_CLASS", 0x4000),
                        ("CREATE_NEW_PROCESS_GROUP", 0x200)):
        monkeypatch.setattr(subprocess, name, value, raising=False)
    calls = []

    def refused(command, **kwargs):
        calls.append((command, kwargs))
        raise OSError("inert refusal before process creation")

    monkeypatch.setattr(subprocess, "Popen", refused)
    identifier = "rule\u2019; ignored as data"
    with pytest.raises(OSError, match="inert refusal"):
        blackbox._read_firewall_command(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", blackbox._FW_DETAIL_SCRIPT],
            timeout=5, query_environment={"ANGERONA_BB_RULE_ID": identifier, "ANGERONA_BB_RULE_MATCH": "name"})
    command, kwargs = calls[0]
    assert command[0] == str(native / "WindowsPowerShell/v1.0/powershell.exe")
    assert kwargs["cwd"] == str(native)
    assert kwargs["env"] == {"PATH": "fixed", "PSModulePath": "fixed",
                             "ANGERONA_BB_RULE_ID": identifier, "ANGERONA_BB_RULE_MATCH": "name"}
    assert kwargs["creationflags"] & 0x08000000


@pytest.mark.parametrize("query", [
    {"ANGERONA_BB_RULE_ID": "x", "ANGERONA_BB_RULE_MATCH": "name", "PSModulePath": "untrusted"},
    {"ANGERONA_BB_RULE_ID": "x\0y", "ANGERONA_BB_RULE_MATCH": "name"},
    {"ANGERONA_BB_RULE_ID": "x" * 4097, "ANGERONA_BB_RULE_MATCH": "name"},
    {"ANGERONA_BB_RULE_ID": "x", "ANGERONA_BB_RULE_MATCH": ["name"]},
])
def test_blackbox_query_rejects_unbounded_or_environment_authority_before_launch(monkeypatch, query):
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("unadmitted query launched"))
    with pytest.raises(ValueError):
        blackbox._read_firewall_command(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", blackbox._FW_DETAIL_SCRIPT],
            timeout=5, query_environment=query)


def test_blackbox_permission_denial_is_explanation_without_elevation(monkeypatch):
    messages = []
    view = SimpleNamespace(status=SimpleNamespace(setText=messages.append))
    blackbox.CrashInspector._explain_access_denied(view)
    assert messages and "cannot relaunch as Administrator" in messages[0]
    assert not hasattr(blackbox.CrashInspector, "_offer_elevation")


def _stop_script() -> str:
    batch = (ROOT / "kill-all-angerona.bat").read_text(encoding="utf-8")
    return batch.split("$stopCode = @'\n", 1)[1].split("\n'@", 1)[0]


@pytest.mark.parametrize("authority,active,expected", [(False, False, "request"), (True, False, "held"), (True, True, "existing")])
def test_source_stop_records_or_verifies_authenticated_stop_without_uac(authority, active, expected):
    calls = []
    admin = SimpleNamespace(stop_active=lambda: active) if authority else None
    stop = SimpleNamespace(_admin_authority=lambda: admin,
                           request_operator_stop=lambda reason: calls.append(("request", reason)),
                           is_standdown_requested=lambda: calls.append(("verified",)) or True)
    module_os = SimpleNamespace(environ={"ANGERONA_ROOT": "inert-root"}, path=os.path)
    module_sys = SimpleNamespace(path=[])

    def import_inert(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "os":
            return module_os
        if name == "sys":
            return module_sys
        if name == "angerona.resilience":
            return SimpleNamespace(shutdown_token=stop)
        raise AssertionError("unexpected helper import " + name)

    safe_builtins = dict(vars(builtins), __import__=import_inert)
    code = compile(ast.parse(_stop_script()), "inert source stop payload", "exec")
    if expected == "held":
        with pytest.raises(RuntimeError, match="will not request UAC"):
            exec(code, {"__builtins__": safe_builtins})
        assert calls == []
    else:
        exec(code, {"__builtins__": safe_builtins})
        assert calls[-1] == ("verified",)
        assert any(call[0] == "request" for call in calls) is (expected == "request")


def test_source_stop_refuses_elevated_context_before_mutable_source_or_python():
    batch = (ROOT / "kill-all-angerona.bat").read_text(encoding="utf-8")
    body = batch.split(":__ANGERONA_SOURCE_STOP__\n", 1)[1]
    assert 'set "__APPDIR__="' in batch
    assert batch.index('set "__APPDIR__="') < batch.index('%__APPDIR__%')
    assert "runas" not in batch.lower() and "-Verb" not in batch
    guard = body.index("if ($principal.IsInRole")
    assert guard < body.index("& $python -I -B -c $stopCode") < body.index(". $ownerScript")
    assert body.index("Test-AngeronaProcessOwnership") < body.index("$null = $process.Handle") < body.index("$process.Kill()")
    assert "Stop-Process -Id" not in body
    assert "Invoke-RestMethod" not in body  # no shared model is unconditionally unloaded
