from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

from angerona.core import crashlog, data_paths, startup_diagnostics

_REAL_DIAGNOSTICS = startup_diagnostics.StartupDiagnostics


@pytest.fixture
def arming(tmp_path, monkeypatch):
    records, native_calls, qt_calls = [], [], []

    class Diagnostics:
        def __init__(self, root):
            assert root == tmp_path

        def record(self, phase, state, **fields):
            records.append((phase, state, fields))
            return True

    qt = ModuleType("PySide6.QtCore")
    qt.QtMsgType = SimpleNamespace(QtCriticalMsg=2, QtFatalMsg=3)
    qt.qInstallMessageHandler = lambda callback: qt_calls.append(callback)
    monkeypatch.setitem(sys.modules, "PySide6.QtCore", qt)
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(startup_diagnostics, "StartupDiagnostics", Diagnostics)
    monkeypatch.setattr(crashlog, "_TARGETS", [])
    monkeypatch.setattr(crashlog, "_FH_FILES", [])
    monkeypatch.setattr(crashlog, "_LAST_REPORT", None)
    monkeypatch.setattr(crashlog.faulthandler, "enable", lambda **kw: native_calls.append(kw["file"].name))
    # Keep the test runner's exception hooks intact after each modeled attempt.
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(crashlog.threading, "excepthook", crashlog.threading.excepthook)
    try:
        yield SimpleNamespace(root=tmp_path, records=records, native_calls=native_calls,
                              qt_calls=qt_calls, qt=qt)
    finally:
        for stream in crashlog._FH_FILES:
            stream.close()


def test_install_is_list_compatible_with_actual_immutable_target_receipts(arming, monkeypatch, capsys):
    existing = arming.root / "logs" / "crash.log"
    existing.parent.mkdir()
    existing.write_bytes(b"preserved original\n")

    result = crashlog.install()

    assert isinstance(result, list)
    assert result == [arming.root / "logs/crash.log", arming.root / "diagnostics/crash.log"]
    report = result.report
    assert report is crashlog.latest_report() and report.state == "armed"
    assert all(row.opened and row.startup_written for row in report.targets)
    assert [row.native_selected for row in report.targets] == [False, True]
    assert report.native_fault_target == arming.root / "diagnostics/crash.log"
    assert arming.native_calls == [str(arming.root / "diagnostics/crash.log")]
    assert report.main_hook and report.thread_hook and report.qt_hook and report.diagnostics_written
    assert existing.read_bytes().startswith(b"preserved original\n")
    for target in result:
        assert "] STARTUP" in target.read_text(encoding="utf-8")
    assert arming.records[0][0:2] == ("crash-log-arming", "armed")
    assert "one native output only" in arming.records[0][2]["coverage"]
    assert capsys.readouterr().err == ""
    with pytest.raises(FrozenInstanceError):
        report.targets[0].opened = False
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_kw: pytest.fail("status must be memory-only"), raising=False)
    assert crashlog.latest_report() is report


@pytest.mark.parametrize("resolver,role", [("_data_log", "logs"), ("_repo_log", "diagnostics")])
def test_target_resolution_failure_is_reported_and_other_target_still_arms(
    arming, monkeypatch, capsys, resolver, role,
):
    def denied():
        raise PermissionError(13, "password=private-fixture; inaccessible target")
    monkeypatch.setattr(crashlog, resolver, denied)

    report = crashlog.install().report

    failed = next(row for row in report.targets if row.role == role)
    assert failed.path is None and failed.errors == ("resolve:PermissionError:13",)
    assert report.state == "partial" and report.native_fault_target is not None
    assert sum(row.startup_written for row in report.targets) == 1
    stderr = capsys.readouterr().err
    assert "resolve:PermissionError:13" in stderr and "private-fixture" not in stderr
    assert arming.records[0][1] == "partial"


def test_all_resolvers_fail_reports_unavailable_and_returns_legacy_empty_list(arming, monkeypatch, capsys):
    def denied():
        raise OSError("private path")
    monkeypatch.setattr(crashlog, "_data_log", denied)
    monkeypatch.setattr(crashlog, "_repo_log", denied)

    result = crashlog.install()

    assert result == [] and result.report.state == "unavailable"
    assert result.report.native_fault_target is None and not arming.native_calls
    assert result.report.diagnostics_written and arming.records[0][1] == "unavailable"
    assert "Startup continues" in capsys.readouterr().err


def test_open_failure_and_startup_append_failure_are_separate(arming, monkeypatch, capsys):
    real_open = open
    attempts = {}
    def selective_open(path, *args, **kwargs):
        path = Path(path)
        attempts[path] = attempts.get(path, 0) + 1
        if path.parent.name == "logs" and attempts[path] == 1:
            raise PermissionError(13, "secret=do-not-publish")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(crashlog, "open", selective_open, raising=False)

    report = crashlog.install().report

    logs = report.targets[0]
    assert not logs.opened and logs.startup_written
    assert logs.errors == ("open:PermissionError:13",)
    assert report.state == "partial" and report.targets[1].native_selected
    assert "secret=" not in capsys.readouterr().err


def test_startup_write_failure_cannot_advertise_writable_target(arming, monkeypatch):
    real_open = open
    attempts = {}
    def selective_open(path, *args, **kwargs):
        path = Path(path)
        attempts[path] = attempts.get(path, 0) + 1
        if path.parent.name == "logs" and attempts[path] == 2:
            raise OSError(28, "private fixture full")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(crashlog, "open", selective_open, raising=False)

    report = crashlog.install().report

    assert report.targets[0].opened and not report.targets[0].startup_written
    assert report.targets[0].errors == ("startup-write:OSError:28",)
    assert report.targets[1].startup_written and report.state == "partial"
    assert any("startup=False" in row for row in arming.records[0][2]["actual"])


@pytest.mark.parametrize("fail_all", [False, True])
def test_native_enable_failure_reports_real_single_output_or_unavailable(arming, monkeypatch, fail_all):
    def enable(**kwargs):
        path = kwargs["file"].name
        arming.native_calls.append(path)
        if fail_all or Path(path).parent.name == "diagnostics":
            raise OSError(5, "private native failure")
    monkeypatch.setattr(crashlog.faulthandler, "enable", enable)

    report = crashlog.install().report

    assert report.state == "partial"
    assert report.targets[1].errors == ("faulthandler:OSError:5",)
    assert not report.targets[1].native_selected
    assert report.targets[0].native_selected is not fail_all
    assert report.native_fault_target == (None if fail_all else arming.root / "logs/crash.log")
    assert len(arming.native_calls) == 2 and sum(row.native_selected for row in report.targets) <= 1


def test_qt_hook_failure_is_visible_without_stopping_python_log_capture(arming, monkeypatch):
    def unavailable(_callback):
        raise RuntimeError("private Qt issue")
    monkeypatch.setattr(arming.qt, "qInstallMessageHandler", unavailable)

    report = crashlog.install().report

    assert report.main_hook and report.thread_hook and not report.qt_hook
    assert report.errors == ("qt-hook:RuntimeError",) and report.state == "partial"
    assert all(row.startup_written for row in report.targets)


@pytest.mark.parametrize("raises", [False, True])
def test_private_diagnostic_sink_failure_is_observable_and_never_fatal(arming, monkeypatch, capsys, raises):
    class Unavailable:
        def __init__(self, _root):
            if raises:
                raise PermissionError("password=private")
        def record(self, *_a, **_kw):
            return False
    monkeypatch.setattr(startup_diagnostics, "StartupDiagnostics", Unavailable)

    report = crashlog.install().report

    assert report.state == "armed" and not report.diagnostics_written
    assert report.diagnostics_error == ("PermissionError" if raises else "private-receipt-unavailable")
    stderr = capsys.readouterr().err
    assert len(stderr) < 700 and "diagnostics:" in stderr and "password=" not in stderr


@pytest.mark.parametrize("diagnostic_available", [False, True])
def test_actual_entry_survives_installer_failure_and_reports_it(
    tmp_path, monkeypatch, capsys, diagnostic_available,
):
    from angerona import __main__ as entry
    from angerona.core import hardening, privilege, singleton, win
    rows = []
    class Diagnostics:
        def __init__(self, root):
            assert root == tmp_path
        def record(self, *args, **kwargs):
            rows.append((args, kwargs))
            return diagnostic_available
    def failed_install():
        raise PermissionError("token=private-fixture")
    monkeypatch.setattr(entry.sys, "argv", ["angerona", "--headless"])
    monkeypatch.setattr(entry.sys, "frozen", False, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(win, "install_no_window_default", lambda: None)
    monkeypatch.setattr(crashlog, "install", failed_install)
    monkeypatch.setattr(startup_diagnostics, "StartupDiagnostics", Diagnostics)
    monkeypatch.setattr(hardening, "apply_process_mitigations", lambda: None)
    # Reaching this supported return proves logger failure did not block entry.
    # No headless graph, application, Qt instance or sensors are constructed.
    reached = []
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda: reached.append(True))

    assert entry.main() == 0 and reached == [True]
    assert rows[0][0] == ("crash-log-arming", "unavailable")
    assert rows[0][1]["exception_type"] == "PermissionError"
    stderr = capsys.readouterr().err
    assert "Crash logging unavailable" in stderr and "Startup continues" in stderr
    assert "token=" not in stderr and "private-fixture" not in stderr


def test_cold_import_does_not_load_qt_config_or_application():
    script = """
import builtins, sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('PySide6', 'angerona.app', 'angerona.core.config', 'angerona.modules')):
        raise AssertionError('cold crashlog import attempted: ' + name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from angerona.core import crashlog
assert crashlog.latest_report() is None
assert crashlog._TARGETS == [] and crashlog._FH_FILES == []
print('CRASHLOG_COLD_IMPORT_OK')
"""
    result = subprocess.run([sys.executable, "-B", "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CRASHLOG_COLD_IMPORT_OK" in result.stdout


def test_real_private_startup_receipt_uses_existing_bounded_writer(arming, monkeypatch):
    monkeypatch.setattr(startup_diagnostics, "StartupDiagnostics", _REAL_DIAGNOSTICS)

    report = crashlog.install().report

    assert report.diagnostics_written
    path = arming.root / "diagnostics/startup-diagnostics.jsonl"
    raw = path.read_bytes()
    assert len(raw) < startup_diagnostics.MAX_FRAME_BYTES
    row = json.loads(raw)
    assert row["schema"] == "angerona-startup-diagnostics-v1"
    assert row["phase"] == "crash-log-arming" and row["status"] == "armed"
    assert len(row["actual"]) == 2 and all(len(value) <= 256 for value in row["actual"])
    assert "one native output only" in row["coverage"]
