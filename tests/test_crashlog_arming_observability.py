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
_PID = 81001
_BIRTH = "134378104580365256"


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
    monkeypatch.setattr(crashlog, "_NORMAL_PATHS", {})
    monkeypatch.setattr(crashlog, "_NORMAL_ROWS",
                        {role: crashlog._NormalTarget(role) for role in crashlog._NORMAL_ROLES})
    monkeypatch.setattr(crashlog, "_NORMAL_SUPPRESSIONS",
                        {role: (0, 0, 0, "") for role in crashlog._NORMAL_ROLES})
    monkeypatch.setattr(crashlog, "_NORMAL_COUNT_GAP", False)
    monkeypatch.setattr(crashlog, "_NORMAL_LOCK", crashlog.threading.Lock())
    monkeypatch.setattr(crashlog, "_NORMAL_STATS_LOCK", crashlog.threading.Lock())
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(crashlog, "_NORMAL_MESSAGE_BYTES", 64 * 1024)
    monkeypatch.setattr(crashlog, "_NORMAL_PAUSED", False)
    monkeypatch.setattr(crashlog, "_NORMAL_CONFIGURED_AT", None)
    monkeypatch.setattr(crashlog, "_NORMAL_CACHE", crashlog._NORMAL_CACHE)
    crashlog._cache_normal_budget()
    monkeypatch.setattr(crashlog, "os", SimpleNamespace(getpid=lambda: _PID))
    monkeypatch.setattr(startup_diagnostics, "process_identity",
                        lambda: {"pid": _PID, "birth_filetime": _BIRTH})
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


def test_native_current_thread_scope_accepts_the_real_none_success_contract(arming, monkeypatch):
    calls = []

    def enable(*, file, all_threads):
        calls.append((file, all_threads))
        return None  # CPython's successful enable() return value.

    monkeypatch.setattr(crashlog.faulthandler, "enable", enable)
    report = crashlog.install().report

    assert report.state == "armed" and len(calls) == 1
    assert calls[0][1] is False and not calls[0][0].closed
    assert Path(calls[0][0].name) == report.native_fault_target
    assert "native_threads=current" in arming.records[-1][2]["coverage"]


def test_positional_only_native_fallback_never_restores_default_all_threads(arming, monkeypatch):
    calls = []

    def enable(file, all_threads=True, /):
        calls.append((file, all_threads))

    monkeypatch.setattr(crashlog.faulthandler, "enable", enable)
    report = crashlog.install().report

    assert report.state == "armed" and len(calls) == 1
    assert calls[0][1] is False and Path(calls[0][0].name) == report.native_fault_target


def test_failed_positional_fallback_preserves_scope_for_the_second_output(arming, monkeypatch):
    calls = []

    def enable(*args, **kwargs):
        calls.append((args, kwargs))
        if kwargs:
            assert kwargs["all_threads"] is False
            raise TypeError("fixture positional API")
        assert len(args) == 2 and args[1] is False
        if Path(args[0].name).parent.name == "diagnostics":
            raise OSError(5, "private fixture native failure")

    monkeypatch.setattr(crashlog.faulthandler, "enable", enable)
    report = crashlog.install().report

    assert report.state == "partial" and len(calls) == 4
    assert report.targets[1].errors == ("faulthandler:OSError:5",)
    assert report.native_fault_target == arming.root / "logs/crash.log"
    assert all(not stream.closed for stream in crashlog._FH_FILES)
    assert "native_threads=current" in arming.records[-1][2]["coverage"]


@pytest.mark.parametrize("unavailable", [None, False])
def test_unavailable_native_api_is_not_reported_as_armed(arming, monkeypatch, unavailable):
    monkeypatch.setattr(crashlog.faulthandler, "enable", unavailable)
    report = crashlog.install().report

    assert report.state == "partial" and report.native_fault_target is None
    assert all(not row.native_selected and row.errors == ("faulthandler:TypeError",)
               for row in report.targets)
    assert report.main_hook and report.thread_hook and report.qt_hook
    assert "native_threads=unavailable" in arming.records[-1][2]["coverage"]


def test_native_scope_change_keeps_complete_python_exception_and_qt_evidence(arming, monkeypatch):
    forwarded = []
    monkeypatch.setattr(sys, "__excepthook__", lambda *args: forwarded.append(args))
    report = crashlog.install().report

    def owned_python_evidence():
        raise ValueError("OWNED_PYTHON_STACK_WITNESS")

    try:
        owned_python_evidence()
    except ValueError:
        captured = sys.exc_info()
        sys.excepthook(*captured)
        crashlog.threading.excepthook(SimpleNamespace(
            thread=SimpleNamespace(name="OwnedPythonWitness"),
            exc_type=captured[0], exc_value=captured[1], exc_traceback=captured[2],
        ))
    arming.qt_calls[0](arming.qt.QtMsgType.QtCriticalMsg, None, "OWNED_QT_CRITICAL_WITNESS")

    assert report.main_hook and report.thread_hook and report.qt_hook and len(forwarded) == 1
    for target in report.targets:
        evidence = target.path.read_text("utf-8")
        assert "UNHANDLED EXCEPTION (main)" in evidence
        assert "THREAD EXCEPTION (OwnedPythonWitness)" in evidence
        assert evidence.count("ValueError: OWNED_PYTHON_STACK_WITNESS") == 2
        assert "owned_python_evidence" in evidence and "OWNED_QT_CRITICAL_WITNESS" in evidence


def test_native_scope_change_keeps_python_owned_all_thread_snapshot(arming, monkeypatch):
    from angerona.resilience import diagnostics

    entered, release = crashlog.threading.Event(), crashlog.threading.Event()

    def owned_python_snapshot_witness():
        entered.set()
        release.wait(10)

    worker = crashlog.threading.Thread(
        target=owned_python_snapshot_witness, name="OwnedPythonSnapshotWitness", daemon=True,
    )
    worker.start()
    try:
        assert entered.wait(5)
        crashlog.install()
        monkeypatch.setattr(diagnostics, "diag_dir", lambda: arming.root)
        assert diagnostics.write_thread_dump()
        report = json.loads((arming.root / "thread_dump.json").read_text("utf-8"))
        own_rows = [row for row in report["threads"] if row["name"] == "OwnedPythonSnapshotWitness"]
        assert len(own_rows) == 1
        assert any("owned_python_snapshot_witness" in frame for frame in own_rows[0]["stack"])
        assert any("test_native_scope_change_keeps_python_owned_all_thread_snapshot" in frame
                   for row in report["threads"] for frame in row["stack"])
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()


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
    if name.startswith(('PySide6', 'angerona.app', 'angerona.core.config', 'angerona.modules',
                        'angerona.core.startup_diagnostics')):
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
    assert row["pid"] == _PID and row["birth_filetime"] == _BIRTH
    assert "identity=pid-birth-observed" in row["coverage"]


def test_one_generation_capture_is_reused_in_header_report_and_private_row(arming, monkeypatch):
    calls = []

    def identity():
        calls.append(True)
        return {"pid": _PID, "birth_filetime": _BIRTH}

    monkeypatch.setattr(startup_diagnostics, "process_identity", identity)
    report = crashlog.install().report
    assert calls == [True]
    assert report.pid == _PID and report.birth_filetime == _BIRTH
    assert report.identity_state == "pid-birth-observed" and report.identity_error == ""
    assert int(report.birth_filetime) > 2**53 and type(report.birth_filetime) is str
    row = arming.records[-1][2]
    assert row["pid"] == report.pid and row["birth_filetime"] == report.birth_filetime
    for path in (target.path for target in report.targets):
        text = path.read_text(encoding="utf-8")
        assert f"pid={_PID};birth_filetime={_BIRTH};identity=pid-birth-observed" in text
        assert "generation_scope=installation-observation" in text
    # Neither a cached read nor publishing the same frozen observation queries
    # a live generation again or silently assigns a later process to this row.
    monkeypatch.setattr(crashlog, "os", SimpleNamespace(getpid=lambda: pytest.fail("cached read queried PID")))
    monkeypatch.setattr(startup_diagnostics, "process_identity",
                        lambda: pytest.fail("cached read queried native generation"))
    assert crashlog.latest_report() is report
    published = crashlog._publish_report(report)
    assert published.pid == _PID and published.birth_filetime == _BIRTH
    assert arming.records[-1][2]["birth_filetime"] == _BIRTH and calls == [True]


@pytest.mark.parametrize("identity,reason", [
    (None, "identity-malformed"),
    ([], "identity-malformed"),
    ({}, "identity-malformed"),
    ({"pid": _PID, "birth_filetime": _BIRTH, "private": "credential=not-exported"}, "identity-malformed"),
    ({"pid": _PID, "private": "credential=not-exported"}, "identity-malformed"),
    ({"pid": _PID, "x" * 4096: _BIRTH}, "identity-malformed"),
    ({"pid": True, "birth_filetime": _BIRTH}, "identity-malformed"),
    ({"pid": "81001", "birth_filetime": _BIRTH}, "identity-malformed"),
    ({"pid": 0, "birth_filetime": _BIRTH}, "identity-malformed"),
    ({"pid": 0x100000000, "birth_filetime": _BIRTH}, "identity-malformed"),
    ({"pid": _PID + 1, "birth_filetime": _BIRTH}, "pid-mismatch"),
    ({"pid": _PID}, "birth-unavailable"),
    ({"pid": _PID, "birth_filetime": None}, "birth-unavailable"),
    ({"pid": _PID, "birth_filetime": True}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": int(_BIRTH)}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "0"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "01"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "-1"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "+1"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "١"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "1.0"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "18446744073709551616"}, "birth-malformed"),
    ({"pid": _PID, "birth_filetime": "9" * 4096}, "birth-malformed"),
], ids=["none", "list", "empty", "unknown-field", "two-unknown-fields", "oversized-key", "bool-pid", "text-pid", "zero-pid",
        "large-pid", "foreign-pid", "missing-birth", "no-birth", "bool-birth", "numeric-birth",
        "zero-birth", "leading-zero", "negative", "plus", "unicode", "fraction", "u64-overflow", "oversized"])
def test_malformed_or_unavailable_identity_never_borrows_a_birth_or_blocks_hooks(
    arming, monkeypatch, capsys, identity, reason,
):
    calls = []

    def supplier():
        calls.append(True)
        return identity

    monkeypatch.setattr(startup_diagnostics, "process_identity", supplier)
    report = crashlog.install().report
    assert calls == [True]
    assert report.state == "armed" and report.main_hook and report.thread_hook and report.qt_hook
    assert report.pid == _PID and report.birth_filetime is None
    assert report.identity_state == "pid-only" and report.identity_error == reason
    row = arming.records[-1][2]
    assert row["pid"] == _PID and row["birth_filetime"] is None
    assert "identity:" + reason in row["log_error"]
    assert "credential=not-exported" not in json.dumps(row) + capsys.readouterr().err
    for target in report.targets:
        text = target.path.read_text(encoding="utf-8")
        assert f"pid={_PID};birth_filetime=unavailable;identity=pid-only" in text
        assert "credential=not-exported" not in text


@pytest.mark.parametrize("birth", ["1", _BIRTH, "18446744073709551615"])
def test_positive_canonical_u64_birth_has_no_arbitrary_float_precision_floor(arming, monkeypatch, birth):
    monkeypatch.setattr(startup_diagnostics, "process_identity", lambda: {"pid": _PID, "birth_filetime": birth})
    report = crashlog.install().report
    assert report.birth_filetime == birth and report.identity_state == "pid-birth-observed"
    assert arming.records[-1][2]["birth_filetime"] == birth


def test_generation_supplier_exception_exports_only_a_fixed_reason_and_keeps_hooks(arming, monkeypatch, capsys):
    def failed():
        raise RuntimeError("password=private-generation-fixture")

    monkeypatch.setattr(startup_diagnostics, "process_identity", failed)
    report = crashlog.install().report
    assert report.state == "armed" and report.identity_state == "pid-only"
    assert report.identity_error == "identity-query-failed" and report.birth_filetime is None
    assert "private-generation-fixture" not in json.dumps(arming.records) + capsys.readouterr().err
    assert all("private-generation-fixture" not in target.path.read_text("utf-8") for target in report.targets)


@pytest.mark.parametrize("pid", [None, True, 0, -1, "81001", 0x100000000])
def test_unavailable_current_pid_is_not_replaced_by_supplier_identity(arming, monkeypatch, pid):
    monkeypatch.setattr(crashlog, "os", SimpleNamespace(getpid=lambda: pid))
    monkeypatch.setattr(startup_diagnostics, "process_identity",
                        lambda: pytest.fail("native birth cannot be bound to a valid current PID"))
    report = crashlog.install().report
    assert report.state == "armed" and report.pid is None and report.birth_filetime is None
    assert report.identity_state == "unavailable" and report.identity_error == "pid-unavailable"
    assert arming.records[-1][2]["pid"] is None


def test_current_pid_query_failure_does_not_leak_or_borrow_identity(arming, monkeypatch, capsys):
    def failed():
        raise OSError("private-pid-query-secret")
    monkeypatch.setattr(crashlog, "os", SimpleNamespace(getpid=failed))
    monkeypatch.setattr(startup_diagnostics, "process_identity",
                        lambda: pytest.fail("invalid current PID cannot borrow a generation"))
    report = crashlog.install().report
    assert report.state == "armed" and report.identity_error == "pid-unavailable"
    assert report.pid is None and report.birth_filetime is None
    assert "private-pid-query-secret" not in json.dumps(arming.records) + capsys.readouterr().err


@pytest.mark.parametrize("same_pid", [False, True], ids=["changed-pid", "reused-pid"])
def test_explicit_reinstallation_observes_new_generation_without_rewriting_old_report(arming, monkeypatch, same_pid):
    current = [_PID, _BIRTH]
    calls = []
    monkeypatch.setattr(crashlog, "os", SimpleNamespace(getpid=lambda: current[0]))

    def supplier():
        calls.append(tuple(current))
        return {"pid": current[0], "birth_filetime": current[1]}

    monkeypatch.setattr(startup_diagnostics, "process_identity", supplier)
    first = crashlog.install().report
    current[:] = [_PID if same_pid else _PID + 1, str(int(_BIRTH) + 1)]
    second = crashlog.install().report
    assert calls == [(_PID, _BIRTH), tuple(current)]
    assert first.pid == _PID and first.birth_filetime == _BIRTH
    assert second.pid == current[0] and second.birth_filetime == current[1]
    assert first is not second and crashlog.latest_report() is second
    assert arming.records[0][2]["birth_filetime"] == _BIRTH
    assert arming.records[1][2]["birth_filetime"] == current[1]


def test_normal_budget_hold_preserves_native_arming_hooks_and_explicit_startup_gap(arming, monkeypatch):
    existing = arming.root / "logs/crash.log"
    existing.parent.mkdir()
    original = b"preserved oversized evidence\n" * 8
    existing.write_bytes(original)
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", len(original) - 1)

    report = crashlog.install().report

    assert report.main_hook and report.thread_hook and report.qt_hook
    assert report.native_fault_target is not None and arming.native_calls
    assert all(row.opened for row in report.targets)
    assert all(not row.startup_written for row in report.targets)
    assert report.state == "unavailable"
    assert report.targets[0].errors == ("startup-write:normal-write:file-limit",)
    assert all("startup=False" in row for row in arming.records[-1][2]["actual"])
    assert existing.read_bytes() == original
    reserved = tuple(row["reserved_bytes"] for row in crashlog.normal_write_snapshot()["targets"])
    streams, native_calls = tuple(crashlog._FH_FILES), tuple(arming.native_calls)
    crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=True)
    assert tuple(crashlog._FH_FILES) == streams and tuple(arming.native_calls) == native_calls
    assert all(not stream.closed for stream in streams)
    crashlog.install()
    assert tuple(row["reserved_bytes"] for row in crashlog.normal_write_snapshot()["targets"]) == reserved


def test_reinstallation_preserves_nonzero_normal_allowance_and_suppression(arming, monkeypatch):
    crashlog.install()
    before = crashlog.normal_write_snapshot()
    used = before["targets"][0]["reserved_bytes"]
    assert used > 0 and all(row["reserved_bytes"] == used for row in before["targets"])
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", used)
    crashlog._write("UNIT", "capacity rejection")
    held = crashlog.normal_write_snapshot()
    assert all(row["suppressed_blocks"] == 1 for row in held["targets"])
    report = crashlog.install().report
    assert report.main_hook and report.thread_hook and report.qt_hook and report.native_fault_target
    after = crashlog.normal_write_snapshot()
    assert all(row["reserved_bytes"] == used and row["appended_blocks"] == 1
               and row["suppressed_blocks"] == 2 for row in after["targets"])
