"""Private bounded diagnostics, exact dependency evidence and closed fallbacks."""
from __future__ import annotations

import builtins
import importlib.metadata
import io
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona import startup
from angerona.core import startup_diagnostics as diagnostics
from angerona.core.startup_recovery import private_directory


@pytest.fixture
def storage(tmp_path, monkeypatch):
    root = tmp_path / "private-state"
    assert private_directory(root, create=True)
    monkeypatch.setattr(startup, "canonical_storage", lambda: root)
    for name in ("OLLAMA_MODELS", "ANGERONA_OLLAMA_MODELS"):
        monkeypatch.delenv(name, raising=False)
    return root


def records(root):
    path = root / "diagnostics" / "startup-diagnostics.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def test_error_persists_type_trace_reason_paths_and_prints_even_when_handled(storage, monkeypatch, capsys):
    def failure(*_args, **_kwargs):
        raise startup.RepairableStartupError(82, "Synthetic dependency version mismatch")
    monkeypatch.setattr(startup, "run_startup", failure)
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--check-only"])
    assert startup.main() == 82
    stderr = capsys.readouterr().err
    assert "Synthetic dependency version mismatch" in stderr
    assert str(storage / "diagnostics" / "startup-diagnostics.jsonl") in stderr
    assert str(storage / "logs" / "startup-preflight.log") in stderr
    row = records(storage)[-1]
    assert row["phase"] == "source-check-only" and row["exit_code"] == 82
    assert row["exception_type"] == "RepairableStartupError"
    assert "raise startup.RepairableStartupError" in row["traceback"]
    assert row["renderer_hint"] == "review-diagnostics"
    assert row["pid"] == os.getpid()


def test_error_sink_failure_is_visible_and_preserves_original_outcome(storage, monkeypatch, capsys):
    monkeypatch.setattr(diagnostics.StartupDiagnostics, "record", lambda self, *_a, **_kw: False)
    monkeypatch.setattr(startup, "run_startup", lambda *_a, **_kw: (_ for _ in ()).throw(startup.StartupError("original failure")))
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--check-only"])
    assert startup.main() == 85
    message = capsys.readouterr().err
    assert "original failure" in message and "persistence unavailable" in message


def test_unknown_fault_records_actual_exception_without_graphics_retry_hint(storage, monkeypatch, capsys):
    monkeypatch.setattr(startup, "run_startup", lambda *_a, **_kw: (_ for _ in ()).throw(OSError(5, "synthetic access denied")))
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--check-only"])
    assert startup.main() == 85
    assert "synthetic access denied" in capsys.readouterr().err
    row = records(storage)[-1]
    assert row["exception_type"] == "OSError" and row["error_code"] == 5
    assert row["renderer_hint"] == "review-diagnostics"


def test_native_identity_never_substitutes_helper_pid_for_unknown_probe():
    assert diagnostics.process_identity(SimpleNamespace()) == {}


@pytest.mark.skipif(os.name != "nt", reason="Native Windows creation FILETIME")
def test_actual_native_birth_is_preserved_as_exact_decimal_string():
    row = diagnostics.process_identity()
    assert row["pid"] == os.getpid()
    assert type(row["birth_filetime"]) is str
    assert row["birth_filetime"].isdigit() and int(row["birth_filetime"]) > 2**53


def test_recorder_redacts_and_ignores_environment_and_unknown_fields(storage):
    recorder = diagnostics.StartupDiagnostics(storage)
    assert recorder.record("probe", "failed", reason="password=hunter2 Bearer abc.def ghp_1234567890123456 https://user:pw@example.invalid/a?token=secret",
                           environment={"PRIVATE": "must-not-record"})
    raw = recorder.path.read_text()
    assert "hunter2" not in raw and "abc.def" not in raw and "ghp_1234567890123456" not in raw
    assert "user:pw" not in raw and "?token" not in raw and "must-not-record" not in raw
    assert "environment" not in records(storage)[0]


def test_diagnostic_rotation_caps_only_its_three_files(storage, monkeypatch):
    monkeypatch.setattr(diagnostics, "MAX_FILE_BYTES", 1024)
    recorder = diagnostics.StartupDiagnostics(storage)
    unrelated = storage / "evidence.json"
    unrelated.write_bytes(b"preserved")
    for number in range(24):
        assert recorder.record("test", "observed", reason="x" * 80, attempt=number), recorder.last_error
    managed = list(recorder.path.parent.glob("startup-diagnostics.jsonl*"))
    assert len(managed) == 3
    assert all(path.stat().st_size <= 1024 for path in managed)
    assert unrelated.read_bytes() == b"preserved"
    assert all(len(line) <= diagnostics.MAX_FRAME_BYTES for path in managed for line in path.read_bytes().splitlines())


def test_diagnostic_record_budget_stops_growth_explicitly(storage, monkeypatch):
    monkeypatch.setattr(diagnostics, "MAX_RECORDS", 2)
    recorder = diagnostics.StartupDiagnostics(storage)
    assert recorder.record("one", "observed") and recorder.record("two", "observed")
    before = recorder.path.read_bytes()
    assert not recorder.record("three", "observed")
    assert recorder.path.read_bytes() == before and "budget" in recorder.last_error


def test_hardlinked_diagnostic_destination_is_refused_without_touching_original(storage, tmp_path):
    (storage / "diagnostics").mkdir(mode=0o700)
    original = tmp_path / "original"
    original.write_bytes(b"preserved original")
    target = storage / "diagnostics" / "startup-diagnostics.jsonl"
    os.link(original, target)
    recorder = diagnostics.StartupDiagnostics(storage)
    assert not recorder.record("test", "observed")
    assert original.read_bytes() == b"preserved original"


def test_unknown_existing_report_is_not_overwritten_or_rotated(storage):
    recorder = diagnostics.StartupDiagnostics(storage)
    assert recorder.record("known", "observed")
    recorder.path.write_bytes(b"unrecognized private original")
    assert not recorder.record("test", "observed")
    assert recorder.path.read_bytes() == b"unrecognized private original"
    assert not recorder.path.with_name(recorder.path.name + ".1").exists()


def test_oversized_optional_detail_has_an_explicit_coverage_gap(storage):
    recorder = diagnostics.StartupDiagnostics(storage)
    assert recorder.record("probe", "failed", traceback="x" * 10000, output_tail="y" * 10000,
                           mismatches=["z" * 1000] * 100)
    row = records(storage)[-1]
    assert "omitted" in row["coverage"]
    assert recorder.path.stat().st_size <= diagnostics.MAX_FRAME_BYTES


def test_dependency_probe_reports_all_expected_actual_mismatches_before_exit82(storage, tmp_path, monkeypatch, capsys):
    (tmp_path / "constraints-release.txt").write_text("certifi==2026.10.19\npsutil==7.2.2\nmissing-one==1.0\n")
    monkeypatch.chdir(tmp_path)
    original_import = builtins.__import__
    def importing(name, *args, **kwargs):
        if name == "sys":
            return SimpleNamespace(version_info=(3, 12, 1))
        if name == "sysconfig":
            return SimpleNamespace(get_platform=lambda: "win-amd64")
        return original_import(name, *args, **kwargs)
    def version(name):
        if name == "missing-one":
            raise importlib.metadata.PackageNotFoundError(name)
        return {"certifi": "2026.10.23", "psutil": "7.2.2"}[name]
    monkeypatch.setattr(importlib.metadata, "version", version)
    with pytest.raises(SystemExit) as error:
        exec(startup._PROBE, {"__builtins__": dict(vars(builtins), __import__=importing)})
    assert error.value.code == 82
    text = capsys.readouterr().out
    rows = [json.loads(line.split(" ", 1)[1]) for line in text.splitlines() if line.startswith("ANGERONA_DEPENDENCY ")]
    assert len(rows) == 3
    assert rows[0] == {"package": "certifi", "expected": "2026.10.19", "actual": "2026.10.23", "match": False, "actual_truncated": False}
    assert rows[1]["match"] is True and rows[2]["actual"] == "<not installed>"
    log = storage / "probe.log"
    log.write_text(text)
    recorder = diagnostics.StartupDiagnostics(storage)
    startup._record_dependency_audit(recorder, log)
    summary = records(storage)[-1]
    assert summary["packages_checked"] == 3 and summary["mismatches_total"] == 2
    assert "expected=2026.10.19, actual=2026.10.23" in summary["mismatches"][0]


def test_software_renderer_is_explicit_child_only_and_reuses_admission_checks(storage, tmp_path, monkeypatch):
    monkeypatch.setenv("QT_OPENGL", "hostile-inherited")
    monkeypatch.setenv("QT_QUICK_BACKEND", "hostile-inherited")
    monkeypatch.setenv("ANGERONA_STARTUP_SUPERVISED", "1")
    plan = startup.LaunchPlan(tmp_path, storage, ("python.exe",), False, rendering="software")
    child = startup.child_environment(plan)
    assert child["QT_OPENGL"] == child["QT_QUICK_BACKEND"] == "software"
    assert os.environ["QT_OPENGL"] == "hostile-inherited"
    assert "ANGERONA_STARTUP_SUPERVISED" not in child
    normal = startup.child_environment(startup.LaunchPlan(tmp_path, storage, ("python.exe",), False))
    assert "QT_OPENGL" not in normal and "QT_QUICK_BACKEND" not in normal
    calls = []
    monkeypatch.setattr(startup, "run_startup", lambda *_a, **kw: calls.append(kw))
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--check-only", "--software-renderer"])
    assert startup.main() == 0
    assert calls == [{"check_only": True, "software_renderer": True}]


def test_only_closed_gui_category_receives_renderer_hint(storage):
    recorder = diagnostics.StartupDiagnostics(storage)
    recorder.failure("gui-runtime", startup.RepairableStartupError(83, "native Qt unavailable"), exit_code=83)
    assert records(storage)[-1]["renderer_hint"] == "software-renderer"


def test_verified_core_pid_is_kept_distinct_from_dashboard_launcher(storage, tmp_path, monkeypatch):
    plan = startup.LaunchPlan(tmp_path, storage, ("fake-python.exe",), False)
    launcher = SimpleNamespace(pid=41001, returncode=None, poll=lambda: None)
    listener = SimpleNamespace(endpoint="fixture-only", receive=lambda: 41002, close=lambda: None)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "probe_source", lambda *_a: None)
    monkeypatch.setattr(startup, "ReadyListener", lambda: listener)
    monkeypatch.setattr(startup, "_ready_process", lambda pid, *_a: pid == 41002)
    monkeypatch.setattr(startup.subprocess, "Popen", lambda *_a, **_kw: launcher)
    startup.run_startup(lambda _message: None, threading.Event())
    launches = [row for row in records(storage) if row.get("process_role") == "dashboard-launcher"]
    ready = [row for row in records(storage) if row.get("process_role") == "core-dashboard"]
    assert launches[-1]["pid"] == 41001
    assert ready[-1]["pid"] == 41002 and ready[-1]["bootstrap_pid"] == 41001
    assert "not retained" in ready[-1]["coverage"] and "birth_filetime" not in ready[-1]


def test_dependency_consistency_output_is_capped_without_changing_exit82(monkeypatch):
    output = io.StringIO()
    original_import = builtins.__import__
    class Check:
        def __init__(self, **_kwargs):
            pass
        def main(self, _arguments):
            sys.stdout.write("x" * 100000)
            sys.stderr.write("y" * 100000)
            return 1
    def importing(name, *args, **kwargs):
        if name == "pip._internal.commands.check":
            return SimpleNamespace(CheckCommand=Check)
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(sys, "stdout", output)
    with pytest.raises(SystemExit) as error:
        exec(startup._PIP_CHECK, {"__builtins__": dict(vars(builtins), __import__=importing)})
    assert error.value.code == 82
    assert len(output.getvalue()) < 66000 and output.getvalue().count("output limit reached") == 1


@pytest.mark.parametrize("error,code", [(None, 0), (startup.RepairableStartupError(82, "pins"), 82),
                                      (ValueError("source failure"), 85),
                                      (startup.ProbeTimedOut("retired probe"), 87),
                                      (startup.StartupCancelled("operator cancelled"), 1223),
                                      (startup.DashboardProcessFailed("core exited"), 1)])
def test_no_startup_window_keeps_same_launch_checks_flags_and_closed_outcomes(storage, monkeypatch, capsys, error, code):
    called = []
    def run(*_args, **kwargs):
        called.append(kwargs)
        if error is not None:
            raise error
    monkeypatch.setattr(startup, "run_startup", run)
    monkeypatch.setattr(startup, "_interface_lease", lambda: pytest.fail("No-window strategy reached Tk lease setup"))
    monkeypatch.setattr(startup, "_configure_tk_environment", lambda: pytest.fail("No-window strategy reached Tk"))
    monkeypatch.setattr(startup.sys, "argv", ["startup", "--no-startup-window", "--software-renderer", "--setup", "--chill"])
    assert startup.main() == code
    assert called == [{"setup": True, "software_renderer": True}]
    if error is not None:
        assert str(error) in capsys.readouterr().err


def test_only_actual_startup_interface_failure_uses_closed_exit84(storage, monkeypatch, capsys):
    closed = []
    monkeypatch.setattr(startup, "_interface_lease", lambda: SimpleNamespace(root=storage, close=lambda: closed.append(True)))
    monkeypatch.setattr(startup, "_configure_tk_environment", lambda: (_ for _ in ()).throw(ImportError("synthetic Tk loader failure")))
    monkeypatch.setattr(startup, "run_startup", lambda *_a, **_kw: pytest.fail("Failed interface started dashboard checks"))
    monkeypatch.setattr(startup.sys, "argv", ["startup"])
    assert startup.main() == 84
    assert closed == [True]
    assert "synthetic Tk loader failure" in capsys.readouterr().err
    row = records(storage)[-1]
    assert row["exit_code"] == 84 and row["renderer_hint"] == "review-diagnostics"
    assert row["phase"] == "startup-interface"
