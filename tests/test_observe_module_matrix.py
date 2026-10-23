"""Matrix tests: inert fixtures only; no module/runtime workers are started."""
from __future__ import annotations

import importlib.util
import ast
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools" / "observe_module_matrix.py"
SPEC = importlib.util.spec_from_file_location("matrix_prototype", PATH)
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


def rows():
    return ([{"name": name} for name in matrix.AUDITED]
            + [{"name": "Unaudited " + str(index)} for index in range(86 - len(matrix.AUDITED))])


def safe_config(selected=()):
    values = {key: False for key in matrix.OFF}
    values.update({key: True for key in matrix.ON})
    values.update({key: "" for key in matrix.BLANK})
    values.update(matrix.FIXED)
    values["module_states"] = {row["name"]: row["name"] in selected for row in rows()}
    return values


def complete_state():
    return dict(first_cycle_complete=True, cycle_count=2, thread_alive=True,
                status="running", health_state="ok", event_overflow_count=0, crash_count=0)


def clean_summary():
    return dict(clean_shutdown=True, errors=[], capture_dropped=0, export_dropped=0,
                gap_records=0, max_heartbeat_gap_seconds=0.3)


def test_plan_covers_all_solos_but_only_exact_audited_runtime():
    cases = matrix.make_cases(rows())
    solos = [case for case in cases if case["id"].startswith("solo-")]
    assert len(solos) == 86
    assert {case["modules"][0] for case in solos if case["disposition"] == "ELIGIBLE"} == set(matrix.AUDITED)
    assert len(matrix.AUDITED) == 14  # Explicit reviewed identities; never inferred from metadata.
    assert sum(case["disposition"] == "HELD" for case in solos) == 72
    assert len([case for case in cases if case["id"].startswith("pair-")]) == 91
    assert len([case for case in cases if case["disposition"] == "ELIGIBLE"]) == 108
    assert next(case for case in cases if case["id"] == "all-86-runtime")["disposition"] == "HELD"
    assert next(case for case in cases if case["id"] == "offline-all-selftests")["disposition"] == "HELD"
    for case in cases:
        if case["disposition"] == "ELIGIBLE":
            matrix.validate_case(case)


def test_changed_inventory_cannot_be_accepted_as_same_review():
    for changed in (rows()[:-1], rows() + [{"name": "New module"}], rows()[:-1] + [rows()[0]]):
        with pytest.raises(ValueError):
            matrix.make_cases(changed)


@pytest.mark.parametrize("case", [
    dict(id="x", mode="modules", modules=["Adversary Combat"], disposition="ELIGIBLE"),
    dict(id="x", mode="modules", modules=["Process Monitor"] * 2, disposition="ELIGIBLE"),
    dict(id="x", mode="modules", modules=[], disposition="ELIGIBLE"),
    dict(id="raw-scanner", mode="scanner", modules=["SpywareGuard"], disposition="ELIGIBLE"),
    dict(id="x", mode="arbitrary", modules=["SpywareGuard"], disposition="ELIGIBLE"),
    dict(id="solo-spywareguard", mode="modules", modules=["SpywareGuard"], disposition="HELD"),
])
def test_unreviewed_or_malformed_case_cannot_launch(case):
    with pytest.raises(ValueError):
        matrix.validate_case(case)


def test_explicit_selection_cannot_choose_held_unknown_duplicate_or_exceed_budget():
    plan = {"cases": matrix.make_cases(rows())}
    for requested, budget in ((["all-86-runtime"], 18), (["new"], 18),
                              (["control", "control"], 18), ([], 2)):
        with pytest.raises(ValueError):
            matrix.select_cases(plan, requested, budget)
    assert [case["id"] for case in matrix.select_cases(plan, ["control", "raw-scanner"], 2)] == ["control", "raw-scanner"]


def test_safety_configuration_requires_exact_bool_full_inventory_and_no_destinations():
    names = {row["name"] for row in rows()}
    matrix.assert_config(safe_config(["SpywareGuard"]), names, ["SpywareGuard"])
    for field, value in (("spyware_auto_contain", True), ("require_signed_aar", False),
                         ("spyware_network_enabled", 0), ("aria_push_url", "https://example.com"),
                         ("ollama_host", "http://localhost:11434"), ("ai_provider_order", ["ollama"])):
        bad = safe_config(["SpywareGuard"])
        bad[field] = value
        with pytest.raises(ValueError):
            matrix.assert_config(bad, names, ["SpywareGuard"])
    bad = safe_config(["SpywareGuard"])
    bad["module_states"]["Unaudited 1"] = True
    with pytest.raises(ValueError):
        matrix.assert_config(bad, names, ["SpywareGuard"])
    bad = safe_config(["SpywareGuard"])
    del bad["module_states"]["Unaudited 1"]
    with pytest.raises(ValueError):
        matrix.assert_config(bad, names, ["SpywareGuard"])


def test_live_thread_and_empty_alert_stream_do_not_prove_sensor_cycle():
    active = {"SpywareGuard": dict(thread_alive=True, status="running", health_state="ok")}
    state, gaps = matrix.classification(active, clean_summary(), expected_modules=["SpywareGuard"])
    assert state == "OBSERVED_WITH_GAPS"
    assert any("no completed sensor cycle" in gap for gap in gaps)


@pytest.mark.parametrize("field,value", [("capture_dropped", 1), ("gap_records", 1),
                                       ("export_dropped", 1), ("scanner_drops", 1),
                                       ("source_changed", True), ("max_heartbeat_gap_seconds", 3.1)])
def test_explicit_loss_source_edits_and_scheduling_delays_remain_gaps(field, value):
    summary = clean_summary()
    summary[field] = value
    state, gaps = matrix.classification({"Process Monitor": complete_state()}, summary,
                                         expected_modules=["Process Monitor"])
    assert state == "OBSERVED_WITH_GAPS" and gaps


def test_degraded_integrity_approval_cannot_be_reported_fully_working():
    active = {"Self-Integrity Monitor": dict(complete_state(), health_state="degraded")}
    state, gaps = matrix.classification(active, clean_summary(), expected_modules=list(active))
    assert state == "OBSERVED_WITH_GAPS"
    assert any("not fully available" in gap for gap in gaps)


def test_shutdown_pending_wins_over_otherwise_good_observation():
    summary = dict(clean_summary(), shutdown_pending=True)
    state, gaps = matrix.classification({"Process Monitor": complete_state()}, summary,
                                         expected_modules=["Process Monitor"])
    assert state == "SHUTDOWN_PENDING" and gaps


def test_scanner_requires_authenticated_heartbeat_progress_not_just_own_loop():
    summary = clean_summary()
    assert matrix.classification({}, summary, expected_modules=[], scanner=True)[0] == "OBSERVED_WITH_GAPS"
    summary["scanner_heartbeat_count"] = 2
    assert matrix.classification({}, summary, expected_modules=[], scanner=True)[0] == "OBSERVED"


def test_stops_only_selected_workers_and_retains_pending_identity(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def block():
        entered.set()
        release.wait(5)
    worker = threading.Thread(target=block, name="InertMatrixFixture")
    called = []
    modules = {"Process Monitor": SimpleNamespace(_thread=worker),
               "Adversary Combat": SimpleNamespace()}
    manager = SimpleNamespace(modules=modules, set_enabled=lambda name, state: called.append((name, state)))
    worker.start()
    try:
        assert entered.wait(1)
        pending, errors = matrix.stop_selected(manager, ["Process Monitor"], timeout=0.01)
        assert pending == [worker] and errors == []
        assert called == [("Process Monitor", False)]
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()


def test_source_plan_detects_transitive_helper_edits_and_new_python_files(tmp_path, monkeypatch):
    script = tmp_path / "tools" / "observe_module_matrix.py"
    script.parent.mkdir()
    script.write_text("# inert harness\n", encoding="utf-8")
    monkeypatch.setattr(matrix, "__file__", str(script))
    for relative in matrix.TCB:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# inert required source\n", encoding="utf-8")
    helper = tmp_path / "src" / "angerona" / "core" / "engine_transport.py"
    helper.write_text("# custody helper before\n", encoding="utf-8")
    before = matrix.source_snapshot(tmp_path, {})
    assert helper.relative_to(tmp_path).as_posix() in before
    helper.write_text("# custody helper after\n", encoding="utf-8")
    changed = matrix.source_snapshot(tmp_path, {})
    assert changed != before
    extra = helper.with_name("new_transitive_helper.py")
    extra.write_text("# injected first-party source\n", encoding="utf-8")
    assert matrix.source_snapshot(tmp_path, {}) != changed
    extra.unlink()
    assert matrix.source_snapshot(tmp_path, {}) == changed


def test_capture_budget_keeps_loss_counters_and_no_partial_records(tmp_path, monkeypatch):
    # Replace only private-file creation; do not load Config/discovery/modules.
    import os
    repo = ROOT
    monkeypatch.syspath_prepend(str(repo / "src"))
    from angerona.core import engine_transport
    monkeypatch.setattr(engine_transport, "create_private_file",
                        lambda path: os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    capture = matrix.Capture(tmp_path / "bounded.jsonl", limit=90)
    assert capture.put({"kind": "event", "severity": "HIGH", "message": "a"})
    assert not capture.put({"kind": "event", "severity": "CRITICAL", "message": "x" * 200})
    capture.close()
    assert capture.dropped == 1
    assert capture.severities == {"HIGH": 1, "CRITICAL": 1}
    records = (tmp_path / "bounded.jsonl").read_bytes().splitlines()
    assert len(records) == 1
    assert len((tmp_path / "bounded.jsonl").read_bytes()) <= 90


def test_snapshot_gap_does_not_repeat_forever_or_hide_retained_views():
    class Sink:
        records = []
        def put(self, record):
            self.records.append(record)
    class Service:
        def recent(self, cursor, limit):
            assert cursor == 0 and limit == 200
            return dict(gap=3, first_seq=4, last_seq=5,
                        records=[dict(seq=4, kind="event"), dict(seq=5, kind="coverage")])
    sink = Sink()
    cursor, done = matrix.drain_views(Service(), sink, 0)
    assert cursor == 5 and done
    assert sink.records[0] == dict(kind="gap", reason="retained-view-loss", lost=3)
    assert [record.get("seq") for record in sink.records[1:]] == [4, 5]


def test_cli_defaults_do_not_start_runtime_and_has_no_arbitrary_commands():
    args = matrix.arguments(["--repo", "D:/repo", "--python", "D:/repo/venv/Scripts/python.exe"])
    assert args.run is False and args.child == "" and args.duration == 15
    with pytest.raises(SystemExit):
        matrix.arguments(["--repo", "D:/repo", "--python", "D:/python.exe", "--command", "anything"])


def test_failed_profile_save_still_signals_only_owned_selected_worker():
    called = []
    module = SimpleNamespace(stop=lambda: called.append("stop"))
    def failed_save(name, enabled):
        assert name == "Process Monitor" and enabled is False
        raise OSError("inert disk fixture")
    manager = SimpleNamespace(modules={"Process Monitor": module}, set_enabled=failed_save)
    pending, errors = matrix.stop_selected(manager, ["Process Monitor"], timeout=0.01)
    assert pending == [] and called == ["stop"]
    assert errors == ["OSError: disabling Process Monitor"]


def test_supervisor_pending_exit_aborts_without_process_termination(tmp_path, monkeypatch):
    import io
    import subprocess
    repo = ROOT
    monkeypatch.syspath_prepend(str(repo / "src"))
    from angerona.core import engine_transport
    monkeypatch.setattr(engine_transport, "private_directory", lambda path: path.mkdir(exist_ok=True))
    monkeypatch.setattr(engine_transport, "create_private_file", lambda path: __import__("os").open(
        path, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_EXCL, 0o600))
    monkeypatch.setattr(matrix, "exclusive_directory", lambda path: path.mkdir())
    monkeypatch.setattr(matrix, "environment", lambda *_args: {})
    monkeypatch.setattr(matrix, "STARTUP_SECONDS", -100)
    records = {}
    monkeypatch.setattr(matrix, "write_private", lambda path, value: records.__setitem__(path.name, value))
    class Child:
        pid = 123456
        stdout = io.BytesIO(b"")
        def poll(self):
            return None
        def wait(self, timeout):
            raise subprocess.TimeoutExpired("inert-child", timeout)
        def kill(self):
            pytest.fail("No process termination is authorized")
        terminate = kill
    monkeypatch.setattr(matrix.subprocess, "Popen", lambda *args, **kwargs: Child())
    args = SimpleNamespace(python=Path("D:/fake-python.exe"), duration=5, run_id="inert")
    case = dict(id="control", mode="modules", modules=[], disposition="ELIGIBLE")
    report = matrix.supervise_case(args, repo, tmp_path, case)
    assert report["state"] == "UNRESOLVED" and report["exit_code"] is None
    assert report["normal_exit"] is False and report["next_case_allowed"] is False
    assert records["stop.request.json"] == dict(schema=matrix.SCHEMA, run_id="inert", case_id="control", action="stop")
    assert any("no forced termination" in error for error in report["errors"])


def test_hidden_child_requires_explicit_run_before_any_preparation(monkeypatch, tmp_path):
    import os
    if os.name != "nt":
        pytest.skip("Windows matrix CLI")
    repo = tmp_path / "missing-checkout"

    def reject_preparation(*_args, **_kwargs):
        raise AssertionError("child rejection must precede path resolution")

    with monkeypatch.context() as guard:
        guard.setattr(matrix.Path, "resolve", reject_preparation)
        with pytest.raises(ValueError, match="requires explicit --run"):
            matrix.main(["--repo", str(repo), "--python", str(repo / "venv/Scripts/python.exe"),
                         "--run-id", "no-child-created", "--child", "control"])
    assert not (repo / ".tmp/module-observation-matrix/run-no-child-created").exists()


def test_venv_launcher_exit_does_not_prove_actual_core_exit(monkeypatch):
    import psutil
    monkeypatch.setattr(psutil, "Process", lambda _pid: SimpleNamespace(create_time=lambda: 1234.0))
    assert matrix.owned_identity_exited(dict(pid=12345, birth=1234.0)) is False
    assert matrix.owned_identity_exited(dict(pid=12345, birth=1233.0)) is True
    assert matrix.owned_identity_exited(None) is False
    def denied(_pid):
        raise psutil.AccessDenied(_pid)
    monkeypatch.setattr(psutil, "Process", denied)
    assert matrix.owned_identity_exited(dict(pid=12345, birth=1234.0)) is False
    def gone(_pid):
        raise psutil.NoSuchProcess(_pid)
    monkeypatch.setattr(psutil, "Process", gone)
    assert matrix.owned_identity_exited(dict(pid=12345, birth=1234.0)) is True


def test_injected_exposure_provider_and_bound_fleet_are_not_audited_defaults(monkeypatch):
    import sys
    def expected_provider():
        return None
    fake_module = SimpleNamespace(unavailable_snapshot_observer=expected_provider)
    monkeypatch.setitem(sys.modules, "angerona.modules.exposure_graph_guard", fake_module)
    selected = ["AegisPath Exposure Graph Guard", "Fleet Health Monitor"]
    names = {row["name"] for row in rows()}
    modules = {name: SimpleNamespace() for name in names}
    modules[selected[0]] = SimpleNamespace(_snapshot_observer=expected_provider)
    modules[selected[1]] = SimpleNamespace(_fabric=None, _tenant_id="")
    manager = SimpleNamespace(modules=modules, config=safe_config(selected),
                              is_enabled=lambda name: name in selected)
    matrix.assert_runtime_defaults(manager, selected)
    modules[selected[0]]._snapshot_observer = lambda: None
    with pytest.raises(ValueError, match="unavailable default"):
        matrix.assert_runtime_defaults(manager, selected)
    modules[selected[0]]._snapshot_observer = expected_provider
    modules[selected[1]]._fabric = object()
    with pytest.raises(ValueError, match="remain unbound"):
        matrix.assert_runtime_defaults(manager, selected)


class InertClock:
    def __init__(self):
        self.wall, self.cpu = 0.0, 0.0

    def advance(self, wall, cpu=0.0):
        self.wall += wall
        self.cpu += cpu

    def install(self, monkeypatch):
        monkeypatch.setattr(matrix, "time", SimpleNamespace(
            monotonic=lambda: self.wall, perf_counter=lambda: self.wall,
            thread_time=lambda: self.cpu))


def test_terminal_persistence_cannot_hide_behind_a_small_last_loop_start_gap(monkeypatch):
    clock, summary = InertClock(), clean_summary()
    summary["max_heartbeat_gap_seconds"] = 0.0
    clock.install(monkeypatch)
    with matrix.observation_window(summary, 60) as observation:
        for _ in range(100):
            with matrix.observer_iteration(summary, observation):
                clock.advance(0.04672)
            clock.advance(0.25)
        assert clock.wall == pytest.approx(29.672)
        with matrix.observer_iteration(summary, observation):
            with matrix.observer_step(summary, "heartbeat_persistence"):
                clock.advance(65.435608)
        clock.advance(0.25)
        assert clock.wall > 60  # The next loop condition exits, without a new heartbeat.
    assert summary["max_heartbeat_gap_seconds"] < 0.3
    assert summary["max_observation_gap_seconds"] == pytest.approx(65.685608)
    assert summary["max_observer_work_seconds"] == pytest.approx(65.435608)
    assert summary["max_observer_work_thread_cpu_seconds"] == 0
    assert summary["observation_seconds"] == pytest.approx(95.357608)
    assert summary["observation_deadline_overrun_seconds"] == pytest.approx(35.357608)
    state, gaps = matrix.classification({}, summary, expected_modules=[])
    assert state == "OBSERVED_WITH_GAPS"
    assert any("heartbeat exceeded" in gap for gap in gaps)
    assert any("deadline exceeded" in gap for gap in gaps)


def test_terminal_write_exception_retains_original_error_and_measured_work(monkeypatch):
    clock, summary = InertClock(), clean_summary()
    clock.install(monkeypatch)
    with pytest.raises(OSError, match="inert terminal write failure"):
        with matrix.observation_window(summary, 60) as observation:
            with matrix.observer_iteration(summary, observation):
                with matrix.observer_step(summary, "heartbeat_persistence"):
                    clock.advance(3, 0.5)
                    raise OSError("inert terminal write failure")
    assert summary["observation_seconds"] == 3
    assert summary["max_observation_gap_seconds"] == 3
    assert summary["max_observer_work_seconds"] == 3
    assert summary["observer_step_maxima"]["heartbeat_persistence"] == {
        "wall_seconds": 3, "thread_cpu_seconds": 0.5}


def test_owned_stop_break_accounts_last_iteration_and_stop_check(monkeypatch):
    clock, summary, stop = InertClock(), clean_summary(), threading.Event()
    clock.install(monkeypatch)
    with matrix.observation_window(summary, 60) as observation:
        while clock.wall < 60:
            with matrix.observer_iteration(summary, observation):
                with matrix.observer_step(summary, "heartbeat_persistence"):
                    clock.advance(3)
                    stop.set()
                with matrix.observer_step(summary, "owned_stop_check"):
                    clock.advance(0.1)
                    if stop.is_set():
                        summary["stop_reason"] = "owned-stop-request"
                        break
    assert summary["stop_reason"] == "owned-stop-request"
    assert summary["heartbeat_count"] == 1
    assert summary["max_observer_work_seconds"] == pytest.approx(3.1)
    assert summary["final_observer_silence_seconds"] == pytest.approx(3.1)
    assert summary["observer_step_maxima"]["owned_stop_check"]["wall_seconds"] == pytest.approx(0.1)


@pytest.mark.parametrize("cpu", [0, 2.5])
def test_wall_silence_is_a_gap_with_cpu_attribution_kept_separate(monkeypatch, cpu):
    clock, summary = InertClock(), clean_summary()
    clock.install(monkeypatch)
    with matrix.observation_window(summary, 60) as observation:
        with matrix.observer_iteration(summary, observation):
            with matrix.observer_step(summary, "heartbeat_persistence"):
                clock.advance(3, cpu)
    assert summary["max_observer_work_thread_cpu_seconds"] == cpu
    assert summary["observer_step_maxima"]["heartbeat_persistence"]["thread_cpu_seconds"] == cpu
    assert matrix.classification({}, summary, expected_modules=[])[0] == "OBSERVED_WITH_GAPS"


def test_short_work_and_normal_deadline_rounding_preserve_clean_classification(monkeypatch):
    clock, summary = InertClock(), clean_summary()
    clock.install(monkeypatch)
    with matrix.observation_window(summary, 1) as observation:
        while clock.wall < 1:
            with matrix.observer_iteration(summary, observation):
                with matrix.observer_step(summary, "heartbeat_persistence"):
                    clock.advance(0.05)
            clock.advance(0.25)
    assert summary["observation_deadline_overrun_seconds"] == pytest.approx(0.2)
    assert summary["max_observation_gap_seconds"] == pytest.approx(0.3)
    assert matrix.classification({}, summary, expected_modules=[])[0] == "OBSERVED"


def private_writer_fixture(tmp_path, monkeypatch):
    """Exercise actual atomic writes with isolated custody and fsync witnesses."""
    import os
    from angerona.core import engine_transport
    events, streams = [], []
    def create(path):
        events.append("create")
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    def fdopen(descriptor, mode):
        stream = os.fdopen(descriptor, mode)
        streams.append(stream)
        return stream
    def sync(descriptor):
        assert not streams[-1].closed
        events.append("fsync")
        os.fsync(descriptor)
    def verify(path):
        events.append("verify")
        assert path.parent == tmp_path
    def replace(source, target):
        assert streams[-1].closed
        events.append("replace")
        os.replace(source, target)
    monkeypatch.setattr(engine_transport, "create_private_file", create)
    monkeypatch.setattr(engine_transport, "verify_private", verify)
    # Avoid patching os.fsync globally in a suite which may own other threads.
    monkeypatch.setattr(matrix, "os", SimpleNamespace(fdopen=fdopen, fsync=sync, replace=replace))
    return events, streams


@pytest.mark.parametrize("filename", ["plan.json", "ready.json", "owned-identity.json", "stop.request.json",
                                     "result.json", "supervisor.json", "matrix.json"])
def test_authoritative_artifacts_keep_default_fsync(tmp_path, monkeypatch, filename):
    events, streams = private_writer_fixture(tmp_path, monkeypatch)
    target = tmp_path / filename
    target.write_text('{"old":true}\n', encoding="utf-8")
    matrix.write_private(target, {"new": True})
    assert events == ["create", "fsync", "verify", "replace"]
    assert json.loads(target.read_text(encoding="utf-8")) == {"new": True}
    assert all(stream.closed for stream in streams)
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("durable", [False, True])
def test_volatile_heartbeat_only_omits_fsync_not_private_atomic_custody(tmp_path, monkeypatch, durable):
    events, streams = private_writer_fixture(tmp_path, monkeypatch)
    target = tmp_path / "heartbeat.json"
    target.write_text('{"count":1}\n', encoding="utf-8")
    matrix.write_private(target, {"count": 2}, durable=durable)
    assert events == (["create", "fsync", "verify", "replace"] if durable
                      else ["create", "verify", "replace"])
    assert json.loads(target.read_text(encoding="utf-8")) == {"count": 2}
    assert all(stream.closed for stream in streams)
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("durable", [False, True])
def test_custody_rejection_preserves_target_and_cleans_temporary_file(tmp_path, monkeypatch, durable):
    from angerona.core import engine_transport
    events, streams = private_writer_fixture(tmp_path, monkeypatch)
    target = tmp_path / "heartbeat.json"
    original = b'{"count":1}\n'
    target.write_bytes(original)
    def deny(_path):
        raise PermissionError("inert target ACL refusal")
    monkeypatch.setattr(engine_transport, "verify_private", deny)
    with pytest.raises(PermissionError, match="ACL refusal"):
        matrix.write_private(target, {"count": 2}, durable=durable)
    assert target.read_bytes() == original
    assert "replace" not in events and all(stream.closed for stream in streams)
    assert list(tmp_path.iterdir()) == [target]


def test_default_fsync_failure_cannot_downgrade_authoritative_write(tmp_path, monkeypatch):
    events, streams = private_writer_fixture(tmp_path, monkeypatch)
    target = tmp_path / "result.json"
    original = b'{"retained":true}\n'
    target.write_bytes(original)
    def fail(_descriptor):
        raise OSError("inert fsync failure")
    monkeypatch.setattr(matrix.os, "fsync", fail)
    with pytest.raises(OSError, match="fsync failure"):
        matrix.write_private(target, {"replacement": True})
    assert target.read_bytes() == original
    assert "replace" not in events and all(stream.closed for stream in streams)
    assert list(tmp_path.iterdir()) == [target]


def test_only_advisory_heartbeat_call_opts_out_of_durability():
    tree = ast.parse(PATH.read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "write_private"]
    opt_out = []
    for call in calls:
        for keyword in call.keywords:
            if keyword.arg == "durable":
                assert isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool
                if keyword.value.value is False:
                    opt_out.append(call)
    assert len(opt_out) == 1
    path = opt_out[0].args[0]
    assert isinstance(path, ast.BinOp) and isinstance(path.op, ast.Div)
    assert isinstance(path.right, ast.Constant) and path.right.value == "heartbeat.json"
