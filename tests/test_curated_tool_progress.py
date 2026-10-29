"""Measured scanner progress, wire identity and actual pinned-engine scans."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import types
from types import SimpleNamespace

import pytest

from angerona.core import curated_tools as tools
from angerona.core import curated_tool_worker as worker
from angerona.core.curated_tool_progress import (
    ObservedConnection, ObservedReader, ScannerProgress, validate_snapshot,
)


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


def test_failed_new_scan_never_reuses_previous_process_resources(tmp_path):
    service = tools.CuratedToolService(root=tmp_path / "unused", cfg=SimpleNamespace(github_tools_enabled=False))
    previous = tools.ToolOperation()
    current = tools.ToolOperation()
    service._resource = dict(operation_id=previous.operation_id, job_id="a" * 32,
                             pid=12345, cpu_percent=88.0, rss_mib=128, process_alive=False,
                             state="stopped")
    with pytest.raises(tools.ToolError, match="disabled"):
        service.scan(tools.ToolScanRequest(), current)
    sample = service.resource_snapshot()
    assert sample["operation_id"] == current.operation_id and sample["job_id"] == ""
    assert sample["state"] == "unavailable" and sample["resource_gap"]
    assert not {"pid", "cpu_percent", "rss_mib", "process_alive"}.intersection(sample)
    assert not (tmp_path / "unused" / "jobs").exists()


def tracker(tmp_path):
    output, clock = [], Clock()
    document = dict(operation_id="a" * 32, nonce="b" * 64,
                    limits={"runtime_seconds": 60})
    observer = ScannerProgress(document, tmp_path / ("c" * 32), "123456789012345678",
                               output.append, clock=clock)
    return observer, output, clock


def decode(raw, sequence=0):
    return validate_snapshot(raw, job_id="c" * 32, nonce="b" * 64,
                             birth="123456789012345678", operation_id="a" * 32,
                             previous_sequence=sequence)


def test_wire_identity_duplicate_nonfinite_and_counter_bounds(tmp_path):
    observer, output, _ = tracker(tmp_path)
    observer.publish(force=True)
    parsed = decode(output[-1])
    assert parsed["state"] == "running" and parsed["overall_percent"] is None
    assert "nonce" not in parsed and "birth" not in parsed
    original = json.loads(output[-1])
    for name, value in (("job_id", "d" * 32), ("nonce", "e" * 64), ("birth", "other"),
                        ("operation_id", "f" * 32), ("sequence", True),
                        ("elapsed_s", float("inf")), ("elapsed_s", 10**300),
                        ("state", "clean"), ("completed_steps", True)):
        document = dict(original, **{name: value})
        with pytest.raises(ValueError):
            decode(json.dumps(document).encode())
    with pytest.raises(ValueError, match="Duplicate"):
        decode(output[-1][:-1] + b',"schema":1}')
    with pytest.raises(ValueError):
        decode(output[-1], sequence=parsed["sequence"])
    with pytest.raises(ValueError):
        decode(b'{"extra":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}')
    for values in ({"item_completed": 8, "item_total": 4, "item_percent": 200},
                   {"item_completed": 1, "item_total": 4, "item_percent": 90},
                   {"item_completed": 1.5, "item_total": 4, "item_percent": 37.5},
                   {"extra": {"nested": ["unreviewed"]}},
                   {"overall_percent": 100}):
        with pytest.raises(ValueError):
            decode(json.dumps(dict(original, **values)).encode())


def test_exact_existing_database_rows_advance_without_extra_sql_or_fake_reader_percent(tmp_path):
    observer, output, clock = tracker(tmp_path)
    observer.current_step = "browser"
    observer.current_file = str(tmp_path / "original-history")
    observer.steps = [dict(id="browser", label="Browser", state="running", completed=0,
                           total=None, unit="checks", percent=None, checked=0, skipped=0,
                           elapsed_s=0, remaining_s=None)]
    observer.step_started = clock()
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE urls(value TEXT)")
    connection.executemany("INSERT INTO urls VALUES(?)", [(str(index),) for index in range(20)])
    statements = []
    connection.set_trace_callback(statements.append)
    proxy = ObservedConnection(connection, observer)
    rows = proxy.execute("SELECT value FROM urls").fetchall()
    assert len(rows) == 20 and rows[0] == ("0",)
    visited = []
    for row in rows:
        visited.append(row)
        clock.value += .2
        observer.publish(force=True)
    observer.publish(force=True)
    assert visited == [(str(index),) for index in range(20)]
    assert statements == ["SELECT value FROM urls"]  # No COUNT or additional evidence query.
    publications = [decode(raw) for raw in output]
    assert any(0 < item["item_percent"] < 100 for item in publications if item["item_percent"] is not None)
    assert any(item["item_remaining_s"] > 0 for item in publications if item["item_remaining_s"] is not None)
    assert publications[-1]["item_completed"] == publications[-1]["item_total"] == 20
    assert publications[-1]["item_unit"] == "database rows processed"
    assert publications[-1]["steps"][0]["percent"] is None
    assert publications[-1]["overall_percent"] == 0  # File/query completion is not reader completion.
    assert publications[-1]["current_file"] == str(tmp_path / "original-history")
    proxy.close()


def test_streamed_query_does_not_materialize_or_guess_total(tmp_path):
    observer, _, _ = tracker(tmp_path)
    observer.current_step = "browser"
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE samples(value INTEGER)")
    connection.executemany("INSERT INTO samples VALUES(?)", [(n,) for n in range(10)])
    rows = ObservedConnection(connection, observer).execute("SELECT value FROM samples")
    assert list(rows) == [(n,) for n in range(10)]
    assert observer.item_completed == 10 and observer.item_total is None
    assert observer.item_percent is None and observer.item_remaining_s is None
    connection.close()


def test_file_read_progress_never_observes_control_scratch_or_becomes_scan_progress(tmp_path):
    observer, _, _ = tracker(tmp_path)
    observer.current_step = "browser"
    original = tmp_path / "inert-history"
    original.write_bytes(b"12345678")
    with original.open("rb") as stream:
        wrapped = ObservedReader(stream, observer, original, binary=True)
        assert wrapped.read(4) == b"1234" and observer.item_percent == 50
        assert wrapped.read() == b"5678" and observer.item_percent == 100
    assert observer.current_file == str(original)
    assert observer.observe_file(observer.job / "scratch/progress.json", 1024) is None
    assert observer.current_file == str(original)
    assert observer.observe_file(12) is None
    observer.read_position(None, 123)
    with original.open("rb") as stream:
        wrapped = ObservedReader(stream, observer, original, binary=True)
        wrapped.seek(-1, os.SEEK_END)
        assert wrapped.read() == b"8"
        assert observer.item_percent is None and observer.item_total is None
        assert observer.item_completed == 1 and "non-sequential" in observer.item_unit


def test_reader_result_and_cancellation_preserve_real_counts(tmp_path):
    observer, output, clock = tracker(tmp_path)
    ctx = SimpleNamespace(partial=None, quick=False, targets=())
    plan = [SimpleNamespace(name="browser"), SimpleNamespace(name="hash")]
    def run(context, resolver):
        result = resolver(plan[0])(context)
        assert result.checked == 7
        raise RuntimeError("synthetic cancelled reader")
    def resolver(_spec):
        def check(context):
            context.partial = SimpleNamespace(name="browser", checked=7, skipped=2)
            clock.value += 2
            observer.publish(force=True)
            return SimpleNamespace(checked=7, skipped=2, checks=[])
        return check
    namespace = dict(reader_run=run, reader_select=lambda _ctx: plan, reader_resolve=resolver)
    observer.install(namespace)
    with pytest.raises(RuntimeError, match="synthetic cancelled"):
        namespace["reader_run"](ctx)
    observer.finish("timed-out")
    final = decode(output[-1])
    assert final["state"] == "timed-out"
    assert final["steps"][0]["checked"] == 7 and final["steps"][0]["skipped"] == 2
    assert final["steps"][0]["state"] == "incomplete"
    assert final["steps"][1]["state"] == "queued"
    assert final["overall_percent"] == 50


def test_stdlib_temporary_reports_stay_bounded_and_unknown_openers_are_not_invoked(tmp_path, monkeypatch):
    job = tmp_path / "job"
    job.mkdir()
    budget = worker._WriteBudget(job, 64 * 1024**2)
    outside = tmp_path / "outside-original"
    outside.write_bytes(b"preserved")
    called = []
    def unknown(*_args):
        called.append(True)
        return os.open(outside, os.O_RDWR)
    with pytest.raises(OSError, match="Unreviewed"):
        budget.io_open(job, "w", opener=unknown)
    assert called == [] and outside.read_bytes() == b"preserved"
    with monkeypatch.context() as patch:
        patch.setattr(worker.io, "open", budget.io_open)
        patch.setattr(worker.os, "open", budget.os_open)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".zbt_report_",
                                         suffix=".tmp", dir=job, delete=False) as output:
            output.write('{"fixture":true}')
            path = Path(output.name)
    assert path.parent == job and path.read_text(encoding="utf-8") == '{"fixture":true}'
    assert budget.remaining < 60 * 1024**2
    budget.replace(path, job / "report.json")
    assert (job / "report.json").read_text(encoding="utf-8") == '{"fixture":true}'


def test_verified_temp_opener_rejects_reused_foreign_fd_without_closing_or_writing_it(tmp_path, monkeypatch):
    codes = [code for code in tempfile.NamedTemporaryFile.__code__.co_consts
             if isinstance(code, types.CodeType) and code.co_name == "opener"]
    if not codes:
        pytest.skip("This Python's NamedTemporaryFile does not use an io.open opener")
    job = tmp_path / "job"
    job.mkdir()
    outside = tmp_path / "outside-original"
    outside.write_bytes(b"preserved")
    budget = worker._WriteBudget(job, 64 * 1024**2)
    captured = []
    def substituted_inner(directory, prefix, suffix, *_args):
        owned = budget.os_open(str(job / (prefix + "inert" + suffix)), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(owned)
        foreign = budget.original_os_open(str(outside), os.O_RDWR)
        if foreign != owned:
            os.dup2(foreign, owned)
            os.close(foreign)
        captured.append(owned)
        return owned, str(job / "inert.tmp")
    values = dict(dir=str(job), prefix=".zbt_report_", suffix=".tmp", flags=0,
                  output_type=str, name=None)
    def cell(value):
        return (lambda: value).__closure__[0]
    code = codes[0]
    assert set(code.co_freevars) <= set(values)
    opener = types.FunctionType(code, tempfile.__dict__, closure=tuple(cell(values[key]) for key in code.co_freevars))
    opener.__qualname__ = "NamedTemporaryFile.<locals>.opener"
    try:
        with monkeypatch.context() as patch:
            patch.setattr(tempfile, "_mkstemp_inner", substituted_inner)
            with pytest.raises(OSError, match="descriptor generation"):
                budget.io_open(str(job), "w", opener=opener)
        assert captured and os.fstat(captured[0]).st_size == len(b"preserved")
        assert outside.read_bytes() == b"preserved"
    finally:
        for descriptor in captured:
            os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="actual ordinary-user Windows owned scanner job")
@pytest.mark.parametrize("match", [False, True])
def test_real_pinned_engine_selected_evidence_positive_negative_and_progress(tmp_path, monkeypatch, match):
    if not tools._admin_state()["verified"] or tools._admin_state()["elevated"]:
        pytest.skip("Managed scanner requires verified ordinary-user token")
    # Both scopes and all environmental fallback locations are exact owned
    # fixtures. Never enumerate the real profile, host processes or network.
    profile = tmp_path / "synthetic-profile"
    for child in ("local", "roaming", "Downloads", "Desktop", "Documents"):
        (profile / child).mkdir(parents=True, exist_ok=True)
    for name, relative in (("HOME", ""), ("USERPROFILE", ""), ("APPDATA", "roaming"),
                           ("LOCALAPPDATA", "local"), ("PROGRAMDATA", "local")):
        monkeypatch.setenv(name, str(profile / relative))
    evidence = tmp_path / "selected-evidence"
    evidence.mkdir()
    original = evidence / "inert-payload.bin"
    original.write_bytes(b"Angerona inert scanner test, no executable content.\n")
    before = original.read_bytes()
    digest = hashlib.sha256(before if match else b"a different inert fixture").hexdigest()
    indicators = tmp_path / "inert-indicators.txt"
    indicators.write_text(digest + "\tsample\tprimary\tsynthetic fixture\n", encoding="utf-8")
    bundle = Path(__file__).resolve().parents[1] / "assets/integrations/zero_breach"
    pinned_before = hashlib.sha256((bundle / "engine.py").read_bytes()).hexdigest()
    service = tools.CuratedToolService(tmp_path / "managed-tools", bundle=bundle)
    service.prepare(tools.ToolOperation(timeout=30), allow_download=False)
    operation = tools.ToolOperation(timeout=30)
    result = service.scan(tools.ToolScanRequest(mode="targeted", targets=(str(evidence),),
                                              iocs=(str(indicators),), priority="normal"), operation)
    assert result["native_retired"] is True
    assert result["native_generations"] and all(row["native_retired"] for row in result["native_generations"])
    assert result["state"] == ("findings" if match else "complete"), result
    resource = service.resource_snapshot()
    assert resource["operation_id"] == operation.operation_id
    assert resource["job_id"] == result["job_id"] and resource["process_alive"] is False
    assert resource["pid"] and resource["creation_filetime"]
    assert bool(result["findings"]) is match
    assert original.read_bytes() == before
    assert hashlib.sha256((bundle / "engine.py").read_bytes()).hexdigest() == pinned_before == tools.ZERO_BREACH["sha256"]
    snapshot = service.progress_snapshot()
    assert snapshot["operation_id"] == operation.operation_id and snapshot["owner_retired"] is True
    assert snapshot["sequence"] >= 2 and snapshot["steps"]
    assert any(row["id"] == "hash" and row["checked"] == 1 for row in snapshot["steps"])
    assert snapshot["current_step"] == "report" and snapshot["current_file"].endswith("report.json")
    snapshot["steps"].clear()
    assert service.progress_snapshot()["steps"]  # Detached memory-only state.
    job = service._root() / "jobs" / result["job_id"]
    assert not (job / "scratch").exists()
    (tmp_path / "native-real-scan-receipt.json").write_text(json.dumps({key: result[key] for key in (
        "state", "exit_code", "native_started", "native_retired", "native_generations", "scanner_progress")}, indent=2), encoding="utf-8")


@pytest.mark.skipif(os.name != "nt", reason="actual ordinary-user Windows owned scanner job")
def test_actual_worker_deadline_keeps_partial_task_and_retires_all_running_rows(tmp_path, monkeypatch):
    if not tools._admin_state()["verified"] or tools._admin_state()["elevated"]:
        pytest.skip("Managed scanner requires verified ordinary-user token")
    selected = tmp_path / "inert-evidence.bin"
    selected.write_bytes(b"inert selected evidence")
    bundle = Path(__file__).resolve().parents[1] / "assets/integrations/zero_breach"
    service = tools.CuratedToolService(tmp_path / "managed-tools", bundle=bundle)
    service.prepare(tools.ToolOperation(timeout=30), allow_download=False)
    real_command = service._command
    def controlled_command(image, path):
        command = real_command(image, path)
        position = command.index("-c") + 1
        original = command[position]
        marker = ";from angerona.core.curated_tool_worker import main;"
        assert original.count(marker) == 1
        injection = """
from angerona.core.curated_tool_progress import ScannerProgress
import time
previous_observe=ScannerProgress.observe_file
def observed(self,path,size=None):
    token=previous_observe(self,path,size)
    if token is not None and str(path).endswith('inert-evidence.bin'):
        self.publish(force=True)
        time.sleep(20) # Explicit owned diagnostic stall, not a performance claim.
    return token
ScannerProgress.observe_file=observed
from angerona.core.curated_tool_worker import main
"""
        command[position] = original.replace(marker, "\n" + injection + "\n")
        return command
    monkeypatch.setattr(service, "_command", controlled_command)
    operation, results, errors = tools.ToolOperation(timeout=30), [], []
    def scan():
        try:
            results.append(service.scan(tools.ToolScanRequest(mode="targeted", targets=(str(selected),), priority="normal"), operation))
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=scan)
    thread.start()
    observed = False
    try:
        until = time.monotonic() + 15
        while thread.is_alive() and time.monotonic() < until:
            if service.progress_snapshot().get("current_file") == str(selected):
                observed = True
                operation.deadline = time.monotonic() + .1  # Deterministic actual deadline after evidence open.
                break
            time.sleep(.05)
        thread.join(10)
        assert observed and not thread.is_alive() and not errors, errors
        result = results[0]
        assert result["state"] == "cancelled" and result["timed_out"] is True
        assert result["native_retired"] is True and all(row["native_retired"] for row in result["native_generations"])
        progress = result["scanner_progress"]
        assert progress["owner_retired"] and progress["state"] == "timed-out"
        assert progress["current_file"] == str(selected)
        assert not any(row["state"] in {"running", "queued"} for row in progress["steps"])
        assert any(row["state"] == "not-run" for row in progress["steps"])
        assert selected.read_bytes() == b"inert selected evidence"
        (tmp_path / "native-deadline-receipt.json").write_text(json.dumps({key: result[key] for key in (
            "state", "timed_out", "native_retired", "native_generations", "scanner_progress")}, indent=2), encoding="utf-8")
    finally:
        if thread.is_alive():
            operation.cancel()
            thread.join(10)


@pytest.mark.skipif(os.name != "nt", reason="actual ordinary-user Windows owned scanner job")
def test_real_browser_database_rows_show_measured_item_progress_and_findings(tmp_path, monkeypatch):
    if not tools._admin_state()["verified"] or tools._admin_state()["elevated"]:
        pytest.skip("Managed scanner requires verified ordinary-user token")
    profile = tmp_path / "owned-browser" / "Default"
    profile.mkdir(parents=True)
    (profile / "Preferences").write_text("{}", encoding="utf-8")
    history = profile / "History"
    with sqlite3.connect(history) as connection:
        connection.execute("CREATE TABLE urls(url TEXT, title TEXT, last_visit_time INTEGER)")
        connection.execute("CREATE TABLE downloads(current_path TEXT, tab_url TEXT, referrer TEXT)")
        connection.executemany("INSERT INTO urls VALUES(?,?,?)", [
            ("https://owned-indicator.invalid/" if number == 10 else f"https://fixture-{number}.invalid/",
             "Owned inert test record", 13300000000000000) for number in range(30)
        ])
    original = history.read_bytes()
    indicators = tmp_path / "owned-indicators.txt"
    indicators.write_text("owned-indicator.invalid\tsample\tprimary\tsynthetic fixture\n", encoding="utf-8")
    bundle = Path(__file__).resolve().parents[1] / "assets/integrations/zero_breach"
    service = tools.CuratedToolService(tmp_path / "managed-tools", bundle=bundle)
    service.prepare(tools.ToolOperation(timeout=30), allow_download=False)
    real_command = service._command
    def controlled_command(image, path):
        command = real_command(image, path)
        position = command.index("-c") + 1
        marker = ";from angerona.core.curated_tool_worker import main;"
        injection = """
import angerona.core.curated_tool_progress as progress
import time
previous_rows=progress._rows_visited
def measured(*args):
    previous_rows(*args)
    time.sleep(.1) # Controlled observation window, never a scanner speed claim.
progress._rows_visited=measured
from angerona.core.curated_tool_worker import main
"""
        assert command[position].count(marker) == 1
        command[position] = command[position].replace(marker, "\n" + injection + "\n")
        return command
    monkeypatch.setattr(service, "_command", controlled_command)
    operation, results, errors, samples = tools.ToolOperation(timeout=30), [], [], []
    def scan():
        try:
            results.append(service.scan(tools.ToolScanRequest(mode="targeted", targets=(str(profile),),
                            iocs=(str(indicators),), priority="normal"), operation))
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=scan)
    thread.start()
    try:
        until = time.monotonic() + 35
        while thread.is_alive() and time.monotonic() < until:
            samples.append(service.progress_snapshot())
            time.sleep(.03)
        thread.join(10)
        assert not thread.is_alive() and not errors, errors
        result = results[0]
        assert result["state"] == "findings" and result["findings"], result
        assert result["native_retired"] and all(row["native_retired"] for row in result["native_generations"])
        measured = [row for row in samples if row.get("current_step") == "browser"
                    and row.get("item_unit") == "database rows processed"
                    and row.get("item_total") == 30 and 0 < row.get("item_completed", 0) < 30]
        assert measured, samples
        assert any(row["item_remaining_s"] is not None for row in measured)
        assert all(row["current_file"] == str(history) for row in measured)
        assert all(next(step for step in row["steps"] if step["id"] == "browser")["percent"] is None for row in measured)
        assert history.read_bytes() == original
    finally:
        if thread.is_alive():
            operation.cancel()
            thread.join(10)


@pytest.mark.skipif(os.name != "nt", reason="actual ordinary-user Windows owned scanner job")
def test_malformed_optional_progress_cannot_abort_actual_engine_or_report(tmp_path, monkeypatch):
    if not tools._admin_state()["verified"] or tools._admin_state()["elevated"]:
        pytest.skip("Managed scanner requires verified ordinary-user token")
    selected = tmp_path / "owned-inert.bin"
    selected.write_bytes(b"owned inert evidence")
    bundle = Path(__file__).resolve().parents[1] / "assets/integrations/zero_breach"
    service = tools.CuratedToolService(tmp_path / "managed-tools", bundle=bundle)
    service.prepare(tools.ToolOperation(timeout=30), allow_download=False)
    real_command = service._command
    def controlled_command(image, path):
        command = real_command(image, path)
        position = command.index("-c") + 1
        marker = ";from angerona.core.curated_tool_worker import main;"
        injection = """
from angerona.core.curated_tool_progress import ScannerProgress
previous_init=ScannerProgress.__init__
def corrupt(self,*args,**kwargs):
    previous_init(self,*args,**kwargs)
    original_writer=self.writer
    self.writer=lambda _raw:original_writer(b'{"extra":'+b'['*1500+b'0'+b']'*1500+b'}')
ScannerProgress.__init__=corrupt
from angerona.core.curated_tool_worker import main
"""
        assert command[position].count(marker) == 1
        command[position] = command[position].replace(marker, "\n" + injection + "\n")
        return command
    monkeypatch.setattr(service, "_command", controlled_command)
    result = service.scan(tools.ToolScanRequest(mode="targeted", targets=(str(selected),), priority="normal"),
                          tools.ToolOperation(timeout=30))
    assert result["state"] == "complete" and result["report"], result
    assert result["native_retired"] and all(row["native_retired"] for row in result["native_generations"])
    assert result["scanner_progress"]["progress_gap"]
    assert result["scanner_progress"]["owner_retired"]
    assert selected.read_bytes() == b"owned inert evidence"
