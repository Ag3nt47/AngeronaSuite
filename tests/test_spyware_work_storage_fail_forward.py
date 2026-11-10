"""Combined-scan free-space holds with no Core, host scan or child launch.

The actual controller priority-work/focus scope, ToolOperation, service scan,
preflight and write-admission methods run. Disk/native-collector publications,
source runtime selection and persistence custody are explicit inert seams.
These tests prove ordering/refusal and typed facts, not real scan coverage.
"""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from angerona.core import curated_tools as backend
from angerona.gui import curated_tools as ui


@pytest.mark.parametrize("stage", ["preflight", "before-worker"])
@pytest.mark.parametrize("allowance_mib", [64, 256, 1024])
def test_actual_pre_worker_admissions_keep_full_reserve_and_measured_facts(
        tmp_path, monkeypatch, stage, allowance_mib):
    root = tmp_path / "managed"
    root.mkdir()
    working = allowance_mib * 1024**2
    required = 3 * 1024**3 + working
    service = backend.CuratedToolService(root, cfg=SimpleNamespace(
        github_tools_enabled=True, github_tools_job_limit_mib=allowance_mib))
    monkeypatch.setattr(backend, "_require_user", lambda: None)
    monkeypatch.setattr(service, "_python", lambda: tmp_path / "python.exe")
    measured = []
    def disk_usage(path):
        measured.append(path)
        return SimpleNamespace(free=required - 1)
    monkeypatch.setattr(backend.shutil, "disk_usage", disk_usage)
    monkeypatch.setattr(backend.subprocess, "Popen",
                        lambda *_a, **_k: pytest.fail("A worker was launched"))
    with pytest.raises(backend.ToolWorkStorageHeld) as caught:
        if stage == "preflight":
            service._preflight_scan(root)
        else:
            service._run(root / "engine.py", [], root,
                         backend.ToolOperation(), backend.ToolScanRequest())
    hold = caught.value.storage_hold
    assert measured == [root]
    assert hold["required_bytes"] == required
    assert hold["working_bytes"] == working and hold["reserve_bytes"] == 3 * 1024**3
    assert hold["free_bytes"] == required - 1 and hold["stage"] == stage
    assert hold["checked_path"] == str(root.absolute())
    assert hold["volume"] == root.anchor
    assert hold["volume_kind"] == "checked-path-anchor"
    assert hold["tool_worker_started"] is False and hold["automatic_deletion"] is False
    assert service.progress_snapshot() == {}


def test_exact_required_capacity_is_not_rejected_or_reduced(tmp_path, monkeypatch):
    required = 3 * 1024**3 + 256 * 1024**2
    service = backend.CuratedToolService(tmp_path, cfg=SimpleNamespace(
        github_tools_enabled=True, github_tools_job_limit_mib=256))
    monkeypatch.setattr(backend, "_require_user", lambda: None)
    monkeypatch.setattr(service, "_python", lambda: tmp_path / "python.exe")
    monkeypatch.setattr(backend.shutil, "disk_usage", lambda _path: SimpleNamespace(free=required))
    assert service._preflight_scan(tmp_path) is None


class _Cancel:
    def __init__(self, wait):
        self.flag = False
        self.on_wait = wait

    def set(self):
        self.flag = True

    def is_set(self):
        return self.flag

    def wait(self, seconds):
        self.on_wait(seconds)
        return self.flag


@pytest.fixture
def combined(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    clock, calls, frames = [100.0], [], []
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=lambda: 1800000000.0,
                                sleep=lambda value: clock.__setitem__(0, clock[0] + value))
    monkeypatch.setattr(backend, "time", fake_time)
    monkeypatch.setattr(ui, "time", fake_time)
    cfg = SimpleNamespace(data_dir=tmp_path, github_tools_enabled=True,
        github_tools_job_limit_mib=256, spyware_scan_verify_admin=False,
        spyware_scan_native_enabled=True, spyware_scan_zero_breach_enabled=True)

    class Native:
        def __init__(self):
            self.state = {}
            self.cancelled = []
            self.change_next = False

        def request_priority_scan(self, request_id):
            return self.request_scoped_priority_scan(request_id)

        def request_scoped_priority_scan(self, request_id, **_options):
            calls.append("native-admit")
            self.state = dict(request_id=request_id, lifecycle_generation=7,
                state="running", request_finished=False, collector_finished=False,
                progress={"state": "running", "overall_percent": 99},
                coverage={"advisory_count": 1})
            return True

        def priority_scan_snapshot(self):
            calls.append("native-snapshot")
            if self.change_next:
                self.change_next = False
                calls.append("wrong-generation")
                return dict(self.state, lifecycle_generation=8)
            return dict(self.state)

        def complete(self):
            calls.append("native-complete")
            self.state = dict(self.state, state="completed", request_finished=True,
                collector_finished=True, coverage_incomplete=False,
                progress={"state": "completed", "overall_percent": 100})

        def cancel_priority_scan(self, request_id):
            assert request_id == self.state["request_id"]
            self.cancelled.append(request_id)
            calls.append("native-cancel")
            self.state = dict(self.state, state="cancelled", request_finished=True,
                collector_finished=True, coverage_incomplete=True)

    native = Native()
    class Focus:
        def __enter__(self):
            calls.append("focus-enter")
            return self

        def __exit__(self, *_args):
            assert native.state["request_finished"] and native.state["collector_finished"]
            calls.append("focus-exit")

        def renew(self):
            return True

    manager = SimpleNamespace(cfg=cfg, modules={"SpywareGuard": native},
        priority_scan_focus=lambda **_kw: Focus())
    controller = ui.CuratedToolsController(manager)
    controller._frame = lambda kind, value: frames.append((kind, value))
    service = backend.CuratedToolService(tmp_path, cfg=cfg)
    monkeypatch.setattr(service, "status", lambda: {"verified": True, "execution_available": True})
    monkeypatch.setattr(backend, "_require_user", lambda: None)
    monkeypatch.setattr(service, "_python", lambda: tmp_path / "python.exe")
    monkeypatch.setattr(backend.shutil, "disk_usage", lambda _p: SimpleNamespace(free=2_700_000_000))
    @contextmanager
    def transaction(operation):
        operation.check()
        calls.append("tool-transaction-enter")
        try:
            yield tmp_path
        finally:
            calls.append("tool-transaction-exit")
    monkeypatch.setattr(service, "_transaction", transaction)
    monkeypatch.setattr(service, "_owned_job",
                        lambda *_a, **_k: pytest.fail("A job was created after a free-space hold"))
    monkeypatch.setattr(backend.subprocess, "Popen",
                        lambda *_a, **_k: pytest.fail("A worker was launched"))
    operation = backend.ToolOperation(timeout=10)
    def finish_after_wait(seconds):
        calls.append("native-wait")
        clock[0] += seconds
        native.complete()
    operation.cancelled = _Cancel(finish_after_wait)
    actual_scan = service.scan
    def scan(request, owner, **options):
        calls.append("tool-scan")
        try:
            return actual_scan(request, owner, **options)
        except backend.ToolWorkStorageHeld:
            calls.append("storage-hold")
            raise
    monkeypatch.setattr(service, "scan", scan)
    tx = SimpleNamespace(app=app, clock=clock, calls=calls, frames=frames,
        native=native, controller=controller, service=service, operation=operation,
        cfg=cfg, scan=scan)
    yield tx
    controller.shutdown()
    assert controller.wait_for_shutdown(.1)
    controller.deleteLater()
    app.processEvents()


def _combined(tx):
    return tx.controller._priority_work(backend, tx.service, tx.cfg, tx.operation,
        {"native_enabled": True, "zero_breach_enabled": True},
        lambda message: tx.calls.append(message), budget=10)


def test_actual_combined_focus_allows_native_completion_after_optional_space_hold(combined):
    tx = combined
    result = _combined(tx)
    assert result["state"] == "incomplete" and result["coverage_incomplete"] is True
    assert result["native"]["state"] == "completed"
    assert result["native"]["coverage"]["advisory_count"] == 1
    assert result["native_scan_completion"]["lifecycle_generation"] == 7
    toolkit = result["details"]["zero_breach"]
    assert toolkit["state"] == "held" and toolkit["tool_worker_started"] is False
    assert toolkit["coverage"]["state"] == "not-started" and toolkit["findings"] == []
    assert result["storage_hold"]["required_bytes"] == 3_489_660_928
    assert result["storage_hold"]["free_bytes"] == 2_700_000_000
    assert result["scan_progress"]["finished"] == result["scan_progress"]["total"] == 4
    assert tx.calls.index("native-admit") < tx.calls.index("storage-hold")
    assert tx.calls.index("storage-hold") < tx.calls.index("native-wait")
    assert tx.calls.index("native-complete") < tx.calls.index("focus-exit")
    assert tx.native.cancelled == [] and tx.controller._native_request_id == ""
    assert tx.service.progress_snapshot()["state"] == "not-started"


@pytest.mark.parametrize("failure", ["stop", "deadline", "generation", "source-integrity",
                                      "custody-unknown", "unexpected"])
def test_stop_deadline_generation_and_untyped_failures_keep_strict_native_retirement(
        combined, monkeypatch, failure):
    tx = combined
    if failure in {"source-integrity", "custody-unknown", "unexpected"}:
        error = (RuntimeError("Inert unknown supplier") if failure == "unexpected" else
                 backend.ToolError("Inert source integrity hold" if failure == "source-integrity"
                                   else "Inert native retirement remains unresolved"))
        def fail(*_a, **_k):
            raise error
        monkeypatch.setattr(tx.service, "scan", fail)
    else:
        scan = tx.service.scan
        def held(*args, **kwargs):
            try:
                return scan(*args, **kwargs)
            except backend.ToolWorkStorageHeld:
                if failure == "stop":
                    tx.operation.cancel()
                elif failure == "deadline":
                    tx.clock[0] = tx.operation.deadline
                else:
                    tx.native.change_next = True
                raise
        monkeypatch.setattr(tx.service, "scan", held)
    result = _combined(tx)
    assert result["state"] == {"stop": "cancelled", "deadline": "timed-out",
                               "generation": "incomplete"}.get(failure, "failed")
    assert result["coverage_incomplete"] is True
    assert result["native"]["state"] == "cancelled"
    assert result["native"]["lifecycle_generation"] == 7
    assert len(tx.native.cancelled) == 1
    assert tx.calls.index("native-cancel") < tx.calls.index("focus-exit")
    assert "native-complete" not in tx.calls
    assert tx.controller._native_request_id == ""
    if failure == "generation":
        assert "wrong-generation" in tx.calls
    if failure in {"source-integrity", "custody-unknown", "unexpected"}:
        assert "storage_hold" not in result


def test_free_space_report_explains_working_volume_not_report_slot_deletion(combined):
    tx = combined
    result = _combined(tx)
    controls = ui.SpywareScanControls(tx.controller.manager, controller=tx.controller)
    try:
        controls._apply(dict(result, busy=False, lifecycle="terminal"))
        text = controls.stage_explanation.text()
        assert "working volume" in text and "3.25 GiB" in text
        assert "Native checks retain their own recorded result" in text
        assert "retained reports need review" not in text
        assert "extra report" not in text and "No evidence was deleted" in text
    finally:
        controls.close()
        controls.deleteLater()
        tx.app.processEvents()
