"""Offscreen client tests never connect to an operator process or run responses."""
from __future__ import annotations

from collections import deque
import copy
import json
import threading
import time

from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication
import pytest

from angerona.gui.live_debug_panel import LiveDebugPanel, _StreamWorker


class FakeClient:
    def __init__(self, records=(), error=None):
        self.records = deque(records)
        self.error = error
        self.canceled = threading.Event()
        self.entered = threading.Event()
        self.closed = threading.Event()
        self.calls = []

    def connect(self, timeout):
        self.calls.append(("connect", timeout, threading.get_ident()))

    def read(self, timeout):
        self.entered.set()
        if self.records:
            return self.records.popleft()
        if self.error:
            raise self.error
        self.canceled.wait(timeout)
        return None

    def cancel(self):
        self.canceled.set()

    def close(self):
        self.calls.append(("close", None, threading.get_ident()))
        self.closed.set()


def pump_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(0.005)
    QApplication.instance().processEvents()
    assert predicate()


def test_construction_is_inert_and_bounds_rows():
    calls = []
    panel = LiveDebugPanel(client_factory=lambda *a, **k: calls.append((a, k)))
    try:
        assert calls == []
        assert panel.pid_input.value() == 0
        assert not panel._timer.isActive()
        assert not panel.disconnect_button.isEnabled()
        assert panel.model.maximum == 1000
        assert panel.status.textFormat() == Qt.TextFormat.PlainText
        assert not panel.connect_to_pid()
        assert "positive" in panel.status.text()
    finally:
        panel.close()
    with pytest.raises(ValueError):
        LiveDebugPanel(max_rows=20)


@pytest.mark.parametrize("birth", ["nan", "inf", "-1", "garbage"])
def test_invalid_expected_birth_never_opens_pipe(birth):
    calls = []
    panel = LiveDebugPanel(default_pid=45001, client_factory=lambda *a, **k: calls.append(True))
    try:
        panel.birth_input.setText(birth)
        assert not panel.connect_to_pid()
        assert not calls
        assert panel._worker is None
    finally:
        panel.close()


@pytest.mark.parametrize("pid", [0, -1, True, 2**32, "45001"])
def test_worker_rejects_invalid_pid_before_factory(pid):
    calls = []
    worker = _StreamWorker(pid, None, lambda *a, **k: calls.append(True))
    worker.start()
    assert worker.wait(1500)
    rows, lost, state, message, _pending = worker.take()
    assert calls == []
    assert rows == [] and lost == 0
    assert state == "failed" and "process ID" in message


def test_pipe_reads_connect_and_close_run_outside_qt_thread():
    client = FakeClient([{"kind": "event", "message": "fixture", "severity": "HIGH"}])
    factory_calls = []
    def factory(endpoint, **kwargs):
        factory_calls.append((endpoint, kwargs, threading.get_ident()))
        return client
    panel = LiveDebugPanel(default_pid=45001, client_factory=factory)
    try:
        panel.birth_input.setText("1800000000.5")
        assert panel.connect_to_pid()
        pump_until(lambda: panel.model.rowCount() == 1)
        assert not panel.connect_button.isEnabled()
        assert factory_calls[0][0] == r"\\.\pipe\Angerona.LiveDebug.45001"
        assert factory_calls[0][1] == {"expected_pid": 45001, "expected_birth": 1800000000.5}
        assert factory_calls[0][2] != threading.get_ident()
        panel.disconnect_stream()
        pump_until(lambda: panel._worker is None)
        assert client.closed.is_set()
        assert all(call[2] != threading.get_ident() for call in client.calls)
        assert panel.connect_button.isEnabled()
    finally:
        panel.stop_workers(1500)
        panel.close()


def test_connection_errors_are_plain_text_and_last_records_remain_visible():
    hostile = '<b>Windows diagnostic source unavailable</b>'
    client = FakeClient([{"kind": "coverage", "message": "Source unavailable"}], RuntimeError(hostile))
    panel = LiveDebugPanel(default_pid=45001, client_factory=lambda *a, **k: client)
    try:
        assert panel.connect_to_pid()
        pump_until(lambda: panel._worker is None)
        assert hostile in panel.status.text()
        assert panel.status.textFormat() == Qt.TextFormat.PlainText
        assert panel.model.rowCount() == 1
        assert panel.model.rows[0].record["kind"] == "coverage"
    finally:
        panel.close()


def test_worker_buffer_and_view_are_bounded_and_drop_notices_are_explicit():
    panel = LiveDebugPanel(max_rows=500)
    worker = _StreamWorker(45001, None)
    panel._worker = worker
    panel._workers.append(worker)
    try:
        for index in range(300):
            worker.offer({"kind": "event", "message": f"row-{index}"})
        panel._drain()
        assert panel.model.rowCount() == 65
        assert panel.model.rows[0].record["kind"] == "gap"
        assert panel.model.rows[0].record["dropped_events"] == 44
        for _ in range(4):
            panel._drain()
        assert panel.model.rowCount() == 257
        panel.model.append([{"kind": "diagnostic", "message": str(index)} for index in range(520)])
        panel._drain()
        assert panel.model.rowCount() == 500
        assert panel.model.evicted == 277
        assert "Client gaps: 44" in panel.counters.text()
        assert "History evicted: 277" in panel.counters.text()
    finally:
        panel.close()


def test_rejected_or_mutated_client_records_cannot_silently_change_evidence():
    worker = _StreamWorker(45001, None)
    original = {"kind": "event", "details": {"pid": 45001}}
    worker.offer(original)
    original["details"]["pid"] = 1
    worker.offer({"kind": "event", "message": "x" * (33 * 1024)})
    rows, lost, *_ = worker.take()
    assert lost == 0
    assert rows[0]["details"]["pid"] == 45001
    assert rows[1]["kind"] == "coverage"
    assert rows[1]["collection_complete"] is False
    assert "UNKNOWN" in rows[1]["message"]


def test_reviews_require_explanation_and_never_mutate_original_or_security_policy():
    hostile = '<img src="https://example.invalid/track"><b>evidence</b>'
    original = {"kind": "event", "severity": "CRITICAL", "message": hostile,
        "details": {"response_authorized": True, "response_contract": {"actions": ["isolate_host"]}}}
    before = copy.deepcopy(original)
    panel = LiveDebugPanel()
    try:
        panel.model.append([original])
        panel.table.selectRow(0)
        assert hostile.replace('"', '\\"') in panel.record_detail.toPlainText()
        assert panel.record_detail.isReadOnly()
        assert not panel.annotate_selected("false-positive", " ")
        assert panel.model.rows[0].annotation is None
        assert panel.annotate_selected("false-positive", "Reviewed installer command and signed executable")
        assert panel.model.rows[0].record == before
        assert original == before
        assert panel.model.rows[0].annotation["scope"] == "local-note-only"
        assert panel.model.data(panel.model.index(0, 5)) == "false-positive"
    finally:
        panel.close()


def test_explicit_selected_export_preserves_original_and_refuses_overwrite(tmp_path):
    panel = LiveDebugPanel()
    target = tmp_path / "review.json"
    try:
        panel.model.append([{"kind": "event", "severity": "HIGH", "message": "fixture"}])
        panel.table.selectRow(0)
        assert panel.annotate_selected("needs-review", "Need additional process identity evidence")
        assert panel.export_selected(target)
        pump_until(lambda: not panel._exports)
        value = json.loads(target.read_text(encoding="ascii"))
        assert value["original_view"]["severity"] == "HIGH"
        assert value["local_review"]["verdict"] == "needs-review"
        assert value["policy_changes"] is False
        saved = target.read_bytes()
        assert panel.export_selected(target)
        pump_until(lambda: not panel._exports)
        assert "Export failed" in panel.review_status.text()
        assert target.read_bytes() == saved
        assert not panel.export_selected("relative.json")
    finally:
        panel.stop_workers(1500)
        panel.close()


def test_snapshot_is_bounded_valid_json_with_explicit_omissions():
    panel = LiveDebugPanel(max_rows=500)
    try:
        panel.model.append([{"kind": "diagnostic", "message": "x" * 12000} for _ in range(30)])
        snapshot = panel.snapshot_text()
        assert len(snapshot.encode("ascii")) <= 64 * 1024
        value = json.loads(snapshot)
        assert value["advisory_only"] is True
        assert value["omitted_visible_records"] > 0
        assert value["visible_records"] == 30
    finally:
        panel.close()


def test_widget_destruction_cancels_reads_and_retains_worker_until_safe_exit():
    client = FakeClient()
    panel = LiveDebugPanel(default_pid=45001, client_factory=lambda *a, **k: client)
    assert panel.connect_to_pid()
    worker = panel._worker
    assert client.entered.wait(1.0)
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert worker.wait(1500)
    assert client.canceled.is_set()
    assert client.closed.is_set()
