"""Inert startup observations, bounded receipt ownership and modeless review.

No application, source seal scan, helper, scanner or response is launched.
"""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner


class Inbox:
    def __init__(self):
        self.rows = {}; self.upserts = 0

    def upsert(self, key, title, description, review, **options):
        self.rows[key] = (title, description, review, options); self.upserts += 1

    def remove(self, key):
        self.rows.pop(key, None)


class Parent(QWidget):
    _shark_narration = Signal(str)

    def __init__(self, path):
        super().__init__()
        self.config = SimpleNamespace(data_dir=path)
        self._notifications = Inbox()
        self.red_team_engine = SimpleNamespace(_thread=None)
        self.shark_engine = SimpleNamespace(_thread=None)


@pytest.fixture
def view(tmp_path):
    app = QApplication.instance() or QApplication([])
    parent = Parent(tmp_path)
    bridge = RedTeamBridge(parent)
    yield bridge
    bridge._timer.stop()
    for worker in bridge._tasks:
        if worker.ident is not None:
            worker.join(2)
        assert not worker.is_alive()
    parent.close(); parent.deleteLater(); app.processEvents()


def failed_owner():
    owner = RedTeamToolOwner(lambda *_args: None, initialize={"private": "DO_NOT_CAPTURE_PAYLOAD"})
    owner._key = b"DO_NOT_CAPTURE_KEY"
    owner._startup_phase("source-seal")
    owner._startup_observation("failed", "ToolProtocolError")
    return owner


def test_actual_missing_existing_seal_reports_closed_phase_without_starting_native_work(monkeypatch):
    import angerona.gui.red_team_bridge as module
    monkeypatch.setattr(module, "sanitized_child_environment", lambda: {})
    monkeypatch.setattr(module.subprocess, "Popen", lambda *_a, **_k: pytest.fail("No helper may launch"))
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._run()
    state = owner.lifecycle_snapshot()
    assert state["startup_failure"]["phase"] == "source-seal"
    assert state["startup_failure"]["exception_type"] == "ToolProtocolError"
    assert not state["startup_source_seal_present"]
    assert not state["startup_source_checked"]
    assert state["stopped"] and not state["ready"] and owner._process is None


def test_first_failure_is_immutable_and_progress_has_fixed_capacity():
    owner = failed_owner()
    original = owner.lifecycle_snapshot()["startup_failure"]
    for index in range(32):
        owner._startup_phase("native-admission")
    owner._startup_observation("failed", "DO_NOT_CAPTURE\nTOKEN=secret")
    state = owner.lifecycle_snapshot()
    assert state["startup_failure"] == original
    assert len(state["startup_progress"]) == 16
    state["startup_failure"]["phase"] = "forged"
    assert owner.lifecycle_snapshot()["startup_failure"] == original
    assert owner._startup_attempt != owner._epoch


def test_normal_close_after_ui_ready_does_not_become_startup_failure():
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._ui_ready.set()
    owner._startup_observation("ready")
    owner._startup_observation("failed", "EOFError")
    assert owner.lifecycle_snapshot()["startup_terminal"] == "ready"
    assert owner.lifecycle_snapshot()["startup_failure"] is None


def test_retired_owner_requires_final_admission_before_custody_or_replacement(view, monkeypatch):
    owner = failed_owner(); owner._retired.set(); view.owner = owner
    view._closing = True
    view._startup_recorder = SimpleNamespace(record=lambda *_a, **_k: True)
    assert view._startup_receipts.empty() and not owner._startup_final_receipt_queued
    assert not view.custody_released()
    import angerona.gui.red_team_bridge as module
    monkeypatch.setattr(module, "RedTeamToolOwner", lambda *_a, **_k: pytest.fail("Old final receipt was not admitted"))
    view._start()
    assert view.owner is owner and view._timer.isActive()
    view._poll_close()
    view._startup_diag_worker.join(2)
    view._poll_close()
    assert owner._startup_final_receipt_queued and view.custody_released()
    writer = view._startup_diag_worker
    view._poll_close()
    assert view._startup_diag_worker is writer and view._startup_receipts.empty()


def test_retirement_write_never_relabels_failed_primary_receipt_as_written(view):
    owner = failed_owner(); owner._retired.set(); view.owner = owner
    view._startup_recorder = SimpleNamespace(path=view.parent_view.config.data_dir / "unused.jsonl",
        record=lambda _phase, _status, **fields: fields["actual"][0].startswith("receipt=retirement;"))
    state = owner.lifecycle_snapshot()
    view._queue_startup_receipt(owner, state)
    view._queue_startup_final_receipt(owner, state)
    view._ensure_startup_recorder(); view._startup_diag_worker.join(2)
    assert view._startup_write_states[owner._startup_attempt] == "held"
    assert view._startup_write_states[owner._startup_attempt + ":retirement"] == "written"
    view._review_startup_failure(owner)
    window = next(w for w in view.parent_view.findChildren(QWidget)
        if w.windowTitle() == "Angerona — Red Team startup review")
    assert "This attempt's receipt: held" in window._startup_details.toPlainText()
    assert "Retirement supplement: written" in window._startup_details.toPlainText()


def test_failed_optional_final_writer_has_held_disposition_and_cannot_strand_stop(view, monkeypatch):
    owner = failed_owner(); owner._retired.set(); view.owner = owner; view._closing = True
    monkeypatch.setattr(threading.Thread, "start", lambda _self: (_ for _ in ()).throw(RuntimeError("inert writer admission failure")))
    view._poll_close()
    assert owner._startup_final_receipt_queued and view._startup_receipts.empty()
    assert view._startup_write_states[owner._startup_attempt + ":retirement"] == "held"
    assert view._startup_receipt_gap and view.custody_released()


def test_real_private_writer_preserves_bounded_child_native_budget_and_kind_projection(view):
    from angerona.core.startup_diagnostics import StartupDiagnostics
    from angerona.shark.red_team_ipc import STARTUP_PREFIX
    owner = failed_owner(); owner._retired.set(); view.owner = owner
    owner._native_diagnostic_hold.set()
    for index in range(16):
        owner._startup_stderr.feed(STARTUP_PREFIX + json.dumps(dict(phase="source-seal", status="failed",
            error_type="SourceGuardTimeout", elapsed_ms=index)).encode() + b"\n", received_after_ms=100 + index)
    owner._startup_native_rows = [dict(pid=1002, birth_ticks="18446744073709551613",
        image="DO_NOT_LOG_NATIVE_PATH", exit_code=1, signaled=True, identity_unchanged=True,
        handle_closed=False, error_type="NativeDiagnosticExitUnavailable")]
    owner._startup_native_capture_attempted = True
    owner._startup_native_capture_error = "NativeDiagnosticPinUnavailable"
    view._startup_recorder = StartupDiagnostics(view.parent_view.config.data_dir)
    state = owner.lifecycle_snapshot()
    view._queue_startup_receipt(owner, state)
    view._queue_startup_final_receipt(owner, state)
    view._ensure_startup_recorder(); view._startup_diag_worker.join(3)
    assert not view._startup_diag_worker.is_alive()
    assert view._startup_write_states[owner._startup_attempt] == "written", view._startup_recorder.last_error
    assert view._startup_write_states[owner._startup_attempt + ":retirement"] == "written"
    lines = [json.loads(line) for line in view._startup_recorder.path.read_text().splitlines()]
    assert len(lines) == 2 and [row["status"] for row in lines] == ["failed", "retired"]
    assert lines[0]["actual"][0].startswith("receipt=startup;")
    assert lines[1]["actual"][0].startswith("receipt=retirement;")
    for row in lines:
        text = "\n".join(row["actual"])
        assert "verification_s=90" in text and "presentation_s=15" in text and "whole_s=105" in text
        assert text.count("source-seal/failed/SourceGuardTimeout") == 16
        assert "projection omissions: child_rows=0; native_rows=0" in text
        assert len(row["actual"]) <= 24 and all(len(item) <= 256 for item in row["actual"])
    final = "\n".join(lines[1]["actual"])
    assert "pid=1002 birth=18446744073709551613 exit=1" in final
    assert "NativeDiagnosticExitUnavailable" in final and "readonly_close_gap=True" in final
    assert "DO_NOT_CAPTURE" not in json.dumps(lines) and "DO_NOT_LOG_NATIVE_PATH" not in json.dumps(lines)


def test_receipt_is_coalesced_closed_and_owned_background_work(view):
    owner = failed_owner(); view.owner = owner
    calls = []
    view._startup_recorder = SimpleNamespace(record=lambda *args, **fields: calls.append((args, fields)) or True)
    state = owner.lifecycle_snapshot()
    view._queue_startup_receipt(owner, state); view._queue_startup_receipt(owner, state)
    assert view._startup_receipts.qsize() == 1 and not calls
    view._ensure_startup_recorder(); view._startup_diag_worker.join(2)
    assert not view._startup_diag_worker.is_alive()
    assert view._startup_diag_worker in view.owned_workers()
    assert len(calls) == 1 and calls[0][0] == ("red-team-tool-startup", "failed")
    encoded = json.dumps(calls)
    assert "DO_NOT_CAPTURE" not in encoded
    assert owner._epoch not in encoded
    assert view._startup_last_receipt == (state["startup_attempt"], "written")


def test_receipt_capacity_gap_does_not_change_native_readiness_or_admission(view):
    owner = failed_owner(); view.owner = owner
    for _ in range(8):
        view._startup_receipts.put_nowait(("failed", {}))
    before = owner.lifecycle_snapshot()
    view._queue_startup_receipt(owner, before)
    assert view._startup_receipt_gap and view._startup_receipts.qsize() == 8
    assert owner.lifecycle_snapshot() == before


def test_failed_private_write_is_explicit_and_keeps_owner_failure(view):
    owner = failed_owner(); view.owner = owner
    view._startup_recorder = SimpleNamespace(path=view.parent_view.config.data_dir / "startup-unused.jsonl",
        record=lambda *_args, **_fields: False)
    view._queue_startup_receipt(owner, owner.lifecycle_snapshot())
    view._ensure_startup_recorder(); view._startup_diag_worker.join(2)
    assert view._startup_last_receipt == (owner._startup_attempt, "held")
    assert owner.lifecycle_snapshot()["startup_failure"]["exception_type"] == "ToolProtocolError"
    view._review_startup_failure(owner)
    window = next(w for w in view.parent_view.findChildren(QWidget)
        if w.windowTitle() == "Angerona — Red Team startup review")
    assert "This attempt's receipt: held" in window._startup_details.toPlainText()
    view._set_startup_write_state("a" * 32, "written")
    view._review_startup_failure(owner)
    assert "This attempt's receipt: held" in window._startup_details.toPlainText()


def test_retired_owner_keeps_drain_timer_when_writer_exits_between_empty_and_enqueue(view):
    owner = failed_owner(); owner._retired.set(); view.owner = owner
    view._closing = True; view._starting_at = time.monotonic()
    class Unwinding:
        calls = 0
        def is_alive(self):
            self.calls += 1
            return self.calls == 1
    old = Unwinding(); view._startup_diag_worker = old
    view._tasks = [old]
    view._timer.start()
    view._poll_close()
    assert view._timer.isActive() and view._startup_receipts.qsize() == 2
    assert not view.custody_released()
    calls = []
    view._startup_recorder = SimpleNamespace(record=lambda *a, **k: calls.append((a, k)) or True)
    view._poll_close()
    view._startup_diag_worker.join(2)
    view._poll_close()
    assert not view._timer.isActive() and view._startup_receipts.empty()
    assert view.custody_released()
    assert len(calls) == 2


def test_optional_writer_start_failure_marks_queue_held_without_blocking_stop(view, monkeypatch):
    owner = failed_owner(); owner._retired.set(); view.owner = owner
    view._queue_startup_receipt(owner, owner.lifecycle_snapshot())
    view._queue_startup_final_receipt(owner, owner.lifecycle_snapshot())
    def unavailable(_self):
        raise RuntimeError("inert native thread admission failure")
    monkeypatch.setattr(threading.Thread, "start", unavailable)
    view._ensure_startup_recorder()
    assert view._startup_receipt_gap and view._startup_receipts.empty()
    assert view._startup_write_states[owner._startup_attempt] == "held"
    assert view._startup_write_states[owner._startup_attempt + ":retirement"] == "held"
    assert view._session_released() and view.custody_released()


def test_started_then_raised_writer_remains_owned_until_actual_work_finishes(view, monkeypatch):
    owner = failed_owner(); owner._retired.set(); view.owner = owner
    release = threading.Event(); entered = threading.Event()
    def blocked(*_a, **_k):
        entered.set(); assert release.wait(2); return True
    view._startup_recorder = SimpleNamespace(record=blocked)
    view._queue_startup_receipt(owner, owner.lifecycle_snapshot())
    view._queue_startup_final_receipt(owner, owner.lifecycle_snapshot())
    original_start = threading.Thread.start
    def ambiguous(worker):
        original_start(worker)
        assert entered.wait(1)
        raise RuntimeError("inert start completed then raised")
    monkeypatch.setattr(threading.Thread, "start", ambiguous)
    try:
        view._ensure_startup_recorder()
        assert view._startup_receipt_gap and view._startup_diag_worker.is_alive()
        assert not view._session_released() and not view.custody_released()
    finally:
        release.set(); view._startup_diag_worker.join(2)
    assert view._session_released() and view.custody_released()
    assert view._startup_write_states[owner._startup_attempt] == "written"


def test_one_nonmodal_notice_and_retry_requires_current_native_retired_owner(view):
    owner = failed_owner(); view.owner = owner
    state = owner.lifecycle_snapshot()
    view._notify_startup_failure(owner, state); view._notify_startup_failure(owner, state)
    inbox = view.parent_view._notifications
    assert inbox.upserts == 1 and len(inbox.rows) == 1
    calls = []; view.show = lambda: calls.append("explicit retry")
    view._retry_startup_owner(owner); assert not calls
    owner._retired.set()  # Explicit inert cleanup proof fixture, no native process exists.
    view._retry_startup_owner(owner); assert calls == ["explicit retry"]
    view.parent_view._termination_started = True
    view._retry_startup_owner(owner); assert calls == ["explicit retry"]
    view.parent_view._termination_started = False
    replacement = failed_owner(); replacement._retired.set(); view.owner = replacement
    view._retry_startup_owner(owner); assert calls == ["explicit retry"]
    view._review_startup_failure(owner)
    window = next(w for w in view.parent_view.findChildren(QWidget)
        if w.windowTitle() == "Angerona — Red Team startup review")
    assert not window.isModal() and window.windowModality() == Qt.NonModal
    assert not window._startup_retry.isEnabled()


def _writer_failure_owner(error, *, kind="show", descriptor=None):
    owner = RedTeamToolOwner(lambda *_args: None, initialize={"private": "DO_NOT_CAPTURE_INITIALIZE"})
    owner._key = b"DO_NOT_CAPTURE_KEY"
    owner._startup_phase("await-ui-ready")

    def fail_send(*_args, **_kwargs):
        raise error

    owner._channel = SimpleNamespace(send=fail_send)
    owner._queue.put((kind, {"private": "DO_NOT_CAPTURE_FRAME"}, "", None, descriptor))
    owner._write_loop()  # Synchronous inert transport fixture; no native child.
    return owner


def test_writer_first_failure_keeps_terminal_before_stop_and_reader_unwind():
    owner = _writer_failure_owner(BrokenPipeError("DO_NOT_CAPTURE_ERROR_TEXT"))
    state = owner.lifecycle_snapshot()
    terminal = state["startup_terminal_record"]
    assert state["stopped"] and state["startup_terminal"] == "failed"
    assert state["startup_failure"]["exception_type"] == "BrokenPipeError"
    assert terminal == dict(status="failed", phase="await-ui-ready", error_type="BrokenPipeError",
        operation="channel-send", message_kind="show", context_code="writer-error")
    assert state["startup_stop_origin"] == "writer-failure" and state["startup_stop_origin_known"]
    assert not state["ready"] and not state["ui_ready"] and owner._process is None
    owner._run()  # Already stopped: no source scan, spawn, or authenticated work.
    owner._startup_observation("failed", "EOFError")
    assert owner.lifecycle_snapshot()["startup_terminal_record"] == terminal
    terminal["error_type"] = "forged"
    assert owner.lifecycle_snapshot()["startup_terminal_record"]["error_type"] == "BrokenPipeError"


def test_writer_send_failure_precedes_later_descriptor_cleanup_error(monkeypatch):
    import angerona.gui.red_team_bridge as module
    closes = []

    def close_fixture(descriptor):
        assert descriptor == 9137  # An inert integer, never a real descriptor.
        closes.append(descriptor)
        raise ValueError("DO_NOT_CAPTURE_CLEANUP_TEXT")

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "close", close_fixture)
        owner = _writer_failure_owner(BrokenPipeError("DO_NOT_CAPTURE_SEND_TEXT"), descriptor=9137)
    assert closes == [9137]
    state = owner.lifecycle_snapshot()
    assert state["startup_terminal_record"]["error_type"] == "BrokenPipeError"
    assert state["startup_terminal_record"]["operation"] == "channel-send"
    assert state["startup_failure"]["exception_type"] == "BrokenPipeError"
    assert state["stopped"] and not state["ui_ready"]


def test_unknown_writer_kind_and_exception_name_have_closed_projection(view):
    class DO_NOT_CAPTURE_EXCEPTION_NAME(Exception):
        pass

    owner = _writer_failure_owner(DO_NOT_CAPTURE_EXCEPTION_NAME("DO_NOT_CAPTURE_TEXT"),
        kind="DO_NOT_CAPTURE_MESSAGE_KIND")
    view.owner = owner
    state = owner.lifecycle_snapshot()
    assert state["startup_terminal_record"]["error_type"] == "Exception"
    assert state["startup_terminal_record"]["message_kind"] == "unknown"
    view._queue_startup_receipt(owner, state)
    status, fields = view._startup_receipts.get_nowait()
    view._startup_receipts.task_done()
    encoded = json.dumps(view._startup_persist_fields(fields))
    assert status == "failed" and "DO_NOT_CAPTURE" not in encoded
    assert owner._epoch not in encoded and "writer-error" in encoded


@pytest.mark.parametrize("origin,known", [("suite-shutdown", True), ("unknown", False)])
def test_pre_ui_stop_is_not_ready_or_an_invented_failure(origin, known):
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._startup_phase("hello-receive")
    if known:
        owner._startup_stop_requested(origin)
    assert owner.stop(.2)  # No processes/handles exist in this lifecycle fixture.
    state = owner.lifecycle_snapshot()
    assert state["startup_terminal"] == "stopped" and state["startup_failure"] is None
    assert state["startup_terminal_record"]["phase"] == "hello-receive"
    assert state["startup_stop_origin"] == origin and state["startup_stop_origin_known"] is known
    owner._startup_observation("failed", "EOFError")
    owner._startup_observation("ready")
    assert owner.lifecycle_snapshot()["startup_terminal"] == "stopped"
    assert not state["ui_ready"] and not state["ready"] and state["retired"]


def test_authenticated_pre_ui_close_records_only_the_known_request_origin(view):
    owner = RedTeamToolOwner(lambda *_args: None)
    owner._startup_phase("await-ui-ready")
    owner._ready.set()  # Inert authenticated-owner admission fixture.
    view.owner = owner
    actions = []
    view.parent_view._stop_simulation = lambda: actions.append("existing-stop-route")
    view._handle_incoming((owner, owner._epoch), "close", {}, "")
    state = owner.lifecycle_snapshot()
    assert actions == ["existing-stop-route"] and view._closing
    assert state["startup_terminal"] == "stopped" and state["startup_failure"] is None
    assert state["startup_stop_origin"] == "authenticated-tool-close" and state["startup_stop_origin_known"]
    assert not state["ui_ready"]


def test_real_retirement_projection_retains_first_terminal_context_and_unknowns(view):
    from angerona.core.startup_diagnostics import StartupDiagnostics
    from angerona.shark.red_team_ipc import STARTUP_PREFIX
    owner = _writer_failure_owner(BrokenPipeError("DO_NOT_CAPTURE_ERROR_TEXT"))
    owner._run()  # Original stopped writer remains the terminal before reader unwind.
    owner._retired.set()  # Inert completed native custody fixture; no child exists.
    view.owner = owner
    for index in range(16):
        owner._startup_stderr.feed(STARTUP_PREFIX + json.dumps(dict(phase="qt-ui", status="started",
            error_type="", elapsed_ms=index)).encode() + b"\n", received_after_ms=100 + index)
    owner._startup_native_rows = [dict(pid=1002, birth_ticks="18446744073709551613",
        image="DO_NOT_CAPTURE_NATIVE_PATH", exit_code=1, signaled=True, identity_unchanged=True,
        handle_closed=True, error_type="")]
    view._startup_recorder = StartupDiagnostics(view.parent_view.config.data_dir)
    state = owner.lifecycle_snapshot()
    view._queue_startup_receipt(owner, state)
    view._queue_startup_final_receipt(owner, state)
    view._ensure_startup_recorder()
    view._startup_diag_worker.join(3)
    assert not view._startup_diag_worker.is_alive()
    assert view._startup_write_states[owner._startup_attempt] == "written"
    assert view._startup_write_states[owner._startup_attempt + ":retirement"] == "written"
    records = [json.loads(line) for line in view._startup_recorder.path.read_text().splitlines()]
    assert [record["status"] for record in records] == ["failed", "retired"]
    for record in records:
        text = "\n".join(record["actual"])
        assert "status=failed; phase=await-ui-ready; error=BrokenPipeError" in text
        assert "stop_origin=writer-failure; origin_known=True" in text
        assert "operation=channel-send; kind=show; code=writer-error" in text
        assert text.count("qt-ui/started/-") == 16
        assert "projection omissions: child_rows=0; native_rows=0" in text
        assert len(record["actual"]) <= 24 and all(len(value) <= 256 for value in record["actual"])
        assert "verification_s=90" in text and "presentation_s=15" in text and "whole_s=105" in text
    assert "DO_NOT_CAPTURE" not in json.dumps(records)
    # A legacy/unlabelled stopped owner must remain explicitly unknown in the
    # final receipt; retirement is not evidence that presentation was ready.
    unknown = RedTeamToolOwner(lambda *_args: None)
    assert unknown.stop(.2)
    view._queue_startup_receipt(unknown, unknown.lifecycle_snapshot())
    view._queue_startup_final_receipt(unknown, unknown.lifecycle_snapshot())
    queued = []
    while not view._startup_receipts.empty():
        status, fields = view._startup_receipts.get_nowait()
        queued.append((status, view._startup_persist_fields(fields)))
        view._startup_receipts.task_done()
    assert [status for status, _fields in queued] == ["stopped", "retired"]
    for _status, fields in queued:
        text = "\n".join(fields["actual"])
        assert "status=stopped" in text and "stop_origin=unknown; origin_known=False" in text
        assert "became ready" not in fields["reason"]
