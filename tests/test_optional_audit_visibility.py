"""Optional audit visibility carries no native completion or recovery authority."""
from __future__ import annotations

import copy
import json
import os
import threading
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from angerona.core import remediation_log, status_report
from angerona.core.commands import CommandConsole
from angerona.core.eventbus import EventBus


def _view(**changes):
    value = dict(schema=1, state="observed", scope="instance-lifetime", durable=False,
                 response_authorized=False, entry_limit_bytes=65536, scalar_allowance_bytes=32,
                 attempted=5, recorded=1, rejected=2, rejected_oversize=1, rejected_invalid=1,
                 unavailable=0, persistence_unknown=1, pending=1, coverage_gap=True)
    value.update(changes)
    return value


def _result(**changes):
    value = dict(schema=1, attempted=5, recorded=1, rejected=2, unavailable=1,
                 persistence_unknown=1, response_authorized=False)
    value.update(changes)
    return value


def _no_io(*_args, **_kwargs):
    raise AssertionError("optional-audit visibility attempted I/O or native work")


class _MemoryLedger:
    def __init__(self, source):
        self.source = source
        self._lock = threading.Lock()

    def optional_audit_snapshot(self):
        return self.source

    @property
    def _db(self):
        return _no_io()

    recent = by_mitre = stats = _no_io


def _console():
    # _remlog needs no constructed command engine, model or host provider.
    return CommandConsole.__new__(CommandConsole)


def test_snapshot_copies_only_whitelisted_memory_without_initialization_or_db_lock(monkeypatch):
    source = _view(private_error="private-path", payload={"token": "private-token"})
    original = copy.deepcopy(source)
    ledger = _MemoryLedger(source)
    monkeypatch.setattr(remediation_log, "get_log", lambda: ledger)
    monkeypatch.setattr(remediation_log, "init_log", _no_io)
    results = []
    errors = []

    def read():
        try:
            results.append(status_report._optional_audit_snapshot())
        except BaseException as exc:
            errors.append(exc)

    # A wrong SQL-lock dependency fails within a finite fixture deadline; the
    # finally path releases it and retires this owned Python thread.
    ledger._lock.acquire()
    thread = threading.Thread(target=read, name="OptionalAuditVisibilityFixture")
    try:
        thread.start()
        thread.join(5)
        assert not thread.is_alive(), "memory projection waited for the SQL lock"
    finally:
        ledger._lock.release()
        if thread.ident is not None:
            thread.join(5)
    assert not thread.is_alive() and not errors
    value = results[0]
    assert value["state"] == "observed" and value["pending"] == 1
    assert value["coverage_gap"] is True and value["response_authorized"] is False
    assert value["scope"] == "instance-lifetime" and value["durable"] is False
    assert "private" not in json.dumps(value) and source == original
    value["attempted"] = 999
    assert source == original


def test_projection_and_formatting_never_refresh_clock_path_or_native_provider(monkeypatch):
    from pathlib import Path

    ledger = _MemoryLedger(_view())
    with monkeypatch.context() as guard:
        guard.setattr(remediation_log, "get_log", lambda: ledger)
        guard.setattr(remediation_log, "init_log", _no_io)
        guard.setattr(status_report.time, "time", _no_io)
        guard.setattr(status_report.time, "monotonic", _no_io)
        guard.setattr(status_report.os, "stat", _no_io)
        guard.setattr(Path, "read_bytes", _no_io)
        value = status_report._optional_audit_snapshot()
        text = status_report.optional_audit_status_text(value)
        result = status_report.optional_audit_result_text(_result())
    assert value["state"] == "observed" and "pending=1" in text
    assert "not durable across restart" in text and "history continuity" in text
    assert "reset on instance replacement or restart" in text
    assert "persistence_unknown=1" in result


@pytest.mark.parametrize("changes", [
    {"schema": True}, {"schema": 2}, {"state": "healthy"}, {"state": "x" * 10000},
    {"scope": "process-lifetime"}, {"scope": "private"}, {"durable": True},
    {"response_authorized": True}, {"entry_limit_bytes": True}, {"entry_limit_bytes": 65535},
    {"scalar_allowance_bytes": 0}, {"attempted": True}, {"attempted": -1},
    {"attempted": 1 << 63}, {"attempted": 4}, {"recorded": False}, {"pending": -1},
    {"rejected_invalid": 0}, {"rejected_oversize": "1"}, {"coverage_gap": 1},
    {"coverage_gap": False}, {"persistence_unknown": None},
])
def test_malformed_snapshot_is_wholly_unavailable_with_unknown_counts(changes):
    value = status_report._optional_audit_snapshot(_MemoryLedger(_view(**changes)))
    assert value["state"] == "unavailable" and value["reason_code"] == "invalid_observation"
    assert "attempted" not in value and "coverage_gap" not in value
    text = status_report.optional_audit_status_text(value)
    assert "counts unknown" in text and "attempted=0" not in text and "private" not in text


@pytest.mark.parametrize("source", [None, [], {}, {str(index): 0 for index in range(40)}])
def test_missing_or_oversized_snapshot_cannot_be_clean_zero(source):
    value = status_report._optional_audit_snapshot(_MemoryLedger(source))
    assert value["state"] == "unavailable" and "attempted" not in value


def test_absent_missing_failed_and_uninitialized_readers_are_explicit(monkeypatch):
    assert status_report._optional_audit_snapshot(None)["reason_code"] == "not_initialized"
    assert status_report._optional_audit_snapshot(object())["reason_code"] == "reader_unavailable"
    broken = SimpleNamespace(optional_audit_snapshot=lambda: (_ for _ in ()).throw(RuntimeError("private")))
    value = status_report._optional_audit_snapshot(broken)
    assert value["reason_code"] == "reader_failed" and "private" not in json.dumps(value)
    monkeypatch.setattr(remediation_log, "get_log", lambda: None)
    assert "counts unknown" in _console()._remlog(["status"])
    monkeypatch.setattr(remediation_log, "get_log", _no_io)
    assert "counts unknown" in _console()._remlog(["status"])


def test_pending_is_distinct_from_rejected_and_zero_does_not_attest_continuity():
    source = _view(attempted=1, recorded=0, rejected=0, rejected_oversize=0,
                   rejected_invalid=0, persistence_unknown=0, pending=1, coverage_gap=False)
    value = status_report._optional_audit_snapshot(_MemoryLedger(source))
    assert value["state"] == "observed" and value["coverage_gap"] is False
    text = status_report.optional_audit_status_text(value)
    assert "pending=1" in text and "rejected=0" in text
    assert "Zero gaps do not prove history continuity" in text


def test_remlog_status_uses_no_history_queries_and_empty_rows_still_show_gap(monkeypatch):
    ledger = _MemoryLedger(_view())
    monkeypatch.setattr(remediation_log, "get_log", lambda: ledger)
    for args in (["status"], ["STATUS"], ["status", "20"]):
        text = _console()._remlog(args)
        assert "coverage_gap=True" in text and "rejected=2" in text
        assert "persistence_unknown=1" in text and "not durable across restart" in text
    ledger.recent = lambda _limit: []
    text = _console()._remlog([])
    assert "No remediation log entries" in text and "coverage_gap=True" in text
    ledger.by_mitre = lambda _mitre, _limit: []
    assert "coverage_gap=True" in _console()._remlog(["T1112"])


def test_status_json_and_text_persist_changed_optional_counters_without_new_queries(tmp_path, monkeypatch):
    ledger = _MemoryLedger(_view())
    monkeypatch.setattr(remediation_log, "get_log", lambda: ledger)
    reporter = status_report.StatusReporter(
        EventBus(), SimpleNamespace(count_since=lambda _since: 0),
        SimpleNamespace(modules={}, is_enabled=lambda _name: False),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=True,
                        ollama_host="local", ollama_model="fixture"),
    )
    assert reporter._write(force=True)
    path = tmp_path / "diagnostics" / "status.json"
    first = json.loads(path.read_text())
    assert first["optional_audit"]["rejected"] == 2
    ledger.source = _view(attempted=6, rejected=3, rejected_oversize=2)
    assert reporter._write()
    latest = json.loads(path.read_text())
    assert latest["optional_audit"]["rejected"] == 3
    text = (tmp_path / "diagnostics" / "status.txt").read_text()
    assert "rejected=3" in text and "coverage_gap=True" in text
    assert "instance-lifetime" in json.dumps(latest["optional_audit"])
    assert "Native security journals and closure authority are separate" in text
    assert "optional_audit" not in (latest.get("runtime_healer") or {}).get("components", {})


@pytest.mark.parametrize("changes", [
    {"schema": True}, {"response_authorized": True}, {"attempted": True},
    {"attempted": 4}, {"recorded": -1}, {"rejected": 1 << 63},
    {"unavailable": None}, {"persistence_unknown": "private"},
])
def test_malformed_per_invocation_counts_are_not_partially_rendered(changes):
    text = status_report.optional_audit_result_text(_result(**changes))
    assert "unavailable; counts unknown" in text and "attempted=" not in text
    assert "private" not in text


def test_per_invocation_result_copies_no_receipts_records_or_error_details():
    source = _result(private_error="private", proof_receipt={"response_authorized": True}, records=["private"])
    original = copy.deepcopy(source)
    text = status_report.optional_audit_result_text(source)
    assert "attempted=5" in text and "unavailable=1" in text and "persistence_unknown=1" in text
    assert "Native results and closure authority are separate" in text
    assert "private" not in text and "proof_receipt" not in text and source == original


@pytest.fixture
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    assert app is not None, "the session fixture owns QApplication"
    return app


def _retire_widget(widget):
    from PySide6.QtCore import QCoreApplication, QEvent
    from shiboken6 import isValid

    if isValid(widget):
        widget.close()
    if isValid(widget):
        widget.deleteLater()
        QCoreApplication.sendPostedEvents(widget, QEvent.Type.DeferredDelete)
    assert not isValid(widget)


@pytest.mark.parametrize("optional", [_result(), None, _result(attempted=True)])
def test_threat_window_summary_keeps_optional_audit_separate(qapp, monkeypatch, optional):
    from PySide6.QtWidgets import QMessageBox
    from angerona.gui.pages import ThreatWindow

    calls = []
    result = {"applied": 7, "skipped": 3, "failed": 2, "records": [{"private": "private"}]}
    if optional is not None:
        result["optional_audit"] = optional
    posture = SimpleNamespace(generate_remediation=_no_io, weaknesses=_no_io,
        apply_vetted_remediation=lambda **kwargs: calls.append(kwargs) or result)
    monkeypatch.setattr(ThreatWindow, "_refresh", lambda _self: None)
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_kw: QMessageBox.Yes)
    dialog = ThreatWindow(EventBus(), object(), SimpleNamespace(modules={"fixture": posture}))
    messages = []
    monkeypatch.setattr(dialog, "_run_async", lambda operation: messages.append(operation()))
    try:
        dialog._selected_mitre = "T1112"
        dialog._apply_fix()
        assert calls == [{"apply": True}]
        text = messages[0]
        assert "applied=7, skipped=3, failed=2" in text and "private" not in text
        if optional is not None and type(optional["attempted"]) is int:
            assert "Optional audit (this invocation): attempted=5" in text and "rejected=2" in text
        else:
            assert "Optional audit (this invocation): unavailable; counts unknown" in text
    finally:
        _retire_widget(dialog)


@pytest.mark.parametrize("optional", [_result(), None, _result(recorded=-1)])
def test_main_window_summary_keeps_optional_audit_separate(qapp, monkeypatch, tmp_path, optional):
    from PySide6.QtWidgets import QDialog
    from angerona.gui.main_window import MainWindow

    result = {"applied": 4, "skipped": 2, "failed": 1, "records": [{"private": "private"}]}
    if optional is not None:
        result["optional_audit"] = optional
    calls, messages, owned = [], [], []
    posture = SimpleNamespace(apply_vetted_remediation=lambda **kwargs: calls.append(kwargs) or result)

    class ReviewDialog(QDialog):
        def __init__(self, *_args, on_apply, **_kwargs):
            super().__init__()
            self.apply_callback = on_apply
            owned.append(self)

        def set_text(self, _text):
            pass

        def exec(self):
            messages.append(self.apply_callback())
            return QDialog.Accepted

    monkeypatch.setattr("angerona.gui.main_window.AARDialog", ReviewDialog)
    window = SimpleNamespace(manager=SimpleNamespace(modules={"Posture Hardening": posture}),
                             config=SimpleNamespace(data_dir=tmp_path), _qss=lambda: "")
    try:
        # The failed handoff avoids disk reads; only the inert apply callback
        # above runs. No MainWindow constructor, model or native action starts.
        MainWindow._show_aar_dialog(window, {"report_kind": "shark", "text": "fixture", "error": "fixture"})
        assert calls == [{"apply": True}]
        text = messages[0]
        assert "applied=4, skipped=2, failed=1" in text and "private" not in text
        if optional is not None and optional["recorded"] >= 0:
            assert "Optional audit (this invocation): attempted=5" in text and "rejected=2" in text
        else:
            assert "Optional audit (this invocation): unavailable; counts unknown" in text
    finally:
        for dialog in owned:
            _retire_widget(dialog)
