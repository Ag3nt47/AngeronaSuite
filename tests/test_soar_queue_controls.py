from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.gui import pages


_QAPP: QApplication | None = None


def _app() -> QApplication:
    # Keep one Python owner alive for the entire pytest process. Destroying and
    # recreating QApplication between Qt test modules can abort on Windows.
    global _QAPP
    _QAPP = QApplication.instance() or QApplication([])
    return _QAPP


class _FakeProcess:
    pid = 424242
    create_stamp = 1234.5
    suspend_calls = 0
    resume_calls = 0

    def __init__(self, pid: int) -> None:
        if pid != self.pid:
            raise RuntimeError("unknown process")

    def oneshot(self):
        return contextlib.nullcontext()

    def create_time(self) -> float:
        return self.create_stamp

    def name(self) -> str:
        return "malware-probe.exe"

    def exe(self) -> str:
        return r"C:\Temp\malware-probe.exe"

    def suspend(self) -> None:
        type(self).suspend_calls += 1

    def resume(self) -> None:
        type(self).resume_calls += 1


class _FakeSoar:
    status = "running"

    @staticmethod
    def _is_protected_process(_pid: int) -> bool:
        return False


class _Manager:
    modules = {"SOAR Automation": _FakeSoar()}


def _install_fake_process(monkeypatch) -> None:
    _FakeProcess.suspend_calls = 0
    _FakeProcess.resume_calls = 0
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(Process=_FakeProcess))


def _active_event() -> Event:
    return Event(
        module="Behavior Detector",
        message="active malicious process",
        severity=Severity.CRITICAL,
        ts=time.time(),
        details={
            "pid": _FakeProcess.pid,
            "name": "malware-probe.exe",
            "exe": r"C:\Temp\malware-probe.exe",
            "active_attack": True,
        },
    )


def test_queue_record_transitions_are_atomic_and_visible_to_cached_reader(
    monkeypatch,
):
    _install_fake_process(monkeypatch)
    event = _active_event()

    assert pages._persist_soar_queue(event)
    records = pages._read_soar_queue()
    assert len(records) == 1
    record = records[0]
    assert record["status"] == pages._SOAR_PENDING
    assert record["action"]["kind"] == "suspend_process"
    assert record["action"]["create_time"] == _FakeProcess.create_stamp

    assert pages._update_soar_queue_record(
        pages._soar_record_id(record),
        status=pages._SOAR_APPROVED,
        approved_at=99.0,
    )
    updated = pages._read_soar_queue()[0]
    assert updated["status"] == pages._SOAR_APPROVED
    assert updated["approved_at"] == 99.0


def test_soar_large_history_uses_bounded_tail_and_state_overlay(
    monkeypatch, tmp_path,
):
    path = tmp_path / "soar_queue.json"
    state_path = tmp_path / "soar_queue_state.json"
    monkeypatch.setattr(pages, "_soar_queue_path", lambda: path)
    monkeypatch.setattr(pages, "_soar_queue_state_path", lambda: state_path)
    pages._invalidate_soar_queue_cache()
    with path.open("w", encoding="utf-8") as handle:
        for index in range(10_000):
            handle.write(json.dumps({
                "request_id": f"{index:032x}",
                "ts": index,
                "status": pages._SOAR_PENDING,
            }) + "\n")

    original_read_text = pages.Path.read_text

    def refuse_full_queue_read(self, *args, **kwargs):
        if self == path:
            raise AssertionError("SOAR JSONL must not be read wholesale")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(pages.Path, "read_text", refuse_full_queue_read)
    newest = f"{9_999:032x}"

    assert len(pages._read_soar_queue(limit=25)) == 25
    assert pages._update_soar_queue_record(
        newest, status=pages._SOAR_APPROVED, approved_at=1.0
    )
    assert pages._read_soar_queue(limit=1)[0]["status"] == pages._SOAR_APPROVED


def test_response_execution_rebinds_to_live_event_and_rejects_tampering(
    monkeypatch,
):
    _install_fake_process(monkeypatch)
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    event = _active_event()
    bus.publish(event)
    record = pages._new_soar_queue_record(bus.recent(1)[0])

    tampered = dict(record)
    tampered["origin_message_sha256"] = "0" * 64
    with pytest.raises(PermissionError, match="no longer in the live evidence ring"):
        pages._execute_approved_soar_record(tampered, bus, _Manager())
    assert _FakeProcess.suspend_calls == 0

    retargeted = dict(record)
    retargeted["action"] = dict(record["action"], pid=_FakeProcess.pid + 1)
    with pytest.raises(PermissionError, match="does not match the signed origin"):
        pages._execute_approved_soar_record(retargeted, bus, _Manager())
    assert _FakeProcess.suspend_calls == 0

    result = pages._execute_approved_soar_record(record, bus, _Manager())
    assert "Suspended malware-probe.exe" in result
    assert _FakeProcess.suspend_calls == 1
    assert bus.recent(1)[0].details["action_succeeded"] is True

    with pytest.raises(PermissionError, match="already executed"):
        pages._execute_approved_soar_record(record, bus, _Manager())
    assert _FakeProcess.suspend_calls == 1


def test_authenticated_bus_refuses_queue_record_without_origin_hmac(monkeypatch):
    _install_fake_process(monkeypatch)
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    event = _active_event()
    bus.publish(event)
    record = pages._new_soar_queue_record(bus.recent(1)[0])
    record["origin_hmac"] = ""

    with pytest.raises(PermissionError, match="origin HMAC"):
        pages._execute_approved_soar_record(record, bus, _Manager())
    assert _FakeProcess.suspend_calls == 0


def test_live_alert_block_directly_contains_without_soar_navigation(
    monkeypatch,
):
    _install_fake_process(monkeypatch)
    monkeypatch.setattr(QMessageBox, "exec", lambda _self: QMessageBox.Ok)
    app = _app()
    bus = EventBus()
    event = _active_event()
    bus.publish(event)
    window = QMainWindow()
    window.manager = _Manager()
    panel = pages.AlertsPanel(SimpleNamespace(), bus=bus)
    window.setCentralWidget(panel)

    try:
        assert panel._block_event(bus.recent(1)[0]) is True
        assert _FakeProcess.suspend_calls == 1
        record = pages._read_soar_queue()[0]
        assert record["status"] == pages._SOAR_EXECUTED
        assert "resume" in record["execution_result"]
    finally:
        window.close()
        app.processEvents()


def test_soar_queue_requires_live_session_approval_and_can_dismiss(
    monkeypatch,
):
    _install_fake_process(monkeypatch)
    monkeypatch.setattr(
        QMessageBox, "question", lambda *_args, **_kwargs: QMessageBox.Yes
    )
    app = _app()
    bus = EventBus()
    event = _active_event()
    bus.publish(event)
    assert pages._persist_soar_queue(event)
    panel = pages.SoarPanel(bus, _Manager())
    panel.refresh()
    panel.table.selectRow(0)
    app.processEvents()

    try:
        request_id = panel._selected_request_id()
        assert request_id
        assert panel._btn_approve.isEnabled()
        assert not panel._btn_execute.isEnabled()

        panel._approve_selected()
        assert request_id in panel._approved_requests
        assert panel._btn_execute.isEnabled()
        assert pages._read_soar_queue()[0]["status"] == pages._SOAR_APPROVED

        panel._dismiss_selected()
        assert request_id not in panel._approved_requests
        assert pages._read_soar_queue()[0]["status"] == pages._SOAR_DISMISSED
        assert _FakeProcess.suspend_calls == 0
    finally:
        panel.close()
        panel.deleteLater()
        app.processEvents()


def test_soar_queue_execute_revalidates_and_records_success(monkeypatch):
    _install_fake_process(monkeypatch)
    monkeypatch.setattr(
        QMessageBox, "question", lambda *_args, **_kwargs: QMessageBox.Yes
    )
    app = _app()
    bus = EventBus()
    event = _active_event()
    bus.publish(event)
    assert pages._persist_soar_queue(event)
    panel = pages.SoarPanel(bus, _Manager())
    panel.refresh()
    panel.table.selectRow(0)
    app.processEvents()

    try:
        panel._approve_selected()
        assert panel._btn_execute.isEnabled()
        panel._execute_selected()

        assert _FakeProcess.suspend_calls == 1
        record = pages._read_soar_queue()[0]
        assert record["status"] == pages._SOAR_EXECUTED
        assert "resume" in record["execution_result"]
        assert not panel._btn_execute.isEnabled()
    finally:
        panel.close()
        panel.deleteLater()
        app.processEvents()


def test_soar_session_approval_is_bound_to_canonical_request_digest(monkeypatch):
    _install_fake_process(monkeypatch)
    monkeypatch.setattr(
        QMessageBox, "question", lambda *_args, **_kwargs: QMessageBox.Yes
    )
    app = _app()
    bus = EventBus()
    event = _active_event()
    bus.publish(event)
    assert pages._persist_soar_queue(event)
    panel = pages.SoarPanel(bus, _Manager())
    panel.refresh()
    panel.table.selectRow(0)
    app.processEvents()

    try:
        panel._approve_selected()
        request_id = panel._selected_request_id()
        assert request_id in panel._approved_requests

        path = pages._soar_queue_path()
        record = pages._read_soar_queue()[0]
        record["action"] = dict(record["action"], pid=_FakeProcess.pid + 1)
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        pages._invalidate_soar_queue_cache()

        panel._execute_selected()

        assert _FakeProcess.suspend_calls == 0
        assert request_id not in panel._approved_requests
        assert "changed" in panel._status.text().casefold()
    finally:
        panel.close()
        panel.deleteLater()
        app.processEvents()
