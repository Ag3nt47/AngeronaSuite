from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

from angerona.gui import resolve_center


@pytest.fixture(scope="module", autouse=True)
def app():
    return QApplication.instance() or QApplication([])


def _subject(events=()):
    refreshed = []
    status = QLabel()
    status.setTextFormat(Qt.TextFormat.PlainText)
    subject = SimpleNamespace(_status=status, _events=lambda: list(events),
                              _invalidate_snapshot=lambda: refreshed.append(True))
    return subject, refreshed


def test_single_ack_failure_preserves_active_view_and_explains_hold(monkeypatch):
    subject, refreshed = _subject()

    def refused(*_args):
        raise ValueError("Exact record authentication unavailable")

    monkeypatch.setattr(resolve_center.alert_ack, "ack", refused)
    resolve_center.ResolveCenter._ignore(subject, object())
    assert refreshed == []
    assert "held" in subject._status.text().lower()
    assert "remains active" in subject._status.text()
    assert "Exact record authentication unavailable" in subject._status.text()


def test_successful_single_ack_reports_exact_record_and_expiry(monkeypatch):
    event = object()
    calls = []
    subject, refreshed = _subject()
    monkeypatch.setattr(resolve_center.alert_ack, "ack", lambda value, _reason: calls.append(value))
    resolve_center.ResolveCenter._ignore(subject, event)
    assert calls == [event] and refreshed == [True]
    assert "exact record for one hour" in subject._status.text()
    assert "New detections and changed evidence remain active" in subject._status.text()


def test_bulk_ack_reports_partial_success_and_keeps_failed_records_active(monkeypatch):
    events = ["first", "held", "first"]
    subject, refreshed = _subject(events)
    confirmations, calls = [], []

    def confirm(*args):
        confirmations.append(args)
        return QMessageBox.StandardButton.Yes

    def acknowledge(event, _reason):
        calls.append(event)
        if event == "held":
            raise ValueError("Evidence expired")

    monkeypatch.setattr(QMessageBox, "question", confirm)
    monkeypatch.setattr(resolve_center.alert_ack, "signature", lambda event: event)
    monkeypatch.setattr(resolve_center.alert_ack, "ack", acknowledge)
    resolve_center.ResolveCenter._ignore_all_shown(subject)
    assert calls == ["first", "held"]
    assert refreshed == [True]
    assert "1 exact record(s) for one hour; 1 held" in subject._status.text()
    assert "Held records remain active" in subject._status.text()
    assert "Evidence expired" in subject._status.text()
    assert "one hour" in confirmations[0][2]
    assert "each class" not in confirmations[0][2]
    assert "New detections and changed evidence remain active" in confirmations[0][2]
    assert confirmations[0][-1] == QMessageBox.StandardButton.No


def test_bulk_cancel_or_total_failure_never_claims_success(monkeypatch):
    subject, refreshed = _subject(["inert"])
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.StandardButton.No)
    monkeypatch.setattr(resolve_center.alert_ack, "ack", lambda *_args: pytest.fail("Cancelled acknowledgement ran"))
    resolve_center.ResolveCenter._ignore_all_shown(subject)
    assert refreshed == []
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.StandardButton.Yes)

    def unavailable(_event):
        raise ValueError("Record cannot be authenticated")

    monkeypatch.setattr(resolve_center.alert_ack, "signature", unavailable)
    resolve_center.ResolveCenter._ignore_all_shown(subject)
    assert refreshed == []
    assert "0 exact record(s) for one hour; 1 held" in subject._status.text()


def test_unack_failure_keeps_review_open_and_surfaces_error(monkeypatch):
    subject, refreshed = _subject()
    accepted = []
    dialog = SimpleNamespace(accept=lambda: accepted.append(True))

    def refused(_signature):
        raise ValueError("Acknowledgement store unavailable")

    monkeypatch.setattr(resolve_center.alert_ack, "unack", refused)
    resolve_center.ResolveCenter._unignore(subject, "inert-signature", dialog)
    assert accepted == refreshed == []
    assert "restore held" in subject._status.text()
    assert "store unavailable" in subject._status.text()
