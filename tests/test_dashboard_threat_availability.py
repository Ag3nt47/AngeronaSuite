"""Inert Qt assessment availability; no host response or policy operations."""
from __future__ import annotations

import os
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QElapsedTimer, QEvent
from PySide6.QtGui import QFontMetrics
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.core.breach_state import BreachDisplaySnapshot
from angerona.gui import main_window, pages
from angerona.gui.header_controls import CurrentAssessmentBanner
from angerona.gui.main_window import MainWindow


@pytest.fixture(autouse=True)
def forbid_host_dispatch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Assessment presentation cannot dispatch host work")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def wait_until(predicate):
    elapsed = QElapsedTimer()
    elapsed.start()
    while not predicate() and elapsed.elapsed() < 3000:
        QTest.qWait(5)
    assert predicate()


class ReaderProbe:
    def __init__(self):
        self.snapshot = (0, ("Secure", "#22c55e"))
        self.fail = False
        self.gate = None
        self.entered = threading.Event()
        self.calls = []
        self.gates = []

    def prepare(self):
        snapshot, fail, gate = self.snapshot, self.fail, self.gate
        if gate is not None:
            self.gates.append(gate)

        def read():
            self.calls.append(threading.get_ident())
            self.entered.set()
            if gate is not None:
                assert gate.wait(3), "Test-owned reader was not released"
            if fail:
                raise RuntimeError("Inert unavailable assessment")
            return snapshot

        return read


@pytest.fixture
def owned_cards(monkeypatch):
    assert QApplication.instance() is not None
    cards = pages.DashboardCards(SimpleNamespace(), None, None)
    probe = ReaderProbe()
    monkeypatch.setattr(cards._threat_reader, "_prepare", probe.prepare)
    try:
        yield cards, probe
    finally:
        for gate in probe.gates:
            gate.set()
        for reader in (cards._threat_reader, cards._count_reader):
            reader.close()
            if reader.thread is not None:
                reader.thread.join(3)
                assert not reader.thread.is_alive()
        cards.close()
        cards.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not isValid(cards)


def confirmed():
    return BreachDisplaySnapshot(active=True, state="breached", case_id="a" * 32,
                                 sequence=1, containment_state="held")


@pytest.mark.parametrize("snapshot,visible", [
    ((0, ("Secure", "#22c55e")), "None detected"),
    ((0, ("High", "#f97316")), "High"),
    ((2, ("Critical", "#ef4444")), "Critical"),
])
def test_fresh_display_qualifies_scope_without_changing_core_result(owned_cards, snapshot, visible):
    cards, _probe = owned_cards
    cards._apply_threat_snapshot(snapshot)
    assert cards._normal_threat_snapshot is snapshot
    assert cards.c_threat.value.text() == visible
    assert cards.c_threat._caption.text() == "Active HIGH/CRITICAL (10m)"
    assert cards.c_threat.accessibleName() == "Active HIGH/CRITICAL (10m)"
    assert "collection gaps" in cards.c_threat.toolTip()
    assert cards.c_crit.value.text() == str(snapshot[0])


@pytest.mark.parametrize("snapshot,visible,count", [
    (None, "Unavailable", "—"),
    ((0, ("Secure", "#22c55e")), "Unavailable", "—"),
    ((0, ("High", "#f97316")), "High · stale", "0 · stale"),
    ((2, ("Critical", "#ef4444")), "Critical · stale", "2 · stale"),
])
def test_failure_and_status_callbacks_cannot_revalidate_retained_data(owned_cards, snapshot, visible, count):
    cards, _probe = owned_cards
    if snapshot is not None:
        cards._apply_threat_snapshot(snapshot)
    cards._set_threat_reader_status("unavailable")
    for state in ("updating", "current", "updating"):
        cards._set_threat_reader_status(state)
        assert cards.c_threat.value.text() == visible
        assert cards.c_crit.value.text() == count
        assert "unavailable" in cards.c_threat.toolTip()
        assert cards._normal_threat_snapshot is snapshot
    expected_color = snapshot[1][1] if snapshot is not None and snapshot[1][0] != "Secure" else "#fbbf24"
    assert expected_color in cards.c_threat.value.styleSheet()
    cards._apply_threat_snapshot((0, ("Secure", "#22c55e")))
    assert cards.c_threat.value.text() == "None detected"
    assert cards.c_crit.value.text() == "0"
    assert not cards._normal_threat_failed


def test_actual_async_failure_stays_unknown_during_blocked_retry_until_success(owned_cards):
    cards, probe = owned_cards
    cards._apply_threat_snapshot(probe.snapshot)
    probe.fail = True
    cards._threat_reader.request()
    wait_until(lambda: not cards._threat_reader.busy)
    assert cards.c_threat.value.text() == "Unavailable"
    assert cards.c_crit.value.text() == "—"
    probe.fail = False
    probe.gate = threading.Event()
    probe.entered.clear()
    cards._threat_reader.request()
    assert probe.entered.wait(1)
    QTest.qWait(50)
    assert cards._threat_reader.busy
    assert cards.c_threat.value.text() == "Unavailable"
    assert cards.c_crit.value.text() == "—"
    probe.gate.set()
    wait_until(lambda: not cards._threat_reader.busy)
    assert cards.c_threat.value.text() == "None detected"
    assert cards.c_crit.value.text() == "0"
    assert len(probe.calls) == 2
    assert all(ident != threading.get_ident() for ident in probe.calls)


def test_failed_assessment_cannot_erase_breach_or_revive_green_after_case_clear(owned_cards):
    cards, probe = owned_cards
    cards._apply_threat_snapshot(probe.snapshot)
    cards.set_breach_override(confirmed())
    probe.fail = True
    cards._threat_reader.request()
    wait_until(lambda: not cards._threat_reader.busy)
    assert cards.c_threat.value.text() == "Compromised"
    assert "#ef4444" in cards.c_threat.value.styleSheet()
    assert "Confirmed case" in cards.c_threat.toolTip()
    assert cards.c_crit.value.text() == "—"
    probe.fail = False
    probe.gate = threading.Event()
    probe.entered.clear()
    cards.set_breach_override(BreachDisplaySnapshot(state="resolved", sequence=2))
    assert probe.entered.wait(1)
    assert cards.c_threat.value.text() == "Unavailable"
    assert cards.c_crit.value.text() == "—"
    probe.gate.set()
    wait_until(lambda: not cards._threat_reader.busy)
    assert cards.c_threat.value.text() == "None detected"
    assert cards.c_crit.value.text() == "0"


@pytest.mark.parametrize("label,color", [("High", "#f97316"), ("Critical", "#ef4444")])
def test_stale_warning_remains_in_collapsed_caption_and_fits_compact_card(owned_cards, label, color):
    cards, _probe = owned_cards
    cards._apply_threat_snapshot((1, (label, color)))
    cards._set_threat_reader_status("unavailable")
    card = cards.c_threat
    card.setFixedWidth(220)
    cards.show()
    QApplication.processEvents()
    font = card.value._display_font()
    assert QFontMetrics(font).horizontalAdvance(card.value.text()) <= card.value.contentsRect().width()
    card._minimize_button.click()
    QApplication.processEvents()
    assert card.is_collapsed()
    assert f"{label} · stale" in card._caption.text()
    assert card.accessibleName() == "Active HIGH/CRITICAL (10m)"
    card._minimize_button.click()
    QApplication.processEvents()
    assert not card.is_collapsed()
    assert card.value.text() == f"{label} · stale"
    assert color in card.value.styleSheet()


def test_threat_window_reports_active_scope_instead_of_broad_secure_label(monkeypatch):
    monkeypatch.setattr(pages.ThreatWindow, "_refresh", lambda _self: None)
    dialog = pages.ThreatWindow(SimpleNamespace(), object(), SimpleNamespace(modules={}))
    try:
        dialog._apply_threat_snapshot(([], ("Secure", "#22c55e")))
        assert dialog._threat_snapshot == []
        assert "Active HIGH/CRITICAL (10m): None detected" in dialog.status_lbl.text()
        assert "Secure" not in dialog.status_lbl.text()
        assert "No active HIGH/CRITICAL" in dialog.detail.toPlainText()
    finally:
        dialog.close()
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not isValid(dialog)


class AssessmentHarness:
    _ASSESSMENT_DWELL_SECONDS = MainWindow._ASSESSMENT_DWELL_SECONDS
    _ASSESSMENT_FRESH_SECONDS = MainWindow._ASSESSMENT_FRESH_SECONDS
    _current_assessment_rows = MainWindow._current_assessment_rows
    _refresh_current_assessment = MainWindow._refresh_current_assessment
    _open_current_assessment = MainWindow._open_current_assessment

    def __init__(self):
        self.calls = []
        self.config = SimpleNamespace(ui_motion_enabled=True)
        self._termination_started = False
        self._eco_on = True
        self._assessment_banner = CurrentAssessmentBanner()
        self._assessment_key = "updating"
        self._assessment_keys = ()
        self._assessment_since = 0.0
        self._assessment_threat = None
        self._assessment_threat_at = 0.0
        self._assessment_coverage = (1, 2)
        self._breach_view = SimpleNamespace(active=False)
        self._notifications = SimpleNamespace(
            _entries={"storage:recovery": None, "setup": None}, count=2,
            show=lambda: self.calls.append("inbox"),
        )
        self.cards = SimpleNamespace(
            _normal_threat_snapshot=(0, ("Secure", "#22c55e")),
            _normal_threat_status="current", _normal_threat_failed=False,
            _open_modules=lambda: self.calls.append("coverage"),
            _open_threat=lambda: self.calls.append("threat"),
        )

    def _on_posture_click(self):
        self.calls.append("case")

    def _show_settings(self, tab):
        self.calls.append(tab)

    def isVisible(self):
        return True

    def isMinimized(self):
        return False


@pytest.fixture
def assessment():
    owner = AssessmentHarness()
    try:
        yield owner
    finally:
        owner._assessment_banner.close()
        owner._assessment_banner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not isValid(owner._assessment_banner)


def test_current_assessment_rotates_cached_review_routes(assessment, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(main_window, "time", SimpleNamespace(monotonic=lambda: now[0]))
    banner = assessment._assessment_banner
    height = banner.sizeHint().height()
    for at, key, route in ((0, "coverage", "coverage"), (10, "storage", "System"),
                           (20, "inbox", "inbox"), (30, "mode", "System")):
        now[0] = at
        assessment._refresh_current_assessment()
        assert assessment._assessment_key == key
        assert banner.minimumSizeHint().width() == 0
        assert banner.sizeHint().height() == height
        assert banner.accessibleName() == "Current assessment"
        assessment._open_current_assessment()
        assert assessment.calls[-1] == route
    assessment.config.ui_motion_enabled = False
    now[0] = 50
    assessment._refresh_current_assessment()
    assert assessment._assessment_key == "mode"


def test_current_assessment_keeps_confirmed_case_and_revalidates_click(assessment, monkeypatch):
    monkeypatch.setattr(main_window, "time", SimpleNamespace(monotonic=lambda: 10.0))
    assessment._refresh_current_assessment(now=0)
    assert assessment._assessment_key == "coverage"
    assessment._breach_view.active = True
    assessment._open_current_assessment()
    assert assessment.calls == []
    assert assessment._assessment_key == "case"
    assessment._open_current_assessment()
    assert assessment.calls == ["case"]
    assessment._refresh_current_assessment(now=300)
    assert assessment._assessment_key == "case"
    assert "#ef4444" in assessment._assessment_banner.styleSheet()


def test_current_assessment_does_not_promote_failed_or_expired_threat_data(assessment):
    cards = assessment.cards
    cards._normal_threat_snapshot = (1, ("Critical", "#ef4444"))
    assessment._refresh_current_assessment(now=0)
    assert assessment._assessment_key == "critical"
    cards._normal_threat_failed = True
    assessment._refresh_current_assessment(now=1)
    assert assessment._assessment_key == "unavailable"
    assert "active critical" not in assessment._assessment_banner.text()
    cards._normal_threat_failed = False
    cards._normal_threat_snapshot = (0, ("High", "#f97316"))
    assessment._refresh_current_assessment(now=2)
    assert assessment._assessment_key == "high"
    assessment._refresh_current_assessment(now=153)
    assert assessment._assessment_key == "unavailable"
