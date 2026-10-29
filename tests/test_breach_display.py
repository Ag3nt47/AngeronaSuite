"""Synthetic first-party breach projections exercise UI only, no response."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QVBoxLayout, QWidget

from angerona.core.breach_state import BreachActionAvailability, BreachDisplaySnapshot
from angerona.gui import breach_display as ui


@pytest.fixture
def bridge(monkeypatch):
    monkeypatch.setattr(ui, "motion_allowed", lambda config: config.ui_motion_enabled)
    window = QMainWindow()
    window.config = SimpleNamespace(ui_motion_enabled=True)
    window.manager = SimpleNamespace()
    window._last_posture = dict(score=86, label="Secure", color="#22c55e")
    window._last_posture_tooltip = "Composite posture fixture"
    body = QWidget()
    layout = QVBoxLayout(body)
    window.posture_lbl = QLabel("POSTURE 86 · Secure")
    layout.addWidget(window.posture_lbl)
    window.setCentralWidget(body)
    window.resize(800, 500)
    window.show()
    result = ui.BreachDisplayBridge(window)
    yield result
    result.shutdown()
    window.close()
    result.deleteLater()
    window.deleteLater()


def confirmed(**values):
    return replace(BreachDisplaySnapshot(active=True, state="breached", case_id="a" * 32, sequence=1,
                                         summary="Verified synthetic case", containment_state="held"), **values)


def test_external_dictionaries_and_malformed_typed_values_cannot_trigger_breach(bridge):
    assert not bridge.apply({"active": True, "state": "compromised", "case_id": "untrusted-report"})
    assert not bridge.apply(confirmed(active="yes"))
    assert not bridge.apply(confirmed(case_id=""))
    assert not bridge.apply(confirmed(actions=(BreachActionAvailability([], True),)))
    assert bridge.snapshot is None
    assert bridge.dialog is None
    assert bridge.window.posture_lbl.text() == "POSTURE 86 · Secure"


def test_typed_case_sets_exact_badge_slow_flash_and_click_transparent_outline(bridge):
    assert bridge.apply(confirmed(summary="<b>literal case</b>"))
    QApplication.processEvents()
    assert bridge.window.posture_lbl.text() == "⚠️Breached⚠️"
    assert "&lt;b&gt;literal case&lt;/b&gt;" in bridge.window.posture_lbl.toolTip()
    assert bridge.flash_timer.interval() == 1000
    assert bridge.flash_timer.isActive()
    outline = bridge._outlines[bridge.window]
    assert outline.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    assert outline.isVisible()
    assert "#ef4444" in bridge.window.posture_lbl.styleSheet()
    bridge._flash()
    assert "#fb923c" in bridge.window.posture_lbl.styleSheet()
    assert bridge.dialog is not None
    assert "Confirmed breach" in bridge.dialog.notice.text()


def test_reduced_motion_uses_solid_red_and_hidden_surfaces_stop_timers(bridge):
    bridge.window.config.ui_motion_enabled = False
    bridge.apply(confirmed())
    assert not bridge.flash_timer.isActive()
    assert "#ef4444" in bridge.window.posture_lbl.styleSheet()
    bridge.dialog.hide()
    bridge.window.hide()
    bridge._sync_visibility()
    assert not bridge.flash_timer.isActive()
    assert not bridge.poll_timer.isActive()


def test_stale_clear_is_rejected_and_lifting_lockdown_does_not_clear_breach(bridge):
    bridge.apply(confirmed(sequence=4))
    assert not bridge.apply(BreachDisplaySnapshot(sequence=3))
    assert bridge.active
    bridge.apply(confirmed(sequence=5, containment_state="operator-lifted"))
    assert bridge.active
    assert bridge.window.posture_lbl.text() == "⚠️Breached⚠️"
    bridge.apply(BreachDisplaySnapshot(state="resolved", sequence=6))
    assert not bridge.active
    assert bridge.window.posture_lbl.text() == "POSTURE 86 · Secure"
    assert not bridge.flash_timer.isActive()


def test_response_buttons_require_published_availability_and_a_real_queue(bridge):
    available = (BreachActionAvailability("lift_lockdown", True, "Restore only this case's owned rules"),)
    bridge.apply(confirmed(actions=available))
    assert not bridge.dialog.actions["lift_lockdown"].isEnabled()
    calls = []
    bridge.window.manager._breach_state_controller = SimpleNamespace(request_action=lambda *args: calls.append(args))
    bridge.apply(confirmed(sequence=2, actions=available))
    assert bridge.dialog.actions["lift_lockdown"].isEnabled()
    assert not bridge.dialog.actions["kill"].isEnabled()
    assert not calls


def test_action_confirmation_rechecks_current_case_before_queueing(bridge, monkeypatch):
    grant = BreachActionAvailability("lift_lockdown", True, "Restore only this case's owned rules")
    initial = confirmed(actions=(grant,))
    current = [initial]
    calls = []
    bridge.window.manager._breach_state_controller = SimpleNamespace(
        snapshot=lambda: current[0], request_action=lambda *args: calls.append(args) or True)
    bridge.apply(initial)

    def changed_case(*_args, **_kwargs):
        current[0] = confirmed(sequence=2, case_id="other-case", actions=(grant,))
        return ui.QMessageBox.StandardButton.Yes

    monkeypatch.setattr(ui.QMessageBox, "question", changed_case)
    bridge.dialog.actions["lift_lockdown"].click()
    assert not calls
    assert "availability changed" in bridge.dialog.notice.text()


def test_review_resolution_is_a_separate_explicit_action_from_lifting_lockdown(bridge, monkeypatch):
    grant = BreachActionAvailability("review_resolved", True, "Operator reviewed the case evidence")
    snapshot = confirmed(actions=(grant,), containment_state="lifted")
    calls = []
    bridge.window.manager._breach_state_controller = SimpleNamespace(
        snapshot=lambda: snapshot, request_action=lambda *args: calls.append(args) or True)
    bridge.apply(snapshot)
    assert bridge.active
    monkeypatch.setattr(ui.QMessageBox, "question", lambda *_args, **_kwargs: ui.QMessageBox.StandardButton.Yes)
    bridge.dialog.actions["review_resolved"].click()
    assert calls == [(snapshot.case_id, "review_resolved")]
    assert bridge.active  # A queued request is not a successful resolution.
    assert "queued" in bridge.dialog.notice.text()


def test_read_only_trace_and_live_report_refresh_hold_the_reader_position(bridge):
    details = tuple((f"record-{index}", "Review evidence " + "x" * 180) for index in range(60))
    bridge.apply(confirmed(details=details))
    dialog = bridge.dialog
    QApplication.processEvents()
    cursor = dialog.text.document().find("record-35")
    assert cursor.hasSelection()
    dialog.text.setTextCursor(cursor)
    bar = dialog.text.verticalScrollBar()
    assert bar.maximum() > 20
    bar.setValue(bar.maximum() // 2)
    position = bar.value()
    selected = dialog.text.textCursor().selectedText()
    bridge.apply(confirmed(sequence=2, details=details, containment_state="held"))
    assert dialog.text.verticalScrollBar().value() == position
    assert dialog.text.textCursor().selectedText() == selected
    dialog.show_trace()
    assert "does not contact a remote target" in dialog.text.toPlainText()


def test_shutdown_cannot_be_rearmed_by_a_late_projection(bridge):
    bridge.apply(confirmed())
    bridge.shutdown()
    assert not bridge.apply(confirmed(sequence=2))
    bridge.poll()
    assert not bridge.flash_timer.isActive()
    assert not bridge.poll_timer.isActive()


def test_hidden_window_keeps_only_memory_poll_and_notifies_once_for_new_case(bridge):
    current = [BreachDisplaySnapshot()]
    bridge.window.manager._breach_state_controller = SimpleNamespace(snapshot=lambda: current[0])
    bridge.window.hide()
    bridge.poll()
    assert bridge.poll_timer.isActive()
    assert not bridge.flash_timer.isActive()
    current[0] = confirmed()
    bridge.poll()
    first_dialog = bridge.dialog
    assert first_dialog is not None and first_dialog.isVisible()
    first_dialog.hide()
    bridge.poll()
    assert bridge.dialog is first_dialog and not first_dialog.isVisible()
    assert not bridge.flash_timer.isActive()


def test_popup_preference_preserves_confirmed_state_without_focus_spam(bridge):
    bridge.window.config.breach_alert_popup_enabled = False
    bridge.apply(confirmed())
    assert bridge.active
    assert bridge.dialog is None
    assert bridge.window.posture_lbl.text() == "⚠️Breached⚠️"
    assert bridge.open_report() is not None  # Explicit review is still available.


def test_latched_case_guards_real_threat_card_footer_and_latest_normal_restore(bridge):
    from angerona.gui.dashboard_footer import DashboardFooter
    from angerona.gui.main_window import MainWindow
    from angerona.gui.pages import DashboardCards

    window = bridge.window
    window._breach_view = bridge
    window.cards = DashboardCards(SimpleNamespace(), None, None)
    window.cards._count_reader.close()
    window.cards._threat_reader.close()
    refreshes = []
    window.cards._threat_reader = SimpleNamespace(request=lambda: refreshes.append("threat"), close=lambda: None)
    window._posture_reader = SimpleNamespace(request=lambda: refreshes.append("posture"))
    window._dashboard_footer = DashboardFooter()
    window.centralWidget().layout().addWidget(window.cards)
    window.centralWidget().layout().addWidget(window._dashboard_footer)
    first = dict(score=86, label="Secure", color="#22c55e")
    MainWindow._apply_posture_snapshot(window, (first, "Initial engine score"))
    window.cards._apply_threat_snapshot((0, ("Secure", "#22c55e")))
    bridge.apply(confirmed())
    assert window.cards.c_threat.value.text() == "Compromised"
    assert window.cards.c_crit.value.text() == "0"  # The ten-minute count is not fabricated.
    assert "10 minutes" in window.cards.c_crit.toolTip()
    assert "COMPROMISED" in window._dashboard_footer._display_cells()[-1]
    assert "a" * 32 in window._dashboard_footer.accessibleName()
    assert "containment: held" in bridge.dialog.notice.text()

    # Several independent normal refreshes must not erase a latched case.
    latest = dict(score=59, label="Critical", color="#fb923c")
    for normal in (first, latest):
        MainWindow._apply_posture_snapshot(window, (normal, "Latest engine score"))
        window.cards._apply_threat_snapshot((2, ("High", "#fb923c")))
        window.cards._set_threat_reader_status("current")
        assert window.cards.c_threat.value.text() == "Compromised"
        assert "Confirmed case" in window.cards.c_threat.toolTip()
        assert "COMPROMISED" in window._dashboard_footer._display_cells()[-1]
        assert window.posture_lbl.text() == "⚠️Breached⚠️"
    assert window._last_posture == latest
    assert window.cards.c_crit.value.text() == "2"

    bridge.apply(confirmed(sequence=2, containment_state="lifted"))
    assert window.cards.c_threat.value.text() == "Compromised"
    assert "lifted" in window._dashboard_footer._display_cells()[-1]
    assert "containment: lifted" in bridge.dialog.notice.text()
    bridge.dialog.hide()
    window.cards.c_threat.clicked.emit()
    assert bridge.dialog.isVisible()  # The critical tile opens this exact live case.

    bridge.apply(BreachDisplaySnapshot(state="resolved", sequence=3))
    assert window.cards.c_threat.value.text() == "High"
    assert window.cards.c_crit.value.text() == "2"
    assert "Posture 59 · Critical" in window._dashboard_footer._display_cells()[-1]
    assert window.posture_lbl.text() == "POSTURE 59 · Critical"
    assert refreshes == ["threat", "posture"]  # Refresh current normal data on review clear.


def test_plain_report_cannot_override_card_or_footer_incident_state():
    from angerona.gui.dashboard_footer import DashboardFooter
    from angerona.gui.pages import DashboardCards

    cards = DashboardCards(SimpleNamespace(), None, None)
    footer = DashboardFooter()
    try:
        cards._apply_threat_snapshot((0, ("Secure", "#22c55e")))
        footer.update_posture(dict(score=86, label="Secure", color="#22c55e"))
        cards.set_breach_override({"active": True, "case_id": "untrusted"})
        footer.set_breach_override({"active": True, "case_id": "untrusted"})
        assert cards.c_threat.value.text() == "Secure"
        assert "Posture 86 · Secure" in footer._display_cells()[-1]
    finally:
        cards.close()
        footer.close()
        cards.deleteLater()
        footer.deleteLater()


def test_review_clear_before_first_normal_snapshot_shows_updating_not_stale_compromise():
    from angerona.gui.pages import DashboardCards
    cards = DashboardCards(SimpleNamespace(), None, None)
    cards._threat_reader.close()
    cards._threat_reader = SimpleNamespace(request=lambda: None, close=lambda: None)
    try:
        cards.set_breach_override(confirmed())
        assert cards.c_threat.value.text() == "Compromised"
        cards.set_breach_override(BreachDisplaySnapshot(state="resolved", sequence=2))
        assert cards.c_threat.value.text() == "Updating…"
        assert "Updating threat assessment" in cards.c_threat.toolTip()
        cards._apply_threat_snapshot((0, ("Secure", "#22c55e")))
        assert cards.c_threat.value.text() == "Secure"
    finally:
        cards.close()
        cards.deleteLater()
