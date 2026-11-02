"""Inert geometry and literal evidence checks; no native broker is admitted."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QPoint
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QGroupBox, QLabel, QPlainTextEdit, QPushButton, QWidget

from angerona.core.host_adaptation import PROFILES
from angerona.gui.adaptation_workbench import AdaptationWorkbench, _AdaptiveRow


def _app():
    return QApplication.instance() or QApplication([])


def _pump(count=18):
    app = _app()
    for _index in range(count):
        app.processEvents()


def _workbench(monkeypatch):
    _app()
    monkeypatch.setattr(AdaptationWorkbench, "_load_persisted_views", lambda self: None)
    monkeypatch.setattr(AdaptationWorkbench, "_refresh_status", lambda self: None)
    monkeypatch.setattr("angerona.gui.recovery_panel.RecoveryPanel", lambda *_args: QWidget())
    monkeypatch.setattr("angerona.gui.prevention_panel.PreventionPanel", lambda *_args: QWidget())
    service = SimpleNamespace(profiles=lambda: tuple(PROFILES.values()), state=lambda: {})
    return AdaptationWorkbench(service)


def _assert_rows_fit(dialog, *, minimum_rows=1):
    rows = dialog.findChildren(_AdaptiveRow)
    assert len(rows) >= minimum_rows
    for row in rows:
        if not row.isVisibleTo(dialog):
            continue
        row._reflow()
        _pump(2)
        available = row._budget()
        assert available > 200, row.objectName()
        assert row.width() <= available + 2, (row.objectName(), row.width(), available)
        rect = row.contentsRect()
        for control in row._widgets:
            assert control.geometry().left() >= rect.left(), row.objectName()
            assert control.geometry().right() <= rect.right() + 1, row.objectName()
            if isinstance(control, QPushButton):
                full = row._captions[control]
                assert control.accessibleName() == full
                assert control.toolTip()
                assert control.text(), (row.objectName(), full)


def _assert_page_controls_fit(page, viewport):
    for control in page.findChildren(QWidget):
        if not isinstance(control, (QLabel, QPushButton, QComboBox, QCheckBox, QGroupBox)):
            continue
        if not control.isVisibleTo(page) or control.window() is not page.window():
            continue
        ancestor = control.parentWidget()
        while ancestor is not None and ancestor is not page:
            if isinstance(ancestor, QAbstractItemView):
                break  # Tables retain their own horizontal evidence scrolling.
            ancestor = ancestor.parentWidget()
        if ancestor is not page:
            continue
        left = control.mapTo(viewport, QPoint(0, 0)).x()
        assert left >= 0 and left + control.width() <= viewport.width() + 1, (
            type(control).__name__, control.objectName(), left, control.width(), viewport.width(),
        )
        if isinstance(control, QGroupBox):
            assert control.fontMetrics().horizontalAdvance(control.title()) + 12 <= control.width(), control.title()


@pytest.mark.parametrize("width", [360, 480, 960])
@pytest.mark.parametrize("scale", [1.0, 1.35])
def test_adaptation_rows_fit_parent_viewport_with_large_font(monkeypatch, width, scale):
    dialog = _workbench(monkeypatch)
    font = QFont(dialog.font())
    font.setPointSizeF(font.pointSizeF() * scale)
    dialog.setFont(font)
    dialog.resize(width, 700)
    dialog.show()
    try:
        _pump()
        assert dialog.width() == width
        assert dialog._workbench_scroll.widget().width() <= dialog._workbench_scroll.viewport().width() + 1
        for index in range(7):
            dialog.tabs.setCurrentIndex(index)
            _pump()
            surface = dialog.tabs.widget(index)
            assert surface.widget().width() <= surface.viewport().width() + 1, index
            _assert_page_controls_fit(surface.widget(), surface.viewport())
            _assert_rows_fit(dialog, minimum_rows=12)
    finally:
        dialog.close()
        _pump()


def test_adaptation_row_restores_captions_and_existing_actions_after_shrink(monkeypatch):
    dialog = _workbench(monkeypatch)
    clicked = []
    dialog.apply_button.clicked.connect(lambda: clicked.append(True))
    # Do not admit the existing apply slot; this test checks presentation and
    # retained identity, while the separate exact-plan tests check admission.
    dialog.apply_button.clicked.disconnect(dialog._apply_profile)
    original_button = dialog.apply_button
    try:
        dialog.resize(1200, 720)
        dialog.show()
        dialog.tabs.setCurrentIndex(dialog.adapt_tab_index)
        _pump()
        for width in (360, 480, 1200, 360, 1200):
            dialog.resize(width, 720)
            _pump()
            assert dialog.apply_button is original_button
            _assert_rows_fit(dialog, minimum_rows=12)
        row = dialog.findChild(_AdaptiveRow, "adaptation_apply_actions")
        assert dialog.apply_button.text() == row._captions[dialog.apply_button]
        dialog.apply_button.setEnabled(True)
        dialog.apply_button.click()
        assert clicked == [True]
    finally:
        dialog.close()
        _pump()


def test_adaptation_inline_change_details_keep_full_literal_evidence(monkeypatch):
    dialog = _workbench(monkeypatch)
    literal = '<not-markup> C:\\long\\path\\' + "subdirectory\\" * 30 + "evidence\nsecond line 🛡"
    effect = {"profile": "Public", "before": {"outbound": "Allow"},
              "after": {"outbound": "Block"}, "changed": True,
              "reason": literal, "reversibility": "Exact full-policy snapshot",
              "verification": "Projected only"}
    try:
        dialog.resize(360, 700)
        dialog.show()
        dialog.tabs.setCurrentIndex(dialog.adapt_tab_index)
        dialog._display_effects([effect])
        dialog.change_table.selectRow(0)
        _pump()
        assert json.loads(dialog.change_details.toPlainText()) == effect
        assert literal in json.loads(dialog.change_details.toPlainText())["reason"]
        assert dialog.change_details.isReadOnly()
        updated = {**effect, "verification": "Fresh firewall postconditions verified"}
        dialog._display_effects([updated], applied=True)
        _pump()
        assert json.loads(dialog.change_details.toPlainText()) == updated
        dialog._profile_changed()
        assert dialog.change_details.toPlainText() == ""
    finally:
        dialog.close()
        _pump()


def test_adaptation_intent_and_copyable_details_remain_modeless_and_fit(monkeypatch):
    dialog = _workbench(monkeypatch)
    operations = []
    monkeypatch.setattr(dialog, "_prepare_review", lambda *args, **kwargs: operations.append((args, kwargs)))
    dialog._show_auto_adapt()
    intent = dialog._auto_intent_dialog
    assert intent is not None
    try:
        font = QFont(intent.font())
        font.setPointSizeF(font.pointSizeF() * 1.35)
        intent.setFont(font)
        intent.resize(360, 520)
        _pump()
        assert intent.width() == 360 and not intent.isModal()
        area = intent.findChild(QWidget, "adaptation_intent_scroll")
        assert area.widget().width() <= area.viewport().width() + 1
        _assert_page_controls_fit(area.widget(), area.viewport())
        selector = intent.findChild(QComboBox)
        selector.setCurrentIndex(selector.findData("public"))
        for check in intent.findChildren(QCheckBox):
            assert check.mapTo(area.viewport(), QPoint(0, 0)).x() >= 0
            assert check.width() <= area.viewport().width()
            assert check.width() >= check.sizeHint().width(), check.text()
        intent.accept()
        assert operations == [(("public", False, True), {"task": "auto_prepare"})]
        literal = "Get-NetFirewallAddressFilter <AccessDenied>\nFull diagnostic evidence preserved 🛡"
        notice = dialog._show_notice("Held", "Review retained", literal)
        notice.resize(360, 440)
        _pump()
        assert notice.width() == 360 and not notice.isModal()
        body = notice.findChild(QPlainTextEdit)
        assert body.toPlainText() == literal
        copy = next(button for button in notice.findChildren(QPushButton) if button.text() == "Copy details")
        copy.click()
        assert QApplication.clipboard().text() == literal
        dialog._confirm_operation("Restore", "Exact snapshot review", literal, lambda: operations.append("approved"))
        approval = dialog._confirmation_dialogs[-1]
        approval.resize(360, 480)
        _pump()
        assert not approval.isModal()
        _assert_rows_fit(approval)
        assert next(button for button in approval.findChildren(QPushButton) if button.text() == "Cancel").isDefault()
        approval.reject()
        assert "approved" not in operations
    finally:
        dialog.close()
        _pump()


def _deny_nested_baseline_dialogs(monkeypatch):
    from PySide6.QtWidgets import QDialog, QMessageBox

    def denied(*_args, **_kwargs):
        raise AssertionError("baseline consent must not open a nested modal loop")

    monkeypatch.setattr(QDialog, "exec", denied)
    monkeypatch.setattr(QMessageBox, "warning", denied)
    monkeypatch.setattr(QMessageBox, "information", denied)


def _ready_baseline():
    return {"available": True, "supported": True, "baseline_id": "baseline-fixture-exact",
            "captured_at": "2026-11-01T12:00:00Z", "firewall_sha256": "a" * 64}


@pytest.mark.parametrize("verb", ["capture", "restore"])
def test_baseline_consent_is_modeless_default_cancel_and_dispatches_only_after_approval(monkeypatch, verb):
    dialog = _workbench(monkeypatch)
    _deny_nested_baseline_dialogs(monkeypatch)
    dialog._recovery_view = _ready_baseline() if verb == "restore" else {"available": False, "supported": True}
    queued, native = [], []
    monkeypatch.setattr(dialog, "_run_task", lambda name, operation: queued.append((name, operation)))
    operation_name = f"{verb}_security_baseline"
    setattr(dialog.service, operation_name, lambda **kwargs: native.append(kwargs))
    try:
        getattr(dialog, f"_{operation_name}")()
        approval = dialog._confirmation_dialogs[-1]
        assert not approval.isModal() and queued == [] and native == []
        cancel = next(button for button in approval.findChildren(QPushButton) if button.text() == "Cancel")
        assert cancel.isDefault()
        details = approval.findChild(QPlainTextEdit).toPlainText()
        assert "complete Windows Firewall policy" in details
        if verb == "restore":
            assert "baseline-fixture-exact" in details and "a" * 64 in details
        approval.reject()
        assert queued == [] and native == []
        getattr(dialog, f"_{operation_name}")()
        approval = dialog._confirmation_dialogs[-1]
        approval.accept()
        assert len(queued) == 1 and queued[0][0] == operation_name and native == []
        queued[0][1]()
        assert native == [{"approved": True}]
        # Retaining an earlier Qt wrapper never grants a second operation.
        approval.accept()
        assert len(queued) == 1
    finally:
        dialog.close()
        _pump()


@pytest.mark.parametrize("verb", ["capture", "restore"])
@pytest.mark.parametrize("change", ["close", "busy", "intent-generation", "newer-consent"])
def test_baseline_consent_discards_closed_busy_adjusted_or_superseded_request(monkeypatch, verb, change):
    dialog = _workbench(monkeypatch)
    _deny_nested_baseline_dialogs(monkeypatch)
    dialog._recovery_view = _ready_baseline() if verb == "restore" else {"available": False, "supported": True}
    queued = []
    monkeypatch.setattr(dialog, "_run_task", lambda *args: queued.append(args))
    request = getattr(dialog, f"_{verb}_security_baseline")
    try:
        request()
        approval = dialog._confirmation_dialogs[-1]
        if change == "close":
            dialog.close()
        elif change == "busy":
            dialog._busy_task = "audit"
        elif change == "intent-generation":
            dialog._profile_changed()
        else:
            request()
            assert len(dialog._confirmation_dialogs) == 2
        approval.accept()
        assert queued == []
        if change == "newer-consent":
            dialog._confirmation_dialogs[-1].accept()
            assert len(queued) == 1
    finally:
        dialog._busy_task = ""
        dialog.close()
        _pump()


@pytest.mark.parametrize("field", ["baseline_id", "captured_at", "firewall_sha256", "available", "checking"])
def test_restore_baseline_consent_keeps_displayed_identity_and_refuses_changed_cache(monkeypatch, field):
    dialog = _workbench(monkeypatch)
    _deny_nested_baseline_dialogs(monkeypatch)
    original = _ready_baseline()
    dialog._recovery_view = original
    queued = []
    monkeypatch.setattr(dialog, "_run_task", lambda *args: queued.append(args))
    try:
        dialog._restore_security_baseline()
        approval = dialog._confirmation_dialogs[-1]
        details = approval.findChild(QPlainTextEdit)
        before = details.toPlainText()
        original[field] = False if field == "available" else True if field == "checking" else "changed"
        assert details.toPlainText() == before
        approval.accept()
        assert queued == []
        assert any("baseline changed" in notice.findChild(QPlainTextEdit).toPlainText()
                   for notice in dialog._notice_dialogs)
    finally:
        dialog.close()
        _pump()


def test_capture_baseline_consent_preserves_existing_baseline_and_checking_holds(monkeypatch):
    dialog = _workbench(monkeypatch)
    _deny_nested_baseline_dialogs(monkeypatch)
    queued = []
    monkeypatch.setattr(dialog, "_run_task", lambda *args: queued.append(args))
    try:
        dialog._recovery_view = {"available": False, "checking": True}
        dialog._capture_security_baseline()
        assert dialog._confirmation_dialogs == [] and queued == []
        assert "Recovery integrity check is running" in dialog.footer_detail.text()
        dialog._recovery_view = {"available": False, "supported": True}
        dialog._capture_security_baseline()
        approval = dialog._confirmation_dialogs[-1]
        dialog._recovery_view = _ready_baseline()
        approval.accept()
        assert queued == []
        assert any("never silently replaced" in notice.findChild(QPlainTextEdit).toPlainText()
                   for notice in dialog._notice_dialogs)
        count = len(dialog._confirmation_dialogs)
        dialog._capture_security_baseline()
        assert len(dialog._confirmation_dialogs) == count
        dialog._recovery_view = {"available": False}
        dialog._restore_security_baseline()
        assert queued == []
        assert any("No restorable host baseline exists yet" in notice.findChild(QPlainTextEdit).toPlainText()
                   for notice in dialog._notice_dialogs)
    finally:
        dialog.close()
        _pump()
