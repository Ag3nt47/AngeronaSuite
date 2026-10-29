"""EKG evidence must expire without inventing heartbeats from process presence."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QPlainTextEdit

from angerona.gui.component_heartbeat import (
    ComponentHeartbeatModel, ComponentHeartbeatStrip, EXPECTED_ROLES, MAX_COMPONENTS,
)
from angerona.gui.dashboard_footer import DashboardFooter
from angerona.gui.main_window import MainWindow


def beat(role="core", *, generation="pid123:birth456", stamp=100.0, **changes):
    result = dict(role=role, generation_id=generation, pid=123,
                  last_heartbeat_monotonic=stamp, deadline_seconds=5.0,
                  state="running", reason="Authenticated advancing heartbeat.")
    result.update(changes)
    return result


def test_absent_heartbeats_are_explicitly_unavailable_even_when_a_process_is_present():
    model = ComponentHeartbeatModel()
    model.publish([dict(role="watchdog", pid=123, generation_id="pid123:birth456",
                        state="running", deadline_seconds=5.0)], 100)
    records = model.snapshot(100)
    assert tuple(row.role for row in records) == EXPECTED_ROLES
    assert not any(row.fresh for row in records)
    watchdog = records[1]
    assert watchdog.state == "unavailable"
    assert "timestamp" in watchdog.reason


def test_real_heartbeat_expires_without_a_new_supplier_publication():
    model = ComponentHeartbeatModel()
    model.publish([beat()], 100)
    assert model.snapshot(100)[0].fresh
    assert model.snapshot(104.999)[0].fresh
    assert not model.snapshot(105)[0].fresh
    assert model.snapshot(105)[0].state == "stale"


@pytest.mark.parametrize("changes", [
    dict(stamp=None), dict(stamp=float("nan")), dict(stamp=float("inf")),
    dict(stamp=101), dict(stamp=True), dict(generation=""),
    dict(deadline_seconds=0), dict(deadline_seconds=float("inf")),
    dict(deadline_seconds=121), dict(deadline_seconds=True),
    dict(state="starting"), dict(state="disabled"), dict(state="stopped"),
    dict(state="unavailable"),
])
def test_unusable_or_inactive_evidence_stays_flat(changes):
    payload = beat()
    if "stamp" in changes:
        changes = dict(changes)
        payload["last_heartbeat_monotonic"] = changes.pop("stamp")
    if "generation" in changes:
        changes = dict(changes)
        payload["generation_id"] = changes.pop("generation")
    payload.update(changes)
    model = ComponentHeartbeatModel()
    model.publish([payload], 100)
    assert not model.snapshot(100)[0].fresh


def test_generation_replacement_cannot_reuse_the_previous_heartbeat():
    model = ComponentHeartbeatModel()
    model.publish([beat()], 100)
    assert model.snapshot(100)[0].fresh
    model.publish([beat(generation="pid123:birth789")], 101)
    assert not model.snapshot(101)[0].fresh
    assert model.snapshot(101)[0].state == "starting"
    model.publish([beat(generation="pid123:birth789", stamp=101)], 101)
    assert model.snapshot(101)[0].fresh
    model.publish([beat(generation="pid123:birth456", stamp=100)], 101)
    assert not model.snapshot(101)[0].fresh


def test_publication_is_copied_bounded_and_duplicate_generations_fail_closed():
    payload = beat()
    model = ComponentHeartbeatModel()
    model.publish([payload], 100)
    payload["state"] = "disabled"
    assert model.snapshot(100)[0].fresh
    model.publish([beat(), beat(generation="other")], 100)
    assert not model.snapshot(100)[0].fresh
    assert "Conflicting" in model.snapshot(100)[0].reason
    model.publish([beat(role=f"helper-{index}") for index in range(100)], 100)
    assert len(model.snapshot(100)) <= MAX_COMPONENTS
    assert tuple(row.role for row in model.snapshot(100)[:4]) == EXPECTED_ROLES


def test_strip_animates_only_fresh_evidence_and_exposes_plain_details():
    now = [100.0]
    strip = ComponentHeartbeatStrip(clock=lambda: now[0])
    records = [beat(reason="<b>untrusted diagnostic</b>")]
    details = Mock()
    strip.details_requested.connect(details)
    try:
        strip.set_source(lambda: tuple(dict(row) for row in records))
        strip.show()
        QApplication.processEvents()
        assert strip._animation_timer.isActive()
        assert "core: live" in strip.accessibleName()
        image = strip.grab().toImage()
        green_rows = {y for x in range(strip.width() // 4) for y in range(16, 37)
                      if (pixel := image.pixelColor(x, y)).green() > 130 and
                      pixel.red() < 100 and pixel.blue() < 190}
        assert max(green_rows) - min(green_rows) > 5
        QTest.keyClick(strip, Qt.Key_Space)
        assert details.call_count == 1
        dialog = strip._details_dialog
        assert dialog is not None
        assert "<b>untrusted diagnostic</b>" in strip.details_text()
        dialog.reject()
        QTest.keyClick(strip, Qt.Key_Return)
        assert details.call_count == 2
        strip._details_dialog.reject()
        now[0] = 105.0
        strip._animate()
        assert not strip._animation_timer.isActive()
        assert "core: stale" in strip.accessibleName()
        assert all(not row.fresh for row in strip.snapshot())
        image = strip.grab().toImage()
        red_rows = {y for x in range(strip.width() // 4) for y in range(16, 37)
                    if (pixel := image.pixelColor(x, y)).red() > 150 and
                    pixel.green() < 140 and pixel.blue() < 160}
        assert red_rows and max(red_rows) - min(red_rows) <= 3
    finally:
        strip.close()
        strip.deleteLater()


def test_supplier_failure_immediately_discards_old_live_claims_and_hidden_animation_stops():
    strip = ComponentHeartbeatStrip(clock=lambda: 100)
    try:
        strip.set_source(lambda: (beat(),))
        strip.show()
        QApplication.processEvents()
        assert strip._animation_timer.isActive()
        strip.hide()
        assert not strip._animation_timer.isActive() and not strip._poll_timer.isActive()

        def unavailable():
            raise RuntimeError("private diagnostic")

        strip.set_source(unavailable)
        assert not any(row.fresh for row in strip.snapshot())
        assert "publication is unavailable" in strip.details_text()
        assert "private diagnostic" not in strip.details_text()
    finally:
        strip.close()
        strip.deleteLater()


@pytest.mark.parametrize("wrap", [True, False])
def test_live_details_refresh_preserves_review_scroll_and_selection(wrap):
    now = [100.0]
    roles = (*EXPECTED_ROLES, *(f"helper-{index:02d}" for index in range(20)))
    records = [beat(role=role, generation=f"pid{index + 100}:birth456",
                    reason=f"Review target {index} 🌐 " + "diagnostic detail " * 25)
               for index, role in enumerate(roles)]
    strip = ComponentHeartbeatStrip(clock=lambda: now[0])
    try:
        strip.set_source(lambda: tuple(dict(row) for row in records))
        strip.show_details()
        dialog = strip._details_dialog
        view = dialog.findChild(QPlainTextEdit, "ComponentHeartbeatDetailsText")
        if not wrap:
            view.setLineWrapMode(QPlainTextEdit.NoWrap)
        QApplication.processEvents()
        assert not view.isUndoRedoEnabled()
        cursor = view.document().find("Review target 12 🌐")
        assert cursor.hasSelection()
        view.setTextCursor(cursor)
        vertical, horizontal = view.verticalScrollBar(), view.horizontalScrollBar()
        assert vertical.maximum() > 10
        vertical.setValue(vertical.maximum() // 2)
        horizontal.setValue(horizontal.maximum() // 2)
        position = (vertical.value(), horizontal.value())
        selected = view.textCursor().selectedText()
        original_dialog = dialog
        for _ in range(3):
            now[0] += 0.7
            strip.refresh_snapshot()
            QApplication.processEvents()
            assert strip._details_dialog is original_dialog
            assert (vertical.value(), horizontal.value()) == position
            assert view.textCursor().selectedText() == selected
        assert "2.1 s" in view.toPlainText()
        assert not view.document().isUndoAvailable()
    finally:
        if strip._details_dialog is not None:
            strip._details_dialog.reject()
        strip.close()
        strip.deleteLater()


def test_main_window_supplier_contract_and_1280_footer_fit():
    window = QMainWindow()
    window.resize(1280, 720)
    footer = DashboardFooter(window)
    strip = ComponentHeartbeatStrip(window, clock=lambda: 100)
    window.statusBar().setSizeGripEnabled(False)
    window.statusBar().addPermanentWidget(footer, 1)
    window.statusBar().addPermanentWidget(strip)
    window.setCentralWidget(QLabel("Inert dashboard layout fixture"))
    owner = SimpleNamespace(component_heartbeat_strip=strip)
    try:
        MainWindow.set_component_heartbeat_source(owner, lambda: (beat(),))
        window.show()
        QApplication.processEvents()
        assert strip.snapshot()[0].fresh
        assert window.statusBar().contentsRect().contains(strip.geometry())
        assert not footer.geometry().intersects(strip.geometry())
        assert strip.height() == 38 and strip.width() <= 236
        assert window.height() == 720 and not window.grab().isNull()
    finally:
        window.close()
        window.deleteLater()
