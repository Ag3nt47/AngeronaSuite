"""Visible health notes and native style events for dashboard chip updates."""
from types import SimpleNamespace

from PySide6.QtCore import QObject, QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QFontMetrics, QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget

import pytest

from angerona.gui.pages import ResourceStrip, StatusStrip
from angerona.gui.theme import build_qss


class StyleEvents(QObject):
    def __init__(self, chip):
        super().__init__(chip)
        self.count = 0
        chip.installEventFilter(self)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.StyleChange:
            self.count += 1
        return False


def manager():
    module = SimpleNamespace(name="Fixture sensor", CODE="TEST", status="running",
                             health_state="ok", health=90, health_note="Original note")
    return SimpleNamespace(modules={module.name: module}, is_enabled=lambda _name: True), module


def refresh(strip):
    strip.refresh()
    strip.show()
    QApplication.instance().processEvents()


def test_health_note_only_change_updates_visible_tooltip():
    owner, module = manager()
    strip = StatusStrip(owner)
    refresh(strip)
    chip = strip._chips[module.name]
    observer = StyleEvents(chip)
    old_text = chip.text()
    module.health_note = "Updated provenance and coverage note"
    refresh(strip)
    assert module.health_note in chip.toolTip()
    assert chip.text() == old_text and observer.count == 0


def test_health_percentage_change_preserves_style_without_repolish():
    owner, module = manager()
    strip = StatusStrip(owner)
    refresh(strip)
    chip = strip._chips[module.name]
    observer = StyleEvents(chip)
    module.health = 91
    refresh(strip)
    assert "91%" in chip.text() and "91%" in chip.toolTip()
    assert observer.count == 0
    module.health_state = "critical"
    refresh(strip)
    assert observer.count > 0 and "#ef4444" in chip.styleSheet()


def test_resource_value_change_repolishes_only_when_color_changes():
    owner, module = manager()
    activity = []
    strip = ResourceStrip(owner, SimpleNamespace(recent=lambda _limit: activity))
    refresh(strip)
    chip = strip._chips[module.name]
    observer = StyleEvents(chip)
    activity.append(SimpleNamespace(module=module.name))
    refresh(strip)
    assert "24%" in chip.text() and "24%" in chip.toolTip()
    assert observer.count == 0
    activity.extend([SimpleNamespace(module=module.name)] * 2)
    refresh(strip)
    assert "40%" in chip.text() and "#f59e0b" in chip.styleSheet()
    assert observer.count > 0


def many_modules(count=73):
    modules = {}
    for index in range(count):
        name = f"Fixture sensor {index:02d}"
        modules[name] = SimpleNamespace(name=name, CODE=f"S{index:04d}", status="running",
                                       health_state="ok", health=100, health_note="Ready")
    return SimpleNamespace(modules=modules, is_enabled=lambda _name: True)


def ribbon_pair(owner, width=900, config=None):
    window = QWidget()
    window.resize(width, 200)
    layout = QVBoxLayout(window)
    health = StatusStrip(owner, config=config)
    activity = ResourceStrip(owner, SimpleNamespace(recent=lambda _limit: []))
    health.set_companion(activity)
    layout.addWidget(health)
    layout.addWidget(activity)
    health.refresh()
    activity.refresh()
    window.show()
    QApplication.instance().processEvents()
    return window, health, activity


@pytest.mark.parametrize("width,scale", [(640, 0.75), (1280, 1.0), (1920, 1.35)])
def test_all_73_chips_remain_readable_and_reachable(width, scale):
    window, health, activity = ribbon_pair(many_modules(), width)
    window.setStyleSheet(build_qss(scale=scale))
    QApplication.instance().processEvents()
    try:
        for strip in (health, activity):
            for chip in strip._chips.values():
                metrics = QFontMetrics(chip.font())
                assert chip.width() >= max(metrics.horizontalAdvance(line)
                                           for line in chip.text().splitlines()) + 12
                assert chip.height() >= metrics.lineSpacing() * 2 + 4
            bar = strip._scroll.horizontalScrollBar()
            assert bar.maximum() > 0
            bar.setValue(bar.maximum())
            last = list(strip._chips.values())[-1]
            rect = last.mapTo(strip._scroll.viewport(), last.rect().bottomRight())
            assert rect.x() < strip._scroll.viewport().width()
        assert health._scroll.horizontalScrollBar().value() == activity._scroll.horizontalScrollBar().value()
        assert "Estimated" in activity._summary.text()
        assert "73/73" in health._summary.text()
    finally:
        window.close()


def test_manual_wheel_and_keyboard_browse_both_ribbons(monkeypatch):
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    window, health, activity = ribbon_pair(many_modules())
    opened = []
    last = list(health._chips.values())[-1]
    last.clicked.connect(opened.append)
    try:
        bar = activity._scroll.horizontalScrollBar()
        event = QWheelEvent(QPointF(20, 20), QPointF(20, 20), QPoint(), QPoint(0, -120),
                            Qt.NoButton, Qt.NoModifier, Qt.NoScrollPhase, False)
        activity._scroll.wheelEvent(event)
        assert bar.value() > 0
        assert health._scroll.horizontalScrollBar().value() == bar.value()
        assert health._manual_until > 0
        last.setFocus()
        QApplication.instance().processEvents()
        QTest.keyClick(last, Qt.Key_Return)
        assert opened == [last._name]
        assert health._scroll.horizontalScrollBar().value() > 0
        assert last.accessibleName() == last._name
    finally:
        window.close()


def test_pan_stops_for_pause_manual_input_hover_hidden_and_reduced_motion(monkeypatch):
    monkeypatch.setattr("angerona.gui.header_controls.motion_allowed", lambda _cfg=None: True)
    window, health, activity = ribbon_pair(many_modules())
    monkeypatch.setattr(health, "underMouse", lambda: False)
    monkeypatch.setattr(activity, "underMouse", lambda: False)
    QApplication.instance().focusWidget().clearFocus() if QApplication.instance().focusWidget() else None
    bar = health._scroll.horizontalScrollBar()
    try:
        health._manual_until = 0
        health._advance_pan()
        assert bar.value() == 1 and activity._scroll.horizontalScrollBar().value() == 1
        health.pause_for_interaction()
        health._advance_pan()
        assert bar.value() == 1
        health._manual_until = 0
        monkeypatch.setattr(activity, "underMouse", lambda: True)
        health._advance_pan()
        assert bar.value() == 1
        monkeypatch.setattr(activity, "underMouse", lambda: False)
        health._pause.setChecked(True)
        assert not health._pan_timer.isActive()
        health._manual_until = 0
        health._advance_pan()
        assert bar.value() == 1
        health._pause.setChecked(False)
        health.hide()
        assert not health._pan_timer.isActive()
        health._advance_pan()
        assert bar.value() == 1
        health.show()
        monkeypatch.setattr("angerona.gui.header_controls.motion_allowed", lambda _cfg=None: False)
        health.refresh()
        assert not health._pan_timer.isActive() and not health._pause.isEnabled()
        health._manual_until = 0
        health._advance_pan()
        assert bar.value() == 1
    finally:
        window.close()


def test_same_count_module_replacement_rebuilds_without_empty_tick():
    owner, old = manager()
    strip = StatusStrip(owner)
    refresh(strip)
    new = SimpleNamespace(**vars(old))
    new.name = "Replacement sensor"
    owner.modules = {new.name: new}
    strip.refresh()
    assert set(strip._chips) == {new.name}
    assert "90%" in strip._chips[new.name].text()
    strip.close()
