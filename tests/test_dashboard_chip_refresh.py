"""Visible health notes and native style events for dashboard chip updates."""
from types import SimpleNamespace

from PySide6.QtCore import QObject, QEvent
from PySide6.QtWidgets import QApplication

from angerona.gui.pages import ResourceStrip, StatusStrip


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
