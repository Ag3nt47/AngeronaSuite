from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui.header_controls import (
    HeaderActionButton,
    PanelRevealOverlay,
    motion_allowed,
    navigation_icon,
)
from angerona.gui.system_pulse import SystemPulseCard, _memory, _rate


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_header_actions_have_distinct_vector_icons_and_definitions() -> None:
    _app()
    kinds = (
        "selftest", "simulation", "eco", "world", "attack", "intel",
        "forensics", "console", "setup", "help", "settings", "stop",
    )
    keys = {navigation_icon(kind).cacheKey() for kind in kinds}
    assert len(keys) == len(kinds)

    button = HeaderActionButton(
        "WORLD VIEW", "world", "World View", "Shows the live system flow."
    )
    assert not button.icon().isNull()
    assert button.accessibleName() == "World View"
    assert button.accessibleDescription() == "Shows the live system flow."
    assert "<b" in button.toolTip()
    assert "Shows the live system flow." in button.toolTip()


def test_panel_reveal_starts_as_a_nonblocking_overlay() -> None:
    _app()
    parent = QWidget()
    parent.resize(800, 500)
    source = HeaderActionButton("HELP", "help", "Help", "Explains the suite.", parent)
    source.resize(100, 30)
    overlay = PanelRevealOverlay(parent)
    called = []
    assert overlay.reveal(source, lambda: called.append(True), "#38bdf8")
    assert not overlay.isHidden()
    assert not overlay.reveal(source, lambda: None)
    overlay._animation.stop()
    overlay.hide()
    assert called == []


def test_reduced_motion_environment_is_a_hard_override(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    assert motion_allowed() is False


def test_system_pulse_card_and_human_readable_units() -> None:
    _app()
    card = SystemPulseCard(interval_ms=60_000)
    card._timer.stop()
    card._apply_sample(
        {
            "cpu": 34.0,
            "ram": 61.0,
            "available": 8 * 1024 ** 3,
            "wifi": 87,
            "down": 2 * 1024 ** 2,
            "up": 512 * 1024,
        }
    )
    assert card._cpu.value.text() == "34%"
    assert card._ram.value.text() == "61%"
    assert card._wifi.value.text() == "87%"
    assert "8.0 GB" in card._memory.text()
    assert "2.0 MB/s" in card._network.text()
    assert _memory(3 * 1024 ** 3) == "3.0 GB"
    assert _rate(1024) == "1.0 KB/s"
    card.close()
