from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from angerona.gui.dashboard_details import (
    ConsoleDetailDialog,
    FuturisticDetailDialog,
    SystemPulseDetailDialog,
)
from angerona.gui.aria_hud import AriaHud
from angerona.gui.header_controls import (
    HeaderActionButton,
    PanelRevealOverlay,
    install_global_window_reveal,
    motion_allowed,
    navigation_icon,
    show_with_window_reveal,
)
from angerona.gui.system_pulse import SystemPulseCard, _memory, _rate
from angerona.gui.pages import _ClickableSection, _show_nonmodal_from
from angerona.gui.red_team_console import RedTeamConsole


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
    button.set_compact(True, 38)
    assert button.text() == ""
    assert button.minimumWidth() == 38
    assert button.maximumWidth() == 38
    assert button.toolTip()
    button.set_full_label("LIVE WORLD VIEW")
    assert button.text() == ""
    button.set_compact(False)
    assert button.text() == "LIVE WORLD VIEW"


def test_panel_reveal_animates_the_real_destination_window() -> None:
    app = _app()
    parent = QWidget()
    parent.resize(800, 500)
    parent.show()
    source = HeaderActionButton("HELP", "help", "Help", "Explains the suite.", parent)
    source.resize(100, 30)
    overlay = PanelRevealOverlay(parent)
    target = QDialog(parent)
    target.resize(420, 260)
    called = []
    assert overlay.reveal(
        source,
        lambda: (called.append(True), target.show()),
        "#38bdf8",
    )
    app.processEvents()
    assert called == [True]
    assert target.isVisible()
    assert overlay._target is target
    assert not target.mask().isEmpty()
    assert not overlay.reveal(source, lambda: None)
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert target.mask().isEmpty()

    # The native X close is intercepted once. The real window remains alive
    # while its contents collapse through the same mask in reverse, then the
    # original close proceeds without a full-size flash.
    target.close()
    app.processEvents()
    assert target.isVisible()
    assert overlay._target is target
    assert overlay._mode == "closing"
    assert not target.mask().isEmpty()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert not target.isVisible()
    assert overlay._target is None
    assert overlay._mode == "idle"
    parent.close()


def test_close_button_uses_the_same_reverse_reveal_path() -> None:
    app = _app()
    parent = QWidget()
    parent.resize(640, 400)
    parent.show()
    source = QWidget(parent)
    source.resize(50, 24)
    overlay = PanelRevealOverlay(parent)
    target = QDialog(parent)
    target.resize(320, 200)
    layout = QVBoxLayout(target)
    close = QPushButton("Close")
    close.clicked.connect(target.close)
    layout.addWidget(close)
    assert overlay.reveal(source, target.show)
    app.processEvents()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()

    QTest.mouseClick(close, Qt.LeftButton)
    app.processEvents()
    assert target.isVisible()
    assert overlay._target is target
    assert overlay._mode == "closing"
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert not target.isVisible()
    parent.close()


def test_global_window_reveal_covers_legacy_dialog_open_and_close_paths() -> None:
    app = _app()
    parent = QWidget()
    parent.resize(640, 400)
    parent.show()
    source = QPushButton("Legacy action", parent)
    source.resize(120, 32)
    overlay = PanelRevealOverlay(parent)
    overlay.enable_global_windows()

    QTest.mouseClick(source, Qt.LeftButton)
    target = QDialog(parent)
    target.resize(340, 220)
    target.show()
    app.processEvents()
    assert overlay._target is target
    assert not target.mask().isEmpty()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()

    target.close()
    app.processEvents()
    assert target.isVisible()
    assert overlay._mode == "closing"
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert not target.isVisible()
    overlay.enable_global_windows(False)
    parent.close()


def test_reused_window_receives_a_fresh_reveal_after_hide_and_show() -> None:
    app = _app()
    parent = QWidget()
    parent.resize(640, 400)
    parent.show()
    overlay = PanelRevealOverlay(parent)
    overlay.enable_global_windows()
    target = QDialog(parent)
    target.resize(340, 220)

    target.show()
    app.processEvents()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert overlay._target is None

    target.hide()
    app.processEvents()
    target.show()
    app.processEvents()
    assert overlay._target is target
    assert overlay._mode == "opening"
    assert not target.mask().isEmpty()

    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    setattr(target, "_angerona_close_bypass", True)
    target.close()
    overlay.enable_global_windows(False)
    parent.close()


def test_global_reveal_excludes_holographic_and_transient_surfaces() -> None:
    app = _app()
    parent = QWidget()
    parent.resize(640, 400)
    parent.show()
    overlay = PanelRevealOverlay(parent)
    overlay.enable_global_windows()

    token = QWidget(None, Qt.Tool)
    token.setProperty("_angerona_orb_ignore", True)
    token.resize(116, 116)
    token.show()
    app.processEvents()
    assert overlay._target is None
    assert token.mask().isEmpty()

    token.close()
    overlay.enable_global_windows(False)
    parent.close()


def test_overlapping_window_opens_are_queued_without_a_full_size_flash() -> None:
    app = _app()
    parent = QWidget()
    parent.resize(640, 400)
    parent.show()
    overlay = PanelRevealOverlay(parent)
    overlay.enable_global_windows()
    first = QDialog(parent)
    second = QDialog(parent)
    first.resize(340, 220)
    second.resize(360, 240)

    first.show()
    second.show()
    app.processEvents()
    assert overlay._target is first
    assert not second.mask().isEmpty()
    assert any(reference() is second for reference in overlay._pending_windows)

    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert overlay._target is second
    assert not second.mask().isEmpty()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()

    for dialog in (first, second):
        setattr(dialog, "_angerona_close_bypass", True)
        dialog.close()
    overlay.enable_global_windows(False)
    parent.close()


def test_close_veto_confirmation_can_open_during_reverse_transition() -> None:
    class ConfirmingDialog(QDialog):
        prompt: QDialog | None = None

        def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
            if self.prompt is None:
                self.prompt = QDialog(self)
                self.prompt.setWindowTitle("Confirm close")
                self.prompt.resize(260, 140)
                self.prompt.show()
                event.ignore()
                return
            super().closeEvent(event)

    app = _app()
    parent = QWidget()
    parent.resize(640, 400)
    parent.show()
    overlay = PanelRevealOverlay(parent)
    overlay.enable_global_windows()
    target = ConfirmingDialog(parent)
    target.resize(360, 240)
    target.show()
    app.processEvents()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()

    target.close()
    app.processEvents()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert target.isVisible()
    assert target.prompt is not None
    assert target.prompt.isVisible()
    assert overlay._target is target.prompt
    assert not target.prompt.mask().isEmpty()

    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    setattr(target.prompt, "_angerona_close_bypass", True)
    target.prompt.close()
    setattr(target, "_angerona_close_bypass", True)
    target.close()
    overlay.enable_global_windows(False)
    parent.close()


def test_standalone_window_installs_one_shared_reveal_coordinator() -> None:
    app = _app()
    window = QWidget()
    window.resize(520, 320)
    overlay = show_with_window_reveal(window, color="#c084fc")
    app.processEvents()

    assert overlay is install_global_window_reveal(window)
    assert overlay._target is window
    assert not window.mask().isEmpty()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()

    child = QDialog(window)
    child.resize(300, 180)
    child.show()
    app.processEvents()
    assert overlay._target is child
    assert not child.mask().isEmpty()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()

    setattr(child, "_angerona_close_bypass", True)
    child.close()
    overlay.enable_global_windows(False)
    setattr(window, "_angerona_close_bypass", True)
    window.close()


def test_aria_voice_request_carries_its_button_as_reveal_origin() -> None:
    app = _app()
    hud = AriaHud(score_fn=lambda: 100, compact=True)
    hud.show()
    origins = []
    hud.microphone_requested.connect(origins.append)
    QTest.mouseClick(hud.mic_button, Qt.LeftButton)
    app.processEvents()
    assert origins == [hud.mic_button]
    hud.close()


def test_reduced_motion_environment_is_a_hard_override(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    assert motion_allowed() is False

    # If motion is disabled after a destination was registered (for example,
    # while Settings is open), its X must close immediately instead of starting
    # a reverse transition.
    app = _app()
    parent = QWidget()
    parent.resize(500, 320)
    parent.show()
    source = QWidget(parent)
    source.resize(40, 24)
    overlay = PanelRevealOverlay(parent)
    target = QDialog(parent)
    target.resize(260, 160)
    assert overlay.reveal(source, lambda: target.show())
    app.processEvents()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    target.close()
    app.processEvents()
    assert not target.isVisible()
    assert overlay._mode == "idle"
    parent.close()


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


def test_system_pulse_click_and_history_power_expanded_detail() -> None:
    app = _app()
    card = SystemPulseCard(interval_ms=60_000)
    card._timer.stop()
    requested: list[bool] = []
    card.details_requested.connect(lambda: requested.append(True))
    for index in range(110):
        card._apply_sample(
            {
                "cpu": float(index % 100),
                "ram": 50.0,
                "available": 4 * 1024 ** 3,
                "wifi": 80,
                "down": 2048.0,
                "up": 1024.0,
            }
        )
    QTest.mouseClick(card, Qt.LeftButton)
    app.processEvents()
    assert requested == [True]
    snapshot = card.snapshot()
    assert len(snapshot["history"]) == 90
    assert snapshot["latest"]["cpu"] == 9.0

    detail = SystemPulseDetailDialog(card)
    detail.show()
    app.processEvents()
    assert detail.cpu.value.text() == "9%"
    assert detail.available.value.text() == "4.0 GB"
    assert detail.graph._samples
    detail.close()
    card.close()


def test_clickable_section_routes_real_dialog_through_owner_reveal() -> None:
    app = _app()

    class Owner(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.calls = []

        def _reveal_window_from(self, source, factory, color):
            self.calls.append((source, color))
            return factory()

    owner = Owner()
    layout = QVBoxLayout(owner)
    section = _ClickableSection(
        "Live Alerts", "Open the expanded signed event timeline."
    )
    layout.addWidget(section)
    owner.show()
    QTest.mouseClick(section, Qt.LeftButton)
    app.processEvents()
    assert section.toolTip()

    detail = _show_nonmodal_from(
        section,
        lambda: FuturisticDetailDialog("Test", "Bounded detail", parent=owner),
        "#22c55e",
    )
    app.processEvents()
    assert owner.calls[-1] == (section, "#22c55e")
    assert detail.isVisible()
    assert detail.header._timer.isActive()
    detail.close()
    owner.close()


def test_expanded_console_reuses_guarded_dashboard_command_path() -> None:
    app = _app()

    class FakeConsole:
        def __init__(self) -> None:
            self.out = QPlainTextEdit()
            self.out.setPlainText("ready\n")
            self._busy = 0
            self.commands = []

        def run_command(self, text: str) -> None:
            self.commands.append(text)
            self.out.appendPlainText(f"> {text}")

    console = FakeConsole()
    detail = ConsoleDetailDialog(console)
    detail.command.setText("resources")
    detail._run()
    detail._refresh()
    app.processEvents()
    assert console.commands == ["resources"]
    assert "resources" in detail.transcript.toPlainText()
    assert int(detail.lines.value.text()) >= 2
    detail.close()


def test_red_team_run_footer_stays_reachable_at_minimum_window_size(tmp_path) -> None:
    app = _app()
    dialog = RedTeamConsole(None, default_target=str(tmp_path))
    dialog.resize(700, 520)
    dialog.show()
    app.processEvents()

    launch_origin = dialog.launch_btn.mapTo(dialog, QPoint(0, 0))
    launch_bottom = launch_origin.y() + dialog.launch_btn.height()
    assert dialog.minimumWidth() <= 700
    assert dialog.minimumHeight() <= 520
    assert dialog.isSizeGripEnabled()
    assert dialog.launch_btn.isVisible()
    assert launch_bottom <= dialog.contentsRect().bottom()
    assert dialog.launch_btn.parentWidget() is not dialog._run_scroll.widget()
    assert dialog._run_scroll.verticalScrollBar().maximum() > 0
    dialog.close()
