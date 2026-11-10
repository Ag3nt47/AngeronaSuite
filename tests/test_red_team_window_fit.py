"""Inert layout regressions; run only after reviewed candidate integration.

These tests do not launch Core, probes, scanners, network or tool workers.
Screen fixtures use Qt logical geometry plus enlarged font metrics; native
Windows/DPI acceptance remains separate from these offscreen checks.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QPoint, QRect, Qt, Signal
from PySide6.QtGui import QAccessible
from PySide6.QtWidgets import QApplication, QMainWindow, QScrollArea, QWidget

from angerona.gui import github_tools
from angerona.gui.red_team_console import RedTeamConsole
from angerona.gui.theme import build_qss


class _Parent(QMainWindow):
    _shark_narration = Signal(str)

    def _qss(self):
        return build_qss("cyber", scale=getattr(self, "_sizing_theme_scale", 1.0))


class _Screen:
    def __init__(self, rectangle, ratio):
        self.rectangle = QRect(rectangle)
        self.ratio = ratio
        self.ratio_queries = 0

    def availableGeometry(self):
        return QRect(self.rectangle)

    def devicePixelRatio(self):
        self.ratio_queries += 1
        return self.ratio


class _InertTools(QWidget):
    """Represent a tall inactive page without tool-controller or I/O work."""
    def __init__(self, parent):
        super().__init__(parent)
        self.setMinimumSize(900, 1100)

    def cancel_pending(self):
        pass


def _settle(app):
    # Bounded event turns include the one queued native-decoration fit.
    for _ in range(6):
        app.processEvents()


def _inside(widget, owner):
    rectangle = QRect(widget.mapTo(owner, QPoint()), widget.size())
    assert widget.isVisibleTo(owner)
    assert owner.rect().contains(rectangle), (widget.objectName(), rectangle, owner.rect())
    return rectangle


def _action_name(text):
    # Qt accessibility strips mnemonic ampersands and may normalize spacing.
    return " ".join(text.replace("&&", "\x00").replace("&", "").replace("\x00", "&").split())


def _sticky_visible(console, *, launch_enabled=True):
    for widget in (console.overall_progress, console.workflow_status,
                   console.response_readiness, console.launch_btn, console.stop_btn):
        _inside(widget, console)
    label = console.response_readiness
    assert label.height() >= label.heightForWidth(label.width())
    for button in (console.launch_btn, console.stop_btn):
        interface = QAccessible.queryAccessibleInterface(button)
        assert interface is not None and interface.role() == QAccessible.Role.Button
        name = _action_name(interface.text(QAccessible.Text.Name))
        caption = _action_name(button.text())
        assert name == caption
        assert name.endswith("Launch simulation" if button is console.launch_btn else "Stop clean")
        assert not interface.state().invisible
        assert interface.state().disabled == (not button.isEnabled())
    assert console.launch_btn.isEnabled() is launch_enabled
    assert console.stop_btn.isEnabled()
    if console.launch_warning.isVisible():
        warning = console.launch_warning
        _inside(warning, console)
        assert warning.height() >= warning.heightForWidth(warning.width())
        accessible = QAccessible.queryAccessibleInterface(warning)
        assert accessible.text(QAccessible.Text.Name) == "Simulation response warning"
    readiness = QAccessible.queryAccessibleInterface(console.response_readiness)
    assert readiness.text(QAccessible.Text.Name) == "Containment readiness preview"


@pytest.fixture
def console_factory(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    held = []
    monkeypatch.setattr(github_tools, "GitHubToolsPanel", _InertTools)
    def history(self):
        self._sizing_dispatch_calls = getattr(self, "_sizing_dispatch_calls", [])
        self._sizing_dispatch_calls.append("history")

    def editor(self):
        self._sizing_dispatch_calls = getattr(self, "_sizing_dispatch_calls", [])
        self._sizing_dispatch_calls.append("editor")
        self._editor_loaded = True

    monkeypatch.setattr(RedTeamConsole, "_load_history", history)
    monkeypatch.setattr(RedTeamConsole, "_load_editor", editor)
    monkeypatch.setattr(RedTeamConsole, "_refresh_device_enrollments", lambda self: None)
    warning = ("Practice canaries ready; ordinary host response remains held. "
               "Each action still needs an exact lease, original evidence and a "
               "verified postcondition. Readiness is not a containment result.")
    monkeypatch.setattr(RedTeamConsole, "_refresh_response_readiness",
                        lambda self: self.response_readiness.setText(warning))

    def build(rectangle, *, font_scale=1.0, ratio=1.0, settle=True):
        screen = _Screen(rectangle, ratio)
        monkeypatch.setattr(RedTeamConsole, "screen", lambda self: screen)
        parent = _Parent()
        parent.config = SimpleNamespace()
        parent._sizing_theme_scale = font_scale
        font = parent.font()
        font.setPointSizeF(max(9.0, font.pointSizeF()) * font_scale)
        parent.setFont(font)
        console = RedTeamConsole(parent, default_target=str(tmp_path / "inert-markers"))
        held.append((console, parent))
        console.show()
        if settle:
            _settle(app)
        return app, console, screen

    yield build
    for console, parent in reversed(held):
        console._editor_reader.close()
        assert console._editor_reader.thread is None
        console.close()
        parent.close()
        console.deleteLater()
        parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    _settle(app)


@pytest.mark.parametrize("rectangle,font_scale,ratio", [
    (QRect(0, 0, 1366, 728), 1.0, 1.0),
    (QRect(0, 0, 1920, 1032), 1.0, 1.0),
    (QRect(1920, 40, 1056, 900), 1.0, 1.0),
    (QRect(-1280, 24, 1280, 720), 1.35, 1.5),
    (QRect(100, 60, 800, 640), 1.25, 1.25),
])
def test_normal_first_show_fits_frame_and_sticky_actions(
    console_factory, rectangle, font_scale, ratio,
):
    _app, console, screen = console_factory(rectangle, font_scale=font_scale, ratio=ratio)
    assert rectangle.contains(console.frameGeometry())
    assert console.styleSheet() == build_qss("cyber", scale=font_scale)
    _sticky_visible(console)
    _inside(console._run_content_scroll, console)
    assert console._run_content_scroll.viewport().height() >= 48
    # QScreen geometry already uses logical pixels; multiplying by DPR would
    # make nonzero-origin and high-scale screens overflow or shrink twice.
    assert screen.ratio_queries == 0
    assert console.windowModality() == Qt.WindowModality.NonModal
    assert console.windowFlags() & Qt.WindowType.WindowMinimizeButtonHint
    assert console.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint


def test_expanded_setup_scrolls_middle_without_moving_footer_or_warning(console_factory):
    app, console, _screen = console_factory(QRect(0, 0, 1056, 728), font_scale=1.2)
    response_warning = ("Containment is unavailable for this accepted inert display fixture. "
                        "No host response was applied. Review the original evidence and "
                        "response readiness before treating any marker as contained.")
    console.set_launch_status({"status": "accepted", "response_warning": response_warning,
                               "runs": {}}, {"auto_remediate": True})
    _settle(app)
    frame = QRect(console.frameGeometry())
    assert _screen.rectangle.contains(frame)
    before = {button.text(): _inside(button, console)
              for button in (console.launch_btn, console.stop_btn)}
    warning = console.response_readiness.text()
    console.setup_disclosure.set_expanded(True)
    _settle(app)
    area = console._run_content_scroll
    assert console.setup_disclosure.is_expanded()
    assert area.verticalScrollBar().maximum() > 0
    area.verticalScrollBar().setValue(area.verticalScrollBar().maximum())
    _settle(app)
    assert console.frameGeometry() == frame
    _sticky_visible(console, launch_enabled=False)
    assert _screen.rectangle.contains(console.frameGeometry())
    assert console.launch_warning.parentWidget() is console._response_panel
    assert console.launch_warning.isVisible()
    assert console.launch_warning.text() == response_warning
    assert console.response_readiness.text() == warning
    assert console._live_panel.parentWidget() is console._run_splitter
    for button in (console.launch_btn, console.stop_btn):
        assert _inside(button, console) == before[button.text()]


def test_inactive_device_lab_and_other_tall_pages_do_not_raise_run_minimum(console_factory):
    app, console, _screen = console_factory(QRect(1800, 20, 1056, 760))
    frame = QRect(console.frameGeometry())
    assert all(isinstance(console._tabs.widget(i), QScrollArea)
               for i in range(1, console._tabs.count()))
    device = next(i for i in range(console._tabs.count())
                  if "Device Security Lab" in console._tabs.tabText(i))
    console._tabs.setCurrentIndex(device)
    _settle(app)
    area = console._tabs.widget(device)
    assert console.frameGeometry() == frame
    assert area.verticalScrollBar().maximum() > 0
    area.ensureWidgetVisible(console.device_lab_log)
    _settle(app)
    visible = QRect(console.device_lab_log.mapTo(area.viewport(), QPoint()),
                    console.device_lab_log.size())
    assert area.viewport().rect().intersects(visible)
    console._tabs.setCurrentIndex(0)
    _settle(app)
    _sticky_visible(console)


def test_show_again_preserves_operator_normal_geometry(console_factory):
    app, console, _screen = console_factory(QRect(1200, 20, 1200, 900))
    console.resize(760, 650)
    console.move(1240, 50)
    _settle(app)
    chosen = QRect(console.geometry())
    console.hide()
    console.show()
    _settle(app)
    assert console.geometry() == chosen
    _sticky_visible(console)


@pytest.mark.parametrize("interruption", ["move-resize", "hide", "close"])
def test_queued_first_fit_respects_operator_and_lifecycle_fences(console_factory, interruption):
    app, console, _screen = console_factory(QRect(1200, 20, 1200, 900), settle=False)
    timer = console._initial_screen_fit_timer
    assert timer.parent() is console and timer.isSingleShot()
    if interruption == "move-resize":
        console.resize(760, 650)
        console.move(1250, 60)
    elif interruption == "hide":
        console.hide()
    else:
        console.close()
    chosen = QRect(console.geometry())
    _settle(app)
    assert console.geometry() == chosen
    assert not timer.isActive()
    if interruption in {"hide", "close"}:
        assert not console.isVisible()


def test_real_tab_dispatch_and_info_context_survive_page_viewports(console_factory):
    app, console, _screen = console_factory(QRect(1800, 20, 1056, 820))
    console._sizing_dispatch_calls = []
    tabs = console._tabs
    history = next(i for i in range(tabs.count()) if "History" in tabs.tabText(i))
    editor = next(i for i in range(tabs.count()) if "Sandbox Editor" in tabs.tabText(i))
    controller = console._context_info
    assert tabs.widget(controller.info_index).widget() is controller.info
    tabs.setCurrentIndex(history)
    _settle(app)
    assert console._sizing_dispatch_calls == ["history"]
    tabs.setCurrentIndex(editor)
    _settle(app)
    assert console._sizing_dispatch_calls == ["history", "editor"]
    assert console._editor_loaded
    tabs.setCurrentIndex(controller.info_index)
    _settle(app)
    assert console._sizing_dispatch_calls == ["history", "editor"]
    assert controller.last_functional_index == editor
    assert controller.info.topic == controller.resolver(tabs.tabText(editor))
    tabs.setCurrentIndex(history)
    tabs.setCurrentIndex(controller.info_index)
    _settle(app)
    assert console._sizing_dispatch_calls == ["history", "editor", "history"]
    assert controller.last_functional_index == history
    assert controller.info.topic == controller.resolver(tabs.tabText(history))


def test_wrapped_response_reservation_shrinks_after_widening_and_shorter_text(console_factory):
    app, console, screen = console_factory(QRect(0, 0, 1280, 1000))
    label = console.response_readiness
    label.setText(("Containment remains held until original evidence and exact response "
                   "authority verify. Review this complete warning before treating a "
                   "marker as contained. ") * 2)
    console.resize(760, 900)
    _settle(app)
    narrow = label.minimumSizeHint().height()
    assert label.height() >= label.heightForWidth(label.width())
    console.resize(1120, 900)
    _settle(app)
    wide = label.minimumSizeHint().height()
    assert wide < narrow
    assert label.height() >= label.heightForWidth(label.width())
    label.setText("Containment remains held.")
    _settle(app)
    short = label.minimumSizeHint().height()
    assert short < wide
    assert label.height() >= label.heightForWidth(label.width())
    assert screen.rectangle.contains(console.frameGeometry())
    _sticky_visible(console)
