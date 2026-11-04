"""Visible local action text wraps without changing work or hiding content."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication, QDialog, QScrollArea, QVBoxLayout, QWidget

from angerona.gui.action_progress import ActionActivities, ActionProgressView


_APP = None


@pytest.fixture
def panel():
    global _APP
    _APP = QApplication.instance() or QApplication([])
    owner = QDialog()
    font = owner.font()
    font.setPointSizeF(font.pointSizeF() * 1.35)
    owner.setFont(font)
    area = QScrollArea()
    area.setWidgetResizable(True)
    page = QWidget()
    layout = QVBoxLayout(page)
    activities = ActionActivities(page, publish_global=False)
    view = ActionProgressView(activities, page)
    layout.addWidget(view)
    layout.addStretch()
    area.setWidget(page)
    QVBoxLayout(owner).addWidget(area)
    owner.show()
    yield owner, area, page, view, activities
    activities.close()
    owner.close()
    owner.deleteLater()
    QApplication.processEvents()


def _settle():
    for _index in range(4):
        QApplication.processEvents()


def _fits(area, page, view):
    viewport = area.viewport()
    assert area.horizontalScrollBar().maximum() == 0
    assert page.width() <= viewport.width()
    assert view.isVisibleTo(page) and view.caption.isVisibleTo(page)
    for child in (view, view.ring, view.caption):
        left = child.mapTo(viewport, QPoint(0, 0)).x()
        assert 0 <= left and left + child.width() <= viewport.width()
    assert view.caption.width() > 0
    assert view.caption.height() + 1 >= view.caption.heightForWidth(view.caption.width())
    assert view.caption.heightForWidth(view.caption.width()) <= view.height()
    assert not view.ring.geometry().intersects(view.caption.geometry())


@pytest.mark.parametrize("width", [240, 360, 480])
def test_visible_local_action_full_caption_fits_narrow_viewport(panel, width):
    owner, area, page, view, activities = panel
    owner.resize(width, 800)
    label = "Installed startup: status…"
    handle = activities.begin("status", label, done=1, total=4)
    _settle()
    _fits(area, page, view)
    assert view.caption.text() == label
    assert view.caption.font() == owner.font()
    assert view.ring.percent == 25 and view.ring.busy
    assert activities.snapshot() == {
        "label": label, "done": 1, "total": 4, "active_count": 1, "serial": handle.serial}


def test_long_visible_caption_and_action_count_wrap_on_resize_without_restarting(panel):
    owner, area, page, view, activities = panel
    first = activities.begin("first", "Checking installed startup")
    label = "Recording the current verification result and preserving the existing administrator startup settings for review"
    second = activities.begin("second", label, done=3, total=6)
    original_font = view.caption.font()
    snapshot = activities.snapshot()
    for width in (960, 480, 360, 240, 960):
        owner.resize(width, 800)
        _settle()
        _fits(area, page, view)
        assert view.caption.text() == label + " · 2 actions active"
        assert view.caption.font() == original_font
        assert activities.snapshot() == snapshot
        assert view.ring.percent == 50 and view.ring.busy
    assert activities.finish(second)
    _settle()
    assert view.caption.text() == "Checking installed startup"
    assert activities.snapshot()["serial"] == first.serial
    assert activities.finish(first)
    _settle()
    assert view.isHidden() and activities.snapshot() == {}


def test_measured_complete_keeps_wrapped_running_view_below100_until_exact_finish(panel):
    owner, area, page, view, activities = panel
    owner.resize(240, 800)
    label = "Installed startup: status…"
    handle = activities.begin("status", label, done=1, total=1)
    _settle()
    _fits(area, page, view)
    assert view.ring.percent == 99 and view.ring.busy
    assert view.caption.text() == label and activities.snapshot()["serial"] == handle.serial
    assert activities.finish(handle)
    _settle()
    assert view.isHidden() and not view.ring.busy
