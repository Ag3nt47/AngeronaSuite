from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtGui import QImage, QPainter, QWheelEvent
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest

from angerona.core.eventbus import EventBus
from angerona.core.suite_topology import SuiteTopologyService
from angerona.gui.suite_map import SuiteMapDialog


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


class CachedService:
    def __init__(self, snapshot):
        self.value, self.closed, self.starts = snapshot, False, 0
    def snapshot(self): return self.value
    def start(self): self.starts += 1; self.closed = False; return True
    def request_shutdown(self): self.closed = True
    def owned_workers(self): return ()
    def custody_released(self): return self.closed


def scene():
    class Fixture:
        description = "Example module description"
        capability_outputs = ("fixture",)
    fixture = Fixture()
    fixture.__dict__.update(_status="running", health=90, health_note="fixture")
    service = SuiteTopologyService(SimpleNamespace(modules={"Example module": fixture}), EventBus())
    return service._build()


def test_scene_renders_navigates_and_zoom_is_bounded(app):
    service = CachedService(scene())
    routes = []
    dialog = SuiteMapDialog(None, None, service=service, navigate=lambda *args: routes.append(args))
    dialog.resize(1024, 650)
    dialog.show()
    app.processEvents()
    image = QImage(dialog.canvas.size(), QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    dialog.canvas.render(painter, QPoint())
    painter.end()
    assert dialog.canvas._hits
    node = next(node for node in scene().nodes if node.route == "module")
    dialog._select(node)
    dialog.go.click()
    assert routes == [("module", "Example module")]
    assert "Example module" in dialog.details.toPlainText()
    event = QWheelEvent(QPointF(10,10), QPointF(10,10), QPoint(0,0), QPoint(0,12000),
        Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
    dialog.canvas.wheelEvent(event)
    assert .3 <= dialog.canvas.zoom <= 4.5
    dialog.close()
    app.processEvents()
    assert service.closed
    assert not dialog.canvas._timer.isActive()
    assert not dialog._timer.isActive()


def test_filter_and_refresh_retain_selection_and_inspection_scroll(app):
    service = CachedService(scene())
    dialog = SuiteMapDialog(None, None, service=service, navigate=lambda *_: None)
    dialog.show()
    app.processEvents()
    node = next(node for node in scene().nodes if node.route == "module")
    dialog._select(node)
    dialog.search.setText("Example")
    dialog._refresh()
    assert dialog.listing.count() == 1
    assert dialog._selection.id == node.id
    before = dialog.details.toPlainText()
    dialog._refresh()
    assert dialog.details.toPlainText() == before
    dialog.flows.setChecked(False)
    assert not dialog.canvas.animate
    dialog.close()
    app.processEvents()


def test_hover_data_is_escaped_plain_tooltip(app):
    from angerona.core.suite_topology import TopologyNode
    dialog = SuiteMapDialog(None, None, service=CachedService(scene()))
    node = TopologyNode("x", '<img src="file:///private">', "module", "unknown", None, (0,0,0), (("Name", "<script>"),))
    dialog.canvas._hits = []
    dialog._select(node)
    assert '<img src="file:///private">' in dialog.details.toPlainText()
    assert not dialog.go.isEnabled()
    dialog.close()


def test_reduced_motion_stops_animation_timer_and_tracks_policy_changes(app, monkeypatch):
    monkeypatch.setattr("angerona.gui.suite_map.motion_allowed", lambda config: config.ui_motion_enabled)
    config = SimpleNamespace(ui_motion_enabled=False)
    dialog = SuiteMapDialog(None, None, service=CachedService(scene()), config=config)
    dialog.show()
    app.processEvents()
    assert not dialog.flows.isEnabled()
    assert not dialog.canvas.animate
    assert not dialog.canvas._timer.isActive()
    config.ui_motion_enabled = True
    dialog._refresh()
    assert dialog.flows.isEnabled()
    assert not dialog.flows.isChecked()
    dialog.flows.setChecked(True)
    assert dialog.canvas._timer.isActive()
    config.ui_motion_enabled = False
    dialog._refresh()
    assert not dialog.canvas._timer.isActive()
    dialog.close()
