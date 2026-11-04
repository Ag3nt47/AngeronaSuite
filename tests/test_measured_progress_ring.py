from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import QApplication

from angerona.gui.animations import (
    GlobalLoadingIndicator, begin_loading, finish_loading, update_loading,
)
from angerona.gui.curated_tools import ScanProgressRing
from angerona.gui.progress_ring import ProgressRing, color_for_pct


@pytest.fixture
def ring(monkeypatch):
    from angerona.gui import header_controls

    monkeypatch.setattr(header_controls, "motion_allowed", lambda config=None:
                        bool(getattr(config, "ui_motion_enabled", True)))
    item = ProgressRing(SimpleNamespace(ui_motion_enabled=True))
    try:
        yield item
    finally:
        item.set_state(None, None, False)
        item.close()
        item.deleteLater()
        QApplication.processEvents()


@pytest.mark.parametrize("done,total,expected", [(0, 4, 0), (1, 4, 25), (2, 4, 50),
                                                (3, 4, 75), (4, 4, 99)])
def test_progress_is_measured_and_running_completion_is_not_terminal(ring, done, total, expected):
    ring.set_state(done, total, True)
    assert ring.percent == expected and ring.busy
    assert ring.progress_color == color_for_pct(expected)
    for _ in range(20):
        ring._rotate()
    assert ring.percent == expected
    assert "does not establish successful containment" in ring.toolTip()
    ring.set_state(done, total, False)
    assert ring.percent == done * 100 // total
    assert not ring._timer.isActive()


@pytest.mark.parametrize("done,total", [(None, None), (0, 0), (1, 0), (-1, 4),
                                       (5, 4), (True, 4), (1, True), (1.0, 4),
                                       (1, 1_000_001)])
def test_invalid_counts_are_unknown_and_cannot_reuse_previous_percentage(ring, done, total):
    ring.set_state(3, 4, True)
    ring.set_state(done, total, True)
    assert ring.percent is None and ring.busy
    assert "unavailable" in ring.accessibleName()
    assert ring.progress_color.name() == "#38bdf8"


@pytest.mark.parametrize("fraction", [None, True, float("nan"), float("inf"), -0.1, 1.1,
                                     pytest.param(10**1000, id="overflow-sized-fraction")])
def test_invalid_fraction_does_not_turn_into_a_percentage(ring, fraction):
    ring.set_fraction(0.75, True)
    assert ring.percent == 75
    ring.set_fraction(fraction, True)
    assert ring.percent is None


def test_motion_sleeps_hidden_and_respects_reduced_motion(ring):
    ring.set_state(1, 4, True)
    assert not ring._timer.isActive()
    ring.show()
    QApplication.processEvents()
    assert ring._timer.isActive()
    ring.hide()
    QApplication.processEvents()
    assert not ring._timer.isActive()
    ring.show()
    QApplication.processEvents()
    assert ring._timer.isActive()
    ring.config.ui_motion_enabled = False
    ring.set_state(2, 4, True)
    assert not ring._timer.isActive()
    assert ring.percent == 50


def test_shared_palette_and_spyware_name_remain_compatible():
    assert color_for_pct(0).getRgb()[:3] == (255, 77, 77)
    assert color_for_pct(50).getRgb()[:3] == (255, 176, 32)
    assert color_for_pct(100).getRgb()[:3] == (47, 227, 138)
    item = ScanProgressRing(SimpleNamespace(ui_motion_enabled=False))
    try:
        assert isinstance(item, ProgressRing)
        item.set_fraction(1, False)
        assert item.percent == 100
        assert item.progress_color == color_for_pct(100)
        assert item.width() >= 68 and item.height() >= 68
        font = item.font()
        font.setPointSize(22)
        item.setFont(font)
        metrics = QFontMetrics(font)
        assert item.width() >= metrics.horizontalAdvance("100%") + 24
        assert item.height() >= metrics.height() + 24
    finally:
        item.close()
        item.deleteLater()
        QApplication.processEvents()


def test_global_latest_activity_and_overlap_do_not_blend_unrelated_percentages():
    item = GlobalLoadingIndicator()
    first = second = None
    try:
        first = begin_loading("Known operation", done=3, total=4)
        second = begin_loading("Unknown operation")
        QApplication.processEvents()
        assert item.active_count == 2 and item._ring.percent is None
        update_loading(first, done=4, total=4)
        QApplication.processEvents()
        assert item._ring.percent is None
        finish_loading(second)
        second = None
        QApplication.processEvents()
        assert item.active_count == 1 and item._ring.percent == 99
        assert item._ring.busy and item._ring.progress_color == color_for_pct(99)
        assert item.current_text == "Known operation  4/4"
        update_loading(first, "Still settling")
        QApplication.processEvents()
        assert item._ring.percent == 99
        update_loading(first, "Unknown new phase", done=0, total=0)
        QApplication.processEvents()
        assert item._ring.percent is None
        assert item.current_text == "Unknown new phase"
        finish_loading(first)
        first = None
        QApplication.processEvents()
        assert item.active_count == 0 and item.isHidden()
        assert not item._ring.busy and not item._ring._timer.isActive()
    finally:
        finish_loading(first)
        finish_loading(second)
        item.close()
        item.deleteLater()
        QApplication.processEvents()


@pytest.mark.parametrize("extent", [28, 34, 36])
def test_compact_global_ring_fits_reserved_width_with_visible_measured_center(extent):
    item = GlobalLoadingIndicator()
    token = None
    try:
        item.set_compact(True, extent)
        token = begin_loading("Measured action", done=1, total=4)
        QApplication.processEvents()
        item._reveal_if_active()
        QApplication.processEvents()
        assert item.minimumWidth() == item.maximumWidth() == extent
        assert item.rect().contains(item._ring.geometry())
        assert item._ring.percent == 25 and item._label.isHidden()
    finally:
        finish_loading(token)
        item.close()
        item.deleteLater()
        QApplication.processEvents()
