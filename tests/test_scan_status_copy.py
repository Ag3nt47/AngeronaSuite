"""Measured scan-status presentation and retained Qt reader position."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QScrollArea

from angerona.gui.curated_tools import ScanStepRow, SpywareScanControls
from angerona.gui.theme import build_qss


@pytest.fixture(scope="module", autouse=True)
def _application():
    application = QApplication.instance() or QApplication([])
    yield application


class _MemoryController(QObject):
    status_changed = Signal(dict)

    def __init__(self, snapshot):
        super().__init__()
        self.manager = SimpleNamespace(cfg=SimpleNamespace(ui_motion_enabled=False))
        self.value = snapshot

    def snapshot(self):
        return deepcopy(self.value)

    def cancel(self):
        pytest.fail("Presentation tests must not dispatch a scan action")


def _snapshot(native_state="completed", *, finished=("preflight",), planned=None):
    return dict(
        state="running", busy=True, lifecycle="running", timeout_seconds=3600,
        elapsed_seconds=200,
        scan_progress=dict(unit="workflow_stages", request_id="a" * 32,
                           stage="toolkit", finished=len(finished), total=4,
                           planned_stages=planned or ("preflight", "native", "toolkit", "aggregation"),
                           finished_stages=finished),
        scanner_progress=dict(
            native=dict(state=native_state, overall_percent=100,
                        completed_steps=4, total_steps=4, steps=[]),
            toolkit=dict(state="running", overall_percent=0,
                         completed_steps=0, total_steps=5,
                         current_step="browser", current_task="Reading supported browser evidence",
                         current_file="D:/synthetic-owned-fixture/History", remaining_s=None,
                         steps=[dict(id="browser", label="Browser and application checks", state="running",
                                     completed=0, total=None, unit="checks", checked=13225, skipped=1,
                                     elapsed_s=200, remaining_s=None)])))


def test_unknown_browser_total_uses_observed_count_without_fabricated_percent_or_eta():
    step = _snapshot()["scanner_progress"]["toolkit"]["steps"][0]
    original = deepcopy(step)
    row = ScanStepRow()
    try:
        row.apply("Zero-Breach", step)
        assert "checked 13,225 · total unknown" in row.count.text()
        assert row.count.text().count("checked 13,225") == 1
        assert "0 checks processed" not in row.count.text()
        assert "skipped 1" in row.count.text()
        assert "ETA Calculating" in row.count.text()
        assert row.bar.format() == "Indeterminate · no known total"
        assert step == original
    finally:
        row.deleteLater()


@pytest.mark.parametrize("completed,total,unit,expected", [
    (120, 240, "records", "120/240 records"),
    (20, None, "files", "20 files processed · total unknown"),
])
def test_known_count_and_other_measured_units_are_preserved(completed, total, unit, expected):
    row = ScanStepRow()
    try:
        step = dict(state="running", completed=completed, total=total, unit=unit,
                    checked=120, skipped=0, remaining_s=None)
        row.apply("Zero-Breach", step)
        assert expected in row.count.text()
        assert "checked 120" in row.count.text()
        assert row.bar.format() == ("50%" if total else "Indeterminate · no known total")
    finally:
        row.deleteLater()


def test_native_finished_copy_preserves_workflow_fraction_and_input_authority():
    value = _snapshot()
    original = deepcopy(value)
    controller = _MemoryController(value)
    panel = SpywareScanControls(controller.manager, controller=controller)
    try:
        chip = panel.stage_chips["native"]
        assert chip.text() == "Native · checks finished"
        assert "report aggregation is pending" in chip.toolTip()
        assert "report aggregation pending" in chip.accessibleName()
        assert "#38bdf8" in chip.styleSheet()  # informational, not finalized green
        assert "report aggregation is pending" in panel.stage_explanation.text()
        assert "wait for remaining native work" not in panel.stage_explanation.text()
        assert panel.progress_ring.percent == 50  # existing measured fraction
        assert "1/4 stages finished" in panel.progress_count.text()
        assert controller.value == original and value == original

        accepted = deepcopy(value)
        accepted["scan_progress"].update(finished=2, finished_stages=("preflight", "native"))
        panel._apply(accepted)
        assert chip.text() == "Native"
        assert chip.accessibleName() == "Native: finished"
        assert "#4ade80" in chip.styleSheet()
        assert panel.progress_ring.percent == 50
        assert "2/4 stages finished" in panel.progress_count.text()
    finally:
        panel._clock.stop()
        panel.deleteLater()


@pytest.mark.parametrize("native_state", ["queued", "running", "cancelling", "cancelled", "incomplete", "failed", "unavailable"])
def test_noncompleted_native_state_never_gets_checks_finished_copy(native_state):
    controller = _MemoryController(_snapshot(native_state))
    panel = SpywareScanControls(controller.manager, controller=controller)
    try:
        assert panel.stage_chips["native"].text() == "Native"
        assert "checks finished" not in panel.stage_chips["native"].accessibleName()
        assert "#4ade80" not in panel.stage_chips["native"].styleSheet()
        assert controller.value["scan_progress"]["finished_stages"] == ("preflight",)
    finally:
        panel._clock.stop()
        panel.deleteLater()


def test_unselected_or_new_request_resets_native_copy_without_inheriting_completion():
    controller = _MemoryController(_snapshot())
    panel = SpywareScanControls(controller.manager, controller=controller)
    try:
        assert "checks finished" in panel.stage_chips["native"].text()
        new = _snapshot("queued")
        new["scan_progress"]["request_id"] = "b" * 32
        new["scanner_progress"].pop("native")
        panel._apply(new)
        assert panel.stage_chips["native"].text() == "Native"
        assert panel.stage_chips["native"].accessibleName() == "Native: pending"

        unselected = _snapshot(planned=("preflight", "toolkit", "aggregation"))
        panel._apply(unselected)
        assert panel.stage_chips["native"].accessibleName() == "Native: not scheduled"
    finally:
        panel._clock.stop()
        panel.deleteLater()


@pytest.mark.parametrize("state,lifecycle", [("cancelled", "draining"), ("timed-out", "running"), ("failed", "running")])
def test_failure_and_cancellation_explanations_keep_priority(state, lifecycle):
    value = _snapshot()
    value.update(state=state, lifecycle=lifecycle)
    controller = _MemoryController(value)
    panel = SpywareScanControls(controller.manager, controller=controller)
    try:
        assert "report aggregation is pending" not in panel.stage_explanation.text()
        if state == "timed-out":
            assert "incomplete coverage" in panel.stage_explanation.text()
        assert value["scan_progress"]["finished_stages"] == ("preflight",)
    finally:
        panel._clock.stop()
        panel.deleteLater()


@pytest.mark.parametrize("width,scale", [(480, 1.0), (640, 1.0), (640, 1.35)])
def test_progress_copy_fits_narrow_real_qt_viewport_and_keeps_reader_widget(width, scale):
    controller = _MemoryController(_snapshot())
    panel = SpywareScanControls(controller.manager, controller=controller)
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(panel)
    area.setStyleSheet(build_qss(scale=scale))
    area.resize(width, 720)
    area.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        assert area.horizontalScrollBar().maximum() == 0
        original_row = panel.step_rows["toolkit:browser"]
        position = area.verticalScrollBar().maximum() // 2
        area.verticalScrollBar().setValue(position)
        newer = _snapshot()
        newer["scanner_progress"]["toolkit"]["steps"][0]["checked"] = 13226
        panel._apply(newer)
        for _ in range(4):
            QApplication.processEvents()
        assert area.horizontalScrollBar().maximum() == 0
        assert panel.step_rows["toolkit:browser"] is original_row
        assert area.verticalScrollBar().value() == position
        assert "checked 13,226" in original_row.count.text()
        assert "report aggregation is pending" in panel.stage_chips["native"].toolTip()
    finally:
        panel._clock.stop()
        area.close()
        area.deleteLater()
