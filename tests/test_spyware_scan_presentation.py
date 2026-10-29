"""Readable scan presentation with inert status copies and no host actions."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, QPoint, QPointF, QRect, Qt, Signal
from PySide6.QtGui import QFontDatabase, QWheelEvent
from PySide6.QtWidgets import QApplication, QDialog, QGroupBox, QVBoxLayout

from angerona.gui import curated_tools as ui
from angerona.gui.spyware_guard_page import SpywareGuardPage
from angerona.gui.theme import build_qss
from test_spyware_guard_page import FakeModule


class MemoryController(QObject):
    status_changed = Signal(dict)
    credits_ready = Signal(object)
    settings_saved = Signal()

    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self._closed = False
        self.requests = []
        self.cancels = 0
        self.value = dict(state="ready", busy=False, installed=True, verified=True,
                          version="0.1.10", execution_available=True)

    def snapshot(self):
        return copy.deepcopy(self.value)

    def publish(self, **values):
        self.value.update(values)
        self.status_changed.emit(self.snapshot())

    def priority_scan(self, **options):
        self.requests.append(options)
        return True

    def cancel(self):
        self.cancels += 1

    def prepare(self): pass
    def scan(self, **_kwargs): pass
    def load_credits(self): pass
    def self_test(self): pass
    def open_tool(self): pass
    def revert(self): pass
    def save_options(self, _values): pass
    def clear_reports(self): pass


@pytest.fixture
def memory(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Scan presentation cannot dispatch host work")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    module = FakeModule()
    config = SimpleNamespace(**module.snapshot["settings"], ui_motion_enabled=True,
                             spyware_scan_native_enabled=False, spyware_scan_zero_breach_enabled=True,
                             spyware_scan_priority="high", spyware_scan_cpu_percent=40,
                             spyware_scan_memory_mib=256)
    manager = SimpleNamespace(cfg=config, modules={"SpywareGuard": module})
    controller = MemoryController(manager)
    monkeypatch.setattr(ui, "get_curated_tools_controller", lambda _manager: controller)
    if sys.platform == "win32":
        for filename in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "seguiemj.ttf"):
            path = Path("C:/Windows/Fonts") / filename
            if path.is_file():
                assert QFontDatabase.addApplicationFont(str(path)) >= 0
    return controller, manager, config, module


def progress(finished=1, total=4, stage="toolkit"):
    return dict(request_id="a" * 32, unit="workflow_stages", stage=stage,
                finished=finished, total=total,
                planned_stages=("preflight", "native", "toolkit", "aggregation"),
                finished_stages=("preflight",))


def test_full_scope_is_explicit_and_saved_selections_survive_status_updates(memory):
    controller, manager, config, module = memory
    panel = ui.SpywareScanControls(manager)
    try:
        assert {group.title() for group in panel.findChildren(QGroupBox)} >= {
            "Scope", "Included checks", "Progress", "What's happening now", "Resource and privilege details",
        }
        assert "Entire PC" in panel.scope_button.text()
        assert not panel.native.isChecked() and panel.zero_breach.isChecked()
        assert panel.priority.currentData() == "high"
        assert panel.cpu.value() == 40 and panel.memory.value() == 256
        assert controller.requests == [] and module.calls == []
        assert panel.start()
        assert controller.requests[-1]["mode"] == "full"
        assert controller.requests[-1]["targets"] == ()
        assert controller.requests[-1]["native_enabled"] is False
        assert controller.requests[-1]["max_cpu_percent"] == 40
        panel._scope_actions["browser"].trigger()
        controller.publish(busy=True, scan_progress=progress())
        assert panel._scope_mode == "browser"
        assert panel.start()
        assert controller.requests[-1]["mode"] == "browser"
        assert config.spyware_scan_native_enabled is False
        assert module.calls == []
        panel._scope_actions["targeted"].trigger()
        before = len(controller.requests)
        assert not panel.start()
        assert len(controller.requests) == before
        assert "Choose local evidence" in panel.scope_error.text()
        panel.scope_paths.setPlainText("D:/synthetic/evidence")
        assert panel.start()
        assert controller.requests[-1]["targets"] == ("D:/synthetic/evidence",)
    finally:
        panel.close()


def test_scan_options_ignore_wheel_but_keep_click_and_keyboard_selection(memory):
    controller, manager, _, _ = memory
    widget = ui.CuratedScannerWidget(manager, controller=controller)
    try:
        assert widget.mode.currentData() == "full"
        for control in (widget.mode, widget.device, widget.priority_controls.priority,
                        widget.priority_controls.cpu, widget.priority_controls.memory):
            before = control.currentIndex() if hasattr(control, "currentIndex") else control.value()
            event = QWheelEvent(QPointF(10, 10), QPointF(10, 10), QPoint(), QPoint(0, -120),
                                Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                                Qt.ScrollPhase.NoScrollPhase, False)
            control.wheelEvent(event)
            after = control.currentIndex() if hasattr(control, "currentIndex") else control.value()
            assert after == before
            assert not event.isAccepted()  # The surrounding scroll view retains the gesture.
        widget.mode.setCurrentIndex(widget.mode.findData("browser"))
        assert widget.mode.currentData() == "browser"
        assert "#b91c1c" in widget.priority_button.styleSheet()
    finally:
        widget.close()


@pytest.mark.parametrize("work", [QRect(-1920, 0, 1536, 816), QRect(-1920, 0, 640, 480)])
def test_real_github_hub_keeps_all_tabs_and_scope_edits_inside_work_area(memory, work):
    controller, manager, _, _ = memory
    dialog = ui.GitHubToolsDialog(manager)
    dialog.screen = lambda: SimpleNamespace(availableGeometry=lambda: QRect(work))
    dialog.setStyleSheet(build_qss(scale=1.1))
    try:
        dialog.show()
        dialog.scanner.targets.setPlainText("D:/synthetic/kept-evidence")
        dialog.scanner.mode.setCurrentIndex(dialog.scanner.mode.findData("browser"))
        for index in range(dialog.tabs.count()):
            dialog.tabs.setCurrentIndex(index)
            QApplication.processEvents()
            dialog._window_fit.fit_now(work)
            assert work.contains(dialog.frameGeometry())
            assert dialog.tabs.currentIndex() == index
        assert dialog.tabs.count() == 3
        assert dialog.scanner.mode.currentData() == "browser"
        assert dialog.scanner.targets.toPlainText() == "D:/synthetic/kept-evidence"
        assert controller.requests == []
    finally:
        dialog.retire_view()
        dialog.deleteLater()


def test_progress_uses_only_stage_counters_and_stops_animation_when_hidden(memory, monkeypatch):
    controller, manager, config, _ = memory
    from angerona.gui import header_controls
    monkeypatch.setattr(header_controls, "_windows_client_animations_enabled", lambda: True)
    monkeypatch.delenv("ANGERONA_REDUCE_MOTION", raising=False)
    panel = ui.SpywareScanControls(manager)
    panel.show()
    QApplication.processEvents()
    try:
        controller.publish(busy=True, scan_progress=progress(),
                           message="Untrusted toolkit says <b>100% complete</b>",
                           resource_usage={"cpu_percent": 80, "rss_mib": 512,
                                           "read_bytes": 1024**2, "write_bytes": 0})
        assert panel.progress_ring.percent == 25
        assert "Toolkit process · liveness unavailable · latest available sample" in panel.resources.text()
        assert "1/4" in panel.progress_count.text()
        assert "exact file completion is unavailable" in panel.stage_explanation.text()
        assert panel.stage_explanation.textFormat() == Qt.TextFormat.PlainText
        assert panel.progress_ring._timer.isActive()
        for _ in range(5):
            panel.progress_ring._rotate()
        controller.publish(resource_usage={"cpu_percent": 90, "rss_mib": 1024})
        assert panel.progress_ring.percent == 25
        assert "100% complete" not in panel.stage_explanation.text()
        controller.publish(scan_progress=progress(finished=True))
        assert panel.progress_ring.percent is None
        assert "Indeterminate" in panel.progress_count.text()
        controller.publish(scan_progress=progress(2), admin_state={"verified": True, "elevated": False,
                                                                 "integrity": "medium"})
        assert panel.progress_ring.percent == 50
        assert "Ordinary-user token" in panel.privileges.text()
        assert "No new authority" in panel.privileges.text()
        controller.publish(busy=False, state="incomplete", scan_progress=progress(4, stage="finished"))
        assert panel.progress_ring.percent == 100
        assert "incomplete coverage" in panel.progress_stage.text()
        assert "held, unavailable or did not complete" in panel.stage_explanation.text()
        assert "do not establish a clean PC" in panel.stage_explanation.text()
        controller.publish(resource_usage={"process_alive": False, "cpu_percent": 12, "rss_mib": 48})
        assert "Toolkit process · stopped · latest available sample" in panel.resources.text()
        assert "12.0%" in panel.resources.text()
        panel.explanation_toggle.setChecked(True)
        assert panel.explanation_details.isVisible()
        assert "External toolkit findings remain leads" in panel.explanation_details.text()
        config.ui_motion_enabled = False
        controller.publish(busy=True, scan_progress=progress(2))
        assert not panel.progress_ring._timer.isActive()
        panel.hide()
        assert not panel.progress_ring._timer.isActive()
        assert panel.progress_ring.percent == 50
    finally:
        panel.close()


@pytest.mark.parametrize("width,height", [(1536, 816), (1092, 582), (640, 480)])
def test_real_spyware_workspace_fits_with_scroll_and_preserves_tabs_and_edits(memory, width, height):
    controller, manager, config, module = memory
    dialog = QDialog()
    dialog.setMinimumSize(560, 420)
    dialog.resize(1080, 900)
    work = QRect(-1920, 0, width, height)
    dialog.screen = lambda: SimpleNamespace(availableGeometry=lambda: QRect(work))
    layout = QVBoxLayout(dialog)
    page = SpywareGuardPage(manager, config, None, dialog)
    layout.addWidget(page)
    dialog.setStyleSheet(build_qss(scale=1.1))
    try:
        dialog.show()
        for _ in range(5):
            QApplication.processEvents()
            page._window_fit.fit_now(work)
        assert work.contains(dialog.frameGeometry()), (work, dialog.frameGeometry())
        assert page._window_fit.scroll_area is not None
        assert "#b91c1c" in page.scan_button.styleSheet()
        assert page.tabs.count() == 7
        page.priority_scan.scope_paths.setPlainText("D:/synthetic/kept-evidence")
        page.priority_scan._scope_actions["browser"].trigger()
        for index in range(page.tabs.count()):
            page.tabs.setCurrentIndex(index)
            QApplication.processEvents()
            page._window_fit.fit_now(work)
            assert page.tabs.currentIndex() == index
            assert work.contains(dialog.frameGeometry())
        scroll = page._window_fit.scroll_area
        scroll.ensureWidgetVisible(page.tabs, 0, 0)
        QApplication.processEvents()
        assert QRect(page.tabs.mapTo(scroll.viewport(), QPoint()), page.tabs.size()).intersects(scroll.viewport().rect())
        page.priority_scan.explanation_toggle.setChecked(True)
        QApplication.processEvents()
        page._window_fit.fit_now(work)
        assert work.contains(dialog.frameGeometry())
        assert page.priority_scan._scope_mode == "browser"
        assert page.priority_scan.scope_paths.toPlainText() == "D:/synthetic/kept-evidence"
        assert controller.requests == [] and module.calls == []
        assert config.spyware_scan_cpu_percent == 40
    finally:
        page.close()
        dialog.close()
        dialog.deleteLater()


def test_reader_rows_show_real_counts_unknown_eta_and_keep_widgets_and_scroll(memory):
    controller, manager, config, _ = memory
    panel = ui.SpywareScanControls(manager)
    panel.resize(620, 700)
    panel.show()
    steps = [dict(id=f"reader-{index}", label=f"Synthetic reader {index}", state="running" if index == 3 else "pending",
                  completed=25 if index == 3 else 0, total=100 if index == 3 else None,
                  percent=None, unit="records", elapsed_s=12, remaining_s=None)
             for index in range(12)]
    value = dict(operation_id="a" * 32, state="running", current_task="Read observed browser records",
                 current_file="D:/synthetic/<literal>/History", overall_percent=25, elapsed_s=12,
                 remaining_s=None, steps=steps)
    try:
        controller.publish(busy=True, scan_progress=progress(), timeout_seconds=600,
                           scanner_progress={"toolkit": value})
        QApplication.processEvents()
        row = panel.step_rows["toolkit:reader-3"]
        assert row.bar.value() == 25 and "25/100 records" in row.count.text()
        assert "ETA Calculating" in row.count.text()
        assert "Read observed browser records" in panel.activity.text()
        assert "D:/synthetic/<literal>/History" in panel.current_file.text()
        assert panel.current_file.textFormat() == Qt.TextFormat.PlainText
        assert "time budget 600s" in panel.timing.text() and "Calculating" in panel.timing.text()
        assert panel.progress_ring.percent < 100
        panel.steps_scroll.verticalScrollBar().setValue(80)
        position = panel.steps_scroll.verticalScrollBar().value()
        value["steps"][3]["completed"] = 30
        controller.publish(scanner_progress={"toolkit": value})
        assert panel.step_rows["toolkit:reader-3"] is row
        assert row.bar.value() == 30
        assert panel.steps_scroll.verticalScrollBar().value() == position
        controller.publish(busy=False, state="timed-out", message="Time budget reached (600s). Synthetic reader deadline.")
        assert "Time budget reached" in panel.progress_stage.text()
        assert "600s" in panel.outcome.text()
        assert panel.step_rows["toolkit:reader-3"] is row
        assert "no scan is running" not in panel.activity.text()  # Last observed task is retained.
        assert "incomplete coverage" in panel.stage_explanation.text()
        assert not panel.cancel_button.isEnabled()
        assert not panel.progress_ring._timer.isActive()
        panel.budget.setValue(900)
        assert panel.start()
        assert controller.requests[-1]["timeout_seconds"] == 900
        assert not hasattr(config, "github_tools_timeout_seconds")
    finally:
        panel.close()


def test_active_or_draining_workflow_never_displays_one_hundred_percent(memory):
    controller, manager, _, _ = memory
    panel = ui.SpywareScanControls(manager)
    try:
        controller.publish(busy=True, scan_progress=progress(4, stage="aggregation"), lifecycle="draining")
        assert panel.progress_ring.percent == 99
        assert "Stopping" in panel.progress_stage.text()
        assert panel.cancel_button.isEnabled()
        controller.publish(busy=False, state="completed", lifecycle="terminal", scan_progress=progress(4, stage="finished"))
        assert panel.progress_ring.percent == 100
    finally:
        panel.close()


def test_current_query_item_has_separate_real_percent_eta_and_neutral_units(memory):
    controller, manager, _, _ = memory
    panel = ui.SpywareScanControls(manager)
    value = dict(state="running", current_file="D:/synthetic/History", current_task="Process current query",
                 overall_percent=None, completed_steps=0, total_steps=8,
                 item_completed=40, item_total=100, item_unit="database rows processed", item_remaining_s=30,
                 remaining_s=None, steps=[])
    try:
        controller.publish(busy=True, scan_progress=progress(), scanner_progress={"toolkit": value})
        assert panel.item_progress.value() == 40 and "40%" in panel.item_progress.format()
        assert "40/100 database rows processed" in panel.item_caption.text()
        assert "item ETA 0:30" in panel.item_caption.text()
        assert "database rows processed read" not in panel.current_file.text()
        assert panel.progress_ring.percent == 25  # Current query is not whole-reader completion.
        assert "ETA Calculating" in panel.timing.text()
        value.update(item_completed=4096, item_total=8192, item_unit="bytes read", item_remaining_s=2)
        controller.publish(scanner_progress={"toolkit": value})
        assert panel.item_progress.value() == 50 and "4,096/8,192 bytes read" in panel.item_caption.text()
        value.update(item_total=None, item_remaining_s=None)
        controller.publish(scanner_progress={"toolkit": value})
        assert "indeterminate" in panel.item_progress.format()
        assert "4,096 observed" in panel.item_caption.text() and "Calculating" in panel.item_caption.text()
    finally:
        panel.close()


@pytest.mark.parametrize("state", ["running", "cancelled"])
def test_native_hash_step_includes_observed_partial_file_without_finishing_other_candidates(memory, state):
    row = ui.ScanStepRow()
    try:
        step = dict(id="hashes", label="Bounded file hashes", state=state, completed=1, total=4,
                    unit="candidate records", percent=99, item_completed=512, item_total=1024,
                    item_unit="bytes", percent_basis="completed candidate slots plus current file byte fraction")
        row.apply("Native SpywareGuard", step)
        assert row.bar.value() == 37 and row.bar.format() == "37.5%"
        assert "1/4 candidate records" in row.count.text()
        assert "includes this current-file byte fraction" in row.count.text()
        step["item_completed"] = 1024
        row.apply("Native SpywareGuard", step)
        assert row.bar.value() == 50  # One settled slot + one observed file's bytes, not all four.
        row.apply("Zero-Breach", step)
        assert row.bar.value() == 25  # A file/query item cannot advance an entire toolkit reader.
    finally:
        row.close()


@pytest.mark.parametrize("item_done,item_total", [
    (True, 1024), (512, False), (-1, 1024), (1025, 1024),
    (float("nan"), 1024), (512, float("inf")), (512, 0), (512, 17 * 1024**2),
])
def test_malformed_partial_file_counts_cannot_inflate_native_step_percent(memory, item_done, item_total):
    row = ui.ScanStepRow()
    try:
        row.apply("Native SpywareGuard", dict(id="hashes", state="running", completed=1, total=4,
                  unit="candidate records", percent=99, item_completed=item_done, item_total=item_total,
                  item_unit="bytes", percent_basis="completed candidate slots plus current file byte fraction"))
        assert row.bar.value() == 25 and row.bar.format() == "25%"
    finally:
        row.close()


@pytest.mark.parametrize("ended_state", ["completed", "timed-out", "cancelled", "failed"])
def test_retired_toolkit_rows_are_not_run_while_native_request_still_drains(memory, ended_state):
    controller, manager, _, _ = memory
    panel = ui.SpywareScanControls(manager)
    try:
        native = dict(state="cancelling", current_task="Finishing an owned native collector", steps=[
            dict(id="persistence", label="Persistence", state="running", completed=0, total=1),
            dict(id="processes", label="Processes", state="pending", completed=0, total=None)])
        toolkit = dict(state=ended_state, current_file="D:/synthetic/History", steps=[
            dict(id="history", label="History", state="running", completed=20, total=100),
            dict(id="cookies", label="Cookies", state="queued", completed=0, total=None),
            dict(id="logs", label="Logs", state="pending", completed=0, total=None)])
        controller.publish(busy=True, state="stopping", lifecycle="draining", scan_progress=progress(),
                           scanner_progress={"native": native, "toolkit": toolkit})
        assert "running" in panel.step_rows["native:persistence"].caption.text()
        assert "pending" in panel.step_rows["native:processes"].caption.text()
        assert "Interrupted" in panel.step_rows["toolkit:history"].caption.text()
        assert panel.step_rows["toolkit:history"].bar.value() == 20
        assert "Not run" in panel.step_rows["toolkit:cookies"].caption.text()
        assert "Not run" in panel.step_rows["toolkit:logs"].caption.text()
        assert "Calculating" not in panel.step_rows["toolkit:logs"].count.text()
        assert panel.cancel_button.isEnabled()  # Native collector remains owned and active.
        assert panel.progress_ring.percent < 100
    finally:
        panel.close()


def test_longer_per_run_choice_preserves_saved_limit_and_completed_scanner_reaches_100(memory):
    controller, manager, config, _ = memory
    before = copy.deepcopy(vars(config))
    panel = ui.SpywareScanControls(manager)
    try:
        assert panel.budget.minimum() == 30 and panel.budget.maximum() == 14400
        assert panel.budget.value() == 300
        assert ui._LIMITS["github_tools_timeout_seconds"][1:] == (300, 30, 900)
        panel.budget.setValue(14400)
        assert panel.start()
        assert controller.requests[-1]["timeout_seconds"] == 14400
        assert vars(config) == before
        controller.publish(busy=True, scan_progress=progress(4, stage="aggregation"), scanner_progress={
            "native": {"state": "completed", "overall_percent": 100, "steps": []},
            "toolkit": {"state": "running", "overall_percent": 100, "steps": []},
        })
        assert "100%" in panel.scanner_summaries["native"].text()
        assert "99%" in panel.scanner_summaries["toolkit"].text()
        assert panel.progress_ring.percent < 100
        controller.publish(scanner_progress={
            "native": {"state": "running", "overall_percent": 100, "steps": []},
            "toolkit": {"state": "completed", "overall_percent": 100, "steps": []},
        })
        assert "99%" in panel.scanner_summaries["native"].text()
        assert "100%" in panel.scanner_summaries["toolkit"].text()
    finally:
        panel.close()
