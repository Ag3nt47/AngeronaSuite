"""Inert presentation counters; draft only until the canonical suite retires."""
from __future__ import annotations

import copy

import pytest
from PySide6.QtGui import QTextCursor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QProgressBar, QVBoxLayout, QWidget

from angerona.gui import curated_tools as ui
from angerona.gui import spyware_guard_page as spyware_ui
from angerona.gui.spyware_guard_page import SpywareGuardPage
from test_spyware_guard_page import news_rows
from test_spyware_scan_presentation import memory, progress  # noqa: F401 - imported pytest fixture


def process():
    QApplication.instance().processEvents()


@pytest.mark.parametrize("kind", ["controls", "scanner"])
@pytest.mark.parametrize("suspend", ["hide", "minimize"])
def test_scan_view_keeps_only_latest_hidden_status_and_restores_once(memory, monkeypatch, kind, suspend):
    controller, manager, _, _ = memory
    window = QDialog()
    view = (ui.SpywareScanControls(manager) if kind == "controls" else
            ui.CuratedScannerWidget(manager))
    QVBoxLayout(window).addWidget(view)
    controls = view if kind == "controls" else view.priority_controls
    controls._set_scope("targeted")
    controls.scope_paths.setPlainText("D:/synthetic/retained-evidence")
    controls.cpu.setValue(30)
    window.show()
    process()
    reader = dict(state="running", current_task="Synthetic reader", current_file="D:/synthetic/initial.txt",
                  steps=[dict(id="files", label="Files", state="running", completed=1, total=100)])
    controller.publish(busy=True, scan_progress=progress(), scanner_progress={"toolkit": reader})
    document = controls.current_file.editor.document()
    scope_document = controls.scope_paths.document()
    row = controls.step_rows["toolkit:files"]
    controls.current_file.setSelection(0, 7)
    selected = controls.current_file.selectedText()
    if suspend == "hide":
        window.hide()
    else:
        window.showMinimized()
    process()
    applied = []
    original_apply = view._apply
    monkeypatch.setattr(view, "_apply", lambda value: (applied.append(value), original_apply(value))[-1])
    monkeypatch.setattr(controller, "snapshot", lambda: pytest.fail("View read another controller snapshot"))
    wakeups = []
    for timer in (controls._clock, controls.progress_ring._timer):
        timer.timeout.connect(lambda: wakeups.append(1))
        assert not timer.isActive()
    try:
        for number in range(32):
            latest = copy.deepcopy(controller.value)
            latest.update(busy=number != 31, state="completed" if number == 31 else "running",
                          lifecycle="terminal" if number == 31 else "running",
                          message=f"Literal <b>frame {number}</b>",
                          scanner_progress={"toolkit": dict(reader, current_file=f"D:/synthetic/frame-{number}.txt")})
            controller.value = latest
            controller.status_changed.emit(copy.deepcopy(latest))
        controller.cancel()
        QTest.qWait(120)
        assert controller.cancels == 1
        assert applied == [] and wakeups == []
        assert view._presentation.latest == latest
        assert view._presentation._pending
        if suspend == "hide":
            window.show()
        else:
            window.showNormal()
        process()
        assert len(applied) == 1 and applied[0] == latest
        assert not view._presentation._pending
        assert controls.current_file.editor.document() is document
        assert controls.scope_paths.document() is scope_document
        assert controls.step_rows["toolkit:files"] is row
        assert controls.current_file.selectedText() == selected
        assert "frame-31.txt" in controls.current_file.text()
        assert controls._scope_mode == "targeted" and controls.cpu.value() == 30
        assert controls.scope_paths.toPlainText() == "D:/synthetic/retained-evidence"
        assert controller.requests == []
    finally:
        window.close()
        window.deleteLater()


def test_identical_visible_scan_status_does_not_rewrite_labels_styles_or_progress(memory, monkeypatch):
    controller, manager, _, _ = memory
    panel = ui.SpywareScanControls(manager)
    panel.show()
    process()
    reader = dict(state="running", steps=[dict(id="files", state="running", completed=1, total=100)])
    controller.publish(busy=True, scan_progress=progress(), scanner_progress={"toolkit": reader})
    calls = []
    for cls, name in ((QLabel, "setText"), (QWidget, "setStyleSheet"),
                      (QProgressBar, "setValue"), (QProgressBar, "setFormat")):
        method = getattr(cls, name)
        monkeypatch.setattr(cls, name, lambda widget, value, method=method, name=name: (
            calls.append(name), method(widget, value))[-1])
    try:
        for _ in range(10):
            controller.publish()
        assert calls == []
    finally:
        panel.close()


def test_identical_dashboard_refresh_skips_document_edits_and_qt_table_traversal(memory, monkeypatch):
    _, manager, config, module = memory
    page = SpywareGuardPage(manager, config, None)
    page.show()
    process()
    module.snapshot.update(revision=1,
                           hits=[dict(rule=f"rule-{i}", pid=i, severity="HIGH") for i in range(200)],
                           containments=[dict(target="synthetic", status="held")],
                           indicators=[dict(kind="sha256", value="a" * 64, approved=False,
                                            source_url="https://example.invalid/review", evidence_id="old")],
                           sources=[dict(url="https://example.invalid/research", state="unavailable")],
                           coverage={"rows": [f"coverage-{i}" for i in range(80)]},
                           sandbox={"rows": [f"sandbox-{i}" for i in range(80)]})
    page.refresh()
    page.indicators_table.selectRow(0)
    editors = (page.coverage, page.sandbox_results, page.definitions_preview)
    assert all(not editor.isUndoRedoEnabled() for editor in editors)
    documents = [editor.document() for editor in editors]
    cursor = page.coverage.textCursor()
    cursor.setPosition(2)
    cursor.setPosition(12, QTextCursor.MoveMode.KeepAnchor)
    page.coverage.setTextCursor(cursor)
    selection = (cursor.anchor(), cursor.position())
    changes, visits = [], []
    for editor in editors:
        editor.textChanged.connect(lambda: changes.append(1))
    for table in (page.hits_table, page.containments_table, page.sources_table, page.indicators_table):
        for name in ("item", "setRowCount", "currentRow"):
            method = getattr(table, name)
            monkeypatch.setattr(table, name, lambda *args, method=method, name=name: (
                visits.append(name), method(*args))[-1])
    try:
        reads = module.reads
        for _ in range(10):
            page.refresh()
        assert module.reads == reads + 10
        assert visits == [] and changes == []
        assert all(editor.document() is document for editor, document in zip(editors, documents))
        module.snapshot["coverage"]["rows"][0] = "changed coverage"
        module.snapshot["hits"][0]["rule"] = "changed rule"
        module.snapshot["indicators"][0]["evidence_id"] = "new"
        page._settings_dirty = True
        page._pending_settings = {"spyware_memory_enabled": True}
        module.snapshot["settings"]["spyware_memory_enabled"] = True
        page.refresh()
        assert module.snapshot["revision"] == 1
        assert visits and changes
        assert page.hits_table.item(0, 1).text() == "changed rule"
        assert page.indicators_table.currentRow() == -1
        assert page.coverage.document() is documents[0]
        cursor = page.coverage.textCursor()
        assert (cursor.anchor(), cursor.position()) == selection
        assert "changed coverage" in page.coverage.toPlainText()
        assert not page._settings_dirty and page._pending_settings is None
        assert page.setting_checks["spyware_memory_enabled"].isChecked()
    finally:
        page.close()


def test_unchanged_snapshot_still_rechecks_time_derived_news_eligibility(memory, monkeypatch):
    _, manager, config, module = memory
    now = [1_800_000_000.0]
    monkeypatch.setattr(spyware_ui.time, "time", lambda: now[0])
    good = news_rows(now[0])[0]
    module.snapshot.update(revision=1, news=[dict(good, published=now[0] - spyware_ui.MAX_NEWS_AGE + 1,
                                                verified_at=now[0] - 1)])
    module.snapshot["settings"]["spyware_network_enabled"] = True
    page = SpywareGuardPage(manager, config, None)
    page.show()
    process()
    try:
        assert page._news_items[0]["origin"] == "cached-feed"
        assert page._news_items[0]["stale"] is False
        now[0] += 2
        page.refresh()
        assert page._news_items[0]["stale"] is True
        assert "STALE CACHE" in page.news_badge.text()
        now[0] += spyware_ui.MAX_CACHED_NEWS_AGE
        page.refresh()
        assert all(item["origin"] != "cached-feed" for item in page._news_items)
        assert module.snapshot["revision"] == 1
    finally:
        page.close()


@pytest.mark.parametrize("suspend", ["hide", "minimize"])
def test_dashboard_and_cosmetic_timers_have_zero_hidden_window_wakeups(memory, monkeypatch, suspend):
    _, manager, config, module = memory
    monkeypatch.setattr(spyware_ui, "motion_allowed", lambda _config: True)
    window = QDialog()
    page = SpywareGuardPage(manager, config, None)
    QVBoxLayout(window).addWidget(page)
    window.resize(810, 460)
    module.snapshot["settings"]["spyware_network_enabled"] = True
    module.snapshot["news"] = news_rows(spyware_ui.time.time())
    module.snapshot["news_status"] = {"state": "refreshing", "refreshing": True}
    window.show()
    process()
    page._sync_news_motion()
    timers = (page._timer, page._news_rotation_timer, page._news_scroll_timer, page.news_spinner._timer)
    assert [timer.interval() for timer in timers] == [3000, 9000, 100, 150]
    original_intervals = tuple(timer.interval() for timer in timers)
    assert all(timer.isActive() for timer in timers)
    wakeups = []
    for timer in timers:
        timer.setInterval(20)
        timer.timeout.connect(lambda: wakeups.append(1))
    try:
        if suspend == "hide":
            window.hide()
        else:
            window.showMinimized()
        process()
        reads = module.reads
        assert all(not timer.isActive() for timer in timers)
        QTest.qWait(120)
        page.refresh()
        assert wakeups == [] and module.reads == reads
        # The 20 ms cadence probes hidden wakeups only. Restore the real cadence
        # before showing so a valid news rotation cannot replace the known
        # long headline with a short, non-scrolling headline during this check.
        for timer, interval in zip(timers, original_intervals):
            timer.setInterval(interval)
        assert all(not timer.isActive() for timer in timers)
        assert module.reads == reads
        if suspend == "hide":
            window.show()
        else:
            window.showNormal()
        process()
        assert module.reads > reads
        assert all(timer.isActive() for timer in timers)
        page._pause_news(True)
        window.showMinimized()
        process()
        window.showNormal()
        process()
        assert all(not timer.isActive() for timer in timers[1:])
    finally:
        window.close()
        window.deleteLater()


def test_short_headline_stops_only_marquee_while_other_visible_timers_run(memory, monkeypatch):
    _, manager, config, module = memory
    monkeypatch.setattr(spyware_ui, "motion_allowed", lambda _config: True)
    window = QDialog()
    page = SpywareGuardPage(manager, config, None)
    QVBoxLayout(window).addWidget(page)
    window.resize(1100, 600)
    module.snapshot["settings"]["spyware_network_enabled"] = True
    rows = news_rows(spyware_ui.time.time())
    rows[1]["title"] = "Spyware update"
    module.snapshot["news"] = rows
    module.snapshot["news_status"] = {"state": "refreshing", "refreshing": True}
    window.show()
    process()
    page._sync_news_motion()
    try:
        assert page._news_index == 0
        assert page._news_scroll_timer.isActive()
        assert page.news_scroll.horizontalScrollBar().maximum() > 0
        page._rotate_news()
        process()
        page._sync_news_motion()
        assert page._news_index == 1
        assert page.news_headline.text() == "Spyware update"
        assert page.news_scroll.horizontalScrollBar().maximum() == 0
        assert not page._news_scroll_timer.isActive()
        assert page._timer.isActive()
        assert page._news_rotation_timer.isActive()
        assert page.news_spinner._timer.isActive()
        assert module.calls == []
    finally:
        window.close()
        window.deleteLater()
