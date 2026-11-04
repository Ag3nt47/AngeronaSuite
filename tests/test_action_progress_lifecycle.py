"""Exact finite-action presentation; inert producers and no host operations."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Signal
from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui import action_progress as actions
from angerona.gui import github_tools
from angerona.gui import sentinel_lens
from angerona.gui import update_controller as updates
from angerona.gui.selftest_results import SelfTestResultsDialog
from angerona.updater.github_updater import UpdateReport


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def captured(monkeypatch):
    calls = []
    monkeypatch.setattr(actions, "begin_loading", lambda label, **counts: calls.append(("begin", label, counts)) or str(len(calls)))
    monkeypatch.setattr(actions, "update_loading", lambda *args, **kwargs: calls.append(("update", args, kwargs)))
    monkeypatch.setattr(actions, "finish_loading", lambda token: calls.append(("finish", token)))
    return calls


def test_overlapping_actions_preserve_older_view_and_exact_replacement(captured):
    owner = QWidget()
    group = actions.ActionActivities(owner)
    view = actions.ActionProgressView(group, owner)
    first = group.begin("audit", "Audit", done=1, total=4)
    second = group.begin("export", "Export")
    assert group.snapshot()["active_count"] == 2 and view.ring.percent is None
    assert group.begin("export", "Coalesced click") == second
    newer = group.begin("export", "New admitted export", replace=True)
    assert newer != second and not group.finish(second)
    assert not group.update(second, done=100, total=100)
    assert group.snapshot()["serial"] == newer.serial
    assert group.finish(newer)
    assert group.snapshot()["active_count"] == 1 and view.ring.percent == 25
    assert group.finish(first) and group.snapshot() == {} and view.isHidden()
    assert not group.finish(first)
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_counts_are_measured_unknown_clears_and_running_never_shows_complete(captured):
    owner = QWidget()
    group = actions.ActionActivities(owner)
    view = actions.ActionProgressView(group, owner)
    handle = group.begin("check", "Measured check", done=0, total=4)
    assert view.ring.percent == 0
    group.update(handle, done=2, total=4)
    assert view.ring.percent == 50
    middle = view.ring.progress_color.name()
    group.update(handle, done=4, total=4)
    assert view.ring.percent == 99 and view.ring.progress_color.name() != middle
    group.update(handle, done=0, total=0)
    assert view.ring.percent is None and view.ring.busy
    group.close()
    assert group.snapshot() == {} and not view.ring.busy
    owner.deleteLater()


def test_owner_destruction_finishes_all_global_tokens_without_new_worker(captured):
    owner = QWidget()
    group = actions.ActionActivities(owner)
    one, two = group.begin("one", "One"), group.begin("two", "Two")
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert ("finish", one.token) in captured and ("finish", two.token) in captured


def test_selftest_dialog_accepts_real_counts_and_recovery_coalesces():
    dialog = SelfTestResultsDialog("fixture", [], [], [])
    try:
        dialog.set_busy("Running self-test")
        first = dialog._activity_handle
        dialog.set_busy("Running self-test")
        assert dialog._activity_handle == first
        dialog.set_progress(3, 6)
        assert dialog.progress_view.ring.percent == 50
        dialog.recovery_finished([], [])
        assert dialog._activities.snapshot() == {} and not dialog.progress_view.ring.busy
    finally:
        dialog.close()


def _controller(tmp_path, monkeypatch, check):
    monkeypatch.setattr(updates, "check_installed_updates", check)
    cfg = SimpleNamespace(data_dir=tmp_path, github_daily_check_enabled=True)
    controller = updates.UpdateController(cfg, tmp_path / "source")
    controller._timer.stop()
    controller._initial.stop()
    return controller


def _retire(controller, *releases):
    for release in releases:
        release.set()
    controller.close()
    for reader in (controller._check, controller._download):
        if reader.thread is not None:
            reader.thread.join(3)
            assert not reader.thread.is_alive()
    controller.deleteLater()


def test_daily_check_is_quiet_and_manual_claim_waits_for_real_result(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def check(*_args, **_kwargs):
        entered.set()
        assert release.wait(4)
        return UpdateReport("checked", 1, "fixture", "a" * 40, "a" * 40, "", "none", "same")

    controller = _controller(tmp_path, monkeypatch, check)
    try:
        controller.check_daily()
        assert entered.wait(2)
        assert controller.activities.snapshot() == {}
        controller.check_now()
        assert controller.activities.snapshot()["active_count"] == 1
        for _index in range(3):
            QApplication.instance().processEvents()
        assert controller.activities.snapshot()["total"] == 0
        release.set()
        until(lambda: not controller._check.busy)
        assert controller.activities.snapshot() == {}
    finally:
        _retire(controller, release)


def test_reentrant_manual_check_cannot_be_finished_by_older_delivery(tmp_path, monkeypatch):
    first, second = threading.Event(), threading.Event()
    entered_second = threading.Event()
    calls = []

    def check(*_args, **_kwargs):
        calls.append(True)
        if len(calls) == 1:
            assert first.wait(4)
        else:
            entered_second.set()
            assert second.wait(4)
        return UpdateReport("checked", 1, "fixture", "a" * 40, "a" * 40, "", "none", "same")

    controller = _controller(tmp_path, monkeypatch, check)
    seen = []

    def again(_report):
        seen.append(True)
        if len(seen) == 1:
            controller.check_now()

    controller.report_ready.connect(again)
    try:
        controller.check_now()
        first.set()
        until(entered_second.is_set)
        assert controller.activities.snapshot()["active_count"] == 1
        assert controller._check.busy
        second.set()
        until(lambda: len(seen) == 2 and not controller._check.busy)
        assert controller.activities.snapshot() == {}
    finally:
        _retire(controller, first, second)


def test_failed_manual_check_and_close_settle_presentation(tmp_path, monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("synthetic read failure")

    controller = _controller(tmp_path, monkeypatch, fail)
    try:
        controller.check_now()
        until(lambda: not controller._check.busy)
        assert controller.activities.snapshot() == {}
        controller.activities.begin("fixture", "Still presented")
        controller.close()
        assert controller.activities.snapshot() == {}
    finally:
        _retire(controller)


def test_github_source_result_does_not_finish_before_exact_worker_exits(monkeypatch):
    panel = github_tools.GitHubToolsPanel()
    original = threading.Thread
    published, release = threading.Event(), threading.Event()

    def retained_thread(*, target, **kwargs):
        def run():
            target()
            published.set()
            assert release.wait(4)
        return original(target=run, **kwargs)

    monkeypatch.setattr(github_tools.threading, "Thread", retained_thread)
    try:
        panel._start("preview", lambda _operation: "literal fixture", "Reading selected source…")
        assert published.wait(2)
        panel._poll()
        assert panel._busy and panel._activities.snapshot()
        assert panel.preview.toPlainText() == ""
        release.set()
        until(lambda: not panel._busy)
        assert panel.preview.toPlainText() == "literal fixture" and panel._activities.snapshot() == {}
    finally:
        release.set()
        if panel._worker is not None:
            panel._worker.join(3)
            assert not panel._worker.is_alive()
        panel.close()
        panel.deleteLater()


def test_sentinel_narrative_result_keeps_wheel_until_native_finished(monkeypatch):
    entered, release = threading.Event(), threading.Event()

    class EarlyResult(QThread):
        result = Signal(str)

        def __init__(self, *_args):
            super().__init__()

        def run(self):
            self.result.emit("literal narrative")
            entered.set()
            assert release.wait(4)

    monkeypatch.setattr(sentinel_lens, "_NarrativeWorker", EarlyResult)
    monkeypatch.setattr(sentinel_lens, "render_narrative", lambda *_args: "fixture")
    service = SimpleNamespace(snapshot=lambda: dict(nodes=[], edges=[], anomalies=[], stats={}, service_health={}))
    dialog = sentinel_lens.SentinelLensDialog(None, config=SimpleNamespace(), service=service)
    dialog._selected_node = "fixture"
    worker = None
    try:
        dialog._ask_local_ai()
        worker = dialog._worker
        assert entered.wait(2)
        until(lambda: "literal narrative" in dialog.detail.toPlainText())
        assert worker.isRunning() and dialog._activities.snapshot()
        release.set()
        until(lambda: not worker.isRunning() and not dialog._activities.snapshot())
    finally:
        release.set()
        if worker is not None:
            assert worker.wait(3000)
        dialog.close()
