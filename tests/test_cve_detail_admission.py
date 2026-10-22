from __future__ import annotations

import threading
import time

import pytest
from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import QApplication, QLabel, QWidget
from shiboken6 import delete, isValid

from angerona.core import cve_fix_advisor, cve_ignore
from angerona.gui import threat_intel_page as page
from angerona.gui import cve_detail_admission as admission_module
from angerona.gui.cve_detail_admission import (
    DetailAnalysisAdmission,
    detail_analysis_admission,
)


def _pump_until(predicate, *, timeout: float = 3.0) -> None:
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "owned Qt operation did not retire"
        app.processEvents()
        time.sleep(0.001)
    app.processEvents()


@pytest.fixture
def isolated_dashboards(monkeypatch):
    monkeypatch.setattr(page, "_load_threats", lambda: {"matches": []})
    monkeypatch.setattr(cve_ignore, "load", lambda: {})

    def no_real_analysis(*_args, **_kwargs):
        raise AssertionError("tests must provide an inert advisor")

    monkeypatch.setattr(cve_fix_advisor, "analyze", no_real_analysis)
    monkeypatch.setattr(cve_fix_advisor, "safe_urlopen", no_real_analysis)
    dashboards = []
    releases = []

    def create():
        dashboard = page.ThreatIntelDashboard()
        dashboards.append(dashboard)
        return dashboard

    yield create, releases
    for release in releases:
        release.set()
    pool = detail_analysis_admission()
    for dashboard in dashboards:
        dashboard.close()
    _pump_until(lambda: pool.active_count == 0 and not any(
        worker.isRunning()
        for dashboard in dashboards
        for worker in tuple(dashboard._detail_workers.values())
    ))
    for dashboard in dashboards:
        dashboard.close()
        dashboard.deleteLater()


def _blocking_advisor(monkeypatch, releases):
    entered = {}
    release = {}
    received = {}
    lock = threading.Lock()

    def advisor(record):
        cve = record["cve"]
        with lock:
            received[cve] = record
        entered[cve].set()
        assert release[cve].wait(5.0)
        return {"cve": cve, "fix_available": False, "reason": "inert test"}

    monkeypatch.setattr(cve_fix_advisor, "analyze", advisor)

    def enroll(cve):
        entered[cve] = threading.Event()
        release[cve] = threading.Event()
        releases.append(release[cve])
        return entered[cve], release[cve]

    return enroll, received


def test_distinct_cve_burst_is_globally_bounded_before_worker_construction(
    monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboards = [create(), create(), create()]
    enroll, received = _blocking_advisor(monkeypatch, releases)
    original_worker = page._FixWorker
    constructed = []

    class CountedWorker(original_worker):
        def __init__(self, *args, **kwargs):
            constructed.append(args[0][0][0])
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(page, "_FixWorker", CountedWorker)
    events = [enroll(f"CVE-2026-{1000 + index}") for index in range(20)]
    record = {"cve": "CVE-2026-1000", "name": "accepted snapshot"}
    first = dashboards[0]._start_detail_analysis(record["cve"], record, lambda _r: None)
    second = dashboards[1]._start_detail_analysis(
        "CVE-2026-1001", {"cve": "CVE-2026-1001"}, lambda _r: None,
    )
    assert first is not None and second is not None
    assert events[0][0].wait(2.0) and events[1][0].wait(2.0)
    record["name"] = "changed after click"
    assert received[record["cve"]]["name"] == "accepted snapshot"
    refused = []
    for index in range(2, 20):
        cve = f"CVE-2026-{1000 + index}"
        assert dashboards[2]._start_detail_analysis(
            cve, {"cve": cve}, lambda _r: None, on_refused=refused.append,
        ) is None
    assert len(constructed) == 2
    assert len(refused) == 18 and all("not queued" in text for text in refused)
    same = []
    assert dashboards[0]._start_detail_analysis(
        record["cve"], record, lambda _r: None, on_refused=same.append,
    ) is None
    assert same == ["Analysis for this CVE is already running."]
    pool = detail_analysis_admission()
    assert pool.active_count == 2

    dashboards[0].close()
    assert first.isInterruptionRequested() and first.isRunning()
    assert pool.active_count == 2
    assert dashboards[2]._start_detail_analysis(
        "CVE-2026-1002", {"cve": "CVE-2026-1002"}, lambda _r: None,
    ) is None
    events[0][1].set()
    assert first.wait(3000)
    _pump_until(lambda: pool.active_count == 1)
    third = dashboards[2]._start_detail_analysis(
        "CVE-2026-1002", {"cve": "CVE-2026-1002"}, lambda _r: None,
    )
    assert third is not None and events[2][0].wait(2.0)
    assert len(constructed) == 3 and pool.active_count == 2
    events[1][1].set()
    events[2][1].set()


def test_result_signal_does_not_release_live_native_worker(
    monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    release = threading.Event()
    releases.append(release)
    results = []

    class ResultThenBlocked(page._FixWorker):
        def run(self):
            cve = self._items[0][0]
            self.result.emit(cve, {"cve": cve, "fix_available": False})
            assert release.wait(5.0)

    monkeypatch.setattr(page, "_FixWorker", ResultThenBlocked)
    workers = [dashboard._start_detail_analysis(
        f"CVE-2026-{2000 + index}", {"cve": f"CVE-2026-{2000 + index}"},
        results.append,
    ) for index in range(2)]
    _pump_until(lambda: len(results) == 2)
    assert all(worker.isRunning() for worker in workers)
    assert detail_analysis_admission().active_count == 2
    assert dashboard._start_detail_analysis(
        "CVE-2026-2002", {"cve": "CVE-2026-2002"}, results.append,
    ) is None
    release.set()


def test_retirement_waits_for_native_running_state_and_is_idempotent():
    class SyntheticWorker(QObject):
        finished = Signal()

        def __init__(self):
            super().__init__()
            self.running = True
            self.cancelled = False

        def isRunning(self):
            return self.running

        def requestInterruption(self):
            self.cancelled = True

    pool = DetailAnalysisAdmission()
    first, second = SyntheticWorker(), SyntheticWorker()
    a, b = pool.reserve(), pool.reserve()
    retired = []
    pool.attach(a, first, lambda: retired.append("first"))
    pool.attach(b, second, lambda: retired.append("second"))
    first.finished.emit()
    assert pool.active_count == 2 and pool._retry.isActive()
    assert pool.reserve() is None and retired == []
    first.running = False
    pool._retry_retiring()
    assert pool.active_count == 1 and retired == ["first"]
    replacement = pool.reserve()
    first.finished.emit()
    pool.abandon(a)
    assert pool.active_count == 2 and retired == ["first"]
    pool.abandon(replacement)
    second.running = False
    second.finished.emit()
    assert pool.active_count == 0 and retired == ["first", "second"]
    assert not pool._retry.isActive()


@pytest.mark.parametrize("failure", ["constructor", "start-before-native", "start-after-native"])
def test_failed_start_releases_only_unused_or_retired_reservation(
    failure, monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    enroll, _received = _blocking_advisor(monkeypatch, releases)
    entered, release = enroll("CVE-2026-3000")
    original_worker = page._FixWorker

    class FailedWorker(original_worker):
        def __init__(self, *args, **kwargs):
            if failure == "constructor":
                raise RuntimeError("inert construction failure")
            super().__init__(*args, **kwargs)

        def start(self, *args, **kwargs):
            if failure == "start-after-native":
                super().start(*args, **kwargs)
                assert entered.wait(2.0)
            raise RuntimeError("inert start failure")

    monkeypatch.setattr(page, "_FixWorker", FailedWorker)
    with pytest.raises(RuntimeError, match="inert"):
        dashboard._start_detail_analysis(
            "CVE-2026-3000", {"cve": "CVE-2026-3000"}, lambda _r: None,
        )
    pool = detail_analysis_admission()
    if failure == "start-after-native":
        assert pool.active_count == 1
        worker = dashboard._detail_workers["CVE-2026-3000"]
        assert worker.isRunning() and worker.isInterruptionRequested()
        dashboard.close()
        assert pool.active_count == 1
        release.set()
        assert worker.wait(3000)
        _pump_until(lambda: pool.active_count == 0)
    else:
        assert pool.active_count == 0
        assert dashboard._detail_workers == {}


def test_shutdown_refuses_new_work_and_keeps_native_owner_until_exit():
    entered, release = threading.Event(), threading.Event()

    class Blocked(QThread):
        def run(self):
            entered.set()
            assert release.wait(5.0)

    pool = DetailAnalysisAdmission()
    worker = Blocked()
    retired = []
    token = pool.reserve()
    pool.attach(token, worker, lambda: retired.append(worker))
    worker.start()
    try:
        assert entered.wait(2.0)
        pool.shutdown()
        assert pool.closing and pool.reserve() is None
        assert pool.active_count == 1 and worker.isInterruptionRequested()
        assert retired == []
    finally:
        release.set()
        assert worker.wait(3000)
    _pump_until(lambda: pool.active_count == 0)
    assert retired == [worker]
    pool.shutdown()
    assert pool.active_count == 0


def test_admission_rejects_non_owner_thread_without_reserving():
    pool = DetailAnalysisAdmission()
    errors = []

    def wrong_thread():
        try:
            pool.reserve()
        except RuntimeError as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=wrong_thread)
    thread.start()
    thread.join(2.0)
    assert not thread.is_alive()
    assert errors == ["CVE detail admission requires its Qt owner thread"]
    assert pool.active_count == 0


def test_hide_show_restarts_single_refresh_timer_with_all_detail_slots_busy(
    monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    renders = {}

    def render(self):
        renders[id(self)] = renders.get(id(self), 0) + 1

    monkeypatch.setattr(page.ThreatIntelDashboard, "_load_and_render", render)
    dashboard = create()
    enroll, _received = _blocking_advisor(monkeypatch, releases)
    workers = []
    for index in range(2):
        cve = f"CVE-2026-{4000 + index}"
        entered, _release = enroll(cve)
        worker = dashboard._start_detail_analysis(cve, {"cve": cve}, lambda _r: None)
        assert worker is not None
        workers.append(worker)
        assert entered.wait(2.0)
    assert all(worker.isRunning() for worker in workers)
    timer = dashboard._timer
    assert timer.isActive()
    dashboard.show()
    QApplication.instance().processEvents()
    for _index in range(3):
        dashboard.hide()
        assert not timer.isActive()
        before = renders[id(dashboard)]
        dashboard.show()
        QApplication.instance().processEvents()
        assert dashboard._timer is timer and timer.isActive()
        assert renders[id(dashboard)] == before + 1
        assert all(worker.isRunning() for worker in workers)


@pytest.mark.parametrize("shutdown_before_callbacks", [False, True])
def test_parent_deleted_after_qt_worker_finishes_before_queued_callbacks(
    monkeypatch, shutdown_before_callbacks,
):
    monkeypatch.setattr(page, "_load_threats", lambda: {"matches": []})
    monkeypatch.setattr(cve_ignore, "load", lambda: {})
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": False, "reason": "inert",
    })
    pool = DetailAnalysisAdmission(QApplication.instance())
    monkeypatch.setattr(admission_module, "detail_analysis_admission", lambda: pool)
    parent = QWidget()
    dashboard = page.ThreatIntelDashboard(parent)
    callback_owner = QLabel("original", dashboard)
    results, done = [], []

    def result_callback(analysis):
        results.append(analysis)
        callback_owner.setText("result")

    def finished_callback():
        done.append(True)
        callback_owner.setText("finished")

    worker = dashboard._start_detail_analysis(
        "CVE-2026-5000", {"cve": "CVE-2026-5000"},
        result_callback, finished_callback, callback_owner=callback_owner,
    )
    assert worker is not None and worker.parent() is pool
    assert worker.wait(3000)
    assert pool.active_count == 1  # The GUI has not received finished yet.
    delete(parent)
    assert not isValid(dashboard) and not isValid(callback_owner)
    assert isValid(worker)  # Its QObject owner survived dashboard destruction.
    if shutdown_before_callbacks:
        pool.shutdown()  # Must not invoke deleteLater on a deleted QObject.
        assert pool.closing and pool.reserve() is None
    _pump_until(lambda: pool.active_count == 0)
    assert results == [] and done == []
    if not shutdown_before_callbacks:
        # Capacity is genuinely reusable after that exact lost-owner race.
        replacement = page.ThreatIntelDashboard()
        try:
            later = replacement._start_detail_analysis(
                "CVE-2026-5001", {"cve": "CVE-2026-5001"}, lambda _r: None,
            )
            assert later is not None and later.wait(3000)
            _pump_until(lambda: pool.active_count == 0)
        finally:
            replacement.close()
            replacement.deleteLater()
        pool.shutdown()
    assert pool.active_count == 0
    pool.deleteLater()


def test_deleted_callback_dialog_drops_gui_callbacks_but_retires_analysis(
    monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    callback_owner = QLabel("original", dashboard)
    results, done = [], []
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": False, "reason": "inert",
    })
    worker = dashboard._start_detail_analysis(
        "CVE-2026-5002", {"cve": "CVE-2026-5002"},
        results.append, lambda: done.append(True), callback_owner=callback_owner,
    )
    assert worker is not None and worker.wait(3000)
    delete(callback_owner)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert isValid(dashboard) and results == [] and done == []
