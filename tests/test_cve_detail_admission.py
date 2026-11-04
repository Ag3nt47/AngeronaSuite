from __future__ import annotations

import threading
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThread, Qt, Signal
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget
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
    monkeypatch.setattr(cve_fix_advisor, "applied_state", lambda _cve: None)

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
        for worker in (dashboard._worker, *tuple(dashboard._detail_workers.values()))
        if worker is not None
    ))
    for dashboard in dashboards:
        dashboard.close()
        dashboard.deleteLater()


def _start_current_detail(dashboard, cve, record, *args, **kwargs):
    """Legacy lifecycle fixtures explicitly provide a current rendered row."""
    dashboard._row_recs[cve] = dict(record)
    dashboard._analysis_rows[cve] = (dashboard._row_recs[cve],)
    return dashboard._start_detail_analysis(cve, record, *args, **kwargs)


def test_detail_local_progress_retires_with_exact_admission_owner(monkeypatch, isolated_dashboards):
    create, releases = isolated_dashboards
    dashboard = create()
    enroll, _received = _blocking_advisor(monkeypatch, releases)
    entered, release = enroll("CVE-2026-98701")
    record = {"cve": "CVE-2026-98701", "name": "inert record"}
    worker = _start_current_detail(dashboard, record["cve"], record, lambda _value: None)
    assert worker is not None and entered.wait(2)
    assert worker in dashboard._detail_activities
    assert dashboard.progress_view.ring.percent is None
    release.set()
    _pump_until(lambda: worker not in dashboard._detail_activities)
    assert not dashboard._activities.snapshot()


def test_batch_local_percent_uses_actual_record_returns(monkeypatch, isolated_dashboards):
    create, releases = isolated_dashboards
    first = {"cve": "CVE-2026-98702", "name": "first inert record"}
    second = {"cve": "CVE-2026-98703", "name": "second inert record"}
    monkeypatch.setattr(page, "_load_threats", lambda: {"matches": [first, second]})
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    dashboard = create()
    enroll, _received = _blocking_advisor(monkeypatch, releases)
    _first_entered, first_release = enroll(first["cve"])
    second_entered, second_release = enroll(second["cve"])
    first_release.set()
    dashboard._analyze_all()
    assert second_entered.wait(2)
    _pump_until(lambda: dashboard.progress_view.ring.percent == 50)
    worker = dashboard._worker
    assert worker.isRunning() and dashboard._activities.snapshot()["done"] == 1
    assert dashboard._activities.snapshot()["total"] == 2
    second_release.set()
    _pump_until(lambda: dashboard._worker is None and not dashboard._activities.snapshot())
    assert dashboard._loading_token is None


def test_inert_proposal_staging_is_background_and_captures_exact_plain_input(monkeypatch, isolated_dashboards):
    from angerona.gui import action_worker
    create, releases = isolated_dashboards
    monkeypatch.setattr(action_worker, "_CLOSING", False)
    assert not action_worker.active_finite_actions()
    entered, release = threading.Event(), threading.Event()
    releases.append(release)
    received = []
    gui_thread = threading.get_ident()

    def stage(cve, analysis):
        received.append((cve, analysis, threading.get_ident()))
        entered.set()
        assert release.wait(4)
        return {"ok": True, "staged": True, "executed": False, "output": "inert fixture; no command ran"}

    monkeypatch.setattr(cve_fix_advisor, "apply_fix", stage)
    dashboard = create()
    monkeypatch.setattr(dashboard, "_load_and_render", lambda: None)
    analysis = {"fix_script": "inert original proposal", "summary": "fixture", "revert_script": "inert rollback"}
    try:
        assert dashboard._start_proposal_job("CVE-2026-98704", analysis)
        assert entered.wait(2) and dashboard._proposal_jobs
        assert dashboard.progress_view.ring.percent is None and getattr(dashboard, "_proposal_notice", None) is None
        analysis["fix_script"] = "changed after admission"
        assert not dashboard._start_proposal_job("CVE-2026-98704", analysis)
        release.set()
        _pump_until(lambda: not dashboard._proposal_jobs and not action_worker.active_finite_actions())
        assert received[0][1]["fix_script"] == "inert original proposal"
        assert received[0][2] != gui_thread
        assert not dashboard._proposal_notice.isModal() and "not executed" in dashboard._proposal_notice.windowTitle().lower()
        assert not dashboard._activities.snapshot()
    finally:
        release.set()
        for worker in action_worker.active_finite_actions():
            assert worker.wait(3000)
        _pump_until(lambda: not action_worker.active_finite_actions())

def _blocking_advisor(monkeypatch, releases, *, release_timeout=5.0):
    entered = {}
    release = {}
    received = {}
    lock = threading.Lock()

    def advisor(record):
        cve = record["cve"]
        with lock:
            received[cve] = record
        entered[cve].set()
        assert release[cve].wait(release_timeout), "test did not release its owned CVE worker"
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
    first = _start_current_detail(dashboards[0], record["cve"], record, lambda _r: None)
    second = _start_current_detail(dashboards[1],
        "CVE-2026-1001", {"cve": "CVE-2026-1001"}, lambda _r: None,
    )
    assert first is not None and second is not None
    assert events[0][0].wait(2.0) and events[1][0].wait(2.0)
    record["name"] = "changed after click"
    assert received[record["cve"]]["name"] == "accepted snapshot"
    refused = []
    for index in range(2, 20):
        cve = f"CVE-2026-{1000 + index}"
        assert _start_current_detail(dashboards[2],
            cve, {"cve": cve}, lambda _r: None, on_refused=refused.append,
        ) is None
    assert len(constructed) == 2
    assert len(refused) == 18 and all("not queued" in text for text in refused)
    same = []
    assert _start_current_detail(dashboards[0],
        record["cve"], record, lambda _r: None, on_refused=same.append,
    ) is None
    assert same == ["Analysis for this CVE is already running."]
    pool = detail_analysis_admission()
    assert pool.active_count == 2

    dashboards[0].close()
    assert first.isInterruptionRequested() and first.isRunning()
    assert pool.active_count == 2
    assert _start_current_detail(dashboards[2],
        "CVE-2026-1002", {"cve": "CVE-2026-1002"}, lambda _r: None,
    ) is None
    events[0][1].set()
    assert first.wait(3000)
    _pump_until(lambda: pool.active_count == 1)
    third = _start_current_detail(dashboards[2],
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
    workers = [_start_current_detail(dashboard,
        f"CVE-2026-{2000 + index}", {"cve": f"CVE-2026-{2000 + index}"},
        results.append,
    ) for index in range(2)]
    _pump_until(lambda: len(results) == 2)
    assert all(worker.isRunning() for worker in workers)
    assert detail_analysis_admission().active_count == 2
    assert _start_current_detail(dashboard,
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
        _start_current_detail(dashboard,
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
    # Keep both workers blocked until the test releases them. The watchdog
    # only bounds cleanup if a loaded Qt runner stalls during a show/hide.
    enroll, _received = _blocking_advisor(monkeypatch, releases, release_timeout=30.0)
    pool = detail_analysis_admission()
    workers = {}
    delivered = []
    for index in range(2):
        cve = f"CVE-2026-{4000 + index}"
        entered, _release = enroll(cve)
        worker = _start_current_detail(dashboard, cve, {"cve": cve},
            lambda result, expected=cve: delivered.append((expected, result["cve"])))
        assert worker is not None
        workers[cve] = worker
        assert entered.wait(2.0)
    assert all(worker.isRunning() for worker in workers.values())
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
        assert pool.active_count == 2 and dashboard._detail_workers == workers
        assert all(worker.isRunning() for worker in workers.values()) and not delivered
    for release in releases:
        release.set()
    _pump_until(lambda: pool.active_count == 0)
    assert not dashboard._detail_workers
    assert sorted(delivered) == [(cve, cve) for cve in sorted(workers)]


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

    worker = _start_current_detail(dashboard,
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
            later = _start_current_detail(replacement,
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
    worker = _start_current_detail(dashboard,
        "CVE-2026-5002", {"cve": "CVE-2026-5002"},
        results.append, lambda: done.append(True), callback_owner=callback_owner,
    )
    assert worker is not None and worker.wait(3000)
    delete(callback_owner)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert isValid(dashboard) and results == [] and done == []


def _show_records(monkeypatch, dashboard, records):
    monkeypatch.setattr(page, "_load_threats", lambda: {"matches": records})
    dashboard._load_and_render()


def _held_freshness_advisor(monkeypatch, releases, count=2):
    entered = [threading.Event() for _index in range(count)]
    release = [threading.Event() for _index in range(count)]
    releases.extend(release)
    received = []
    lock = threading.Lock()

    def advisor(record):
        with lock:
            index = len(received)
            received.append(record)
        entered[index].set()
        assert release[index].wait(5.0)
        return {
            "cve": record["cve"], "fix_available": False,
            "reason": f"inert request {index}",
        }

    monkeypatch.setattr(cve_fix_advisor, "analyze", advisor)
    return entered, release, received


@pytest.mark.parametrize("replacement", ["changed", "removed"])
def test_refresh_discards_old_detail_but_restores_controls_and_retires_owner(
    replacement, monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6000", "name": "accepted description"}
    _show_records(monkeypatch, dashboard, [record])
    entered, release, _received = _held_freshness_advisor(monkeypatch, releases)
    button = QPushButton("Analyze", dashboard)
    button.setEnabled(False)
    label = QLabel("pending", dashboard)
    results = []

    def render(result):
        results.append(result)
        label.setText(result["reason"])

    worker = dashboard._start_detail_analysis(
        record["cve"], record, render, lambda: button.setEnabled(True),
        callback_owner=label,
    )
    assert worker is not None and entered[0].wait(2.0)
    updated = [] if replacement == "removed" else [{
        **record, "name": "new upstream description",
    }]
    _show_records(monkeypatch, dashboard, updated)
    assert detail_analysis_admission().active_count == 1 and worker.isRunning()
    release[0].set()
    assert worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert results == [] and label.text() == "pending" and button.isEnabled()
    assert dashboard._detail_workers == {}
    assert dashboard._cached_analysis(record["cve"]) is None
    assert dashboard._fix_cache == {}


def test_nested_accepted_input_is_deep_copied_and_mutation_rejects_result(
    monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    record = {
        "cve": "CVE-2026-6001",
        "remediation": {"steps": ["original"]},
    }
    _show_records(monkeypatch, dashboard, [record])
    entered, release, received = _held_freshness_advisor(monkeypatch, releases)
    results, finished = [], []
    worker = dashboard._start_detail_analysis(
        record["cve"], record, results.append, lambda: finished.append(True),
    )
    assert worker is not None and entered[0].wait(2.0)
    record["remediation"]["steps"][0] = "changed after acceptance"
    assert received[0]["remediation"] == {"steps": ["original"]}
    release[0].set()
    assert worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert results == [] and finished == [True]
    assert dashboard._cached_analysis(record["cve"]) is None


def test_matching_detail_caches_only_current_record_and_refresh_invalidates_display(
    monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6002", "name": "current", "due_date": "2026-12-01"}
    _show_records(monkeypatch, dashboard, [record])
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": False, "reason": "matching",
    })
    results, finished = [], []
    worker = dashboard._start_detail_analysis(
        record["cve"], record, results.append, lambda: finished.append(True),
    )
    assert worker is not None and worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert len(results) == 1 and finished == [True]
    assert dashboard._cached_analysis(record["cve"], dict(record)) == results[0]
    row = dashboard._row_for_cve(record["cve"])
    assert dashboard._table.item(row, dashboard._C_FIX).text() == "no fix"

    # Due date affects the detail rendering even though it is not a prompt field.
    _show_records(monkeypatch, dashboard, [{**record, "due_date": "2027-01-01"}])
    assert dashboard._cached_analysis(record["cve"]) is None
    row = dashboard._row_for_cve(record["cve"])
    assert dashboard._table.item(row, dashboard._C_FIX).text() == "—"
    assert dashboard._analysis_requests == {}


def test_cache_consumer_rejects_same_cve_with_different_record(
    monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6003", "product": "accepted product"}
    _show_records(monkeypatch, dashboard, [record])
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": True, "summary": "inert",
    })
    worker = dashboard._start_detail_analysis(record["cve"], record, lambda _result: None)
    assert worker is not None and worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert dashboard._cached_analysis(record["cve"], record)["fix_available"]
    assert dashboard._cached_analysis(
        record["cve"], {**record, "product": "different product"},
    ) is None
    assert dashboard._cached_analysis(record["cve"], record)["fix_available"]


@pytest.mark.parametrize("newer_request", ["batch", "detail"])
@pytest.mark.parametrize("first_completed", ["batch", "detail"])
def test_newer_request_wins_in_both_batch_detail_completion_orders(
    newer_request, first_completed, monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6004", "name": "same accepted input"}
    _show_records(monkeypatch, dashboard, [record])
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    monkeypatch.setattr(page, "begin_loading", lambda _message: "inert loading")
    finished_loading = []
    monkeypatch.setattr(page, "finish_loading", finished_loading.append)
    entered, release, received = _held_freshness_advisor(monkeypatch, releases)
    results, done = [], []

    def start_detail():
        return dashboard._start_detail_analysis(
            record["cve"], record, results.append, lambda: done.append(True),
        )

    if newer_request == "detail":
        dashboard._analyze_all()
        batch = dashboard._worker
        assert batch is not None and entered[0].wait(2.0)
        detail = start_detail()
        assert detail is not None and entered[1].wait(2.0)
    else:
        detail = start_detail()
        assert detail is not None and entered[0].wait(2.0)
        dashboard._analyze_all()
        batch = dashboard._worker
        assert batch is not None and entered[1].wait(2.0)
    assert received == [record, record]
    index_by_kind = {newer_request: 1, "detail" if newer_request == "batch" else "batch": 0}
    first_index = index_by_kind[first_completed]
    first_worker = batch if first_completed == "batch" else detail
    release[first_index].set()
    assert first_worker.wait(3000)
    if first_completed == "batch":
        _pump_until(lambda: dashboard._worker is None)
        assert detail_analysis_admission().active_count == 1
    else:
        _pump_until(lambda: detail_analysis_admission().active_count == 0)
        assert batch.isRunning()
    if first_index == 1:
        assert dashboard._cached_analysis(record["cve"])["reason"] == "inert request 1"
    else:
        assert dashboard._cached_analysis(record["cve"]) is None

    second_kind = "detail" if first_completed == "batch" else "batch"
    second_worker = detail if second_kind == "detail" else batch
    release[index_by_kind[second_kind]].set()
    assert second_worker.wait(3000)
    _pump_until(lambda: dashboard._worker is None
                and detail_analysis_admission().active_count == 0)
    assert done == [True]
    assert dashboard._cached_analysis(record["cve"])["reason"] == "inert request 1"
    if newer_request == "detail":
        assert len(results) == 1
        assert dashboard._cached_analysis(record["cve"]) == results[0]
    else:
        assert results == []
    assert dashboard._detail_workers == {}
    assert finished_loading == ["inert loading"]
    discarded = 1 if newer_request == "detail" else 0
    assert f"{discarded} superseded result(s) discarded" in dashboard._footer.text()


def test_current_batch_input_is_deep_copied_and_removed_result_is_discarded(
    monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6005", "name": {"details": ["original"]}}
    _show_records(monkeypatch, dashboard, [record])
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    monkeypatch.setattr(page, "begin_loading", lambda _message: "inert batch")
    finished = []
    monkeypatch.setattr(page, "finish_loading", finished.append)
    entered, release, received = _held_freshness_advisor(monkeypatch, releases)
    dashboard._analyze_all()
    worker = dashboard._worker
    assert worker is not None and entered[0].wait(2.0)
    record["name"]["details"][0] = "changed"
    assert received[0]["name"] == {"details": ["original"]}
    _show_records(monkeypatch, dashboard, [])
    release[0].set()
    assert worker.wait(3000)
    _pump_until(lambda: dashboard._worker is None)
    assert dashboard._cached_analysis(record["cve"]) is None
    assert finished == ["inert batch"] and dashboard._loading_token is None
    assert "1 superseded result(s) discarded" in dashboard._footer.text()


def test_removed_row_refuses_new_detail_without_reserving_or_constructing(
    monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6006", "name": "removed"}
    _show_records(monkeypatch, dashboard, [record])
    _show_records(monkeypatch, dashboard, [])
    refused = []

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a stale detail must not construct a worker")

    monkeypatch.setattr(page, "_FixWorker", forbidden)
    assert dashboard._start_detail_analysis(
        record["cve"], record, lambda _result: None, on_refused=refused.append,
    ) is None
    assert refused == [
        "This vulnerability record changed; refresh the detail view before analyzing.",
    ]
    assert detail_analysis_admission().active_count == 0


@pytest.mark.parametrize("invalid", [
    {"name": "x" * (256 * 1024 + 1)},
    {"name": float("nan")},
    {"name": ("unsupported", "tuple")},
])
def test_invalid_snapshot_refuses_visibly_without_admission(
    invalid, monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6007", **invalid}
    dashboard._row_recs[record["cve"]] = record
    dashboard._analysis_rows[record["cve"]] = (record,)
    refused = []
    assert dashboard._start_detail_analysis(
        record["cve"], record, lambda _result: None, on_refused=refused.append,
    ) is None
    assert len(refused) == 1 and "cannot be analyzed" in refused[0]
    assert detail_analysis_admission().active_count == 0


def test_snapshot_is_order_independent_and_accepts_json_producer_values():
    record = {
        "cve": "CVE-2026-6008", "name": "unicode ☃",
        "vendor": None, "product": ["one", {"number": 17}],
        "remediation": {"enabled": True, "score": 0.5},
    }
    copied, identity = page._analysis_snapshot(record)
    reordered, reordered_identity = page._analysis_snapshot(dict(reversed(list(record.items()))))
    assert identity == reordered_identity and copied == reordered == record
    assert copied is not record and copied["product"] is not record["product"]


@pytest.mark.parametrize("identical_duplicate", [False, True])
def test_batch_keeps_distinct_duplicate_rows_and_shares_only_identical_inputs(
    identical_duplicate, monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    old = {"cve": "CVE-2026-6009", "name": "first visible row"}
    current = {**old, "name": "second visible row"}
    records = [old, dict(old), current] if identical_duplicate else [old, current]
    _show_records(monkeypatch, dashboard, records)
    dashboard._table.sortItems(dashboard._C_FIX, page.Qt.SortOrder.DescendingOrder)
    received = []
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    monkeypatch.setattr(page, "begin_loading", lambda _message: "inert loading")
    monkeypatch.setattr(page, "finish_loading", lambda _token: None)

    def advisor(record):
        received.append(record)
        return {"cve": record["cve"], "fix_available": False, "reason": record["name"]}

    monkeypatch.setattr(cve_fix_advisor, "analyze", advisor)
    dashboard._analyze_all()
    worker = dashboard._worker
    assert worker is not None and worker.wait(3000)
    _pump_until(lambda: dashboard._worker is None)
    assert received == [old, current]
    assert dashboard._table.isSortingEnabled()
    assert dashboard._cached_analysis(old["cve"], old)["reason"] == old["name"]
    assert dashboard._cached_analysis(current["cve"], current)["reason"] == current["name"]
    assert len(dashboard._fix_cache) == 2
    cells = []
    for row in range(dashboard._table.rowCount()):
        _cve, record = dashboard._table.item(row, dashboard._C_CVE).data(page.Qt.UserRole)
        cells.append((record["name"], dashboard._table.item(row, dashboard._C_FIX).text()))
    assert sorted(cells) == sorted((record["name"], "no fix") for record in records)


def test_each_distinct_visible_duplicate_row_can_request_detail_without_cache_crossover(
    monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    first = {"cve": "CVE-2026-6010", "name": "first visible row"}
    second = {**first, "name": "second visible row"}
    _show_records(monkeypatch, dashboard, [first, second])
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": False, "reason": rec["name"],
    })
    results = []
    first_worker = dashboard._start_detail_analysis(first["cve"], first, results.append)
    assert first_worker is not None and first_worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert dashboard._cached_analysis(first["cve"], first)["reason"] == first["name"]
    assert dashboard._cached_analysis(second["cve"], second) is None
    _snapshot, first_identity = page._analysis_snapshot(first)
    _snapshot, second_identity = page._analysis_snapshot(second)
    first_row = dashboard._row_for_cve(first["cve"], first_identity)
    second_row = dashboard._row_for_cve(second["cve"], second_identity)
    assert first_row != second_row
    assert dashboard._table.item(first_row, dashboard._C_FIX).text() == "no fix"
    assert dashboard._table.item(second_row, dashboard._C_FIX).text() == "—"

    second_worker = dashboard._start_detail_analysis(second["cve"], second, results.append)
    assert second_worker is not None and second_worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert [result["reason"] for result in results] == [first["name"], second["name"]]
    assert dashboard._cached_analysis(first["cve"], first)["reason"] == first["name"]
    assert dashboard._cached_analysis(second["cve"], second)["reason"] == second["name"]
    assert dashboard._detail_workers == {} and len(dashboard._fix_cache) == 2


@pytest.mark.parametrize("failure", [
    "loading", "connect", "start-before-native", "start-after-native", "unknown-live-state",
])
def test_failed_batch_start_restores_cache_and_keeps_live_or_unknown_owner(
    failure, monkeypatch, isolated_dashboards,
):
    create, releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-6011", "name": "current cached analysis"}
    _show_records(monkeypatch, dashboard, [record])
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": False, "reason": "prior current result",
    })
    prior = dashboard._start_detail_analysis(record["cve"], record, lambda _result: None)
    assert prior is not None and prior.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    previous_requests = dict(dashboard._analysis_requests)
    previous_cache = dict(dashboard._fix_cache)
    entered, release, _received = _held_freshness_advisor(monkeypatch, releases, count=1)
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    messages, loading_finished = [], []
    monkeypatch.setattr(page.QMessageBox, "information", lambda *args: messages.append(args))

    def begin(_message):
        if failure == "loading":
            raise RuntimeError("inert loading failure")
        return "inert startup token"

    monkeypatch.setattr(page, "begin_loading", begin)
    monkeypatch.setattr(page, "finish_loading", loading_finished.append)
    original_worker = page._FixWorker
    constructed = []

    class RefusedSignal:
        def connect(self, _callback):
            raise RuntimeError("inert connection failure")

    class FailedBatch(original_worker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._query_unknown = False
            constructed.append(self)

        def __getattribute__(self, name):
            if name == "result_for_request" and failure == "connect":
                return RefusedSignal()
            return super().__getattribute__(name)

        def start(self, *args, **kwargs):
            if failure in {"start-after-native", "unknown-live-state"}:
                super().start(*args, **kwargs)
                assert entered[0].wait(2.0)
                self._query_unknown = failure == "unknown-live-state"
            raise RuntimeError("inert start failure")

        def isRunning(self):
            if self._query_unknown and not release[0].is_set():
                raise RuntimeError("inert unavailable native state")
            return super().isRunning()

    monkeypatch.setattr(page, "_FixWorker", FailedBatch)
    with pytest.raises(RuntimeError, match="inert"):
        dashboard._analyze_all()
    assert len(constructed) == 1
    worker = constructed[0]
    assert dashboard._analysis_requests == previous_requests
    assert dashboard._fix_cache == previous_cache
    assert dashboard._cached_analysis(record["cve"])["reason"] == "prior current result"
    retained = failure in {"start-after-native", "unknown-live-state"}
    assert dashboard._loading_token == ("inert startup token" if retained else None)
    assert (worker in dashboard._batch_activities) is retained
    assert dashboard._batch_startup_cleanup_errors == ()
    assert "did not start successfully" in dashboard._footer.text()
    expected_loading = [] if retained or failure in {"loading", "connect"} else ["inert startup token"]
    assert loading_finished == expected_loading

    if failure in {"start-after-native", "unknown-live-state"}:
        assert dashboard._worker is worker
        assert QThread.isRunning(worker) and worker.isInterruptionRequested()
        assert dashboard._batch_retiring is worker and dashboard._batch_retire_timer.isActive()
        dashboard._analyze_all()
        assert len(constructed) == 1 and messages[-1][1] == "Busy"
        release[0].set()
        assert worker.wait(3000)
        _pump_until(lambda: dashboard._worker is None)
    else:
        assert dashboard._worker is None and dashboard._batch_retiring is None
        assert worker._batch_unused_disposable and not worker._batch_native_retirement_proven
    assert not dashboard._batch_retire_timer.isActive()
    assert dashboard._batch_retiring is None
    assert dashboard._fix_cache == previous_cache
    assert dashboard._loading_token is None and worker not in dashboard._batch_activities
    expected_final = [] if failure in {"loading", "connect"} else ["inert startup token"]
    assert loading_finished == expected_final
    assert detail_analysis_admission().active_count == 0


def test_current_lookup_and_result_do_not_reenumerate_unrelated_rows(
    monkeypatch, isolated_dashboards,
):
    create, _releases = isolated_dashboards
    dashboard = create()
    records = [{"cve": f"CVE-2026-{7000 + index}", "name": f"cohort {index}"}
               for index in range(257)]
    target = records[128]
    _show_records(monkeypatch, dashboard, records)

    class NoWholeListScan(list):
        def __iter__(self):
            raise AssertionError("ordinary lookup re-enumerated all current records")

    dashboard._matches = NoWholeListScan(records)
    original_identity = page._analysis_identity
    inspected = []

    def identity(record):
        inspected.append(record["cve"])
        assert record["cve"] == target["cve"], "unrelated record was rehashed"
        return original_identity(record)

    monkeypatch.setattr(page, "_analysis_identity", identity)
    monkeypatch.setattr(cve_fix_advisor, "analyze", lambda rec: {
        "cve": rec["cve"], "fix_available": False, "reason": "indexed current result",
    })
    results = []
    worker = dashboard._start_detail_analysis(target["cve"], target, results.append)
    assert worker is not None and worker.wait(3000)
    _pump_until(lambda: detail_analysis_admission().active_count == 0)
    assert len(results) == 1
    assert dashboard._cached_analysis(target["cve"], target) == results[0]
    assert inspected and set(inspected) == {target["cve"]}
    row = dashboard._row_for_cve(target["cve"])
    assert row >= 0 and dashboard._table.item(row, dashboard._C_FIX).text() == "no fix"


def test_unknown_live_batch_survives_delete_on_close_and_former_parent_deletion(
    monkeypatch,
):
    from angerona.gui import thread_lifecycle as lifecycle

    record = {"cve": "CVE-2026-6012", "name": "held close-lifetime control"}
    monkeypatch.setattr(page, "_load_threats", lambda: {"matches": [record]})
    monkeypatch.setattr(cve_ignore, "load", lambda: {})
    monkeypatch.setattr(cve_fix_advisor, "applied_state", lambda _cve: None)
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    monkeypatch.setattr(page, "begin_loading", lambda _message: "inert close token")
    loading_finished = []
    monkeypatch.setattr(page, "finish_loading", loading_finished.append)
    messages = []
    monkeypatch.setattr(page.QMessageBox, "information", lambda *args: messages.append(args))
    entered, release = threading.Event(), threading.Event()

    def advisor(rec):
        entered.set()
        assert release.wait(5.0)
        return {"cve": rec["cve"], "fix_available": False, "reason": "inert completed"}

    monkeypatch.setattr(cve_fix_advisor, "analyze", advisor)
    original_worker = page._FixWorker
    constructed = []

    class UnknownLiveStart(original_worker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            constructed.append(self)

        def start(self, *args, **kwargs):
            super().start(*args, **kwargs)
            assert entered.wait(2.0)
            raise RuntimeError("inert start failed after native launch")

        def isRunning(self):
            if not release.is_set():
                raise RuntimeError("inert live worker state unavailable")
            return super().isRunning()

    monkeypatch.setattr(page, "_FixWorker", UnknownLiveStart)
    original_drain = lifecycle._retry_deferred_close
    drains = []

    def observe_drain(owner):
        drains.append(owner)
        return original_drain(owner)

    monkeypatch.setattr(lifecycle, "_retry_deferred_close", observe_drain)
    former_parent = QWidget()
    dashboard = page.ThreatIntelDashboard(former_parent)
    dashboard.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    dashboard.show()
    owner_key = id(dashboard)
    retire_timer = dashboard._batch_retire_timer
    worker = None
    checks_completed = False
    try:
        with pytest.raises(RuntimeError, match="inert start failed"):
            dashboard._analyze_all()
        assert len(constructed) == 1
        worker = constructed[0]
        assert dashboard._worker is worker and QThread.isRunning(worker)
        assert dashboard.close() is False
        assert dashboard._angerona_deferred_close and not dashboard.isVisible()
        assert dashboard.parent() is None
        assert lifecycle._DEFERRED_OWNERS[owner_key] is dashboard
        assert dashboard.testAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        delete(former_parent)
        assert not isValid(former_parent)
        assert isValid(dashboard) and isValid(worker)

        # Observe both the initial queued drain and a later drain while state
        # remains unavailable; deferred deletion must stay blocked throughout.
        _pump_until(lambda: len(drains) >= 2)
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert isValid(dashboard) and isValid(worker) and QThread.isRunning(worker)
        assert dashboard._worker is worker and dashboard._batch_retiring is worker
        assert lifecycle._DEFERRED_OWNERS[owner_key] is dashboard
        assert retire_timer.isActive()
        dashboard._analyze_all()
        assert len(constructed) == 1 and messages[-1][1] == "Busy"
        checks_completed = True
    finally:
        release.set()
        if worker is not None and isValid(worker):
            assert worker.wait(3000)
        if isValid(former_parent):
            delete(former_parent)
        if not checks_completed and isValid(dashboard):
            dashboard.close()

    def fully_closed():
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        return not isValid(dashboard) and owner_key not in lifecycle._DEFERRED_OWNERS

    _pump_until(fully_closed)
    assert not isValid(retire_timer)
    assert worker is not None and not isValid(worker)
    assert loading_finished == ["inert close token"]


def _batch_native_wait_fixture(monkeypatch, isolated_dashboards, *, failed_start=False):
    """Real worker return plus a withheld wait(0) result, never a fake success."""
    create, releases = isolated_dashboards
    dashboard = create()
    record = {"cve": "CVE-2026-7711", "name": "native wait proof fixture"}
    _show_records(monkeypatch, dashboard, [record])
    entered, leave_advisor, permit_wait = (threading.Event() for _ in range(3))
    releases.extend((leave_advisor, permit_wait))
    loading_finished, wait_probes, workers = [], [], []
    monkeypatch.setattr(cve_fix_advisor, "ollama_available", lambda: True)
    monkeypatch.setattr(page, "begin_loading", lambda _message: "inert native-wait batch token")
    monkeypatch.setattr(page, "finish_loading", loading_finished.append)

    def advisor(rec):
        entered.set()
        assert leave_advisor.wait(5.0)
        return {"cve": rec["cve"], "fix_available": False, "reason": "inert returned"}

    monkeypatch.setattr(cve_fix_advisor, "analyze", advisor)
    original_worker = page._FixWorker

    class HeldNativeWait(original_worker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._query_unknown = False
            workers.append(self)

        def start(self, *args, **kwargs):
            result = super().start(*args, **kwargs)
            if failed_start:
                assert entered.wait(2.0)
                self._query_unknown = True
                raise RuntimeError("inert failed batch after native start")
            return result

        def isRunning(self):
            if self._query_unknown and not leave_advisor.is_set():
                raise RuntimeError("inert unknown batch native state")
            return super().isRunning()

        def wait(self, msecs=None):
            if msecs == 0 and not permit_wait.is_set():
                wait_probes.append(msecs)
                return False
            return super().wait() if msecs is None else super().wait(msecs)

    monkeypatch.setattr(page, "_FixWorker", HeldNativeWait)
    if failed_start:
        with pytest.raises(RuntimeError, match="inert failed batch"):
            dashboard._analyze_all()
    else:
        dashboard._analyze_all()
    assert entered.wait(2.0) and len(workers) == 1
    worker = workers[0]
    assert dashboard._worker is worker and worker._batch_retirement_retained
    return {
        "dashboard": dashboard, "worker": worker, "leave": leave_advisor,
        "permit_wait": permit_wait, "loading_finished": loading_finished,
        "wait_probes": wait_probes,
    }


@pytest.mark.parametrize("failed_start", [False, True])
def test_batch_activity_and_failed_start_wait_for_actual_native_wait_proof(
    monkeypatch, isolated_dashboards, failed_start,
):
    from angerona.gui.native_retirement import native_retirement_proven

    state = _batch_native_wait_fixture(
        monkeypatch, isolated_dashboards, failed_start=failed_start,
    )
    dashboard, worker = state["dashboard"], state["worker"]
    try:
        assert dashboard._loading_token == "inert native-wait batch token"
        assert worker in dashboard._batch_activities and not state["loading_finished"]
        if failed_start:
            assert worker._startup_failed and worker.isInterruptionRequested()
        state["leave"].set()
        assert QThread.wait(worker, 3000)  # Actual owned native return, bypassing only the negative fixture gate.
        assert QThread.isFinished(worker) is True
        _pump_until(lambda: bool(state["wait_probes"]))
        assert dashboard._worker is worker and dashboard._batch_retiring is worker
        assert dashboard._batch_retire_timer.isActive()
        assert dashboard._loading_token == "inert native-wait batch token"
        assert worker in dashboard._batch_activities
        assert not worker._batch_native_retirement_proven and not native_retirement_proven(worker)
        assert state["loading_finished"] == []

        state["permit_wait"].set()  # Later wait(0) calls the real Qt implementation.
        _pump_until(lambda: dashboard._worker is None)
        assert worker._batch_native_retirement_proven and native_retirement_proven(worker)
        assert worker._batch_owner_settled and not worker._batch_unused_disposable
        assert dashboard._loading_token is None and worker not in dashboard._batch_activities
        assert state["loading_finished"] == ["inert native-wait batch token"]
        dashboard._release_batch_worker(worker)
        assert state["loading_finished"] == ["inert native-wait batch token"]
    finally:
        state["leave"].set()
        state["permit_wait"].set()
        _pump_until(lambda: dashboard._worker is None)


def test_batch_close_detaches_parent_and_stays_responsive_until_native_wait_proof(
    monkeypatch, isolated_dashboards,
):
    from PySide6.QtCore import QTimer

    state = _batch_native_wait_fixture(monkeypatch, isolated_dashboards)
    dashboard, worker = state["dashboard"], state["worker"]
    former_parent = QWidget()
    dashboard.setParent(former_parent, dashboard.windowFlags())
    dashboard.show()
    owner_key = id(dashboard)
    responsive = []
    try:
        state["leave"].set()
        assert QThread.wait(worker, 3000) and QThread.isFinished(worker)
        _pump_until(lambda: bool(state["wait_probes"]))
        assert dashboard.close() is False
        assert dashboard._batch_close_pending and not dashboard.isVisible()
        assert dashboard.parent() is None
        assert page._BATCH_DEFERRED_OWNERS[owner_key] is dashboard
        delete(former_parent)
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert isValid(dashboard) and isValid(worker)
        assert dashboard._worker is worker and not state["loading_finished"]
        QTimer.singleShot(0, lambda: responsive.append(True))
        _pump_until(lambda: bool(responsive))
        assert dashboard._worker is worker and dashboard._batch_retire_timer.isActive()
        assert not worker._batch_native_retirement_proven

        state["permit_wait"].set()
        _pump_until(lambda: dashboard._worker is None
                    and owner_key not in page._BATCH_DEFERRED_OWNERS)
        assert state["loading_finished"] == ["inert native-wait batch token"]
        assert not dashboard._batch_close_pending
    finally:
        state["leave"].set()
        state["permit_wait"].set()
        _pump_until(lambda: dashboard._worker is None)
        if isValid(former_parent):
            delete(former_parent)
        dashboard.close()


def test_invalid_batch_wrapper_without_prior_native_proof_is_held(isolated_dashboards):
    create, _releases = isolated_dashboards
    dashboard = create()
    worker = page._FixWorker([], dashboard)  # Never started: no real native resource exists in this negative fixture.
    delete(worker)
    assert not isValid(worker)
    assert dashboard._batch_retirement_ready(worker) is False
    assert not worker._batch_native_retirement_proven and not worker._batch_unused_disposable
