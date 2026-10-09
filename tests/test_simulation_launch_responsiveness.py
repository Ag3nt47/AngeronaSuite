"""Slow drill readiness and cleanup must not block Qt or bypass safety gates."""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QMainWindow
from shiboken6 import isValid

from angerona.gui.main_window import MainWindow
from angerona.gui.red_team_console import RedTeamConsole
from angerona.gui.simulation_launch import SimulationLaunch


def _drain(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(0.002)
    assert predicate()


class _Window(MainWindow):
    def __init__(self, root):
        QMainWindow.__init__(self)
        self.ui_thread = threading.get_ident()
        self.statuses = []
        self.lines = []
        self.manager = SimpleNamespace(modules={})
        self.config = SimpleNamespace(data_dir=root)
        self.bus, self.storage = object(), object()
        self._eco_on = False
        self._chill_policy = SimpleNamespace(enabled=False)
        self.console = SimpleNamespace(_append=self._append)
        self.shark_monitor = Mock()
        self.shark_swim, self.shark_banner = Mock(), Mock()
        for name in ("red_team_engine", "shark_engine"):
            engine = SimpleNamespace(
                is_running=False, run_id=name + "-run", default_documents_dir=root / "markers",
                hold_evidence_for_aar=Mock(), cancel_evidence_hold=Mock(),
                start=Mock(return_value=True), stop_and_clean=Mock(),
            )
            setattr(self, name, engine)

    def _append(self, text):
        assert threading.get_ident() == self.ui_thread
        self.lines.append(text)

    def _simulation_launch_status(self, *args, **kwargs):
        assert threading.get_ident() == self.ui_thread
        result = super()._simulation_launch_status(*args, **kwargs)
        self.statuses.append(result)
        return result

    def _sim_check_done(self):
        pass  # No real AAR, files or modules in a presentation fixture.


@pytest.fixture
def launch(tmp_path, monkeypatch):
    owner = _Window(tmp_path)
    release, entered = threading.Event(), threading.Event()
    threads = []
    lease = SimpleNamespace(readiness={"policy_count": 37, "sensor_health": 100}, release=Mock())
    def acquire(*_args, **_kwargs):
        threads.append(threading.get_ident())
        entered.set()
        assert release.wait(5), "Test forgot to release inert readiness"
        return lease
    monkeypatch.setattr("angerona.modules.purple_guard.acquire_redteam_validation_lease", acquire)
    monkeypatch.setattr("angerona.shark.run_manifest.preflight_run",
                        Mock(return_value=SimpleNamespace(accepted=True)))
    for module in ("file_integrity", "yara_scanner"):
        monkeypatch.setattr(f"angerona.modules.{module}.register_runtime_watch", Mock(return_value=True))
        monkeypatch.setattr(f"angerona.modules.{module}.unregister_runtime_watch", Mock())
    monkeypatch.setattr("angerona.gui.simulation_launch.reconcile_module_usage", Mock())
    monkeypatch.setattr("angerona.gui.main_window.reconcile_module_usage", Mock())
    monkeypatch.setattr("angerona.gui.main_window.QMessageBox.information", Mock())
    monkeypatch.setattr("angerona.core.drill_readiness.assess_drill_response", lambda *_a, **_k: {
        "ready": True, "state": "ARMED", "reason": "memory readiness",
    })
    for key, value in (
        ("ANGERONA_SOAR_KILL_AND_ROLLBACK", "0"),
        ("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH"),
        ("ANGERONA_SOAR_RESPONSE_SCOPE", "prior scope"),
    ):
        monkeypatch.setenv(key, value)
    cfg = {"run_redteam": True, "run_shark": True, "intensity": "Extreme", "complexity": 4,
           "campaign": True, "comprehensive": True, "auto_remediate": True}
    fixture = SimpleNamespace(owner=owner, release=release, entered=entered, lease=lease,
                              threads=threads, cfg=cfg)
    yield fixture
    release.set()
    job = getattr(owner, "_sim_launch_job", None)
    if job is not None:
        job.cancel()
        job.thread.join(5)
        assert not job.thread.is_alive()
    stop = getattr(owner, "_sim_stop_thread", None)
    if stop is not None:
        stop.join(5)
        assert not stop.is_alive()
    if isValid(owner):
        owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_blocked_validation_keeps_qt_alive_and_all_selected_exercises(launch):
    owner = launch.owner
    assert owner._run_simulation(launch.cfg)["status"] == "preparing"
    job = owner._sim_launch_job
    assert launch.entered.wait(2)
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    _drain(lambda: bool(ticks))
    assert owner.statuses[-1]["status"] == "preparing"
    assert launch.threads == [job.thread.ident]
    assert job.thread.ident != threading.get_ident()
    owner.red_team_engine.start.assert_not_called()
    launch.release.set()
    _drain(lambda: owner._sim_launch_job is None)
    job.thread.join(2)
    assert owner.statuses[-1]["status"] == "accepted"
    assert owner._sim_aar_pending == 2
    kwargs = owner.red_team_engine.start.call_args.kwargs
    assert kwargs["intensity"] == "Extreme"
    assert kwargs["campaign"] and kwargs["comprehensive"]
    assert kwargs["validation_lease"] is launch.lease
    assert owner.shark_engine.start.call_args.kwargs["complexity"] == 4


def test_cancel_during_readiness_rolls_back_without_late_engine_start(launch):
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert launch.entered.wait(2)
    owner._stop_simulation()
    assert job.cancelled.is_set()
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    _drain(lambda: bool(ticks))
    assert not job.finished.is_set()
    launch.release.set()
    _drain(lambda: owner._sim_launch_job is None)
    job.thread.join(2)
    owner.red_team_engine.start.assert_not_called()
    owner.shark_engine.start.assert_not_called()
    launch.lease.release.assert_called_once()
    assert owner.statuses[-1]["status"] == "rejected"
    assert owner._sim_aar_pending == 0
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "0"
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY"] == "HIGH"
    assert os.environ["ANGERONA_SOAR_RESPONSE_SCOPE"] == "prior scope"


def test_cancel_after_start_before_gui_handoff_cleans_once_and_never_accepts(launch):
    owner = launch.owner
    launch.release.set()
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert job.ready.wait(2)  # Do not dispatch Qt's acceptance callback yet.
    assert job.success
    owner._stop_simulation()
    assert job.finished.wait(2)
    _drain(lambda: owner._sim_launch_job is None)
    for engine in (owner.red_team_engine, owner.shark_engine):
        engine.start.assert_called_once()
        engine.stop_and_clean.assert_called_once()
    launch.lease.release.assert_called_once()
    assert all(result["status"] != "accepted" for result in owner.statuses)


def test_destroyed_owner_cancels_detached_preparation_without_late_qt_access(launch):
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert launch.entered.wait(2)
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert job.cancelled.is_set()
    launch.release.set()
    job.thread.join(3)
    assert not job.thread.is_alive()
    launch.lease.release.assert_called_once()
    owner.red_team_engine.start.assert_not_called()
    assert not any(result["status"] == "accepted" for result in owner.statuses)
    # Fixture sees a deleted wrapper; detach ownership without native calls.
    owner._sim_launch_job = None


def test_duplicate_launch_cannot_overlap_pending_preparation(launch):
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert launch.entered.wait(2)
    assert owner._run_simulation(launch.cfg)["status"] == "rejected"
    assert owner._sim_launch_job is job
    assert len(launch.threads) == 1


def test_cleanup_button_runs_blocked_cleanup_once_off_qt(launch):
    owner = launch.owner
    entered, release = threading.Event(), threading.Event()
    identities = []
    def clean():
        identities.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
    owner.red_team_engine.stop_and_clean.side_effect = clean
    try:
        owner._stop_simulation()
        assert entered.wait(2)
        worker = owner._sim_stop_thread
        owner._stop_simulation()
        assert owner._sim_stop_thread is worker
        ticks = []
        QTimer.singleShot(0, lambda: ticks.append(True))
        _drain(lambda: bool(ticks))
        assert identities == [worker.ident]
        assert worker.ident != threading.get_ident()
    finally:
        release.set()
        owner._sim_stop_thread.join(2)
    owner.red_team_engine.stop_and_clean.assert_called_once()
    owner.shark_engine.stop_and_clean.assert_called_once()


def test_worker_start_failure_clears_pending_launch_state(launch, monkeypatch):
    monkeypatch.setattr(SimulationLaunch, "start", Mock(side_effect=RuntimeError("no worker")))
    assert launch.owner._run_simulation(launch.cfg)["status"] == "rejected"
    assert launch.owner._sim_launch_job is None
    launch.owner.red_team_engine.start.assert_not_called()
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "0"


@pytest.mark.parametrize("raises", [False, True])
def test_second_engine_refusal_cleans_partial_start_without_scheduling_aar(launch, raises):
    owner = launch.owner
    if raises:
        owner.shark_engine.start.side_effect = RuntimeError("Shark worker could not start")
    else:
        owner.shark_engine.start.return_value = False
    launch.release.set()
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    _drain(lambda: owner._sim_launch_job is None)
    assert job.finished.is_set()
    owner.red_team_engine.stop_and_clean.assert_called_once()
    launch.lease.release.assert_called_once()
    assert owner._sim_aar_pending == 0
    assert not hasattr(owner, "_sim_poll")
    assert owner.statuses[-1]["status"] == "rejected"
    assert "Shark" in owner.statuses[-1]["reason"]
    assert os.environ["ANGERONA_SOAR_RESPONSE_SCOPE"] == "prior scope"


def test_stop_worker_start_failure_does_not_leave_permanent_busy_state(launch, monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", Mock(side_effect=RuntimeError("no thread")))
    launch.owner._stop_simulation()
    assert launch.owner._sim_stop_complete.is_set()
    assert "Could not dispatch marker cleanup" in launch.owner.lines[-1]
    launch.owner._sim_stop_thread = None


def test_cleanup_failure_is_reported_without_claiming_success(launch):
    launch.owner.red_team_engine.stop_and_clean.side_effect = PermissionError("inert denied cleanup")
    dialog = RedTeamConsole(launch.owner)
    launch.owner._rt_console = dialog
    try:
        launch.owner._stop_simulation()
        _drain(lambda: bool(launch.owner.lines))
        assert "Marker cleanup incomplete" in launch.owner.lines[-1]
        assert "inert denied cleanup" in dialog.live_status.text()
        assert "No cleanup success is claimed" in dialog.live_status.text()
        assert dialog._run_cancelled
        launch.owner.shark_engine.stop_and_clean.assert_called_once()
    finally:
        dialog.deleteLater()
        launch.owner._rt_console = None


def test_console_close_cancels_only_pending_preparation(launch):
    dialog = RedTeamConsole(launch.owner)
    dialog.show()
    launch.owner._rt_console = dialog
    try:
        dialog._report_runs = {"red_team": "previous-run"}
        launch.owner._run_simulation(launch.cfg)
        job = launch.owner._sim_launch_job
        assert launch.entered.wait(2)
        assert "Preparing simulation" in dialog.live_status.text()
        assert dialog._run_pending and not dialog.launch_btn.isEnabled()
        dialog.record_verified_report("red_team", "previous-run", None, error="late old report")
        assert "Preparing simulation" in dialog.live_status.text()
        launch.owner._run_simulation(launch.cfg)
        assert dialog._run_pending and not dialog.launch_btn.isEnabled()
        assert "Preparing simulation" in dialog.live_status.text()
        dialog.close()
        assert job.cancelled.is_set()
        launch.release.set()
        _drain(lambda: launch.owner._sim_launch_job is None)
        assert not dialog._run_pending
    finally:
        dialog.deleteLater()
        launch.owner._rt_console = None
