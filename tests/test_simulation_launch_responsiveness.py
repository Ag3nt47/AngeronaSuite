"""GUI responsiveness across the current sequential Session boundary.

Inert Session adapters prove presentation/ownership only. Actual detector,
lease, response and authenticated report behavior has separate native tests.
"""
from __future__ import annotations

import os
import threading
from unittest.mock import Mock

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer

from angerona.gui.red_team_console import RedTeamConsole
from angerona.gui.simulation_launch import SimulationLaunch
from simulation_gui_fixture import build_launch, drain, retire_launch


@pytest.fixture
def launch(tmp_path, monkeypatch):
    context = build_launch(tmp_path, monkeypatch, block_prepare=True)
    for key, value in (("ANGERONA_SOAR_KILL_AND_ROLLBACK", "0"),
        ("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH"),
        ("ANGERONA_SOAR_RESPONSE_SCOPE", "prior scope")):
        monkeypatch.setenv(key, value)
    yield context
    retire_launch(context)


def test_blocked_preparation_keeps_qt_alive_and_preserves_selected_profiles(launch):
    owner = launch.owner
    assert owner._run_simulation(launch.cfg)["status"] == "preparing"
    job = owner._sim_launch_job
    assert launch.prepare_entered.wait(2)
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    drain(lambda: bool(ticks))
    assert launch.prepare_threads == [job.thread.ident]
    assert job.thread.ident != threading.get_ident()
    assert owner.statuses[-1]["status"] == "preparing"
    launch.prepare_release.set()
    drain(lambda: owner._sim_launch_job is None)
    job.thread.join(2)
    assert not job.thread.is_alive() and job.accepted
    session = owner._simulation_session
    assert session.cfg == launch.cfg
    assert {run.kind for run in owner._simulation_plan.runs} == {"red_team", "shark"}
    assert owner.statuses[-1]["status"] == "accepted"
    assert owner._sim_aar_pending == 1  # Custody sentinel, not two fake AARs.
    assert launch.start_threads == [job.thread.ident]
    owner.red_team_engine.start.assert_not_called()
    owner.shark_engine.start.assert_not_called()
    assert not owner._sim_response_escalated


def test_cancel_during_preparation_never_starts_or_accepts_session(launch):
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert launch.prepare_entered.wait(2)
    owner._stop_simulation()
    assert job.cancelled.is_set() and not job.finished.is_set()
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    drain(lambda: bool(ticks))
    launch.prepare_release.set()
    drain(lambda: owner._sim_launch_job is None)
    job.thread.join(2)
    assert not job.thread.is_alive()
    assert not launch.started.is_set()
    assert owner.statuses[-1]["status"] == "rejected"
    assert owner._sim_aar_pending == 0
    assert os.environ["ANGERONA_SOAR_RESPONSE_SCOPE"] == "prior scope"


def test_stop_after_start_before_gui_handoff_preserves_exact_session_custody(launch):
    launch.prepare_release.set()
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert job.ready.wait(2) and job.claim()
    assert launch.started.wait(2) and job.finished.wait(2)
    job.thread.join(2)
    owner._stop_simulation()
    assert job.cancelled.is_set() and job.session.cancelled.is_set()
    assert job.session.thread in job.owned_workers()
    assert job.session.thread.is_alive()
    owner._poll_simulation_launch()
    # Actual start acknowledgement can be accepted; cancellation never erases
    # the ownership of a native child which already exists.
    assert owner._simulation_session is job.session
    assert owner._session_is_active()
    assert owner._sim_aar_pending == 1
    launch.retire_release.set()
    job.session.thread.join(2)
    drain(lambda: not owner._session_is_active())


def test_lost_session_start_ack_holds_owned_child_without_false_acceptance(launch):
    launch.lose_ack = True
    launch.prepare_release.set()
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    drain(lambda: job.finished.is_set())
    assert launch.started.is_set() and job.session.thread.is_alive()
    assert not job.accepted and job.session.cancelled.is_set()
    assert owner._sim_launch_job is job
    assert not any(row["status"] == "accepted" for row in owner.statuses)
    assert owner._sim_aar_pending == 0
    launch.retire_release.set()
    job.session.thread.join(2)
    drain(lambda: owner._sim_launch_job is None)
    assert owner.statuses[-1]["status"] == "rejected"
    assert "lost acknowledgement" in owner.statuses[-1]["reason"]


def test_destroyed_owner_cancels_detached_preparation_without_late_qt_delivery(launch):
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert launch.prepare_entered.wait(2)
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert job.cancelled.is_set()
    launch.prepare_release.set()
    job.thread.join(3)
    assert not job.thread.is_alive() and not launch.started.is_set()
    assert not any(row["status"] == "accepted" for row in owner.statuses)


def test_duplicate_launch_cannot_overlap_pending_preparation(launch):
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    assert launch.prepare_entered.wait(2)
    assert owner._run_simulation(launch.cfg)["status"] == "rejected"
    assert owner._sim_launch_job is job
    assert len(launch.prepare_threads) == 1


def test_cleanup_button_runs_blocked_legacy_cleanup_once_off_qt(launch):
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
        drain(lambda: bool(ticks))
        assert identities == [worker.ident] and worker.ident != threading.get_ident()
    finally:
        release.set()
        owner._sim_stop_thread.join(2)
        assert not owner._sim_stop_thread.is_alive()
    owner.red_team_engine.stop_and_clean.assert_called_once()
    owner.shark_engine.stop_and_clean.assert_called_once()


def test_worker_start_failure_clears_pending_launch_without_session_start(launch, monkeypatch):
    monkeypatch.setattr(SimulationLaunch, "start", Mock(side_effect=RuntimeError("no worker")))
    assert launch.owner._run_simulation(launch.cfg)["status"] == "rejected"
    assert launch.owner._sim_launch_job is None
    assert not launch.started.is_set()
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "0"


@pytest.mark.parametrize("raises", [False, True])
def test_session_start_refusal_keeps_no_false_acceptance_or_report_credit(launch, raises):
    launch.refuse_start = not raises
    launch.start_error = RuntimeError("inert session refusal") if raises else None
    launch.prepare_release.set()
    owner = launch.owner
    owner._run_simulation(launch.cfg)
    job = owner._sim_launch_job
    drain(lambda: owner._sim_launch_job is None)
    job.thread.join(2)
    assert not job.thread.is_alive() and not job.accepted
    assert not launch.started.is_set()
    assert owner._sim_aar_pending == 0
    assert not hasattr(owner, "_sim_poll")
    assert owner.statuses[-1]["status"] == "rejected"
    assert os.environ["ANGERONA_SOAR_RESPONSE_SCOPE"] == "prior scope"


def test_stop_worker_start_failure_does_not_leave_permanent_busy_state(launch, monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", Mock(side_effect=RuntimeError("no thread")))
    launch.owner._stop_simulation()
    assert launch.owner._sim_stop_complete.is_set()
    assert "Could not dispatch marker cleanup" in launch.owner.lines[-1]


def test_cleanup_failure_is_reported_without_claiming_success(launch):
    launch.owner.red_team_engine.stop_and_clean.side_effect = PermissionError("inert denied cleanup")
    dialog = RedTeamConsole(launch.owner)
    launch.owner._rt_console = dialog
    try:
        launch.owner._stop_simulation()
        drain(lambda: bool(launch.owner.lines))
        assert "Marker cleanup incomplete" in launch.owner.lines[-1]
        assert "inert denied cleanup" in dialog.live_status.text()
        assert "No cleanup success is claimed" in dialog.live_status.text()
        assert dialog._run_cancelled
        launch.owner.shark_engine.stop_and_clean.assert_called_once()
    finally:
        dialog.deleteLater()
        launch.owner._rt_console = None


def test_console_close_cancels_preparation_without_dropping_owned_worker(launch):
    dialog = RedTeamConsole(launch.owner)
    dialog.show()
    launch.owner._rt_console = dialog
    try:
        dialog._report_runs = {"red_team": "previous-run"}
        launch.owner._run_simulation(launch.cfg)
        job = launch.owner._sim_launch_job
        assert launch.prepare_entered.wait(2)
        assert "Preparing simulation" in dialog.live_status.text()
        assert dialog._run_pending and not dialog.launch_btn.isEnabled()
        dialog.record_verified_report("red_team", "previous-run", None, error="late old report")
        assert "Preparing simulation" in dialog.live_status.text()
        launch.owner._run_simulation(launch.cfg)
        assert dialog._run_pending
        dialog.close()
        assert job.cancelled.is_set() and job.thread.is_alive()
        launch.prepare_release.set()
        drain(lambda: launch.owner._sim_launch_job is None)
        job.thread.join(2)
        assert not job.thread.is_alive() and not dialog._run_pending
    finally:
        dialog.deleteLater()
        launch.owner._rt_console = None
