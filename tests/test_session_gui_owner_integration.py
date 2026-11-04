"""Exclusive GUI custody, not a substitute for native Session backend gates."""
import threading
from types import MethodType, SimpleNamespace

import pytest

from angerona.core.source_activation import source_activation_resource_retirement_proven
from angerona.gui.main_window import MainWindow
from angerona.gui.simulation_launch import SessionReportInbox
from angerona.shark.simulation_session import LaunchDiagnostic
from test_session_gui_launch_custody import _plan, _report


class _Timer:
    def __init__(self):
        self.stops = 0

    def stop(self):
        self.stops += 1

    def deleteLater(self):
        self.deleted = True


class _Signal:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback):
        self.callbacks.append(callback)

    def disconnect(self, callback):
        self.callbacks.remove(callback)


class _AdoptionTimer(_Timer):
    def __init__(self, _parent=None):
        super().__init__()
        self.timeout, self.starts, self.deleted = _Signal(), 0, False

    def start(self):
        self.starts += 1

    def setInterval(self, interval):
        self.interval = interval

    def deleteLater(self):
        self.deleted = True


@pytest.fixture
def session_view():
    release = threading.Event()
    worker = threading.Thread(target=lambda: release.wait(5), daemon=True)
    worker.start()
    plan = _plan()
    state = SimpleNamespace(phase="queued", reports=(), cancelled=0, diagnostics=(), custody=True)
    finished = threading.Event()
    def cancel():
        state.cancelled += 1
    session = SimpleNamespace(finished=finished, owned_workers=lambda: (worker,), cancel=cancel,
        snapshot=lambda: {"schema": 1, "session_id": plan.session_id, "session_generation": plan.generation,
                          "phase": state.phase, "current_task": "Current owned step"},
        completed_reports=lambda: state.reports, performance_snapshot=lambda _run: None,
        launch_diagnostics=lambda: state.diagnostics,
        retirement_snapshot=lambda: {"schema": 1, "session_id": plan.session_id,
            "session_generation": plan.generation, "custody_released": state.custody,
            "lease_active": not state.custody, "reservation_active": False,
            "owner_pending": False, "retirement_held": False, "response_authorized": False})
    shown, messages, button, progress = [], [], [], []
    console = SimpleNamespace(_run_pending=True, _run_cancelled=False,
        launch_btn=SimpleNamespace(setEnabled=button.append), update_execution_progress=progress.append,
        record_performance_snapshot=lambda _row: None, record_session_lifecycle=lambda _row: None,
        _render_execution_progress=lambda: None)
    view = SimpleNamespace(_simulation_session=session, _simulation_plan=plan, _termination_started=False,
        _session_reports=SessionReportInbox(plan), _session_missing_reports=set(), _session_ui_finished=False,
        _session_status_key=None, _rt_console=console, _sim_poll=_Timer(),
        red_team_engine=SimpleNamespace(run_id="old", is_running=False),
        shark_engine=SimpleNamespace(run_id="old", is_running=False),
        console=SimpleNamespace(_append=messages.append), shark_monitor=SimpleNamespace(append=messages.append),
        shark_swim=_Timer(), shark_banner=_Timer(), _eco_on=False, _sim_launch_job=None,
        _show_aar_dialog=shown.append)
    for name in ("_session_is_active", "_poll_sequential_session", "_session_report_failure",
                 "_cancel_simulation_launch", "_sim_check_done"):
        setattr(view, name, MethodType(getattr(MainWindow, name), view))
    def retire(phase="completed"):
        state.phase = phase
        finished.set()
        release.set()
        worker.join(5)
        assert not worker.is_alive()
    yield SimpleNamespace(view=view, state=state, plan=plan, session=session, shown=shown,
                          messages=messages, button=button, progress=progress, retire=retire, worker=worker)
    release.set()
    worker.join(5)
    assert not worker.is_alive()


def test_queued_not_running_engines_are_not_completed(session_view):
    h = session_view
    h.view._poll_sequential_session()
    assert h.view._session_is_active() and h.view._sim_aar_pending == 1
    assert h.button == [False] and not h.shown and h.view._sim_poll.stops == 0
    assert all(row["finished"] == 0 for row in h.progress[-1].values())


def test_actual_ack_adopts_exact_plan_then_binds_badge_and_existing_poll(session_view, monkeypatch):
    import angerona.gui.main_window as module
    h, calls = session_view, []
    monkeypatch.setattr(module, "QTimer", _AdoptionTimer)
    prep = threading.Thread(target=lambda: None)
    prep.start()
    prep.join(5)
    ready = threading.Event()
    ready.set()
    job = SimpleNamespace(thread=prep, ready=ready, accepted=True, success=True, _claimed=True,
        session=h.session, plan=h.plan, cfg={"auto_remediate": False}, cancelled=threading.Event(),
        cancel=h.session.cancel)
    h.view._simulation_session = h.view._simulation_plan = None
    h.view._sim_launch_job, h.view._sim_launch_timer = job, _AdoptionTimer()
    h.view.destroyed = _Signal()
    h.view.destroyed.connect(job.cancel)
    h.view._retire_simulation_launch_view = MethodType(MainWindow._retire_simulation_launch_view, h.view)
    def accepted(status, _reason, cfg):
        assert status == "accepted" and cfg == job.cfg
        assert h.view._sim_report_runs == {run.kind: run.run_id for run in h.plan.runs}
        calls.append("accepted")
    h.view._simulation_launch_status = accepted
    h.view._rt_console.bind_performance_session = lambda sid, generation, plans: calls.append(
        (sid, generation, plans))
    h.view._poll_sequential_session = lambda: calls.append("cached-poll")
    h.view.shark_swim.start = h.view.shark_banner.start = lambda: None
    MainWindow._poll_simulation_launch(h.view)
    assert h.view._simulation_session is h.session and h.view._simulation_plan is h.plan
    assert h.view._sim_launch_job is None and h.view._sim_response_escalated is False
    assert calls == ["accepted", (h.plan.session_id, h.plan.generation,
        {run.run_id: run.plan_sha256 for run in h.plan.runs}), "cached-poll"]
    assert h.view._sim_poll.interval == 500 and h.view._sim_poll.starts == 1
    assert h.session.cancel in h.view.destroyed.callbacks


def test_cached_new_reports_are_routed_once_while_next_profile_is_queued(session_view):
    h = session_view
    report = _report(h.plan.runs[0])
    h.state.reports = (report,)
    h.view._poll_sequential_session()
    h.view._poll_sequential_session()
    assert h.shown == [report]
    assert h.view._sim_aar_pending == 1 and h.button[-1] is False


def test_finished_event_without_actual_worker_exit_is_not_terminal(session_view):
    h = session_view
    h.session.finished.set()
    h.view._poll_sequential_session()
    assert h.view._sim_aar_pending == 1 and not h.view._session_ui_finished
    assert h.view._sim_poll.stops == 0


def test_retired_session_keeps_launch_and_store_custody_held_until_real_release(session_view):
    h = session_view
    h.state.custody = False
    h.retire("held")
    h.view._poll_sequential_session()
    assert h.view._session_is_active() and h.button[-1] is False
    assert h.view._sim_poll.stops == 0
    simulation_hold, source_update_hold = MainWindow._retained_shutdown_custody(h.view)
    assert simulation_hold.label == "simulation-lease-and-session-custody"
    assert simulation_hold.owner is h.session and simulation_hold.released() is False
    assert source_update_hold.label == "source-update-resource-retirement"
    assert source_update_hold.owner is source_activation_resource_retirement_proven
    assert source_update_hold.released is source_activation_resource_retirement_proven
    assert source_update_hold.released() is True
    h.state.custody = True
    h.view._poll_sequential_session()
    assert not h.view._session_is_active() and h.button[-1] is True
    assert h.view._sim_poll.stops == 1 and simulation_hold.released() is True
    assert source_update_hold.released() is True


def test_terminal_missing_report_is_diagnostic_not_signed_pass_or_fabricated_miss(session_view):
    h = session_view
    h.state.diagnostics = (LaunchDiagnostic(h.plan.session_id, h.plan.runs[0].run_id,
        "reporting", "SessionHeld", "Exact evidence missing"),)
    h.retire("held")
    h.view._poll_sequential_session()
    h.view._poll_sequential_session()
    assert len(h.shown) == 2
    assert all(type(row) is dict and row.get("error") for row in h.shown)
    assert all("score" not in row and "detection_missed" not in row for row in h.shown)
    assert h.view._sim_aar_pending == 0 and h.button[-1] is True
    assert all(row["finished"] == 0 and row["state"] == "incomplete" for row in h.progress[-1].values())


def test_snapshot_binding_loss_cancels_without_accepting_live_performance(session_view):
    h = session_view
    h.session.snapshot = lambda: {"session_id": "other", "session_generation": 1}
    h.session.performance_snapshot = lambda _run: pytest.fail("Foreign snapshot cannot publish performance")
    h.view._poll_sequential_session()
    assert h.state.cancelled == 1 and h.view._sim_aar_pending == 1
    h.retire("held")
    h.view._poll_sequential_session()
    assert h.view._session_ui_finished and all(type(row) is dict for row in h.shown)


@pytest.mark.parametrize("method", ["_sim_check_done", "_red_team_check_done", "_shark_check_done"])
def test_all_completion_polls_delegate_to_session_not_engine_presence(session_view, method):
    h = session_view
    calls = []
    h.view._poll_sequential_session = lambda: calls.append("session")
    getattr(MainWindow, method)(h.view)
    assert calls == ["session"]


@pytest.mark.parametrize("method", ["_red_team_build_aar", "_shark_build_aar", "_simulation_aar_finished"])
def test_legacy_builders_and_policy_restore_never_own_session_report(session_view, method):
    # The minimalist shell has no storage/config/lease; any attempted legacy
    # generation or release would fail instead of silently passing this test.
    getattr(MainWindow, method)(session_view.view)


def test_stop_cancels_session_without_starting_second_engine_cleanup(session_view):
    h = session_view
    MainWindow._stop_simulation(h.view)
    assert h.state.cancelled == 1 and h.worker.is_alive()
    assert not hasattr(h.view, "_sim_stop_thread")


def test_admitted_session_blocks_patch_even_between_engine_runs(session_view):
    h = session_view
    assert MainWindow._admit_aar_work(h.view, SimpleNamespace(), "fix") is False


def test_operator_cleanup_does_not_repeat_session_lease_or_engine_cleanup(session_view):
    h = session_view
    h.retire()
    h.view.red_team_engine.stop_and_clean = lambda: pytest.fail("Duplicate engine cleanup")
    h.view.shark_engine.stop_and_clean = lambda: pytest.fail("Duplicate engine cleanup")
    h.view._release_redteam_validation_lease = lambda: pytest.fail("Duplicate lease release")
    calls = []
    h.view._shutdown_callback = lambda: calls.append("stores")
    MainWindow._operator_stop_cleanup(h.view)
    assert calls == ["stores"]


def test_stop_retains_pre_adoption_session_children(session_view):
    h = session_view
    prep = threading.Thread(target=lambda: None)
    prep.start()
    prep.join(5)
    h.view._simulation_session = None
    h.view._sim_launch_job = SimpleNamespace(thread=prep, owned_workers=lambda: (prep, h.worker))
    h.view._shutdown_view_owners = lambda: ()
    h.view.findChildren = lambda _kind: ()
    rows = MainWindow._retained_shutdown_workers(h.view)
    assert {id(row.worker) for row in rows} >= {id(prep), id(h.worker)}
    assert next(row for row in rows if row.worker is h.worker).before_cleanup
