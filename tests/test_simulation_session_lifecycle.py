"""Whole-workflow presentation needs native owner return plus cached release."""
from dataclasses import replace
import threading

import pytest

from angerona.gui.red_team_console import SessionLifecycleProjection
from test_drill_response_ui import console  # noqa: F401 - real owned Qt fixture
from test_session_gui_owner_integration import session_view  # noqa: F401 - exact-thread GUI shell


_RUN, _SESSION, _PLAN = "redteam-lifecycle", "session-lifecycle", "c" * 64


def _projection(**changes):
    return replace(SessionLifecycleProjection(_SESSION, 1, ((_RUN, _PLAN),), "releasing",
        True, False, False, False), **changes)


def _report():
    return {"run_id": _RUN, "outcome": "verified", "coverage_score_eligible": True,
        "steps_run": 6, "detection_steps": 6, "detection_caught": 6,
        "epistemic_metrics": {"verified_containment": {"count": 6, "eligible": 6, "rate": 1.0}},
        "evidence_taxonomy": {"denominator": 6, "compatible_analytic_union": {"count": 6},
            "native_analytic_detection": {"count": 6}, "simulation_contract_validation": {"count": 0}}}


def _ready(dialog):
    dialog.set_launch_status({"status": "accepted", "runs": {"red_team": _RUN}}, {"auto_remediate": True})
    assert dialog.bind_performance_session(_SESSION, 1, {_RUN: _PLAN})
    dialog.update_execution_progress({"red_team": {"schema": 1, "run_id": _RUN,
        "state": "completed", "finished": 6, "total": 6, "failed_units": 0,
        "current_task": "Actual attempts retired"}})
    dialog.record_verified_report("red_team", _RUN, _report())


def test_ready_report_keeps_workflow99_while_releasing_without_adding_units(console):
    dialog, _parent = console
    _ready(dialog)
    assert dialog.record_session_lifecycle(_projection())
    assert dialog.overall_progress.percent == 99 and dialog.overall_progress.busy
    assert "7/7 units" in dialog.workflow_status.text()
    assert "Finishing session lifecycle" in dialog.workflow_status.text()
    assert dialog.performance_badge.property("performanceState") == "passing"
    original_scores = (dict(dialog._report_results), dict(dialog._report_catch_counts))
    assert dialog.record_session_lifecycle(_projection(owner_finished=True, workers_retired=True,
        custody_released=True, phase="completed"))
    assert dialog.overall_progress.percent == 100 and not dialog.overall_progress.busy
    assert original_scores == (dialog._report_results, dialog._report_catch_counts)


@pytest.mark.parametrize("changes", [
    {"owner_finished": True},
    {"owner_finished": True, "custody_released": True},
    {"owner_finished": True, "workers_retired": True},
    {"owner_finished": True, "workers_retired": True, "custody_released": True, "source_available": False},
])
def test_partial_or_unknown_lifecycle_never_completes_the_wheel(console, changes):
    dialog, _parent = console
    _ready(dialog)
    assert dialog.record_session_lifecycle(_projection(**changes))
    assert dialog.overall_progress.percent == 99 and dialog.overall_progress.busy


def test_missing_projection_after_exact_new_binding_remains_held(console):
    dialog, _parent = console
    _ready(dialog)
    assert dialog._workflow_owner_pending()
    assert dialog.overall_progress.percent == 99


@pytest.mark.parametrize("changes", [{"session_id": "stale"}, {"generation": 0},
    {"generation": True}, {"plans_by_run": ((_RUN, "f" * 64),)}, {"custody_released": 1}])
def test_stale_or_malformed_completion_cannot_finish_current_owner(console, changes):
    dialog, _parent = console
    _ready(dialog)
    completed = _projection(owner_finished=True, workers_retired=True, custody_released=True)
    assert dialog.record_session_lifecycle(replace(completed, **changes)) is False
    assert dialog.overall_progress.percent == 99 and dialog._workflow_owner_pending()


def test_old_generation_completion_cannot_finish_another_accepted_launch(console):
    dialog, _parent = console
    _ready(dialog)
    completed = _projection(owner_finished=True, workers_retired=True, custody_released=True)
    assert dialog.record_session_lifecycle(completed)
    dialog.set_launch_status({"status": "accepted", "runs": {"red_team": _RUN}}, {"auto_remediate": True})
    assert dialog.bind_performance_session(_SESSION, 2, {_RUN: _PLAN})
    dialog.update_execution_progress({"red_team": {"schema": 1, "run_id": _RUN,
        "state": "completed", "finished": 6, "total": 6, "failed_units": 0, "current_task": "New generation"}})
    dialog.record_verified_report("red_team", _RUN, _report())
    assert dialog.record_session_lifecycle(completed) is False
    assert dialog.overall_progress.percent == 99 and dialog.overall_progress.busy


def test_finished_event_before_native_thread_return_projects_pending(session_view):
    h, projected = session_view, []
    h.view._rt_console.record_session_lifecycle = projected.append
    h.session.finished.set()
    h.state.custody = True
    h.view._poll_sequential_session()
    row = projected[-1]
    assert type(row) is SessionLifecycleProjection and row.owner_finished
    assert row.custody_released and not row.workers_retired and row.source_available
    assert h.view._sim_aar_pending == 1 and h.button[-1] is False


def test_dead_thread_with_retained_custody_projects_pending_then_release(session_view):
    h, projected = session_view, []
    h.view._rt_console.record_session_lifecycle = projected.append
    h.state.custody = False
    h.retire("held")
    h.view._poll_sequential_session()
    assert projected[-1].workers_retired and not projected[-1].custody_released
    assert h.button[-1] is False
    h.state.custody = True
    h.view._poll_sequential_session()
    assert projected[-1].workers_retired and projected[-1].custody_released
    assert projected[-1].owner_finished and h.button[-1] is True


@pytest.mark.parametrize("snapshot", [{}, {"schema": 1, "session_id": "other", "session_generation": 1}])
def test_missing_or_stale_cache_cannot_enable_next_launch_after_threads_retire(session_view, snapshot):
    h, projected = session_view, []
    h.view._rt_console.record_session_lifecycle = projected.append
    h.retire()
    h.session.snapshot = lambda: snapshot
    h.view._poll_sequential_session()
    assert not projected[-1].source_available and h.view._session_is_active()
    assert h.button[-1] is False and h.view._sim_poll.stops == 0


def test_missing_owned_thread_source_is_unknown_not_implicit_retirement(session_view):
    h, projected = session_view, []
    h.view._rt_console.record_session_lifecycle = projected.append
    h.session.owned_workers = lambda: ()
    h.session.finished.set()
    h.view._poll_sequential_session()
    assert not projected[-1].source_available and not projected[-1].workers_retired
    assert h.view._session_is_active() and h.view._sim_aar_pending == 1


def test_never_started_thread_presence_is_not_a_retirement_witness(session_view):
    h, projected = session_view, []
    h.view._rt_console.record_session_lifecycle = projected.append
    unstarted = threading.Thread(target=lambda: None)
    h.session.owned_workers = lambda: (unstarted,)
    h.session.finished.set()
    h.view._poll_sequential_session()
    assert not projected[-1].workers_retired and h.view._session_is_active()
    assert h.view._sim_aar_pending == 1
