"""Actual console plus owned-thread GUI shell; no detector/protection claim."""
from types import SimpleNamespace

import pytest

from test_drill_response_ui import console  # noqa: F401 - real owned Qt fixture
from test_session_gui_owner_integration import session_view  # noqa: F401 - exact-thread shell
from test_session_gui_launch_custody import _report
from test_simulation_session_lifecycle import _ready, _projection


def _payload(run_id):
    # A preverified-payload presentation fixture, not fabricated runtime proof.
    return {"run_id": run_id, "outcome": "verified", "coverage_score_eligible": True,
        "steps_run": 1, "detection_steps": 1, "detection_caught": 1,
        "epistemic_metrics": {"verified_containment": {"count": 1, "eligible": 1, "rate": 1.0}},
        "evidence_taxonomy": {"denominator": 1, "compatible_analytic_union": {"count": 1},
            "native_analytic_detection": {"count": 1}, "simulation_contract_validation": {"count": 0}}}


def test_terminal_held_busy_refusal_preserves_exact_owner_until_real_poll_releases(console, session_view):
    dialog, _parent = console
    h = session_view
    runs = {run.kind: run.run_id for run in h.plan.runs}
    dialog.set_launch_status({"status": "accepted", "runs": runs}, {"auto_remediate": True})
    assert dialog.bind_performance_session(h.plan.session_id, h.plan.generation,
        {run.run_id: run.plan_sha256 for run in h.plan.runs})
    for run in h.plan.runs:
        dialog.record_verified_report(run.kind, run.run_id, _payload(run.run_id))
        total = 7 if run.kind == "red_team" else 1
        row = {"schema": 1, "run_id": run.run_id, "state": "completed", "finished": total,
               "total": total, "failed_units": 0, "current_task": "Actual fixture attempts retired"}
        engine = SimpleNamespace(run_id=run.run_id, is_running=False, progress_snapshot=lambda exact=row: exact)
        setattr(h.view, "red_team_engine" if run.kind == "red_team" else "shark_engine", engine)
    h.view._rt_console = dialog
    # Inbox fixtures route only: the real immutable verifier is unchanged and
    # independently tested. This shell's display sink does not assert authenticity.
    h.state.reports = tuple(_report(run) for run in h.plan.runs)
    h.state.custody = False
    h.retire("held")
    h.view._poll_sequential_session()
    assert not dialog._run_pending and not dialog.launch_btn.isEnabled()
    assert dialog.overall_progress.percent == 99 and dialog.overall_progress.busy
    binding, lifecycle = dialog._performance_session, dialog._session_lifecycle
    results, counts = dict(dialog._report_results), dict(dialog._report_catch_counts)

    dialog.set_launch_status({"status": "rejected", "busy": True,
        "reason": "The existing exact session still owns its lease",
        "runs": {"red_team": "untrusted-other-run"}}, {"auto_remediate": False})
    assert dialog._performance_launch_accepted is True
    assert dialog._performance_session is binding and dialog._session_lifecycle is lifecycle
    assert dialog._report_runs == runs and dialog._containment_requested is True
    assert not dialog.launch_btn.isEnabled() and dialog._workflow_owner_pending()
    h.view._poll_sequential_session()  # A new valid current-owner poll is accepted.
    assert dialog._performance_session is binding and dialog.overall_progress.percent == 99
    assert not dialog.launch_btn.isEnabled() and (results, counts) == (dialog._report_results, dialog._report_catch_counts)

    h.state.custody = True
    h.view._poll_sequential_session()
    assert dialog.overall_progress.percent == 100 and not dialog.overall_progress.busy
    assert dialog.launch_btn.isEnabled() and not h.view._session_is_active()
    assert (results, counts) == (dialog._report_results, dialog._report_catch_counts)


def test_repeated_busy_refusal_cannot_detach_terminal_pending_binding(console):
    dialog, _parent = console
    _ready(dialog)
    assert dialog.record_session_lifecycle(_projection(owner_finished=True, workers_retired=True))
    dialog._run_pending = False
    binding = dialog._performance_session
    for _index in range(3):
        dialog.set_launch_status({"status": "rejected", "busy": True, "reason": "Held"})
        assert dialog._performance_session is binding and dialog._workflow_owner_pending()
        assert dialog.overall_progress.percent == 99 and not dialog.launch_btn.isEnabled()


def test_busy_refusal_preserves_accepted_binding_while_first_lifecycle_source_is_pending(console):
    dialog, _parent = console
    _ready(dialog)
    dialog._run_pending = False
    binding = dialog._performance_session
    assert dialog._session_lifecycle is None
    dialog.set_launch_status({"status": "rejected", "busy": True, "reason": "Owner cache pending"})
    assert dialog._performance_session is binding and dialog._workflow_owner_pending()
    assert dialog.overall_progress.percent == 99 and not dialog.launch_btn.isEnabled()


@pytest.mark.parametrize("busy", [False, 1, "true", None])
def test_nonliteral_busy_or_unbound_rejection_does_not_reuse_session_as_authority(console, busy):
    dialog, _parent = console
    _ready(dialog)
    dialog._run_pending = False
    dialog.set_launch_status({"status": "rejected", "busy": busy, "reason": "Rejected new request"})
    assert dialog._performance_launch_accepted is False and dialog._performance_session is None
    assert dialog.overall_progress.percent is None


def test_raw_busy_rejection_without_valid_accepted_binding_does_not_create_one(console):
    dialog, _parent = console
    dialog._run_pending = False
    dialog._performance_launch_accepted = False
    dialog._performance_session = None
    dialog.set_launch_status({"status": "rejected", "busy": True, "runs": {"red_team": "claimed-run"}})
    assert dialog._performance_launch_accepted is False and dialog._performance_session is None
    assert dialog._session_lifecycle is None and dialog.overall_progress.percent is None
