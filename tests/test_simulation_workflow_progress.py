"""Inert progress/UI contracts; these tests establish no detector efficacy."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame

from angerona.gui.main_window import MainWindow
from angerona.shark.progress import SimulationProgress
from angerona.shark.shark_attack import SharkAttackEngine
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.run_manifest import expected_red_team_plan
from test_drill_response_ui import console  # noqa: F401 - shared owned Qt fixture


def _snapshot(run_id="redteam-current", *, finished=0, total=6, state="running", failed=0):
    return {"schema": 1, "run_id": run_id, "state": state, "finished": finished,
            "total": total, "current_task": "Phase 1: initial access", "failed_units": failed}


def _accepted(dialog, *, both=False):
    runs = {"red_team": "redteam-current"}
    if both:
        runs["shark"] = "shark-current"
    dialog.set_launch_status({"status": "accepted", "runs": runs}, {"auto_remediate": True})


def _report(run_id="redteam-current", *, caught=12, total=16, containment=0, outcome="failed"):
    return {
        "run_id": run_id, "outcome": outcome, "steps_run": total + 5,
        "coverage_score_eligible": True, "detection_steps": total,
        "detection_caught": caught,
        "epistemic_metrics": {"verified_containment": {
            "count": containment, "eligible": total,
            "rate": containment / total if total else None,
        }},
        "evidence_taxonomy": {
            "denominator": total,
            "compatible_analytic_union": {"count": caught},
            "native_analytic_detection": {"count": caught},
            "simulation_contract_validation": {"count": 0},
            "unscored_steps": 4,
            "benign_resilience": {"denominator": 1},
        },
    }


@pytest.mark.parametrize("run_id,total", [("", 1), ("run", True), ("run", 0), ("run", 10_001)])
def test_progress_plan_rejects_unknown_or_unbounded_denominator(run_id, total):
    with pytest.raises(ValueError):
        SimulationProgress().begin(run_id, total)


def test_actual_units_stopping_and_terminal_are_separate():
    progress = SimulationProgress()
    generation = progress.begin("run-one", 3)
    assert progress.snapshot()["state"] == "queued"
    with progress.worker(generation):
        progress.start_unit("Initial access")
        assert progress.snapshot()["finished"] == 0
        progress.finish_unit()
        progress.start_unit("Noise decision skipped")
        progress.finish_unit()
        progress.request_stop("run-one")
        assert progress.snapshot()["state"] == "stopping"
        assert progress.snapshot()["finished"] == 2
        progress.finish(generation, cancelled=True)
    row = progress.snapshot()
    assert row["state"] == "cancelled" and row["finished"] == 2 and row["total"] == 3


def test_late_worker_cannot_count_or_finalize_new_run():
    progress = SimulationProgress()
    old_generation = progress.begin("old", 2)
    with progress.worker(old_generation):
        progress.finish_unit()
        new_generation = progress.begin("new", 4)
        progress.start_unit("late old task")
        progress.finish_unit(failed=True)
        assert progress.finish(old_generation, cancelled=True) is False
    row = progress.snapshot()
    assert row["run_id"] == "new" and row["finished"] == 0 and row["failed_units"] == 0
    with progress.worker(new_generation):
        progress.finish_unit()
    assert progress.snapshot()["finished"] == 1


def test_snapshot_is_detached_and_read_only_for_engine_state():
    progress = SimulationProgress()
    progress.begin("run-one", 2)
    row = progress.snapshot()
    row.update(finished=2, state="completed", current_task="forged display copy")
    assert progress.snapshot()["finished"] == 0
    assert progress.snapshot()["state"] == "queued"


def test_worker_error_retires_progress_without_false_completion(tmp_path, monkeypatch):
    engine = SharkAttackEngine(tmp_path)
    engine.run_id = "shark-error"
    generation = engine._progress.begin(engine.run_id, 6)
    engine._running.set()

    def fail(_jitter, _noise):
        raise RuntimeError("inert progress failure")

    monkeypatch.setattr(engine, "_run_playbook", fail)
    with pytest.raises(RuntimeError, match="inert progress failure"):
        engine._run_with_progress((0, 0), 0, generation)
    assert engine.progress_snapshot()["state"] == "failed"
    assert engine.progress_snapshot()["finished"] == 0
    assert not engine.is_running


@pytest.mark.parametrize("noise", [0.0, 1.0])
def test_shark_actual_playbook_accounts_for_random_noise_and_custom(tmp_path, monkeypatch, noise):
    """Replace every probe with a harmless recorder; execute no host actions."""
    engine = SharkAttackEngine(tmp_path)
    engine.run_id = "shark-counts"
    engine._complexity = 2
    engine._custom = {"name": "inert", "payload": "inert"}
    invoked = []
    monkeypatch.setattr(engine, "_cleanup_stale_artifacts", lambda: None)
    monkeypatch.setattr(engine, "_write_history", lambda **_kw: None)
    monkeypatch.setattr("angerona.shark.shark_attack.random.shuffle", lambda _rows: None)
    monkeypatch.setattr("angerona.shark.shark_attack.random.random", lambda: 0.5)

    def step(name):
        def record(_jitter):
            invoked.append(name)
            engine._record(name, "inert", "count-only", 0, ok=True)
        return record

    names = ("initial_access", "discovery", "simulated_persistence", "simulated_byovd",
             "exfiltration", "custom", "noise_injection")
    for name in names:
        monkeypatch.setattr(engine, "_step_" + name, step(name))
    generation = engine._progress.begin(engine.run_id, 14)
    engine._running.set()
    engine._run_with_progress((0, 0), noise, generation)
    row = engine.progress_snapshot()
    assert row["state"] == "completed" and row["finished"] == row["total"] == 14
    assert row["failed_units"] == 0
    assert len(invoked) == (14 if noise else 12)
    assert invoked.count("noise_injection") == (2 if noise else 0)


@pytest.mark.parametrize("noise", [0.0, 1.0])
def test_redteam_comprehensive_plan_counts_actual_attempts_without_host_effects(tmp_path, monkeypatch, noise):
    from angerona.modules.purple_guard import RedTeamValidationLease

    engine = RedTeamEngine(tmp_path)
    engine.run_id = "redteam-counts"
    engine._complexity = 2
    engine._custom = {"name": "inert", "payload": "inert"}
    engine._comprehensive = True
    engine._campaign = True
    engine._expected_plan = expected_red_team_plan({
        "cycles": 2, "custom": engine._custom, "comprehensive": True, "campaign": True})
    invoked = []
    monkeypatch.setattr(engine, "_write_history", lambda **kw: kw["status"])
    monkeypatch.setattr(engine, "_schedule_cleanup", lambda *_args: None)
    # These assertion replacements are used only with harmless recorder stubs;
    # no file/process/network probe or response worker is started by this case.
    monkeypatch.setattr(RedTeamValidationLease, "assert_target_identity", staticmethod(lambda *_a, **_kw: None))
    monkeypatch.setattr(RedTeamValidationLease, "assert_live_producers", staticmethod(lambda *_a, **_kw: None))
    monkeypatch.setattr("angerona.shark.red_team.random.random", lambda: 0.5)

    def step(name):
        def record(_jitter):
            invoked.append(name)
            engine._record(name, "inert", "count-only", 0, ok=True)
        record.__name__ = name
        return record

    for name in dir(engine):
        if name.startswith("_step_"):
            monkeypatch.setattr(engine, name, step(name))
    total = len(engine._expected_plan) + engine._complexity
    generation = engine._progress.begin(engine.run_id, total)
    engine._running.set()
    engine._run_with_progress((0, 0), noise, generation)
    row = engine.progress_snapshot()
    assert row["state"] == "completed" and row["finished"] == row["total"] == total
    assert row["failed_units"] == 0
    assert len(invoked) == len(engine._expected_plan) + (2 if noise else 0)


def test_top_progress_is_above_tabs_and_handles_measured_current_run(console):
    dialog, _parent = console
    summary = dialog.findChild(QFrame, "RedTeamProgressSummary")
    # The named summary is a direct root child above the persistent tab widget.
    assert summary is not None
    assert dialog.layout().indexOf(summary) < dialog.layout().indexOf(dialog._tabs)
    _accepted(dialog)
    assert dialog.update_execution_progress({"red_team": _snapshot(finished=3)})
    assert dialog.overall_progress.percent == 42  # three attempts / six + report unit
    assert "initial access" in dialog.workflow_detail.text()
    assert dialog.workflow_status.textFormat() == Qt.TextFormat.PlainText


@pytest.mark.parametrize("change", [
    {"run_id": "old-run"}, {"finished": True}, {"schema": True},
    {"total": 0}, {"finished": 8}, {"state": []}, {"failed_units": 4},
])
def test_bad_or_stale_progress_never_revalidates_current_counts(console, change):
    dialog, _parent = console
    _accepted(dialog)
    dialog.update_execution_progress({"red_team": _snapshot(finished=3)})
    row = _snapshot(finished=2)
    row.update(change)
    assert dialog.update_execution_progress({"red_team": row}) is False
    assert dialog.overall_progress.percent is None
    assert "unavailable" in dialog.workflow_status.text()


def test_execution_completion_waits_for_report_unit_and_does_not_prove_containment(console):
    dialog, _parent = console
    _accepted(dialog)
    dialog.update_execution_progress({"red_team": _snapshot(finished=6, state="completed")})
    dialog.finish_run()
    assert dialog.overall_progress.percent == 85
    assert dialog.run_spinner._pct == 0
    assert dialog.catch_comparison._caught is None
    dialog.record_verified_report("red_team", "redteam-current", _report())
    assert dialog.overall_progress.percent == 100
    assert "Containment failed" in dialog.live_status.text()
    assert dialog.run_spinner._pct == 0
    assert not dialog.run_spinner._done_timer.isActive()
    assert (dialog.catch_comparison._caught, dialog.catch_comparison._missed) == (12, 4)


def test_signature_failure_never_completes_report_unit_or_score_bar(console):
    dialog, _parent = console
    _accepted(dialog)
    dialog.update_execution_progress({"red_team": _snapshot(finished=6, state="completed")})
    dialog.finish_run()
    dialog.record_verified_report("red_team", "redteam-current", None, error="signature verification failed")
    assert dialog.overall_progress.percent == 85
    assert not dialog.overall_progress.busy
    assert "verification failed" in dialog.workflow_status.text()
    assert dialog.catch_comparison._caught is None and dialog.catch_comparison._missed is None


def test_authenticated_diagnostic_is_distinct_from_scoring_or_signature_success(console):
    dialog, _parent = console
    _accepted(dialog)
    dialog.update_execution_progress({"red_team": _snapshot(finished=13, total=84, state="incomplete", failed=1)})
    payload = _report(caught=0, total=76, outcome="inconclusive")
    payload.update(diagnostic_only=True, coverage_score_eligible=False,
                   validation_status="not-currently-verified", diagnostic_history_authentication="verified",
                   readiness_scope="historical-at-launch", steps_run=13, planned_steps=80)
    payload["epistemic_metrics"]["verified_containment"]["rate"] = None
    dialog.record_verified_report("red_team", "redteam-current", payload)
    result = dialog._report_results["red_team"]
    assert result["eligible"] == 76 and result["diagnostic_only"]
    assert not result.get("error")
    assert dialog.overall_progress.percent == 16  # 13 settled units + authenticated report / 85
    assert "Diagnostic report authenticated; scoring held" in dialog.workflow_status.text()
    assert "80 mandatory steps planned" in dialog.live_status.text()
    assert "credit remain withheld" in dialog.live_status.text()
    assert dialog.catch_comparison._caught is None
    assert not dialog.run_spinner._done_timer.isActive()


def test_diagnostic_flag_cannot_override_current_validation_metadata(console):
    dialog, _parent = console
    _accepted(dialog)
    payload = _report(caught=0, total=16, outcome="inconclusive")
    payload.update(diagnostic_only=True, coverage_score_eligible=False,
                   validation_status="current", diagnostic_history_authentication="verified",
                   readiness_scope="historical-at-launch", steps_run=3, planned_steps=20)
    payload["epistemic_metrics"]["verified_containment"]["rate"] = None
    dialog.record_verified_report("red_team", "redteam-current", payload)
    assert dialog._report_results["red_team"].get("error")
    assert dialog.catch_comparison._caught is None


def test_combined_score_waits_for_both_verified_reports(console):
    dialog, _parent = console
    _accepted(dialog, both=True)
    dialog.update_execution_progress({
        "red_team": _snapshot(finished=6, state="completed"),
        "shark": _snapshot("shark-current", finished=6, state="completed"),
    })
    dialog.record_verified_report("red_team", "redteam-current", _report())
    assert dialog.catch_comparison._caught is None
    dialog.record_verified_report("shark", "shark-current", _report("shark-current", caught=4, total=4))
    assert (dialog.catch_comparison._caught, dialog.catch_comparison._missed) == (16, 4)
    assert "16/20" in dialog.catch_comparison.toolTip()


@pytest.mark.parametrize("change", [
    {"coverage_score_eligible": False}, {"run_id": "other"},
    {"detection_caught": True}, {"detection_steps": True},
    {"detection_steps": 17},
])
def test_unscorable_or_inconsistent_report_stays_neutral(console, change):
    dialog, _parent = console
    _accepted(dialog)
    payload = _report()
    payload.update(change)
    dialog.record_verified_report("red_team", "redteam-current", payload)
    assert dialog.catch_comparison._caught is None


def test_existing_poll_preserves_stopping_worker_before_aar_dispatch(console):
    dialog, _parent = console
    _accepted(dialog)
    engine = SimpleNamespace(run_id="redteam-current", is_running=False,
                             progress_snapshot=lambda: _snapshot(finished=2, state="stopping"))
    main = SimpleNamespace(_rt_console=dialog, red_team_engine=engine,
                           shark_engine=SimpleNamespace(run_id="", is_running=False),
                           _sim_report_runs={"red_team": "redteam-current"})
    # No timer/animation/AAR attributes exist: the pending worker must return
    # before the terminal dispatch path can access any of them.
    MainWindow._sim_check_done(main)
    assert dialog.overall_progress.busy
    assert "Stopping" in dialog.workflow_status.text()
