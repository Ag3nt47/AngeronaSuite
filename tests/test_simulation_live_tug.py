"""Provisional selected outcomes never become final detection misses."""
from angerona.gui.red_team_console import RedTeamConsole
from test_simulation_live_badge_binding import view, snapshot, _RUN  # noqa: F401 - pytest fixture registration


def test_live_containment_bar_does_not_double_count_detection_and_response_gap(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(
        containment_verified_steps=1, provisional_failures=1)) is True
    bar = view.catch_comparison
    assert bar._caught == 1 and bar._missed == 1 and bar._provisional is True
    assert bar._left_label == "Caught + contained" and bar._right_label == "Measured gaps"
    assert "2/2 evaluated checks" in bar.toolTip()
    assert "not final detection misses" in bar.toolTip()
    assert "8 unrun/unsettled" in bar.toolTip()


def test_response_pending_is_outside_live_tug_denominator(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(
        containment_verified_steps=1, provisional_failures=0)) is True
    assert (view.catch_comparison._caught, view.catch_comparison._missed) == (1, 0)
    assert "1 response-pending" in view.catch_comparison.toolTip()
    assert "Running" in view.performance_badge.text()


def test_detection_only_live_bar_is_explicitly_provisional_without_response_claim(view):
    view._containment_requested = False
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(
        containment_required=False, containment_verified_steps=0)) is True
    assert (view.catch_comparison._caught, view.catch_comparison._missed) == (2, 0)
    assert view.catch_comparison._left_label == "Caught"
    assert "LIVE PROVISIONAL" in view.catch_comparison.toolTip()
    assert "0 measured response gaps" in view.catch_comparison.toolTip()


def test_final_sha_without_immutable_report_keeps_comparison_pending(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(state="final",
        final_report_sha256="e" * 64, finalized_misses=0)) is True
    assert view.catch_comparison._caught is None and view.catch_comparison._missed is None


def test_generation_loss_or_cancellation_removes_provisional_green(view):
    RedTeamConsole.record_performance_snapshot(view, snapshot())
    assert view.catch_comparison._caught == 2
    RedTeamConsole.record_performance_snapshot(view, snapshot(state="unverified"))
    assert view.catch_comparison._caught is None
    view._run_cancelled = True
    RedTeamConsole.record_performance_snapshot(view, snapshot())
    assert view.catch_comparison._caught is None


def test_unrun_and_unavailable_are_not_manufactured_misses(view):
    row = snapshot(state="pending", evaluated_steps=0, detection_verified_steps=0,
        native_verified_steps=0, simulation_verified_steps=0, containment_verified_steps=0,
        unsettled_steps=7, unavailable_steps=3)
    RedTeamConsole.record_performance_snapshot(view, row)
    assert view.catch_comparison._caught is None and view.catch_comparison._missed is None


def test_final_authenticated_result_switches_back_to_detection_counts(view):
    RedTeamConsole.record_performance_snapshot(view, snapshot())
    view._report_results = {"red_team": {"count": 0, "eligible": 10, "outcome": "failed"}}
    view._report_catch_counts = {"red_team": (8, 2)}
    view._render_catch_comparison()
    bar = view.catch_comparison
    assert (bar._caught, bar._missed) == (8, 2) and not bar._provisional
    assert (bar._left_label, bar._right_label) == ("Caught", "Missed")
    assert "Finalized expected-positive" in bar.toolTip()


def test_prior_finalized_profile_does_not_mix_with_live_selected_outcome_denominator(view):
    view._report_runs["shark"] = "shark-current"
    view._report_results["shark"] = {"count": 0, "eligible": 16, "outcome": "failed"}
    view._report_catch_counts["shark"] = (12, 4)
    view._live_performance[_RUN] = snapshot()
    view._render_catch_comparison()
    assert (view.catch_comparison._caught, view.catch_comparison._missed) == (2, 0)
    assert "prior finalized profiles are outside" in view.catch_comparison.toolTip()
    assert view.performance_badge.property("performanceState") == "failing"
