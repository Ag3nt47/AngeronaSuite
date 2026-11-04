"""Presentation contract for real immutable Session metrics, not sensor proof."""
from __future__ import annotations

from dataclasses import replace
import os
from types import MethodType, SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QLabel

from angerona.gui.red_team_console import RedTeamConsole, _CaughtMissedBar
from angerona.shark.simulation_session import RunPerformanceSnapshot


_SESSION = "session-" + "a" * 32
_RUN = "redteam-" + "b" * 32
_PLAN = "c" * 64


@pytest.fixture
def view():
    app = QApplication.instance() or QApplication([])
    value = SimpleNamespace(_report_runs={"red_team": _RUN}, _report_results={}, _report_catch_counts={},
        _performance_launch_accepted=True, _performance_session=None, _live_performance={},
        _containment_requested=True, _run_pending=True, _run_cancelled=False, _launch_queued=False,
        performance_badge=QLabel(), catch_comparison=_CaughtMissedBar(),
        _performance_state=RedTeamConsole._performance_state)
    for name in ("_set_performance_badge", "_render_performance_badge", "_live_performance_state",
                 "_render_catch_comparison", "_live_comparison_counts"):
        setattr(value, name, MethodType(getattr(RedTeamConsole, name), value))
    assert RedTeamConsole.bind_performance_session(value, _SESSION, 2, {_RUN: _PLAN}) is True
    try:
        yield value
    finally:
        value.performance_badge.close()
        value.catch_comparison.close()
        app.processEvents()


def snapshot(**changes):
    value = RunPerformanceSnapshot(_SESSION, 2, _RUN, _PLAN, "provisional", 10,
        evaluated_steps=2, detection_verified_steps=2, native_verified_steps=2,
        simulation_verified_steps=2, containment_verified_steps=2, unsettled_steps=8)
    return replace(value, **changes)


def test_only_evaluated_verified_checks_support_passing_so_far_and_scopes_remain_separate(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot()) is True
    assert view.performance_badge.property("performanceState") == "partial"
    assert view.performance_badge.text() == "Passing so far · provisional"
    detail = view.performance_badge.toolTip()
    assert "2/2 evaluated checks caught" in detail and "2 original-native" in detail and "2 simulation" in detail
    assert "8 unsettled" in detail and "unrun stages do not" in detail


def test_verified_provisional_gaps_are_red_without_finalizing_unknown_steps(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(
        containment_verified_steps=1, provisional_failures=1, unavailable_steps=8)) is True
    assert view.performance_badge.property("performanceState") == "failing"
    assert view.performance_badge.text() == "Failing so far · measured gaps"
    assert "1 measured provisional gaps" in view.performance_badge.toolTip()


def test_final_sha_and_counts_do_not_substitute_for_authenticated_report_delivery(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(state="final", finalized_misses=0,
        evaluated_steps=10, detection_verified_steps=10, native_verified_steps=10,
        simulation_verified_steps=0, containment_verified_steps=10, unsettled_steps=0,
        final_report_sha256="f" * 64)) is True
    assert view.performance_badge.property("performanceState") == "partial"
    assert "provisional" in view.performance_badge.text()


@pytest.mark.parametrize("changes", [
    {"session_id": "session-" + "d" * 32}, {"session_generation": 1},
    {"session_generation": True}, {"run_id": "redteam-" + "e" * 32},
    {"plan_sha256": "f" * 64}, {"evaluated_steps": True},
    {"detection_verified_steps": 3}, {"native_verified_steps": 3},
    {"provisional_failures": 3}, {"containment_required": False},
    {"finalized_misses": 1}, {"state": "unrecognized"},
])
def test_wrong_binding_counts_or_mode_cannot_override_current_metrics(view, changes):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot()) is True
    old = view._live_performance[_RUN]
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(**changes)) is False
    assert view._live_performance[_RUN] is old


def test_no_reliable_evaluations_or_generation_loss_remains_neutral(view):
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(state="pending", evaluated_steps=0,
        detection_verified_steps=0, native_verified_steps=0, simulation_verified_steps=0,
        containment_verified_steps=0, unsettled_steps=10)) is True
    assert view.performance_badge.property("performanceState") == "pending"
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(state="unverified")) is True
    assert view.performance_badge.property("performanceState") == "unverified"


def test_rejected_launch_cannot_reuse_old_accepted_session_or_native_counts(view):
    view._performance_launch_accepted = False
    assert RedTeamConsole.bind_performance_session(view, _SESSION, 3, {_RUN: _PLAN}) is False
    assert RedTeamConsole.record_performance_snapshot(view, snapshot()) is False
    view._render_performance_badge()
    assert view.performance_badge.property("performanceState") == "pending"


def test_detection_only_scope_never_implies_a_response_pass(view):
    view._containment_requested = False
    assert RedTeamConsole.record_performance_snapshot(view, snapshot(containment_required=False,
        containment_verified_steps=0)) is True
    assert view.performance_badge.text() == "Passing so far · provisional"
    assert "0 durable containment" in view.performance_badge.toolTip()
