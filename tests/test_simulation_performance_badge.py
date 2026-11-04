"""No execution count, unsigned text or stale run can manufacture Passing."""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QLabel

from angerona.gui.red_team_console import RedTeamConsole


def result(caught, missed=0, *, contained=None, outcome=None, **fields):
    eligible = caught + missed
    contained = eligible if contained is None else contained
    outcome = outcome or ("verified" if contained == eligible else "failed" if not contained else "partial")
    return {"count": contained, "eligible": eligible, "outcome": outcome, **fields}, (caught, missed)


@pytest.mark.parametrize("row,metric,options,expected", [
    (*result(16), {}, "passing"),
    (*result(12, 4, contained=0), {}, "failing"),
    (*result(16, contained=0), {}, "failing"),
    (*result(16, contained=8), {}, "partial"),
    (*result(16, contained=0), {"containment_requested": False}, "passing"),
    ({"count": 0, "eligible": 76, "outcome": "inconclusive", "diagnostic_only": True,
      "coverage_held": True}, None, {}, "inconclusive"),
    ({"count": 0, "eligible": 0, "outcome": "inconclusive", "error": "Signature unavailable"},
     None, {}, "unverified"),
    (*result(16), {"cancelled": True}, "inconclusive"),
    (result(16)[0], None, {}, "unverified"),
    ({"count": True, "eligible": 1, "outcome": "verified"}, (1, 0), {}, "unverified"),
    ({"count": 1, "eligible": 1, "outcome": "verified"}, (16, 0), {}, "unverified"),
    ({"count": 1, "eligible": 16, "outcome": "failed"}, (16, 0), {}, "unverified"),
    ({"count": 0, "eligible": 0, "outcome": "inconclusive"}, (0, 0), {}, "inconclusive"),
])
def test_badge_uses_only_accepted_scored_evidence_and_selected_criterion(row, metric, options, expected):
    state, label, detail = RedTeamConsole._performance_state({"red_team": "current"},
        {"red_team": row}, {"red_team": metric}, **options)
    assert state == expected and label and detail
    if options.get("containment_requested") is False and state == "passing":
        assert "detection only" in label and "no response pass" in detail


def test_pending_profiles_are_not_misses_or_a_complete_pass():
    row, metric = result(8)
    state, label, detail = RedTeamConsole._performance_state(
        {"red_team": "red-current", "shark": "shark-current"}, {"red_team": row}, {"red_team": metric})
    assert state == "partial" and "evidence pending" in label and "1/2" in detail


def test_measured_misses_remain_visible_while_another_requested_profile_is_pending():
    row, metric = result(7, 1, contained=0)
    state, label, _ = RedTeamConsole._performance_state(
        {"red_team": "red-current", "shark": "shark-current"}, {"red_team": row}, {"red_team": metric})
    assert state == "failing" and "1 measured miss" in label


def test_old_profile_results_and_workflow_completion_do_not_become_current_passing():
    row, metric = result(8)
    state, label, _ = RedTeamConsole._performance_state({"shark": "current"},
        {"red_team": row}, {"red_team": metric}, running=True)
    assert state == "pending" and "Running" in label
    view = SimpleNamespace(_report_runs={"red_team": "current"})
    RedTeamConsole.record_verified_report(view, "red_team", "old", {"outcome": "verified"})
    assert vars(view) == {"_report_runs": {"red_team": "current"}}


def test_badge_is_accessible_text_and_unknown_state_clears_green():
    app = QApplication.instance() or QApplication([])
    badge = QLabel()
    view = SimpleNamespace(performance_badge=badge)
    RedTeamConsole._set_performance_badge(view, "passing", "Passing", "Completed simulation only")
    assert badge.text() == "Passing" and badge.property("performanceState") == "passing"
    assert "Passing" in badge.accessibleName() and "simulation" in badge.accessibleDescription()
    assert "#2fe38a" in badge.styleSheet()
    RedTeamConsole._set_performance_badge(view, "unknown-input", "Passing", "Unverified input")
    assert badge.text() == "Unverified" and badge.property("performanceState") == "unverified"
    assert "#2fe38a" not in badge.styleSheet()
    badge.close()
    app.processEvents()
