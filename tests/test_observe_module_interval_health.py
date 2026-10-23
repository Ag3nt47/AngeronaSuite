"""Pure snapshot tests only: no configuration, modules or OS work."""
import importlib.util
from pathlib import Path
import json

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("matrix_interval_tests", ROOT / "tools" / "observe_module_matrix.py")
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)
NAME = "C2 Beacon Detector"


def healthy(**updates):
    state = dict(first_cycle_complete=True, cycle_count=2, thread_alive=True,
                 status="running", health_state="ok", health=100, health_note="Complete snapshot",
                 event_overflow_count=0, crash_count=0)
    return dict(state, **updates)


def summary():
    return dict(clean_shutdown=True, errors=[], capture_dropped=0, export_dropped=0,
                gap_records=0, max_heartbeat_gap_seconds=0.25)


def classify(result, final):
    return matrix.classification({NAME: final}, result, expected_modules=[NAME])


def test_recovered_health_retains_earlier_observed_gap():
    result = summary()
    for elapsed, state in [(0, healthy()), (45.9, healthy(health=65, health_state="degraded", health_note="Incomplete snapshot")),
                           (60, healthy())]:
        matrix.record_module_interval_health(result, {NAME: state}, elapsed)
    row = result["module_interval_health"][NAME]
    assert row["samples"] == 3 and row["gap_samples"] == 1
    assert row["minimum_health"] == 65 and row["last_health"] == 100
    assert row["first_gap_elapsed_seconds"] == row["last_gap_elapsed_seconds"] == 45.9
    assert row["observed_incomplete"] is True
    assert classify(result, healthy())[0] == "OBSERVED_WITH_GAPS"


def test_warming_samples_are_explicit_and_do_not_mint_a_coverage_fault():
    result = summary()
    matrix.record_module_interval_health(result, {NAME: healthy(first_cycle_complete=False, cycle_count=0,
                                                              health=0, health_state="unknown")}, 0)
    matrix.record_module_interval_health(result, {NAME: healthy()}, 2)
    row = result["module_interval_health"][NAME]
    assert row["warming_samples"] == 1 and row["completed_samples"] == 1
    assert row["first_completed_elapsed_seconds"] == 2
    assert row["minimum_health"] == 0 and row["gap_samples"] == 0
    assert classify(result, healthy())[0] == "OBSERVED"
    assert classify(result, healthy(first_cycle_complete=False, cycle_count=0))[0] == "OBSERVED_WITH_GAPS"


@pytest.mark.parametrize("change,flag", [
    ({"event_overflow_count": 2}, "observed_loss"),
    ({"crash_count": 1}, "observed_crash"),
    ({"thread_alive": False, "status": "stopped"}, "observed_not_running"),
    ({"first_cycle_complete": False, "cycle_count": 0}, "observed_incomplete"),
    ({"health": None}, "observed_incomplete"),
])
def test_recovered_loss_crash_liveness_or_unknown_evidence_remains_a_gap(change, flag):
    result = summary()
    for elapsed, state in [(0, healthy()), (1, healthy(**change)), (2, healthy())]:
        matrix.record_module_interval_health(result, {NAME: state}, elapsed)
    row = result["module_interval_health"][NAME]
    assert row[flag] and row["gap_samples"] == 1
    if change.get("first_cycle_complete") is False:
        assert row["warming_samples"] == 0 and row["incomplete_after_completion_samples"] == 1
    assert classify(result, healthy())[0] == "OBSERVED_WITH_GAPS"


def test_real_loss_or_failure_is_not_excused_by_startup_warming():
    result = summary()
    matrix.record_module_interval_health(result, {NAME: healthy(first_cycle_complete=False, cycle_count=0,
                                                              event_overflow_count=1, crash_count=1,
                                                              thread_alive=False)}, 0)
    matrix.record_module_interval_health(result, {NAME: healthy()}, 2)
    row = result["module_interval_health"][NAME]
    assert row["warming_samples"] == 1 and row["gap_samples"] == 1
    assert row["observed_crash"] and row["observed_loss"] and row["observed_not_running"]
    assert classify(result, healthy())[0] == "OBSERVED_WITH_GAPS"


def test_many_changed_notes_keep_only_bounded_first_and_last_samples():
    result = summary()
    names = list(matrix.AUDITED)
    for elapsed in range(1000):
        states = {name: healthy(health=65, health_state="degraded", health_note=str(elapsed) + "x" * 1000)
                  for name in names}
        matrix.record_module_interval_health(result, states, elapsed)
    assert set(result["module_interval_health"]) == set(names)
    for row in result["module_interval_health"].values():
        assert row["samples"] == row["gap_samples"] == 1000
        assert len(row["first_gap_note"]) == len(row["last_gap_note"]) == 200
        assert row["first_gap_note"].startswith("0x") and row["last_gap_note"].startswith("999x")
        assert not any(isinstance(value, (list, dict)) for value in row.values())
    assert len(json.dumps(result)) < 32 * 1024
