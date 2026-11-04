"""Scheduler isolation/retirement tests do not supply detector authority."""
from __future__ import annotations

import threading

import pytest

from angerona.shark import simulation_session as sessions


class _SchedulerOnlyManager:
    pass


def _session(root, manager=None):
    return sessions.SimulationSession(manager=manager or _SchedulerOnlyManager(), bus=None,
        recorder=None, data_root=root, red_team_engine=None, shark_engine=None)


def test_an_untrusted_graph_yields_typed_launch_diagnostic_and_no_run_or_report(tmp_path):
    session = _session(tmp_path)
    plan = session.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")
    assert session.start(plan)
    assert session.finished.wait(5)
    for worker in session.owned_workers():
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert session.snapshot()["phase"] == "held"
    assert session.completed_reports() == ()
    performance = session.performance_snapshot(plan.runs[0].run_id)
    assert type(performance) is sessions.RunPerformanceSnapshot
    assert performance.finalized_misses is None
    assert performance.native_verified_steps == performance.containment_verified_steps == 0
    diagnostics = session.launch_diagnostics()
    assert len(diagnostics) == 1
    assert not diagnostics[0].authenticated_run and not diagnostics[0].response_authorized
    assert "exact simulation graph" in diagnostics[0].detail
    assert not (tmp_path / "shark_history.json").exists()


def test_reserved_owner_excludes_another_window_before_its_thread_is_even_published(tmp_path, monkeypatch):
    """Force the pre-thread race; the stub performs scheduling work only."""
    original_thread = threading.Thread
    construction_entered, construction_release, worker_release = (threading.Event() for _ in range(3))
    manager = _SchedulerOnlyManager()
    first = _session(tmp_path, manager)
    second = _session(tmp_path, manager)
    first_plan = first.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")
    second_plan = second.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")
    result, errors = [], []

    class PausedConstruction(original_thread):
        def __init__(self, *args, **kwargs):
            if kwargs.get("name") == "simulation-session":
                construction_entered.set()
                assert construction_release.wait(5)
            super().__init__(*args, **kwargs)

    def scheduling_worker_only():
        try:
            assert worker_release.wait(5)
        finally:
            # A scheduler-only stub cannot stand in for a successful detector,
            # lease, report or cleanup; it merely retires its reservation.
            with sessions._SESSION_OWNERS_LOCK:
                first._reservation_active = False
            first.finished.set()

    def start_first():
        try:
            result.append(first.start(first_plan))
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(sessions.threading, "Thread", PausedConstruction)
    monkeypatch.setattr(first, "_run", scheduling_worker_only)
    caller = original_thread(target=start_first, name="owned-session-start-caller")
    caller.start()
    try:
        assert construction_entered.wait(2)
        assert first.thread is None and first._reservation_active
        assert second.start(second_plan) is False
        construction_release.set()
        caller.join(timeout=5)
        assert not caller.is_alive() and result == [True] and not errors
        assert first.thread.is_alive()
        first.cancel()
        assert first.cancelled.is_set() and first.thread in first.owned_workers()
        assert first.thread.is_alive()  # cancellation is not retirement
    finally:
        construction_release.set()
        worker_release.set()
        caller.join(timeout=5)
        for worker in first.owned_workers():
            worker.join(timeout=5)
    assert not caller.is_alive()
    assert all(not worker.is_alive() for worker in first.owned_workers())
    assert first.start(first_plan) is False  # immutable run IDs are single use
    assert first.completed_reports() == ()
    assert not (tmp_path / "shark_history.json").exists()


def test_uncertain_retirement_cannot_be_silently_reset_by_preparing_another_run(tmp_path):
    session = _session(tmp_path)
    session._retirement_held = True
    with pytest.raises(sessions.SessionHeld):
        session.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")
