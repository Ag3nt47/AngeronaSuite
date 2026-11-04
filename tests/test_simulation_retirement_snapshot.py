"""Memory-only lifecycle projection; these fixtures grant no native authority."""
from __future__ import annotations

import threading

import pytest

from angerona.shark import simulation_session as sessions


class _SchedulingManager:
    pass


def _session(root):
    return sessions.SimulationSession(manager=_SchedulingManager(), bus=None, recorder=None,
        data_root=root, red_team_engine=None, shark_engine=None)


@pytest.mark.parametrize("hold", ["lease", "reservation", "uncertain-release"])
def test_retired_thread_alone_never_clears_memory_custody_hold(tmp_path, hold):
    session = _session(tmp_path)
    plan = session.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")

    class MustNotProbe:
        def is_alive(self):
            raise AssertionError("cached custody projection attempted a worker probe")

    session.thread = MustNotProbe()
    session.finished.set()
    if hold == "lease":
        session._active_lease = object()  # Unknown custody, never a usable native lease.
    elif hold == "reservation":
        session._reservation_active = True
    else:
        session._retirement_held = True
    value = session.retirement_snapshot()
    assert value["schema"] == 1 and value["session_id"] == plan.session_id
    assert value["custody_released"] is False and value["response_authorized"] is False
    assert value["owner_pending"] is False
    assert value["lease_active"] is (hold == "lease")
    assert value["reservation_active"] is (hold == "reservation")
    assert value["retirement_held"] is (hold == "uncertain-release")


def test_accepted_owner_is_pending_before_its_thread_is_published_then_retires_actual_worker(tmp_path, monkeypatch):
    session = _session(tmp_path)
    plan = session.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")
    entered, resume = threading.Event(), threading.Event()
    original_thread = threading.Thread
    result, errors = [], []

    class PausedConstruction(original_thread):
        def __init__(self, *args, **kwargs):
            if kwargs.get("name") == "simulation-session":
                entered.set()
                assert resume.wait(5)
            super().__init__(*args, **kwargs)

    def start():
        try:
            result.append(session.start(plan))
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(sessions.threading, "Thread", PausedConstruction)
    caller = original_thread(target=start, name="owned-retirement-start-caller")
    caller.start()
    try:
        assert entered.wait(2)
        assert session.thread is None
        pending = session.retirement_snapshot()
        assert pending["owner_pending"] and pending["reservation_active"]
        assert not pending["custody_released"] and not pending["response_authorized"]
        resume.set()
        caller.join(timeout=5)
        assert not caller.is_alive() and result == [True] and not errors
        assert session.finished.wait(5)
        for worker in session.owned_workers():
            worker.join(timeout=5)
            assert not worker.is_alive()
        # The real worker refused the unsupported graph, minted no lease/run,
        # completed its finally block and actually retired.
        assert session.completed_reports() == () and len(session.launch_diagnostics()) == 1
        assert session.retirement_snapshot()["custody_released"] is True
    finally:
        resume.set()
        caller.join(timeout=5)
        for worker in session.owned_workers():
            worker.join(timeout=5)
    assert not caller.is_alive() and all(not worker.is_alive() for worker in session.owned_workers())
