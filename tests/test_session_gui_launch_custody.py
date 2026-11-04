"""GUI acceptance/ownership tests; these fakes do not prove native detection."""
from dataclasses import replace
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from angerona.gui.simulation_launch import (
    SessionReportInbox, SimulationLaunch, prepared_execution_rows, session_custody_released,
)
from angerona.shark.aar_report import AARReportResult
from angerona.shark.simulation_session import PreparedRun, PreparedStep, SessionPlan


def _plan():
    def run(kind):
        steps = () if kind == "red_team" else (
            PreparedStep("step-1", 0, 1, "discovery", "read-only", ()),)
        return PreparedRun("session-fixture", "run-" + kind, kind, ".", ".",
            json.dumps({"budget": {"projected_steps": 7}}), "b" * 64,
            steps, 60, ("a" if kind == "red_team" else "c") * 64)
    return SessionPlan("session-fixture", (run("red_team"), run("shark")), 1)


def _report(run, digest="d"):
    # Deliberately unauthenticated immutable route data. The inbox never claims
    # authenticity; the real GUI verifier is separately mandatory/tested.
    return AARReportResult("route only", run.run_id, run.kind,
        "redteam_aar" if run.kind == "red_team" else "shark_aar",
        digest * 64, "e" * 64, 1, b"text", b"{}", b"{}", "f" * 64, b"{}", Path("."))


@pytest.fixture
def launch_factory(monkeypatch):
    import angerona.shark.simulation_session as module
    release = threading.Event()
    started = threading.Event()
    instances = []
    jobs = []
    plan = _plan()

    class FakeSession:
        def __init__(self, **kwargs):
            self.kwargs, self.thread, self.cfg = kwargs, None, None
            self.cancelled, self.finished = threading.Event(), threading.Event()
            self.fail_start, self.lose_ack = False, False
            self.received = None
            instances.append(self)

        def prepare(self, cfg, *, default_target):
            self.cfg = cfg
            return plan

        def start(self, exact):
            self.received = exact
            if self.fail_start:
                self.finished.set()
                return False
            self.thread = threading.Thread(target=lambda: (started.set(), release.wait(5)), daemon=True)
            self.thread.start()
            if self.lose_ack:
                raise RuntimeError("start ack lost after actual child creation")
            return True

        def cancel(self):
            self.cancelled.set()

        def owned_workers(self):
            return () if self.thread is None else (self.thread,)

    monkeypatch.setattr(module, "SimulationSession", FakeSession)

    def make(cfg=None):
        job = SimulationLaunch(cfg=cfg or {"run_redteam": True}, manager=object(),
            bus=object(), storage=object(), data_root=Path("."),
            red_team_engine=SimpleNamespace(default_documents_dir=Path(".")), shark_engine=object(),
            response_escalated=True)
        jobs.append(job)
        return job
    yield SimpleNamespace(make=make, instances=instances, release=release, started=started, plan=plan)
    release.set()
    for job in jobs:
        job.cancel()
        if job.thread.ident is not None:
            job.thread.join(5)
        for worker in job.owned_workers():
            if worker.ident is not None:
                worker.join(5)
            assert not worker.is_alive(), "Fixture must retire every exact admitted thread"


def test_prepare_does_not_start_and_claim_is_not_a_success_ack(launch_factory, monkeypatch):
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "preserved")
    import os
    job = launch_factory.make()
    job.start()
    assert job.ready.wait(5) and job.success
    assert not job.accepted and not launch_factory.started.is_set()
    assert job.claim() is True
    assert job.finished.wait(5)
    job.thread.join(5)
    assert job.accepted and launch_factory.instances[0].received is launch_factory.plan
    assert launch_factory.instances[0].thread in job.owned_workers()
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "preserved"
    assert job.claim() is False


def test_cfg_is_detached_without_changing_callers_preferences(launch_factory):
    cfg = {"run_shark": True, "auto_remediate": False, "custom": {"name": "original"}}
    job = launch_factory.make(cfg)
    cfg["custom"]["name"] = "later"
    job.start()
    assert job.ready.wait(5)
    assert launch_factory.instances[0].cfg["custom"]["name"] == "original"
    assert launch_factory.instances[0].cfg["auto_remediate"] is False


@pytest.mark.parametrize("when", ["before-start", "after-ready", "after-admission"])
def test_cancel_retains_exact_ownership(launch_factory, when):
    job = launch_factory.make()
    if when == "before-start":
        job.cancel()
    job.start()
    assert job.ready.wait(5)
    if when == "after-admission":
        assert job.claim()
        assert launch_factory.started.wait(5)
        assert job.finished.wait(5)
    job.cancel()
    assert job.finished.wait(5)
    job.thread.join(5)
    session = launch_factory.instances[0]
    assert session.cancelled.is_set()
    if when == "after-admission":
        assert session.thread in job.owned_workers() and session.thread.is_alive()
    else:
        assert not job.accepted and not launch_factory.started.is_set()


@pytest.mark.parametrize("lose_ack", [False, True])
def test_rejected_or_lost_ack_never_drops_admitted_child(launch_factory, lose_ack):
    job = launch_factory.make()
    job.start()
    assert job.ready.wait(5)
    session = launch_factory.instances[0]
    session.lose_ack, session.fail_start = lose_ack, not lose_ack
    assert job.claim() and job.finished.wait(5)
    job.thread.join(5)
    assert not job.accepted and not job.success and session.cancelled.is_set()
    if lose_ack:
        assert session.thread in job.owned_workers() and session.thread.is_alive()


def test_queued_progress_uses_plan_counts_but_never_detection_counts():
    rows = prepared_execution_rows(_plan(), {}, phase="queued")
    assert rows["red_team"]["total"] == 7
    assert rows["shark"]["total"] == 1
    assert all(row["finished"] == 0 and row["state"] == "queued" for row in rows.values())
    assert all("caught" not in row and "missed" not in row for row in rows.values())


@pytest.mark.parametrize("bad", [None, {}, {"finished": True}, {"finished": 8}, {"failed_units": 8}])
def test_started_engine_missing_or_invalid_progress_is_unknown(bad):
    run = _plan().runs[0]
    row = {"schema": 1, "run_id": run.run_id, "finished": 2, "total": 7,
           "failed_units": 0, "state": "running", "current_task": "Actual task"}
    if bad is not None:
        row = row | bad if bad else {}
    engine = SimpleNamespace(run_id=run.run_id, progress_snapshot=lambda: row if bad is not None else None)
    assert prepared_execution_rows(_plan(), {"red_team": engine}, phase="running")["red_team"] is None


def test_terminal_does_not_complete_unrun_units():
    rows = prepared_execution_rows(_plan(), {}, phase="cancelled", terminal=True)
    assert all(row["finished"] == 0 and row["state"] == "cancelled" for row in rows.values())


def test_report_inbox_routes_once_and_reports_conflict_without_replacing_original():
    plan, inbox = _plan(), SessionReportInbox(_plan())
    report = _report(plan.runs[0])
    assert inbox.take((report,)) == ((report,), ())
    assert inbox.take((report,)) == ((), ())
    conflict = replace(report, report_sha256="0" * 64)
    deliveries, notices = inbox.take((conflict,))
    assert not deliveries and len(notices) == 1
    assert inbox.seen[report.run_id][0] == report.report_sha256
    assert inbox.take((conflict,)) == ((), ())


def test_report_inbox_bounds_repeated_foreign_or_bad_cache_notices():
    inbox = SessionReportInbox(_plan())
    for index in range(100):
        _, unexpected = inbox.take((object(),))
        _, bad_cache = inbox.take([])
        assert len(unexpected) == len(bad_cache) == int(index == 0)
    assert len(inbox.conflicts) == 2 and not inbox.seen


def test_foreign_run_immutable_report_is_not_routed():
    plan = _plan()
    inbox = SessionReportInbox(plan)
    foreign = replace(_report(plan.runs[0]), run_id="other-run")
    assert not inbox.take((foreign,))[0]
    assert not inbox.seen


@pytest.mark.parametrize("change", [{"lease_active": True}, {"reservation_active": True},
    {"owner_pending": True}, {"retirement_held": True}, {"custody_released": 1},
    {"response_authorized": True}, {"schema": True}])
def test_custody_requires_literal_released_cache_without_other_holds(change):
    snapshot = {"schema": 1, "lease_active": False, "reservation_active": False,
        "owner_pending": False, "retirement_held": False, "custody_released": True,
        "response_authorized": False}
    owner = SimpleNamespace(retirement_snapshot=lambda: snapshot)
    assert session_custody_released(owner) is True
    snapshot.update(change)
    assert session_custody_released(owner) is False
