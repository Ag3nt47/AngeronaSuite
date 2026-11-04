"""Inert Session-boundary adapter for GUI contracts, never detector evidence.

The real SimulationLaunch and MainWindow protocols remain under test. This
adapter owns real Python threads, typed immutable plans and explicit custody;
it produces no authenticated report, lease, detection or response authority.
"""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QMainWindow
from shiboken6 import isValid

from angerona.gui.main_window import MainWindow
from angerona.shark.simulation_session import PreparedRun, PreparedStep, SessionPlan


def drain(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.002)
    assert predicate()


class Window(MainWindow):
    def __init__(self, root):
        QMainWindow.__init__(self)
        self.ui_thread = threading.get_ident()
        self.statuses, self.lines, self.report_failures = [], [], []
        self.manager = SimpleNamespace(modules={})
        self.config = SimpleNamespace(data_dir=root)
        self.bus, self.storage = object(), object()
        self._eco_on = False
        self._chill_policy = SimpleNamespace(enabled=False)
        self._simulation_session = None
        self._simulation_plan = None
        self.console = SimpleNamespace(_append=self._append)
        self.shark_monitor = Mock()
        self.shark_swim, self.shark_banner = Mock(), Mock()
        for name in ("red_team_engine", "shark_engine"):
            setattr(self, name, SimpleNamespace(
                is_running=False, run_id=name + "-fixture", default_documents_dir=root / "markers",
                start=Mock(return_value=True), stop_and_clean=Mock(),
                hold_evidence_for_aar=Mock(), cancel_evidence_hold=Mock(),
            ))

    def _append(self, text):
        assert threading.get_ident() == self.ui_thread
        self.lines.append(text)

    def _simulation_launch_status(self, *args, **kwargs):
        assert threading.get_ident() == self.ui_thread
        value = super()._simulation_launch_status(*args, **kwargs)
        self.statuses.append(value)
        return value

    def _session_report_failure(self, run_id, kind, reason):
        # Collect the deliberately unverified fixture gap; never open or forge AAR.
        self.report_failures.append((run_id, kind, reason))


def build_launch(root, monkeypatch, *, block_prepare=False, ready=True):
    context = SimpleNamespace(
        owner=Window(root), prepare_entered=threading.Event(), prepare_release=threading.Event(),
        retire_release=threading.Event(), started=threading.Event(), sessions=[],
        prepare_threads=[], start_threads=[], prepare_error=None, start_error=None,
        refuse_start=False, lose_ack=False,
        readiness={"ready": ready, "state": "ARMED" if ready else "RECOVERY REQUIRED",
                   "reason": "inert readiness" if ready else "journal hold"},
    )
    if not block_prepare:
        context.prepare_release.set()

    class FixtureSession:
        def __init__(self, **kwargs):
            self.kwargs, self.thread, self.plan, self.cfg = kwargs, None, None, None
            self.cancelled, self.finished = threading.Event(), threading.Event()
            self.phase = "preparing"
            context.sessions.append(self)

        def prepare(self, cfg, *, default_target):
            context.prepare_threads.append(threading.get_ident())
            context.prepare_entered.set()
            assert context.prepare_release.wait(5), "Fixture must release preparation"
            if context.prepare_error is not None:
                raise context.prepare_error
            self.cfg = json.loads(json.dumps(cfg))
            runs = []
            for kind, flag in (("red_team", "run_redteam"), ("shark", "run_shark")):
                if not cfg.get(flag):
                    continue
                steps = () if kind == "red_team" else (
                    PreparedStep("inert-step", 0, 1, "discovery", "read-only", ()),)
                runs.append(PreparedRun("inert-session", "inert-" + kind, kind,
                    str(root), str(cfg.get("target_dir") or default_target),
                    json.dumps({"budget": {"projected_steps": 7}}), "b" * 64,
                    steps, 60, ("a" if kind == "red_team" else "c") * 64))
            self.plan = SessionPlan("inert-session", tuple(runs), 1)
            return self.plan

        def start(self, plan):
            context.start_threads.append(threading.get_ident())
            assert plan is self.plan
            if context.start_error is not None:
                raise context.start_error
            if context.refuse_start:
                self.finished.set()
                self.phase = "held"
                return False

            def work():
                self.phase = "running"
                context.started.set()
                try:
                    assert context.retire_release.wait(5), "Fixture must retire exact session worker"
                finally:
                    self.phase = "cancelled" if self.cancelled.is_set() else "completed"
                    self.finished.set()

            self.thread = threading.Thread(target=work, name="inert-presentation-session")
            self.thread.start()
            if context.lose_ack:
                raise RuntimeError("inert lost acknowledgement after native thread start")
            return True

        def cancel(self):
            self.cancelled.set()
            if self.thread is None:
                self.finished.set()
                self.phase = "cancelled"

        def owned_workers(self):
            return () if self.thread is None else (self.thread,)

        def snapshot(self):
            return {"schema": 1, "session_id": self.plan.session_id,
                    "session_generation": self.plan.generation, "phase": self.phase,
                    "current_task": "Inert presentation fixture"}

        def retirement_snapshot(self):
            pending = self.thread is not None and self.thread.is_alive()
            return {"schema": 1, "lease_active": False, "reservation_active": pending,
                    "retirement_held": False, "owner_pending": pending,
                    "custody_released": not pending, "response_authorized": False}

        def completed_reports(self):
            return ()

        def performance_snapshot(self, _run_id):
            return None

        def launch_diagnostics(self):
            return ()

    monkeypatch.setattr("angerona.shark.simulation_session.SimulationSession", FixtureSession)
    monkeypatch.setattr("angerona.core.drill_readiness.assess_drill_response",
                        lambda *_a, **_kw: dict(context.readiness))
    monkeypatch.setattr("angerona.gui.main_window.QMessageBox.information", Mock())
    monkeypatch.setattr("angerona.gui.main_window.QMessageBox.warning", Mock())
    context.reconcile = Mock()
    monkeypatch.setattr("angerona.gui.main_window.reconcile_module_usage", context.reconcile)
    context.cfg = {"run_redteam": True, "run_shark": True, "intensity": "Extreme",
                   "complexity": 4, "campaign": True, "comprehensive": True,
                   "auto_remediate": True}
    return context


def retire_launch(context):
    context.prepare_release.set()
    context.retire_release.set()
    owner = context.owner
    job = getattr(owner, "_sim_launch_job", None)
    if job is not None:
        job.cancel()
        if job.thread.ident is not None:
            job.thread.join(3)
            assert not job.thread.is_alive()
    for session in context.sessions:
        session.cancel()
        for worker in session.owned_workers():
            if worker.ident is not None:
                worker.join(3)
                assert not worker.is_alive()
    stop = getattr(owner, "_sim_stop_thread", None)
    if stop is not None and stop.ident is not None:
        stop.join(3)
        assert not stop.is_alive()
    if isValid(owner):
        for name in ("_sim_launch_timer", "_sim_stop_timer", "_sim_poll"):
            timer = getattr(owner, name, None)
            if timer is not None and isValid(timer):
                timer.stop()
        owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
