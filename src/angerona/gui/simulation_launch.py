"""Detached acceptance of one sequential simulation owner; no Qt or arming."""
from __future__ import annotations

import json
from pathlib import Path
import threading


class SimulationLaunch:
    """Prepare off Qt, await a GUI claim, acknowledge actual Session.start.

    This helper never starts an engine, generates a report, releases a lease,
    changes a watch or modifies settings/policy. Those belong to Session.
    """

    def __init__(self, *, cfg, manager, bus, storage, data_root,
                 red_team_engine, shark_engine, response_escalated=False):
        del response_escalated  # Legacy argument never grants escalation here.
        if type(cfg) is not dict:
            raise ValueError("A plain simulation configuration is required")
        self.cfg = json.loads(json.dumps(cfg, allow_nan=False))
        self.manager, self.bus, self.storage = manager, bus, storage
        self.data_root = Path(data_root)
        self.red_team_engine, self.shark_engine = red_team_engine, shark_engine
        self.target = str(self.cfg.get("target_dir") or red_team_engine.default_documents_dir).strip()
        self.session = None
        self.plan = None
        self.reason = ""
        self.success = False
        self.accepted = False
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.cancelled = threading.Event()
        self._decision = threading.Event()
        self._lock = threading.Lock()
        self._claimed = False
        self.thread = threading.Thread(target=self._run, name="simulation-acceptance", daemon=True)

    def start(self):
        self.thread.start()

    def cancel(self, *_unused):
        with self._lock:
            self.cancelled.set()
            self._decision.set()
            session = self.session
        if session is not None:
            session.cancel()

    def claim(self):
        with self._lock:
            if not self.ready.is_set() or not self.success or self.cancelled.is_set() or self._claimed:
                return False
            self._claimed = True
            self._decision.set()
            return True

    def owned_workers(self):
        workers = [self.thread]
        session = self.session
        if session is not None:
            workers.extend(session.owned_workers())
        return tuple({id(worker): worker for worker in workers if isinstance(worker, threading.Thread)}.values())

    def _run(self):
        try:
            from angerona.shark.simulation_session import SimulationSession
            session = SimulationSession(manager=self.manager, bus=self.bus, recorder=self.storage,
                data_root=self.data_root, red_team_engine=self.red_team_engine, shark_engine=self.shark_engine)
            with self._lock:
                self.session = session
            if self.cancelled.is_set():
                raise RuntimeError("Launch cancelled before preparation")
            self.plan = session.prepare(self.cfg, default_target=self.target)
            if self.cancelled.is_set():
                raise RuntimeError("Launch cancelled before acceptance")
            self.success = True
            self.ready.set()
            self._decision.wait()
            if self.cancelled.is_set() or not self._claimed:
                raise RuntimeError("Launch cancelled before acceptance")
            if session.start(self.plan) is not True:
                raise RuntimeError("The exact prepared session was not accepted; current authority/resources remain held")
            self.accepted = True
            if self.cancelled.is_set():
                session.cancel()
        except Exception as exc:
            self.reason = (type(exc).__name__ + ": " + str(exc))[:1000]
            self.success = False
            if self.session is not None:
                self.session.cancel()
        finally:
            self.finished.set()
            self.ready.set()


def session_custody_released(session):
    """Read exact owner's bounded cache; no release, native probe or I/O."""
    try:
        snapshot = session.retirement_snapshot()
        return (type(snapshot) is dict and type(snapshot.get("schema")) is int
            and snapshot["schema"] == 1 and snapshot.get("custody_released") is True
            and snapshot.get("response_authorized") is False
            and all(snapshot.get(key) is False for key in (
                "lease_active", "reservation_active", "retirement_held", "owner_pending")))
    except Exception:
        return False


def prepared_execution_rows(plan, engines, *, phase, terminal=False):
    """Plain cached execution, including actual zero-work queued profiles.

    These units are workflow attempts, never detections/misses/coverage proof.
    """
    rows = {}
    for prepared in plan.runs:
        decision = json.loads(prepared.preflight_json)
        total = len(prepared.steps) if prepared.kind == "shark" else decision["budget"]["projected_steps"]
        if type(total) is not int or not 0 < total <= 10_000:
            continue
        engine = engines.get(prepared.kind)
        cached = None
        started = engine is not None and getattr(engine, "run_id", None) == prepared.run_id
        if started:
            getter = getattr(engine, "progress_snapshot", None)
            if callable(getter):
                cached = getter()
        if (type(cached) is dict and cached.get("run_id") == prepared.run_id
                and type(cached.get("total")) is int and cached["total"] == total
                and type(cached.get("finished")) is int and 0 <= cached["finished"] <= total
                and type(cached.get("failed_units")) is int
                and 0 <= cached["failed_units"] <= cached["finished"]):
            row = dict(cached)
            if terminal and row.get("state") in {"queued", "running", "stopping"}:
                row.update(state="cancelled" if phase == "cancelled" else "incomplete",
                    current_task="Session ended; execution completion remains unverified")
        elif started:
            # An admitted engine with an unavailable/broken count is unknown,
            # never relabelled as a newly queued zero-work run.
            rows[prepared.kind] = None
            continue
        else:
            row = {"schema": 1, "run_id": prepared.run_id, "state": "queued",
                "finished": 0, "total": total, "failed_units": 0,
                "current_task": "Queued for the sequential owner; no check has run"}
            if terminal:
                row.update(state="cancelled" if phase == "cancelled" else "incomplete",
                    current_task="No authenticated execution count for this planned profile")
        rows[prepared.kind] = row
    return rows


class SessionReportInbox:
    """Bounded once-per-run routing; the GUI's existing verifier is mandatory."""
    def __init__(self, plan):
        self.expected = {run.run_id: run.kind for run in plan.runs}
        self.seen = {}
        self.conflicts = set()

    def take(self, reports):
        from angerona.shark.aar_report import AARReportResult
        deliveries, notices = [], []
        if type(reports) is not tuple or len(reports) > 4:
            if "cache-contract" in self.conflicts:
                return (), ()
            self.conflicts.add("cache-contract")
            return (), (("", "", "Session report cache is outside its bounded contract"),)
        for report in reports:
            if type(report) is not AARReportResult or self.expected.get(report.run_id) != report.report_kind:
                identity = "unexpected-report"
                if identity not in self.conflicts:
                    self.conflicts.add(identity)
                    notices.append(("", "", "An unexpected report was held outside this accepted plan"))
                continue
            identity = (report.report_sha256, report.head_sha256, report.sequence)
            previous = self.seen.get(report.run_id)
            if previous is not None:
                if previous != identity and report.run_id not in self.conflicts:
                    self.conflicts.add(report.run_id)
                    notices.append((report.run_id, report.report_kind, "Conflicting report generations for one accepted run; review required"))
                continue
            self.seen[report.run_id] = identity
            deliveries.append(report)
        return tuple(deliveries), tuple(notices)


def stop_engines(engines, finished, errors=None):
    """Run existing bounded engine cleanup without retaining GUI objects."""
    try:
        for engine in engines:
            try:
                engine.stop_and_clean()
            except Exception as exc:
                if errors is not None:
                    errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        finished.set()
