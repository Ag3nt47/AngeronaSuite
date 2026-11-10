"""One simulation owner; queued plans confer no detector or host authority.

The plan and UI counters are scheduling/ground-truth metadata. Actual native
detector receipts and durable exact Combat actions remain independent gates.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import sys
import threading
import time
import uuid
import weakref

from angerona.shark.run_manifest import (
    MAX_ADMITTED_DRILL_SECONDS, MAX_ARTIFACT_REFERENCES, MAX_STEPS, preflight_run,
)

_OPERATIONS = frozenset({"initial_access", "discovery", "simulated_persistence",
                         "simulated_byovd", "exfiltration", "custom", "noise_injection"})
_RECIPES = frozenset({"text", "archive", "driver", "html", "pdf-text"})
_FILE_OPERATIONS = frozenset({"initial_access", "simulated_persistence", "simulated_byovd"})
_SETTLE_SECONDS = 30
_WORKFLOW_SETTLEMENT_FLOOR_SECONDS = 30.0
_WORKFLOW_SETTLEMENT_SECONDS_PER_CONTRACT = 1.5
_WORKFLOW_SETTLEMENT_MAX_SECONDS = 60.0
_SESSION_OWNERS_LOCK = threading.Lock()
_SESSION_OWNERS = weakref.WeakKeyDictionary()


class SessionHeld(RuntimeError):
    """A missing invariant holds subsequent probe admission; no success implied."""


class _ReportHeld(SessionHeld):
    def __init__(self, reason):
        super().__init__("An authenticated immutable report was unavailable")
        self.reason = reason


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def _digest(value) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PreparedStep:
    planned_step_id: str
    position: int
    cycle: int
    operation: str
    variant: str
    control_kinds: tuple[str, ...]


@dataclass(frozen=True)
class PreparedRun:
    session_id: str
    run_id: str
    kind: str
    data_root: str
    target: str
    preflight_json: str
    request_digest: str
    steps: tuple[PreparedStep, ...]
    admitted_ttl_seconds: int
    plan_sha256: str

    def manifest(self) -> dict:
        body = {
            "schema": "angerona.prepared-simulation-run.v1", "session_id": self.session_id,
            "run_id": self.run_id, "kind": self.kind, "data_root": self.data_root,
            "target": self.target, "request_digest": self.request_digest,
            "admitted_ttl_seconds": self.admitted_ttl_seconds,
            "steps": [{**asdict(step), "control_kinds": list(step.control_kinds)}
                      for step in self.steps],
        }
        return {**body, "plan_sha256": self.plan_sha256}


@dataclass(frozen=True)
class SessionPlan:
    session_id: str
    runs: tuple[PreparedRun, ...]
    generation: int = 0


@dataclass(frozen=True)
class RunPerformanceSnapshot:
    session_id: str
    session_generation: int
    run_id: str
    plan_sha256: str
    state: str
    eligible_planned: int
    evaluated_steps: int = 0
    native_verified_steps: int = 0
    simulation_verified_steps: int = 0
    detection_verified_steps: int = 0
    containment_verified_steps: int = 0
    provisional_failures: int = 0
    containment_required: bool = True
    unsettled_steps: int = 0
    unavailable_steps: int = 0
    finalized_misses: int | None = None
    producer_generations: tuple[tuple[str, int], ...] = ()
    scanner_source_epoch: str | None = None
    final_report_sha256: str | None = None
    verification_scope: str = "current controlled native detection and strict durable response observations"


def validate_prepared_manifest(value: object) -> bool:
    """Validate plain bounded plan structure; this grants no response authority."""
    try:
        if type(value) is not dict or set(value) != {
            "schema", "session_id", "run_id", "kind", "data_root", "target",
            "request_digest", "admitted_ttl_seconds", "steps", "plan_sha256",
        }:
            return False
        if (value["schema"] != "angerona.prepared-simulation-run.v1"
                or value["kind"] not in {"shark", "red_team"}
                or any(type(value[key]) is not str or not value[key]
                       or len(value[key]) > 32768 for key in ("data_root", "target"))
                or type(value["session_id"]) is not str
                or re.fullmatch(r"session-[0-9a-f]{32}", value["session_id"]) is None
                or type(value["run_id"]) is not str
                or re.fullmatch(r"(?:shark|redteam)-[0-9a-f]{32}", value["run_id"]) is None
                or not value["run_id"].startswith("shark-" if value["kind"] == "shark" else "redteam-")
                or type(value["admitted_ttl_seconds"]) is not int
                or not 60 <= value["admitted_ttl_seconds"] <= MAX_ADMITTED_DRILL_SECONDS
                or type(value["steps"]) is not list or len(value["steps"]) > MAX_STEPS):
            return False
        for key in ("request_digest", "plan_sha256"):
            if type(value[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None:
                return False
        controls = 0
        for index, step in enumerate(value["steps"]):
            if (type(step) is not dict or set(step) != {
                "planned_step_id", "position", "cycle", "operation", "variant", "control_kinds",
            } or type(step["position"]) is not int or step["position"] != index
                    or type(step["cycle"]) is not int or not 1 <= step["cycle"] <= 4
                    or type(step["operation"]) is not str or step["operation"] not in _OPERATIONS
                    or type(step["variant"]) is not str or len(step["variant"]) > 32
                    or type(step["control_kinds"]) is not list
                    or len(step["control_kinds"]) > 2
                    or any(type(kind) is not str or kind not in _RECIPES for kind in step["control_kinds"])):
                return False
            kinds = step["control_kinds"]
            operation = step["operation"]
            if ((operation == "initial_access" and (len(kinds) != 1 or kinds[0] not in {"text", "archive", "html", "pdf-text"}))
                    or (operation == "simulated_persistence" and (not kinds or kinds != ["text"] * len(kinds)))
                    or (operation == "simulated_byovd" and kinds != ["driver"])
                    or (operation not in _FILE_OPERATIONS and kinds)):
                return False
            identity = {"run_id": value["run_id"], "position": index, "cycle": step["cycle"],
                        "operation": operation, "variant": step["variant"], "control_kinds": kinds}
            if step["planned_step_id"] != "PSTEP-" + _digest(identity)[:24].upper():
                return False
            controls += len(kinds)
        body = dict(value)
        supplied = body.pop("plan_sha256")
        if value["kind"] == "red_team" and value["steps"]:
            return False
        if value["kind"] == "shark":
            cycles = {step["cycle"] for step in value["steps"]}
            if not cycles or cycles != set(range(1, max(cycles) + 1)):
                return False
            for cycle in cycles:
                operations = [step["operation"] for step in value["steps"] if step["cycle"] == cycle]
                if (len(operations) != len(set(operations))
                        or not {"initial_access", "discovery", "simulated_persistence",
                                "simulated_byovd", "exfiltration"}.issubset(operations)):
                    return False
        return controls <= 64 and controls <= MAX_ARTIFACT_REFERENCES and _digest(body) == supplied
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def validate_prepared_run(prepared: object, *, kind: str | None = None) -> bool:
    if type(prepared) is not PreparedRun or (kind is not None and prepared.kind != kind):
        return False
    try:
        if len(prepared.preflight_json.encode("utf-8")) > 64 * 1024:
            return False
        decision = json.loads(prepared.preflight_json)
        if type(decision) is not dict or decision.get("accepted") is not True:
            return False
        target = decision.get("target") or {}
        replay = preflight_run(
            kind=prepared.kind, cycles=decision["cycles"], jitter_range=decision["jitter"],
            noise_chance=decision["noise_chance"], target_dir=prepared.target,
            custom=decision.get("custom"), campaign=decision["campaign"],
            comprehensive=decision["comprehensive"],
        )
        controls = sum(len(step.control_kinds) for step in prepared.steps)
        expected_ttl = max(60, int(replay.budget["admitted_run_ttl_seconds"]) +
            sum(bool(step.control_kinds) for step in prepared.steps) * _SETTLE_SECONDS)
        return bool(replay.accepted and _json(replay.as_dict()) == prepared.preflight_json
            and replay.request_digest == prepared.request_digest
            and prepared.admitted_ttl_seconds == expected_ttl
            and controls <= replay.budget["projected_artifact_references"]
            and len(prepared.steps) <= replay.budget["projected_steps"]
            and target.get("path_sha256") == hashlib.sha256(
                os.path.normcase(prepared.target).encode("utf-8")).hexdigest()
            and validate_prepared_manifest(prepared.manifest()))
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return False

@dataclass(frozen=True)
class _WorkflowSettlementBudget:
    run_id: str
    plan_sha256: str
    planned_contracts: int | None
    seconds: float
    basis: str


def _workflow_settlement_budget(prepared=None):
    """Freeze scheduling metadata only; this never extends evidence or a lease."""
    if prepared is None:
        return _WorkflowSettlementBudget('', '', None, _WORKFLOW_SETTLEMENT_FLOOR_SECONDS,
                                         'legacy-unknown')
    if not validate_prepared_run(prepared):
        raise SessionHeld('Workflow settlement requires a validated frozen plan')
    contracts = json.loads(prepared.preflight_json)['budget']['detection_contract_steps']
    if type(contracts) is not int or not 0 <= contracts <= MAX_STEPS:
        raise SessionHeld('The frozen planned contract count is invalid')
    seconds = min(_WORKFLOW_SETTLEMENT_MAX_SECONDS,
                  max(_WORKFLOW_SETTLEMENT_FLOOR_SECONDS,
                      contracts * _WORKFLOW_SETTLEMENT_SECONDS_PER_CONTRACT))
    return _WorkflowSettlementBudget(prepared.run_id, prepared.plan_sha256, contracts,
                                     seconds, 'replay-validated-planned-contracts')


def prepare_session(cfg: dict, *, data_root: Path, default_target: Path) -> SessionPlan:
    """Freeze IDs and finite recipes before any producer/lease/engine is started."""
    session_id = "session-" + uuid.uuid4().hex
    target = str(Path(cfg.get("target_dir") or default_target).resolve(strict=False))
    root = str(Path(data_root).resolve(strict=False))
    runs = []
    for kind in ("red_team", "shark"):
        if not cfg.get("run_redteam" if kind == "red_team" else "run_shark"):
            continue
        preset = None
        if kind == "red_team":
            from angerona.shark.red_team import INTENSITY_LEVELS
            preset = INTENSITY_LEVELS.get(str(cfg.get("intensity")))
        decision = preflight_run(
            kind=kind, cycles=(preset["cycles"] if preset else 1) if kind == "red_team" else cfg.get("complexity", 1),
            jitter_range=preset["jitter"] if preset else (2.0, 7.0) if kind == "red_team" else (2.0, 9.0),
            noise_chance=preset["noise"] if preset else 0.25,
            target_dir=target, custom=cfg.get("custom") or None,
            campaign=bool(cfg.get("campaign", False)) if kind == "red_team" else False,
            comprehensive=bool(cfg.get("comprehensive", True)) if kind == "red_team" else False,
        )
        if not decision.accepted:
            raise SessionHeld("Simulation preflight refused: " + "; ".join(decision.violations))
        run_id = ("shark-" if kind == "shark" else "redteam-") + uuid.uuid4().hex
        steps = []
        if kind == "shark":
            for cycle in range(1, decision.cycles + 1):
                initial = random.choice(("text", "archive", "html", "pdf-text"))
                persistence = random.choice((1, 2))
                selected = [("initial_access", initial, (initial,)),
                    ("discovery", "read-only", ()),
                    ("simulated_persistence", "marker-only", ("text",) * persistence),
                    ("simulated_byovd", "never-loaded", ("driver",)),
                    ("exfiltration", "native-network-gap", ())]
                if decision.custom is not None:
                    selected.append(("custom", "observation-only", ()))
                if random.random() < decision.noise_chance:
                    selected.append(("noise_injection", "benign", ()))
                random.shuffle(selected)
                for operation, variant, kinds in selected:
                    identity = {"run_id": run_id, "position": len(steps), "cycle": cycle,
                                "operation": operation, "variant": variant, "control_kinds": list(kinds)}
                    steps.append(PreparedStep("PSTEP-" + _digest(identity)[:24].upper(),
                        len(steps), cycle, operation, variant, kinds))
        controls = sum(len(step.control_kinds) for step in steps)
        if controls > 64 or len(steps) > MAX_STEPS:
            raise SessionHeld("Prepared simulation exceeds its existing object budget")
        # Account explicitly for the new per-step response phase; retain the
        # existing hard maximum and never renew the lease after admission.
        ttl = max(60, int(decision.budget["admitted_run_ttl_seconds"]) +
                  sum(bool(step.control_kinds) for step in steps) * _SETTLE_SECONDS)
        if ttl > MAX_ADMITTED_DRILL_SECONDS:
            raise SessionHeld("Prepared simulation exceeds the existing deadline bound")
        prepared = PreparedRun(session_id, run_id, kind, root, target, _json(decision.as_dict()),
                               decision.request_digest, tuple(steps), ttl, "")
        body = prepared.manifest()
        body.pop("plan_sha256")
        prepared = PreparedRun(**{**asdict(prepared), "steps": prepared.steps, "plan_sha256": _digest(body)})
        if not validate_prepared_run(prepared):
            raise SessionHeld("Prepared simulation binding did not verify")
        runs.append(prepared)
    if not runs:
        raise SessionHeld("No simulation scenario was selected")
    return SessionPlan(session_id, tuple(runs))


def prepared_history_matches(history: object, manifest: object) -> bool:
    """Match signed ground truth to its plan; native evidence stays separate."""
    if type(history) is not dict or not validate_prepared_manifest(manifest):
        return False
    try:
        rows = history["steps"]
        planned = manifest["steps"]
        if (history["run_id"] != manifest["run_id"] or history["kind"] != manifest["kind"]
                or history["safety_contract"]["request_digest"] != manifest["request_digest"]
                or history["campaign"].get("prepared_run") != manifest or type(rows) is not list):
            return False
        if manifest["kind"] == "red_team":
            return not planned  # Its existing mandatory-plan/lease verifier stays authoritative.
        if len(rows) > len(planned):
            return False
        safety = history["safety_contract"]
        if max((step["cycle"] for step in planned), default=0) != safety.get("cycles"):
            return False
        for cycle in range(1, safety["cycles"] + 1):
            operations = {step["operation"] for step in planned if step["cycle"] == cycle}
            if ("custom" in operations) != bool(safety.get("custom")):
                return False
            if safety.get("noise_chance") == 0 and "noise_injection" in operations:
                return False
        if history["status"] == "completed" and len(rows) != len(planned):
            return False
        for row, expected in zip(rows, planned):
            if row.get("planned_step_id") != expected["planned_step_id"]:
                return False
            if len(row.get("artifact_paths") or []) > max(len(expected["control_kinds"]),
                    1 if expected["operation"] in {"custom", "noise_injection"} else 0):
                return False
            if (row.get("ok") is True and expected["control_kinds"]
                    and len(row.get("artifact_paths") or []) != len(expected["control_kinds"])):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


class SharkRunSession:
    """Exact current run routing; scheduling metadata is never native proof."""

    def __init__(self, owner, prepared, lease, engine, enrollment, readiness):
        self._owner, self._prepared, self._lease = owner, prepared, lease
        self._engine, self._enrollment = engine, enrollment
        self._readiness_json = _json(readiness)
        self.cleanup_allowed = False
        self._events = deque()
        self._events_lock = threading.Lock()
        self._evidence_loss = False
        self._declarations = {}
        self._issued_steps = set()
        self._settled_steps = set()
        self._counted_native = set()
        self._counted_containment = set()
        self._generations = {}
        from angerona.core.module_base import BaseModule
        for name in ("YARA Scanner", "Purple Remediation Guard", "Process Monitor", "Adversary Combat"):
            module = owner.manager.modules.get(name)
            if not isinstance(module, BaseModule):
                raise SessionHeld("A required exact simulation producer is unavailable")
            self._generations[name] = (module, module.lifecycle_generation)
        owner.bus.subscribe(self._capture)

    def readiness_snapshot(self):
        return json.loads(self._readiness_json)

    def matches(self, prepared, lease, engine):
        return (prepared is self._prepared and lease is self._lease and engine is self._engine
                and self._owner._active_binding is self)

    def _capture(self, event):
        from angerona.core.eventbus import Event
        if type(event) is not Event or event.module not in {"YARA Scanner", "Adversary Combat"}:
            return
        # Queue only: no hashing, signature verification, native I/O or journal
        # read on a detector's inline publication thread.
        with self._events_lock:
            if len(self._events) >= 512:
                self._evidence_loss = True
            else:
                self._events.append(event)

    def close_capture(self):
        self._owner.bus.unsubscribe(self._capture)

    def check_current(self):
        from angerona.core.module_base import BaseModule
        from angerona.modules.purple_guard import validation_authority_matches
        from angerona.modules.yara_scanner import YaraScannerModule
        if (self._owner.cancelled.is_set()
                or time.monotonic() >= self._owner._run_deadline
                or not validation_authority_matches(self._lease, recorder=self._owner.recorder,
                    bus=self._owner.bus, manager=self._owner.manager)):
            raise SessionHeld("The exact simulation run is cancelled, expired or released")
        for name, (expected, generation) in self._generations.items():
            current = self._owner.manager.modules.get(name)
            state = BaseModule.operational_snapshot(expected)
            if (current is not expected or state["lifecycle_generation"] != generation
                    or state["status"] != "running" or state["thread_alive"] is not True):
                raise SessionHeld("A required exact simulation producer generation changed")
        detector = self._generations["YARA Scanner"][0]
        if type(detector) is not YaraScannerModule or not YaraScannerModule._control_enrollment_valid(detector, self._enrollment):
            raise SessionHeld("The native scanner's source epoch or owner is unavailable")

    def create_controls(self, planned):
        from angerona.modules.purple_guard import RedTeamValidationLease
        self.check_current()
        if (type(planned) is not PreparedStep or planned not in self._prepared.steps
                or planned.planned_step_id in self._issued_steps or not planned.control_kinds):
            raise SessionHeld("A fixed control step was absent, repeated or out of plan")
        self._issued_steps.add(planned.planned_step_id)
        created = []
        for recipe in planned.control_kinds:
            self.check_current()
            marker_writer = getattr(self._engine, "_marker_writer", None)
            writer_options = ({} if marker_writer is None else
                {"marker_writer": marker_writer, "writer_source": self})
            declaration = RedTeamValidationLease.create_yara_control(self._lease,
                run_id=self._prepared.run_id, step_id=planned.planned_step_id,
                scanner_enrollment=self._enrollment, control_kind=recipe, **writer_options)
            self._declarations[declaration["path"]] = declaration
            identity = declaration["identity"]
            # Preserve exact cleanup custody even if the next fixed create fails.
            with self._engine._artifact_lock:
                self._engine._owned_artifacts[Path(declaration["path"])] = tuple(
                    identity[field] for field in ("device", "inode", "size", "mtime_ns"))
            created.append(declaration)
        return tuple(created)

    @staticmethod
    def _detach(event):
        from angerona.core.response_proof import event_proof_digest
        event_proof_digest(event)  # Existing exact plain-tree/byte bounds first.
        return replace(event, details=json.loads(_json(event.details)))

    def settle_step(self, planned, step):
        from angerona.modules.yara_scanner import YaraScannerModule
        from angerona.shark import aar_report

        if planned.planned_step_id in self._settled_steps:
            raise SessionHeld("A planned step settlement was replayed")
        self._settled_steps.add(planned.planned_step_id)
        if not planned.control_kinds:
            if planned.operation == "exfiltration":
                self._owner._note_step_performance(self, planned, "unavailable", False)
                return {"state": "held", "reason": "native-network-analytic-and-enforcement-unavailable",
                        "native_detections": 0, "verified_targets": 0, "expected_targets": 0}
            return {"state": "not-applicable", "reason": "observation-or-benign-work",
                    "native_detections": 0, "verified_targets": 0, "expected_targets": 0}
        paths = tuple(step.get("artifact_paths") or ())
        declarations = {path: value for path, value in self._declarations.items()
                        if value["step_id"] == planned.planned_step_id}
        if (len(paths) != len(planned.control_kinds) or set(paths) != set(declarations)
                or step.get("planned_step_id") != planned.planned_step_id):
            raise SessionHeld("The actual files do not match every exact planned target")
        expected = {("path", aar_report._canonical_path(path)) for path in paths}
        deadline = min(self._owner._run_deadline, time.monotonic() + _SETTLE_SECONDS)
        detector = self._generations["YARA Scanner"][0]
        while True:
            self.check_current()
            self._owner._phase("settling", planned_step_id=planned.planned_step_id)
            with self._events_lock:
                captured, loss = tuple(self._events), self._evidence_loss
            if loss:
                self._owner._note_step_performance(self, planned, "unavailable", False)
                return {"state": "held", "reason": "bounded-event-capture-overflow",
                        "native_detections": 0, "verified_targets": 0, "expected_targets": len(expected)}
            catches, responses = {}, []
            for source in captured:
                try:
                    event = self._detach(source)
                    if self._owner.bus.verify(event) is not True:
                        continue
                    if event.module == "Adversary Combat":
                        responses.append(event)
                    elif event.module == "YARA Scanner":
                        path = event.details.get("artifact_path")
                        if (path in declarations
                                and YaraScannerModule.verify_control_detection_event(detector, event)
                                and aar_report._verify_shark_native_event(event,
                                    manager=self._owner.manager, bus=self._owner.bus,
                                    recorder=self._owner.recorder)):
                            catches[path] = event
                except (AttributeError, TypeError, ValueError, OverflowError, RecursionError):
                    continue
            verified = set()
            if catches and responses:
                verifier = aar_report._live_combat_action_verifier(
                    self._owner.manager, self._owner.bus, Path(self._prepared.data_root), red_team=False)
                for catch in catches.values():
                    for response in responses:
                        verified.update(aar_report._verified_containment_targets(
                            step, catch, response, combat_verifier=verifier))
            native_keys = {event.hmac_sig for event in catches.values()}
            new_native = native_keys - self._counted_native
            new_containment = verified - self._counted_containment
            self._counted_native.update(new_native)
            self._counted_containment.update(new_containment)
            if new_native or new_containment:
                self._owner._phase("settling", native_delta=len(new_native),
                                   contained_delta=len(new_containment))
            native_complete = len(catches) == len(expected)
            if native_complete:
                self._owner._note_step_performance(self, planned, "detected", True)
            if verified == expected:
                self._owner._note_step_performance(self, planned, "verified", True)
                self._owner._phase("running", settled_delta=1)
                return {"state": "settled", "reason": "original-native-proof-and-durable-exact-action",
                        "native_detections": len(catches), "verified_targets": len(verified),
                        "expected_targets": len(expected)}
            if native_complete and not self._owner.performance_snapshot(self._prepared.run_id).containment_required:
                self._owner._phase("running", settled_delta=1)
                return {"state": "settled", "reason": "original-native-proof-detection-only-mode",
                        "native_detections": len(catches), "verified_targets": len(verified),
                        "expected_targets": len(expected)}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                from angerona.modules.adversary_combat import AdversaryCombat
                combat = self._generations["Adversary Combat"][0]
                response = AdversaryCombat.response_snapshot(combat)
                pending = response.get("queue_pending")
                known_gap = bool(native_complete and type(pending) is int and pending == 0
                                 and response.get("canary_ready") is True)
                self._owner._note_step_performance(self, planned,
                    "failed" if known_gap else "unsettled", native_complete)
                self._owner._phase("running")
                return {"state": "held", "reason": "bounded-native-response-settlement-expired",
                        "native_detections": len(catches), "verified_targets": len(verified),
                        "expected_targets": len(expected)}
            self._owner.cancelled.wait(min(0.1, remaining))


@dataclass(frozen=True)
class LaunchDiagnostic:
    session_id: str
    run_id: str
    phase: str
    reason_code: str
    detail: str = ""
    authenticated_run: bool = field(default=False, init=False)
    response_authorized: bool = field(default=False, init=False)


class RedTeamRunObserver:
    """Bounded completed-step checks on the retained session owner, never Qt.

    Engine statements are immutable local ground truth, not authenticated final
    history. Only original producer proofs and exact durable actions can produce
    provisional verified counts. Missing evidence stays pending/unknown.
    """

    def __init__(self, owner, prepared, lease, engine):
        from angerona.shark.run_manifest import expected_red_team_plan
        self.owner, self.prepared, self.lease, self.engine = owner, prepared, lease, engine
        self.expected = {row["plan_step_id"]: row for row in
                         expected_red_team_plan(json.loads(prepared.preflight_json))}
        self._lock = threading.Lock()
        self._pending, self._events = deque(), deque()
        self._seen = set()
        self._detection_checked = {}
        self._detection_attempts = {}
        self._verified_detection_types = {}
        self._response_checked = {}
        self._response_attempts = {}
        self._terminal_checked = set()
        self._loss = False
        self._disabled = False
        self._lease_id = lease.readiness.get("lease_id")
        self._generations = {name: (module, module.lifecycle_generation)
            for name, module in owner.manager.modules.items() if name in {
                "Purple Remediation Guard", "Process Monitor", "File Integrity Monitor", "YARA Scanner", "Adversary Combat"}}
        owner.bus.subscribe(self._capture_event)

    def matches(self, prepared, lease, engine):
        return (prepared is self.prepared and lease is self.lease and engine is self.engine
                and self.owner._active_redteam_observer is self)

    def _capture_event(self, event):
        from angerona.core.eventbus import Event
        if type(event) is not Event or type(event.details) is not dict:
            return
        details = event.details
        relevant = details.get("lease_id") == self._lease_id and bool(self._lease_id)
        relevant = relevant or (event.module == "Adversary Combat"
            and details.get("trigger_module") in self._generations
            and type(details.get("verified_actions")) is list)
        if not relevant:
            return
        with self._lock:
            if len(self._events) >= 512:
                self._loss = True
            else:
                self._events.append(event)

    def capture_completed_steps(self, producer, rows, position):
        from angerona.shark.red_team import RedTeamEngine, _COMPLETED_STEP_SITE_CODE
        try:
            if (type(producer) is not RedTeamEngine or producer is not self.engine
                    or producer.run_id != self.prepared.run_id or producer._validation_lease is not self.lease
                    or producer._thread is not threading.current_thread()
                    or sys._getframe(1).f_code is not _COMPLETED_STEP_SITE_CODE
                    or type(producer)._run_playbook.__code__ is not _COMPLETED_STEP_SITE_CODE
                    or type(rows) is not tuple or len(rows) > 16):
                return
            now = time.monotonic()
            for offset, source in enumerate(rows):
                row = asdict(source)
                identifier = row.get("plan_step_id")
                expected = self.expected.get(identifier)
                if expected is None or expected.get("category") != "detection":
                    continue
                encoded = _json(row)
                if len(encoded.encode("utf-8")) > 64 * 1024:
                    raise ValueError("completed step exceeds observation budget")
                with self._lock:
                    if identifier in self._seen or len(self._seen) >= MAX_STEPS:
                        self._loss = True
                        continue
                    self._seen.add(identifier)
                    self._pending.append((identifier, position + offset, encoded, now + _SETTLE_SECONDS))
        except Exception:
            with self._lock:
                self._loss = True

    @staticmethod
    def _copy_event(event):
        """Bound plain metadata before serialization, including wide native IDs."""
        if (type(event.message) is not str or len(event.message) > 32768
                or type(event.module) is not str or len(event.module) > 200):
            raise ValueError("event envelope")
        stack = [(event.details, 0)]
        nodes = 0
        size = len(event.message.encode("utf-8", "strict")) + len(event.module.encode("utf-8", "strict"))
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > 1024 or depth > 12 or size > 64 * 1024:
                raise ValueError("event observation budget")
            if type(value) is dict:
                if len(value) > 128 or any(type(key) is not str or len(key) > 256 for key in value):
                    raise ValueError("event keys")
                for key, item in value.items():
                    size += len(key.encode("utf-8", "strict"))
                    stack.append((item, depth + 1))
            elif type(value) in (tuple, list):
                if len(value) > 256:
                    raise ValueError("event collection")
                stack.extend((item, depth + 1) for item in value)
            elif type(value) is str:
                if len(value) > 32768:
                    raise ValueError("event string")
                size += len(value.encode("utf-8", "strict"))
            elif type(value) is int:
                if value.bit_length() > 256:
                    raise ValueError("event integer")
                size += 80
            elif type(value) is float:
                if not math.isfinite(value):
                    raise ValueError("event scalar")
                size += 32
            elif value is None or type(value) is bool:
                size += 8
            else:
                raise ValueError("non-plain event")
        encoded = _json(event.details)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValueError("event observation bytes")
        return replace(event, details=json.loads(encoded))

    def drain(self, *, final=False):
        from angerona.core.module_base import BaseModule
        from angerona.modules.adversary_combat import AdversaryCombat
        from angerona.shark import aar_report
        if self.owner.cancelled.is_set():
            self.owner._redteam_performance_unavailable(self)
            return
        if self._disabled:
            return
        # A fast playbook can retire between polls with more than two exact
        # tickets still queued. Review each remaining ticket once within the
        # original run deadline before switching to the signed report.
        for _batch in range(MAX_STEPS if final else 2):
            if final and time.monotonic() >= self.owner._run_deadline:
                return
            with self._lock:
                if self._loss or not self._pending:
                    if self._loss:
                        self.owner._redteam_performance_unavailable(self)
                    return
                ticket = self._pending.popleft()
                captured = tuple(self._events)
            identifier, position, encoded, deadline = ticket
            row = json.loads(encoded)
            now = time.monotonic()
            paths = set(row.get("artifact_paths") or ())
            tokens = set(row.get("correlation_tokens") or ())
            candidates = [event for event in captured if event.module != "Adversary Combat"
                and (event.details.get("path") in paths or event.details.get("artifact_path") in paths
                     or event.details.get("correlation_token") in tokens)]
            signatures = {event.hmac_sig for event in candidates
                          if type(event.hmac_sig) is str and re.fullmatch(r"[0-9a-f]{64}", event.hmac_sig)}
            verified_types = self._verified_detection_types.get(identifier, (False, False))
            analytic_signatures = set()
            for event in candidates:
                if type(event.hmac_sig) is not str or event.hmac_sig not in signatures:
                    continue
                # These are scheduling hints only. The actual AAR verifier
                # below still requires the original native/Purple receipt.
                # Raw observations never consume an analytic opportunity.
                if not verified_types[0] and aar_report._is_native_analytic(event):
                    analytic_signatures.add(("native", event.hmac_sig))
                if not verified_types[1] and aar_report._is_purple_validation(row, event):
                    analytic_signatures.add(("simulation", event.hmac_sig))
            new_analytics = analytic_signatures - self._detection_checked.get(identifier, set())
            response_signatures = {event.hmac_sig for event in captured
                if event.module == "Adversary Combat" and type(event.hmac_sig) is str
                and re.fullmatch(r"[0-9a-f]{64}", event.hmac_sig)
                and event.details.get("trigger_event_digest") in signatures
                and type(event.details.get("verified_actions")) is list}
            new_responses = response_signatures - self._response_checked.get(identifier, set())
            detection_attempts = self._detection_attempts.get(identifier, 0)
            response_attempts = self._response_attempts.get(identifier, 0)
            if new_analytics and detection_attempts >= 8:
                self.owner._redteam_performance_unavailable(self)
                return
            detection_due = bool(new_analytics)
            response_due = bool(new_responses) and response_attempts < 4
            terminal_due = (final or now >= deadline) and identifier not in self._terminal_checked
            if not (detection_due or response_due or terminal_due):
                if not final and now < deadline:
                    with self._lock:
                        self._pending.append(ticket)
                continue
            # Coalesce all newly captured signatures into one evaluation.
            # Detection upgrades, response hints and the terminal opportunity
            # have separate finite budgets; none steals another's turn.
            if any(self.owner.manager.modules.get(name) is not module
                   or BaseModule.operational_snapshot(module)["lifecycle_generation"] != generation
                   for name, (module, generation) in self._generations.items()):
                self.owner._redteam_performance_unavailable(self)
                return
            events = []
            try:
                events = [self._copy_event(event) for event in captured]
            except (AttributeError, TypeError, ValueError, UnicodeError, OverflowError):
                self.owner._redteam_performance_unavailable(self)
                return
            verdict = aar_report.evaluate_live_redteam_step(row, position=position,
                run_id=self.prepared.run_id, events=events, manager=self.owner.manager,
                bus=self.owner.bus, recorder=self.owner.recorder, validation_lease=self.lease,
                data_root=self.owner.data_root)
            if detection_due:
                self._detection_checked.setdefault(identifier, set()).update(analytic_signatures)
                self._detection_attempts[identifier] = detection_attempts + 1
            if response_due:
                self._response_checked.setdefault(identifier, set()).update(response_signatures)
                self._response_attempts[identifier] = response_attempts + 1
            if terminal_due:
                self._terminal_checked.add(identifier)
            if verdict is not None:
                self._verified_detection_types[identifier] = (
                    verified_types[0] or verdict.native_catch is not None,
                    verified_types[1] or verdict.simulation_validation is not None,
                )
            if self.owner.cancelled.is_set():
                self.owner._redteam_performance_unavailable(self)
                return
            settled_negative = False
            combat = self.owner.manager.modules.get("Adversary Combat")
            if verdict is not None and verdict.catch is not None and not verdict.target_containment_verified:
                if time.monotonic() >= deadline and type(combat) is AdversaryCombat:
                    state = AdversaryCombat.response_snapshot(combat)
                    pending = state.get("queue_pending")
                    settled_negative = (type(pending) is int and pending == 0 and state.get("canary_ready") is True)
            self.owner._note_redteam_performance(self, identifier, verdict, settled_negative)
            if not final and time.monotonic() < deadline:
                with self._lock:
                    self._pending.append(ticket)

    def close(self):
        self.owner.bus.unsubscribe(self._capture_event)


class SimulationSession:
    """Retained detached owner of sequential engine, settlement and report work.

    MainWindow must delegate report/lease release to this owner. Merely hiding
    a window never proves retirement; STOP retains owned_workers() until joined.
    """

    def __init__(self, *, manager, bus, recorder, data_root, red_team_engine, shark_engine):
        self.manager, self.bus, self.recorder = manager, bus, recorder
        self.data_root = Path(data_root).resolve(strict=False)
        self.red_team_engine, self.shark_engine = red_team_engine, shark_engine
        self.thread = None
        self.cancelled = threading.Event()
        self.finished = threading.Event()
        self._lock = threading.Lock()
        self._prepared = None
        self._session_generation = 0
        self._performance = {}
        self._performance_observations = {}
        self._plan_started = False
        self._reservation_active = False
        self._retirement_held = False
        self._cfg = None
        self._active_binding = None
        self._active_redteam_observer = None
        self._active_engine = None
        self._engine_thread = None
        self._active_lease = None
        self._lease_release_attempted = False
        self._run_deadline = 0.0
        self._workflow_budgets = {}
        self._workflow_current_budget = None
        self._workflow_settlements = {}
        self._workflow_producer_state = "unrequested"
        self._execution_completed = 0
        self._execution_current_finished = 0
        self._reports = []
        self._diagnostics = []
        self._cache = {"schema": 1, "session_id": "", "session_generation": 0, "phase": "unprepared",
            "current_run_id": "", "queued_run_ids": (), "planned_runs": 0,
            "completed_reports": 0, "execution_finished": 0, "execution_total": 0,
            "execution_available": False,
            "settled_steps": 0, "native_detections": 0, "contained_targets": 0,
            "reason_code": "", "response_authorized": False,
            "workflow_settlement_policy_seconds": None, "workflow_settlement_allowance_seconds": None,
            "workflow_settlement_basis": "unprepared", "workflow_settlement_planned_contracts": None,
            "workflow_settlement_elapsed_seconds": 0.0, "workflow_settlement_drained": None,
            "workflow_settlement_baseline_exceeded": False, "workflow_settlement_warning": "",
            "workflow_settlement_diagnostic_published": False,
            "workflow_producer_state": "unrequested"}

    def prepare(self, cfg, *, default_target):
        with self._lock:
            if not self._quiescent_locked():
                raise SessionHeld("A simulation session still owns its worker")
            original = (self._session_generation, self._prepared, self._plan_started)
        # Detach the requested mode with the request itself. Neither planning
        # nor a later metric projection changes the machine's response policy.
        frozen_cfg = json.loads(_json(cfg))
        containment_required = frozen_cfg.get("auto_remediate", True)
        if type(containment_required) is not bool:
            raise SessionHeld("The requested containment mode must be a boolean")
        plan = replace(prepare_session(frozen_cfg, data_root=self.data_root, default_target=default_target),
                       generation=original[0] + 1)
        performance, workflow_budgets = {}, {}
        for run in plan.runs:
            workflow_budgets[run.run_id] = _workflow_settlement_budget(run)
            eligible = (sum(bool(step.control_kinds) or step.operation == "exfiltration" for step in run.steps)
                        if run.kind == "shark" else json.loads(run.preflight_json)["budget"]["detection_contract_steps"])
            performance[run.run_id] = RunPerformanceSnapshot(plan.session_id, plan.generation,
                run.run_id, run.plan_sha256, "pending", eligible,
                containment_required=containment_required, unsettled_steps=eligible)
        with self._lock:
            if (not self._quiescent_locked() or self._session_generation != original[0]
                    or self._prepared is not original[1] or self._plan_started is not original[2]):
                raise SessionHeld("Simulation ownership changed while its plan was being prepared")
            self._prepared = plan
            self._plan_started = False
            self._cfg = frozen_cfg
            self._reports.clear()
            self._diagnostics.clear()
            self._performance_observations.clear()
            self._performance = performance
            self._workflow_budgets = workflow_budgets
            self._workflow_current_budget = None
            self._workflow_settlements.clear()
            self._workflow_producer_state = "unrequested"
            self._execution_completed = 0
            self._execution_current_finished = 0
            self._cache.update(completed_reports=0, execution_finished=0, settled_steps=0,
                               native_detections=0, contained_targets=0, reason_code="",
                               workflow_settlement_policy_seconds=None,
                               workflow_settlement_allowance_seconds=None,
                               workflow_settlement_basis="queued",
                               workflow_settlement_planned_contracts=None,
                               workflow_settlement_elapsed_seconds=0.0,
                               workflow_settlement_baseline_exceeded=False,
                               workflow_settlement_drained=None, workflow_settlement_warning="",
                               workflow_settlement_diagnostic_published=False,
                               workflow_producer_state="unrequested")
            self._cache.update(session_id=plan.session_id, session_generation=plan.generation,
                phase="queued", current_run_id="",
                queued_run_ids=tuple(run.run_id for run in plan.runs), planned_runs=len(plan.runs),
                execution_total=sum(len(run.steps) if run.kind == "shark" else
                    json.loads(run.preflight_json)["budget"]["projected_steps"] for run in plan.runs))
        return plan

    def _quiescent_locked(self):
        return (not any(worker.is_alive() for worker in (self.thread, self._engine_thread)
                        if worker is not None)
                and self._active_lease is None and not self._reservation_active
                and not self._retirement_held
                and (not self._plan_started or self.finished.is_set()))

    def start(self, plan):
        with self._lock:
            if (plan is not self._prepared or type(plan) is not SessionPlan
                    or self._plan_started
                    or plan.generation != self._session_generation + 1
                    or not 1 <= len(plan.runs) <= 2
                    or len({run.run_id for run in plan.runs}) != len(plan.runs)
                    or any(run.session_id != plan.session_id or not validate_prepared_run(run) for run in plan.runs)
                    or (self.thread is not None and self.thread.is_alive())):
                return False
            self._plan_started = True
            self._session_generation = plan.generation
            self.finished.clear()
        with _SESSION_OWNERS_LOCK:
            ref = _SESSION_OWNERS.get(self.manager)
            previous = ref() if ref is not None else None
            if previous is not None and (previous._reservation_active or previous._retirement_held
                    or previous._active_lease is not None or any(worker.is_alive()
                        for worker in (previous.thread, previous._engine_thread) if worker is not None)):
                self.finished.set()
                return False
            self._reservation_active = True
            _SESSION_OWNERS[self.manager] = weakref.ref(self)
        self.cancelled.clear()
        self.finished.clear()
        try:
            self.thread = threading.Thread(target=self._run, name="simulation-session", daemon=True)
            self.thread.start()
        except (OSError, RuntimeError):
            self._phase("held", reason_code="session-worker-launch-failed")
            with _SESSION_OWNERS_LOCK:
                self._reservation_active = False
            self.finished.set()
            return False
        return True

    def cancel(self):
        self.cancelled.set()
        with self._lock:
            engine = self._active_engine
        # The engines' existing cancellation Event is a stop hint; it does not
        # close storage, release custody or pretend their actual thread exited.
        event = getattr(engine, "_cancel", None)
        if type(event) is threading.Event:
            event.set()

    def owned_workers(self):
        with self._lock:
            return tuple(worker for worker in (self.thread, self._engine_thread)
                         if isinstance(worker, threading.Thread))

    def snapshot(self):
        with self._lock:
            return dict(self._cache)

    def retirement_snapshot(self):
        """Read existing custody flags only; callers still join actual workers.

        No I/O, native probe, lease release or authority decision is performed.
        An accepted-but-not-yet-published owner is pending, and an uncertain
        release remains held after its Thread has retired.
        """
        with self._lock:
            lease_active = self._active_lease is not None
            reservation_active = bool(self._reservation_active)
            retirement_held = bool(self._retirement_held)
            owner_pending = bool(self._plan_started and not self.finished.is_set())
            return {"schema": 1, "session_id": self._cache["session_id"],
                "session_generation": self._cache["session_generation"],
                "lease_active": lease_active, "reservation_active": reservation_active,
                "retirement_held": retirement_held, "owner_pending": owner_pending,
                "custody_released": not (lease_active or reservation_active or retirement_held or owner_pending),
                "response_authorized": False}

    def completed_reports(self):
        with self._lock:
            return tuple(self._reports)

    def performance_snapshot(self, run_id=None):
        """Return only immutable cached observations, never rescore on GUI ticks."""
        with self._lock:
            key = run_id if type(run_id) is str else self._cache["current_run_id"]
            if not key and self._prepared is not None:
                key = self._prepared.runs[0].run_id
            return self._performance.get(key)

    def _note_step_performance(self, binding, planned, state, native_complete):
        if (binding is not self._active_binding or planned not in binding._prepared.steps
                or not (planned.control_kinds or planned.operation == "exfiltration")):
            return
        prepared = binding._prepared
        key = (prepared.run_id, planned.planned_step_id)
        with self._lock:
            self._record_step_observation_locked(key, native=bool(native_complete),
                detected=bool(native_complete), contained=state == "verified",
                response_failed=state == "failed", unavailable=state == "unavailable",
                producer_generations=tuple(sorted((name, generation)
                    for name, (_module, generation) in binding._generations.items())),
                scanner_source_epoch=binding._enrollment.source_epoch)

    def _record_step_observation_locked(self, key, *, native=False, simulation=False,
                                        detected=False, contained=False, response_failed=False,
                                        unavailable=False, producer_generations=(),
                                        scanner_source_epoch=None):
        """Merge independent verified facts; this cache issues no proof/authority.

        One detection evaluation may precede its response settlement. Re-reading
        a genuine event or observing the later durable action never adds another
        step to the denominator. Unknown response leaves detection intact.
        """
        prior = self._performance_observations.get(key, (False,) * 6)
        row = (prior[0] or native, prior[1] or simulation, prior[2] or detected,
               prior[3] or contained, prior[4] or response_failed, prior[5] or unavailable)
        self._performance_observations[key] = row
        previous = self._performance[key[0]]
        rows = [value for (run_id, _identifier), value in self._performance_observations.items()
                if run_id == key[0]]
        evaluated = sum(value[2] for value in rows)
        unavailable_count = sum(value[5] and not value[2] for value in rows)
        gaps = sum(value[4] and not value[3] for value in rows) if previous.containment_required else 0
        self._performance[key[0]] = replace(previous,
            state="unverified" if any(value[5] for value in rows) else "provisional" if evaluated else "pending",
            evaluated_steps=evaluated, native_verified_steps=sum(value[0] for value in rows),
            simulation_verified_steps=sum(value[1] for value in rows),
            detection_verified_steps=evaluated, containment_verified_steps=sum(value[3] for value in rows),
            provisional_failures=gaps, unavailable_steps=unavailable_count,
            unsettled_steps=previous.eligible_planned - evaluated - unavailable_count,
            producer_generations=producer_generations,
            scanner_source_epoch=scanner_source_epoch or previous.scanner_source_epoch)

    def _redteam_performance_unavailable(self, observer):
        if observer is not self._active_redteam_observer:
            return
        observer._disabled = True
        with self._lock:
            previous = self._performance[observer.prepared.run_id]
            self._performance[observer.prepared.run_id] = replace(previous, state="unverified",
                unavailable_steps=previous.eligible_planned - previous.evaluated_steps,
                unsettled_steps=0)

    def _note_redteam_performance(self, observer, identifier, verdict, settled_negative):
        if (observer is not self._active_redteam_observer or observer._disabled
                or identifier not in observer.expected
                or observer.expected[identifier].get("category") != "detection"):
            return
        key = (observer.prepared.run_id, identifier)
        with self._lock:
            caught = verdict is not None and verdict.catch is not None
            self._record_step_observation_locked(key,
                native=bool(caught and verdict.native_catch is not None),
                simulation=bool(caught and verdict.simulation_validation is not None), detected=caught,
                contained=bool(caught and verdict.target_containment_verified),
                response_failed=bool(caught and settled_negative),
                producer_generations=tuple(sorted((name, generation)
                    for name, (_module, generation) in observer._generations.items())))

    def _drain_redteam_observations(self, *, final=False):
        observer = self._active_redteam_observer
        if observer is not None:
            try:
                observer.drain(final=final)
            except Exception:
                # Optional live attribution cannot interrupt the genuine engine
                # or weaken its final signed campaign-completeness gate.
                self._redteam_performance_unavailable(observer)

    def _note_report_performance(self, prepared, report):
        payload = json.loads(report.report_bytes)
        eligible = payload.get("coverage_score_eligible") is True and payload.get("diagnostic_only") is not True
        with self._lock:
            previous = self._performance[prepared.run_id]
            if not eligible:
                self._performance[prepared.run_id] = replace(previous, state="unverified",
                    finalized_misses=None, final_report_sha256=report.report_sha256)
                return
            actual = payload["epistemic_metrics"]["verified_containment"]
            taxonomy = payload["evidence_taxonomy"]
            native = taxonomy["native_analytic_detection"]["count"]
            simulation = taxonomy["simulation_contract_validation"]["count"]
            union = taxonomy["compatible_analytic_union"]["count"]
            if (type(actual["count"]) is not int or type(actual["eligible"]) is not int
                    or actual["eligible"] != previous.eligible_planned
                    or taxonomy["denominator"] != previous.eligible_planned
                    or any(type(value) is not int or not 0 <= value <= actual["eligible"]
                           for value in (actual["count"], native, simulation, union))
                    or not max(native, simulation, actual["count"]) <= union <= native + simulation):
                self._performance[prepared.run_id] = replace(previous, state="unverified")
                return
            self._performance[prepared.run_id] = replace(previous, state="final",
                evaluated_steps=actual["eligible"], containment_verified_steps=actual["count"],
                native_verified_steps=native, simulation_verified_steps=simulation,
                detection_verified_steps=union, provisional_failures=0, unsettled_steps=0, unavailable_steps=0,
                finalized_misses=actual["eligible"] - (actual["count"] if previous.containment_required else union),
                final_report_sha256=report.report_sha256)

    def launch_diagnostics(self):
        with self._lock:
            return tuple(self._diagnostics)

    def _phase(self, phase, **changes):
        with self._lock:
            self._cache["phase"] = phase
            for argument, key in (("settled_delta", "settled_steps"),
                                  ("native_delta", "native_detections"),
                                  ("contained_delta", "contained_targets")):
                self._cache[key] += changes.pop(argument, 0)
            self._cache.update(changes)

    def _check_graph(self):
        from angerona.core.eventbus import EventBus
        from angerona.core.module_manager import ModuleManager
        from angerona.core.storage import FlightRecorder
        from angerona.shark.shark_attack import SharkAttackEngine
        from angerona.shark.red_team import RedTeamEngine
        if (type(self.manager) is not ModuleManager or type(self.bus) is not EventBus
                or type(self.recorder) is not FlightRecorder
                or self.manager.bus is not self.bus or self.manager.recorder is not self.recorder
                or type(self.shark_engine) is not SharkAttackEngine
                or type(self.red_team_engine) is not RedTeamEngine
                or self.shark_engine.data_dir.resolve(strict=False) != self.data_root):
            raise SessionHeld("The exact simulation graph/root is unavailable")

    def _wait_for_owner_enrollment(self, lease, prepared):
        from angerona.modules.yara_scanner import YaraScannerModule, scan_roots
        detector = self.manager.modules.get("YARA Scanner")
        if type(detector) is not YaraScannerModule or Path(prepared.target) not in scan_roots():
            raise SessionHeld("The exact held target is outside the admitted native scan scope")
        deadline = min(self._run_deadline, time.monotonic() + _SETTLE_SECONDS)
        while not self.cancelled.is_set():
            enrollment = YaraScannerModule.control_enrollment(detector)
            if enrollment is not None and YaraScannerModule._control_enrollment_valid(detector, enrollment):
                return enrollment
            if time.monotonic() >= deadline:
                break
            self.cancelled.wait(0.1)
        raise SessionHeld("The native owner did not establish a current bounded enrollment")

    def workflow_settlement_snapshot(self, run_id=None):
        """Copy retained scheduling diagnostics; no report rescoring or I/O."""
        with self._lock:
            key = run_id if run_id is not None else self._cache['current_run_id']
            value = self._workflow_settlements.get(key)
            return dict(value) if value is not None else None

    def _record_workflow_settlement(self, budget, allowance, elapsed, drained, pending, outcome):
        exceeded = elapsed > _WORKFLOW_SETTLEMENT_FLOOR_SECONDS
        warning = ('Response settlement exceeded the 30 second workflow baseline; '
                   'evidence and authority deadlines were not extended.') if exceeded else ''
        record = {'run_id': budget.run_id, 'plan_sha256': budget.plan_sha256,
            'basis': budget.basis, 'planned_contracts': budget.planned_contracts,
            'policy_seconds': budget.seconds, 'allowance_seconds': allowance,
            'elapsed_seconds': elapsed, 'responses_drained': drained, 'pending': pending,
            'outcome': outcome, 'baseline_exceeded': exceeded, 'warning': warning,
            'response_authorized': False, 'diagnostic_published': False,
            'producer_observation_state': self._workflow_producer_state}
        # The warning is retained even if later reporting/custody reaches Completed.
        if exceeded:
            try:
                from angerona.core.eventbus import Event, EventBus, Severity
                if type(self.bus) is EventBus:
                    EventBus.publish(self.bus, Event('Simulation Session', warning,
                        Severity.MEDIUM, details={**{key: value for key, value in record.items()
                            if key != 'diagnostic_published'}, 'disposition': 'health',
                            'active_attack': False, 'diagnostic_only': True}))
                    record['diagnostic_published'] = True
            except Exception:
                pass  # Advisory publication cannot replace the actual drain outcome.
        with self._lock:
            self._workflow_settlements[budget.run_id] = record
            self._cache.update(workflow_settlement_policy_seconds=budget.seconds,
                workflow_settlement_allowance_seconds=allowance,
                workflow_settlement_basis=budget.basis,
                workflow_settlement_planned_contracts=budget.planned_contracts,
                workflow_settlement_elapsed_seconds=elapsed,
                workflow_settlement_baseline_exceeded=exceeded,
                workflow_settlement_drained=drained,
                workflow_settlement_warning=warning,
                workflow_settlement_diagnostic_published=record["diagnostic_published"])
        return drained

    def _begin_final_producer_observation(self, run_id):
        """Schedule the admitted producer's later cycle without minting proof."""
        from angerona.modules.purple_guard import PurpleGuard, RedTeamValidationLease

        producer = self.manager.modules.get("Purple Remediation Guard")
        lease = self._active_lease
        if (type(producer) is not PurpleGuard or type(lease) is not RedTeamValidationLease
                or not RedTeamValidationLease.authority_matches(
                    lease, manager=self.manager, bus=self.bus, recorder=self.recorder)):
            return None
        request = PurpleGuard.request_fresh_observation(producer, lease, run_id=run_id)
        return (producer, request, lease, run_id) if request is not None else None

    def _final_producer_observation_state(self, observation):
        from angerona.modules.purple_guard import PurpleGuard, RedTeamValidationLease

        if type(observation) is not tuple or len(observation) != 4:
            return "unavailable"
        producer, request, lease, run_id = observation
        if (type(producer) is not PurpleGuard or self._active_lease is not lease
                or self.manager.modules.get("Purple Remediation Guard") is not producer
                or not RedTeamValidationLease.authority_matches(
                    lease, manager=self.manager, bus=self.bus, recorder=self.recorder)):
            return "unavailable"
        return PurpleGuard.fresh_observation_state(producer, request, lease, run_id=run_id)

    def _settle_admitted_responses(self):
        from angerona.modules.adversary_combat import AdversaryCombat
        combat = self.manager.modules.get('Adversary Combat')
        combat_generation = getattr(combat, 'lifecycle_generation', None)

        def combat_scope_current():
            current_generation = getattr(combat, 'lifecycle_generation', None)
            return bool(type(combat) is AdversaryCombat
                and self.manager.modules.get('Adversary Combat') is combat
                and type(combat_generation) is int and combat_generation > 0
                and type(current_generation) is int and current_generation == combat_generation)

        budget = self._workflow_current_budget or _workflow_settlement_budget()
        started = time.monotonic()
        # Never renew the original admitted run expiry, including after STOP.
        deadline = min(self._run_deadline, started + budget.seconds)
        allowance = max(0.0, deadline - started)
        pending = None
        try:
            observation = self._begin_final_producer_observation(budget.run_id)
        except Exception:
            observation = None
        while True:
            if not combat_scope_current():
                return self._record_workflow_settlement(budget, allowance,
                    max(0.0, time.monotonic() - started), False, pending, 'unavailable')
            try:
                producer_state = self._final_producer_observation_state(observation)
            except Exception:
                producer_state = "unavailable"
            if producer_state not in {"pending", "complete", "unavailable"}:
                producer_state = "unavailable"
            self._workflow_producer_state = producer_state
            # Completion follows every inline producer publication. Only a
            # later Combat snapshot can account for the work those publications
            # admitted; an earlier empty-queue sample must never be reused.
            if not combat_scope_current():
                return self._record_workflow_settlement(budget, allowance,
                    max(0.0, time.monotonic() - started), False, pending, 'unavailable')
            snapshot = AdversaryCombat.response_snapshot(combat)
            if not combat_scope_current():
                # A blocking snapshot cannot transfer an old worker's empty
                # queue into a replacement generation's completion claim.
                return self._record_workflow_settlement(budget, allowance,
                    max(0.0, time.monotonic() - started), False, pending, 'unavailable')
            pending = snapshot.get('queue_pending')
            now = time.monotonic()
            elapsed = max(0.0, now - started)
            with self._lock:
                self._cache.update(workflow_settlement_elapsed_seconds=elapsed,
                    workflow_settlement_baseline_exceeded=(elapsed > _WORKFLOW_SETTLEMENT_FLOOR_SECONDS),
                    workflow_producer_state=producer_state)
            if type(pending) is not int or pending < 0:
                return self._record_workflow_settlement(budget, allowance,
                    elapsed, False, None, 'unavailable')
            if now > deadline or allowance <= 0:
                return self._record_workflow_settlement(budget, allowance,
                    elapsed, False, pending, 'expired')
            if pending == 0 and producer_state == "complete":
                if not combat_scope_current():
                    return self._record_workflow_settlement(budget, allowance,
                        elapsed, False, pending, 'unavailable')
                return self._record_workflow_settlement(budget, allowance,
                    elapsed, True, pending, 'drained')
            if pending == 0 and producer_state == "unavailable":
                return self._record_workflow_settlement(budget, allowance,
                    elapsed, False, pending, 'unavailable')
            # Cancellation closes probe creation; admitted effects still need
            # truthful terminal records and actual task_done, never a set-Event spin.
            self._drain_redteam_observations()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self._record_workflow_settlement(budget, allowance,
                    max(0.0, time.monotonic() - started), False, pending, 'expired')
            time.sleep(min(0.1, remaining))

    def _observe_engine_progress(self, engine, prepared):
        try:
            progress = type(engine).progress_snapshot(engine)
            done, total = progress.get("finished"), progress.get("total")
            task = progress.get("current_task")
            if (type(progress) is not dict or progress.get("schema") != 1
                    or progress.get("run_id") != prepared.run_id
                    or type(done) is not int or type(total) is not int or not 0 <= done <= total <= 256
                    or type(task) is not str):
                raise ValueError("progress source unavailable")
            self._execution_current_finished = done
            self._phase(self.snapshot()["phase"], execution_available=True,
                execution_finished=self._execution_completed + done, current_task=task[:200])
        except Exception:
            self._phase(self.snapshot()["phase"], execution_available=False,
                        current_task="Execution progress unavailable; previous counts retained")

    def _build_report(self, prepared):
        from angerona.shark import aar_report
        from angerona.modules.purple_guard import validate_redteam_recorder
        name = "shark_history.json" if prepared.kind == "shark" else "redteam_history.json"
        history = aar_report._load_history(self.data_root / name)
        validate_redteam_recorder(self.recorder, self.data_root, bus=self.bus)
        if prepared.kind == "shark" and not prepared_history_matches(history, prepared.manifest()):
            raise SessionHeld("The exact signed Shark history is not bound to the prepared plan")
        if history.get("run_id") != prepared.run_id:
            raise SessionHeld("The report history belongs to another run")
        if (prepared.kind == "shark" and history.get("status") == "completed"
                and self._active_binding is not None):
            self._active_binding.check_current()
        owns_report = self.thread is threading.current_thread()
        kwargs = dict(history_name=name, recorder=self.recorder, bus=self.bus,
            manager=self.manager, validation_lease=self._active_lease, return_result=True,
            report_basename="shark_aar" if prepared.kind == "shark" else "redteam_aar",
            return_failure_reason=True, wait_for_report_worker=owns_report)
        if prepared.kind == "red_team":
            from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY
            kwargs.update(stage_category=REDTEAM_STAGE_CATEGORY, title="RED TEAM ATTACK")
        result = aar_report.generate_aar(self.data_root, **kwargs)
        if (result is aar_report.AARFailureReason.JOURNAL_CHANGED and owns_report
                and not self.cancelled.is_set() and time.monotonic() < self._run_deadline):
            # No report was written. Reauthenticate a fresh history, recorder
            # window and complete journal snapshot through the same verifier.
            result = aar_report.generate_aar(self.data_root, **kwargs)
        if type(result) is aar_report.AARFailureReason:
            raise _ReportHeld(result)
        if type(result) is not aar_report.AARReportResult:
            raise _ReportHeld(aar_report.AARFailureReason.RESULT_UNAVAILABLE)
        if result.run_id != prepared.run_id:
            raise _ReportHeld(aar_report.AARFailureReason.RESULT_BINDING)
        aar_report.verified_aar_handoff_text(result)
        payload = json.loads(result.report_bytes)
        if (prepared.kind == "shark"
                and payload.get("campaign_completeness", {}).get("prepared_run") != prepared.manifest()):
            raise SessionHeld("The immutable report lost its prepared run binding")
        return result

    def _run(self):
        from angerona.modules import file_integrity, yara_scanner
        from angerona.modules.purple_guard import RedTeamValidationLease, acquire_redteam_validation_lease
        added_watches = []
        current = None
        try:
            self._check_graph()
            for current in self._prepared.runs:
                if self.cancelled.is_set():
                    break
                self._phase("preflight", current_run_id=current.run_id,
                    queued_run_ids=tuple(run.run_id for run in self._prepared.runs
                        if run is not current and self._prepared.runs.index(run) > self._prepared.runs.index(current)))
                budget = self._workflow_budgets.get(current.run_id)
                if (type(budget) is not _WorkflowSettlementBudget
                        or budget.run_id != current.run_id or budget.plan_sha256 != current.plan_sha256):
                    raise SessionHeld("The frozen workflow settlement allowance is unavailable")
                self._workflow_current_budget = budget
                self._workflow_producer_state = "unrequested"
                self._phase("preflight", workflow_settlement_policy_seconds=budget.seconds,
                    workflow_settlement_allowance_seconds=None, workflow_settlement_basis=budget.basis,
                    workflow_settlement_planned_contracts=budget.planned_contracts,
                    workflow_settlement_elapsed_seconds=0.0, workflow_settlement_drained=None,
                    workflow_settlement_baseline_exceeded=False, workflow_settlement_warning="",
                    workflow_producer_state="unrequested",
                    workflow_settlement_diagnostic_published=False)
                target = Path(current.target)
                target.mkdir(parents=True, exist_ok=True)
                for getter, register, unregister in (
                    (file_integrity.watch_roots, file_integrity.register_runtime_watch, file_integrity.unregister_runtime_watch),
                    (yara_scanner.scan_roots, yara_scanner.register_runtime_watch, yara_scanner.unregister_runtime_watch),
                ):
                    previous = {Path(root).resolve(strict=False) for root in getter()}
                    if target not in previous:
                        if not register(str(target)):
                            raise SessionHeld("A simulation watch could not be admitted")
                        added_watches.append((unregister, str(target)))
                lease = acquire_redteam_validation_lease(
                    self.manager, self.bus, self.recorder, self.data_root, target,
                    comprehensive=json.loads(current.preflight_json)["comprehensive"])
                self._active_lease = lease
                self._lease_release_attempted = False
                self._run_deadline = time.monotonic() + current.admitted_ttl_seconds
                engine = self.shark_engine if current.kind == "shark" else self.red_team_engine
                with self._lock:
                    self._active_engine = engine
                if current.kind == "shark":
                    readiness = RedTeamValidationLease.consume_for_run(lease, run_id=current.run_id,
                        target=target, data_root=self.data_root,
                        run_ttl_seconds=current.admitted_ttl_seconds)
                    enrollment = self._wait_for_owner_enrollment(lease, current)
                    binding = SharkRunSession(self, current, lease, engine, enrollment, readiness)
                    self._active_binding = binding
                    started = engine.start_prepared(current, validation_lease=lease, step_session=binding)
                else:
                    # Required owner seam: keeps the original engine preflight,
                    # exact lease consume and comprehensive mandatory-plan checks.
                    starter = getattr(engine, "start_prepared", None)
                    if not callable(starter):
                        raise SessionHeld("The Red Team prepared-start adapter is unavailable")
                    engine.hold_evidence_for_aar()
                    observer = RedTeamRunObserver(self, current, lease, engine)
                    self._active_redteam_observer = observer
                    started = starter(current, validation_lease=lease, intensity=self._cfg.get("intensity"),
                                      live_observer=observer)
                if not started or engine.run_id != current.run_id:
                    raise SessionHeld("The exact planned engine did not accept its run")
                with self._lock:
                    self._engine_thread = engine._thread
                worker = self._engine_thread
                if not isinstance(worker, threading.Thread):
                    raise SessionHeld("The actual engine owner thread is unavailable")
                self._phase("running")
                self._execution_current_finished = 0
                while worker.is_alive():
                    if self.cancelled.is_set() or time.monotonic() >= self._run_deadline:
                        engine._cancel.set()
                    if time.monotonic() >= self._run_deadline + 5:
                        raise SessionHeld("The exact engine worker has not retired")
                    self._observe_engine_progress(engine, current)
                    self._drain_redteam_observations()
                    worker.join(timeout=0.1)
                self._observe_engine_progress(engine, current)
                self._execution_completed += self._execution_current_finished
                self._phase("settling", execution_finished=self._execution_completed)
                self._phase("settling")
                responses_drained = self._settle_admitted_responses()
                self._drain_redteam_observations(final=True)
                self._phase("reporting")
                report = self._build_report(current)
                self._note_report_performance(current, report)
                with self._lock:
                    self._reports.append(report)
                    self._cache["completed_reports"] = len(self._reports)
                self._phase("releasing")
                if self._active_binding is not None:
                    self._active_binding.close_capture()
                if self._active_redteam_observer is not None:
                    self._active_redteam_observer.close()
                self._lease_release_attempted = True
                RedTeamValidationLease.release(lease)
                self._active_lease = None
                if self._active_binding is not None:
                    self._active_binding.cleanup_allowed = True
                if current.kind == "red_team":
                    engine.release_evidence_after_aar(engine.evidence_cleanup_scope())
                engine.stop_and_clean()
                self._active_binding = None
                self._active_redteam_observer = None
                if not responses_drained:
                    raise SessionHeld("The bounded response settlement remains incomplete")
            self._phase("cancelled" if self.cancelled.is_set() else "completed")
        except Exception as error:
            if self._active_lease is not None and self._lease_release_attempted:
                self._retirement_held = True
            run_id = current.run_id if current is not None else ""
            reason_code = error.reason.value if type(error) is _ReportHeld else type(error).__name__
            with self._lock:
                self._diagnostics.append(LaunchDiagnostic(
                    self._prepared.session_id, run_id, self._cache["phase"], reason_code,
                    str(error)[:1000]))
            self._phase("held", reason_code="simulation-session-needs-review")
        finally:
            if self._active_binding is not None:
                self._active_binding.close_capture()
            if self._active_redteam_observer is not None:
                self._active_redteam_observer.close()
            if self._active_lease is not None and not self._lease_release_attempted:
                try:
                    self._lease_release_attempted = True
                    RedTeamValidationLease.release(self._active_lease)
                    self._active_lease = None
                except Exception:
                    self._retirement_held = True
                    self._phase("held", reason_code="validation-lease-release-unverified")
            # Release only watches this sequential owner added. Exact producer
            # authority has already been revoked; unresolved files are retained.
            for unregister, target in reversed(added_watches):
                try:
                    unregister(target)
                except Exception:
                    self._retirement_held = True
                    self._phase("held", reason_code="watch-retirement-unverified")
            with _SESSION_OWNERS_LOCK:
                self._reservation_active = False
            self.finished.set()
