"""Bounded, advisory readiness from live objects and reconciled test evidence.

Declarations are not runtime proof. Collection means a reviewed sensor loop has
completed current-generation work, with fresh, healthy, loss-free coverage. A
practice test proves only its inert marker/process scope, never the real exploit
or every technique a detector declares. This cache grants no response authority.
It performs no filesystem, network, process enumeration, or source hashing.
"""
from __future__ import annotations

import math
import re
import sys
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


SCHEMA = "angerona.verified-readiness.v1"
DETECTION_TTL_SECONDS = 24 * 60 * 60
RESPONSE_TTL_SECONDS = 60 * 60
_MAX_HISTORY = 64
_MAX_PENDING = 32
_MAX_TEST_SECONDS = 300.0
_CLOCK_TOLERANCE_SECONDS = 5.0
_TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_COLLECTORS = {
    "angerona.modules.process_monitor.ProcessMonitorModule",
    "angerona.modules.network_monitor.NetworkMonitorModule",
    "angerona.modules.persistence_sweep.PersistenceSweepModule",
    "angerona.modules.file_integrity.FileIntegrityModule",
    "angerona.modules.purple_guard.PurpleGuard",
    "angerona.modules.soar_engine.ActiveResponseSOAR",
    "angerona.modules.api_patch_detector.ApiPatchDetectorModule",
    "angerona.modules.amsi_bridge.AMSIBridgeModule",
}
_PRACTICE_DETECTOR = "angerona.modules.purple_guard.PurpleGuard"
_PRACTICE_RESPONDER = "angerona.modules.soar_engine.ActiveResponseSOAR"
_PRACTICE_CHECKS = frozenset({
    "positive_control_detected", "negative_control_quiet", "recorder_persisted",
    "response_succeeded", "postcondition_satisfied", "detector_event_persisted",
    "response_event_persisted",
})
_BUS_SERVICES: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_BUS_LOCK = threading.Lock()


def _utc(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="seconds")


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


@dataclass(frozen=True)
class _Registration:
    module: weakref.ReferenceType
    name: str
    identity: str
    cls: type
    epoch: object


@dataclass(frozen=True, eq=False)
class _PracticeTicket:
    technique: str
    run_id: str
    detector: _Registration
    responder: _Registration
    detector_generation: int
    responder_generation: int
    wall: float
    mono: float


@dataclass(frozen=True)
class _Evidence:
    technique: str
    kind: str
    source: str
    generation: int
    responder: str
    responder_generation: int
    evidence_id: str
    wall: float
    mono: float
    expires_wall: float
    expires_mono: float
    scope: str
    outcome: str
    reason: str
    source_epoch: object = None
    responder_epoch: object = None
    source_identity: str = ""


class VerifiedReadiness:
    """One manager's in-memory presentation cache; no worker or poller added.

    Snapshot reads only bounded cached scalar lifecycle/cycle fields, never
    overridable module methods, manager control locks, or host collectors. A
    stop token or registry/generation replacement withdraws readiness at once.
    """

    def __init__(self, manager, *, wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._manager = weakref.ref(manager)
        self._wall = wall_clock
        self._mono = monotonic
        self._lock = threading.Lock()
        self._registrations: dict[str, _Registration] = {}
        self._history: deque[_Evidence] = deque(maxlen=_MAX_HISTORY)
        self._pending: dict[int, _PracticeTicket] = {}
        self._clock_invalid_before = float("-inf")
        self._last_clock: tuple[float, float] | None = None
        if manager.bus is not None:
            with _BUS_LOCK:
                _BUS_SERVICES[manager.bus] = weakref.ref(self)

    def register(self, module: object) -> None:
        """Called only after normal built-in discovery/trust registration."""
        cls = type(module)
        loaded = sys.modules.get(cls.__module__)
        manager = self._manager()
        name = str(vars(module).get("name", getattr(cls, "name", "")))
        if (manager is None or manager.modules.get(name) is not module
                or getattr(loaded, cls.__name__, None) is not cls
                or vars(module).get("_angerona_origin") != "builtin"
                or manager.module_trust.get(name, {}).get("origin") != "builtin"):
            return
        registration = _Registration(weakref.ref(module), name,
                                     f"{cls.__module__}.{cls.__name__}", cls, object())
        with self._lock:
            if name not in self._registrations and len(self._registrations) >= 256:
                return
            self._registrations[name] = registration

    def _clock(self) -> tuple[float, float]:
        with self._lock:
            # Read under this short cache lock: two callers that read clocks
            # before locking can enter out of order and mimic a clock rollback.
            wall, mono = float(self._wall()), float(self._mono())
            if (not math.isfinite(wall) or not math.isfinite(mono)
                    or not 0 <= wall < 253_402_214_400 or mono < 0):
                raise ValueError("readiness clock unavailable")
            previous = self._last_clock
            if previous is not None and (
                mono < previous[1] or abs((wall - previous[0]) - (mono - previous[1]))
                > _CLOCK_TOLERANCE_SECONDS
            ):
                # A rollback must never lower the invalidation boundary: old
                # proof cannot revive when clocks advance through its former
                # timestamp again. New proof remains held until that prior
                # high-water is passed, rather than inventing trustworthy age.
                self._clock_invalid_before = max(self._clock_invalid_before, previous[1], mono)
                self._pending.clear()
            self._last_clock = (wall, mono)
        return wall, mono

    def _current(self, entry: _Registration, mono: float) -> dict:
        manager, module = self._manager(), entry.module()
        result = {"source": entry.name, "identity": entry.identity, "collecting": False,
                  "generation": 0, "reason": "registered sensor unavailable"}
        if (manager is None or module is None or type(module) is not entry.cls
                or manager.modules.get(entry.name) is not module):
            return result
        state = vars(module)
        generation = state.get("_lifecycle_generation", 0)
        result["generation"] = generation
        stop, thread = state.get("_stop"), state.get("_thread")
        if (getattr(manager, "_shutdown", False) or getattr(manager, "_ugcap_paused", False)
                or state.get("_status") != "running" or stop is None or stop.is_set()
                or thread is None or not thread.is_alive()):
            result["reason"] = "sensor stopped, held, unavailable, or worker exited"
            return result
        if entry.identity not in _COLLECTORS:
            result["reason"] = "no reviewed collection contract; declaration only"
            return result
        health = _number(state.get("health"))
        completed = _number(state.get("_last_cycle_completed_at"))
        started = _number(state.get("_generation_started_at"))
        cadence = _number(state.get("_last_sleep_interval_seconds"))
        count = _number(state.get("_cycle_count"))
        overflow = _number(state.get("_bus_overflow_count"))
        first = state.get("_first_cycle_complete")
        if health is None or health < 90:
            result["reason"] = "coverage degraded: " + str(state.get("health_note", "unknown"))[:240]
        elif overflow is None or overflow != 0:
            result["reason"] = "evidence continuity lost or unknown"
        elif (completed is None or started is None or cadence is None or count is None
              or cadence < 0 or started <= 0 or completed < started or completed > mono
              or count < 1 or first is None or not first.is_set()):
            result["reason"] = "no completed current-generation sensor work"
        elif mono - completed > max(30.0, min(3600.0, cadence * 3.0 + 5.0)):
            result["reason"] = "sensor work expired"
        elif state.get("_lifecycle_generation") != generation or stop.is_set():
            result["reason"] = "sensor generation changed during snapshot"
        else:
            result.update(collecting=True, reason="fresh completed sensor work; no known loss",
                          age_seconds=round(mono - completed, 3))
        return result

    def observe_assurance(self, producer: object, observation: object) -> None:
        """Broker-only successful-validation observer; never consumes a receipt.

        A clean API/file/AMSI observation proves the narrow sensor leg only. It
        cannot earn technique detection-test or response credit.
        """
        from angerona.core.assurance_receipts import ValidatedDetectorObservation
        if type(observation) is not ValidatedDetectorObservation:
            return
        manager = self._manager()
        broker = getattr(manager, "assurance_receipt_broker", None)
        if broker is None or not broker._consume_notification(producer, observation):
            return
        wall, mono = self._clock()
        with self._lock:
            entry = self._registrations.get(observation.module_name)
        if (entry is None or entry.module() is not producer
                or observation.generation != vars(producer).get("_lifecycle_generation")
                or not wall - 90 <= observation.observed_at <= wall
                or not self._current(entry, mono)["collecting"]):
            return
        evidence = _Evidence("", "sensor-observation", entry.name, observation.generation,
                             "", 0, observation.probe_id, wall, mono, wall + 300, mono + 300,
                             observation.observation, "verified", "sensor leg only; no technique test credit",
                             source_epoch=entry.epoch, source_identity=entry.identity)
        with self._lock:
            self._history.append(evidence)

    def _begin_practice(self, detector, responder, technique: str, run_id: str):
        if (not isinstance(technique, str) or _TECHNIQUE.fullmatch(technique) is None
                or not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None):
            return None
        wall, mono = self._clock()
        with self._lock:
            d = next((v for v in self._registrations.values() if v.module() is detector), None)
            r = next((v for v in self._registrations.values() if v.module() is responder), None)
            self._pending = {key: value for key, value in self._pending.items()
                             if 0 <= mono - value.mono <= _MAX_TEST_SECONDS}
            if (d is None or r is None or d.identity != _PRACTICE_DETECTOR
                    or r.identity != _PRACTICE_RESPONDER or len(self._pending) >= _MAX_PENDING):
                return None
            ticket = _PracticeTicket(technique, run_id, d, r,
                                     vars(detector).get("_lifecycle_generation", 0),
                                     vars(responder).get("_lifecycle_generation", 0), wall, mono)
            self._pending[id(ticket)] = ticket
            return ticket

    def _finish_practice(self, ticket, *, bus, detection=None, response=None,
                         checks=None, receipt_id: str = "", failure: str = "") -> None:
        """Private verifier seam after real durable/postcondition reconciliation."""
        if type(ticket) is not _PracticeTicket:
            return
        wall, mono = self._clock()
        with self._lock:
            if self._pending.pop(id(ticket), None) is not ticket:
                return
        manager = self._manager()
        if (manager is None or bus is not manager.bus or not bus.integrity_enabled
                or not 0 <= mono - ticket.mono <= _MAX_TEST_SECONDS
                or not 0 <= wall - ticket.wall <= _MAX_TEST_SECONDS
                or ticket.mono <= self._clock_invalid_before):
            return
        d, r = self._current(ticket.detector, mono), self._current(ticket.responder, mono)
        if (d["generation"] != ticket.detector_generation
                or r["generation"] != ticket.responder_generation):
            return
        checks = checks if isinstance(checks, dict) else {}
        detection_time = _number(getattr(detection, "ts", None))
        response_time = _number(getattr(response, "ts", None))
        trigger_time = _number((getattr(response, "details", None) or {}).get("trigger_ts"))
        detected = bool(
            d["collecting"] and detection is not None and bus.verify(detection)
            and all(checks.get(key) is True for key in (
                "positive_control_detected", "negative_control_quiet", "detector_event_persisted"))
            and detection.module == ticket.detector.name
            and (detection.details or {}).get("practice_verification_id") == ticket.run_id
            and (detection.details or {}).get("mitre") == ticket.technique
            and detection_time is not None and ticket.wall <= detection_time <= wall
        )
        responded = bool(
            detected and not failure and r["collecting"] and response is not None
            and bus.verify(response) and response.module == ticket.responder.name
            and all(checks.get(key) is True for key in _PRACTICE_CHECKS)
            and response_time is not None and ticket.wall <= response_time <= wall
            and trigger_time is not None and detection_time is not None
            and abs(trigger_time - detection_time) < 0.000001
            and (response.details or {}).get("mitigated") is True
            and isinstance(receipt_id, str) and receipt_id.startswith("DRILL-VERIFY-")
        )
        evidence = _Evidence(
            ticket.technique, "practice", ticket.detector.name, ticket.detector_generation,
            ticket.responder.name, ticket.responder_generation, receipt_id[:100] or ticket.run_id,
            wall, mono, wall + DETECTION_TTL_SECONDS, mono + DETECTION_TTL_SECONDS,
            "inert practice marker/process only; no exploit or general action coverage",
            "response-verified" if responded else "detection-tested" if detected else "failed",
            "positive + negative controls, authenticated durable events, response postcondition"
            if responded else str(failure or "response verification requirements failed")[:240],
            source_epoch=ticket.detector.epoch, responder_epoch=ticket.responder.epoch,
            source_identity=ticket.detector.identity,
        )
        with self._lock:
            self._history.append(evidence)

    def snapshot(self, techniques) -> dict:
        try:
            wall, mono = self._clock()
        except (TypeError, ValueError, OverflowError):
            return {"schema": SCHEMA, "available": False, "reason": "readiness clock unavailable",
                    "techniques": [], "history": []}
        with self._lock:
            entries, history = dict(self._registrations), tuple(self._history)
            invalid_before = self._clock_invalid_before
        states = {name: self._current(entry, mono) for name, entry in entries.items()}
        rows = []
        for technique in techniques:
            evidence = next((e for e in reversed(history)
                             if e.kind == "practice" and e.technique == technique.tid), None)
            sources = list(technique.detect)
            if evidence is not None and evidence.source not in sources:
                sources.append(evidence.source)
            sensor_rows = [states.get(name, {"source": name, "collecting": False,
                                            "reason": "sensor not registered"}) for name in sources]
            collecting = any(row["collecting"] for row in sensor_rows)
            stage = "collecting" if collecting else "declared"
            gaps = [f"{row['source']}: {row['reason']}" for row in sensor_rows if not row["collecting"]]
            if not sources:
                gaps.append("no detector declared or verified")
            if evidence is not None:
                source = states.get(evidence.source, {})
                responder = states.get(evidence.responder, {})
                valid = (evidence.outcome in {"detection-tested", "response-verified"}
                         and evidence.mono > invalid_before
                         and 0 <= mono - evidence.mono and evidence.wall <= wall
                         and mono < evidence.expires_mono and wall < evidence.expires_wall
                         and source.get("collecting") and source.get("generation") == evidence.generation
                         and entries.get(evidence.source) is not None
                         and entries[evidence.source].epoch is evidence.source_epoch)
                if valid:
                    stage = "detection-tested"
                    if (evidence.outcome == "response-verified"
                            and mono - evidence.mono < RESPONSE_TTL_SECONDS
                            and wall - evidence.wall < RESPONSE_TTL_SECONDS
                            and responder.get("collecting")
                            and responder.get("generation") == evidence.responder_generation
                            and entries.get(evidence.responder) is not None
                            and entries[evidence.responder].epoch is evidence.responder_epoch):
                        stage = "response-verified"
                    else:
                        gaps.append("response proof expired or responder stopped/replaced")
                else:
                    gaps.append("test failed, expired, clock-invalid, or source stopped/replaced")
            else:
                gaps.append("no authenticated technique-specific positive/negative test")
            rows.append({"tid": technique.tid, "stage": stage, "collecting": collecting,
                         "sources": sensor_rows, "gaps": gaps,
                         "evidence": self._evidence_dict(evidence, wall, mono, invalid_before)
                         if evidence else None})
        return {"schema": SCHEMA, "available": True, "generated_at": _utc(wall),
                "policy": {"collection_min_health": 90, "collection_requires_no_known_loss": True,
                           "collection_max_age_seconds": "max(30, min(3600, 3 * cadence + 5))",
                           "detection_ttl_seconds": DETECTION_TTL_SECONDS,
                           "response_ttl_seconds": RESPONSE_TTL_SECONDS,
                           "clock_tolerance_seconds": _CLOCK_TOLERANCE_SECONDS,
                           "scope": "advisory; current sensor work and narrowly scoped practice proofs"},
                "techniques": rows, "history": [self._evidence_dict(e, wall, mono, invalid_before)
                                                 for e in reversed(history)]}

    @staticmethod
    def _evidence_dict(e: _Evidence, wall: float, mono: float, invalid_before: float) -> dict:
        return {"technique": e.technique, "kind": e.kind, "source": e.source,
                "source_identity": e.source_identity,
                "generation": e.generation, "responder": e.responder,
                "responder_generation": e.responder_generation, "evidence_id": e.evidence_id,
                "observed_at": _utc(e.wall), "expires_at": _utc(e.expires_wall),
                "response_expires_at": _utc(e.wall + RESPONSE_TTL_SECONDS) if e.kind == "practice" else None,
                "scope": e.scope, "outcome": e.outcome, "reason": e.reason,
                "fresh": bool(e.mono > invalid_before and 0 <= mono - e.mono
                              and e.wall <= wall < e.expires_wall and mono < e.expires_mono)}


def _practice_service(bus):
    """Private lookup for the installed practice verifier, never an UI issuer."""
    if bus is None:
        return None
    with _BUS_LOCK:
        reference = _BUS_SERVICES.get(bus)
    return reference() if reference is not None else None
