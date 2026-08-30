"""Observe-only ordered campaign correlation across defensive sensors."""
from __future__ import annotations

from collections import deque
from pathlib import Path
import secrets
import tempfile
import threading
import time

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule
from angerona.core.sensor_provenance import (
    SensorProvenanceBroker,
    SensorProvenanceError,
)
from angerona.core.temporal_tradecraft import (
    TemporalAssessment,
    TemporalSignal,
    TemporalTradecraftEngine,
    TemporalTradecraftError,
    derive_temporal_keys,
    load_temporal_keys,
)


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


_SEVERITY = {
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
    "Critical": Severity.CRITICAL,
}
_BROKER_EVENT_TYPE = "angerona.temporal-input.v1"
_BROKER_EVENT_FIELDS = frozenset({"module", "message", "severity", "ts", "details"})
_BROKER_LABEL_MODULES = {
    "SSH Surface Key Tunnel Guard": "SSH Surface / Key / Tunnel Guard",
    "Zero Trust Network Path Monitor": "Zero-Trust Network Path Monitor",
    "Audit Log Integrity Guard": "Audit Log Integrity Guard",
}


class TemporalTradecraftCorrelatorModule(BaseModule):
    CODE = "TTCR"
    NAME = "Temporal Tradecraft Correlator"
    name = NAME
    description = (
        "Bounded, restart-aware ordered correlation for SSH persistence, sessions, "
        "tunnels, network-path drift, and audit-log clearing."
    )
    category = "Correlation"
    version = "1.13.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Angerona EventBus evidence",
        "Angerona bus.key for authenticated restart state",
    )

    def __init__(
        self,
        *,
        data_root: str | Path | None = None,
        master_key: bytes | None = None,
        engine: TemporalTradecraftEngine | None = None,
        provenance_broker: SensorProvenanceBroker | None = None,
        clock=time.time,
        interval_seconds: float = 5.0,
    ) -> None:
        super().__init__()
        if master_key is not None and (
            not isinstance(master_key, bytes) or len(master_key) != 32
        ):
            raise ValueError("temporal correlator key override must contain 32 bytes")
        self._data_root_override = Path(data_root) if data_root is not None else None
        self._data_root = self._data_root_override
        self._master_key = master_key
        self._engine = engine
        self._provenance_broker = provenance_broker
        self._clock = clock
        self._interval = max(1.0, min(60.0, float(interval_seconds)))
        self._active = threading.Event()
        self._state_lock = threading.RLock()
        self._queue_lock = threading.Lock()
        self._pending: deque[TemporalSignal] = deque(maxlen=256)
        self._pending_dropped = 0
        self._last_state_marker = ""
        self._key_unavailable = False

    def _admit_event(self, event: Event) -> tuple[Event, str]:
        """Return fixed-schema evidence and its producer-provenance grade."""
        details = event.details if isinstance(event.details, dict) else {}
        envelope = details.get("sensor_provenance_envelope")
        if envelope is None:
            return event, "schema-admitted-local"
        if self._provenance_broker is None:
            raise TemporalTradecraftError("sensor-provenance-broker-unavailable")
        try:
            accepted = self._provenance_broker.ingest(envelope)
        except SensorProvenanceError as exc:
            raise TemporalTradecraftError("sensor-provenance-rejected") from exc
        document = accepted.event
        if (
            accepted.event_type != _BROKER_EVENT_TYPE
            or accepted.coverage_state != "ready"
            or not isinstance(document, dict)
            or frozenset(document) != _BROKER_EVENT_FIELDS
            or not isinstance(document.get("module"), str)
            or not isinstance(document.get("message"), str)
            or type(document.get("severity")) is not int
            or not 0 <= document["severity"] <= int(Severity.CRITICAL)
            or not isinstance(document.get("ts"), (int, float))
            or isinstance(document.get("ts"), bool)
            or not isinstance(document.get("details"), dict)
            or _BROKER_LABEL_MODULES.get(accepted.label) != document.get("module")
        ):
            raise TemporalTradecraftError("sensor-provenance-schema-invalid")
        return (
            Event(
                document["module"],
                document["message"],
                Severity(document["severity"]),
                float(document["ts"]),
                dict(document["details"]),
            ),
            "broker-provenanced",
        )

    def bind_manager(self, manager) -> None:
        if self._data_root_override is None:
            config = getattr(manager, "config", None)
            value = getattr(config, "data_dir", None)
            if value is not None:
                self._data_root = Path(value)

    def _root(self) -> Path:
        if self._data_root is not None:
            return self._data_root
        from angerona.core.data_paths import data_dir

        self._data_root = data_dir()
        return self._data_root

    def _ensure_engine(self) -> TemporalTradecraftEngine:
        if self._engine is not None:
            return self._engine
        keys = load_temporal_keys(self._root(), master_key=self._master_key)
        if keys is None:
            # Continue observe-only correlation for the current process, but do
            # not pretend that an ephemeral key authenticates restart history.
            self._key_unavailable = True
            keys = derive_temporal_keys(secrets.token_bytes(32))
        self._engine = TemporalTradecraftEngine(
            self._root() / "shared_logs" / "temporal_tradecraft_state.json",
            state_key=keys[0],
            privacy_key=keys[1],
            persistence_enabled=not self._key_unavailable,
            clock=self._clock,
        )
        if self._key_unavailable:
            self._engine.mark_blind("temporal-key", reason="installation-key-unavailable")
        return self._engine

    @staticmethod
    def _details(**extra: object) -> dict[str, object]:
        base: dict[str, object] = {
            "response_authorized": False,
            "response_authority": "observe-only",
            "capability_mode": "observe",
            "raw_identity_retained": False,
            "actor_attribution": "none",
            "schema": "angerona.temporal-tradecraft.v1",
        }
        base.update(extra)
        return base

    def _publish_assessment(self, assessment: TemporalAssessment) -> None:
        if assessment.state == "blind":
            health = 20
        elif assessment.state == "overflow":
            health = 35
        elif assessment.state == "missing":
            health = 55
        else:
            health = 100
        if assessment.persistence_status in {"untrusted", "unavailable"}:
            health = min(health, 25 if assessment.persistence_status == "untrusted" else 35)
        elif assessment.persistence_status == "missing":
            health = min(health, 55)
        if self._key_unavailable:
            health = min(health, 35)
        note = (
            f"temporal state={assessment.state}; continuity={assessment.reason}; "
            f"persistence={assessment.persistence_status}; "
            f"retained={assessment.retained_signals}; dropped={assessment.dropped_signals}"
        )
        self.set_health(health, note)
        for finding in assessment.findings:
            self.emit(
                finding.summary,
                _SEVERITY.get(finding.severity, Severity.HIGH),
                **self._details(
                    finding_code=finding.pattern_id,
                    temporal_state=assessment.state,
                    signal_kinds=list(finding.signal_kinds),
                    evidence_digests=list(finding.evidence_digests),
                    evidence_grade=finding.evidence_grade,
                    started_at=finding.started_at,
                    ended_at=finding.ended_at,
                ),
            )
        marker = (
            assessment.state,
            assessment.reason,
            assessment.dropped_signals,
            assessment.persistence_status,
        )
        rendered = repr(marker)
        if rendered == self._last_state_marker:
            return
        self._last_state_marker = rendered
        if assessment.state not in {"missing", "blind", "overflow"}:
            return
        severity = Severity.HIGH if assessment.state == "blind" else Severity.MEDIUM
        self.emit(
            "Temporal correlation coverage is incomplete; absence of a match is not clean evidence.",
            severity,
            **self._details(
                finding_code=f"temporal.coverage.{assessment.state}",
                temporal_state=assessment.state,
                continuity_reason=assessment.reason,
                missing_steps=list(assessment.missing_steps),
                retained_signals=assessment.retained_signals,
                dropped_signals=assessment.dropped_signals,
                persistence_status=assessment.persistence_status,
            ),
        )

    def observe_event(self, event: Event) -> TemporalAssessment | None:
        """Admit one supplied bus event; never collect host evidence directly."""
        if event.module == self.name:
            return None
        engine = self._ensure_engine()
        storage_verified = (
            self._bus is None
            or not self._bus.integrity_enabled
            or self._bus.verify(event)
        )
        if not storage_verified:
            with self._state_lock:
                assessment = engine.mark_blind(
                    event.module, reason="event-authentication-failed"
                )
                self._publish_assessment(assessment)
                return assessment
        try:
            admitted, provenance_grade = self._admit_event(event)
        except TemporalTradecraftError as exc:
            with self._state_lock:
                assessment = engine.mark_blind(event.module, reason=str(exc))
                self._publish_assessment(assessment)
                return assessment
        details = admitted.details if isinstance(admitted.details, dict) else {}
        sensor_state = str(details.get("sensor_state") or "").casefold()
        quality = str(details.get("telemetry_quality") or "").casefold()
        with self._state_lock:
            if sensor_state in {"blind", "untrusted"} or quality == "untrusted":
                assessment = engine.mark_blind(
                    admitted.module, reason="upstream-sensor-untrusted"
                )
                self._publish_assessment(assessment)
                return assessment
            if sensor_state in {"gap", "missing"} or quality == "gap":
                assessment = engine.mark_missing("upstream-evidence-gap")
                self._publish_assessment(assessment)
                return assessment
            if sensor_state in {"authenticated", "available", "live", "recovered"}:
                engine.mark_recovered(admitted.module)
            if engine.classify(admitted) is None:
                return None
            assessment = engine.observe_event(
                admitted,
                integrity_verified=True,
                evidence_grade=provenance_grade,
            )
            self._publish_assessment(assessment)
            return assessment

    def _on_bus_event(self, event: Event) -> None:
        if not self._active.is_set() or self.stopping:
            return
        if event.module == self.name:
            return
        engine = self._ensure_engine()
        try:
            admitted, provenance_grade = self._admit_event(event)
        except TemporalTradecraftError:
            self.observe_event(event)
            return
        details = admitted.details if isinstance(admitted.details, dict) else {}
        sensor_state = str(details.get("sensor_state") or "").casefold()
        quality = str(details.get("telemetry_quality") or "").casefold()
        if (
            sensor_state in {"blind", "untrusted", "gap", "missing"}
            or quality in {"untrusted", "gap"}
            or sensor_state in {"authenticated", "available", "live", "recovered"}
        ):
            self.observe_event(event)
            return
        if engine.classify(admitted) is None:
            return
        storage_verified = (
            self._bus is None
            or not self._bus.integrity_enabled
            or self._bus.verify(event)
        )
        try:
            signal = engine.prepare_event(
                admitted,
                integrity_verified=storage_verified,
                evidence_grade=provenance_grade,
            )
        except TemporalTradecraftError:
            # Invalid evidence is rare and carries no queued raw payload. Let
            # the normal path publish the explicit missing/blind state.
            self.observe_event(event)
            return
        if signal is None:
            return
        with self._queue_lock:
            if len(self._pending) >= self._pending.maxlen:
                self._pending_dropped += 1
                return
            self._pending.append(signal)

    def _drain_pending(self) -> None:
        with self._queue_lock:
            rows = tuple(self._pending)
            self._pending.clear()
            dropped = self._pending_dropped
            self._pending_dropped = 0
        engine = self._ensure_engine()
        with self._state_lock:
            if dropped:
                self._publish_assessment(engine.mark_overflow(dropped))
            for row in rows:
                self._publish_assessment(engine.observe(row))

    def self_test(self) -> tuple[bool, str]:
        try:
            with tempfile.TemporaryDirectory(prefix="angerona-temporal-selftest-") as temp:
                state_key, privacy_key = derive_temporal_keys(b"T" * 32)
                engine = TemporalTradecraftEngine(
                    Path(temp) / "state.json",
                    state_key=state_key,
                    privacy_key=privacy_key,
                    clock=lambda: 1000.0,
                )
                rows = (
                    Event(
                        "SSH Surface / Key / Tunnel Guard",
                        "bounded",
                        Severity.HIGH,
                        900.0,
                        {"finding_code": "ssh.baseline.drift", "changes": {"keys_added": ["opaque"]}},
                        "signed-marker",
                    ),
                    Event(
                        "SSH Surface / Key / Tunnel Guard",
                        "bounded",
                        Severity.HIGH,
                        910.0,
                        {"finding_code": "ssh.logs.successful_key_auth"},
                        "signed-marker",
                    ),
                    Event(
                        "SSH Surface / Key / Tunnel Guard",
                        "bounded",
                        Severity.HIGH,
                        920.0,
                        {"finding_code": "ssh.runtime.client_forwarding_process"},
                        "signed-marker",
                    ),
                )
                result = None
                for row in rows:
                    result = engine.observe_event(row, integrity_verified=True)
                if result is None or not any(
                    item.pattern_id == "temporal.ssh_key_session_tunnel"
                    for item in result.findings
                ):
                    return False, "ordered temporal automaton did not complete"
                if any(item.response_authorized for item in result.findings):
                    return False, "observe-only temporal boundary failed"
                serialized = repr(engine.retained_signals)
                if "opaque" in serialized:
                    return False, "temporal evidence retained supplied detail values"
        except Exception as exc:
            return False, f"temporal correlator bounded self-test failed: {exc}"
        return True, "authenticated bounded automaton and observe-only output verified"

    def run(self) -> None:
        engine = self._ensure_engine()
        assessment = engine.note_restart_gap()
        self.set_health(
            35 if self._key_unavailable else 70,
            (
                "Temporal correlation active without authenticated restart custody."
                if self._key_unavailable
                else "Temporal correlation active; restart gap remains explicit for one window."
            ),
        )
        self._active.set()
        if self._bus is not None:
            self._bus.subscribe(self._on_bus_event)
        self.emit(
            "Temporal Tradecraft Correlator online in bounded observe-only mode.",
            Severity.INFO,
            **self._details(
                finding_code="temporal.correlator.online",
                temporal_state=assessment.state,
                persistence_status=assessment.persistence_status,
            ),
        )
        self._publish_assessment(assessment)
        try:
            while not self.stopping:
                self._drain_pending()
                self.sleep(self._interval)
                if not self.stopping:
                    with self._state_lock:
                        self._publish_assessment(engine.tick())
        finally:
            self._active.clear()


__all__ = ["TemporalTradecraftCorrelatorModule"]
