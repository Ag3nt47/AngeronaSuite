"""Observe-only bridge for structured identity/session evidence."""
from __future__ import annotations

from collections import deque
import copy
from pathlib import Path
import secrets
import threading
import time

from angerona.core.eventbus import Event, Severity
from angerona.core.identity_session import (
    IdentitySessionAnalytics,
    IdentitySessionAssessment,
    IdentitySessionError,
    IdentitySessionEvidence,
    TokenizedSessionEvent,
    derive_identity_session_key,
    evidence_from_mapping,
    load_identity_session_key,
)
from angerona.core.identity_collectors import BrowserExtensionCollector, WindowsSessionCollector
from angerona.core.module_base import BaseModule
from angerona.core.sensor_provenance import (
    SensorProvenanceBroker,
    SensorProvenanceError,
)


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


_SEVERITY = {
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
    "Critical": Severity.CRITICAL,
}
_IDENTITY_PRODUCERS = frozenset({"Structured Identity Producer"})
_BROKER_EVENT_TYPE = "angerona.identity-session-input.v1"


class IdentitySessionGuardModule(BaseModule):
    CODE = "IDSG"
    NAME = "Identity Session Guard"
    name = NAME
    description = (
        "Privacy-tokenized LUID, session, device-code, new-device, browser-store, "
        "RMM, and privilege-transition analytics; optional read-only Windows session "
        "events and untrusted browser-extension manifest inventory. No credentials or browser contents."
    )
    category = "Identity"
    version = "1.14.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Structured identity-session evidence from an authenticated producer",
        "Angerona bus.key for stable local privacy pseudonyms",
    )

    def __init__(
        self,
        *,
        data_root: str | Path | None = None,
        master_key: bytes | None = None,
        analytics: IdentitySessionAnalytics | None = None,
        provenance_broker: SensorProvenanceBroker | None = None,
        clock=time.time,
        interval_seconds: float = 10.0,
        session_collection_enabled: bool | None = None,
        browser_inventory_enabled: bool | None = None,
        session_source=None,
        browser_roots=None,
    ) -> None:
        super().__init__()
        if master_key is not None and (
            not isinstance(master_key, bytes) or len(master_key) != 32
        ):
            raise ValueError("identity-session key override must contain 32 bytes")
        self._data_root_override = Path(data_root) if data_root is not None else None
        self._data_root = self._data_root_override
        self._master_key = master_key
        self._analytics = analytics
        self._provenance_broker = provenance_broker
        self._clock = clock
        self._interval = max(1.0, min(60.0, float(interval_seconds)))
        self._active = threading.Event()
        self._analytics_lock = threading.RLock()
        self._queue_lock = threading.Lock()
        self._pending: deque[TokenizedSessionEvent] = deque(maxlen=256)
        self._pending_dropped = 0
        self._key_unavailable = False
        self._rejections = 0
        self._last_coverage_marker = ""
        self._collector_config = None
        self._session_collection_override = session_collection_enabled
        self._browser_inventory_override = browser_inventory_enabled
        self._session_source = session_source
        self._browser_roots = browser_roots
        self._session_collector: WindowsSessionCollector | None = None
        self._browser_collector: BrowserExtensionCollector | None = None
        self._collector_cache_lock = threading.Lock()
        self._collector_coverage = {
            "sessions": {"state": "disabled", "reason": "native session collection requires explicit opt-in"},
            "browser_extensions": {"state": "disabled", "reason": "manifest inventory requires explicit opt-in"},
            "external_idp": {"state": "unavailable", "reason": "no authenticated external IdP connector configured"},
        }
        self._browser_inventory: dict = {}
        self._next_browser_poll = 0.0
        self._last_collector_marker = ""

    def bind_manager(self, manager) -> None:
        self._collector_config = getattr(manager, "config", None)
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

    def _ensure_analytics(self) -> IdentitySessionAnalytics:
        if self._analytics is not None:
            return self._analytics
        key = load_identity_session_key(self._root(), master_key=self._master_key)
        if key is None:
            self._key_unavailable = True
            key = derive_identity_session_key(secrets.token_bytes(32))
        self._analytics = IdentitySessionAnalytics(key, clock=self._clock)
        if self._key_unavailable:
            self._analytics.mark_coverage(
                "blind", "stable privacy-key custody is unavailable"
            )
        return self._analytics

    @staticmethod
    def _details(**extra: object) -> dict[str, object]:
        details: dict[str, object] = {
            "response_authorized": False,
            "response_authority": "observe-only",
            "capability_mode": "observe",
            "collection_mode": "supplied-evidence-only",
            "secrets_collected": False,
            "raw_identity_retained": False,
            "actor_attribution": "none",
        }
        details.update(extra)
        return details

    def _collector_enabled(self, name: str) -> bool:
        override = (self._session_collection_override if name == "identity_session_collection_enabled"
                    else self._browser_inventory_override)
        return override is True if override is not None else getattr(self._collector_config, name, False) is True

    def coverage_snapshot(self) -> dict:
        """Small detached cache only; safe for GUI callers, no collection or key read."""
        with self._collector_cache_lock:
            snapshot = copy.deepcopy(self._collector_coverage)
        for key, setting in (("sessions", "identity_session_collection_enabled"),
                             ("browser_extensions", "browser_extension_inventory_enabled")):
            if not self._collector_enabled(setting):
                snapshot[key] = {"state": "disabled", "reason": "collector explicitly disabled"}
        snapshot["runtime"] = {"active": self._active.is_set() and not self._stop.is_set(),
                               "status": self._status, "response_authorized": False}
        return snapshot

    def browser_inventory_snapshot(self) -> dict:
        """Explicit bounded inventory copy; metadata is unverified, never response authority."""
        if not self._collector_enabled("browser_extension_inventory_enabled"):
            return {"state": "disabled", "rows": [], "response_authorized": False}
        with self._collector_cache_lock:
            return copy.deepcopy(self._browser_inventory)

    def _poll_collectors_once(self) -> None:
        """Worker-only producer path. Opt-outs create neither sources nor profile reads."""
        if self.stopping:
            return
        analytics = self._ensure_analytics()
        sessions_enabled = self._collector_enabled("identity_session_collection_enabled")
        browser_enabled = self._collector_enabled("browser_extension_inventory_enabled")
        if not sessions_enabled:
            if self._session_collector is not None:
                self._session_collector.close()
                self._session_collector = None
            sessions = {"state": "disabled", "reason": "native session collection requires explicit opt-in"}
        elif self._key_unavailable:
            sessions = {"state": "unavailable", "reason": "stable installation privacy key is unavailable"}
        else:
            if self._session_collector is None:
                self._session_collector = WindowsSessionCollector(
                    self._root(), analytics._key, analytics.tokenize,
                    source=self._session_source, clock=self._clock,
                )
            batch = self._session_collector.poll(cancelled=self.generation_stop_event().is_set)
            if self.stopping:
                return
            with self._analytics_lock:
                for row in batch.records:
                    self._publish(analytics.observe(row))
            sessions = batch.summary()
        if self.stopping:
            return
        if not browser_enabled:
            browser = {"state": "disabled", "reason": "manifest inventory requires explicit opt-in"}
            self._browser_collector = None
            self._next_browser_poll = 0.0
            with self._collector_cache_lock:
                self._browser_inventory = {}
        elif self._key_unavailable:
            browser = {"state": "unavailable", "reason": "stable installation privacy key is unavailable"}
        elif time.monotonic() >= self._next_browser_poll:
            if self._browser_collector is None:
                self._browser_collector = BrowserExtensionCollector(analytics._key, roots=self._browser_roots)
            inventory = self._browser_collector.collect(cancelled=self.generation_stop_event().is_set)
            self._next_browser_poll = time.monotonic() + 300.0
            browser = {key: value for key, value in inventory.items() if key != "rows"}
            with self._collector_cache_lock:
                self._browser_inventory = inventory
        else:
            with self._collector_cache_lock:
                browser = copy.deepcopy(self._collector_coverage["browser_extensions"])
        with self._collector_cache_lock:
            self._collector_coverage["sessions"] = sessions
            self._collector_coverage["browser_extensions"] = browser
        marker = repr((sessions.get("state"), sessions.get("reason"), browser.get("state"), browser.get("count")))
        if marker != self._last_collector_marker and (sessions_enabled or browser_enabled):
            self._last_collector_marker = marker
            self.emit(
                "Identity collector coverage updated; selected events and manifest inventory remain observe-only.",
                Severity.INFO,
                **self._details(
                    finding_code="identity_session.collector_coverage",
                    collection_mode="opt-in-local-metadata", coverage=self.coverage_snapshot(),
                    active_attack=False, disposition="observation",
                ),
            )
        if self._key_unavailable:
            self.set_health(35, "Stable privacy-key custody is unavailable.")
        elif sessions_enabled and sessions.get("state") in {"loss", "untrusted", "denied", "unavailable", "replay", "rejected"}:
            self.set_health(35, "Windows session evidence unavailable/incomplete; review collector coverage.")
        elif sessions_enabled or browser_enabled:
            self.set_health(80, "Selected local metadata observed; external IdP/browser activation coverage remains unknown.")

    def _publish(self, assessment: IdentitySessionAssessment) -> None:
        for finding in assessment.findings:
            self.emit(
                finding.reason,
                _SEVERITY.get(finding.severity, Severity.HIGH),
                **self._details(
                    finding_code=finding.rule_id,
                    identity_session_state=assessment.state,
                    principal_token=finding.principal_token,
                    session_token=finding.session_token,
                    device_token=finding.device_token,
                    evidence_count=finding.evidence_count,
                    evidence_grade=finding.evidence_grade,
                    collection_mode=("native-windows-security-event-log"
                                     if finding.evidence_grade == "native-os-event-log" else "supplied-evidence-only"),
                ),
            )
        if assessment.state not in {"missing", "blind", "overflow"}:
            return
        marker = repr((assessment.state, assessment.reason, assessment.dropped_events))
        if marker == self._last_coverage_marker:
            return
        self._last_coverage_marker = marker
        self.emit(
            "Identity/session evidence coverage is incomplete; no clean conclusion is available.",
            Severity.HIGH if assessment.state == "blind" else Severity.MEDIUM,
            **self._details(
                finding_code=f"identity_session.coverage.{assessment.state}",
                identity_session_state=assessment.state,
                coverage_reason=assessment.reason,
                retained_events=assessment.retained_events,
                dropped_events=assessment.dropped_events,
            ),
        )

    def observe_evidence(
        self,
        evidence: IdentitySessionEvidence,
        *,
        evidence_grade: str = "unprovenanced",
    ) -> IdentitySessionAssessment:
        analytics = self._ensure_analytics()
        with self._analytics_lock:
            assessment = analytics.observe(evidence, evidence_grade=evidence_grade)
            self._publish(assessment)
            return assessment

    def _on_bus_event(self, event: Event) -> None:
        if (
            not self._active.is_set()
            or self.stopping
            or event.module == self.name
        ):
            return
        details = event.details if isinstance(event.details, dict) else {}
        supplied = details.get("identity_session_evidence")
        envelope = details.get("sensor_provenance_envelope")
        provenance_grade = "schema-admitted-local"
        if envelope is not None:
            if self._provenance_broker is None:
                with self._analytics_lock:
                    self._publish(self._ensure_analytics().mark_coverage(
                        "blind", "sensor provenance broker is unavailable"
                    ))
                return
            try:
                accepted = self._provenance_broker.ingest(envelope)
            except SensorProvenanceError:
                with self._analytics_lock:
                    self._publish(self._ensure_analytics().mark_coverage(
                        "blind", "sensor provenance envelope was rejected"
                    ))
                return
            if (
                accepted.event_type != _BROKER_EVENT_TYPE
                or accepted.label not in _IDENTITY_PRODUCERS
                or accepted.coverage_state != "ready"
                or not isinstance(accepted.event, dict)
            ):
                with self._analytics_lock:
                    self._publish(self._ensure_analytics().mark_coverage(
                        "missing", "sensor provenance schema or continuity is invalid"
                    ))
                return
            supplied = dict(accepted.event)
            provenance_grade = "broker-provenanced"
        elif event.module not in _IDENTITY_PRODUCERS:
            return
        if not isinstance(supplied, dict):
            return
        analytics = self._ensure_analytics()
        storage_verified = (
            self._bus is None
            or not self._bus.integrity_enabled
            or self._bus.verify(event)
        )
        if not storage_verified:
            with self._analytics_lock:
                assessment = analytics.mark_coverage(
                    "blind", "supplying event failed EventBus authentication"
                )
                self._publish(assessment)
            return
        try:
            # Admission and tokenization happen synchronously; the raw mapping
            # is never queued or assigned to module state.
            evidence = evidence_from_mapping(supplied)
            tokenized = analytics.tokenize(
                evidence,
                evidence_grade=provenance_grade,
            )
            with self._queue_lock:
                if len(self._pending) >= self._pending.maxlen:
                    self._pending_dropped += 1
                    return
                self._pending.append(tokenized)
        except IdentitySessionError as exc:
            self._rejections += 1
            with self._analytics_lock:
                assessment = analytics.mark_coverage(
                    "missing", "structured identity/session evidence was rejected"
                )
                self._publish(assessment)
            self.emit(
                "Identity/session evidence failed the fixed admission schema.",
                Severity.MEDIUM,
                **self._details(
                    finding_code="identity_session.evidence_rejected",
                    rejection_type=type(exc).__name__,
                    rejected_evidence_count=self._rejections,
                    raw_evidence_omitted=True,
                ),
            )

    def _drain_pending(self) -> None:
        with self._queue_lock:
            rows = tuple(self._pending)
            self._pending.clear()
            dropped = self._pending_dropped
            self._pending_dropped = 0
        analytics = self._ensure_analytics()
        with self._analytics_lock:
            if dropped:
                self._publish(analytics.mark_coverage(
                    "overflow",
                    f"bounded identity/session ingress dropped {dropped} event(s)",
                ))
            for row in rows:
                self._publish(analytics.observe(row))

    def self_test(self) -> tuple[bool, str]:
        try:
            analytics = IdentitySessionAnalytics(
                derive_identity_session_key(b"I" * 32), clock=lambda: 1000.0
            )
            first = IdentitySessionEvidence(
                900.0,
                "device_code_flow",
                principal_ref="private-principal@example.invalid",
                source_ref="private-source",
                outcome="success",
            )
            second = IdentitySessionEvidence(
                910.0,
                "new_device",
                principal_ref="private-principal@example.invalid",
                device_ref="private-device",
                outcome="success",
            )
            analytics.observe(first, evidence_grade="broker-provenanced")
            result = analytics.observe(second, evidence_grade="broker-provenanced")
            if not any(
                item.rule_id == "identity_session.device_code_new_device"
                for item in result.findings
            ):
                return False, "device-code/new-device transition did not correlate"
            rendered = repr(analytics.retained_events)
            if any(raw in rendered for raw in (
                "private-principal", "private-source", "private-device"
            )):
                return False, "identity/session analytics retained raw identifiers"
            if any(item.response_authorized for item in result.findings):
                return False, "identity/session observe-only boundary failed"
        except Exception as exc:
            return False, f"identity/session bounded self-test failed: {exc}"
        return True, "supplied-only tokenization and bounded transition analytics verified"

    def run(self) -> None:
        analytics = self._ensure_analytics()
        self._active.set()
        if self._bus is not None:
            self._bus.subscribe(self._on_bus_event)
        if self._key_unavailable:
            self.set_health(35, "Identity/session analytics active with ephemeral privacy tokens.")
        else:
            self.set_health(70, "Awaiting structured identity/session evidence; no direct collection.")
        self.emit(
            "Identity Session Guard online; it consumes structured metadata and never token values.",
            Severity.INFO,
            **self._details(
                finding_code="identity_session.guard.online",
                identity_session_state=(
                    "blind" if self._key_unavailable else "awaiting-supplied-evidence"
                ),
                retained_events=len(analytics.retained_events),
            ),
        )
        try:
            while not self.stopping:
                self._drain_pending()
                self._poll_collectors_once()
                interval = min(self._interval, 2.0) if self._collector_enabled("identity_session_collection_enabled") else self._interval
                self.sleep(interval)
        finally:
            self._active.clear()
            if self._session_collector is not None:
                self._session_collector.close()
                self._session_collector = None


__all__ = ["IdentitySessionGuardModule"]
