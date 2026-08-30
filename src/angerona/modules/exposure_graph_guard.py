"""Native observe-only freshness and completeness guard for AegisPath."""
from __future__ import annotations

import time
import threading
from collections.abc import Callable

from angerona.core.eventbus import Severity
from angerona.core.exposure_graph import (
    Applicability,
    AssertionState,
    CoverageStatus,
    EdgeKind,
    EvidenceBinding,
    EvidenceFreshness,
    EvidenceProvenance,
    ExposureEdge,
    ExposureNode,
    ExposureSnapshot,
    NodeKind,
    PrivacyClass,
    ResourceStatus,
    build_coverage_manifest,
    build_exposure_snapshot,
    evidence_is_current_bound,
    evaluate_snapshot_coverage,
    verify_snapshot_digest,
)
from angerona.core.module_base import BaseModule


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")
POLL_INTERVAL_SECONDS = 60.0
DEFAULT_MAX_SNAPSHOT_AGE_SECONDS = 900.0
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 30.0
_PROVIDER_WAIT_SLICE_SECONDS = 0.05


def unavailable_snapshot_observer() -> ExposureSnapshot | None:
    return None


class ExposureGraphGuardModule(BaseModule):
    """Monitor graph evidence health without changing the host or graph."""

    CODE = "AEGP"
    NAME = "AegisPath Exposure Graph Guard"
    name = NAME
    description = (
        "Monitors immutable exposure-graph generations for invalid receipts, "
        "resource truncation, provider-attested semantic scope, stale or missing "
        "evidence, and collection age."
    )
    category = "Exposure Management"
    version = "1.13.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    maturity_channel = "stable"
    platform_requirements = (
        "A local immutable ExposureSnapshot provider",
        "Evidence sources that disclose freshness and collection generation",
    )
    capability_inputs = (
        "immutable-exposure-graph-snapshot",
        "evidence-provenance-freshness-and-generation",
    )
    capability_outputs = (
        "exposure-graph-coverage-health",
        "stale-or-missing-evidence-observation",
        "resource-limit-observation",
    )
    capability_permissions = ()
    high_risk_permissions = ()
    data_classes = (
        "content-addressed-graph-digest",
        "bounded-aggregate-evidence-health",
    )
    egress = "none"
    retention = "one-in-memory-state-token-and-provider-owned-immutable-snapshot"
    response_authority = "none"
    capability_dependencies = ()
    capability_conflicts = ()
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = "missing-stale-invalid-or-truncated-evidence-never-means-safe"
    settings_schema = {
        "type": "object",
        "properties": {
            "max_snapshot_age_seconds": {
                "type": "number",
                "minimum": 30,
                "maximum": 86400,
                "default": DEFAULT_MAX_SNAPSHOT_AGE_SECONDS,
            },
            "provider_timeout_seconds": {
                "type": "number",
                "minimum": 0.01,
                "maximum": DEFAULT_PROVIDER_TIMEOUT_SECONDS,
                "default": DEFAULT_PROVIDER_TIMEOUT_SECONDS,
            },
        },
        "additionalProperties": False,
    }
    resource_budget = {
        "worker_model": "single-lifecycle-thread-plus-one-bounded-in-flight-provider",
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "provider_call_timeout_required_seconds": 30.0,
        "throttle_min": 1.0,
        "throttle_max": 1.0,
    }

    def __init__(
        self,
        *,
        snapshot_observer: Callable[[], ExposureSnapshot | None] | None = None,
        max_snapshot_age_seconds: float = DEFAULT_MAX_SNAPSHOT_AGE_SECONDS,
        provider_timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__()
        if not callable(snapshot_observer or unavailable_snapshot_observer):
            raise ValueError("snapshot observer must be callable")
        if not callable(clock):
            raise ValueError("clock must be callable")
        age = float(max_snapshot_age_seconds)
        if not 30.0 <= age <= 86_400.0:
            raise ValueError("snapshot age threshold must be between 30 and 86,400 seconds")
        timeout = float(provider_timeout_seconds)
        if not 0.01 <= timeout <= DEFAULT_PROVIDER_TIMEOUT_SECONDS:
            raise ValueError("provider timeout must be between 0.01 and 30 seconds")
        self._snapshot_observer = snapshot_observer or unavailable_snapshot_observer
        self._max_snapshot_age = age
        self._provider_timeout = timeout
        self._clock = clock
        self._last_state = ""
        self._provider_lock = threading.Lock()
        self._provider_done = threading.Event()
        self._provider_thread: threading.Thread | None = None
        self._provider_result: object = None
        self._provider_error: Exception | None = None

    def _call_provider(self, observer: Callable[[], object]) -> None:
        result: object = None
        error: Exception | None = None
        try:
            result = observer()
        except Exception as exc:
            error = exc
        with self._provider_lock:
            self._provider_result = result
            self._provider_error = error
            self._provider_done.set()

    def observe_once(self) -> ExposureSnapshot | None:
        """Wait boundedly for at most one in-flight daemon provider call.

        Python cannot safely kill an arbitrary blocked callable. A timed-out
        provider is therefore quarantined as the sole in-flight call: later
        polls never accumulate helper threads, and module stop cancels the wait.
        """
        stop_event = self.generation_stop_event()
        if stop_event.is_set():
            raise InterruptedError("module stopping before provider observation")
        with self._provider_lock:
            thread = self._provider_thread
            if thread is None or not thread.is_alive():
                self._provider_result = None
                self._provider_error = None
                self._provider_done = threading.Event()
                thread = threading.Thread(
                    target=self._call_provider,
                    args=(self._snapshot_observer,),
                    name=f"{self.name}-provider",
                    daemon=True,
                )
                self._provider_thread = thread
                thread.start()
            done = self._provider_done
        deadline = time.monotonic() + self._provider_timeout
        while not done.wait(_PROVIDER_WAIT_SLICE_SECONDS):
            if stop_event.is_set():
                raise InterruptedError("module stopping during provider observation")
            if time.monotonic() >= deadline:
                raise TimeoutError("exposure graph provider exceeded bounded timeout")
        thread.join(timeout=_PROVIDER_WAIT_SLICE_SECONDS)
        with self._provider_lock:
            error = self._provider_error
            snapshot = self._provider_result
            if self._provider_thread is thread and not thread.is_alive():
                self._provider_thread = None
        if error is not None:
            raise error
        if snapshot is not None and not isinstance(snapshot, ExposureSnapshot):
            raise ValueError("exposure graph observer contract violation")
        return snapshot

    def _publish_health(self, *, now: float | None = None) -> dict[str, object]:
        current = float(self._clock() if now is None else now)
        try:
            snapshot = self.observe_once()
        except Exception as exc:
            snapshot = None
            observer_error = type(exc).__name__
        else:
            observer_error = ""
        if snapshot is None:
            state = f"unavailable:{observer_error or 'no-snapshot'}"
            health, severity = 20, Severity.HIGH
            note = "Exposure graph snapshot unavailable; reachability is unknown."
            details = {
                "snapshot_available": False,
                "snapshot_valid": False,
                "processing_complete": False,
                "semantic_coverage_verified": False,
                "coverage_complete": False,
                "coverage_reason": observer_error or "no-snapshot",
            }
        elif not verify_snapshot_digest(snapshot):
            state = f"invalid:{snapshot.generation}:{snapshot.digest}"
            health, severity = 15, Severity.CRITICAL
            note = "Exposure graph content receipt is invalid; analysis is not trusted."
            details = {
                "snapshot_available": True,
                "snapshot_valid": False,
                "processing_complete": False,
                "semantic_coverage_verified": False,
                "coverage_complete": False,
                "coverage_reason": "snapshot-digest-invalid",
                "generation": snapshot.generation,
            }
        else:
            coverage_status, coverage_reasons = evaluate_snapshot_coverage(
                snapshot, at_time=current
            )
            missing = sum(
                edge.evidence.freshness is EvidenceFreshness.MISSING
                for edge in snapshot.edges
            )
            unknown = sum(
                edge.evidence.freshness is EvidenceFreshness.UNKNOWN
                for edge in snapshot.edges
            )
            stale = sum(
                not evidence_is_current_bound(
                    edge.evidence,
                    at_time=current,
                    generation=snapshot.generation,
                )
                for edge in snapshot.edges
            )
            stale_threat = sum(
                node.threat_evidence is not None
                and (
                    not evidence_is_current_bound(
                        node.threat_evidence,
                        at_time=current,
                        generation=snapshot.generation,
                    )
                )
                for node in snapshot.nodes
            )
            age = max(0.0, current - snapshot.observed_at)
            incomplete = snapshot.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
            coverage_verified = coverage_status is CoverageStatus.VERIFIED
            aged = age > self._max_snapshot_age
            future_dated = snapshot.observed_at > current + 5.0
            state = (
                f"{snapshot.digest}:{incomplete}:{coverage_status.value}:{missing}:"
                f"{unknown}:{stale}:{stale_threat}:{aged}:{future_dated}"
            )
            if incomplete:
                health, severity = 35, Severity.HIGH
                note = "Exposure graph hit a resource bound; absent routes do not prove safety."
            elif coverage_status is CoverageStatus.UNUSABLE:
                health, severity = 25, Severity.HIGH
                note = "Exposure graph is unusable for scope analysis; no safety inference is valid."
            elif not coverage_verified:
                health, severity = 40, Severity.HIGH
                note = "Exposure graph processing completed, but declared semantic scope is unverified."
            elif missing:
                health, severity = 45, Severity.HIGH
                note = "Exposure graph contains relationships with missing evidence."
            elif stale or stale_threat or unknown or aged or future_dated:
                health, severity = 65, Severity.MEDIUM
                note = "Exposure graph freshness is incomplete; confirmed coverage is degraded."
            else:
                health, severity = 100, Severity.INFO
                note = (
                    "Exposure graph evidence is current and provider-attested for the exact "
                    "declared scope; provider authority remains a local trust boundary."
                )
            processing_complete = not incomplete
            coverage_complete = (
                processing_complete
                and coverage_verified
                and not (missing or stale or stale_threat or unknown or aged or future_dated)
            )
            details = {
                "snapshot_available": True,
                "snapshot_valid": True,
                "processing_complete": processing_complete,
                "semantic_coverage_verified": coverage_verified,
                "semantic_coverage_status": coverage_status.value,
                "semantic_coverage_reasons": coverage_reasons,
                "coverage_complete": coverage_complete,
                "coverage_reason": (
                    ",".join(snapshot.truncation_reasons)
                    if incomplete
                    else ",".join(coverage_reasons)
                    if not coverage_verified
                    else "evidence-freshness-gap"
                    if missing or stale or stale_threat or unknown or aged or future_dated
                    else "verified-current-declared-scope"
                ),
                "generation": snapshot.generation,
                "snapshot_digest": snapshot.digest,
                "policy_digest": snapshot.policy_digest,
                "snapshot_age_seconds": age,
                "snapshot_future_dated": future_dated,
                "edge_count": len(snapshot.edges),
                "missing_evidence_edges": missing,
                "unknown_evidence_edges": unknown,
                "stale_evidence_edges": stale,
                "stale_threat_signal_nodes": stale_threat,
                "dropped_nodes": snapshot.dropped_nodes,
                "dropped_edges": snapshot.dropped_edges,
                "resource_status": snapshot.status.value,
            }
        self.set_health(health, "" if health == 100 else note)
        if state != self._last_state:
            self._last_state = state
            self.emit(
                note,
                severity,
                schema="angerona.aegis-path.graph-health.v1",
                observation_only=True,
                enforcement_performed=False,
                response_authorized=False,
                response_authority="observe-only",
                raw_asset_names_omitted=True,
                **details,
            )
        return details

    def run(self) -> None:
        while not self.stopping:
            self._publish_health()
            self.sleep(POLL_INTERVAL_SECONDS)

    def self_test(self) -> tuple[bool, str]:
        evidence = EvidenceBinding(
            evidence_id="selftest-evidence",
            source="local-self-test",
            provenance=EvidenceProvenance.SENSOR,
            freshness=EvidenceFreshness.CURRENT,
            confidence=1.0,
            privacy=PrivacyClass.INTERNAL,
            generation=7,
            observed_at=1_900_000_000.0,
            expires_at=1_900_000_600.0,
            digest="sha256:" + "a" * 64,
        )
        nodes = (
            ExposureNode("entry", NodeKind.ENTRY_POINT, "Self-test entry"),
            ExposureNode("target", NodeKind.TARGET, "Self-test target", criticality=4),
        )
        edges = (
            ExposureEdge(
                "edge", "entry", "target", EdgeKind.REACHES,
                AssertionState.CONFIRMED, Applicability.EXACT, evidence,
                "Bounded self-test relationship",
            ),
        )
        manifest = build_coverage_manifest(
            nodes,
            edges,
            attested_at=1_900_000_000.0,
            expires_at=1_900_000_600.0,
        )
        snapshot = build_exposure_snapshot(
            nodes,
            edges,
            generation=7,
            observed_at=1_900_000_000.0,
            coverage_manifest=manifest,
        )
        original, original_clock = self._snapshot_observer, self._clock
        try:
            self._snapshot_observer = lambda: snapshot
            self._clock = lambda: 1_900_000_001.0
            details = self._publish_health()
        except Exception as exc:
            return False, f"exposure graph guard self-test failed: {type(exc).__name__}"
        finally:
            self._snapshot_observer, self._clock = original, original_clock
        if self.health != 100 or not details.get("coverage_complete"):
            return False, "current complete graph did not produce healthy observe-only state"
        return True, (
            "immutable digest, evidence generation/freshness, resource-limit, and "
            "observe-only health contract verified"
        )


def register() -> ExposureGraphGuardModule:
    return ExposureGraphGuardModule()


__all__ = [
    "ExposureGraphGuardModule",
    "register",
    "unavailable_snapshot_observer",
]
