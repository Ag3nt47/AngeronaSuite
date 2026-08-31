"""Digest-bound active and alert-inert shadow execution for DetectionForge.

Active and shadow work use physically separate bounded queues.  Shadow floods
therefore cannot evict active work, while every shadow drop remains visible in
the local runtime snapshot.  Shadow evaluation has no publisher, evidence,
incident, SOAR, or response callback by construction.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping, Sequence

from angerona.core.detection_packages import (
    DetectionPackage,
    package_digest,
    validate_package,
)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule

MAX_RUNTIME_EVENT_BYTES = 256 * 1024
MAX_RUNTIME_RULES = 128
MAX_DEDUPE_KEYS = 8192
MAX_SHADOW_OBSERVATIONS = 512
MAX_SHADOW_EVALUATIONS_PER_PROCESS = 256
MAX_SHADOW_SLICE_MS = 25.0
_SEVERITIES = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class DetectionRuntimeError(RuntimeError):
    """A runtime rule or event cannot be admitted safely."""


def _safe_value(value: object, *, depth: int = 0) -> object:
    if depth > 5:
        raise DetectionRuntimeError("runtime event exceeds its nesting depth")
    if value is None or type(value) in (bool, int, str):
        if isinstance(value, str) and len(value) > 8192:
            return value[:8192]
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DetectionRuntimeError("runtime event contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise DetectionRuntimeError("runtime event contains an oversized object")
        result: dict[str, object] = {}
        for key, item in value.items():
            rendered = str(key)
            if not rendered or len(rendered) > 160 or "\x00" in rendered:
                raise DetectionRuntimeError("runtime event contains an unsafe field name")
            result[rendered] = _safe_value(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise DetectionRuntimeError("runtime event contains an oversized list")
        return [_safe_value(item, depth=depth + 1) for item in value]
    raise DetectionRuntimeError("runtime event contains an unsupported value type")


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise DetectionRuntimeError("runtime event is not strict JSON") from exc


@dataclass(frozen=True)
class RuntimeFinding:
    event_id: str
    package_id: str
    package_digest: str
    severity: Severity
    message: str
    elapsed_ms: float
    budget_exceeded: bool

    def event_details(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "rule_id": self.package_id,
            "rule_digest": self.package_digest,
            "evaluation_elapsed_ms": round(self.elapsed_ms, 6),
            "evaluation_budget_exceeded": self.budget_exceeded,
            "detection_runtime_generated": True,
            "nonrecursive": True,
            "active_detection": True,
            "shadow_mode": False,
            "response_authorized": False,
            "response_authority": "observe-only",
            "response_actions": [],
            "incident_authorized": False,
            "soar_authorized": False,
            "egress": "none",
        }


@dataclass(frozen=True)
class ShadowObservation:
    event_id: str
    package_id: str
    package_digest: str
    matched: bool
    disposition: str
    elapsed_ms: float


@dataclass(frozen=True)
class DetectionRuntimeSnapshot:
    active_digests: tuple[str, ...]
    shadow_digests: tuple[str, ...]
    active_queue_depth: int
    shadow_queue_depth: int
    active_queue_capacity: int
    shadow_queue_capacity: int
    active_drops: int
    shadow_drops: int
    active_findings: int
    active_deduplicated: int
    shadow_deduplicated: int
    active_budget_drops: int
    shadow_budget_drops: int
    budget_violations: int
    rule_integrity_failures: int
    evaluation_failures: int
    recursive_events_rejected: int
    invalid_events_rejected: int
    event_id_collisions: int
    source_cursor_collisions: int
    active_activation_epoch: int
    shadow_activation_epoch: int
    active_epoch_drops: int
    shadow_epoch_drops: int
    shadow_observations: tuple[ShadowObservation, ...]

    def to_dict(self) -> dict[str, object]:
        document = asdict(self)
        document["active_digests"] = list(self.active_digests)
        document["shadow_digests"] = list(self.shadow_digests)
        document["shadow_observations"] = [
            asdict(observation) for observation in self.shadow_observations
        ]
        return document


@dataclass(frozen=True)
class _QueuedEvent:
    event_id: str
    identity_digest: str
    source_cursor: int | None
    claimed_event_id: str | None
    event_json: str

    def event(self) -> dict[str, Any]:
        value = json.loads(self.event_json)
        if not isinstance(value, dict):  # pragma: no cover - sealed on admission
            raise DetectionRuntimeError("queued runtime event is invalid")
        return value


@dataclass(frozen=True)
class _QueuedWork:
    event: _QueuedEvent
    activation_epoch: int
    next_rule: int = 0


@dataclass(frozen=True)
class _RuntimeRule:
    package: DetectionPackage
    package_id: str
    package_digest: str
    document_json: str
    severity: Severity
    max_eval_ms: float
    max_events_per_second: int

    def verify(self) -> None:
        document = self.package.document
        if not hmac.compare_digest(str(document.get("digest", "")), self.package_digest):
            raise DetectionRuntimeError("bound rule digest changed")
        if not hmac.compare_digest(package_digest(document), self.package_digest):
            raise DetectionRuntimeError("bound rule document changed")
        if not hmac.compare_digest(_canonical(dict(document)), self.document_json):
            raise DetectionRuntimeError("bound rule bytes changed")


def _bind_rule(package: DetectionPackage) -> _RuntimeRule:
    if not isinstance(package, DetectionPackage):
        raise DetectionRuntimeError("runtime rules must be DetectionPackage instances")
    try:
        document_json = _canonical(_safe_value(dict(package.document)))
        document = json.loads(document_json)
        validate_package(document)
    except Exception as exc:
        raise DetectionRuntimeError(f"runtime rule binding failed: {exc}") from exc
    snapshot = DetectionPackage(document)
    performance = document["performance"]
    return _RuntimeRule(
        package=snapshot,
        package_id=snapshot.package_id,
        package_digest=str(document["digest"]),
        document_json=document_json,
        severity=_SEVERITIES[str(document["severity"])],
        max_eval_ms=float(performance["max_eval_ms"]),
        max_events_per_second=int(performance["max_events_per_second"]),
    )


class DetectionRuntimeEngine:
    """Thread-safe queue and evaluator with a reserved active lane."""

    def __init__(
        self,
        *,
        active_capacity: int = 256,
        shadow_capacity: int = 768,
        active_sink: Callable[[RuntimeFinding], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        work_clock: Callable[[], float] = time.perf_counter,
        authority_revalidation_seconds: float = 1.0,
    ) -> None:
        self.active_capacity = max(8, min(int(active_capacity), 8192))
        self.shadow_capacity = max(8, min(int(shadow_capacity), 8192))
        self._active_queue: deque[_QueuedWork] = deque()
        self._shadow_queue: deque[_QueuedWork] = deque()
        self._active_rules: tuple[_RuntimeRule, ...] = ()
        self._shadow_rules: tuple[_RuntimeRule, ...] = ()
        self._active_sink = active_sink
        self._clock = clock
        self._work_clock = work_clock
        self._authority_revalidation_seconds = max(
            0.05, min(float(authority_revalidation_seconds), 5.0)
        )
        self._lock = threading.RLock()
        # Evaluation itself is deliberately single-flight. Queue operations
        # remain concurrent, but a second caller cannot start shadow work while
        # another caller has already dequeued (and is still evaluating) active
        # work.
        self._process_lock = threading.RLock()
        self._active_seen: OrderedDict[tuple[str, str, str, int], None] = OrderedDict()
        self._shadow_seen: OrderedDict[tuple[str, str, str, int], None] = OrderedDict()
        self._active_inflight: set[tuple[str, str, str, int]] = set()
        self._shadow_inflight: set[tuple[str, str, str, int]] = set()
        self._claimed_ids: OrderedDict[str, str] = OrderedDict()
        self._source_cursors: OrderedDict[int, str] = OrderedDict()
        self._rate_windows: dict[tuple[str, str], deque[float]] = {}
        self._shadow_observations: deque[ShadowObservation] = deque(
            maxlen=MAX_SHADOW_OBSERVATIONS
        )
        self._active_drops = 0
        self._shadow_drops = 0
        self._active_findings = 0
        self._active_deduplicated = 0
        self._shadow_deduplicated = 0
        self._active_budget_drops = 0
        self._shadow_budget_drops = 0
        self._budget_violations = 0
        self._rule_integrity_failures = 0
        self._evaluation_failures = 0
        self._recursive_rejected = 0
        self._invalid_rejected = 0
        self._event_id_collisions = 0
        self._source_cursor_collisions = 0
        self._active_epoch = 0
        self._shadow_epoch = 0
        self._active_epoch_drops = 0
        self._shadow_epoch_drops = 0
        self._active_registry: DetectionPackageRegistry | None = None
        self._active_bindings: dict[str, str] = {}
        self._active_authority_deadline = 0.0
        # Once a manager-owned engine is sealed, active-lane mutation requires
        # the coordinator-held identity capability and the exact registry and
        # module lifecycle generation bound here. Standalone engines are
        # deliberately unsealed for explicit development/test workflows.
        self.__runtime_authority: object | None = None
        self.__authority_registry: DetectionPackageRegistry | None = None
        self.__authority_registry_root: object | None = None
        self.__authority_module: object | None = None
        self.__authority_manager: object | None = None
        self.__authority_generation = -1

    def seal_active_authority(
        self,
        registry: DetectionPackageRegistry,
        module: object | None,
        *,
        transition_capability: object,
        authority_generation: int | None = None,
        manager: object | None = None,
    ) -> object:
        """Rotate the production active-lane capability for one exact generation."""
        if not isinstance(registry, DetectionPackageRegistry) or not registry.root_governed:
            raise DetectionRuntimeError(
                "manager-owned active authority requires a root-governed registry"
            )
        registry.assert_transition_authority(transition_capability)
        if module is None:
            generation = 0
            if authority_generation not in {None, 0} or manager is not None:
                raise DetectionRuntimeError(
                    "standalone runtime authority generation is invalid"
                )
        else:
            if getattr(module, "engine", None) is not self:
                raise DetectionRuntimeError("runtime module does not own this engine")
            current_generation = getattr(module, "lifecycle_generation", None)
            if type(current_generation) is not int or current_generation < 0:
                raise DetectionRuntimeError("runtime module lifecycle generation is invalid")
            generation = (
                current_generation
                if authority_generation is None
                else authority_generation
            )
            if type(generation) is not int or generation < 0:
                raise DetectionRuntimeError("runtime authority generation is invalid")
            if generation != current_generation and not self._pending_first_start(
                module, generation
            ):
                raise DetectionRuntimeError(
                    "runtime authority cannot bind an unobserved lifecycle generation"
                )
            if manager is not None:
                modules = getattr(manager, "modules", None)
                module_name = getattr(module, "name", None)
                if (
                    not isinstance(modules, Mapping)
                    or modules.get(module_name) is not module
                    or getattr(manager, "bus", None) is None
                    or getattr(module, "_bus", None) is not getattr(manager, "bus", None)
                ):
                    raise DetectionRuntimeError(
                        "runtime manager does not own the exact module and EventBus"
                    )
        with self._process_lock:
            with self._lock:
                if (
                    self.__authority_registry_root is not None
                    and self.__authority_registry_root != registry.root
                ):
                    raise DetectionRuntimeError(
                        "sealed runtime registry root cannot be substituted"
                    )
                if (
                    self.__authority_module is not None
                    and module is not self.__authority_module
                ):
                    raise DetectionRuntimeError(
                        "sealed runtime module cannot be substituted"
                    )
                if (
                    self.__authority_manager is not None
                    and manager is not self.__authority_manager
                ):
                    raise DetectionRuntimeError(
                        "sealed runtime manager cannot be substituted"
                    )
                capability = object()
                self.__runtime_authority = capability
                self.__authority_registry = registry
                self.__authority_registry_root = registry.root
                self.__authority_module = module
                self.__authority_manager = manager
                self.__authority_generation = generation
                return capability

    @staticmethod
    def _pending_first_start(module: object, generation: int) -> bool:
        """Recognize only a fresh registered module's imminent first start."""
        thread = getattr(module, "_thread", None)
        return bool(
            getattr(module, "lifecycle_generation", None) == 0
            and generation == 1
            and getattr(module, "status", None) == "stopped"
            and (thread is None or not thread.is_alive())
            and not bool(getattr(module, "_subscribed", False))
            and not bool(getattr(module, "stopping", True))
        )

    def _assert_active_authority(
        self,
        registry: DetectionPackageRegistry | None,
        runtime_authority: object | None,
        *,
        allow_pending_start: bool = False,
        require_live_owner: bool = False,
    ) -> None:
        capability = self.__runtime_authority
        if capability is None:
            if runtime_authority is not None:
                raise DetectionRuntimeError(
                    "unsealed standalone runtime rejects an authority capability"
                )
            return
        if runtime_authority is not capability:
            raise DetectionRuntimeError("active runtime authority capability is invalid")
        if registry is not None and registry is not self.__authority_registry:
            raise DetectionRuntimeError("active runtime registry identity is invalid")
        module = self.__authority_module
        if module is not None:
            if getattr(module, "engine", None) is not self:
                raise DetectionRuntimeError("active runtime module identity changed")
            if (
                getattr(module, "lifecycle_generation", None)
                != self.__authority_generation
                and not (
                    allow_pending_start
                    and self._pending_first_start(
                        module, self.__authority_generation
                    )
                )
            ):
                raise DetectionRuntimeError("active runtime authority generation is stale")
            manager = self.__authority_manager
            if manager is not None:
                modules = getattr(manager, "modules", None)
                if (
                    not isinstance(modules, Mapping)
                    or modules.get(getattr(module, "name", None)) is not module
                    or getattr(manager, "bus", None) is None
                    or getattr(module, "_bus", None) is not getattr(manager, "bus", None)
                ):
                    raise DetectionRuntimeError(
                        "active runtime manager identity changed"
                    )
            if require_live_owner:
                thread = getattr(module, "_thread", None)
                if (
                    getattr(module, "status", None) != "running"
                    or thread is None
                    or not thread.is_alive()
                    or not bool(getattr(module, "_subscribed", False))
                    or bool(getattr(module, "stopping", True))
                ):
                    raise DetectionRuntimeError(
                        "active runtime owner is not live and subscribed"
                    )

    def assert_active_authority(
        self,
        registry: DetectionPackageRegistry,
        runtime_authority: object,
    ) -> None:
        """Read-only proof that a coordinator still owns the current seal."""
        with self._process_lock:
            self._assert_active_authority(
                registry, runtime_authority, require_live_owner=True
            )

    def set_active_sink(self, sink: Callable[[RuntimeFinding], None] | None) -> None:
        with self._lock:
            self._active_sink = sink

    @staticmethod
    def _bind_rules(
        packages: DetectionPackage | Sequence[DetectionPackage] | None,
    ) -> tuple[_RuntimeRule, ...]:
        if packages is None:
            return ()
        values = (packages,) if isinstance(packages, DetectionPackage) else tuple(packages)
        if len(values) > MAX_RUNTIME_RULES:
            raise DetectionRuntimeError("runtime package set exceeds 128 rules")
        result = tuple(_bind_rule(package) for package in values)
        digests = [rule.package_digest for rule in result]
        if len(digests) != len(set(digests)):
            raise DetectionRuntimeError("runtime package digest is duplicated")
        return result

    def sync_active_from_registry(
        self,
        registry: DetectionPackageRegistry,
        *,
        package_id: str,
        expected_digest: str,
        activation_epoch: int,
        runtime_authority: object | None = None,
    ) -> tuple[str, ...]:
        """Compatibility wrapper for an exact one-package active registry."""
        return self.sync_active_set_from_registry(
            registry,
            expected_bindings={package_id: expected_digest},
            activation_epoch=activation_epoch,
            runtime_authority=runtime_authority,
        )

    def sync_active_set_from_registry(
        self,
        registry: DetectionPackageRegistry,
        *,
        expected_bindings: Mapping[str, str],
        activation_epoch: int,
        runtime_authority: object | None = None,
    ) -> tuple[str, ...]:
        """Atomically bind the complete exact active registry set.

        A caller-owned ``DetectionPackage`` can never enter the active lane.  The
        registry holds its process lock across all trust-validating reads and
        compares the manifest again afterward, so a concurrent or out-of-band
        transition fails closed without building a mixed active set.
        ``activation_epoch`` is the durable promotion serial and prevents an old
        transition from replacing a newer runtime binding.
        """
        with self._process_lock:
            self._assert_active_authority(
                registry, runtime_authority, require_live_owner=True
            )
            return self._sync_active_set_from_registry(
                registry,
                expected_bindings=expected_bindings,
                activation_epoch=activation_epoch,
            )

    def restore_active_set_for_startup(
        self,
        registry: DetectionPackageRegistry,
        *,
        expected_bindings: Mapping[str, str],
        activation_epoch: int,
        runtime_authority: object,
    ) -> tuple[str, ...]:
        """Restore a sealed active set for an exact module's imminent first start."""
        with self._process_lock:
            self._assert_active_authority(
                registry,
                runtime_authority,
                allow_pending_start=True,
            )
            return self._sync_active_set_from_registry(
                registry,
                expected_bindings=expected_bindings,
                activation_epoch=activation_epoch,
            )

    def _sync_active_set_from_registry(
        self,
        registry: DetectionPackageRegistry,
        *,
        expected_bindings: Mapping[str, str],
        activation_epoch: int,
    ) -> tuple[str, ...]:
        if not isinstance(registry, DetectionPackageRegistry):
            raise DetectionRuntimeError("active synchronization requires a registry")
        if not isinstance(expected_bindings, Mapping):
            raise DetectionRuntimeError("active bindings must be a package-to-digest mapping")
        if len(expected_bindings) > MAX_RUNTIME_RULES:
            raise DetectionRuntimeError("active binding set exceeds 128 rules")
        if type(activation_epoch) is not int or activation_epoch < 1:
            raise DetectionRuntimeError("activation epoch must be a positive integer")
        normalized: dict[str, str] = {}
        for package_id, digest in expected_bindings.items():
            if (
                not isinstance(package_id, str)
                or not 1 <= len(package_id) <= 128
                or "\x00" in package_id
            ):
                raise DetectionRuntimeError("active package identifier is invalid")
            if (
                not isinstance(digest, str)
                or len(digest) != 71
                or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])
            ):
                raise DetectionRuntimeError("active package digest is invalid")
            normalized[package_id] = digest
        if len(normalized) != len(expected_bindings):
            raise DetectionRuntimeError("active package identifier is duplicated")
        normalized = dict(sorted(normalized.items()))

        try:
            packages = registry.active_set(normalized)
        except Exception as exc:
            raise DetectionRuntimeError(str(exc)) from exc
        rules = self._bind_rules(packages)
        with self._lock:
            if activation_epoch < self._active_epoch:
                raise DetectionRuntimeError("stale activation epoch rejected")
            if activation_epoch == self._active_epoch:
                current = tuple(rule.package_digest for rule in self._active_rules)
                expected = tuple(normalized.values())
                if current == expected:
                    self._active_registry = registry
                    self._active_bindings = normalized
                    self._active_authority_deadline = (
                        self._clock() + self._authority_revalidation_seconds
                    )
                    return current
                if current:
                    raise DetectionRuntimeError("activation epoch substitution detected")
                # A prior reconciliation failure may have cleared the lane at
                # this exact epoch. Rebinding is safe only after the registry
                # checks above prove the same authoritative digest remains active.
            self._active_epoch_drops += len(self._active_queue)
            self._active_queue.clear()
            self._active_rules = rules
            self._active_epoch = activation_epoch
            self._active_registry = registry
            self._active_bindings = normalized
            self._active_authority_deadline = (
                self._clock() + self._authority_revalidation_seconds
            )
            self._active_seen.clear()
            self._active_inflight.clear()
            self._rate_windows = {
                key: value for key, value in self._rate_windows.items() if key[0] != "active"
            }
        return tuple(rule.package_digest for rule in rules)

    def fail_closed_active(
        self,
        *,
        activation_epoch: int,
        expected_current_epoch: int | None = None,
        expected_current_digests: Sequence[str] | None = None,
        runtime_authority: object | None = None,
    ) -> bool:
        """Clear active work after a registry/runtime reconciliation failure."""
        if type(activation_epoch) is not int or activation_epoch < 1:
            raise DetectionRuntimeError("activation epoch must be a positive integer")
        with self._process_lock:
            self._assert_active_authority(None, runtime_authority)
            return self._fail_closed_active_locked(
                activation_epoch=activation_epoch,
                expected_current_epoch=expected_current_epoch,
                expected_current_digests=expected_current_digests,
            )

    def _fail_closed_active_locked(
        self,
        *,
        activation_epoch: int,
        expected_current_epoch: int | None,
        expected_current_digests: Sequence[str] | None,
    ) -> bool:
        """Clear the lane while the caller holds the process serialization lock."""
        if type(activation_epoch) is not int or activation_epoch < 1:
            raise DetectionRuntimeError("activation epoch must be a positive integer")
        with self._lock:
            if (
                expected_current_epoch is not None
                and self._active_epoch != expected_current_epoch
            ):
                return False
            if expected_current_digests is not None and tuple(
                rule.package_digest for rule in self._active_rules
            ) != tuple(expected_current_digests):
                return False
            self._active_epoch_drops += len(self._active_queue)
            self._active_queue.clear()
            self._active_rules = ()
            self._active_epoch = max(self._active_epoch, activation_epoch)
            self._active_registry = None
            self._active_bindings = {}
            self._active_authority_deadline = 0.0
            self._active_seen.clear()
            self._active_inflight.clear()
            self._rate_windows = {
                key: value
                for key, value in self._rate_windows.items()
                if key[0] != "active"
            }
            return True

    def _ensure_active_authority_valid(self) -> bool:
        """Revalidate expiry and publisher authority on a short bounded cadence."""
        with self._lock:
            registry = self._active_registry
            bindings = dict(self._active_bindings)
            epoch = self._active_epoch
            deadline = self._active_authority_deadline
            current_digests = tuple(
                rule.package_digest for rule in self._active_rules
            )
            authority_module = self.__authority_module
            authority_manager = self.__authority_manager
            authority_generation = self.__authority_generation
        if registry is None or not bindings or not current_digests:
            return True
        authority_thread = (
            getattr(authority_module, "_thread", None)
            if authority_module is not None
            else None
        )
        if authority_module is not None and (
            getattr(authority_module, "engine", None) is not self
            or getattr(authority_module, "status", None) != "running"
            or authority_thread is None
            or not authority_thread.is_alive()
            or not bool(getattr(authority_module, "_subscribed", False))
            or bool(getattr(authority_module, "stopping", True))
            or (
                authority_manager is not None
                and (
                    not isinstance(getattr(authority_manager, "modules", None), Mapping)
                    or getattr(authority_manager, "modules").get(
                        getattr(authority_module, "name", None)
                    )
                    is not authority_module
                    or getattr(authority_manager, "bus", None) is None
                    or getattr(authority_module, "_bus", None)
                    is not getattr(authority_manager, "bus", None)
                )
            )
        ):
            # A stop can be signalled after the module loop condition but
            # before its process call. Do no work in that final iteration and
            # preserve the exact binding for a same-instance restart. Any
            # external caller while stopped still reaches the CAS clear below.
            if (
                threading.current_thread() is authority_thread
                and bool(getattr(authority_module, "stopping", True))
            ):
                return False
            cleared = self._fail_closed_active_locked(
                activation_epoch=max(1, epoch),
                expected_current_epoch=epoch,
                expected_current_digests=current_digests,
            )
            if cleared:
                with self._lock:
                    self._rule_integrity_failures += 1
            return False
        if (
            authority_module is not None
            and getattr(authority_module, "lifecycle_generation", None)
            != authority_generation
        ):
            if self._adopt_exact_running_generation(
                authority_module, authority_generation
            ):
                # A restart never inherits the prior cadence window. Re-check
                # expiry, registry state, and publisher trust before any rule
                # from the retained exact binding can evaluate again.
                deadline = 0.0
            else:
                cleared = self._fail_closed_active_locked(
                    activation_epoch=max(1, epoch),
                    expected_current_epoch=epoch,
                    expected_current_digests=current_digests,
                )
                if cleared:
                    with self._lock:
                        self._rule_integrity_failures += 1
                return False
        now = self._clock()
        if now < deadline:
            return True
        try:
            packages = registry.active_set(bindings)
            validated = tuple(
                str(package.document["digest"]) for package in packages
            )
            if validated != tuple(bindings.values()):
                raise DetectionRuntimeError(
                    "authoritative active package order or digest changed"
                )
        except Exception:
            cleared = self._fail_closed_active_locked(
                activation_epoch=max(1, epoch),
                expected_current_epoch=epoch,
                expected_current_digests=current_digests,
            )
            if cleared:
                with self._lock:
                    self._rule_integrity_failures += 1
            return False
        with self._lock:
            if (
                self._active_epoch == epoch
                and self._active_registry is registry
                and self._active_bindings == bindings
            ):
                self._active_authority_deadline = (
                    now + self._authority_revalidation_seconds
                )
        return True

    def _adopt_exact_running_generation(
        self, module: object, previous_generation: int
    ) -> bool:
        """Rotate the seal for a newer live generation of the exact module."""
        generation = getattr(module, "lifecycle_generation", None)
        thread = getattr(module, "_thread", None)
        manager = self.__authority_manager
        if (
            type(generation) is not int
            or generation <= previous_generation
            or getattr(module, "engine", None) is not self
            or getattr(module, "status", None) != "running"
            or thread is None
            or not thread.is_alive()
            or not bool(getattr(module, "_subscribed", False))
            or bool(getattr(module, "stopping", True))
        ):
            return False
        if manager is not None:
            modules = getattr(manager, "modules", None)
            if (
                not isinstance(modules, Mapping)
                or modules.get(getattr(module, "name", None)) is not module
                or getattr(manager, "bus", None) is None
                or getattr(module, "_bus", None) is not getattr(manager, "bus", None)
            ):
                return False
        with self._lock:
            if (
                self.__authority_module is not module
                or self.__authority_generation != previous_generation
                or getattr(module, "lifecycle_generation", None) != generation
            ):
                return False
            # No external holder learns this capability. The coordinator will
            # re-seal on its next live operation; every prior token is stale.
            self.__runtime_authority = object()
            self.__authority_generation = generation
            return True

    def bind_shadow(
        self, packages: DetectionPackage | Sequence[DetectionPackage] | None
    ) -> tuple[str, ...]:
        rules = self._bind_rules(packages)
        with self._lock:
            self._shadow_epoch_drops += len(self._shadow_queue)
            self._shadow_epoch += 1
            self._shadow_rules = rules
            self._shadow_seen.clear()
            self._shadow_inflight.clear()
            self._shadow_queue.clear()
            self._shadow_observations.clear()
            self._rate_windows = {
                key: value for key, value in self._rate_windows.items() if key[0] != "shadow"
            }
        return tuple(rule.package_digest for rule in rules)

    @staticmethod
    def _queue_event(event: Event, *, source_cursor: int | None) -> _QueuedEvent:
        if not isinstance(event, Event):
            raise DetectionRuntimeError("runtime input must be an Angerona Event")
        if source_cursor is not None and (
            type(source_cursor) is not int or source_cursor < 0
        ):
            raise DetectionRuntimeError("source cursor must be a non-negative integer")
        if not isinstance(event.severity, Severity) or not math.isfinite(float(event.ts)):
            raise DetectionRuntimeError("runtime event metadata is invalid")
        details = _safe_value(event.details or {})
        if not isinstance(details, dict):
            raise DetectionRuntimeError("runtime event details must be an object")
        candidate_id = details.get("event_id")
        claimed_event_id = (
            candidate_id
            if isinstance(candidate_id, str) and 1 <= len(candidate_id) <= 128
            else None
        )
        identity = {
            "details": details,
            "hmac_sig": str(event.hmac_sig),
            "message": str(event.message)[:8192],
            "module": str(event.module)[:256],
            "severity": event.severity.name,
            "ts": float(event.ts),
        }
        identity_digest = "sha256:" + hashlib.sha256(
            _canonical(identity).encode("utf-8")
        ).hexdigest()
        event_id = (
            f"runtime-{source_cursor}-{identity_digest[7:23]}"
            if source_cursor is not None
            else f"runtime-{identity_digest[7:31]}"
        )
        fields: dict[str, object] = {
            **details,
            "event_id": event_id,
            "message": identity["message"],
            "module": identity["module"],
            "severity": event.severity.name,
        }
        rendered = _canonical(fields)
        if len(rendered.encode("utf-8")) > MAX_RUNTIME_EVENT_BYTES:
            raise DetectionRuntimeError("runtime event exceeds 256 KiB")
        return _QueuedEvent(
            event_id,
            identity_digest,
            source_cursor,
            claimed_event_id,
            rendered,
        )

    def reject_internal_publication(self) -> None:
        """Count a module-authenticated synchronous self-publication."""
        with self._lock:
            self._recursive_rejected += 1

    def _record_identity_collisions(self, queued: _QueuedEvent) -> None:
        claimed = queued.claimed_event_id
        if claimed is not None:
            previous = self._claimed_ids.get(claimed)
            if previous is not None and previous != queued.identity_digest:
                self._event_id_collisions += 1
            self._claimed_ids[claimed] = queued.identity_digest
            self._claimed_ids.move_to_end(claimed)
            while len(self._claimed_ids) > MAX_DEDUPE_KEYS:
                self._claimed_ids.popitem(last=False)
        cursor = queued.source_cursor
        if cursor is not None:
            previous = self._source_cursors.get(cursor)
            if previous is not None and previous != queued.identity_digest:
                self._source_cursor_collisions += 1
            self._source_cursors[cursor] = queued.identity_digest
            self._source_cursors.move_to_end(cursor)
            while len(self._source_cursors) > MAX_DEDUPE_KEYS:
                self._source_cursors.popitem(last=False)

    def submit(
        self,
        event: Event,
        *,
        include_shadow: bool = True,
        source_cursor: int | None = None,
    ) -> bool:
        try:
            queued = self._queue_event(event, source_cursor=source_cursor)
        except DetectionRuntimeError:
            with self._lock:
                self._invalid_rejected += 1
            return False
        admitted = True
        with self._lock:
            self._record_identity_collisions(queued)
            if self._active_rules:
                if len(self._active_queue) >= self.active_capacity:
                    self._active_drops += 1
                    admitted = False
                else:
                    self._active_queue.append(_QueuedWork(queued, self._active_epoch))
            if include_shadow and self._shadow_rules:
                if len(self._shadow_queue) >= self.shadow_capacity:
                    self._shadow_drops += 1
                else:
                    self._shadow_queue.append(_QueuedWork(queued, self._shadow_epoch))
        return admitted

    def submit_shadow(self, event: Event, *, source_cursor: int | None = None) -> bool:
        """Admit offline shadow work without consuming any active-lane slot."""
        try:
            queued = self._queue_event(event, source_cursor=source_cursor)
        except DetectionRuntimeError:
            with self._lock:
                self._invalid_rejected += 1
            return False
        with self._lock:
            self._record_identity_collisions(queued)
            if not self._shadow_rules:
                return False
            if len(self._shadow_queue) >= self.shadow_capacity:
                self._shadow_drops += 1
                return False
            self._shadow_queue.append(_QueuedWork(queued, self._shadow_epoch))
            return True

    @staticmethod
    def _remember(
        seen: OrderedDict[tuple[str, str, str, int], None],
        key: tuple[str, str, str, int],
    ) -> None:
        seen[key] = None
        seen.move_to_end(key)
        while len(seen) > MAX_DEDUPE_KEYS:
            seen.popitem(last=False)

    @staticmethod
    def _dedupe_key(
        queued: _QueuedEvent, rule: _RuntimeRule, epoch: int
    ) -> tuple[str, str, str, int]:
        cursor = (
            f"cursor:{queued.source_cursor}"
            if queued.source_cursor is not None
            else "cursor:none"
        )
        return queued.identity_digest, cursor, rule.package_digest, epoch

    @staticmethod
    def _claim(
        seen: OrderedDict[tuple[str, str, str, int], None],
        inflight: set[tuple[str, str, str, int]],
        key: tuple[str, str, str, int],
    ) -> bool:
        if key in seen:
            seen.move_to_end(key)
            return False
        if key in inflight:
            return False
        inflight.add(key)
        return True

    def _finish_claim(
        self,
        seen: OrderedDict[tuple[str, str, str, int], None],
        inflight: set[tuple[str, str, str, int]],
        key: tuple[str, str, str, int],
        *,
        evaluated: bool,
    ) -> None:
        with self._lock:
            inflight.discard(key)
            if evaluated:
                self._remember(seen, key)

    def _budget_admits(self, side: str, rule: _RuntimeRule, now: float) -> bool:
        key = (side, rule.package_digest)
        with self._lock:
            window = self._rate_windows.setdefault(key, deque())
            cutoff = now - 1.0
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= rule.max_events_per_second:
                if side == "active":
                    self._active_budget_drops += 1
                else:
                    self._shadow_budget_drops += 1
                return False
            window.append(now)
            return True

    def _active_evaluate(
        self, work: _QueuedWork, rules: tuple[_RuntimeRule, ...]
    ) -> list[tuple[RuntimeFinding, Callable[[RuntimeFinding], None] | None]]:
        published: list[tuple[RuntimeFinding, Callable[[RuntimeFinding], None] | None]] = []
        queued = work.event
        event_fields: dict[str, Any] | None = None
        event_decode_error: Exception | None = None
        event_decode_ms = 0.0
        for rule in rules:
            key = self._dedupe_key(queued, rule, work.activation_epoch)
            with self._lock:
                if not self._claim(self._active_seen, self._active_inflight, key):
                    self._active_deduplicated += 1
                    continue
            evaluated = False
            try:
                if not self._budget_admits("active", rule, self._clock()):
                    continue
                try:
                    rule.verify()
                except DetectionRuntimeError:
                    with self._lock:
                        self._rule_integrity_failures += 1
                    continue
                started = self._work_clock()
                decoded_this_rule = False
                try:
                    if event_fields is None and event_decode_error is None:
                        decoded_this_rule = True
                        decode_started = self._work_clock()
                        try:
                            event_fields = queued.event()
                        except Exception as exc:
                            event_decode_error = exc
                        event_decode_ms = (
                            self._work_clock() - decode_started
                        ) * 1000.0
                    if event_decode_error is not None:
                        raise event_decode_error
                    matched = bool(rule.package.evaluate(event_fields))
                    evaluated = True
                except Exception:
                    with self._lock:
                        self._evaluation_failures += 1
                    continue
                elapsed_ms = (
                    (self._work_clock() - started) * 1000.0
                    + (0.0 if decoded_this_rule else event_decode_ms)
                )
            finally:
                self._finish_claim(
                    self._active_seen,
                    self._active_inflight,
                    key,
                    evaluated=evaluated,
                )
            exceeded = elapsed_ms > rule.max_eval_ms
            if exceeded:
                with self._lock:
                    self._budget_violations += 1
            if not matched:
                continue
            finding = RuntimeFinding(
                event_id=queued.event_id,
                package_id=rule.package_id,
                package_digest=rule.package_digest,
                severity=rule.severity,
                message=f"Detection {rule.package_id} matched event {queued.event_id}",
                elapsed_ms=elapsed_ms,
                budget_exceeded=exceeded,
            )
            with self._lock:
                self._active_findings += 1
                sink = self._active_sink
            published.append((finding, sink))
        return published

    def _shadow_evaluate(
        self,
        work: _QueuedWork,
        rules: tuple[_RuntimeRule, ...],
        *,
        deadline: float,
        remaining_evaluations: int,
    ) -> tuple[int, int]:
        # Intentionally no publisher/evidence/incident/SOAR/response argument.
        queued = work.event
        event_fields: dict[str, Any] | None = None
        event_decode_error: Exception | None = None
        event_decode_ms = 0.0
        evaluations = 0
        for index in range(work.next_rule, len(rules)):
            with self._lock:
                active_waiting = bool(self._active_queue)
            if (
                active_waiting
                or evaluations >= remaining_evaluations
                or self._work_clock() >= deadline
            ):
                return index, evaluations
            rule = rules[index]
            key = self._dedupe_key(queued, rule, work.activation_epoch)
            with self._lock:
                if not self._claim(self._shadow_seen, self._shadow_inflight, key):
                    self._shadow_deduplicated += 1
                    continue
            evaluated = False
            try:
                if not self._budget_admits("shadow", rule, self._clock()):
                    continue
                try:
                    rule.verify()
                except DetectionRuntimeError:
                    with self._lock:
                        self._rule_integrity_failures += 1
                    continue
                started = self._work_clock()
                decoded_this_rule = False
                evaluations += 1
                try:
                    if event_fields is None and event_decode_error is None:
                        decoded_this_rule = True
                        decode_started = self._work_clock()
                        try:
                            event_fields = queued.event()
                        except Exception as exc:
                            event_decode_error = exc
                        event_decode_ms = (
                            self._work_clock() - decode_started
                        ) * 1000.0
                    if event_decode_error is not None:
                        raise event_decode_error
                    matched = bool(rule.package.evaluate(event_fields))
                    disposition = "matched" if matched else "not-matched"
                    evaluated = True
                except Exception:
                    matched = False
                    disposition = "evaluation-failed"
                    with self._lock:
                        self._evaluation_failures += 1
                    continue
                elapsed_ms = (
                    (self._work_clock() - started) * 1000.0
                    + (0.0 if decoded_this_rule else event_decode_ms)
                )
            finally:
                self._finish_claim(
                    self._shadow_seen,
                    self._shadow_inflight,
                    key,
                    evaluated=evaluated,
                )
            if elapsed_ms > rule.max_eval_ms:
                disposition = "budget-exceeded"
                with self._lock:
                    self._budget_violations += 1
            with self._lock:
                self._shadow_observations.append(ShadowObservation(
                    event_id=queued.event_id,
                    package_id=rule.package_id,
                    package_digest=rule.package_digest,
                    matched=matched,
                    disposition=disposition,
                    elapsed_ms=elapsed_ms,
                ))
        return len(rules), evaluations

    def process(
        self,
        *,
        max_active: int = 256,
        max_shadow: int = 256,
        max_shadow_evaluations: int = MAX_SHADOW_EVALUATIONS_PER_PROCESS,
        shadow_slice_ms: float = MAX_SHADOW_SLICE_MS,
    ) -> tuple[int, int]:
        with self._process_lock:
            return self._process_once(
                max_active=max_active,
                max_shadow=max_shadow,
                max_shadow_evaluations=max_shadow_evaluations,
                shadow_slice_ms=shadow_slice_ms,
            )

    def _process_once(
        self,
        *,
        max_active: int = 256,
        max_shadow: int = 256,
        max_shadow_evaluations: int = MAX_SHADOW_EVALUATIONS_PER_PROCESS,
        shadow_slice_ms: float = MAX_SHADOW_SLICE_MS,
    ) -> tuple[int, int]:
        if not self._ensure_active_authority_valid():
            return 0, 0
        active_limit = max(0, min(int(max_active), self.active_capacity))
        shadow_limit = max(0, min(int(max_shadow), self.shadow_capacity))
        shadow_work_limit = max(
            0,
            min(int(max_shadow_evaluations), MAX_SHADOW_EVALUATIONS_PER_PROCESS),
        )
        shadow_ms = max(0.0, min(float(shadow_slice_ms), MAX_SHADOW_SLICE_MS))
        with self._lock:
            active_items = tuple(
                self._active_queue.popleft()
                for _ in range(min(active_limit, len(self._active_queue)))
            )
            active_rules = self._active_rules
        findings: list[tuple[RuntimeFinding, Callable[[RuntimeFinding], None] | None]] = []
        for work in active_items:
            with self._lock:
                current_epoch = self._active_epoch
            if work.activation_epoch != current_epoch:
                with self._lock:
                    self._active_epoch_drops += 1
                continue
            findings.extend(self._active_evaluate(work, active_rules))
        # Invoke active publishers only after all engine locks are released.
        for finding, sink in findings:
            if sink is not None:
                try:
                    sink(finding)
                except Exception:
                    with self._lock:
                        self._evaluation_failures += 1
        # Active work has strict priority. Any work left after ``max_active``
        # means the best-effort shadow lane waits for a later process cycle.
        with self._lock:
            shadow_rules = self._shadow_rules
            active_waiting = bool(self._active_queue)
        if active_waiting or shadow_limit == 0 or shadow_work_limit == 0 or shadow_ms == 0:
            return len(active_items), 0

        shadow_started = 0
        shadow_evaluations = 0
        deadline = self._work_clock() + (shadow_ms / 1000.0)
        while shadow_started < shadow_limit and shadow_evaluations < shadow_work_limit:
            with self._lock:
                if self._active_queue or not self._shadow_queue:
                    break
                work = self._shadow_queue.popleft()
                current_epoch = self._shadow_epoch
            shadow_started += 1
            if work.activation_epoch != current_epoch:
                with self._lock:
                    self._shadow_epoch_drops += 1
                continue
            next_rule, used = self._shadow_evaluate(
                work,
                shadow_rules,
                deadline=deadline,
                remaining_evaluations=shadow_work_limit - shadow_evaluations,
            )
            shadow_evaluations += used
            if next_rule < len(shadow_rules):
                with self._lock:
                    if work.activation_epoch == self._shadow_epoch:
                        self._shadow_queue.appendleft(
                            _QueuedWork(work.event, work.activation_epoch, next_rule)
                        )
                    else:
                        self._shadow_epoch_drops += 1
                break
            if self._work_clock() >= deadline:
                break
        return len(active_items), shadow_started

    def snapshot(self) -> DetectionRuntimeSnapshot:
        with self._lock:
            return DetectionRuntimeSnapshot(
                active_digests=tuple(rule.package_digest for rule in self._active_rules),
                shadow_digests=tuple(rule.package_digest for rule in self._shadow_rules),
                active_queue_depth=len(self._active_queue),
                shadow_queue_depth=len(self._shadow_queue),
                active_queue_capacity=self.active_capacity,
                shadow_queue_capacity=self.shadow_capacity,
                active_drops=self._active_drops,
                shadow_drops=self._shadow_drops,
                active_findings=self._active_findings,
                active_deduplicated=self._active_deduplicated,
                shadow_deduplicated=self._shadow_deduplicated,
                active_budget_drops=self._active_budget_drops,
                shadow_budget_drops=self._shadow_budget_drops,
                budget_violations=self._budget_violations,
                rule_integrity_failures=self._rule_integrity_failures,
                evaluation_failures=self._evaluation_failures,
                recursive_events_rejected=self._recursive_rejected,
                invalid_events_rejected=self._invalid_rejected,
                event_id_collisions=self._event_id_collisions,
                source_cursor_collisions=self._source_cursor_collisions,
                active_activation_epoch=self._active_epoch,
                shadow_activation_epoch=self._shadow_epoch,
                active_epoch_drops=self._active_epoch_drops,
                shadow_epoch_drops=self._shadow_epoch_drops,
                shadow_observations=tuple(self._shadow_observations),
            )


class DetectionRuntimeModule(BaseModule):
    """Native detect-only module; findings never grant response authority."""

    CODE = "DFRT"
    NAME = "Detection Runtime"
    name = NAME
    description = (
        "Runs digest-bound local detection packages with a reserved active lane and "
        "an alert-inert, loss-visible shadow lane for DetectionForge validation."
    )
    category = "Detection"
    version = "1.13.0"
    supported_platforms = frozenset({"windows", "linux", "macos"})
    capability_mode = "detect"
    maturity_channel = "preview"
    platform_requirements = (
        "local Angerona EventBus telemetry",
        "digest-verified DetectionPackage rules",
    )
    capability_inputs = (
        "local-eventbus-security-telemetry",
        "digest-verified-detection-packages",
    )
    capability_outputs = (
        "observe-only-active-detection-findings",
        "local-in-memory-shadow-quality-observations",
        "explicit-active-and-shadow-loss-counters",
    )
    capability_permissions = ("local-memory-read", "local-eventbus-observe")
    high_risk_permissions = ()
    data_classes = (
        "bounded-security-event-fields",
        "detection-package-digests",
        "shadow-match-counters",
    )
    egress = "none"
    retention = "bounded-memory-only-runtime-queues-dedupe-and-shadow-observations"
    response_authority = "none"
    capability_dependencies = ()
    capability_conflicts = ()
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = (
        "active-and-shadow-loss-counted-separately; shadow-flood-never-evicts-active-lane"
    )
    settings_schema = {
        "type": "object",
        "properties": {
            "active_capacity": {"type": "integer", "minimum": 8, "maximum": 8192},
            "shadow_capacity": {"type": "integer", "minimum": 8, "maximum": 8192},
        },
        "additionalProperties": False,
    }
    resource_budget = {
        "worker_model": "single-lifecycle-thread-with-two-bounded-memory-lanes",
        "event_delivery": "active-reserved-and-shadow-best-effort-loss-visible",
        "startup_cycle_timeout_seconds": 15.0,
        "throttle_min": 1.0,
        "throttle_max": 8.0,
    }
    enabled_by_default = True

    def __init__(self, *, engine: DetectionRuntimeEngine | None = None) -> None:
        super().__init__()
        self.engine = engine or DetectionRuntimeEngine()
        self.engine.set_active_sink(self._publish_finding)
        self._subscribed = False
        self._publication_context = threading.local()
        self._source_cursor = 0
        self._source_cursor_lock = threading.Lock()

    def _publish_finding(self, finding: RuntimeFinding) -> None:
        # EventBus delivery is synchronous. A thread-local publication context
        # is therefore an unforgeable in-process recursion marker: telemetry
        # fields or a spoofed module name can never suppress an attacker event.
        self._publication_context.internal = True
        try:
            self.emit(
                finding.message,
                finding.severity,
                **finding.event_details(),
            )
        finally:
            self._publication_context.internal = False

    def _on_event(self, event: Event) -> None:
        if self.stopping:
            return
        if bool(getattr(self._publication_context, "internal", False)):
            self.engine.reject_internal_publication()
            return
        with self._source_cursor_lock:
            self._source_cursor += 1
            cursor = self._source_cursor
        self.engine.submit(event, source_cursor=cursor)

    def evidence_snapshot(self) -> dict[str, object]:
        return self.engine.snapshot().to_dict()

    def run(self) -> None:
        if self._bus is not None and not self._subscribed:
            self._bus.subscribe(self._on_event, delivery_budget_ms=2.0)
            self._subscribed = True
        self.emit(
            "Detection Runtime online — active findings are observe-only; shadow is alert-inert.",
            Severity.INFO,
            response_authorized=False,
            response_authority="observe-only",
            shadow_mode_alert_inert=True,
            egress="none",
        )
        while not self.stopping:
            self.engine.process(max_active=256, max_shadow=128)
            snapshot = self.engine.snapshot()
            if snapshot.active_drops or snapshot.rule_integrity_failures:
                self.set_health(
                    60,
                    f"active drops={snapshot.active_drops}; "
                    f"rule integrity failures={snapshot.rule_integrity_failures}",
                )
            else:
                self.set_health(
                    100,
                    f"active={len(snapshot.active_digests)}; "
                    f"shadow={len(snapshot.shadow_digests)}; "
                    f"shadow drops={snapshot.shadow_drops}",
                )
            self.sleep(0.1)

    def self_test(self) -> tuple[bool, str]:
        snapshot = self.engine.snapshot()
        ok = (
            self.response_authority == "none"
            and self.capability_mode == "detect"
            and snapshot.active_queue_capacity >= 8
            and snapshot.shadow_queue_capacity >= 8
            and snapshot.active_drops >= 0
            and snapshot.shadow_drops >= 0
        )
        return (
            ok,
            "separate bounded lanes and observe-only authority passed"
            if ok else "runtime authority or queue contract failed",
        )


def register() -> DetectionRuntimeModule:
    return DetectionRuntimeModule()


__all__ = [
    "DetectionRuntimeEngine",
    "DetectionRuntimeError",
    "DetectionRuntimeModule",
    "DetectionRuntimeSnapshot",
    "RuntimeFinding",
    "ShadowObservation",
    "register",
]
