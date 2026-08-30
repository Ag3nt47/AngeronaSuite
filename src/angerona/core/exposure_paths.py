"""Bounded, cycle-safe exposure path analysis and inert what-if simulation."""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable

from angerona.core.exposure_graph import (
    Applicability,
    AssertionState,
    CoverageStatus,
    EdgeKind,
    EvidenceProvenance,
    ExposureEdge,
    ExposureSnapshot,
    NodeKind,
    ResourceStatus,
    evidence_is_current_bound,
    evaluate_snapshot_coverage,
    verify_snapshot_digest,
)


PATH_SCHEMA = "angerona.aegis-path.path-analysis.v1"


class AnalysisCASConflict(RuntimeError):
    """The requested immutable graph generation/digest is no longer current."""


class PathClassification(str, Enum):
    CONFIRMED = "confirmed"
    SPECULATIVE = "speculative"


class SelectionMode(str, Enum):
    FULL = "FULL"
    FILTERED = "FILTERED"


@dataclass(frozen=True, slots=True)
class PathLimits:
    max_depth: int = 12
    max_paths: int = 512
    max_expansions: int = 20_000
    timeout_ms: int = 1_000
    max_frontier: int = 5_000
    max_work_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        values = (
            self.max_depth,
            self.max_paths,
            self.max_expansions,
            self.timeout_ms,
            self.max_frontier,
            self.max_work_bytes,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise ValueError("path limits must be integers")
        if not 1 <= self.max_depth <= 64:
            raise ValueError("max_depth must be between 1 and 64")
        if not 1 <= self.max_paths <= 10_000:
            raise ValueError("max_paths must be between 1 and 10,000")
        if not 1 <= self.max_expansions <= 1_000_000:
            raise ValueError("max_expansions must be between 1 and 1,000,000")
        if not 1 <= self.timeout_ms <= 60_000:
            raise ValueError("timeout_ms must be between 1 and 60,000")
        if not 1 <= self.max_frontier <= 100_000:
            raise ValueError("max_frontier must be between 1 and 100,000")
        if not 64 * 1024 <= self.max_work_bytes <= 256 * 1024 * 1024:
            raise ValueError("max_work_bytes must be between 64 KiB and 256 MiB")


@dataclass(frozen=True, slots=True)
class ExposurePath:
    path_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    entry_id: str
    target_id: str
    classification: PathClassification
    evidence_strength: float
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChokePoint:
    node_id: str
    paths_through: int
    total_paths: int
    confirmed_paths: int
    coverage: float


@dataclass(frozen=True, slots=True)
class BlastRadius:
    node_id: str
    reachable_target_ids: tuple[str, ...]
    confirmed_target_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReceipt:
    schema: str
    snapshot_digest: str
    generation: int
    scope_id: str
    policy_digest: str
    evaluated_at: float
    entry_selection_mode: SelectionMode
    target_selection_mode: SelectionMode
    expected_entry_ids: tuple[str, ...]
    expected_target_ids: tuple[str, ...]
    parameters_digest: str
    analysis_digest: str
    status: ResourceStatus


@dataclass(frozen=True, slots=True)
class AnalysisParameters:
    """Exact, renderable selection and resource contract for one analysis."""

    limits: PathLimits
    entry_selection_mode: SelectionMode
    target_selection_mode: SelectionMode
    requested_entry_ids: tuple[str, ...]
    requested_target_ids: tuple[str, ...]
    expected_entry_ids: tuple[str, ...]
    expected_target_ids: tuple[str, ...]
    excluded_node_ids: tuple[str, ...]
    excluded_edge_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.limits, PathLimits):
            raise ValueError("analysis parameters require PathLimits")
        if not isinstance(self.entry_selection_mode, SelectionMode) or not isinstance(
            self.target_selection_mode, SelectionMode
        ):
            raise ValueError("analysis selection mode must be FULL or FILTERED")
        for name in (
            "requested_entry_ids",
            "requested_target_ids",
            "expected_entry_ids",
            "expected_target_ids",
            "excluded_node_ids",
            "excluded_edge_ids",
        ):
            rows = getattr(self, name)
            if (
                not isinstance(rows, tuple)
                or tuple(sorted(rows)) != rows
                or len(rows) != len(set(rows))
                or any(not isinstance(value, str) or not value for value in rows)
            ):
                raise ValueError(f"{name} must be a unique sorted identifier tuple")
        if (
            self.entry_selection_mode is SelectionMode.FULL
            and self.requested_entry_ids
        ):
            raise ValueError("FULL entry selection cannot contain requested identifiers")
        if (
            self.target_selection_mode is SelectionMode.FULL
            and self.requested_target_ids
        ):
            raise ValueError("FULL target selection cannot contain requested identifiers")


@dataclass(frozen=True, slots=True)
class PathAnalysis:
    confirmed_paths: tuple[ExposurePath, ...]
    speculative_paths: tuple[ExposurePath, ...]
    choke_points: tuple[ChokePoint, ...]
    blast_radius: tuple[BlastRadius, ...]
    entry_ids: tuple[str, ...]
    target_ids: tuple[str, ...]
    status: ResourceStatus
    truncation_reasons: tuple[str, ...]
    coverage_status: CoverageStatus
    coverage_reasons: tuple[str, ...]
    evaluated_at: float
    expansions: int
    parameters: AnalysisParameters
    receipt: AnalysisReceipt

    @property
    def all_paths(self) -> tuple[ExposurePath, ...]:
        return self.confirmed_paths + self.speculative_paths


@dataclass(frozen=True, slots=True)
class WhatIfComparison:
    baseline: PathAnalysis
    simulated: PathAnalysis
    breakpoint_edge_ids: tuple[str, ...]
    breakpoint_node_ids: tuple[str, ...]
    removed_confirmed_paths: int
    removed_speculative_paths: int
    no_longer_enumerated_target_ids: tuple[str, ...]
    still_enumerated_target_ids: tuple[str, ...]
    status: ResourceStatus
    coverage_status: CoverageStatus
    coverage_reasons: tuple[str, ...]
    explanation: str


def _digest(value: object) -> str:
    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _require_cas(
    snapshot: ExposureSnapshot,
    expected_generation: int,
    expected_digest: str,
    expected_scope_id: str,
    expected_policy_digest: str,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> None:
    if not verify_snapshot_digest(snapshot, work_guard=work_guard):
        if work_guard is not None and not work_guard(0):
            raise AnalysisCASConflict(
                "snapshot verification exceeded the bounded analysis preflight"
            )
        raise AnalysisCASConflict("snapshot content digest is invalid")
    if (
        snapshot.generation != expected_generation
        or snapshot.digest != expected_digest
        or snapshot.scope_id != expected_scope_id
        or snapshot.policy_digest != expected_policy_digest
    ):
        raise AnalysisCASConflict(
            "snapshot generation, digest, declared scope, or policy changed"
        )


def _edge_is_current(edge: ExposureEdge, evaluated_at: float) -> bool:
    return evidence_is_current_bound(
        edge.evidence,
        at_time=evaluated_at,
        generation=edge.evidence.generation,
    )


def _is_authoritative_negative(edge: ExposureEdge, evaluated_at: float) -> bool:
    """Only a closed, finite, authoritative negative may suppress a CVE edge."""
    return bool(
        edge.kind is EdgeKind.AFFECTED_BY
        and edge.applicability is Applicability.NOT_APPLICABLE
        and edge.assertion is AssertionState.CLOSED
        and edge.evidence.provenance
        in {
            EvidenceProvenance.SCANNER,
            EvidenceProvenance.SIGNED_IMPORT,
            EvidenceProvenance.ANALYST_ATTESTATION,
        }
        and _edge_is_current(edge, evaluated_at)
        and edge.observed_version
        and edge.affected_range
    )


def _path_classification(
    edges: tuple[ExposureEdge, ...], evaluated_at: float
) -> tuple[PathClassification, float, tuple[str, ...]]:
    reasons: set[str] = set()
    strengths: list[float] = []
    confirmed = True
    for edge in edges:
        strengths.append(edge.evidence.confidence)
        if edge.assertion is not AssertionState.CONFIRMED:
            confirmed = False
            reasons.add(f"{edge.edge_id}:assertion-{edge.assertion.value}")
        if not _edge_is_current(edge, evaluated_at):
            confirmed = False
            if edge.evidence.expires_at <= evaluated_at:
                reasons.add(f"{edge.edge_id}:evidence-expired-at-analysis")
            elif edge.evidence.observed_at > evaluated_at:
                reasons.add(f"{edge.edge_id}:evidence-future-at-analysis")
            elif not edge.evidence.digest:
                reasons.add(f"{edge.edge_id}:evidence-unbound")
            else:
                reasons.add(f"{edge.edge_id}:evidence-{edge.evidence.freshness.value}")
        if edge.evidence.confidence <= 0.0:
            confirmed = False
            reasons.add(f"{edge.edge_id}:confidence-unknown")
        if edge.kind is EdgeKind.AFFECTED_BY and edge.applicability is not Applicability.EXACT:
            confirmed = False
            reasons.add(f"{edge.edge_id}:cve-applicability-{edge.applicability.value}")
    if confirmed:
        reasons.add("all-edges-current-confirmed-and-applicable")
    else:
        reasons.add("route-retained-as-speculative-not-proof-of-reachability")
    return (
        PathClassification.CONFIRMED if confirmed else PathClassification.SPECULATIVE,
        min(strengths, default=0.0),
        tuple(sorted(reasons)),
    )


def _path_fact(path: ExposurePath) -> dict:
    return {
        "path_id": path.path_id,
        "node_ids": list(path.node_ids),
        "edge_ids": list(path.edge_ids),
        "entry_id": path.entry_id,
        "target_id": path.target_id,
        "classification": path.classification.value,
        "evidence_strength": path.evidence_strength,
        "reasons": list(path.reasons),
    }


def _parameters_core(parameters: AnalysisParameters) -> dict:
    limits = parameters.limits
    return {
        "limits": {
            "max_depth": limits.max_depth,
            "max_paths": limits.max_paths,
            "max_expansions": limits.max_expansions,
            "timeout_ms": limits.timeout_ms,
            "max_frontier": limits.max_frontier,
            "max_work_bytes": limits.max_work_bytes,
        },
        "entry_selection_mode": parameters.entry_selection_mode.value,
        "target_selection_mode": parameters.target_selection_mode.value,
        "requested_entry_ids": list(parameters.requested_entry_ids),
        "requested_target_ids": list(parameters.requested_target_ids),
        "expected_entry_ids": list(parameters.expected_entry_ids),
        "expected_target_ids": list(parameters.expected_target_ids),
        "excluded_node_ids": list(parameters.excluded_node_ids),
        "excluded_edge_ids": list(parameters.excluded_edge_ids),
    }


def _analysis_core(analysis: PathAnalysis) -> dict:
    return {
        "confirmed_paths": [_path_fact(row) for row in analysis.confirmed_paths],
        "speculative_paths": [_path_fact(row) for row in analysis.speculative_paths],
        "choke_points": [
            {
                "node_id": row.node_id,
                "paths_through": row.paths_through,
                "total_paths": row.total_paths,
                "confirmed_paths": row.confirmed_paths,
                "coverage": row.coverage,
            }
            for row in analysis.choke_points
        ],
        "blast_radius": [
            {
                "node_id": row.node_id,
                "reachable_target_ids": list(row.reachable_target_ids),
                "confirmed_target_ids": list(row.confirmed_target_ids),
            }
            for row in analysis.blast_radius
        ],
        "entry_ids": list(analysis.entry_ids),
        "target_ids": list(analysis.target_ids),
        "status": analysis.status.value,
        "truncation_reasons": list(analysis.truncation_reasons),
        "coverage_status": analysis.coverage_status.value,
        "coverage_reasons": list(analysis.coverage_reasons),
        "evaluated_at": analysis.evaluated_at,
        "expansions": analysis.expansions,
        "parameters": _parameters_core(analysis.parameters),
    }


def _targets_for_paths(paths: Iterable[ExposurePath]) -> set[str]:
    return {path.target_id for path in paths}


def _bounded_ids(
    values: Iterable[str],
    *,
    name: str,
    maximum: int,
    boundary: Callable[[], bool] | None = None,
) -> frozenset[str]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an identifier collection")
    admitted: set[str] = set()
    for index, value in enumerate(values):
        if index % 32 == 0 and boundary is not None and boundary():
            raise AnalysisCASConflict(f"{name} processing exceeded the analysis budget")
        if index >= maximum:
            raise ValueError(f"{name} exceeds the bounded snapshot domain")
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError(f"{name} contains an invalid identifier")
        admitted.add(value)
    return frozenset(admitted)


def _node_index_size(node: object) -> int:
    return 192 + len(getattr(node, "node_id", "")) + len(getattr(node, "label", ""))


def _edge_index_size(edge: object) -> int:
    return 224 + sum(
        len(str(getattr(edge, name, "")))
        for name in ("edge_id", "source_id", "target_id", "reason")
    )


def _frontier_state_size(
    node_path: tuple[str, ...], edge_path: tuple[ExposureEdge, ...]
) -> int:
    return 160 + sum(len(value) + 24 for value in node_path) + sum(
        len(edge.edge_id) + 24 for edge in edge_path
    )


def analyze_exposure_paths(
    snapshot: ExposureSnapshot,
    *,
    expected_generation: int,
    expected_digest: str,
    expected_scope_id: str,
    expected_policy_digest: str,
    limits: PathLimits | None = None,
    entry_ids: Iterable[str] | None = None,
    target_ids: Iterable[str] | None = None,
    excluded_node_ids: Iterable[str] = (),
    excluded_edge_ids: Iterable[str] = (),
    monotonic: Callable[[], float] = time.monotonic,
    clock: Callable[[], float] = time.time,
    cancelled: Callable[[], bool] | None = None,
) -> PathAnalysis:
    """Enumerate simple exposure routes from an exact immutable CAS snapshot.

    Closed edges are excluded.  Missing, expired, stale, speculative, or
    zero-confidence evidence keeps a route visible but can never make it a
    confirmed path.  Every resource cutoff is surfaced as
    ``INCOMPLETE_RESOURCE_LIMIT``; partial results must not be read as safety.
    """
    if not isinstance(snapshot, ExposureSnapshot):
        raise ValueError("snapshot must be an ExposureSnapshot")
    if not callable(monotonic) or not callable(clock):
        raise ValueError("analysis clocks must be callable")
    if cancelled is not None and not callable(cancelled):
        raise ValueError("cancelled must be callable")
    limits = limits or PathLimits()
    if not isinstance(limits, PathLimits):
        raise ValueError("limits must be PathLimits")
    # The analysis clock and work ledger start before content hashing or any
    # caller-controlled selection/preflight work.
    start = float(monotonic())
    if not math.isfinite(start):
        raise ValueError("analysis clocks must return finite numbers")
    deadline = start + limits.timeout_ms / 1_000.0
    reasons: set[str] = set(snapshot.truncation_reasons)
    verification_work = 0

    def boundary() -> bool:
        if cancelled is not None and cancelled():
            reasons.add("analysis_cancelled")
            return True
        current_tick = float(monotonic())
        if not math.isfinite(current_tick) or current_tick > deadline:
            reasons.add("analysis_timeout")
            return True
        return False

    def verification_guard(cost: int) -> bool:
        nonlocal verification_work
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
            reasons.add("preflight_work_invalid")
            return False
        verification_work += cost
        if verification_work > limits.max_work_bytes:
            reasons.add("preflight_work_memory_limit")
            return False
        return not boundary()

    _require_cas(
        snapshot,
        expected_generation,
        expected_digest,
        expected_scope_id,
        expected_policy_digest,
        work_guard=verification_guard,
    )
    evaluated_at = max(snapshot.observed_at, float(clock()))
    if not math.isfinite(evaluated_at):
        raise ValueError("analysis clocks must return finite numbers")

    coverage_status, coverage_reasons = evaluate_snapshot_coverage(
        snapshot, at_time=evaluated_at, work_guard=verification_guard
    )
    if boundary():
        raise AnalysisCASConflict("analysis budget expired during snapshot preflight")
    node_map: dict[str, object] = {}
    index_bytes = 0
    for node_index, node in enumerate(snapshot.nodes):
        if node_index % 32 == 0 and boundary():
            raise AnalysisCASConflict("analysis budget expired while indexing nodes")
        index_bytes += _node_index_size(node)
        if index_bytes > limits.max_work_bytes:
            raise AnalysisCASConflict("node index exceeds the bounded analysis work budget")
        node_map[node.node_id] = node
    excluded_nodes = _bounded_ids(
        excluded_node_ids,
        name="excluded_node_ids",
        maximum=len(node_map) + 1,
        boundary=boundary,
    )
    excluded_edges = _bounded_ids(
        excluded_edge_ids,
        name="excluded_edge_ids",
        maximum=len(snapshot.edges) + 1,
        boundary=boundary,
    )
    if any(value not in node_map for value in excluded_nodes):
        raise ValueError("excluded node identifiers must exist in the snapshot")
    snapshot_edge_ids: set[str] = set()
    for edge_index, edge in enumerate(snapshot.edges):
        if edge_index % 32 == 0 and boundary():
            raise AnalysisCASConflict("analysis budget expired while indexing edges")
        index_bytes += 80 + len(edge.edge_id)
        if index_bytes > limits.max_work_bytes:
            raise AnalysisCASConflict("edge index exceeds the bounded analysis work budget")
        snapshot_edge_ids.add(edge.edge_id)
    if any(value not in snapshot_edge_ids for value in excluded_edges):
        raise ValueError("excluded edge identifiers must exist in the snapshot")
    entry_mode = SelectionMode.FULL if entry_ids is None else SelectionMode.FILTERED
    target_mode = SelectionMode.FULL if target_ids is None else SelectionMode.FILTERED
    requested_entries = (
        frozenset()
        if entry_ids is None
        else _bounded_ids(
            entry_ids,
            name="entry_ids",
            maximum=len(node_map) + 1,
            boundary=boundary,
        )
    )
    requested_targets = (
        frozenset()
        if target_ids is None
        else _bounded_ids(
            target_ids,
            name="target_ids",
            maximum=len(node_map) + 1,
            boundary=boundary,
        )
    )
    if entry_ids is None:
        entries = tuple(sorted(
            node.node_id for node in snapshot.nodes
            if node.kind is NodeKind.ENTRY_POINT and node.node_id not in excluded_nodes
        ))
    else:
        entries = tuple(sorted(requested_entries - excluded_nodes))
    if target_ids is None:
        targets = tuple(sorted(
            node.node_id for node in snapshot.nodes
            if (
                node.kind in {NodeKind.TARGET, NodeKind.DATA}
                or (node.kind is NodeKind.ASSET and node.criticality >= 4)
            )
            and node.node_id not in excluded_nodes
        ))
    else:
        targets = tuple(sorted(requested_targets - excluded_nodes))
    if any(value not in node_map for value in entries + targets):
        raise ValueError("entry and target identifiers must exist in the snapshot")

    parameters = AnalysisParameters(
        limits=limits,
        entry_selection_mode=entry_mode,
        target_selection_mode=target_mode,
        requested_entry_ids=tuple(sorted(requested_entries)),
        requested_target_ids=tuple(sorted(requested_targets)),
        expected_entry_ids=entries,
        expected_target_ids=targets,
        excluded_node_ids=tuple(sorted(excluded_nodes)),
        excluded_edge_ids=tuple(sorted(excluded_edges)),
    )
    if entry_mode is SelectionMode.FILTERED and not entries:
        reasons.add("filtered_entry_selection_empty")
    if target_mode is SelectionMode.FILTERED and not targets:
        reasons.add("filtered_target_selection_empty")

    adjacency: dict[str, list[ExposureEdge]] = {}
    for edge_index, edge in enumerate(snapshot.edges):
        if edge_index % 64 == 0 and boundary():
            break
        if (
            edge.assertion is AssertionState.CLOSED
            and edge.applicability is not Applicability.NOT_APPLICABLE
            and _edge_is_current(edge, evaluated_at)
        ) or _is_authoritative_negative(edge, evaluated_at):
            continue
        if (
            edge.kind is EdgeKind.PROTECTED_BY
            or edge.edge_id in excluded_edges
            or edge.source_id in excluded_nodes
            or edge.target_id in excluded_nodes
        ):
            continue
        edge_size = _edge_index_size(edge)
        if index_bytes + edge_size > limits.max_work_bytes:
            reasons.add("adjacency_work_memory_limit")
            break
        adjacency.setdefault(edge.source_id, []).append(edge)
        index_bytes += edge_size
    adjacency_aborted = False
    for value_index, values in enumerate(adjacency.values()):
        if value_index % 16 == 0 and boundary():
            adjacency_aborted = True
            break
        values.sort(key=lambda edge: (edge.target_id, edge.kind.value, edge.edge_id))
    if adjacency_aborted:
        adjacency.clear()

    paths: list[ExposurePath] = []
    expansions = 0
    stop = False
    target_set = frozenset(targets)
    # Reversed insertion plus sorted outgoing rows makes the LIFO traversal
    # deterministic and lexicographic without recursive call-stack risk.
    stack: list[tuple[str, tuple[str, ...], tuple[ExposureEdge, ...], int]] = []
    frontier_bytes = 0
    result_bytes = 0
    for entry in reversed(entries):
        state_size = _frontier_state_size((entry,), ())
        if len(stack) >= limits.max_frontier:
            reasons.add("frontier_limit")
            break
        if index_bytes + frontier_bytes + state_size > limits.max_work_bytes:
            reasons.add("work_memory_limit")
            break
        stack.append((entry, (entry,), (), state_size))
        frontier_bytes += state_size
    while stack and not stop:
        if boundary():
            break
        current, node_path, edge_path, state_size = stack.pop()
        frontier_bytes = max(0, frontier_bytes - state_size)
        if current in target_set and edge_path:
            classification, strength, path_reasons = _path_classification(
                edge_path, evaluated_at
            )
            path_id = "PATH:" + _digest({
                "snapshot": snapshot.digest,
                "nodes": node_path,
                "edges": [edge.edge_id for edge in edge_path],
            }).split(":", 1)[1][:24]
            path = ExposurePath(
                path_id=path_id,
                node_ids=node_path,
                edge_ids=tuple(edge.edge_id for edge in edge_path),
                entry_id=node_path[0],
                target_id=current,
                classification=classification,
                evidence_strength=strength,
                reasons=path_reasons,
            )
            path_size = _frontier_state_size(node_path, edge_path)
            if (
                index_bytes + frontier_bytes + result_bytes + path_size
                > limits.max_work_bytes
            ):
                reasons.add("work_memory_limit")
                stop = True
                continue
            paths.append(path)
            result_bytes += path_size
            if len(paths) >= limits.max_paths:
                if stack or any(
                    edge.target_id not in node_path for edge in adjacency.get(current, ())
                ):
                    reasons.add("path_limit")
                stop = True
                continue
            # A target may also be an intermediate node. Retain this route and
            # continue so downstream targets cannot be hidden behind it.
        outgoing = adjacency.get(current, ())
        if len(edge_path) >= limits.max_depth:
            if any(edge.target_id not in node_path for edge in outgoing):
                reasons.add("depth_limit")
            continue
        pending: list[
            tuple[str, tuple[str, ...], tuple[ExposureEdge, ...], int]
        ] = []
        pending_bytes = 0
        for edge_index, edge in enumerate(outgoing):
            if edge_index % 32 == 0 and boundary():
                stop = True
                break
            if edge.target_id in node_path:
                continue
            if expansions >= limits.max_expansions:
                reasons.add("expansion_limit")
                stop = True
                break
            expansions += 1
            next_nodes = node_path + (edge.target_id,)
            next_edges = edge_path + (edge,)
            next_size = _frontier_state_size(next_nodes, next_edges)
            if len(stack) + len(pending) >= limits.max_frontier:
                reasons.add("frontier_limit")
                stop = True
                break
            if (
                index_bytes
                + frontier_bytes
                + pending_bytes
                + result_bytes
                + next_size
                > limits.max_work_bytes
            ):
                reasons.add("work_memory_limit")
                stop = True
                break
            pending.append((edge.target_id, next_nodes, next_edges, next_size))
            pending_bytes += next_size
        stack.extend(reversed(pending))
        frontier_bytes += pending_bytes

    if boundary():
        reasons.add("analysis_timeout")
    paths.sort(key=lambda row: (row.node_ids, row.edge_ids, row.path_id))
    confirmed = tuple(
        row for row in paths if row.classification is PathClassification.CONFIRMED
    )
    speculative = tuple(
        row for row in paths if row.classification is PathClassification.SPECULATIVE
    )
    total = len(paths)
    entry_set, target_set = frozenset(entries), frozenset(targets)
    through_count: dict[str, int] = {}
    confirmed_through_count: dict[str, int] = {}
    targets_by_node: dict[str, set[str]] = {}
    confirmed_targets_by_node: dict[str, set[str]] = {}
    aggregation_bytes = 0
    aggregate_stop = False
    for path_index, path in enumerate(paths):
        if path_index % 32 == 0 and boundary():
            aggregate_stop = True
            break
        for node_index, node_id in enumerate(path.node_ids):
            if node_index % 16 == 0 and boundary():
                aggregate_stop = True
                break
            target_bucket = targets_by_node.setdefault(node_id, set())
            if path.target_id not in target_bucket:
                aggregation_bytes += 96 + len(node_id) + len(path.target_id)
            if (
                index_bytes + result_bytes + frontier_bytes + aggregation_bytes
                > limits.max_work_bytes
            ):
                reasons.add("work_memory_limit")
                aggregate_stop = True
                break
            target_bucket.add(path.target_id)
            if path.classification is PathClassification.CONFIRMED:
                confirmed_targets_by_node.setdefault(node_id, set()).add(path.target_id)
        if aggregate_stop:
            break
        for node_id in path.node_ids[1:-1]:
            through_count[node_id] = through_count.get(node_id, 0) + 1
            if path.classification is PathClassification.CONFIRMED:
                confirmed_through_count[node_id] = (
                    confirmed_through_count.get(node_id, 0) + 1
                )
    if aggregate_stop:
        reasons.add("aggregate_incomplete")
    chokes: list[ChokePoint] = []
    if total:
        for node_id in sorted(through_count):
            if node_id in entry_set or node_id in target_set or node_id in excluded_nodes:
                continue
            chokes.append(ChokePoint(
                node_id=node_id,
                paths_through=through_count[node_id],
                total_paths=total,
                confirmed_paths=confirmed_through_count.get(node_id, 0),
                coverage=through_count[node_id] / total,
            ))
    chokes.sort(key=lambda row: (-row.coverage, -row.confirmed_paths, row.node_id))

    radii: list[BlastRadius] = []
    for node_id in sorted(targets_by_node):
        radii.append(BlastRadius(
            node_id=node_id,
            reachable_target_ids=tuple(sorted(targets_by_node[node_id])),
            confirmed_target_ids=tuple(sorted(
                confirmed_targets_by_node.get(node_id, set())
            )),
        ))
    truncation = tuple(sorted(reasons))
    status = (
        ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
        if truncation or snapshot.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
        else ResourceStatus.COMPLETE
    )
    receipt_parameters = {
        "schema": PATH_SCHEMA,
        "snapshot": snapshot.digest,
        "generation": snapshot.generation,
        "scope_id": snapshot.scope_id,
        "policy_digest": snapshot.policy_digest,
        "evaluated_at": evaluated_at,
        "parameters": _parameters_core(parameters),
    }
    provisional_receipt = AnalysisReceipt(
        schema=PATH_SCHEMA,
        snapshot_digest=snapshot.digest,
        generation=snapshot.generation,
        scope_id=snapshot.scope_id,
        policy_digest=snapshot.policy_digest,
        evaluated_at=evaluated_at,
        entry_selection_mode=parameters.entry_selection_mode,
        target_selection_mode=parameters.target_selection_mode,
        expected_entry_ids=parameters.expected_entry_ids,
        expected_target_ids=parameters.expected_target_ids,
        parameters_digest=_digest(receipt_parameters),
        analysis_digest="",
        status=status,
    )
    provisional = PathAnalysis(
        confirmed_paths=confirmed,
        speculative_paths=speculative,
        choke_points=tuple(chokes),
        blast_radius=tuple(radii),
        entry_ids=entries,
        target_ids=targets,
        status=status,
        truncation_reasons=truncation,
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
        evaluated_at=evaluated_at,
        expansions=expansions,
        parameters=parameters,
        receipt=provisional_receipt,
    )
    receipt = AnalysisReceipt(
        schema=PATH_SCHEMA,
        snapshot_digest=snapshot.digest,
        generation=snapshot.generation,
        scope_id=snapshot.scope_id,
        policy_digest=snapshot.policy_digest,
        evaluated_at=evaluated_at,
        entry_selection_mode=parameters.entry_selection_mode,
        target_selection_mode=parameters.target_selection_mode,
        expected_entry_ids=parameters.expected_entry_ids,
        expected_target_ids=parameters.expected_target_ids,
        parameters_digest=provisional_receipt.parameters_digest,
        analysis_digest=_digest({
            "parameters_digest": provisional_receipt.parameters_digest,
            "result": _analysis_core(provisional),
        }),
        status=status,
    )
    return PathAnalysis(
        confirmed_paths=confirmed,
        speculative_paths=speculative,
        choke_points=tuple(chokes),
        blast_radius=tuple(radii),
        entry_ids=entries,
        target_ids=targets,
        status=status,
        truncation_reasons=truncation,
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
        evaluated_at=evaluated_at,
        expansions=expansions,
        parameters=parameters,
        receipt=receipt,
    )


def _selection_matches_snapshot(
    analysis: PathAnalysis,
    snapshot: ExposureSnapshot,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> bool:
    parameters = analysis.parameters
    if not isinstance(parameters, AnalysisParameters):
        return False
    nodes: dict[str, object] = {}
    for index, node in enumerate(snapshot.nodes):
        if index % 32 == 0 and work_guard is not None and not work_guard(192):
            return False
        nodes[node.node_id] = node
    edge_ids: set[str] = set()
    for index, edge in enumerate(snapshot.edges):
        if index % 32 == 0 and work_guard is not None and not work_guard(128):
            return False
        edge_ids.add(edge.edge_id)
    excluded_nodes = frozenset(parameters.excluded_node_ids)
    if any(value not in nodes for value in excluded_nodes) or any(
        value not in edge_ids for value in parameters.excluded_edge_ids
    ):
        return False
    if parameters.entry_selection_mode is SelectionMode.FULL:
        expected_entries = tuple(sorted(
            node.node_id
            for node in snapshot.nodes
            if node.kind is NodeKind.ENTRY_POINT and node.node_id not in excluded_nodes
        ))
    else:
        if any(value not in nodes for value in parameters.requested_entry_ids):
            return False
        expected_entries = tuple(sorted(
            set(parameters.requested_entry_ids) - excluded_nodes
        ))
    if parameters.target_selection_mode is SelectionMode.FULL:
        expected_targets = tuple(sorted(
            node.node_id
            for node in snapshot.nodes
            if (
                node.kind in {NodeKind.TARGET, NodeKind.DATA}
                or (node.kind is NodeKind.ASSET and node.criticality >= 4)
            )
            and node.node_id not in excluded_nodes
        ))
    else:
        if any(value not in nodes for value in parameters.requested_target_ids):
            return False
        expected_targets = tuple(sorted(
            set(parameters.requested_target_ids) - excluded_nodes
        ))
    return bool(
        parameters.expected_entry_ids == expected_entries
        and parameters.expected_target_ids == expected_targets
        and analysis.entry_ids == expected_entries
        and analysis.target_ids == expected_targets
    )


def verify_analysis_receipt(
    analysis: object,
    snapshot: object,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> bool:
    """Return false, never raise, for malformed or selection-substituted receipts."""
    if not isinstance(analysis, PathAnalysis) or not isinstance(
        snapshot, ExposureSnapshot
    ):
        return False
    try:
        if not verify_snapshot_digest(
            snapshot, work_guard=work_guard
        ) or not _selection_matches_snapshot(
            analysis, snapshot, work_guard=work_guard
        ):
            return False
        receipt = analysis.receipt
        parameters = analysis.parameters
        receipt_parameters = {
            "schema": PATH_SCHEMA,
            "snapshot": snapshot.digest,
            "generation": snapshot.generation,
            "scope_id": snapshot.scope_id,
            "policy_digest": snapshot.policy_digest,
            "evaluated_at": analysis.evaluated_at,
            "parameters": _parameters_core(parameters),
        }
        coverage = evaluate_snapshot_coverage(
            snapshot,
            at_time=analysis.evaluated_at,
            work_guard=work_guard,
        )
        return bool(
            isinstance(receipt, AnalysisReceipt)
            and receipt.schema == PATH_SCHEMA
            and receipt.snapshot_digest == snapshot.digest
            and receipt.generation == snapshot.generation
            and receipt.scope_id == snapshot.scope_id
            and receipt.policy_digest == snapshot.policy_digest
            and receipt.evaluated_at == analysis.evaluated_at
            and receipt.entry_selection_mode is parameters.entry_selection_mode
            and receipt.target_selection_mode is parameters.target_selection_mode
            and receipt.expected_entry_ids == parameters.expected_entry_ids
            and receipt.expected_target_ids == parameters.expected_target_ids
            and receipt.parameters_digest == _digest(receipt_parameters)
            and receipt.status is analysis.status
            and analysis.coverage_status is coverage[0]
            and analysis.coverage_reasons == coverage[1]
            and receipt.analysis_digest == _digest({
                "parameters_digest": receipt.parameters_digest,
                "result": _analysis_core(analysis),
            })
        )
    except (AttributeError, TypeError, ValueError, RuntimeError, OverflowError):
        return False


def require_current_analysis(
    analysis: PathAnalysis,
    current_snapshot: ExposureSnapshot,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> None:
    """Fail a compare-and-swap boundary when a newer graph replaced analysis."""
    if not verify_analysis_receipt(
        analysis, current_snapshot, work_guard=work_guard
    ):
        raise AnalysisCASConflict("analysis receipt is not bound to the current snapshot")


def simulate_breakpoints(
    snapshot: ExposureSnapshot,
    *,
    expected_generation: int,
    expected_digest: str,
    expected_scope_id: str,
    expected_policy_digest: str,
    breakpoint_edge_ids: Iterable[str] = (),
    breakpoint_node_ids: Iterable[str] = (),
    limits: PathLimits | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    clock: Callable[[], float] = time.time,
    cancelled: Callable[[], bool] | None = None,
) -> WhatIfComparison:
    """Purely remove graph fragments and compare routes; never perform an action."""
    if not isinstance(snapshot, ExposureSnapshot):
        raise ValueError("snapshot must be an ExposureSnapshot")
    limits = limits or PathLimits()
    if not isinstance(limits, PathLimits):
        raise ValueError("limits must be PathLimits")
    # Baseline analysis starts and enforces the deadline/work ledger before the
    # snapshot digest is hashed.  Avoid a redundant unbudgeted CAS preflight.
    baseline = analyze_exposure_paths(
        snapshot,
        expected_generation=expected_generation,
        expected_digest=expected_digest,
        expected_scope_id=expected_scope_id,
        expected_policy_digest=expected_policy_digest,
        limits=limits,
        monotonic=monotonic,
        clock=clock,
        cancelled=cancelled,
    )
    edge_ids = tuple(sorted(_bounded_ids(
        breakpoint_edge_ids,
        name="breakpoint_edge_ids",
        maximum=len(snapshot.edges) + 1,
    )))
    node_ids = tuple(sorted(_bounded_ids(
        breakpoint_node_ids,
        name="breakpoint_node_ids",
        maximum=len(snapshot.nodes) + 1,
    )))
    known_edges = {edge.edge_id for edge in snapshot.edges}
    known_nodes = {node.node_id for node in snapshot.nodes}
    if any(value not in known_edges for value in edge_ids):
        raise ValueError("breakpoint edge does not exist")
    if any(value not in known_nodes for value in node_ids):
        raise ValueError("breakpoint node does not exist")
    comparison_time = baseline.evaluated_at

    def fixed_clock() -> float:
        return comparison_time

    simulated = analyze_exposure_paths(
        snapshot,
        expected_generation=expected_generation,
        expected_digest=expected_digest,
        expected_scope_id=expected_scope_id,
        expected_policy_digest=expected_policy_digest,
        limits=limits,
        excluded_edge_ids=edge_ids,
        excluded_node_ids=node_ids,
        monotonic=monotonic,
        clock=fixed_clock,
        cancelled=cancelled,
    )
    before_confirmed = len(baseline.confirmed_paths)
    before_speculative = len(baseline.speculative_paths)
    before_targets = _targets_for_paths(baseline.all_paths)
    after_targets = _targets_for_paths(simulated.all_paths)
    coverage_status = (
        CoverageStatus.VERIFIED
        if (
            baseline.coverage_status is CoverageStatus.VERIFIED
            and simulated.coverage_status is CoverageStatus.VERIFIED
        )
        else CoverageStatus.UNUSABLE
        if (
            baseline.coverage_status is CoverageStatus.UNUSABLE
            or simulated.coverage_status is CoverageStatus.UNUSABLE
        )
        else CoverageStatus.UNVERIFIED
    )
    coverage_reasons = tuple(sorted(set(
        baseline.coverage_reasons + simulated.coverage_reasons
    )))
    status = (
        ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
        if (
            baseline.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
            or simulated.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
            or coverage_status is not CoverageStatus.VERIFIED
        )
        else ResourceStatus.COMPLETE
    )
    caveat = (
        "Partial inert comparison: processing limits or unverified semantic coverage "
        "prevent a terminal conclusion; a route no longer enumerated is not proof of "
        "remediation, unreachability, or safety."
        if (
            status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
            or coverage_status is not CoverageStatus.VERIFIED
        )
        else "Inert enumeration comparison only; 'no longer enumerated' is not proof "
        "of unreachability or remediation, and no host, network, process, EventBus, "
        "or SOAR action occurred."
    )
    return WhatIfComparison(
        baseline=baseline,
        simulated=simulated,
        breakpoint_edge_ids=edge_ids,
        breakpoint_node_ids=node_ids,
        removed_confirmed_paths=max(0, before_confirmed - len(simulated.confirmed_paths)),
        removed_speculative_paths=max(
            0, before_speculative - len(simulated.speculative_paths)
        ),
        no_longer_enumerated_target_ids=tuple(sorted(before_targets - after_targets)),
        still_enumerated_target_ids=tuple(sorted(after_targets)),
        status=status,
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
        explanation=caveat,
    )


__all__ = [
    "AnalysisCASConflict",
    "AnalysisReceipt",
    "AnalysisParameters",
    "BlastRadius",
    "ChokePoint",
    "ExposurePath",
    "PathAnalysis",
    "PathClassification",
    "PathLimits",
    "SelectionMode",
    "WhatIfComparison",
    "analyze_exposure_paths",
    "require_current_analysis",
    "simulate_breakpoints",
    "verify_analysis_receipt",
]
