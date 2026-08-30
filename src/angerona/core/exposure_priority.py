"""Explainable exposure-route priority and inert breakpoint planning.

Scores are deterministic work-order signals, never breach probabilities.  KEV
and EPSS can increase priority only when joined to a confirmed, current,
exactly-applicable CVE route; neither signal independently proves exposure.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from angerona.core.exposure_graph import (
    Applicability,
    CoverageStatus,
    EdgeKind,
    ExposureSnapshot,
    NodeKind,
    ResourceStatus,
    evidence_is_current_bound,
)
from angerona.core.exposure_paths import (
    ExposurePath,
    PathAnalysis,
    PathClassification,
    require_current_analysis,
)


PRIORITY_SCHEMA = "angerona.aegis-path.priority.v1"


class PriorityTier(str, Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MODERATE = "moderate"
    REVIEW = "review"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class BreakpointKind(str, Enum):
    NODE = "node"
    EDGE = "edge"


@dataclass(frozen=True, slots=True)
class PathPriority:
    path_id: str
    tier: PriorityTier
    action_score: int
    target_criticality: int
    kev_cves: tuple[str, ...]
    epss_signals: tuple[tuple[str, float], ...]
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]
    score_is_breach_probability: bool = False


@dataclass(frozen=True, slots=True)
class BreakpointCandidate:
    candidate_id: str
    kind: BreakpointKind
    graph_id: str
    paths_covered: int
    confirmed_paths_covered: int
    target_ids: tuple[str, ...]
    coverage: float
    planning_score: int
    reason: str
    simulation_only: bool = True


@dataclass(frozen=True, slots=True)
class PriorityReceipt:
    schema: str
    snapshot_digest: str
    generation: int
    scope_id: str
    policy_digest: str
    evaluated_at: float
    path_analysis_digest: str
    result_digest: str
    status: ResourceStatus


@dataclass(frozen=True, slots=True)
class PriorityAnalysis:
    priorities: tuple[PathPriority, ...]
    breakpoints: tuple[BreakpointCandidate, ...]
    status: ResourceStatus
    truncation_reasons: tuple[str, ...]
    coverage_status: CoverageStatus
    coverage_reasons: tuple[str, ...]
    receipt: PriorityReceipt


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _path_priority(
    snapshot: ExposureSnapshot,
    path: ExposurePath,
    nodes: dict,
    edges: dict,
    *,
    incomplete: bool,
    evaluated_at: float,
) -> PathPriority:
    target = nodes[path.target_id]
    criticality = int(target.criticality)
    score = 25 if path.classification is PathClassification.CONFIRMED else 5
    reasons = [
        (
            "confirmed current exposure route"
            if path.classification is PathClassification.CONFIRMED
            else "speculative route retained for analyst review"
        )
    ]
    limitations: list[str] = []
    if criticality:
        score += criticality * 8
        reasons.append(f"target criticality {criticality}/5")
    else:
        limitations.append("target criticality is unknown")

    kev: set[str] = set()
    epss: dict[str, float] = {}
    exact_cve_nodes: set[str] = set()
    if path.classification is PathClassification.CONFIRMED:
        for edge_id in path.edge_ids:
            edge = edges[edge_id]
            if (
                edge.kind is EdgeKind.AFFECTED_BY
                and edge.applicability is Applicability.EXACT
                and evidence_is_current_bound(
                    edge.evidence,
                    at_time=evaluated_at,
                    generation=snapshot.generation,
                )
            ):
                if nodes[edge.target_id].kind is NodeKind.VULNERABILITY:
                    exact_cve_nodes.add(edge.target_id)
    for node_id in sorted(exact_cve_nodes):
        node = nodes[node_id]
        threat = node.threat_evidence
        threat_current = bool(
            threat is not None
            and evidence_is_current_bound(
                threat,
                at_time=evaluated_at,
                generation=snapshot.generation,
            )
        )
        if threat_current and node.known_exploited is True and node.cve_id:
            kev.add(node.cve_id)
        if threat_current and node.epss is not None and node.cve_id:
            epss[node.cve_id] = node.epss
    if kev:
        score += min(25, 15 + 5 * len(kev))
        reasons.append("KEV signal joined to exact current CVE applicability")
    high_epss = {cve: value for cve, value in epss.items() if value >= 0.5}
    moderate_epss = {cve: value for cve, value in epss.items() if 0.1 <= value < 0.5}
    if high_epss:
        score += min(12, 8 + len(high_epss))
        reasons.append("high EPSS signal joined to exact current CVE applicability")
    elif moderate_epss:
        score += 4
        reasons.append("moderate EPSS signal joined to exact current CVE applicability")

    controls = [
        nodes[node_id] for node_id in path.node_ids
        if nodes[node_id].kind is NodeKind.CONTROL
    ]
    known_control = [
        node.control_effectiveness for node in controls
        if node.control_effectiveness is not None
    ]
    if known_control and min(known_control) < 0.4:
        score += 10
        reasons.append("weak control evidence on route")
    elif controls and not known_control:
        limitations.append("control effectiveness is unknown")
    elif not controls:
        limitations.append("no control-effectiveness evidence is bound to this route")

    score = max(0, min(100, score))
    if path.classification is PathClassification.SPECULATIVE:
        tier = PriorityTier.REVIEW
        limitations.append("KEV or EPSS cannot elevate a speculative route to urgent work")
    elif incomplete:
        tier = PriorityTier.REVIEW
        limitations.append(
            "incomplete processing or unverified semantic coverage cannot support terminal priority"
        )
    elif criticality == 0:
        tier = PriorityTier.INSUFFICIENT_EVIDENCE
    elif score >= 75:
        tier = PriorityTier.IMMEDIATE
    elif score >= 55:
        tier = PriorityTier.HIGH
    elif score >= 35:
        tier = PriorityTier.MODERATE
    else:
        tier = PriorityTier.REVIEW
    limitations.append("action score is a work-order heuristic, not breach probability")
    return PathPriority(
        path_id=path.path_id,
        tier=tier,
        action_score=score,
        target_criticality=criticality,
        kev_cves=tuple(sorted(kev)),
        epss_signals=tuple(sorted(epss.items())),
        reasons=tuple(sorted(set(reasons))),
        limitations=tuple(sorted(set(limitations))),
    )


def _candidate(
    kind: BreakpointKind,
    graph_id: str,
    covered: list[ExposurePath],
    total: int,
) -> BreakpointCandidate:
    confirmed = sum(
        row.classification is PathClassification.CONFIRMED for row in covered
    )
    target_ids = tuple(sorted({row.target_id for row in covered}))
    coverage = len(covered) / total if total else 0.0
    score = min(
        100,
        round(coverage * 65)
        + min(25, confirmed * 5)
        + min(10, len(target_ids) * 2),
    )
    candidate_id = "BREAK:" + _digest({
        "kind": kind.value, "graph_id": graph_id,
    }).split(":", 1)[1][:24]
    return BreakpointCandidate(
        candidate_id=candidate_id,
        kind=kind,
        graph_id=graph_id,
        paths_covered=len(covered),
        confirmed_paths_covered=confirmed,
        target_ids=target_ids,
        coverage=coverage,
        planning_score=score,
        reason=(
            f"Inert removal would affect {len(covered)}/{total} enumerated routes; "
            "validate control feasibility and compensating paths before any separate change."
        ),
    )


def _priority_core(analysis: PriorityAnalysis) -> dict:
    return {
        "priorities": [
            {
                "path_id": row.path_id,
                "tier": row.tier.value,
                "action_score": row.action_score,
                "target_criticality": row.target_criticality,
                "kev_cves": list(row.kev_cves),
                "epss_signals": [list(signal) for signal in row.epss_signals],
                "reasons": list(row.reasons),
                "limitations": list(row.limitations),
                "score_is_breach_probability": row.score_is_breach_probability,
            }
            for row in analysis.priorities
        ],
        "breakpoints": [
            {
                "candidate_id": row.candidate_id,
                "kind": row.kind.value,
                "graph_id": row.graph_id,
                "paths_covered": row.paths_covered,
                "confirmed_paths_covered": row.confirmed_paths_covered,
                "target_ids": list(row.target_ids),
                "coverage": row.coverage,
                "planning_score": row.planning_score,
                "reason": row.reason,
                "simulation_only": row.simulation_only,
            }
            for row in analysis.breakpoints
        ],
        "status": analysis.status.value,
        "truncation_reasons": list(analysis.truncation_reasons),
        "coverage_status": analysis.coverage_status.value,
        "coverage_reasons": list(analysis.coverage_reasons),
    }


def prioritize_exposure_paths(
    snapshot: ExposureSnapshot,
    analysis: PathAnalysis,
    *,
    max_breakpoints: int = 256,
    monotonic: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] | None = None,
) -> PriorityAnalysis:
    """Rank exact analysis results and produce proposal-only breakpoints."""
    if (
        isinstance(max_breakpoints, bool)
        or not isinstance(max_breakpoints, int)
        or not 1 <= max_breakpoints <= 10_000
    ):
        raise ValueError("max_breakpoints must be between 1 and 10,000")
    if not callable(monotonic) or (cancelled is not None and not callable(cancelled)):
        raise ValueError("priority budget callbacks must be callable")
    if not isinstance(analysis, PathAnalysis):
        raise ValueError("analysis must be a PathAnalysis")
    limits = analysis.parameters.limits
    start = float(monotonic())
    if not math.isfinite(start):
        raise ValueError("priority monotonic clock must be finite")
    deadline = start + limits.timeout_ms / 1_000.0
    work_bytes = 0
    budget_reasons: set[str] = set()

    def boundary() -> bool:
        if cancelled is not None and cancelled():
            budget_reasons.add("priority_cancelled")
            return True
        tick = float(monotonic())
        if not math.isfinite(tick) or tick > deadline:
            budget_reasons.add("priority_timeout")
            return True
        return False

    def verification_guard(cost: int) -> bool:
        nonlocal work_bytes
        work_bytes += max(0, int(cost))
        if work_bytes > limits.max_work_bytes:
            budget_reasons.add("priority_preflight_work_memory_limit")
            return False
        return not boundary()

    # Start the priority ledger before receipt/snapshot hashing.
    require_current_analysis(
        analysis, snapshot, work_guard=verification_guard
    )
    work_bytes = 0
    nodes: dict[str, object] = {}
    edges: dict[str, object] = {}
    for index, node in enumerate(snapshot.nodes):
        if index % 32 == 0 and boundary():
            break
        work_bytes += 160 + len(node.node_id) + len(node.label)
        if work_bytes > limits.max_work_bytes:
            budget_reasons.add("priority_work_memory_limit")
            break
        nodes[node.node_id] = node
    if not budget_reasons:
        for index, edge in enumerate(snapshot.edges):
            if index % 32 == 0 and boundary():
                break
            work_bytes += 192 + len(edge.edge_id) + len(edge.reason)
            if work_bytes > limits.max_work_bytes:
                budget_reasons.add("priority_work_memory_limit")
                break
            edges[edge.edge_id] = edge
    incomplete = (
        analysis.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
        or analysis.coverage_status is not CoverageStatus.VERIFIED
    )
    priority_rows: list[PathPriority] = []
    processed_paths: list[ExposurePath] = []
    if not budget_reasons:
        for index, path in enumerate(analysis.all_paths):
            if index % 16 == 0 and boundary():
                break
            work_bytes += 192 + sum(len(value) + 24 for value in path.node_ids)
            work_bytes += sum(len(value) + 24 for value in path.edge_ids)
            if work_bytes > limits.max_work_bytes:
                budget_reasons.add("priority_work_memory_limit")
                break
            priority_rows.append(_path_priority(
                snapshot,
                path,
                nodes,
                edges,
                incomplete=incomplete,
                evaluated_at=analysis.evaluated_at,
            ))
            processed_paths.append(path)
    priorities = tuple(sorted(
        priority_rows,
        key=lambda row: (-row.action_score, row.tier.value, row.path_id),
    ))
    all_paths = processed_paths
    candidates: list[BreakpointCandidate] = []
    endpoints = set(analysis.entry_ids) | set(analysis.target_ids)
    node_paths: dict[str, list[ExposurePath]] = {}
    edge_paths: dict[str, list[ExposurePath]] = {}
    # One bounded pass over enumerated path fragments avoids an N×P scan of a
    # large enterprise graph. Simple paths contain each fragment at most once.
    for path_index, path in enumerate(all_paths):
        if path_index % 16 == 0 and boundary():
            break
        for node_id in path.node_ids[1:-1]:
            work_bytes += len(node_id) + 48
            if work_bytes > limits.max_work_bytes:
                budget_reasons.add("priority_work_memory_limit")
                break
            if node_id not in endpoints:
                node_paths.setdefault(node_id, []).append(path)
        if budget_reasons:
            break
        for edge_id in path.edge_ids:
            work_bytes += len(edge_id) + 48
            if work_bytes > limits.max_work_bytes:
                budget_reasons.add("priority_work_memory_limit")
                break
            edge_paths.setdefault(edge_id, []).append(path)
        if budget_reasons:
            break
    if budget_reasons:
        node_paths.clear()
        edge_paths.clear()
    for candidate_index, node_id in enumerate(sorted(node_paths)):
        if candidate_index % 16 == 0 and boundary():
            break
        candidates.append(_candidate(
            BreakpointKind.NODE, node_id, node_paths[node_id], len(all_paths)
        ))
    for candidate_index, edge_id in enumerate(sorted(edge_paths)):
        if candidate_index % 16 == 0 and boundary():
            break
        candidates.append(_candidate(
            BreakpointKind.EDGE, edge_id, edge_paths[edge_id], len(all_paths)
        ))
    candidates.sort(key=lambda row: (
        -row.planning_score,
        -row.confirmed_paths_covered,
        row.kind.value,
        row.graph_id,
    ))
    reasons = list(analysis.truncation_reasons) + sorted(budget_reasons)
    if len(candidates) > max_breakpoints:
        candidates = candidates[:max_breakpoints]
        reasons.append("breakpoint_limit")
    reasons = sorted(set(reasons))
    status = (
        ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
        if reasons or incomplete
        else ResourceStatus.COMPLETE
    )
    provisional_receipt = PriorityReceipt(
        schema=PRIORITY_SCHEMA,
        snapshot_digest=snapshot.digest,
        generation=snapshot.generation,
        scope_id=snapshot.scope_id,
        policy_digest=snapshot.policy_digest,
        evaluated_at=analysis.evaluated_at,
        path_analysis_digest=analysis.receipt.analysis_digest,
        result_digest="",
        status=status,
    )
    provisional = PriorityAnalysis(
        priorities=priorities,
        breakpoints=tuple(candidates),
        status=status,
        truncation_reasons=tuple(reasons),
        coverage_status=analysis.coverage_status,
        coverage_reasons=analysis.coverage_reasons,
        receipt=provisional_receipt,
    )
    receipt = PriorityReceipt(
        schema=PRIORITY_SCHEMA,
        snapshot_digest=snapshot.digest,
        generation=snapshot.generation,
        scope_id=snapshot.scope_id,
        policy_digest=snapshot.policy_digest,
        evaluated_at=analysis.evaluated_at,
        path_analysis_digest=analysis.receipt.analysis_digest,
        result_digest=_digest(_priority_core(provisional)),
        status=status,
    )
    return PriorityAnalysis(
        priorities=priorities,
        breakpoints=tuple(candidates),
        status=status,
        truncation_reasons=tuple(reasons),
        coverage_status=analysis.coverage_status,
        coverage_reasons=analysis.coverage_reasons,
        receipt=receipt,
    )


def verify_priority_receipt(
    priority: object,
    snapshot: object,
    analysis: object,
) -> bool:
    """Verify every rendered/safety-relevant priority output and its CAS inputs."""
    if (
        not isinstance(priority, PriorityAnalysis)
        or not isinstance(snapshot, ExposureSnapshot)
        or not isinstance(analysis, PathAnalysis)
    ):
        return False
    try:
        require_current_analysis(analysis, snapshot)
        receipt = priority.receipt
        return bool(
            isinstance(receipt, PriorityReceipt)
            and receipt.schema == PRIORITY_SCHEMA
            and receipt.snapshot_digest == snapshot.digest
            and receipt.generation == snapshot.generation
            and receipt.scope_id == snapshot.scope_id
            and receipt.policy_digest == snapshot.policy_digest
            and receipt.evaluated_at == analysis.evaluated_at
            and receipt.path_analysis_digest == analysis.receipt.analysis_digest
            and receipt.status is priority.status
            and priority.coverage_status is analysis.coverage_status
            and priority.coverage_reasons == analysis.coverage_reasons
            and receipt.result_digest == _digest(_priority_core(priority))
        )
    except (AttributeError, TypeError, ValueError, RuntimeError, OverflowError):
        return False


__all__ = [
    "BreakpointCandidate",
    "BreakpointKind",
    "PathPriority",
    "PriorityAnalysis",
    "PriorityReceipt",
    "PriorityTier",
    "prioritize_exposure_paths",
    "verify_priority_receipt",
]
