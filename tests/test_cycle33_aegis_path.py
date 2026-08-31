from __future__ import annotations

import itertools
import os
import socket
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import replace

import pytest
from PySide6.QtGui import QColor

from angerona.core.eventbus import EventBus
from angerona.core.exposure_graph import (
    Applicability,
    AssertionState,
    CoverageStatus,
    CoverageDomain,
    DEFAULT_POLICY_DIGEST,
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
    build_relationship_absence_attestation,
    evaluate_snapshot_coverage,
    verify_coverage_manifest,
    verify_relationship_absence_attestation,
    verify_snapshot_digest,
)
from angerona.core.exposure_paths import (
    AnalysisCASConflict,
    PathClassification,
    PathLimits,
    SelectionMode,
    analyze_exposure_paths,
    require_current_analysis,
    simulate_breakpoints,
    verify_analysis_receipt,
)
from angerona.core.exposure_priority import (
    PriorityTier,
    prioritize_exposure_paths,
    verify_priority_receipt,
)
from angerona.gui.aegis_path import AegisPathDialog, AegisPathWidget
from angerona.modules.exposure_graph_guard import ExposureGraphGuardModule


NOW = 1_900_000_000.0


def _evidence(
    evidence_id: str,
    *,
    generation: int = 7,
    freshness: EvidenceFreshness = EvidenceFreshness.CURRENT,
    confidence: float = 0.9,
    expires_at: float = NOW + 600,
    provenance: EvidenceProvenance = EvidenceProvenance.SENSOR,
    source: str = "local-sensor-fixture",
) -> EvidenceBinding:
    return EvidenceBinding(
        evidence_id=evidence_id,
        source=source,
        provenance=provenance,
        freshness=freshness,
        confidence=confidence,
        privacy=PrivacyClass.SENSITIVE,
        generation=generation,
        observed_at=NOW - 10,
        expires_at=expires_at,
        digest="sha256:" + "a" * 64,
    )


def _edge(
    edge_id: str,
    source: str,
    target: str,
    *,
    kind: EdgeKind = EdgeKind.REACHES,
    assertion: AssertionState = AssertionState.CONFIRMED,
    applicability: Applicability = Applicability.EXACT,
    freshness: EvidenceFreshness = EvidenceFreshness.CURRENT,
    generation: int = 7,
) -> ExposureEdge:
    provenance = (
        EvidenceProvenance.SCANNER
        if kind is EdgeKind.AFFECTED_BY
        else EvidenceProvenance.SENSOR
    )
    return ExposureEdge(
        edge_id,
        source,
        target,
        kind,
        assertion,
        applicability,
        _evidence(
            f"evidence-{edge_id}",
            freshness=freshness,
            generation=generation,
            provenance=provenance,
        ),
        f"Exact fixture reason for {edge_id}",
        observed_version=("1.2.3" if kind is EdgeKind.AFFECTED_BY else ""),
        affected_range=("<2.0.0" if kind is EdgeKind.AFFECTED_BY else ""),
    )


def _snapshot(nodes, edges, *, generation: int = 7, observed_at: float = NOW, **kwargs):
    scope_id = kwargs.get("scope_id", "local-host")
    policy_digest = kwargs.get("policy_digest", DEFAULT_POLICY_DIGEST)
    manifest = build_coverage_manifest(
        nodes,
        edges,
        scope_id=scope_id,
        policy_digest=policy_digest,
        attested_at=observed_at,
        expires_at=observed_at + 600,
    )
    return build_exposure_snapshot(
        nodes,
        edges,
        generation=generation,
        observed_at=observed_at,
        coverage_manifest=manifest,
        **kwargs,
    )


def _golden_graph(*, generation: int = 7):
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Internet gateway"),
        ExposureNode("route-a", NodeKind.SERVICE, "Route A"),
        ExposureNode("route-b", NodeKind.IDENTITY, "Route B"),
        ExposureNode("choke", NodeKind.CONTROL, "Shared policy", control_effectiveness=0.3),
        ExposureNode("target-a", NodeKind.TARGET, "Payroll", criticality=5),
        ExposureNode("target-b", NodeKind.DATA, "Engineering", criticality=4),
    )
    edges = (
        _edge("e1", "entry", "route-a", generation=generation),
        _edge("e2", "entry", "route-b", generation=generation),
        _edge("e3", "route-a", "choke", generation=generation),
        _edge("e4", "route-b", "choke", generation=generation),
        _edge("e5", "choke", "target-a", generation=generation),
        _edge("e6", "choke", "target-b", generation=generation),
        _edge("cycle", "choke", "route-a", generation=generation),
    )
    return _snapshot(
        nodes,
        edges,
        generation=generation,
        observed_at=NOW,
    )


def _analyze(snapshot, **kwargs):
    kwargs.setdefault("clock", lambda: NOW)
    return analyze_exposure_paths(
        snapshot,
        expected_generation=snapshot.generation,
        expected_digest=snapshot.digest,
        expected_scope_id=snapshot.scope_id,
        expected_policy_digest=snapshot.policy_digest,
        **kwargs,
    )


def test_snapshot_digest_is_immutable_and_independent_of_input_order() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("middle", NodeKind.SERVICE, "Middle"),
        ExposureNode("target", NodeKind.TARGET, "Target", criticality=5),
    )
    edges = (
        _edge("edge-a", "entry", "middle"),
        _edge("edge-b", "middle", "target"),
    )
    digests = {
        _snapshot(
            node_order,
            edge_order,
            generation=7,
            observed_at=NOW,
        ).digest
        for node_order in itertools.permutations(nodes)
        for edge_order in itertools.permutations(edges)
    }
    assert len(digests) == 1
    snapshot = _snapshot(
        nodes, edges, generation=7, observed_at=NOW
    )
    assert verify_snapshot_digest(snapshot)
    assert snapshot.nodes == tuple(sorted(nodes, key=lambda row: row.node_id))
    assert snapshot.edges == tuple(sorted(edges, key=lambda row: row.edge_id))
    with pytest.raises(Exception):
        snapshot.nodes += (nodes[0],)  # type: ignore[misc]


def test_order_independent_overflow_is_explicit_and_orphans_are_counted() -> None:
    nodes = (
        ExposureNode("a", NodeKind.ENTRY_POINT, "A"),
        ExposureNode("b", NodeKind.SERVICE, "B"),
        ExposureNode("c", NodeKind.TARGET, "C"),
        ExposureNode("z", NodeKind.TARGET, "Z"),
    )
    edges = (
        _edge("a-edge", "a", "b"),
        _edge("b-edge", "b", "c"),
        _edge("z-edge", "c", "z"),
    )
    left = _snapshot(
        nodes, edges, generation=7, observed_at=NOW, max_nodes=3, max_edges=3
    )
    right = _snapshot(
        tuple(reversed(nodes)),
        tuple(reversed(edges)),
        generation=7,
        observed_at=NOW,
        max_nodes=3,
        max_edges=3,
    )
    assert left.digest == right.digest
    assert left.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert left.dropped_nodes == 1
    assert left.dropped_edges == 1
    assert set(left.truncation_reasons) == {"node_limit", "edge_endpoint_not_admitted"}


def test_attacker_sized_sequence_stops_before_indexing_and_is_explicit() -> None:
    class OversizedNodes(Sequence):
        def __len__(self):
            return 131_073

        def __getitem__(self, _index):
            raise AssertionError("hard-limit input must not be traversed")

    snapshot = build_exposure_snapshot(
        OversizedNodes(), (), generation=7, observed_at=NOW
    )
    assert snapshot.nodes == ()
    assert snapshot.dropped_nodes == 131_073
    assert snapshot.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert "node_hard_input_limit" in snapshot.truncation_reasons


def test_closed_enums_and_exact_cve_applicability_fail_closed() -> None:
    with pytest.raises(ValueError, match="closed NodeKind"):
        ExposureNode("node", "asset", "Asset")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exact applicability"):
        _edge(
            "cve-edge",
            "asset",
            "cve",
            kind=EdgeKind.AFFECTED_BY,
            applicability=Applicability.ASSUMED,
        )
    with pytest.raises(ValueError, match="cannot close"):
        _edge(
            "closed-edge",
            "asset",
            "target",
            assertion=AssertionState.CLOSED,
            freshness=EvidenceFreshness.STALE,
        )
    with pytest.raises(ValueError, match="unbounded evidence"):
        replace(
            _edge("unbounded", "asset", "target"),
            assertion=AssertionState.CLOSED,
            evidence=_evidence("unbounded-closure", expires_at=0.0),
        )
    with pytest.raises(ValueError, match="immutable tuple"):
        ExposureNode(
            "mutable", NodeKind.ASSET, "Mutable", properties=[("key", "value")]
        )  # type: ignore[arg-type]


def test_generation_mismatch_and_tampered_snapshot_are_rejected() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    with pytest.raises(ValueError, match="generation"):
        _snapshot(
            nodes,
            (_edge("edge", "entry", "target", generation=6),),
            generation=7,
            observed_at=NOW,
        )
    valid = _snapshot(
        nodes,
        (_edge("edge", "entry", "target"),),
        generation=7,
        observed_at=NOW,
    )
    tampered = replace(valid, observed_at=valid.observed_at + 1)
    assert not verify_snapshot_digest(tampered)
    with pytest.raises(AnalysisCASConflict):
        _analyze(tampered)


def test_expired_closure_future_evidence_and_non_cve_affected_edges_fail_closed() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    expired_closure = replace(
        _edge("closed", "entry", "target", assertion=AssertionState.CLOSED),
        evidence=_evidence("closure", expires_at=NOW - 1),
    )
    with pytest.raises(ValueError, match="expired evidence"):
        _snapshot(
            nodes, (expired_closure,), generation=7, observed_at=NOW
        )
    future = replace(
        _edge("future", "entry", "target"),
        evidence=replace(_evidence("future-evidence"), observed_at=NOW + 1),
    )
    with pytest.raises(ValueError, match="after its snapshot"):
        _snapshot(nodes, (future,), generation=7, observed_at=NOW)
    not_a_cve = _edge(
        "not-cve", "entry", "target", kind=EdgeKind.AFFECTED_BY
    )
    with pytest.raises(ValueError, match="affected_by direction"):
        _snapshot(
            nodes, (not_a_cve,), generation=7, observed_at=NOW
        )


def test_cycle_safe_enumeration_has_golden_choke_and_blast_radius() -> None:
    snapshot = _golden_graph()
    analysis = _analyze(snapshot)
    assert analysis.status is ResourceStatus.COMPLETE
    assert len(analysis.confirmed_paths) == 4
    assert not analysis.speculative_paths
    assert all(len(path.node_ids) == len(set(path.node_ids)) for path in analysis.all_paths)
    assert analysis.choke_points[0].node_id == "choke"
    assert analysis.choke_points[0].paths_through == 4
    assert analysis.choke_points[0].coverage == 1.0
    entry_radius = next(row for row in analysis.blast_radius if row.node_id == "entry")
    assert entry_radius.reachable_target_ids == ("target-a", "target-b")
    assert entry_radius.confirmed_target_ids == ("target-a", "target-b")
    assert verify_analysis_receipt(analysis, snapshot)
    changed_parameters = replace(
        analysis,
        receipt=replace(analysis.receipt, parameters_digest="sha256:" + "0" * 64),
    )
    assert not verify_analysis_receipt(changed_parameters, snapshot)


@pytest.mark.parametrize(
    "limits,expected_reason",
    [
        (PathLimits(max_depth=2), "depth_limit"),
        (PathLimits(max_paths=1), "path_limit"),
        (PathLimits(max_expansions=1), "expansion_limit"),
    ],
)
def test_every_path_resource_cutoff_is_explicit(limits, expected_reason) -> None:
    analysis = _analyze(_golden_graph(), limits=limits)
    assert analysis.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert expected_reason in analysis.truncation_reasons


def test_timeout_is_explicit_and_partial_results_never_claim_complete() -> None:
    calls = [0]

    def bounded_clock() -> float:
        calls[0] += 1
        # The verification ledger now starts before hashing. Keep preflight in
        # budget, then expire during graph analysis to exercise partial status.
        return 0.0 if calls[0] < 1_900 else 2.0

    analysis = _analyze(
        _golden_graph(),
        limits=PathLimits(timeout_ms=1_000),
        monotonic=bounded_clock,
    )
    assert analysis.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert "analysis_timeout" in analysis.truncation_reasons


@pytest.mark.parametrize(
    "freshness",
    [EvidenceFreshness.STALE, EvidenceFreshness.MISSING, EvidenceFreshness.UNKNOWN],
)
def test_stale_missing_and_unknown_evidence_remain_visible_but_never_confirmed(
    freshness,
) -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target", criticality=5),
    )
    snapshot = _snapshot(
        nodes,
        (_edge("edge", "entry", "target", freshness=freshness),),
        generation=7,
        observed_at=NOW,
    )
    analysis = _analyze(snapshot)
    assert not analysis.confirmed_paths
    assert len(analysis.speculative_paths) == 1
    assert analysis.speculative_paths[0].classification is PathClassification.SPECULATIVE
    assert freshness.value in " ".join(analysis.speculative_paths[0].reasons)


def test_expired_current_evidence_cannot_confirm_a_path() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    edge = replace(
        _edge("edge", "entry", "target"),
        evidence=_evidence("expired", expires_at=NOW - 1),
    )
    snapshot = _snapshot(
        nodes, (edge,), generation=7, observed_at=NOW
    )
    assert len(_analyze(snapshot).speculative_paths) == 1


def _cve_graph(*, stale_route: bool = False):
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("asset", NodeKind.ASSET, "App server", criticality=3),
        ExposureNode(
            "vuln",
            NodeKind.VULNERABILITY,
            "Package finding",
            cve_id="CVE-2026-12345",
            known_exploited=True,
            epss=0.91,
            threat_evidence=_evidence(
                "threat-CVE-2026-12345",
                provenance=EvidenceProvenance.THREAT_INTELLIGENCE,
                source="local-threat-feed-fixture",
            ),
        ),
        ExposureNode("target", NodeKind.TARGET, "Crown jewels", criticality=5),
    )
    edges = (
        _edge(
            "route",
            "entry",
            "asset",
            freshness=(EvidenceFreshness.STALE if stale_route else EvidenceFreshness.CURRENT),
        ),
        _edge("applies", "asset", "vuln", kind=EdgeKind.AFFECTED_BY),
        _edge("impact", "vuln", "target", kind=EdgeKind.IMPACTS),
    )
    return _snapshot(
        nodes, edges, generation=7, observed_at=NOW
    )


def test_kev_epss_criticality_and_control_priority_is_explainable_not_probability() -> None:
    snapshot = _cve_graph()
    analysis = _analyze(snapshot)
    priority = prioritize_exposure_paths(snapshot, analysis)
    item = priority.priorities[0]
    assert item.tier in {PriorityTier.IMMEDIATE, PriorityTier.HIGH}
    assert item.kev_cves == ("CVE-2026-12345",)
    assert item.epss_signals == (("CVE-2026-12345", 0.91),)
    assert item.score_is_breach_probability is False
    assert "not breach probability" in " ".join(item.limitations)
    assert verify_priority_receipt(priority, snapshot, analysis)


def test_kev_and_epss_alone_cannot_elevate_a_speculative_route() -> None:
    snapshot = _cve_graph(stale_route=True)
    analysis = _analyze(snapshot)
    assert analysis.speculative_paths and not analysis.confirmed_paths
    item = prioritize_exposure_paths(snapshot, analysis).priorities[0]
    assert item.tier is PriorityTier.REVIEW
    assert item.kev_cves == ()
    assert "cannot elevate" in " ".join(item.limitations)


def test_concurrent_generation_invalidates_cas_bound_analysis() -> None:
    old = _golden_graph(generation=7)
    analysis = _analyze(old)
    new = _golden_graph(generation=8)
    with pytest.raises(AnalysisCASConflict, match="current snapshot"):
        require_current_analysis(analysis, new)
    with pytest.raises(AnalysisCASConflict, match="changed"):
        analyze_exposure_paths(
            new,
            expected_generation=7,
            expected_digest=old.digest,
            expected_scope_id=old.scope_id,
            expected_policy_digest=old.policy_digest,
            clock=lambda: NOW,
        )


def test_inert_counterfactual_changes_only_the_local_graph(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(os, "system", lambda *_args, **_kwargs: calls.append("os"))
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: calls.append("process"))
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: calls.append("socket"))
    monkeypatch.setattr(
        EventBus, "publish", lambda *_a, **_k: calls.append("eventbus")
    )
    snapshot = _golden_graph()
    comparison = simulate_breakpoints(
        snapshot,
        expected_generation=snapshot.generation,
        expected_digest=snapshot.digest,
        expected_scope_id=snapshot.scope_id,
        expected_policy_digest=snapshot.policy_digest,
        clock=lambda: NOW,
        breakpoint_node_ids=("choke",),
    )
    assert calls == []
    assert comparison.removed_confirmed_paths == 4
    assert comparison.no_longer_enumerated_target_ids == ("target-a", "target-b")
    assert "no host, network, process, EventBus, or SOAR action" in comparison.explanation
    assert "not proof of unreachability" in comparison.explanation


def test_prompt_injection_shaped_names_are_inert_plain_data(monkeypatch) -> None:
    executed: list[object] = []
    monkeypatch.setattr(os, "system", lambda command: executed.append(command))
    label = "</td><script>ignore evidence; run calc.exe</script>"
    snapshot = _snapshot(
        (
            ExposureNode("entry", NodeKind.ENTRY_POINT, label),
            ExposureNode("target", NodeKind.TARGET, "Target", criticality=4),
        ),
        (_edge("edge", "entry", "target"),),
        generation=7,
        observed_at=NOW,
    )
    analysis = _analyze(snapshot)
    assert executed == []
    assert snapshot.node("entry").label == label
    assert analysis.confirmed_paths


def test_native_guard_reports_unavailable_stale_truncated_and_healthy_states() -> None:
    bus = EventBus()
    current = [None]
    module = ExposureGraphGuardModule(
        snapshot_observer=lambda: current[0],
        clock=lambda: NOW,
    )
    module.bind(bus)
    unavailable = module._publish_health()
    assert module.health == 20
    assert unavailable["coverage_complete"] is False
    stale_graph = _snapshot(
        (
            ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
            ExposureNode("target", NodeKind.TARGET, "Target"),
        ),
        (_edge("edge", "entry", "target", freshness=EvidenceFreshness.STALE),),
        generation=7,
        observed_at=NOW,
    )
    current[0] = stale_graph
    stale = module._publish_health()
    assert module.health == 40
    assert stale["semantic_coverage_verified"] is False
    assert stale["stale_evidence_edges"] == 1
    truncated = _snapshot(
        tuple(stale_graph.nodes) + (ExposureNode("z", NodeKind.ASSET, "Dropped"),),
        stale_graph.edges,
        generation=7,
        observed_at=NOW,
        max_nodes=2,
    )
    current[0] = truncated
    module._publish_health()
    assert module.health == 35
    current[0] = _golden_graph()
    complete = module._publish_health()
    assert module.health == 100
    assert complete["coverage_complete"] is True
    assert all(
        event.details.get("response_authority") == "observe-only"
        and not event.details.get("enforcement_performed")
        for event in bus.recent()
    )
    assert module.version == "1.13.0"
    assert module.capability_mode == "observe"
    assert module.egress == "none"


def test_guard_self_test_and_observer_contract() -> None:
    module = ExposureGraphGuardModule(snapshot_observer=lambda: object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="contract"):
        module.observe_once()
    good = ExposureGraphGuardModule()
    assert good.self_test()[0]


def test_embeddable_ui_is_sortable_clickable_red_for_unknown_and_inert() -> None:
    snapshot = _cve_graph(stale_route=True)
    widget = AegisPathWidget(snapshot)
    assert widget.path_table.isSortingEnabled()
    assert widget.target_table.isSortingEnabled()
    assert widget.entry_table.isSortingEnabled()
    assert widget.breakpoint_table.isSortingEnabled()
    assert widget._limits.timeout_ms <= 150
    assert "single-user" in widget.boundary_label.text()
    assert "SENSITIVE/RESTRICTED" in widget.boundary_label.text()
    assert widget.path_table.rowCount() == 1
    assert widget.path_table.item(0, 0).text() == "speculative"
    assert widget.path_table.item(0, 0).foreground().color() == QColor("#ef4444")
    widget.path_table.selectRow(0)
    assert "evidence-route" in widget.details.toPlainText()
    assert "freshness" in widget.details.toPlainText()
    assert widget.breakpoint_table.rowCount() > 0
    widget.breakpoint_table.selectRow(0)
    assert widget.what_if_button.isEnabled()
    widget.what_if_button.click()
    assert "What if:" in widget.comparison_label.text()
    assert "inert" in widget.comparison_label.text().casefold()
    dialog = AegisPathDialog(snapshot)
    assert dialog.widget.analysis is not None
    dialog.close()
    widget.close()


def test_ui_reuses_immutable_snapshot_indexes_for_selection_details() -> None:
    snapshot = _golden_graph()
    widget = AegisPathWidget(snapshot)
    node_index = widget._node_index
    edge_index = widget._edge_index
    adjacent_edges = widget._adjacent_edges
    path_index = widget._path_index
    breakpoint_index = widget._breakpoint_index

    assert tuple(node_index) == tuple(node.node_id for node in snapshot.nodes)
    assert tuple(edge_index) == tuple(edge.edge_id for edge in snapshot.edges)
    assert tuple(edge.edge_id for edge in adjacent_edges["choke"]) == tuple(
        edge.edge_id
        for edge in snapshot.edges
        if "choke" in {edge.source_id, edge.target_id}
    )
    assert tuple(path_index) == tuple(path.path_id for path in widget.analysis.all_paths)
    assert tuple(breakpoint_index) == tuple(
        candidate.candidate_id
        for candidate in widget.priority_analysis.breakpoints
    )

    widget._show_node("choke")
    widget.path_table.selectRow(0)
    widget.breakpoint_table.selectRow(0)
    assert widget._node_index is node_index
    assert widget._edge_index is edge_index
    assert widget._adjacent_edges is adjacent_edges
    assert widget._path_index is path_index
    assert widget._breakpoint_index is breakpoint_index
    widget.close()


def test_ui_missing_snapshot_is_red_unknown_and_does_not_infer_safety() -> None:
    widget = AegisPathWidget()
    assert "UNKNOWN" in widget.status_label.text()
    assert "#ef4444" in widget.status_label.styleSheet()
    assert "never proves" in widget.comparison_label.text()
    widget.close()


def test_ui_renders_prompt_injection_label_as_plain_text() -> None:
    label = "<img src=x onerror='run calc'>"
    snapshot = _snapshot(
        (
            ExposureNode("entry", NodeKind.ENTRY_POINT, label),
            ExposureNode("target", NodeKind.TARGET, "Target", criticality=4),
        ),
        (_edge("edge", "entry", "target"),),
        generation=7,
        observed_at=NOW,
    )
    widget = AegisPathWidget(snapshot)
    widget.entry_table.selectRow(0)
    assert label in widget.details.toPlainText()
    widget.close()


def test_intermediate_target_does_not_hide_downstream_target() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("mid", NodeKind.TARGET, "Intermediate target", criticality=4),
        ExposureNode("deep", NodeKind.TARGET, "Downstream target", criticality=5),
    )
    snapshot = _snapshot(
        nodes,
        (
            _edge("to-mid", "entry", "mid"),
            _edge("to-deep", "mid", "deep"),
        ),
    )
    analysis = _analyze(snapshot)
    assert {path.target_id for path in analysis.confirmed_paths} == {"mid", "deep"}
    assert next(path for path in analysis.confirmed_paths if path.target_id == "deep").node_ids == (
        "entry",
        "mid",
        "deep",
    )


def test_processing_complete_is_not_semantic_coverage_and_empty_never_green() -> None:
    empty_manifest = build_coverage_manifest(
        (), (), attested_at=NOW, expires_at=NOW + 600
    )
    empty = build_exposure_snapshot(
        (),
        (),
        generation=7,
        observed_at=NOW,
        coverage_manifest=empty_manifest,
    )
    assert empty.status is ResourceStatus.COMPLETE
    assert empty.coverage_status is CoverageStatus.UNUSABLE
    assert "empty_graph" in empty.coverage_reasons
    assert evaluate_snapshot_coverage(empty, at_time=NOW)[0] is CoverageStatus.UNUSABLE
    module = ExposureGraphGuardModule(
        snapshot_observer=lambda: empty,
        clock=lambda: NOW,
        provider_timeout_seconds=0.5,
    )
    module.bind(EventBus())
    details = module._publish_health()
    assert details["processing_complete"] is True
    assert details["semantic_coverage_verified"] is False
    assert module.health < 100

    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    unmanifested = build_exposure_snapshot(
        nodes,
        (_edge("edge", "entry", "target"),),
        generation=7,
        observed_at=NOW,
    )
    assert unmanifested.status is ResourceStatus.COMPLETE
    assert unmanifested.coverage_status is CoverageStatus.UNVERIFIED


def test_analysis_time_not_snapshot_time_controls_evidence_expiry() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    edge = replace(
        _edge("edge", "entry", "target"),
        evidence=_evidence("short-lived", expires_at=NOW + 5),
    )
    snapshot = _snapshot(nodes, (edge,))
    analysis = _analyze(snapshot, clock=lambda: NOW + 10)
    assert not analysis.confirmed_paths
    assert "evidence-expired-at-analysis" in " ".join(
        analysis.speculative_paths[0].reasons
    )
    closed_edge = replace(
        _edge("closed", "entry", "target"),
        assertion=AssertionState.CLOSED,
        evidence=_evidence("short-lived-closure", expires_at=NOW + 5),
    )
    closed_snapshot = _snapshot(nodes, (closed_edge,))
    expired_closure = _analyze(closed_snapshot, clock=lambda: NOW + 10)
    assert not expired_closure.confirmed_paths
    assert len(expired_closure.speculative_paths) == 1
    assert "assertion-closed" in " ".join(expired_closure.speculative_paths[0].reasons)


def test_scope_and_policy_are_part_of_the_analysis_cas_boundary() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    snapshot = _snapshot(nodes, (_edge("edge", "entry", "target"),))
    other_policy = "sha256:" + "b" * 64
    with pytest.raises(AnalysisCASConflict, match="scope, or policy"):
        analyze_exposure_paths(
            snapshot,
            expected_generation=snapshot.generation,
            expected_digest=snapshot.digest,
            expected_scope_id="substituted-host",
            expected_policy_digest=snapshot.policy_digest,
            clock=lambda: NOW,
        )
    with pytest.raises(AnalysisCASConflict, match="scope, or policy"):
        analyze_exposure_paths(
            snapshot,
            expected_generation=snapshot.generation,
            expected_digest=snapshot.digest,
            expected_scope_id=snapshot.scope_id,
            expected_policy_digest=other_policy,
            clock=lambda: NOW,
        )


def test_provider_timeout_is_bounded_single_flight_and_module_stop_is_responsive() -> None:
    release = threading.Event()
    started = threading.Event()

    def blocked_provider():
        started.set()
        release.wait(5.0)
        return None

    module = ExposureGraphGuardModule(
        snapshot_observer=blocked_provider,
        provider_timeout_seconds=0.02,
    )
    module.bind(EventBus())
    before = time.monotonic()
    details = module._publish_health()
    assert time.monotonic() - before < 0.5
    assert details["coverage_reason"] == "TimeoutError"
    first_thread = module._provider_thread
    module._publish_health()
    assert module._provider_thread is first_thread

    lifecycle = ExposureGraphGuardModule(
        snapshot_observer=blocked_provider,
        provider_timeout_seconds=30.0,
    )
    lifecycle.bind(EventBus())
    started.clear()
    lifecycle.start()
    assert started.wait(0.5)
    lifecycle.stop()
    assert lifecycle._thread is not None
    lifecycle._thread.join(timeout=0.5)
    assert not lifecycle._thread.is_alive()
    release.set()


def test_frontier_work_memory_and_cancellation_are_explicit_bounds() -> None:
    frontier = _analyze(
        _golden_graph(),
        limits=PathLimits(max_frontier=1),
    )
    assert frontier.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert "frontier_limit" in frontier.truncation_reasons

    targets = tuple(
        ExposureNode(f"target-{index:03d}", NodeKind.TARGET, f"Target {index}")
        for index in range(400)
    )
    nodes = (ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),) + targets
    edges = tuple(
        _edge(f"edge-{index:03d}", "entry", target.node_id)
        for index, target in enumerate(targets)
    )
    with pytest.raises(AnalysisCASConflict, match="bounded analysis preflight"):
        _analyze(
            _snapshot(nodes, edges),
            limits=PathLimits(
                max_paths=1_000,
                max_expansions=1_000,
                max_frontier=1_000,
                max_work_bytes=64 * 1024,
            ),
        )

    with pytest.raises(AnalysisCASConflict, match="bounded analysis preflight"):
        _analyze(_golden_graph(), cancelled=lambda: True)


def test_threat_and_version_signals_require_current_bound_evidence() -> None:
    with pytest.raises(ValueError, match="bound threat evidence"):
        ExposureNode(
            "vuln",
            NodeKind.VULNERABILITY,
            "Unbound signal",
            cve_id="CVE-2026-9999",
            known_exploited=True,
        )
    with pytest.raises(ValueError, match="threat-intelligence provenance"):
        ExposureNode(
            "vuln",
            NodeKind.VULNERABILITY,
            "Wrong authority",
            cve_id="CVE-2026-9999",
            epss=0.8,
            threat_evidence=_evidence("wrong-authority"),
        )
    with pytest.raises(ValueError, match="observed and affected versions"):
        ExposureEdge(
            "applies",
            "asset",
            "vuln",
            EdgeKind.AFFECTED_BY,
            AssertionState.CONFIRMED,
            Applicability.EXACT,
            _evidence("scanner", provenance=EvidenceProvenance.SCANNER),
            "Missing version basis",
        )

    snapshot = _cve_graph()
    stale_nodes = tuple(
        replace(
            node,
            threat_evidence=replace(node.threat_evidence, expires_at=NOW + 1),
        )
        if node.node_id == "vuln"
        else node
        for node in snapshot.nodes
    )
    stale_snapshot = _snapshot(stale_nodes, snapshot.edges)
    analysis = _analyze(stale_snapshot, clock=lambda: NOW + 2)
    item = prioritize_exposure_paths(stale_snapshot, analysis).priorities[0]
    assert item.kev_cves == ()
    assert item.epss_signals == ()


def test_non_path_edge_semantics_and_endpoint_directions_fail_closed() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("asset", NodeKind.ASSET, "Asset"),
        ExposureNode("control", NodeKind.CONTROL, "Control"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    protected = ExposureEdge(
        "protected",
        "asset",
        "control",
        EdgeKind.PROTECTED_BY,
        AssertionState.CONFIRMED,
        Applicability.EXACT,
        _evidence("control-evidence"),
        "Control protects the asset; this is not attacker movement",
    )
    snapshot = _snapshot(
        nodes,
        (
            _edge("entry-asset", "entry", "asset"),
            protected,
            _edge("control-target", "control", "target"),
        ),
    )
    assert _analyze(snapshot).all_paths == ()

    with pytest.raises(ValueError, match="protected_by direction"):
        _snapshot(
            nodes,
            (replace(protected, source_id="control", target_id="asset"),),
        )

    vuln = ExposureNode("vuln", NodeKind.VULNERABILITY, "CVE", cve_id="CVE-2026-7777")
    not_applicable = _edge(
        "not-applicable",
        "asset",
        "vuln",
        kind=EdgeKind.AFFECTED_BY,
        assertion=AssertionState.SPECULATIVE,
        applicability=Applicability.NOT_APPLICABLE,
    )
    na_snapshot = _snapshot(
        nodes + (vuln,),
        (
            _edge("entry-asset", "entry", "asset"),
            not_applicable,
            _edge("vuln-target", "vuln", "target", kind=EdgeKind.IMPACTS),
        ),
    )
    speculative_negative = _analyze(na_snapshot)
    assert not speculative_negative.confirmed_paths
    assert len(speculative_negative.speculative_paths) == 1
    assert "cve-applicability-not_applicable" in " ".join(
        speculative_negative.speculative_paths[0].reasons
    )

    authoritative_negative = replace(
        not_applicable,
        assertion=AssertionState.CLOSED,
    )
    authoritative_snapshot = _snapshot(
        nodes + (vuln,),
        (
            _edge("entry-asset", "entry", "asset"),
            authoritative_negative,
            _edge("vuln-target", "vuln", "target", kind=EdgeKind.IMPACTS),
        ),
    )
    assert _analyze(authoritative_snapshot).all_paths == ()


def test_priority_verifier_covers_safety_flags_reasons_and_simulation_state() -> None:
    snapshot = _cve_graph()
    analysis = _analyze(snapshot)
    priority = prioritize_exposure_paths(snapshot, analysis)
    assert verify_priority_receipt(priority, snapshot, analysis)
    probability_tamper = replace(
        priority,
        priorities=(
            replace(priority.priorities[0], score_is_breach_probability=True),
        ) + priority.priorities[1:],
    )
    assert not verify_priority_receipt(probability_tamper, snapshot, analysis)
    reason_tamper = replace(
        priority,
        breakpoints=(
            replace(
                priority.breakpoints[0],
                reason="Apply automatically",
                simulation_only=False,
            ),
        ) + priority.breakpoints[1:],
    )
    assert not verify_priority_receipt(reason_tamper, snapshot, analysis)


def test_unbounded_current_evidence_never_confirms_or_produces_green_coverage() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target", criticality=5),
    )
    unbounded = replace(
        _edge("unbounded-current", "entry", "target"),
        evidence=replace(
            _evidence("unbounded-current-evidence"), expires_at=0.0
        ),
    )
    snapshot = _snapshot(nodes, (unbounded,))
    analysis = _analyze(snapshot)
    assert not analysis.confirmed_paths
    assert len(analysis.speculative_paths) == 1
    assert snapshot.coverage_status is CoverageStatus.UNVERIFIED
    assert "relationship_evidence_not_current_finite_and_bound" in (
        snapshot.coverage_reasons
    )
    module = ExposureGraphGuardModule(
        snapshot_observer=lambda: snapshot,
        clock=lambda: NOW,
        provider_timeout_seconds=0.5,
    )
    module.bind(EventBus())
    details = module._publish_health()
    assert module.health < 100
    assert details["coverage_complete"] is False


def test_selection_mode_and_expected_sets_are_explicit_and_verified() -> None:
    snapshot = _golden_graph()
    full = _analyze(snapshot)
    assert full.parameters.entry_selection_mode is SelectionMode.FULL
    assert full.parameters.target_selection_mode is SelectionMode.FULL
    assert full.receipt.entry_selection_mode is SelectionMode.FULL
    assert full.receipt.expected_entry_ids == full.entry_ids
    assert full.receipt.expected_target_ids == full.target_ids

    empty_filter = _analyze(snapshot, entry_ids=())
    assert empty_filter.parameters.entry_selection_mode is SelectionMode.FILTERED
    assert empty_filter.receipt.entry_selection_mode is SelectionMode.FILTERED
    assert empty_filter.entry_ids == ()
    assert empty_filter.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert "filtered_entry_selection_empty" in empty_filter.truncation_reasons
    assert verify_analysis_receipt(empty_filter, snapshot)

    substituted = replace(
        empty_filter,
        parameters=replace(
            empty_filter.parameters,
            expected_entry_ids=("entry",),
        ),
    )
    assert not verify_analysis_receipt(substituted, snapshot)


def test_node_only_scope_requires_finite_authorized_absence_attestation() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    ordinary_manifest = build_coverage_manifest(
        nodes,
        (),
        attested_at=NOW,
        expires_at=NOW + 600,
    )
    ordinary = build_exposure_snapshot(
        nodes,
        (),
        generation=7,
        observed_at=NOW,
        coverage_manifest=ordinary_manifest,
    )
    assert ordinary.coverage_status is CoverageStatus.UNVERIFIED
    assert "authorized_relationship_absence_attestation_missing_or_invalid" in (
        ordinary.coverage_reasons
    )

    authority = _evidence(
        "relationship-absence-authority",
        provenance=EvidenceProvenance.ANALYST_ATTESTATION,
        source="authorized-local-coverage-owner",
    )
    absence = build_relationship_absence_attestation(
        scope_id="local-host",
        policy_digest=DEFAULT_POLICY_DIGEST,
        coverage_domain=CoverageDomain.EXPOSURE_RELATIONSHIPS,
        authority_id="local-coverage-owner",
        evidence=authority,
    )
    authorized_manifest = build_coverage_manifest(
        nodes,
        (),
        attested_at=NOW,
        expires_at=NOW + 600,
        relationship_absence=absence,
    )
    authorized = build_exposure_snapshot(
        nodes,
        (),
        generation=7,
        observed_at=NOW,
        coverage_manifest=authorized_manifest,
    )
    assert authorized.coverage_status is CoverageStatus.VERIFIED
    assert evaluate_snapshot_coverage(
        authorized, at_time=NOW + 601
    )[0] is CoverageStatus.UNVERIFIED


def test_direct_snapshots_enforce_caps_and_builder_invariants() -> None:
    entry = ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry")
    target = ExposureNode("target", NodeKind.TARGET, "Target")
    with pytest.raises(ValueError, match="hard structural"):
        ExposureSnapshot(
            schema="angerona.aegis-path.exposure-graph.v1",
            generation=7,
            observed_at=NOW,
            nodes=(entry,) * 16_385,
            edges=(),
            status=ResourceStatus.COMPLETE,
            truncation_reasons=(),
            dropped_nodes=0,
            dropped_edges=0,
            scope_id="local-host",
            policy_digest=DEFAULT_POLICY_DIGEST,
            coverage_manifest=None,
            coverage_status=CoverageStatus.UNVERIFIED,
            coverage_reasons=("coverage_manifest_missing",),
            digest="sha256:" + "0" * 64,
        )
    with pytest.raises(ValueError, match="unique and sorted"):
        ExposureSnapshot(
            schema="angerona.aegis-path.exposure-graph.v1",
            generation=7,
            observed_at=NOW,
            nodes=(target, entry),
            edges=(),
            status=ResourceStatus.COMPLETE,
            truncation_reasons=(),
            dropped_nodes=0,
            dropped_edges=0,
            scope_id="local-host",
            policy_digest=DEFAULT_POLICY_DIGEST,
            coverage_manifest=None,
            coverage_status=CoverageStatus.UNVERIFIED,
            coverage_reasons=("coverage_manifest_missing",),
            digest="sha256:" + "0" * 64,
        )


def test_what_if_propagates_unverified_semantic_coverage() -> None:
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Entry"),
        ExposureNode("target", NodeKind.TARGET, "Target"),
    )
    snapshot = build_exposure_snapshot(
        nodes,
        (_edge("edge", "entry", "target"),),
        generation=7,
        observed_at=NOW,
    )
    comparison = simulate_breakpoints(
        snapshot,
        expected_generation=snapshot.generation,
        expected_digest=snapshot.digest,
        expected_scope_id=snapshot.scope_id,
        expected_policy_digest=snapshot.policy_digest,
        breakpoint_edge_ids=("edge",),
        clock=lambda: NOW,
    )
    assert comparison.coverage_status is CoverageStatus.UNVERIFIED
    assert comparison.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
    assert "unverified semantic coverage" in comparison.explanation


def test_all_cycle33_verifiers_return_false_for_malformed_types() -> None:
    assert verify_coverage_manifest(None) is False
    assert verify_relationship_absence_attestation(
        None,
        scope_id="local-host",
        policy_digest=DEFAULT_POLICY_DIGEST,
        generation=7,
        at_time=NOW,
    ) is False
    assert verify_snapshot_digest(None) is False
    assert verify_analysis_receipt(None, None) is False
    assert verify_priority_receipt(None, None, None) is False
