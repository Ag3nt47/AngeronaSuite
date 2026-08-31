"""Embeddable, read-only AegisPath exposure-route workbench."""
from __future__ import annotations

import json

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from angerona.core.exposure_graph import (
    CoverageStatus,
    EvidenceFreshness,
    ExposureEdge,
    ExposureNode,
    ExposureSnapshot,
    ResourceStatus,
)
from angerona.core.exposure_paths import (
    ExposurePath,
    PathAnalysis,
    PathClassification,
    PathLimits,
    analyze_exposure_paths,
    simulate_breakpoints,
)
from angerona.core.exposure_priority import (
    BreakpointCandidate,
    PriorityAnalysis,
    prioritize_exposure_paths,
    verify_priority_receipt,
)


_UNKNOWN_RED = QColor("#ef4444")
_CONFIRMED_GREEN = QColor("#22c55e")
_MUTED = QColor("#94a3b8")
_GUI_MAX_NODES = 4_096
_GUI_MAX_EDGES = 16_384
_GUI_TIMEOUT_MS = 150
_GUI_MAX_FRONTIER = 2_000
_GUI_MAX_WORK_BYTES = 4 * 1024 * 1024
_GUI_SYNC_MAX_NODES = 256
_GUI_SYNC_MAX_EDGES = 1_024
_GUI_MAX_TABLE_ROWS = 512
_GUI_MAX_DETAIL_EDGES = 256


def _interactive_limits(requested: PathLimits | None) -> PathLimits:
    source = requested or PathLimits()
    if not isinstance(source, PathLimits):
        raise ValueError("limits must be PathLimits")
    return PathLimits(
        max_depth=source.max_depth,
        max_paths=min(source.max_paths, 512),
        max_expansions=min(source.max_expansions, 5_000),
        timeout_ms=min(source.timeout_ms, _GUI_TIMEOUT_MS),
        max_frontier=min(source.max_frontier, _GUI_MAX_FRONTIER),
        max_work_bytes=min(source.max_work_bytes, _GUI_MAX_WORK_BYTES),
    )


class _NumberItem(QTableWidgetItem):
    def __init__(self, value: int | float, rendered: str | None = None) -> None:
        super().__init__(str(value) if rendered is None else rendered)
        self._number = float(value)

    def __lt__(self, other) -> bool:
        if isinstance(other, _NumberItem):
            return self._number < other._number
        return super().__lt__(other)


def _table(headers: tuple[str, ...]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setSortingEnabled(True)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    return table


def _text_item(text: object, *, unknown: bool = False, payload=None) -> QTableWidgetItem:
    item = QTableWidgetItem(str(text))
    item.setToolTip(str(text))
    if unknown:
        item.setForeground(_UNKNOWN_RED)
    if payload is not None:
        item.setData(Qt.UserRole, payload)
    return item


def _analyze_snapshot(
    snapshot: ExposureSnapshot, limits: PathLimits
) -> tuple[PathAnalysis, PriorityAnalysis]:
    analysis = analyze_exposure_paths(
        snapshot,
        expected_generation=snapshot.generation,
        expected_digest=snapshot.digest,
        expected_scope_id=snapshot.scope_id,
        expected_policy_digest=snapshot.policy_digest,
        limits=limits,
    )
    priority = prioritize_exposure_paths(snapshot, analysis)
    if not verify_priority_receipt(priority, snapshot, analysis):
        raise ValueError("priority receipt invalid")
    return analysis, priority


class _AnalysisSignals(QObject):
    finished = Signal(object, object, object, int, str)


class _AnalysisTask(QRunnable):
    def __init__(
        self, snapshot: ExposureSnapshot, limits: PathLimits, token: int
    ) -> None:
        super().__init__()
        self.snapshot = snapshot
        self.limits = limits
        self.token = token
        self.signals = _AnalysisSignals()

    def run(self) -> None:
        try:
            analysis, priority = _analyze_snapshot(self.snapshot, self.limits)
        except Exception as exc:
            analysis, priority = None, None
            error = type(exc).__name__
        else:
            error = ""
        self.signals.finished.emit(
            self.snapshot, analysis, priority, self.token, error
        )


class AegisPathWidget(QWidget):
    """Sortable/clickable evidence, route, target, and breakpoint explorer."""

    def __init__(
        self,
        snapshot: ExposureSnapshot | None = None,
        parent=None,
        *,
        limits: PathLimits | None = None,
    ) -> None:
        super().__init__(parent)
        self._snapshot: ExposureSnapshot | None = None
        self._analysis: PathAnalysis | None = None
        self._priority: PriorityAnalysis | None = None
        # ExposureSnapshot is immutable.  Index its bounded contents once when
        # a verified analysis is accepted instead of rebuilding full maps (or
        # rescanning every edge) on each operator selection.
        self._node_index: dict[str, ExposureNode] = {}
        self._edge_index: dict[str, ExposureEdge] = {}
        self._adjacent_edges: dict[str, tuple[ExposureEdge, ...]] = {}
        self._path_index: dict[str, ExposurePath] = {}
        self._breakpoint_index: dict[str, BreakpointCandidate] = {}
        self._limits = _interactive_limits(limits)
        self._analysis_token = 0
        self._analysis_pending = False
        self._thread_pool = QThreadPool(self)
        self._thread_pool.setMaxThreadCount(1)
        self._active_task: _AnalysisTask | None = None

        root = QVBoxLayout(self)
        title = QLabel("AegisPath · Evidence-bound Exposure Paths")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        self.status_label = QLabel("UNKNOWN · no immutable graph snapshot")
        self.status_label.setStyleSheet("color: #ef4444; font-weight: 600;")
        root.addWidget(title)
        root.addWidget(self.status_label)
        self.boundary_label = QLabel(
            "Local single-user trust/privacy boundary · provider manifests are "
            "tamper-evident, not externally signed · clicked details may contain "
            "SENSITIVE/RESTRICTED telemetry and must not be shared without sanitization."
        )
        self.boundary_label.setWordWrap(True)
        self.boundary_label.setStyleSheet("color: #f59e0b;")
        root.addWidget(self.boundary_label)

        self.tabs = QTabWidget()
        self.path_table = _table((
            "State", "Entry point", "Target", "Hops", "Evidence", "Exact reason"
        ))
        self.target_table = _table((
            "Target", "Label", "Criticality", "Confirmed paths", "Speculative paths"
        ))
        self.entry_table = _table((
            "Entry point", "Label", "Confirmed paths", "Speculative paths"
        ))
        self.breakpoint_table = _table((
            "Plan score", "Type", "Breakpoint", "Coverage", "Confirmed", "Targets", "Reason"
        ))
        self.tabs.addTab(self.path_table, "Paths")
        self.tabs.addTab(self.target_table, "Targets")
        self.tabs.addTab(self.entry_table, "Entry points")
        self.tabs.addTab(self.breakpoint_table, "Breakpoints")

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(
            "Click any row for exact evidence IDs, source, provenance, freshness, "
            "confidence, privacy class, generation, applicability, and reasons."
        )
        self.details.setToolTip(
            "Single-user local inspection surface. Evidence source strings and properties "
            "are intentionally unsanitized here; sanitize before export or sharing."
        )
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.tabs)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        controls = QHBoxLayout()
        self.what_if_button = QPushButton("What if this breakpoint were applied?")
        self.what_if_button.setEnabled(False)
        self.what_if_button.setToolTip(
            "Runs an inert graph comparison only; it cannot change the host or network."
        )
        self.comparison_label = QLabel("No counterfactual selected.")
        self.comparison_label.setWordWrap(True)
        controls.addWidget(self.what_if_button)
        controls.addWidget(self.comparison_label, 1)
        root.addLayout(controls)

        self.path_table.itemSelectionChanged.connect(self._show_selected_path)
        self.target_table.itemSelectionChanged.connect(self._show_selected_target)
        self.entry_table.itemSelectionChanged.connect(self._show_selected_entry)
        self.breakpoint_table.itemSelectionChanged.connect(
            self._show_selected_breakpoint
        )
        self.what_if_button.clicked.connect(self._run_what_if)
        if snapshot is not None:
            self.set_snapshot(snapshot)
        else:
            self.clear_snapshot("no immutable graph snapshot")

    @property
    def snapshot(self) -> ExposureSnapshot | None:
        return self._snapshot

    @property
    def analysis(self) -> PathAnalysis | None:
        return self._analysis

    @property
    def priority_analysis(self) -> PriorityAnalysis | None:
        return self._priority

    def clear_snapshot(self, reason: str = "snapshot unavailable") -> None:
        self._analysis_token += 1
        self._analysis_pending = False
        self._active_task = None
        self._snapshot = None
        self._analysis = None
        self._priority = None
        self._node_index.clear()
        self._edge_index.clear()
        self._adjacent_edges.clear()
        self._path_index.clear()
        self._breakpoint_index.clear()
        for table in (
            self.path_table,
            self.target_table,
            self.entry_table,
            self.breakpoint_table,
        ):
            table.setSortingEnabled(False)
            table.setRowCount(0)
            table.setSortingEnabled(True)
        self.status_label.setText(f"UNKNOWN · {str(reason)[:240]}")
        self.status_label.setStyleSheet("color: #ef4444; font-weight: 600;")
        self.details.clear()
        self.what_if_button.setEnabled(False)
        self.comparison_label.setText(
            "No comparison available; missing data never proves the route is closed."
        )

    def set_snapshot(self, snapshot: ExposureSnapshot) -> None:
        if (
            isinstance(snapshot, ExposureSnapshot)
            and (
                len(snapshot.nodes) > _GUI_MAX_NODES
                or len(snapshot.edges) > _GUI_MAX_EDGES
            )
        ):
            self.clear_snapshot(
                "snapshot exceeds interactive verification bounds; use bounded backend analysis"
            )
            return
        if not isinstance(snapshot, ExposureSnapshot):
            self.clear_snapshot("snapshot receipt invalid")
            return
        if self._analysis_pending:
            self.status_label.setText(
                "UNKNOWN · bounded background analysis already in progress"
            )
            self.status_label.setStyleSheet("color: #ef4444; font-weight: 600;")
            return
        if (
            len(snapshot.nodes) > _GUI_SYNC_MAX_NODES
            or len(snapshot.edges) > _GUI_SYNC_MAX_EDGES
        ):
            self.clear_snapshot("bounded background verification in progress")
            self._analysis_token += 1
            token = self._analysis_token
            self._analysis_pending = True
            task = _AnalysisTask(snapshot, self._limits, token)
            task.signals.finished.connect(self._accept_background_analysis)
            self._active_task = task
            self.status_label.setText(
                "VERIFYING · bounded analysis is running off the UI thread"
            )
            self.status_label.setStyleSheet("color: #f59e0b; font-weight: 600;")
            self._thread_pool.start(task)
            return
        try:
            analysis, priority = _analyze_snapshot(snapshot, self._limits)
        except Exception as exc:
            self.clear_snapshot(f"analysis unavailable: {type(exc).__name__}")
            return
        self._snapshot = snapshot
        self._analysis = analysis
        self._priority = priority
        self._populate()

    def _accept_background_analysis(
        self,
        snapshot: object,
        analysis: object,
        priority: object,
        token: int,
        error: str,
    ) -> None:
        if token != self._analysis_token or not self._analysis_pending:
            return
        self._analysis_pending = False
        self._active_task = None
        if (
            error
            or not isinstance(snapshot, ExposureSnapshot)
            or not isinstance(analysis, PathAnalysis)
            or not isinstance(priority, PriorityAnalysis)
        ):
            self.clear_snapshot(f"background analysis unavailable: {error or 'invalid-result'}")
            return
        self._snapshot = snapshot
        self._analysis = analysis
        self._priority = priority
        self._populate()

    def _populate(self) -> None:
        snapshot, analysis, priority = self._snapshot, self._analysis, self._priority
        if snapshot is None or analysis is None or priority is None:
            return
        node_index = {node.node_id: node for node in snapshot.nodes}
        edge_index = {edge.edge_id: edge for edge in snapshot.edges}
        adjacent: dict[str, list[ExposureEdge]] = {}
        for edge in snapshot.edges:
            adjacent.setdefault(edge.source_id, []).append(edge)
            if edge.target_id != edge.source_id:
                adjacent.setdefault(edge.target_id, []).append(edge)
        self._node_index = node_index
        self._edge_index = edge_index
        self._adjacent_edges = {
            node_id: tuple(edges) for node_id, edges in adjacent.items()
        }
        self._path_index = {path.path_id: path for path in analysis.all_paths}
        self._breakpoint_index = {
            candidate.candidate_id: candidate for candidate in priority.breakpoints
        }
        incomplete = (
            snapshot.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
            or analysis.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
            or priority.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
        )
        coverage_verified = analysis.coverage_status is CoverageStatus.VERIFIED
        display_limited = any(
            len(rows) > _GUI_MAX_TABLE_ROWS
            for rows in (
                analysis.all_paths,
                analysis.target_ids,
                analysis.entry_ids,
                priority.breakpoints,
            )
        )
        if incomplete or not coverage_verified or display_limited:
            reasons = sorted(set(
                snapshot.truncation_reasons
                + analysis.truncation_reasons
                + priority.truncation_reasons
                + analysis.coverage_reasons
            ))
            if display_limited:
                reasons.append("interactive_display_limit")
            self.status_label.setText(
                (
                    "INCOMPLETE_RESOURCE_LIMIT"
                    if incomplete
                    else "INTERACTIVE_DISPLAY_LIMIT"
                    if display_limited
                    else f"{analysis.coverage_status.value}_SEMANTIC_COVERAGE"
                )
                + " · absence does not prove safety · "
                + ", ".join(reasons)
            )
            self.status_label.setStyleSheet("color: #ef4444; font-weight: 600;")
        else:
            self.status_label.setText(
                f"PROCESSING_COMPLETE · SEMANTIC_COVERAGE_VERIFIED · generation "
                f"{snapshot.generation} · {snapshot.digest}"
            )
            self.status_label.setStyleSheet("color: #22c55e; font-weight: 600;")
        target_counts: dict[str, list[int]] = {}
        entry_counts: dict[str, list[int]] = {}
        for path in analysis.confirmed_paths:
            target_counts.setdefault(path.target_id, [0, 0])[0] += 1
            entry_counts.setdefault(path.entry_id, [0, 0])[0] += 1
        for path in analysis.speculative_paths:
            target_counts.setdefault(path.target_id, [0, 0])[1] += 1
            entry_counts.setdefault(path.entry_id, [0, 0])[1] += 1
        self.path_table.setSortingEnabled(False)
        rendered_paths = analysis.all_paths[:_GUI_MAX_TABLE_ROWS]
        self.path_table.setRowCount(len(rendered_paths))
        for row_index, path in enumerate(rendered_paths):
            unknown = path.classification is PathClassification.SPECULATIVE
            state = _text_item(path.classification.value, unknown=unknown, payload=path.path_id)
            if not unknown:
                state.setForeground(_CONFIRMED_GREEN)
            self.path_table.setItem(row_index, 0, state)
            self.path_table.setItem(row_index, 1, _text_item(path.entry_id))
            self.path_table.setItem(row_index, 2, _text_item(path.target_id))
            self.path_table.setItem(row_index, 3, _NumberItem(len(path.edge_ids)))
            strength = _NumberItem(path.evidence_strength, f"{path.evidence_strength:.2f}")
            if unknown or path.evidence_strength <= 0.0:
                strength.setForeground(_UNKNOWN_RED)
            self.path_table.setItem(row_index, 4, strength)
            self.path_table.setItem(
                row_index, 5, _text_item("; ".join(path.reasons), unknown=unknown)
            )
        self.path_table.setSortingEnabled(True)
        self.path_table.resizeColumnsToContents()

        self.target_table.setSortingEnabled(False)
        rendered_targets = analysis.target_ids[:_GUI_MAX_TABLE_ROWS]
        self.target_table.setRowCount(len(rendered_targets))
        for row_index, node_id in enumerate(rendered_targets):
            confirmed, speculative = target_counts.get(node_id, [0, 0])
            node = node_index[node_id]
            unknown = confirmed == 0
            self.target_table.setItem(
                row_index, 0, _text_item(node_id, unknown=unknown, payload=node_id)
            )
            self.target_table.setItem(row_index, 1, _text_item(node.label))
            criticality = _NumberItem(node.criticality, str(node.criticality or "UNKNOWN"))
            if node.criticality == 0:
                criticality.setForeground(_UNKNOWN_RED)
            self.target_table.setItem(row_index, 2, criticality)
            self.target_table.setItem(row_index, 3, _NumberItem(confirmed))
            speculative_item = _NumberItem(speculative)
            if speculative:
                speculative_item.setForeground(_UNKNOWN_RED)
            self.target_table.setItem(row_index, 4, speculative_item)
        self.target_table.setSortingEnabled(True)
        self.target_table.resizeColumnsToContents()

        self.entry_table.setSortingEnabled(False)
        rendered_entries = analysis.entry_ids[:_GUI_MAX_TABLE_ROWS]
        self.entry_table.setRowCount(len(rendered_entries))
        for row_index, node_id in enumerate(rendered_entries):
            confirmed, speculative = entry_counts.get(node_id, [0, 0])
            node = node_index[node_id]
            self.entry_table.setItem(
                row_index, 0, _text_item(node_id, unknown=confirmed == 0, payload=node_id)
            )
            self.entry_table.setItem(row_index, 1, _text_item(node.label))
            self.entry_table.setItem(row_index, 2, _NumberItem(confirmed))
            speculative_item = _NumberItem(speculative)
            if speculative:
                speculative_item.setForeground(_UNKNOWN_RED)
            self.entry_table.setItem(row_index, 3, speculative_item)
        self.entry_table.setSortingEnabled(True)
        self.entry_table.resizeColumnsToContents()

        self.breakpoint_table.setSortingEnabled(False)
        rendered_breakpoints = priority.breakpoints[:_GUI_MAX_TABLE_ROWS]
        self.breakpoint_table.setRowCount(len(rendered_breakpoints))
        for row_index, candidate in enumerate(rendered_breakpoints):
            score = _NumberItem(candidate.planning_score)
            score.setData(Qt.UserRole, candidate.candidate_id)
            self.breakpoint_table.setItem(row_index, 0, score)
            self.breakpoint_table.setItem(row_index, 1, _text_item(candidate.kind.value))
            self.breakpoint_table.setItem(row_index, 2, _text_item(candidate.graph_id))
            self.breakpoint_table.setItem(
                row_index, 3, _NumberItem(candidate.coverage, f"{candidate.coverage:.1%}")
            )
            self.breakpoint_table.setItem(
                row_index, 4, _NumberItem(candidate.confirmed_paths_covered)
            )
            self.breakpoint_table.setItem(
                row_index, 5, _text_item(", ".join(candidate.target_ids) or "UNKNOWN", unknown=not candidate.target_ids)
            )
            self.breakpoint_table.setItem(row_index, 6, _text_item(candidate.reason))
        self.breakpoint_table.setSortingEnabled(True)
        self.breakpoint_table.resizeColumnsToContents()
        synchronous_comparison_safe = (
            len(snapshot.nodes) <= _GUI_SYNC_MAX_NODES
            and len(snapshot.edges) <= _GUI_SYNC_MAX_EDGES
        )
        self.what_if_button.setEnabled(
            bool(priority.breakpoints) and synchronous_comparison_safe
        )
        self.comparison_label.setText(
            "Select a breakpoint, then run a side-effect-free route comparison."
            if synchronous_comparison_safe
            else "Large-graph what-if is disabled in the UI; use bounded backend analysis."
        )
        if analysis.all_paths:
            self.details.setPlainText(
                "Click a path to inspect its exact edge evidence and limitations."
            )

    def _selected_payload(self, table: QTableWidget, column: int = 0):
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, column)
        return None if item is None else item.data(Qt.UserRole)

    def _show_selected_path(self) -> None:
        if self._snapshot is None or self._analysis is None:
            return
        path_id = self._selected_payload(self.path_table)
        path = self._path_index.get(str(path_id))
        if path is None:
            return
        document = {
            "path_id": path.path_id,
            "classification": path.classification.value,
            "evidence_strength": path.evidence_strength,
            "reasons": path.reasons,
            "nodes": [
                {
                    "id": node_id,
                    "kind": self._node_index[node_id].kind.value,
                    "label": self._node_index[node_id].label,
                    "criticality": self._node_index[node_id].criticality or "UNKNOWN",
                    "cve_id": self._node_index[node_id].cve_id or None,
                }
                for node_id in path.node_ids
            ],
            "edges": [
                self._edge_document(self._edge_index[edge_id])
                for edge_id in path.edge_ids
            ],
            "receipt": {
                "snapshot_digest": self._analysis.receipt.snapshot_digest,
                "generation": self._analysis.receipt.generation,
                "analysis_digest": self._analysis.receipt.analysis_digest,
            },
        }
        self.details.setPlainText(json.dumps(document, indent=2, ensure_ascii=False))

    @staticmethod
    def _edge_document(edge) -> dict:
        evidence = edge.evidence
        return {
            "edge_id": edge.edge_id,
            "source": edge.source_id,
            "target": edge.target_id,
            "relationship": edge.kind.value,
            "assertion": edge.assertion.value,
            "applicability": edge.applicability.value,
            "reason": edge.reason,
            "evidence": {
                "id": evidence.evidence_id,
                "source": evidence.source,
                "provenance": evidence.provenance.value,
                "freshness": evidence.freshness.value,
                "confidence": evidence.confidence,
                "privacy": evidence.privacy.value,
                "generation": evidence.generation,
                "observed_at": evidence.observed_at,
                "expires_at": evidence.expires_at,
                "digest": evidence.digest or "UNKNOWN",
            },
        }

    def _show_selected_target(self) -> None:
        self._show_node(self._selected_payload(self.target_table))

    def _show_selected_entry(self) -> None:
        self._show_node(self._selected_payload(self.entry_table))

    def _show_node(self, node_id) -> None:
        if self._snapshot is None or node_id is None:
            return
        node = self._node_index.get(str(node_id))
        if node is None:
            return
        related_edges = self._adjacent_edges.get(node.node_id, ())
        related = [
            self._edge_document(edge)
            for edge in related_edges[:_GUI_MAX_DETAIL_EDGES]
        ]
        related_total = len(related_edges)
        self.details.setPlainText(json.dumps({
            "node_id": node.node_id,
            "kind": node.kind.value,
            "label": node.label,
            "criticality": node.criticality or "UNKNOWN",
            "cve_id": node.cve_id or None,
            "known_exploited": node.known_exploited,
            "epss": node.epss,
            "control_effectiveness": node.control_effectiveness,
            "properties": dict(node.properties),
            "related_evidence": related,
            "related_evidence_display_limit": _GUI_MAX_DETAIL_EDGES,
            "related_evidence_omitted": max(0, related_total - len(related)),
        }, indent=2, ensure_ascii=False))

    def _selected_breakpoint(self) -> BreakpointCandidate | None:
        if self._priority is None:
            return None
        candidate_id = self._selected_payload(self.breakpoint_table)
        return self._breakpoint_index.get(str(candidate_id))

    def _show_selected_breakpoint(self) -> None:
        candidate = self._selected_breakpoint()
        snapshot = self._snapshot
        synchronous_comparison_safe = bool(
            snapshot is not None
            and len(snapshot.nodes) <= _GUI_SYNC_MAX_NODES
            and len(snapshot.edges) <= _GUI_SYNC_MAX_EDGES
        )
        self.what_if_button.setEnabled(
            candidate is not None and synchronous_comparison_safe
        )
        if candidate is None:
            return
        self.details.setPlainText(json.dumps({
            "candidate_id": candidate.candidate_id,
            "kind": candidate.kind.value,
            "graph_id": candidate.graph_id,
            "paths_covered": candidate.paths_covered,
            "confirmed_paths_covered": candidate.confirmed_paths_covered,
            "target_ids": candidate.target_ids,
            "coverage": candidate.coverage,
            "planning_score": candidate.planning_score,
            "reason": candidate.reason,
            "simulation_only": candidate.simulation_only,
            "warning": "This proposal is not approval and cannot perform a host action.",
        }, indent=2, ensure_ascii=False))

    def _run_what_if(self) -> None:
        snapshot, candidate = self._snapshot, self._selected_breakpoint()
        if snapshot is None or candidate is None:
            return
        edge_ids = (candidate.graph_id,) if candidate.kind.value == "edge" else ()
        node_ids = (candidate.graph_id,) if candidate.kind.value == "node" else ()
        try:
            comparison = simulate_breakpoints(
                snapshot,
                expected_generation=snapshot.generation,
                expected_digest=snapshot.digest,
                expected_scope_id=snapshot.scope_id,
                expected_policy_digest=snapshot.policy_digest,
                breakpoint_edge_ids=edge_ids,
                breakpoint_node_ids=node_ids,
                limits=self._limits,
            )
        except Exception as exc:
            self.comparison_label.setText(
                f"UNKNOWN · inert comparison failed: {type(exc).__name__}"
            )
            self.comparison_label.setStyleSheet("color: #ef4444;")
            return
        self.comparison_label.setStyleSheet(
            "color: #ef4444;"
            if (
                comparison.status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT
                or comparison.coverage_status is not CoverageStatus.VERIFIED
            )
            else ""
        )
        self.comparison_label.setText(
            f"What if: {comparison.removed_confirmed_paths} confirmed and "
            f"{comparison.removed_speculative_paths} speculative paths removed; "
            f"{len(comparison.no_longer_enumerated_target_ids)} targets no longer enumerated; "
            f"{len(comparison.still_enumerated_target_ids)} still enumerated (not proven reachable). "
            f"Semantic coverage {comparison.coverage_status.value}: "
            f"{', '.join(comparison.coverage_reasons)}. "
            f"{comparison.explanation}"
        )


class AegisPathDialog(QDialog):
    """Thin dialog wrapper around the embeddable Local SOC widget."""

    def __init__(
        self,
        snapshot: ExposureSnapshot | None = None,
        parent=None,
        *,
        limits: PathLimits | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("AegisPath Exposure Graph")
        self.resize(1_300, 850)
        layout = QVBoxLayout(self)
        self.widget = AegisPathWidget(snapshot, self, limits=limits)
        layout.addWidget(self.widget)


__all__ = ["AegisPathDialog", "AegisPathWidget"]
