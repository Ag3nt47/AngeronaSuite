"""Embeddable DetectionForge validation workspace and local service facade."""
from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from angerona.core.detection_evaluation import (
    EVALUATION_REASON_CODES,
    METRIC_REASON_CODES,
    SOURCE_KIND_CODES,
    CohortLoss,
    DetectionComparison,
    ReplayCohort,
    capture_replay_cohort,
    compare_detection_packages,
)
from angerona.core.detection_packages import DetectionPackage
from angerona.core.detection_promotion import (
    DetectionPromotionCoordinator,
    PromotionReceipt,
    PromotionResult,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAttestation,
    QualityReceipt,
)
from angerona.core.detection_registry import DetectionPackageRegistry, ValidationReport
from angerona.modules.detection_runtime import DetectionRuntimeEngine


_SENSITIVE_EXPORT_KEYS = frozenset({
    "error", "errors", "event", "event_id", "event_ids", "filename",
    "incomplete_reason", "label_source", "message", "nonce", "path",
    "reason", "resource_coverage", "signer", "source_id",
})
_PATH_TEXT = re.compile(r"(?:[A-Za-z]:[\\/]|/(?:home|Users|var|tmp)/|\\\\)")
_CLOSED_EXPORT_CODES: dict[str, frozenset[str]] = {
    "source_kind_code": SOURCE_KIND_CODES,
    "metric_reason_code": METRIC_REASON_CODES,
    "disposition": frozenset({
        "matched", "not-matched", "evaluation-failed", "budget-exceeded",
    }),
    "action": frozenset({"promote", "rollback"}),
    "state": frozenset({"active", "rejected", "runtime-fail-closed"}),
    "input_trust": frozenset({"authenticated", "self-attested"}),
    "integrity_scope": frozenset({"authenticated-present-prefix"}),
}


def _recursive_export_redaction(value: object, *, field: str = "") -> object:
    """Recursively remove sensitive fields and reject open code values."""
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str) or raw_key in _SENSITIVE_EXPORT_KEYS:
                continue
            result[raw_key] = _recursive_export_redaction(item, field=raw_key)
        return result
    if isinstance(value, (list, tuple)):
        if field == "reason_codes":
            return [
                item for item in value
                if isinstance(item, str) and item in EVALUATION_REASON_CODES
            ]
        return [_recursive_export_redaction(item, field=field) for item in value]
    if isinstance(value, str):
        allowed = _CLOSED_EXPORT_CODES.get(field)
        if allowed is not None and value not in allowed:
            return "invalid"
        if _PATH_TEXT.search(value) or "\x00" in value or "\r" in value or "\n" in value:
            return "redacted"
    return value


@dataclass(frozen=True)
class ForgeGateRow:
    view: str
    gate: str
    state: str
    reason: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.state not in {"pass", "fail", "info", "pending"}:
            raise ValueError("forge gate state is invalid")


class DetectionForgeService:
    """Local-first facade used by both the widget and non-GUI workflows."""

    def __init__(
        self,
        *,
        registry: DetectionPackageRegistry,
        runtime: DetectionRuntimeEngine,
        quality_store: DetectionQualityStore | None = None,
        promotion: DetectionPromotionCoordinator | None = None,
    ) -> None:
        self.registry = registry
        self.runtime = runtime
        self.quality_store = quality_store
        self.promotion = promotion
        self._lock = threading.RLock()
        self._cohort: ReplayCohort | None = None
        self._comparison: DetectionComparison | None = None
        self._quality_receipt: QualityReceipt | None = None
        self._last_transition: PromotionResult | None = None

    def import_package(
        self,
        path: str | Path,
        *,
        signature: str | Path | None = None,
    ) -> ValidationReport:
        return self.registry.stage(path, signature=signature)

    def replay(
        self,
        rows: Iterable[object],
        *,
        source_id: str,
        source_kind: str,
        high_water: int,
        loss: CohortLoss | None = None,
    ) -> ReplayCohort:
        cohort = capture_replay_cohort(
            rows,
            source_id=source_id,
            source_kind=source_kind,
            high_water=high_water,
            loss=loss,
        )
        with self._lock:
            self._cohort = cohort
            self._comparison = None
            self._quality_receipt = None
        return cohort

    def compare(
        self,
        *,
        active: DetectionPackage | Sequence[DetectionPackage] | None,
        candidate: DetectionPackage | Sequence[DetectionPackage],
        cohort: ReplayCohort | None = None,
    ) -> DetectionComparison:
        with self._lock:
            selected = cohort or self._cohort
        if selected is None:
            raise ValueError("capture a replay cohort before comparison")
        comparison = compare_detection_packages(
            selected,
            active=active,
            candidate=candidate,
        )
        comparison.assert_intact()
        with self._lock:
            self._comparison = comparison
            self._quality_receipt = None
        return comparison

    def record_quality(
        self,
        *,
        package_id: str,
        policy_digest: str,
        signer: str,
        tuning_digest: str,
        resource_coverage: object,
        input_attestation: QualityInputAttestation | None = None,
    ) -> QualityReceipt:
        if self.quality_store is None:
            raise RuntimeError("DetectionForge quality store is unavailable")
        with self._lock:
            comparison = self._comparison
        if comparison is None:
            raise ValueError("complete a comparison before recording quality")
        receipt = self.quality_store.append_evaluation(
            comparison,
            package_id=package_id,
            policy_digest=policy_digest,
            signer=signer,
            tuning_digest=tuning_digest,
            resource_coverage=resource_coverage,
            input_attestation=input_attestation,
        )
        with self._lock:
            self._quality_receipt = receipt
        return receipt

    def shadow(
        self, package: DetectionPackage | Sequence[DetectionPackage] | None
    ) -> tuple[str, ...]:
        return self.runtime.bind_shadow(package)

    def promote(self, receipt: PromotionReceipt) -> PromotionResult:
        if self.promotion is None:
            raise RuntimeError("DetectionForge promotion coordinator is unavailable")
        result = self.promotion.promote(receipt)
        if result.ok:
            result = self._reconcile_transition(result)
        with self._lock:
            self._last_transition = result
        return result

    def rollback(self, receipt: PromotionReceipt) -> PromotionResult:
        if self.promotion is None:
            raise RuntimeError("DetectionForge promotion coordinator is unavailable")
        result = self.promotion.rollback(receipt)
        if result.ok:
            result = self._reconcile_transition(result)
        with self._lock:
            self._last_transition = result
        return result

    def _reconcile_transition(self, result: PromotionResult) -> PromotionResult:
        try:
            self.runtime.sync_active_from_registry(
                self.registry,
                package_id=result.package_id,
                expected_digest=result.target_digest,
                activation_epoch=result.activation_epoch,
            )
            return result
        except Exception:
            # The registry transition is durable, so never continue evaluating
            # its now-retired predecessor when runtime binding cannot reconcile.
            self.runtime.fail_closed_active(activation_epoch=result.activation_epoch)
            return PromotionResult(
                ok=False,
                action=result.action,
                package_id=result.package_id,
                target_digest=result.target_digest,
                previous_digest=result.previous_digest,
                state="runtime-fail-closed",
                activation_epoch=result.activation_epoch,
                errors=("runtime reconciliation failed closed",),
            )

    def observe(self) -> dict[str, object]:
        with self._lock:
            cohort = self._cohort.summary() if self._cohort else None
            comparison = self._comparison.to_dict() if self._comparison else None
            quality = (
                {
                    "receipt_id": self._quality_receipt.receipt_id,
                    "candidate_digest": self._quality_receipt.candidate_digest,
                    "cohort_digest": self._quality_receipt.cohort_digest,
                    "policy_digest": self._quality_receipt.policy_digest,
                }
                if self._quality_receipt else None
            )
            transition = asdict(self._last_transition) if self._last_transition else None
        return {
            "cohort": cohort,
            "comparison": comparison,
            "quality_receipt": quality,
            "runtime": self.runtime.snapshot().to_dict(),
            "last_transition": transition,
        }

    def sanitized_export(self) -> dict[str, object]:
        """Return no event bodies, local paths, HMACs, nonces, or signer names."""
        with self._lock:
            comparison_object = self._comparison
        if comparison_object is not None:
            comparison_object.assert_intact()
        observed = self.observe()
        cohort = observed.get("cohort")
        if isinstance(cohort, dict):
            loss = cohort.get("loss")
            safe_loss = (
                {
                    "overflow": bool(loss.get("overflow", False)),
                    "dropped_rows": int(loss.get("dropped_rows", 0)),
                    "excluded_after_high_water": int(
                        loss.get("excluded_after_high_water", 0)
                    ),
                    "complete": not bool(loss.get("overflow", False))
                    and int(loss.get("dropped_rows", 0)) == 0
                    and not bool(loss.get("incomplete_reason", "")),
                }
                if isinstance(loss, dict)
                else None
            )
            cohort = {
                "schema": cohort.get("schema"),
                "source_kind_code": cohort.get("source_kind"),
                "source_digest": cohort.get("source_digest"),
                "cohort_digest": cohort.get("cohort_digest"),
                "high_water": cohort.get("high_water"),
                "row_count": cohort.get("row_count"),
                "fully_labelled": cohort.get("fully_labelled"),
                "loss": safe_loss,
            }
        comparison = observed.get("comparison")
        if isinstance(comparison, dict):
            comparison = {
                "schema": comparison.get("schema"),
                "cohort_digest": comparison.get("cohort_digest"),
                "source_digest": comparison.get("source_digest"),
                "source_kind_code": comparison.get("source_kind"),
                "high_water": comparison.get("high_water"),
                "row_count": comparison.get("row_count"),
                "active_digests": comparison.get("active_digests"),
                "candidate_digests": comparison.get("candidate_digests"),
                "active_match_count": len(comparison.get("active_event_ids", [])),
                "candidate_match_count": len(
                    comparison.get("candidate_event_ids", [])
                ),
                "new_match_count": len(comparison.get("new_event_ids", [])),
                "lost_match_count": len(comparison.get("lost_event_ids", [])),
                "shared_match_count": len(comparison.get("shared_event_ids", [])),
                "complete": comparison.get("complete"),
                "precision": comparison.get("precision"),
                "recall": comparison.get("recall"),
                "labels_used": comparison.get("labels_used"),
                "evaluation_digest": comparison.get("evaluation_digest"),
                "evaluated_at": comparison.get("evaluated_at"),
                "reason_codes": (
                    list(comparison_object.reason_codes)
                    if comparison_object is not None else []
                ),
                "metric_reason_code": (
                    comparison_object.metric_reason_code
                    if comparison_object is not None else "invalid"
                ),
            }
        runtime_observed = dict(observed["runtime"])  # type: ignore[arg-type]
        runtime = {
            key: runtime_observed.get(key)
            for key in (
                "active_digests", "shadow_digests", "active_queue_depth",
                "shadow_queue_depth", "active_queue_capacity",
                "shadow_queue_capacity", "active_drops", "shadow_drops",
                "active_findings", "active_deduplicated", "shadow_deduplicated",
                "active_budget_drops", "shadow_budget_drops", "budget_violations",
                "rule_integrity_failures", "evaluation_failures",
                "recursive_events_rejected", "invalid_events_rejected",
                "event_id_collisions", "source_cursor_collisions",
                "active_activation_epoch", "shadow_activation_epoch",
                "active_epoch_drops", "shadow_epoch_drops",
            )
        }
        runtime["shadow_observations"] = [
            {
                "package_digest": item.get("package_digest"),
                "matched": item.get("matched"),
                "disposition": item.get("disposition"),
            }
            for item in runtime_observed.get("shadow_observations", [])
            if isinstance(item, dict)
        ]
        transition = observed.get("last_transition")
        if isinstance(transition, dict):
            # Backend/registry exception text can contain local paths or other
            # host-specific diagnostics.  Export only the closed transition
            # outcome fields; detailed errors stay in the local workspace.
            transition = {
                key: transition.get(key)
                for key in (
                    "ok", "action", "target_digest", "previous_digest",
                    "state", "activation_epoch",
                )
            }
        export = {
            "schema": "angerona.detection-forge-export.v1",
            "cohort": cohort,
            "comparison": comparison,
            "runtime": runtime,
            "last_transition": transition,
            "quality_receipts": (
                list(self.quality_store.sanitized_export()) if self.quality_store else []
            ),
            "contains_raw_events": False,
            "contains_hmac_authority": False,
            "contains_local_paths": False,
        }
        redacted = _recursive_export_redaction(export)
        if not isinstance(redacted, dict):  # pragma: no cover - fixed root type
            raise RuntimeError("DetectionForge export redaction failed closed")
        return redacted

    def gate_rows(self) -> tuple[ForgeGateRow, ...]:
        with self._lock:
            cohort = self._cohort
            comparison = self._comparison
            quality = self._quality_receipt
            transition = self._last_transition
        rows: list[ForgeGateRow] = []
        inventory = self.registry.inventory()
        retained = sum(
            len(versions) for versions in inventory.values()
            if isinstance(versions, dict)
        )
        rows.append(ForgeGateRow(
            "Import", "Verified local registry", "pass" if retained else "pending",
            f"{retained} immutable package digest(s) retained" if retained else
            "No package has been imported",
        ))
        if cohort is None:
            rows.append(ForgeGateRow("Replay", "Immutable cohort", "pending", "No cohort captured"))
        else:
            rows.extend((
                ForgeGateRow(
                    "Replay", "Immutable cohort", "pass",
                    f"{len(cohort.rows)} rows sealed at high-water {cohort.high_water}",
                    cohort.cohort_digest,
                ),
                ForgeGateRow(
                    "Replay", "Source custody",
                    "pass" if cohort.loss.complete else "fail",
                    "No source loss reported" if cohort.loss.complete else
                    "Source overflow, drops, or incomplete custody reported",
                    cohort.source_digest,
                ),
            ))
        if comparison is None:
            rows.append(ForgeGateRow("Compare", "Replay complete", "pending", "No comparison run"))
        else:
            rows.extend((
                ForgeGateRow(
                    "Compare", "Replay complete", "pass" if comparison.complete else "fail",
                    "All rules remained within gates" if comparison.complete else
                    "; ".join(comparison.reasons),
                    comparison.evaluation_digest,
                ),
                ForgeGateRow(
                    "Compare", "Lost detections",
                    "pass" if not comparison.lost_event_ids else "fail",
                    f"{len(comparison.lost_event_ids)} active event IDs lost",
                    ", ".join(comparison.lost_event_ids[:20]),
                ),
                ForgeGateRow(
                    "Compare", "Labelled metrics",
                    "pass" if comparison.precision is not None and comparison.recall is not None
                    else "info",
                    comparison.metric_reason,
                    f"precision={comparison.precision}; recall={comparison.recall}",
                ),
            ))
        runtime = self.runtime.snapshot()
        rows.extend((
            ForgeGateRow(
                "Shadow", "Alert-inert lane", "pass",
                "Shadow has no publish, evidence, incident, SOAR, or response callback",
            ),
            ForgeGateRow(
                "Shadow", "Visible loss", "pass" if runtime.shadow_drops == 0 else "fail",
                f"{runtime.shadow_drops} shadow queue drops",
            ),
            ForgeGateRow(
                "Observe", "Active lane", "pass" if runtime.active_drops == 0 else "fail",
                f"{runtime.active_drops} active queue drops",
            ),
        ))
        rows.append(ForgeGateRow(
            "Promote", "Exact quality receipt",
            (
                "pass" if quality and quality.input_trust == "authenticated"
                else "fail" if quality else "pending"
            ),
            (
                "Authenticated quality receipt is ready"
                if quality and quality.input_trust == "authenticated"
                else "Receipt is self-attested and cannot authorize promotion"
                if quality else "No quality receipt recorded"
            ),
            quality.receipt_id if quality else "",
        ))
        rows.append(ForgeGateRow(
            "Rollback", "Last transition",
            "pass" if transition and transition.ok else ("fail" if transition else "pending"),
            (
                f"{transition.action} committed {transition.target_digest}"
                if transition and transition.ok else
                "; ".join(transition.errors) if transition else "No transition attempted"
            ),
        ))
        return tuple(rows)


class _GateTable(QTableWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, 4, parent)
        self.setHorizontalHeaderLabels(("Gate", "State", "Reason", "Exact evidence"))
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.horizontalHeader().setStretchLastSection(True)

    def set_rows(self, rows: Sequence[ForgeGateRow]) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = (row.gate, row.state.upper(), row.reason, row.evidence)
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.ItemDataRole.UserRole, asdict(row))
                if row.state == "fail":
                    item.setForeground(QColor("#ff4d5a"))
                    item.setBackground(QColor("#38191d"))
                elif row.state == "pass":
                    item.setForeground(QColor("#67e8a5"))
                elif row.state == "pending":
                    item.setForeground(QColor("#f6c85f"))
                self.setItem(index, column, item)
        self.resizeColumnsToContents()
        self.setSortingEnabled(True)


class DetectionForgeWidget(QWidget):
    """Embeddable Local SOC tab with seven sortable, clickable views."""

    VIEW_NAMES = ("Import", "Replay", "Compare", "Shadow", "Promote", "Observe", "Rollback")

    def __init__(
        self,
        service: DetectionForgeService,
        parent: QWidget | None = None,
        *,
        auto_refresh: bool = True,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self._tables: dict[str, _GateTable] = {}
        layout = QVBoxLayout(self)
        title = QLabel("DetectionForge · local detection validation and safe promotion")
        title.setObjectName("detectionForgeTitle")
        layout.addWidget(title)

        controls = QHBoxLayout()
        import_button = QPushButton("Import verified package…")
        import_button.clicked.connect(self._import_package)
        refresh_button = QPushButton("Refresh exact gates")
        refresh_button.clicked.connect(self.refresh)
        export_button = QPushButton("Preview sanitized export")
        export_button.clicked.connect(self._show_export)
        controls.addWidget(import_button)
        controls.addWidget(refresh_button)
        controls.addWidget(export_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.tabs = QTabWidget()
        for name in self.VIEW_NAMES:
            table = _GateTable()
            table.cellClicked.connect(self._show_selected)
            self._tables[name] = table
            self.tabs.addTab(table, name)
        splitter.addWidget(self.tabs)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        self.details.setPlaceholderText(
            "Click any row to inspect its exact reason, digest, count, or transition evidence."
        )
        splitter.addWidget(self.details)
        splitter.setSizes((620, 220))
        layout.addWidget(splitter, 1)
        if auto_refresh:
            self.refresh()

    def refresh(self) -> None:
        all_rows = self.service.gate_rows()
        for name, table in self._tables.items():
            table.set_rows(tuple(row for row in all_rows if row.view == name))

    def _show_selected(self, row_index: int, _column: int) -> None:
        table = self.sender()
        if not isinstance(table, _GateTable):
            return
        item = table.item(row_index, 0)
        document = item.data(Qt.ItemDataRole.UserRole) if item else None
        if isinstance(document, dict):
            self.details.setPlainText(json.dumps(document, indent=2, sort_keys=True))

    def _import_package(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Import a bounded detection package",
            "",
            "Detection packages (*.json)",
        )
        if not selected:
            return
        report = self.service.import_package(selected)
        self.details.setPlainText(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        self.refresh()

    def _show_export(self) -> None:
        document = self.service.sanitized_export()
        self.details.setPlainText(json.dumps(document, indent=2, sort_keys=True))


class DetectionForgeDialog(QDialog):
    """Thin standalone wrapper around the embeddable Local SOC widget."""

    def __init__(
        self, service: DetectionForgeService, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("DetectionForge")
        self.resize(1220, 820)
        layout = QVBoxLayout(self)
        layout.addWidget(DetectionForgeWidget(service, self))


__all__ = [
    "DetectionForgeDialog",
    "DetectionForgeService",
    "DetectionForgeWidget",
    "ForgeGateRow",
]
