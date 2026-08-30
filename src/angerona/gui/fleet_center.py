"""Sortable, clickable local Fleet Fabric evidence center."""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
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

from angerona.core.fleet_fabric import FleetFabricStore

_ROLE_EVIDENCE = Qt.UserRole + 31


def _json_ready(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
    return value


class FleetCenterWidget(QWidget):
    """Embeddable local-SOC view over one already-open FleetFabricStore."""

    def __init__(
        self,
        fabric: FleetFabricStore | None = None,
        parent=None,
        *,
        auto_refresh: bool = True,
    ) -> None:
        super().__init__(parent)
        self.fabric = fabric
        self._snapshot: Mapping[str, Any] = {}
        self._selected_rollout_id = ""

        root = QVBoxLayout(self)
        title = QLabel("Fleet Center — local enrollment, health, and rollout evidence")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        subtitle = QLabel(
            "Local-first preview/store · Ed25519 device possession + signed health intake · "
            "tenant-keyed local HMAC integrity · canary halt + proposal-only rollback"
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color:#94a3b8;")
        root.addWidget(subtitle)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Tenant"))
        self.tenant_box = QComboBox()
        self.tenant_box.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.tenant_box)
        refresh = QPushButton("Refresh local evidence")
        refresh.clicked.connect(self.refresh)
        controls.addWidget(refresh)
        self.rollback_button = QPushButton("Preview rollback plan")
        self.rollback_button.setEnabled(False)
        self.rollback_button.clicked.connect(self._preview_rollback)
        controls.addWidget(self.rollback_button)
        controls.addStretch(1)
        self.status = QLabel("No Fleet Fabric store is bound")
        self.status.setStyleSheet("color:#94a3b8;")
        controls.addWidget(self.status)
        root.addLayout(controls)

        split = QSplitter(Qt.Vertical)
        self.tabs = QTabWidget()
        self.health_table = self._table(
            (
                "Health", "Device", "Observed", "Desired policy", "Effective policy",
                "Queue", "Lost Δ", "Exact reason",
            )
        )
        self.health_table.cellClicked.connect(self._health_clicked)
        self.tabs.addTab(self.health_table, "Device health")

        self.rollout_table = self._table(
            (
                "State", "Rollout", "Version", "Policy bundle", "Group", "Targets",
                "Canaries", "Desired policy", "Exact reason",
            )
        )
        self.rollout_table.cellClicked.connect(self._rollout_clicked)
        self.tabs.addTab(self.rollout_table, "Policy rollouts")

        self.enrollment_table = self._table(
            (
                "State", "Device", "Grant", "Issued", "Expires", "Redeemed",
                "Device key digest", "Grant digest",
            )
        )
        self.enrollment_table.cellClicked.connect(self._enrollment_clicked)
        self.tabs.addTab(self.enrollment_table, "Enrollment grants")
        split.addWidget(self.tabs)

        detail_host = QWidget()
        detail_layout = QVBoxLayout(detail_host)
        detail_layout.setContentsMargins(0, 4, 0, 0)
        detail_layout.addWidget(QLabel(
            "Selected evidence — click any row for exact hashes, binding, reason, and loss counters"
        ))
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText(
            "Rows are read-only local evidence. No remote shell or arbitrary command surface exists."
        )
        detail_layout.addWidget(self.detail)
        split.addWidget(detail_host)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        root.addWidget(split, 1)

        boundary = QLabel(
            "OBSERVE + PLAN ONLY: coordinator networking is unavailable here; rollback previews "
            "contain hashes and targets, never commands, scripts, or execution authority."
        )
        boundary.setWordWrap(True)
        boundary.setStyleSheet("color:#22c55e;")
        root.addWidget(boundary)
        self.set_fabric(fabric, refresh=auto_refresh)

    @staticmethod
    def _table(headers: tuple[str, ...]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setSortingEnabled(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionsClickable(True)
        table.horizontalHeader().setSortIndicatorShown(True)
        for index in range(len(headers)):
            table.horizontalHeader().setSectionResizeMode(
                index,
                QHeaderView.Stretch if index == len(headers) - 1 else QHeaderView.ResizeToContents,
            )
        return table

    def set_fabric(
        self, fabric: FleetFabricStore | None, *, refresh: bool = True
    ) -> None:
        self.fabric = fabric
        selected = str(self.tenant_box.currentData() or "")
        self.tenant_box.blockSignals(True)
        self.tenant_box.clear()
        if fabric is not None:
            for tenant_id in fabric.tenant_ids:
                self.tenant_box.addItem(tenant_id, tenant_id)
            index = self.tenant_box.findData(selected)
            if index >= 0:
                self.tenant_box.setCurrentIndex(index)
        self.tenant_box.blockSignals(False)
        if refresh:
            self.refresh()

    @property
    def selected_evidence(self) -> str:
        return self.detail.toPlainText()

    def _clear_evidence_view(self) -> None:
        """Clear all tenant-derived state together so failures cannot leave stale rows."""
        self._snapshot = {}
        self._selected_rollout_id = ""
        self.rollback_button.setEnabled(False)
        self.detail.clear()
        for table in (self.health_table, self.rollout_table, self.enrollment_table):
            table.setSortingEnabled(False)
            table.clearContents()
            table.setRowCount(0)
            table.setSortingEnabled(True)

    def refresh(self) -> None:
        fabric = self.fabric
        tenant_id = str(self.tenant_box.currentData() or "")
        if fabric is None or not tenant_id:
            self._clear_evidence_view()
            self.status.setText("No Fleet Fabric store is bound")
            return
        try:
            snapshot = fabric.dashboard_snapshot(tenant_id)
            self._clear_evidence_view()
            self._render_health(snapshot["health"])
            self._render_rollouts(snapshot["rollouts"])
            self._render_enrollments(snapshot["enrollments"])
        except Exception as exc:
            self._clear_evidence_view()
            self.status.setText(f"Local evidence unavailable: {type(exc).__name__}: {str(exc)[:160]}")
            return
        self._snapshot = snapshot
        health = snapshot["health"]
        transport = snapshot["transport"]
        self.status.setText(
            f"{health.fresh_devices}/{health.enrolled_devices} device(s) fresh · "
            f"{health.missing_devices} missing · {health.stale_devices} stale · "
            f"{health.total_rows} health row(s) · {len(snapshot['rollouts'])} rollout(s) · "
            f"{len(snapshot['enrollments'])} grant(s) · retention loss {health.retention_drops} · "
            f"transport {transport['reason']}"
        )

    @staticmethod
    def _item(value: object, evidence: Mapping[str, Any], *, red: bool = False) -> QTableWidgetItem:
        item = QTableWidgetItem(str(value))
        item.setData(_ROLE_EVIDENCE, dict(evidence))
        if red:
            item.setForeground(QColor("#ef4444"))
        return item

    def _render_health(self, snapshot) -> None:
        table = self.health_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for evidence in snapshot.items:
            sample = evidence.sample
            row = table.rowCount()
            table.insertRow(row)
            detail = _json_ready(evidence)
            values = (
                f"{sample.health_percent}%",
                sample.device_id,
                f"{sample.observed_at:.3f}",
                sample.desired_policy_hash,
                sample.effective_policy_hash,
                f"{sample.queue_depth}/{sample.queue_capacity}",
                sample.dropped_since_previous,
                sample.health_reason or "healthy",
            )
            red = sample.health_percent < 100
            for column, value in enumerate(values):
                table.setItem(row, column, self._item(value, detail, red=red and column in {0, 4, 6, 7}))
        table.setSortingEnabled(True)

    def _render_rollouts(self, rows) -> None:
        table = self.rollout_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for record in rows:
            row = table.rowCount()
            table.insertRow(row)
            detail = dict(record)
            values = (
                record["state"],
                record["rollout_id"],
                record["version"],
                record["policy_bundle_id"],
                record["group_id"],
                record["target_count"],
                record["canary_count"],
                record["desired_policy_hash"],
                record["reason"],
            )
            red = record["state"] == "halted"
            for column, value in enumerate(values):
                table.setItem(row, column, self._item(value, detail, red=red and column in {0, 8}))
        table.setSortingEnabled(True)

    def _render_enrollments(self, rows) -> None:
        table = self.enrollment_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for record in rows:
            row = table.rowCount()
            table.insertRow(row)
            detail = dict(record)
            values = (
                record["state"],
                record["device_id"],
                record["grant_id"],
                f"{record['issued_at']:.3f}",
                f"{record['expires_at']:.3f}",
                f"{record['redeemed_at']:.3f}" if record["redeemed_at"] else "—",
                record["device_public_key_sha256"],
                record["grant_digest"],
            )
            red = record["state"] in {"expired", "revoked"}
            for column, value in enumerate(values):
                table.setItem(row, column, self._item(value, detail, red=red and column == 0))
        table.setSortingEnabled(True)

    @staticmethod
    def _row_evidence(table: QTableWidget, row: int) -> Mapping[str, Any]:
        for column in range(table.columnCount()):
            item = table.item(row, column)
            if item is not None:
                value = item.data(_ROLE_EVIDENCE)
                if isinstance(value, dict):
                    return value
        return {}

    def _show(self, heading: str, evidence: Mapping[str, Any]) -> None:
        self.detail.setPlainText(
            heading + "\n\n" + json.dumps(_json_ready(evidence), indent=2, sort_keys=True)
        )

    def _health_clicked(self, row: int, _column: int) -> None:
        self._show(
            "DEVICE-SIGNED HEALTH + LOCALLY HMAC-SEALED STORAGE EVIDENCE",
            self._row_evidence(self.health_table, row),
        )

    def _rollout_clicked(self, row: int, _column: int) -> None:
        evidence = self._row_evidence(self.rollout_table, row)
        self._selected_rollout_id = str(evidence.get("rollout_id") or "")
        self.rollback_button.setEnabled(evidence.get("state") == "halted")
        self._show("LOCALLY HMAC-SEALED ROLLOUT PLAN STATE", evidence)

    def _enrollment_clicked(self, row: int, _column: int) -> None:
        self._show(
            "ED25519 POSSESSION-PROVED ENROLLMENT + LOCALLY HMAC-SEALED RECEIPT",
            self._row_evidence(self.enrollment_table, row),
        )

    def _preview_rollback(self) -> None:
        fabric = self.fabric
        tenant_id = str(self.tenant_box.currentData() or "")
        if fabric is None or not tenant_id or not self._selected_rollout_id:
            return
        try:
            plan = fabric.rollback_plan(tenant_id, self._selected_rollout_id)
            self._show("PROPOSAL-ONLY ROLLBACK PLAN — EXECUTION NOT AUTHORIZED", asdict(plan))
        except Exception as exc:
            self.detail.setPlainText(
                f"Rollback preview unavailable: {type(exc).__name__}: {str(exc)[:500]}"
            )


class FleetCenterDialog(QDialog):
    """Thin standalone wrapper around the embeddable FleetCenterWidget."""

    def __init__(self, fabric: FleetFabricStore | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.setWindowTitle("Fleet Center — Enterprise Local Fleet Fabric")
        self.setMinimumSize(1220, 760)
        if parent is not None:
            self.setStyleSheet(parent.styleSheet())
        layout = QVBoxLayout(self)
        self.center = FleetCenterWidget(fabric, self)
        layout.addWidget(self.center)
        footer = QHBoxLayout()
        footer.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        footer.addWidget(close)
        layout.addLayout(footer)


__all__ = ["FleetCenterDialog", "FleetCenterWidget"]
