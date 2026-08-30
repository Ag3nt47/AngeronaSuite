from __future__ import annotations

import os
import json
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from angerona.core.config import Config  # noqa: E402
from angerona.core.evidence_store import EvidenceStore  # noqa: E402
from angerona.core.operations_center import LocalOperationsCenter  # noqa: E402
from angerona.gui.operations_center import (  # noqa: E402
    OperationsCenterDialog,
    RadialMetricCard,
)


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_flow_dashboard_exposes_all_local_operations_tabs(tmp_path: Path) -> None:
    app = _app()
    evidence = EvidenceStore(tmp_path / "evidence.db")
    service = LocalOperationsCenter(
        tmp_path,
        evidence_store=evidence,
        config=SimpleNamespace(ui_motion_enabled=False),
        master_key=b"f" * 32,
    )
    try:
        dialog = OperationsCenterDialog(service)
        labels = [dialog.tabs.tabText(index) for index in range(dialog.tabs.count())]
        assert labels == [
            "Overview", "Cases", "Hunt", "Assets", "Detection Content",
            "Fleet Center", "DetectionForge", "AegisPath",
            "Parity & Interop", "Audit", "Info",
        ]
        assert dialog.deck.cards.keys() == {
            "cases", "evidence", "audit", "assets", "detections"
        }
        assert "LOCAL ONLY" in dialog.boundary.text()
        assert dialog.fleet_center.fabric is service.fleet_fabric
        assert dialog.detection_forge.service.registry is service.detections
        assert "UNKNOWN" in dialog.aegis_path.status_label.text()
        dialog.close()
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
    finally:
        service.close()
        evidence.close()


def test_radial_metric_hover_property_is_bounded() -> None:
    _app()
    card = RadialMetricCard(
        "cases", "CASE FLOW", "#38bdf8",
        SimpleNamespace(ui_motion_enabled=False),
    )
    card.set_metric("7", 1.7, "seven active cases")
    assert card.ratio == 1.0
    card.hoverAmount = 2.0
    assert card.hoverAmount == 1.0
    card.hoverAmount = -1.0
    assert card.hoverAmount == 0.0


def test_flow_dashboard_preference_is_persisted(tmp_path: Path) -> None:
    config = Config(data_dir=tmp_path)
    config.dashboard_mode = "flow"
    config.save()
    payload = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert payload["dashboard_mode"] == "flow"
