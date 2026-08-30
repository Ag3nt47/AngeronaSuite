"""Capture the v1.13 Local SOC programs from synthetic evidence only."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ["QT_QPA_PLATFORM"] = "windows"
os.environ.setdefault("QT_SCALE_FACTOR", "1")
os.environ.setdefault("QT_FONT_DPI", "96")
os.environ["ANGERONA_REDUCE_MOTION"] = "1"
os.environ["ANGERONA_PUBLIC_DEMO"] = "1"

from PySide6.QtCore import QCoreApplication, QEvent  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from angerona.core.exposure_graph import (  # noqa: E402
    Applicability,
    AssertionState,
    EdgeKind,
    EvidenceBinding,
    EvidenceFreshness,
    EvidenceProvenance,
    ExposureEdge,
    ExposureNode,
    NodeKind,
    PrivacyClass,
    build_coverage_manifest,
    build_exposure_snapshot,
)
from angerona.core.operations_center import LocalOperationsCenter  # noqa: E402
from angerona.gui.operations_center import OperationsCenterDialog  # noqa: E402
from angerona.gui.theme import build_qss  # noqa: E402


def _synthetic_snapshot(now: float):
    generation = 13
    nodes = (
        ExposureNode("entry", NodeKind.ENTRY_POINT, "Synthetic internet edge"),
        ExposureNode("identity", NodeKind.IDENTITY, "Demo service identity"),
        ExposureNode("service", NodeKind.SERVICE, "Synthetic API service"),
        ExposureNode(
            "control", NodeKind.CONTROL, "Demo segmentation policy",
            control_effectiveness=0.65,
        ),
        ExposureNode(
            "payroll", NodeKind.TARGET, "Synthetic payroll vault", criticality=5,
        ),
        ExposureNode(
            "engineering", NodeKind.DATA, "Synthetic engineering data", criticality=4,
        ),
    )

    def evidence(index: int) -> EvidenceBinding:
        character = format((index % 15) + 1, "x")
        return EvidenceBinding(
            evidence_id=f"public-demo-evidence-{index}",
            source="synthetic-public-demo",
            provenance=EvidenceProvenance.SENSOR,
            freshness=EvidenceFreshness.CURRENT,
            confidence=0.84 + index * 0.02,
            privacy=PrivacyClass.SENSITIVE,
            generation=generation,
            observed_at=now - 15,
            expires_at=now + 3600,
            digest="sha256:" + character * 64,
        )

    edges = (
        ExposureEdge(
            "route-1", "entry", "identity", EdgeKind.REACHES,
            AssertionState.CONFIRMED, Applicability.EXACT, evidence(1),
            "Synthetic externally exposed identity relationship",
        ),
        ExposureEdge(
            "route-2", "identity", "service", EdgeKind.AUTHENTICATES,
            AssertionState.CONFIRMED, Applicability.EXACT, evidence(2),
            "Synthetic service-token relationship",
        ),
        ExposureEdge(
            "route-3", "service", "control", EdgeKind.REACHES,
            AssertionState.CONFIRMED, Applicability.EXACT, evidence(3),
            "Synthetic policy crossing retained for training",
        ),
        ExposureEdge(
            "route-4", "control", "payroll", EdgeKind.REACHES,
            AssertionState.CONFIRMED, Applicability.EXACT, evidence(4),
            "Synthetic high-criticality route",
        ),
        ExposureEdge(
            "route-5", "control", "engineering", EdgeKind.REACHES,
            AssertionState.SPECULATIVE, Applicability.UNKNOWN, evidence(5),
            "Synthetic uncertain route shown in red",
        ),
    )
    manifest = build_coverage_manifest(
        nodes,
        edges,
        attested_at=now - 5,
        expires_at=now + 3600,
        trust_basis="synthetic-public-demo-local-provider",
    )
    return build_exposure_snapshot(
        nodes,
        edges,
        generation=generation,
        observed_at=now,
        coverage_manifest=manifest,
    )


def capture(destination: Path) -> Path:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("Angerona v1.13 Public Synthetic Demonstration")
    app.setStyleSheet(build_qss("slate"))
    with tempfile.TemporaryDirectory(prefix="angerona-public-enterprise-") as temp:
        service = LocalOperationsCenter(Path(temp), master_key=b"D" * 32)
        dialog = None
        try:
            service.bind_exposure_snapshot(_synthetic_snapshot(time.time()))
            dialog = OperationsCenterDialog(service)
            dialog.setWindowTitle(
                "Angerona v1.13 — Enterprise Programs (Synthetic Public Demo)"
            )
            dialog.resize(1800, 1000)
            dialog.tabs.setCurrentWidget(dialog.aegis_path)
            dialog.show()
            for _ in range(12):
                app.processEvents()
                time.sleep(0.02)
            if dialog.aegis_path.path_table.rowCount():
                dialog.aegis_path.path_table.selectRow(0)
                app.processEvents()
            destination.parent.mkdir(parents=True, exist_ok=True)
            pixmap = dialog.grab()
            if pixmap.isNull() or not pixmap.save(str(destination), "PNG"):
                raise RuntimeError(f"could not save screenshot: {destination}")
            return destination
        finally:
            if dialog is not None:
                dialog.close()
                dialog.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
                app.processEvents()
            service.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs" / "screenshots" / "angerona-v1.13-enterprise-programs.png",
    )
    args = parser.parse_args()
    destination = args.output if args.output.is_absolute() else ROOT / args.output
    written = capture(destination.resolve())
    print(f"PASS: wrote synthetic public screenshot {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
