from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QLabel

from angerona.core.capability_assurance import assess_capability, declaration_anchor
from angerona.core.eventbus import EventBus
from angerona.core.module_contract import build_capability_contract
from angerona.gui.pages import (
    ModuleAssuranceDialog,
    ModuleHealthEvidenceDialog,
    ModulesStatusWindow,
)
from angerona.modules.yara_scanner import YaraScannerModule


class _Manager:
    platform = "windows"

    def __init__(self, module) -> None:
        self.modules = {module.name: module}

    @staticmethod
    def is_enabled(_name: str) -> bool:
        return True

    @staticmethod
    def set_enabled(_name: str, _enabled: bool) -> None:
        return None


def _module_and_assurance(*, health: int = 100):
    module = YaraScannerModule()
    contract = build_capability_contract(
        module, capability_id="angerona.builtin.yara_scanner"
    )
    module._angerona_contract = contract
    module.status = "running"
    module._first_cycle_complete.set()
    if health < 100:
        module.set_health(health, "bounded assurance regression degradation")
    assurance = assess_capability(
        module,
        contract=contract,
        operational=module.operational_snapshot(),
        platform="windows",
        enabled=True,
    )
    return module, assurance


def test_assurance_is_weakest_dimension_and_all_deductions_are_source_anchored() -> None:
    module, assurance = _module_and_assurance()
    anchor = declaration_anchor(module)

    assert assurance.score == min(item.score for item in assurance.dimensions)
    assert assurance.score < 100
    assert assurance.interpretation.endswith("or a guarantee.")
    assert assurance.reasons
    assert anchor.source_path == "src/angerona/modules/yara_scanner.py"
    for reason in assurance.reasons:
        assert reason.reason
        assert reason.remediation
        assert reason.source_state == "available"
        assert reason.source_path == anchor.source_path
        assert isinstance(reason.source_line, int) and reason.source_line > 0
        assert reason.source_sha256 == anchor.source_sha256
        assert reason.source_provenance == "verified-loaded-declaration"


def test_absent_contract_field_points_to_class_declaration_without_inventing_a_line() -> None:
    module, assurance = _module_and_assurance()
    anchor = declaration_anchor(module)
    gap = next(
        item for item in assurance.reasons
        if item.code == "assurance.contract.settings_schema"
    )

    assert gap.source_line == anchor.class_line
    assert gap.source_anchor == "module-class-declaration"
    assert "absent field has no source line" in gap.reason


def test_degraded_runtime_keeps_reason_and_falls_back_to_verified_declaration() -> None:
    _module, assurance = _module_and_assurance(health=47)
    runtime = next(
        item for item in assurance.reasons
        if item.code == "assurance.runtime.health"
    )

    assert runtime.dimension_score == 47
    assert runtime.reason == "bounded assurance regression degradation"
    # The test called set_health from outside loaded product code. Angerona does
    # not trust that forged callsite; it truthfully anchors the module class.
    assert runtime.source_provenance == "verified-loaded-declaration"
    assert runtime.source_anchor == "module-class-declaration"


def test_assurance_evidence_dialog_links_exact_github_line_and_highlights_red() -> None:
    app = QApplication.instance() or QApplication([])
    module, assurance = _module_and_assurance()
    reason = assurance.reasons[0]
    dialog = ModuleHealthEvidenceDialog(
        module.name, reason.__dict__, evidence_label="Assurance"
    )
    try:
        link = dialog.findChild(QLabel, "moduleHealthEvidenceRepositoryLink")
        assert link is not None
        assert (
            f"/blob/main/{reason.source_path}#L{reason.source_line}" in link.text()
        )
        assert dialog.highlighted_source_line == reason.source_line
        selections = dialog.source_view.extraSelections()
        assert len(selections) == 1
        assert selections[0].format.background().color() == QColor("#991b1b")
    finally:
        dialog.close()
        app.processEvents()


def test_assurance_dialog_makes_dimensions_and_deductions_clickable() -> None:
    app = QApplication.instance() or QApplication([])
    module, assurance = _module_and_assurance()
    dialog = ModuleAssuranceDialog(module.name, assurance)
    try:
        assert dialog.dimension_table.rowCount() == 5
        assert dialog.reason_table.rowCount() == len(assurance.reasons)
        dialog._show_dimension(0, 0)
        assert "%" in dialog.dimension_detail.text()
        assert dialog.reason_table.item(0, 0).data(256) is not None
    finally:
        dialog.close()
        app.processEvents()


def test_capability_center_exposes_numeric_sortable_assurance_column() -> None:
    app = QApplication.instance() or QApplication([])
    module, assurance = _module_and_assurance()
    window = ModulesStatusWindow(_Manager(module), EventBus())
    window._timer.stop()
    try:
        assert window.table.columnCount() == 9
        assert window.table.horizontalHeaderItem(3).text() == "Assurance"
        item = window.table.item(0, 3)
        assert item is not None
        assert item.text() == f"{assurance.score}%"
        assert "not attack coverage" in item.toolTip()
        assert f"{assurance.reasons[0].source_path}:" in item.toolTip()
        window.assurance_filter.setCurrentText("Below 100%")
        assert window.table.rowCount() == 1
    finally:
        window.close()
        app.processEvents()
