from __future__ import annotations

import inspect
import json
import os
import types
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication

from angerona.core import module_base
from angerona.core.eventbus import Event, EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.gui.pages import ModuleHealthEvidenceDialog, ModuleInspector


class _ProbeModule(BaseModule):
    name = "Health Evidence Probe"
    description = "Exercises the shared degradation evidence contract."
    category = "General"

    def run(self) -> None:
        return None


class _Manager:
    @staticmethod
    def is_enabled(_name: str) -> bool:
        return True

    @staticmethod
    def set_enabled(_name: str, _enabled: bool) -> None:
        return None


class _Config:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        return None


def _trusted_overflow_evidence() -> tuple[_ProbeModule, dict[str, object]]:
    module = _ProbeModule()
    bus = EventBus(ring_size=1, priority_ring_size=1)
    module.bind(bus)
    bus.publish(Event(module.name, "first"))
    bus.publish(Event(module.name, "second"))
    module.read_bus_events()
    evidence = module.health_evidence
    assert evidence is not None
    return module, evidence


def test_degraded_health_captures_exact_trusted_caller_line() -> None:
    _module, evidence = _trusted_overflow_evidence()

    assert evidence["source_state"] == "available"
    assert evidence["source_path"] == "src/angerona/core/module_base.py"
    assert evidence["source_provenance"] == "verified-loaded-implementation"
    assert len(str(evidence["source_sha256"])) == 64
    source_line = int(evidence["source_line"])
    source = Path(module_base.__file__).read_text(encoding="utf-8").splitlines()
    assert "self.set_health(60, note)" in source[source_line - 1]
    assert "retention overflow" in str(evidence["reason"])


def test_all_builtin_snapshots_share_health_evidence_schema_and_parity() -> None:
    manager = ModuleManager(EventBus(), _Config(), target_platform="windows")
    manager.discover()

    assert not manager.discovery_errors
    assert len(manager.modules) >= 80
    for module in manager.modules.values():
        module.set_health(73, f"{module.name} bounded parity probe")
    rows = manager.capability_inventory()

    assert len(rows) == len(manager.modules)
    for row in rows:
        operational = row["operational"]
        evidence = operational["health_evidence"]
        assert operational["schema"] == "angerona.module-operational.v12"
        assert operational["health"] == 73
        assert isinstance(evidence, dict)
        assert evidence["reason"].endswith(" bounded parity probe")
        assert evidence["source_state"] == "untrusted-external"
        assert evidence["source_provenance"] == "unverified-callsite"
        assert evidence["source_path"] is None
        assert evidence["source_line"] is None
    json.dumps(rows, sort_keys=True)


def test_degraded_health_requires_bounded_serializable_reason_and_clears() -> None:
    module = _ProbeModule()
    module.set_health(42, "\x00" + ("x" * 2000))
    snapshot = module.operational_snapshot()

    assert snapshot["health"] == 42
    assert snapshot["health_note"] == "x" * 1000
    assert snapshot["health_evidence"]["reason"] == "x" * 1000
    assert snapshot["health_evidence"]["source_state"] == "untrusted-external"
    assert snapshot["health_evidence"]["source_path"] is None
    json.dumps(snapshot)

    module.set_health(30)
    assert module.health_note == (
        "Module reported 30% health without a diagnostic reason."
    )
    assert module.health_evidence["reason"] == module.health_note

    module.set_health(100, "full coverage restored")
    restored = module.operational_snapshot()
    assert restored["health_evidence"] is None
    assert restored["health_note"] == "full coverage restored"


def test_packaged_runtime_does_not_invent_a_source_path(monkeypatch) -> None:
    module = _ProbeModule()
    monkeypatch.setattr(module_base.sys, "frozen", True, raising=False)

    module.set_health(55, "packaged degradation")

    assert module.health_evidence == {
        "reason": "packaged degradation",
        "source_state": "unavailable",
        "source_path": None,
        "source_line": None,
        "source_sha256": None,
        "source_provenance": "source-less-runtime",
    }


def test_forged_code_filename_is_not_trusted_as_implementation_source() -> None:
    module = _ProbeModule()
    forged = compile(
        "probe.set_health(41, 'forged filename probe')",
        str(Path(module_base.__file__).resolve()),
        "exec",
    )
    function = types.FunctionType(
        forged,
        {"probe": module, "__name__": "angerona.core.module_base"},
    )

    function()

    evidence = module.health_evidence
    assert evidence is not None
    assert evidence["source_state"] == "untrusted-external"
    assert evidence["source_provenance"] == "unverified-callsite"
    assert evidence["source_path"] is None
    assert evidence["source_line"] is None


def test_health_evidence_dialog_highlights_exact_issue_line_red() -> None:
    app = QApplication.instance() or QApplication([])
    _module, evidence = _trusted_overflow_evidence()
    dialog = ModuleHealthEvidenceDialog("Health Evidence Probe", evidence)
    try:
        assert dialog.source_view.isReadOnly()
        assert dialog.highlighted_source_line == evidence["source_line"]
        assert dialog.highlighted_block_index is not None
        selections = dialog.source_view.extraSelections()
        assert len(selections) == 1
        assert selections[0].format.background().color() == QColor("#991b1b")
        highlighted = dialog.source_view.document().findBlockByNumber(
            dialog.highlighted_block_index
        ).text()
        assert highlighted.lstrip().startswith(f"{evidence['source_line']} |")
        assert "self.set_health(60, note)" in highlighted
    finally:
        dialog.close()
        app.processEvents()


def test_untrusted_dialog_withholds_path_and_inspector_makes_reason_clickable() -> None:
    app = QApplication.instance() or QApplication([])
    module = _ProbeModule()
    module.set_health(25, "external test degradation")
    evidence = module.health_evidence
    assert evidence is not None

    detail = ModuleHealthEvidenceDialog(module.name, evidence)
    inspector = ModuleInspector(_Manager(), EventBus(), module)
    inspector._timer.stop()
    try:
        assert detail.highlighted_source_line is None
        assert "not proven" in detail.source_view.toPlainText().lower()
        assert inspector.health_evidence_btn.isVisibleTo(inspector)
        assert "external test degradation" in inspector.health_evidence_btn.text()
        assert "source unavailable" in inspector.health_evidence_btn.text()
        assert inspect.getfile(_ProbeModule) not in inspector.health_evidence_btn.text()
    finally:
        detail.close()
        inspector.close()
        app.processEvents()


def test_inspector_refresh_reuses_one_operational_health_snapshot() -> None:
    app = QApplication.instance() or QApplication([])
    module = _ProbeModule()
    module.set_health(45, "single snapshot degradation")
    original_snapshot = module.operational_snapshot
    calls = 0

    def counted_snapshot() -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original_snapshot()

    module.operational_snapshot = counted_snapshot  # type: ignore[method-assign]
    inspector = ModuleInspector(_Manager(), EventBus(), module)
    inspector._timer.stop()
    try:
        calls = 0
        inspector._refresh()
        assert calls == 1
        assert "single snapshot degradation" in inspector.health_evidence_btn.text()
    finally:
        inspector.close()
        app.processEvents()


def test_inspector_health_text_and_evidence_use_the_same_atomic_snapshot() -> None:
    app = QApplication.instance() or QApplication([])
    module = _ProbeModule()
    module.status = "running"
    module.set_health(100, "live state changed after snapshot")
    degraded_snapshot = {
        **module.operational_snapshot(),
        "status": "running",
        "health": 45,
        "health_state": "critical",
        "health_note": "atomic snapshot degradation",
        "health_evidence": {
            "reason": "atomic snapshot degradation",
            "source_state": "unavailable",
            "source_path": None,
            "source_line": None,
        },
    }
    module.operational_snapshot = lambda: dict(degraded_snapshot)  # type: ignore[method-assign]
    inspector = ModuleInspector(_Manager(), EventBus(), module)
    inspector._timer.stop()
    try:
        inspector._refresh()
        assert "health 45%" in inspector.status_lbl.text()
        assert "atomic snapshot degradation" in inspector.status_lbl.text()
        assert inspector.health_evidence_btn.isVisibleTo(inspector)
        assert "Why health is 45%" in inspector.health_evidence_btn.text()
        assert "atomic snapshot degradation" in inspector.health_evidence_btn.text()
    finally:
        inspector.close()
        app.processEvents()


def test_inspector_does_not_mix_live_degradation_into_a_healthy_snapshot() -> None:
    app = QApplication.instance() or QApplication([])
    module = _ProbeModule()
    module.status = "running"
    healthy_snapshot = module.operational_snapshot()
    module.set_health(31, "live degradation after snapshot")
    module.operational_snapshot = lambda: dict(healthy_snapshot)  # type: ignore[method-assign]
    inspector = ModuleInspector(_Manager(), EventBus(), module)
    inspector._timer.stop()
    try:
        inspector._refresh()
        assert "health 100%" in inspector.status_lbl.text()
        assert "live degradation after snapshot" not in inspector.status_lbl.text()
        assert not inspector.health_evidence_btn.isVisibleTo(inspector)
    finally:
        inspector.close()
        app.processEvents()
