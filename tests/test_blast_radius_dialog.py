from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.gui.pages import (
    BlastRadiusDialog,
    _MAX_VISIBLE_FAMILY_NODES,
    build_blast_tree,
)


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _LargeProvenance:
    def ancestry(self, _pid):
        return [
            {"id": f"PROC:{index}", "kind": "PROC", "label": f"process-{index}"}
            for index in range(_MAX_VISIBLE_FAMILY_NODES + 25)
        ]

    def subtree(self, _pid):
        return None


def test_process_family_tree_snapshot_is_bounded_for_qt_safety() -> None:
    result = build_blast_tree(_LargeProvenance(), 1234)
    assert len(result["origin"]) == _MAX_VISIBLE_FAMILY_NODES
    assert result["origin_truncated"] is True
    assert result["blast_radius"] == []


def test_process_family_tree_displays_provider_error_without_raising() -> None:
    class BrokenProvenance:
        def ancestry(self, _pid):
            raise RuntimeError("ledger temporarily unavailable")

        def subtree(self, _pid):
            return []

    app = _app()
    dialog = BlastRadiusDialog(BrokenProvenance(), 1234)
    dialog.show()
    app.processEvents()
    assert "unavailable" in dialog.summary.text().lower()
    assert "ledger temporarily unavailable" in dialog.summary.text()
    assert dialog.tree.topLevelItemCount() == 1
    dialog.close()
    dialog.deleteLater()
    app.processEvents()
