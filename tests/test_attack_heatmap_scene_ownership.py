"""The actual ATT&CK scene owns each parent and child once; no Core is started."""
from types import SimpleNamespace

from PySide6.QtCore import qInstallMessageHandler
from PySide6.QtWidgets import QGraphicsScene
from shiboken6 import delete

from angerona.gui.attack_heatmap import AttackHeatmapWindow, _CellItem
from angerona.core.attack_tracker import TACTIC_ORDER, TECHNIQUE_CATALOG


def test_actual_matrix_adds_107_cells_and_their_children_without_duplicate_warnings():
    scene = QGraphicsScene()
    clicked = []
    owner = SimpleNamespace(_scene=scene, _cells={}, _on_cell_clicked=clicked.append)
    warnings = []
    previous = qInstallMessageHandler(lambda _kind, _context, message: warnings.append(message))
    try:
        # This is the production builder, without the window constructor,
        # timers, tracker refresh, network, module manager or local-AI work.
        AttackHeatmapWindow._build_scene(owner)
        cells = [item for item in scene.items() if isinstance(item, _CellItem)]
        assert len(cells) == len(TECHNIQUE_CATALOG) == 107
        assert len(scene.items()) == 3 * len(cells) + 2 * len(TACTIC_ORDER)
        for cell in cells:
            assert cell.scene() is scene
            assert cell._lbl.parentItem() is cell and cell._lbl.scene() is scene
            assert cell._bar.parentItem() is cell and cell._bar.scene() is scene
            assert set(cell.childItems()) == {cell._lbl, cell._bar}
        assert not clicked
        assert not any("QGraphicsScene::addItem" in message for message in warnings), warnings
    finally:
        qInstallMessageHandler(previous)
        owner._cells.clear()
        scene.clear()
        delete(scene)
