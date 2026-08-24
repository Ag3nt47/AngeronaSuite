from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QApplication, QMainWindow

from angerona.gui.red_team_console import RedTeamConsole


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _Parent(QMainWindow):
    _shark_narration = Signal(str)

    def _qss(self) -> str:
        return ""


def test_stage_parser_covers_both_simulation_engines() -> None:
    assert RedTeamConsole._stage_from_narration(
        "▶ STAGE: Scheduled Task Persistence [T1053.005] — marker"
    ) == "scheduled_task"
    assert RedTeamConsole._stage_from_narration(
        "▶ STAGE: Persistence (SIMULATED) [single marker] — marker"
    ) == "persistence"
    assert RedTeamConsole._stage_from_narration(
        "▶ STAGE: Exfiltration [burst] — connection"
    ) == "exfiltration"
    assert RedTeamConsole._stage_from_narration(
        "▶ STAGE: BYOVD (SIMULATED) — inert driver marker"
    ) == "defense_evasion"
    assert RedTeamConsole._stage_from_narration("ordinary detail line") is None


def test_live_feed_marks_current_and_completed_stages(tmp_path) -> None:
    app = _app()
    parent = _Parent()
    dialog = RedTeamConsole(parent, default_target=str(tmp_path))
    dialog.show()

    parent._shark_narration.emit("▶ STAGE: Initial Access [plain text lure] — marker")
    app.processEvents()
    assert dialog._chips["initial_access"].property("stageState") == "current"
    assert "Initial Access" in dialog.live_status.text()
    assert "plain text lure" in dialog.log.toPlainText()

    parent._shark_narration.emit("▶ STAGE: Discovery [system enumeration] — read only")
    app.processEvents()
    assert dialog._chips["initial_access"].property("stageState") == "complete"
    assert dialog._chips["discovery"].property("stageState") == "current"
    dialog.finish_run()
    assert dialog._chips["discovery"].property("stageState") == "complete"
    assert "complete" in dialog.live_status.text().lower()

    # The unfinished coaching option remains available for future work but does
    # not consume space or enable itself in today's run UI.
    assert dialog.cb_analogy.isHidden()
    assert not dialog.cb_analogy.isChecked()
    assert dialog._live_panel.parentWidget() is dialog._run_splitter
    dialog.close()
    parent.close()
