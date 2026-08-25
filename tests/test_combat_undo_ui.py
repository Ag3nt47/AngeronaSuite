from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.core.config import Config
from angerona.gui import pages
from angerona.gui.pages import SettingsDialog


def test_combat_history_exposes_only_verified_reversible_actions(
    tmp_path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    selected: list[str] = []
    module = SimpleNamespace(
        list_actions=lambda limit=100: [
            {
                "action_id": "verified-action",
                "action": "quarantine_file",
                "target": str(tmp_path / "threat.bin"),
                "applied_at": 1000.0,
                "reversible": True,
                "undone": False,
                "integrity_status": "verified",
                "status": "applied",
            },
            {
                "action_id": "unsigned-action",
                "action": "isolate_host",
                "target": "local",
                "applied_at": 1001.0,
                "reversible": True,
                "undone": False,
                "integrity_status": "legacy-unverified",
                "status": "applied",
            },
        ],
        undo_action=lambda action_id: (
            selected.append(action_id)
            or {"ok": True, "action": "quarantine_file", "action_id": action_id}
        ),
        undo_all=lambda: {"ok": True, "undone": 1, "failures": []},
    )
    monkeypatch.setattr(pages.QTimer, "singleShot", lambda *_args: None)
    dialog = SettingsDialog(Config(data_dir=tmp_path), lambda: None, lambda _t: None)
    dialog._combat_module = lambda: module

    dialog._refresh_combat_actions()
    assert dialog._combat_undo_selector.count() == 1
    assert dialog._combat_undo_selector.currentData() == "verified-action"
    assert dialog._combat_undo_btn.isEnabled() is True

    dialog._undo_selected_combat_action()
    assert selected == ["verified-action"]
    assert "Undo completed" in dialog._combat_history_status.text()

    dialog._undo_all_combat_actions()
    assert "1 reversible action(s) restored" in dialog._combat_history_status.text()
    dialog.close()
    app.processEvents()


def test_combat_history_disables_undo_without_reversible_actions(
    tmp_path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    module = SimpleNamespace(
        list_actions=lambda limit=100: [{
            "action_id": "unverified-action",
            "action": "isolate_host",
            "target": "local",
            "applied_at": 1000.0,
            "reversible": True,
            "undone": False,
            "integrity_status": "legacy-unverified",
            "status": "applied",
        }],
    )
    monkeypatch.setattr(pages.QTimer, "singleShot", lambda *_args: None)
    dialog = SettingsDialog(Config(data_dir=tmp_path), lambda: None, lambda _t: None)
    dialog._combat_module = lambda: module

    dialog._refresh_combat_actions()

    assert dialog._combat_undo_selector.count() == 0
    assert dialog._combat_undo_selector.isEnabled() is False
    assert dialog._combat_undo_btn.isEnabled() is False
    assert dialog._combat_undo_all_btn.isEnabled() is False
    dialog.close()
    app.processEvents()
