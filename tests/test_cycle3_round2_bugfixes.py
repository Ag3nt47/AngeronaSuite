from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


def test_redirected_mobile_tab_does_not_break_settings_save(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(autostart, "enable_autostart", lambda: True)
    monkeypatch.setattr(autostart, "disable_autostart", lambda: True)

    config = Config(data_dir=tmp_path)
    config.autostart_enabled = False
    config.mobile_dest_number = "+15550000000"
    applied_themes: list[str] = []
    dialog = SettingsDialog(config, lambda: None, applied_themes.append)

    assert not hasattr(dialog, "_mob_chk")  # redirect-only layout
    dialog._ollama_model.setText("qa-model")
    dialog._eco_chk.setChecked(False)
    dialog._save()

    saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert saved["ollama_model"] == "qa-model"
    assert saved["eco_mode"] is False
    assert saved["mobile_dest_number"] == "+15550000000"
    assert applied_themes
    assert not (tmp_path / ".env").exists()

