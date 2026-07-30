from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


def test_canonical_mobile_settings_save_without_console_duplicate(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    mutations: list[str] = []
    monkeypatch.setattr(
        autostart, "enable_autostart", lambda: mutations.append("enable")
    )
    monkeypatch.setattr(
        autostart, "disable_autostart", lambda: mutations.append("disable")
    )
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)

    config = Config(data_dir=tmp_path)
    config.autostart_enabled = False
    config.mobile_dest_number = "+15550000000"
    applied_themes: list[str] = []
    dialog = SettingsDialog(config, lambda: None, applied_themes.append)

    # Settings owns only the redirect; Advanced Console is the single editor.
    assert not hasattr(dialog, "_mob_chk")
    assert any(
        dialog.tabs.tabText(index) == "Mobile Integration"
        for index in range(dialog.tabs.count())
    )
    dialog._ollama_model.setText("qa-model")
    dialog._eco_chk.setChecked(False)
    dialog._save()

    saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert saved["ollama_model"] == "qa-model"
    assert saved["eco_mode"] is False
    assert saved["mobile_dest_number"] == "+15550000000"
    assert saved["process_baseline_enabled"] is False
    assert applied_themes
    assert mutations == []
    assert not (tmp_path / ".env").exists()


def test_information_tab_search_and_take_me_there(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    dialog = SettingsDialog(
        Config(data_dir=tmp_path), lambda: None, lambda _theme: None
    )
    dialog._select_tab("Information")
    dialog._info_search.setText("microphone")
    app.processEvents()
    assert dialog._info_list.count() >= 1
    assert "Local AI and ARIA" in dialog._info_detail.toPlainText()
    dialog._info_take_me.click()
    app.processEvents()
    assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "ARIA"
    dialog.close()
    app.processEvents()
