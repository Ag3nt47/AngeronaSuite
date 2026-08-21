from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


def test_canonical_mobile_settings_editor_is_reachable_and_saves(tmp_path, monkeypatch) -> None:
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
    applied_themes: list[str] = []
    dialog = SettingsDialog(config, lambda: None, applied_themes.append)

    assert dialog._select_tab("Mobile Integration") is True
    assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "Mobile Integration"
    assert hasattr(dialog, "_mob_chk")
    dialog._mob_chk.setChecked(True)
    dialog._mob_cli.setText("C:/Tools/signal-cli.exe")
    dialog._mob_host.setText("+15551112222")
    dialog._mob_dest.setText("+15553334444")
    dialog._ollama_model.setText("qa-model")
    dialog._eco_chk.setChecked(False)
    dialog._save()

    saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert saved["ollama_model"] == "qa-model"
    assert saved["eco_mode"] is False
    assert saved["mobile_enabled"] is True
    assert saved["mobile_signal_cli"] == "C:/Tools/signal-cli.exe"
    assert saved["mobile_host_number"] == "+15551112222"
    assert saved["mobile_dest_number"] == "+15553334444"
    assert saved["process_baseline_enabled"] is False
    assert applied_themes
    assert mutations == []
    assert not (tmp_path / ".env").exists()


def test_restore_privacy_defaults_disables_mobile_in_ui_and_config(
    tmp_path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    config = Config(data_dir=tmp_path)
    config.mobile_enabled = True
    dialog = SettingsDialog(config, lambda: None, lambda _theme: None)

    assert dialog._mob_chk.isChecked() is True
    dialog._restore_privacy_defaults()
    assert dialog._mob_chk.isChecked() is False
    dialog._save()

    saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert config.mobile_enabled is False
    assert saved["mobile_enabled"] is False
    assert dialog.result() == QDialog.DialogCode.Accepted
    app.processEvents()


def test_mobile_pin_uses_cross_platform_protected_store_key(
    tmp_path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    from angerona.core import config as config_module

    updates: list[dict[str, str]] = []
    monkeypatch.setattr(config_module, "write_env_keys", updates.append)
    dialog = SettingsDialog(
        Config(data_dir=tmp_path), lambda: None, lambda _theme: None
    )
    dialog._mob_pin.setText("1234")

    dialog._save_mobile_pin()

    assert updates == [
        {"ANGERONA_MOBILE_PIN": "1234", "ANGERONA_MOBILE_PIN_DPAPI": ""}
    ]
    assert dialog._mob_pin.text() == ""
    dialog.close()
    app.processEvents()


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


def test_information_tab_disables_library_only_navigation(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    dialog = SettingsDialog(
        Config(data_dir=tmp_path), lambda: None, lambda _theme: None
    )
    dialog._select_tab("Information")
    dialog._info_search.setText("response broker")
    app.processEvents()

    detail = dialog._info_detail.toPlainText()
    assert "Library Only" in detail
    assert "no operator navigation in this build" in detail
    assert not dialog._info_take_me.isEnabled()
    assert dialog._info_take_me.text() == "Guidance only"

    dialog.close()
    app.processEvents()
