"""Opt-in sharing must survive settings without enabling itself or granting actions."""
import json
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


@pytest.mark.parametrize("value,enabled", [(True, True), (False, False), ("false", False),
                                          ("true", False), (1, False)])
def test_live_sharing_requires_boolean_opt_in(tmp_path, monkeypatch, value, enabled):
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    config = Config(data_dir=tmp_path)
    assert config.live_debug_enabled is False
    config.settings_path.write_text(json.dumps({"live_debug_enabled": value}), encoding="utf-8")
    assert Config.load().live_debug_enabled is enabled


def test_live_sharing_setting_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    config = Config(data_dir=tmp_path, live_debug_enabled=True)
    config.save()
    assert json.loads(config.settings_path.read_text(encoding="utf-8"))["live_debug_enabled"] is True
    assert Config.load().live_debug_enabled is True


def test_settings_copies_read_only_reader_command_and_displays_loss(tmp_path):
    app = QApplication.instance()
    parent = QWidget()
    status = {"running": True, "birth": 1792680000.25, "queue_dropped": 7, "error": ""}
    parent.manager = SimpleNamespace(live_debug_service=SimpleNamespace(status=lambda: status))
    dialog = SettingsDialog(Config(data_dir=tmp_path), lambda: None, lambda *_: None, parent)
    assert "Queue drops: 7" in dialog._live_debug_status.text()
    assert not dialog._live_debug_chk.isChecked()
    dialog._copy_live_debug_command()
    command = app.clipboard().text()
    assert "live_debug.py" in command and "--follow" in command
    assert "--birth 1792680000.25" in command
    assert "--token" not in command and "--key" not in command
    dialog.close()
    dialog.deleteLater()
    parent.deleteLater()
    app.processEvents()
