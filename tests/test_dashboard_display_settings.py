"""The optional orbital display can be selected and saved without changing workspace mode."""
import json

import pytest
from PySide6.QtWidgets import QDialog

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


def test_appearance_display_choice_persists_and_keeps_standard_as_default(tmp_path, monkeypatch):
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    config = Config(data_dir=tmp_path, autostart_enabled=False)
    monkeypatch.setenv("ANGERONA_DATA", str(config.data_dir))
    dialog = SettingsDialog(config, lambda: None, lambda _: None)
    try:
        assert dialog._dashboard_display.currentData() == "standard"
        dialog._dashboard_display.setCurrentIndex(dialog._dashboard_display.findData("orbital"))
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.dashboard_display == "orbital"
        assert config.dashboard_mode == "classic"
        assert json.loads(config.settings_path.read_text(encoding="utf-8"))["dashboard_display"] == "orbital"
    finally:
        dialog.close()
    loaded = Config.load()
    assert loaded is not config
    assert loaded.data_dir == config.data_dir
    assert loaded.dashboard_display == "orbital"
    assert loaded.dashboard_mode == "classic"
    reopened = SettingsDialog(loaded, lambda: None, lambda _: None)
    try:
        assert reopened._dashboard_display.currentData() == "orbital"
    finally:
        reopened.close()


@pytest.mark.parametrize("display", ["standard", "orbital"])
def test_display_setting_survives_a_fresh_config_load(tmp_path, monkeypatch, display):
    config = Config(data_dir=tmp_path, dashboard_display=display, dashboard_mode="flow")
    monkeypatch.setenv("ANGERONA_DATA", str(config.data_dir))
    config.save()

    loaded = Config.load()

    assert loaded.data_dir == config.data_dir
    assert loaded.dashboard_display == display
    assert loaded.dashboard_mode == "flow"


@pytest.mark.parametrize("display_fields", [{}, {"dashboard_display": "unsupported-view"}],
                         ids=["legacy-missing-field", "unsupported-value"])
def test_legacy_or_unsupported_display_falls_back_to_standard(tmp_path, monkeypatch, display_fields):
    config = Config(data_dir=tmp_path)
    monkeypatch.setenv("ANGERONA_DATA", str(config.data_dir))
    config.settings_path.write_text(
        json.dumps({"theme": "slate", "dashboard_mode": "flow", **display_fields}),
        encoding="utf-8",
    )

    loaded = Config.load()

    assert loaded.data_dir == config.data_dir
    assert loaded.dashboard_display == "standard"
    # Confirm that the settings file was loaded, not discarded wholesale.
    assert loaded.theme == "slate"
    assert loaded.dashboard_mode == "flow"
