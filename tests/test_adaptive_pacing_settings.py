"""Default-on pacing survives existing profiles and explicit operator opt-out."""
import json

import pytest
from PySide6.QtWidgets import QDialog

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog
from angerona.gui.setup_wizard import STEPS


@pytest.mark.parametrize("saved,expected", [({}, True),
    ({"adaptive_scan_pacing_enabled": False}, False),
    ({"adaptive_scan_pacing_enabled": True}, True)])
def test_pacing_default_and_explicit_values_reload(tmp_path, monkeypatch, saved, expected):
    config = Config(data_dir=tmp_path)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    config.settings_path.write_text(json.dumps(saved), encoding="utf-8")
    loaded = Config.load()
    assert loaded.adaptive_scan_pacing_enabled is expected
    loaded.save()
    assert Config.load().adaptive_scan_pacing_enabled is expected


def test_settings_opt_out_persists_and_full_setup_exposes_control(tmp_path, monkeypatch):
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    config = Config(data_dir=tmp_path, autostart_enabled=False)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    dialog = SettingsDialog(config, lambda: None, lambda _: None)
    try:
        assert dialog._adaptive_scan_pacing_chk.isChecked()
        dialog._adaptive_scan_pacing_chk.setChecked(False)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.adaptive_scan_pacing_enabled is False
        assert Config.load().adaptive_scan_pacing_enabled is False
    finally:
        dialog.close()
    assert any(field.key == "adaptive_scan_pacing_enabled" and field.kind == "check"
               for step in STEPS for field in step.fields)
