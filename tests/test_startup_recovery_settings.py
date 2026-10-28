"""Startup recovery preferences: strict consent and real Settings persistence."""
from __future__ import annotations

import json

import pytest
from PySide6.QtWidgets import QDialog

from angerona.core.config import Config, _startup_recovery_settings
from test_settings_autostart_save_probe import _dialog


def test_recovery_defaults_are_enabled_without_enabling_daily_update_network(tmp_path):
    config = Config(data_dir=tmp_path)
    assert config.startup_recovery_enabled is True
    assert config.startup_recovery_github_enabled is True
    assert config.github_daily_check_enabled is False
    config.save()
    saved = json.loads(config.settings_path.read_text())
    assert saved["startup_recovery_enabled"] is True
    assert saved["startup_recovery_github_enabled"] is True


@pytest.mark.parametrize("field", ["startup_recovery_enabled", "startup_recovery_github_enabled"])
@pytest.mark.parametrize("value", ["false", "true", 1, 0, None, [], {}])
def test_malformed_recovery_boolean_is_off_without_discarding_other_preferences(tmp_path, monkeypatch, field, value):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    (tmp_path / "settings.json").write_text(json.dumps({field: value, "ollama_model": "keep-this-model"}))
    config = Config.load()
    assert getattr(config, field) is False
    assert config.ollama_model == "keep-this-model"


@pytest.mark.parametrize("field", ["startup_recovery_enabled", "startup_recovery_github_enabled"])
@pytest.mark.parametrize("value", ["false", 1, None])
def test_explicit_invalid_save_refuses_before_overwriting_existing_preferences(tmp_path, field, value):
    config = Config(data_dir=tmp_path)
    config.save()
    before = config.settings_path.read_bytes()
    setattr(config, field, value)
    with pytest.raises(ValueError, match=field):
        config.save()
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("raw,expected", [
    ("{}", (True, True)),
    ('{"startup_recovery_enabled":false}', (False, True)),
    ('{"startup_recovery_github_enabled":false}', (True, False)),
    ('{"startup_recovery_enabled":false,"startup_recovery_enabled":true}', (False, True)),
    ('{"startup_recovery_github_enabled":true,"startup_recovery_github_enabled":false}', (True, False)),
    ("[]", (False, False)), ("null", (False, False)), ("{broken", (False, False)),
    ('{"startup_recovery_enabled":true}' + " " * (65 * 1024), (False, False)),
], ids=["missing", "master-off", "github-off", "duplicate-master", "duplicate-github", "array", "null", "invalid", "oversized"])
def test_bounded_recovery_preferences_preserve_duplicates_and_fail_closed(raw, expected):
    assert _startup_recovery_settings(raw) == expected


def test_real_general_controls_stage_and_persist_master_and_local_only_choices(tmp_path, monkeypatch):
    dialog, config, probes, changes = _dialog(tmp_path, monkeypatch)
    try:
        assert dialog._startup_recovery_enabled.isChecked()
        assert dialog._startup_recovery_github_enabled.isChecked()
        dialog._startup_recovery_enabled.setChecked(False)
        assert not dialog._startup_recovery_github_enabled.isEnabled()
        assert config.startup_recovery_enabled is True  # Staged until Save.
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        saved = json.loads(config.settings_path.read_text())
        assert saved["startup_recovery_enabled"] is False
        assert saved["startup_recovery_github_enabled"] is True  # Dormant saved preference.
        assert probes == ["query"] and changes == []
    finally:
        dialog.close()
    second, config, _, _ = _dialog(tmp_path / "local-only", monkeypatch)
    try:
        second._startup_recovery_github_enabled.setChecked(False)
        second._save()
        assert second.result() == QDialog.Accepted
        saved = json.loads(config.settings_path.read_text())
        assert saved["startup_recovery_enabled"] is True
        assert saved["startup_recovery_github_enabled"] is False
    finally:
        second.close()


def test_fresh_load_preserves_explicit_both_off_and_missing_file_defaults(tmp_path, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    config = Config.load()
    assert config.startup_recovery_enabled is True and config.startup_recovery_github_enabled is True
    config.startup_recovery_enabled = config.startup_recovery_github_enabled = False
    config.save()
    loaded = Config.load()
    assert loaded.startup_recovery_enabled is False and loaded.startup_recovery_github_enabled is False
