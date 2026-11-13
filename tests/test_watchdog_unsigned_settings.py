"""Unsigned monitoring is explicit intent, never implicit privileged authority."""
from __future__ import annotations

import json

import pytest

from angerona.core.config import Config
from angerona.core.settings_catalog import resolve_area, validate_catalog


def _load_from(path, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    return Config.load()


@pytest.mark.parametrize("enabled", [False, True])
def test_watchdog_opt_in_round_trips_without_changing_operator_preferences(
    tmp_path, monkeypatch, enabled,
):
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    config = Config(data_dir=tmp_path)
    assert config.watchdog3_unsigned_enabled is False
    config.watchdog3_unsigned_enabled = enabled
    config.ollama_model = "preserve-operator-model"
    config.module_states = {"angerona.builtin.spyware_guard": True}
    config.save()
    before = config.settings_path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.watchdog3_unsigned_enabled is enabled
    assert loaded.ollama_model == "preserve-operator-model"
    assert loaded.module_states == config.module_states
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, [], {}])
def test_malformed_enablement_is_off_preserved_and_save_held(tmp_path, monkeypatch, value):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"watchdog3_unsigned_enabled": value,
                                "ollama_model": "preserved"}), encoding="utf-8")
    before = path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.watchdog3_unsigned_enabled is False
    assert loaded.ollama_model == "preserved"
    assert loaded.settings_degraded
    assert "watchdog3_unsigned_enabled" in loaded.settings_issues
    with pytest.raises(ValueError, match="degraded"):
        loaded.save()
    assert path.read_bytes() == before


@pytest.mark.parametrize("value", ["true", 1, None])
def test_invalid_explicit_save_refuses_before_overwriting_settings(tmp_path, monkeypatch, value):
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    config = Config(data_dir=tmp_path)
    config.save()
    before = config.settings_path.read_bytes()
    config.watchdog3_unsigned_enabled = value
    with pytest.raises(ValueError, match="watchdog3_unsigned_enabled"):
        config.save()
    assert config.settings_path.read_bytes() == before


def test_missing_enablement_preserves_off_default_and_legacy_bytes(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    path.write_text('{"ollama_model":"legacy-preserved"}\n', encoding="utf-8")
    before = path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.watchdog3_unsigned_enabled is False
    assert loaded.ollama_model == "legacy-preserved"
    assert path.read_bytes() == before


@pytest.mark.parametrize("values", ["false,true", "true,false", "true,true"])
def test_duplicate_opt_in_cannot_enable_monitoring(tmp_path, monkeypatch, values):
    first, second = values.split(",")
    path = tmp_path / "settings.json"
    path.write_text('{"watchdog3_unsigned_enabled":' + first
                    + ',"watchdog3_unsigned_enabled":' + second
                    + ',"ollama_model":"preserved"}', encoding="utf-8")
    before = path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.watchdog3_unsigned_enabled is False and loaded.settings_degraded
    assert loaded.ollama_model == "preserved"
    assert path.read_bytes() == before


@pytest.mark.parametrize("query", ["watchdog", "watchdog3", "third watchdog",
                                   "signage", "certificate expiry", "reduced protection"])
def test_watchdog_signing_search_has_one_settings_owner(query):
    validate_catalog()
    assert resolve_area(query).title == "Watchdog"
