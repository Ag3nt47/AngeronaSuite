from __future__ import annotations

from dataclasses import fields
import json

import pytest

from angerona.core.config import Config
from angerona.gui.setup_wizard import CONFIG_KINDS, SETUP_PROFILES, STEPS, validate_setup


def test_daily_update_is_an_explicit_network_opt_in_in_first_run_setup() -> None:
    config = Config()
    assert config.github_daily_check_enabled is False
    assert config.github_repo == "Ag3nt47/AngeronaSuite"
    controls = [field for step in STEPS for field in step.fields if field.key == "github_daily_check_enabled"]
    assert len(controls) == 1 and controls[0].kind == "check"
    assert "network" in controls[0].label.lower()
    assert "conflict" in controls[0].note.lower()
    assert all("github_daily_check_enabled" in profile and profile["github_daily_check_enabled"] is False
               for profile in SETUP_PROFILES.values())
    values = {field.key: getattr(config, field.key) for step in STEPS for field in step.fields if field.kind in CONFIG_KINDS}
    values["github_daily_check_enabled"] = True
    values["github_repo"] = "other/fork"
    assert any("canonical repository" in error for error in validate_setup(values))


def test_new_config_option_is_discoverable_with_all_existing_setup_options() -> None:
    mapped = {field.key for step in STEPS for field in step.fields if field.kind in CONFIG_KINDS}
    internal = {"data_dir", "module_states", "teams_bot_skip_auth", "holographic_orb_x", "holographic_orb_y",
                "breach_lifted_cases"}  # Controller-owned case decisions are not setup input.
    assert {field.name for field in fields(Config)} - internal == mapped


@pytest.mark.parametrize("enabled", [True, False])
def test_daily_preference_round_trips_without_enabling_other_network_features(tmp_path, monkeypatch, enabled) -> None:
    from angerona.core import data_paths

    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", classmethod(lambda cls, config: None))
    monkeypatch.setattr(Config, "publish_integration_environment", lambda self: None)
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    config = Config(data_dir=tmp_path, github_daily_check_enabled=enabled)
    config.save()
    stored = json.loads(config.settings_path.read_bytes())
    assert stored["github_daily_check_enabled"] is enabled
    assert stored["recorder_witness_enabled"] is False
    restored = Config.load()
    assert restored.github_daily_check_enabled is enabled
    assert not restored.spyware_network_enabled and not restored.spyware_beacon_enabled
    assert not restored.recorder_witness_enabled and not restored.recorder_witness_independent_host
    stored["github_daily_check_enabled"] = "true"
    config.settings_path.write_text(json.dumps(stored), encoding="utf-8")
    assert Config.load().github_daily_check_enabled is False
