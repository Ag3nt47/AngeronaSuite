"""Persist curated scanner intent and bounded priority choices without escalation."""
from __future__ import annotations

import json

import pytest

from angerona.core.config import Config


def _load_from(root, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: root)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    return Config.load()


def test_curated_scan_choices_and_lifted_case_survive_reload(tmp_path, monkeypatch):
    config = Config(data_dir=tmp_path)
    config.ollama_model = "retain-operator-model"
    config.github_tools_allow_download = False
    config.spyware_scan_priority = "high"
    config.spyware_scan_background_percent = 5
    config.breach_lifted_cases = ["a" * 32]
    config.save()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.ollama_model == "retain-operator-model"
    assert loaded.github_tools_allow_download is False
    assert loaded.spyware_scan_priority == "high"
    assert loaded.spyware_scan_background_percent == 5
    assert loaded.breach_lifted_cases == ["a" * 32]


@pytest.mark.parametrize("name,value", [
    ("github_tools_allow_download", "false"),
    ("breach_auto_isolate_enabled", 1),
    ("github_tools_timeout_seconds", 901),
    ("github_tools_job_limit_mib", True),
    ("spyware_scan_cpu_percent", 100),
    ("spyware_scan_priority", "realtime"),
    ("breach_lifted_cases", ["not-a-case"]),
])
def test_invalid_scan_settings_leave_existing_preferences_byte_identical(tmp_path, name, value):
    config = Config(data_dir=tmp_path)
    config.save()
    before = config.settings_path.read_bytes()
    setattr(config, name, value)
    with pytest.raises(ValueError, match=name):
        config.save()
    assert config.settings_path.read_bytes() == before


def test_malformed_network_choices_do_not_enable_actions_or_downloads(tmp_path, monkeypatch):
    (tmp_path / "settings.json").write_text(json.dumps({
        "github_tools_allow_download": "false", "github_tools_auto_prepare": 1,
        "breach_auto_isolate_enabled": "true", "spyware_scan_priority": "realtime",
        "spyware_scan_cpu_percent": True, "breach_lifted_cases": ["b" * 32, "bad", "b" * 32],
        "ollama_model": "preserved",
    }), encoding="utf-8")
    config = _load_from(tmp_path, monkeypatch)
    assert not config.github_tools_allow_download and not config.github_tools_auto_prepare
    assert not config.breach_auto_isolate_enabled
    assert config.spyware_scan_priority == "above-normal"
    assert config.spyware_scan_cpu_percent == 70
    assert config.breach_lifted_cases == ["b" * 32]
    assert config.ollama_model == "preserved"
