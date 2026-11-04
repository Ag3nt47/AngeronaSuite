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
    ("spyware_scan_timeout_seconds", 29),
    ("spyware_scan_timeout_seconds", 14401),
    ("spyware_scan_timeout_seconds", True),
    ("spyware_scan_timeout_seconds", False),
    ("spyware_scan_timeout_seconds", 3600.0),
    ("spyware_scan_timeout_seconds", "3600"),
    ("spyware_scan_timeout_seconds", None),
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


@pytest.mark.parametrize("spyware_timeout,generic_timeout", [
    (30, 300), (3600, 300), (7200, 45), (14400, 45),
])
def test_spyware_timeout_round_trip_is_independent_of_generic_timeout(
    tmp_path, monkeypatch, spyware_timeout, generic_timeout,
):
    config = Config(data_dir=tmp_path)
    assert config.spyware_scan_timeout_seconds == 3600
    assert config.github_tools_timeout_seconds == 300
    config.spyware_scan_timeout_seconds = spyware_timeout
    config.github_tools_timeout_seconds = generic_timeout
    config.ollama_model = "retain-timeout-operator-model"
    config.save()
    before = config.settings_path.read_bytes()
    saved = json.loads(before)
    assert saved["spyware_scan_timeout_seconds"] == spyware_timeout
    assert saved["github_tools_timeout_seconds"] == generic_timeout

    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.spyware_scan_timeout_seconds == spyware_timeout
    assert loaded.github_tools_timeout_seconds == generic_timeout
    assert loaded.ollama_model == "retain-timeout-operator-model"
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("value", [29, 14401, True, False, 3600.0, "3600", None])
def test_malformed_spyware_timeout_retains_default_without_rewriting_preferences(
    tmp_path, monkeypatch, value,
):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "spyware_scan_timeout_seconds": value,
        "github_tools_timeout_seconds": 45,
        "ollama_model": "preserved-malformed-timeout-model",
    }), encoding="utf-8")
    before = path.read_bytes()

    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.spyware_scan_timeout_seconds == 3600
    assert loaded.github_tools_timeout_seconds == 45
    assert loaded.ollama_model == "preserved-malformed-timeout-model"
    assert path.read_bytes() == before


def test_legacy_preferences_default_spyware_timeout_without_rewriting_file(
    tmp_path, monkeypatch,
):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "github_tools_timeout_seconds": 45,
        "spyware_scan_priority": "high",
        "ollama_model": "preserved-legacy-model",
    }, indent=3) + "\n", encoding="utf-8")
    before = path.read_bytes()

    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.spyware_scan_timeout_seconds == 3600
    assert loaded.github_tools_timeout_seconds == 45
    assert loaded.spyware_scan_priority == "high"
    assert loaded.ollama_model == "preserved-legacy-model"
    assert path.read_bytes() == before


@pytest.mark.parametrize("count", ["unlimited", 1, 8, 9, 32])
def test_retained_report_count_round_trip_does_not_change_byte_or_scan_budgets(tmp_path, monkeypatch, count):
    config = Config(data_dir=tmp_path)
    assert config.github_tools_report_count == "unlimited"
    config.github_tools_report_count = count
    config.github_tools_report_limit_mib = 80
    config.spyware_scan_timeout_seconds = 7200
    config.ollama_model = "preserved-count-model"
    config.save()
    before = config.settings_path.read_bytes()
    saved = json.loads(before)
    assert saved["github_tools_report_count"] == count
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.github_tools_report_count == count
    assert loaded.github_tools_report_limit_mib == 80
    assert loaded.spyware_scan_timeout_seconds == 7200
    assert loaded.ollama_model == "preserved-count-model"
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("value", [True, False, 0, 33, 8.0, "9", None])
def test_invalid_retained_report_count_cannot_replace_saved_preferences(tmp_path, value):
    config = Config(data_dir=tmp_path)
    config.save()
    before = config.settings_path.read_bytes()
    config.github_tools_report_count = value
    with pytest.raises(ValueError, match="github_tools_report_count"):
        config.save()
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("value", [True, False, 0, 33, 8.0, "9", None])
def test_malformed_report_count_load_keeps_eight_without_rewriting_preferences(tmp_path, monkeypatch, value):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"github_tools_report_count": value,
        "github_tools_report_limit_mib": 80, "ollama_model": "preserved-malformed-count"}), encoding="utf-8")
    before = path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.github_tools_report_count == 8
    assert loaded.github_tools_report_limit_mib == 80
    assert loaded.ollama_model == "preserved-malformed-count"
    assert path.read_bytes() == before


def test_legacy_missing_report_count_defaults_to_unlimited_without_rewriting_preferences(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"github_tools_report_limit_mib": 80,
        "ollama_model": "preserved-legacy-count"}, indent=3) + "\n", encoding="utf-8")
    before = path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.github_tools_report_count == "unlimited" and loaded.github_tools_report_limit_mib == 80
    assert loaded.ollama_model == "preserved-legacy-count"
    assert path.read_bytes() == before



@pytest.mark.parametrize("scope", ["full", "browser", "quick"])
def test_automatic_spyware_schedule_round_trip_preserves_other_scan_choices(tmp_path, monkeypatch, scope):
    config = _load_from(tmp_path, monkeypatch)
    assert config.spyware_scan_auto_enabled is True
    assert config.spyware_scan_auto_scope == "full"
    assert not config.settings_path.exists()

    config.spyware_scan_auto_enabled = scope != "browser"
    config.spyware_scan_auto_scope = scope
    config.spyware_scan_native_enabled = False
    config.spyware_scan_zero_breach_enabled = True
    config.github_tools_report_count = 9
    config.save()
    saved = config.settings_path.read_bytes()
    loaded = _load_from(tmp_path, monkeypatch)
    assert loaded.spyware_scan_auto_enabled is (scope != "browser")
    assert loaded.spyware_scan_auto_scope == scope
    assert loaded.spyware_scan_native_enabled is False
    assert loaded.spyware_scan_zero_breach_enabled is True
    assert loaded.github_tools_report_count == 9
    assert config.settings_path.read_bytes() == saved


@pytest.mark.parametrize("raw,enabled,scope", [
    ('{"github_tools_report_count":"unlimited"}', True, "full"),
    ('{"spyware_scan_auto_enabled":1,"spyware_scan_auto_scope":"browser"}', False, "browser"),
    ('{"spyware_scan_auto_enabled":true,"spyware_scan_auto_scope":"targeted"}', False, "full"),
    ('{"spyware_scan_auto_scope":["browser"]}', False, "full"),
    ('{"spyware_scan_auto_scope":null}', False, "full"),
    ('{"spyware_scan_auto_enabled":', False, "full"),
    ('{"spyware_scan_auto_enabled":false,"spyware_scan_auto_enabled":true}', False, "full"),
    ('{"spyware_scan_auto_enabled":true,"spyware_scan_auto_enabled":true}', False, "full"),
    ('{"spyware_scan_auto_scope":"quick","spyware_scan_auto_scope":"full"}', False, "full"),
    ('{"nested":{"spyware_scan_auto_scope":"quick","spyware_scan_auto_scope":"full"},'
     '"spyware_scan_auto_scope":"browser"}', True, "browser"),
])
def test_legacy_or_invalid_schedule_choices_load_without_rewriting(tmp_path, monkeypatch, raw, enabled, scope):
    path = tmp_path / "settings.json"
    path.write_text(raw, encoding="utf-8")
    original = path.read_bytes()
    config = _load_from(tmp_path, monkeypatch)
    assert config.spyware_scan_auto_enabled is enabled
    assert config.spyware_scan_auto_scope == scope
    assert path.read_bytes() == original


@pytest.mark.parametrize("name,value", [
    ("spyware_scan_auto_enabled", 1),
    ("spyware_scan_auto_enabled", "false"),
    ("spyware_scan_auto_scope", "targeted"),
    ("spyware_scan_auto_scope", "FULL"),
    ("spyware_scan_auto_scope", None),
    ("spyware_scan_auto_scope", ["quick"]),
])
def test_invalid_automatic_schedule_save_preserves_existing_preferences(tmp_path, name, value):
    config = Config(data_dir=tmp_path)
    config.save()
    before = config.settings_path.read_bytes()
    setattr(config, name, value)
    with pytest.raises(ValueError, match=name):
        config.save()
    assert config.settings_path.read_bytes() == before
