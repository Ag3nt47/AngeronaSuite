"""Explicit opt-in settings and setup grouping, using only disposable roots."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def staged_module(canonical, relative):
    stage = Path(__file__).parent / relative
    if not stage.is_file():
        return __import__(canonical, fromlist=[canonical.rsplit(".", 1)[1]])
    parent, name = canonical.rsplit(".", 1)
    package = __import__(parent, fromlist=[name])
    spec = importlib.util.spec_from_file_location(canonical, stage)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[canonical] = loaded
    setattr(package, name, loaded)
    spec.loader.exec_module(loaded)
    return loaded


configuration = staged_module("angerona.core.config", "core/config.py")
setup = staged_module("angerona.gui.setup_wizard", "gui/setup_wizard.py")
KEYS = ("community_rules_enabled", "community_playbooks_enabled")


@pytest.fixture(autouse=True)
def private_settings_root(tmp_path, monkeypatch):
    from angerona.core import data_paths

    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(configuration.Config, "_load_dotenv", classmethod(lambda cls, cfg: None))
    monkeypatch.setattr(configuration.Config, "publish_integration_environment", lambda _self: None)
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))


def test_rules_and_playbooks_default_off_and_profiles_never_enable_them():
    cfg = configuration.Config()
    assert all(getattr(cfg, key) is False for key in KEYS)
    assert all(profile.get(key, False) is False for profile in setup.SETUP_PROFILES.values() for key in KEYS)


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("enabled", [True, False])
def test_exact_explicit_opt_in_round_trips_without_changing_other_preferences(key, enabled):
    cfg = configuration.Config()
    cfg.eco_mode = False
    cfg.github_tools_allow_download = False
    cfg.spyware_scan_auto_enabled = False
    cfg.spyware_scan_auto_scope = "browser"
    cfg.module_states = {"Fixture module": False}
    setattr(cfg, key, enabled)
    cfg.save()
    restored = configuration.Config.load()
    assert getattr(restored, key) is enabled
    assert getattr(restored, next(name for name in KEYS if name != key)) is False
    assert restored.eco_mode is False
    assert restored.github_tools_allow_download is False
    assert restored.spyware_scan_auto_enabled is False
    assert restored.spyware_scan_auto_scope == "browser"
    assert restored.module_states == {"Fixture module": False}


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, [], {}])
def test_malformed_opt_in_loads_off_and_save_refuses(key, value):
    cfg = configuration.Config()
    cfg.settings_path.write_text(json.dumps({key: value}), encoding="utf-8")
    assert getattr(configuration.Config.load(), key) is False
    setattr(cfg, key, value)
    original = cfg.settings_path.read_bytes()
    with pytest.raises(ValueError, match=key):
        cfg.save()
    assert cfg.settings_path.read_bytes() == original


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("first,second", [("false", "true"), ("true", "false"), ("true", "true")])
def test_duplicate_opt_in_is_off_in_both_orders(key, first, second):
    cfg = configuration.Config()
    raw = '{"' + key + '":' + first + ',"' + key + '":' + second + ',"eco_mode":false}'
    cfg.settings_path.write_text(raw, encoding="utf-8")
    restored = configuration.Config.load()
    assert getattr(restored, key) is False
    assert restored.eco_mode is False


def test_missing_new_settings_preserves_old_preferences_and_defaults_off():
    cfg = configuration.Config()
    cfg.settings_path.write_text('{"theme":"light","eco_mode":false,"github_tools_allow_download":false}', encoding="utf-8")
    restored = configuration.Config.load()
    assert restored.theme == "light"
    assert restored.eco_mode is False
    assert restored.github_tools_allow_download is False
    assert all(getattr(restored, key) is False for key in KEYS)


def test_nested_similar_name_does_not_invalidate_top_level_operator_choice():
    raw = '{"module_states":{"community_rules_enabled":false,"community_rules_enabled":true},"community_rules_enabled":true}'
    doc, _scan_duplicate = configuration._settings_document(raw)
    assert doc["community_rules_enabled"] is True


def test_new_controls_are_grouped_once_and_maintained_tools_keep_existing_keys():
    step = next(step for step in setup.STEPS if step.title == "Community tools, rules and playbooks")
    mapped = {field.key: field for field in step.fields}
    assert set(KEYS) <= set(mapped)
    assert {"github_tools_enabled", "github_tools_auto_prepare", "github_tools_allow_download",
            "github_tools_job_limit_mib", "github_tools_report_limit_mib", "github_tools_report_count",
            "github_tools_timeout_seconds"} <= set(mapped)
    assert all(sum(field.key == key for page in setup.STEPS for field in page.fields) == 1 for key in mapped)
    assert all(mapped[key].kind == "check" and "Off by default" in mapped[key].note for key in KEYS)
    assert "activate" in step.intro
    assert setup.self_test()[0]


@pytest.mark.parametrize("key", KEYS)
def test_setup_validator_requires_boolean_without_mutating_staged_values(key):
    cfg = configuration.Config()
    values = {field.key: getattr(cfg, field.key) for step in setup.STEPS for field in step.fields
              if field.kind in setup.CONFIG_KINDS}
    values[key] = "true"
    assert any(key in error for error in setup.validate_setup(values))
    assert values[key] == "true"


def test_coverage_notes_distinguish_collection_retrieval_and_privilege():
    step = next(step for step in setup.STEPS if step.title == "Sensor coverage and local evidence")
    text = " ".join(field.placeholder for field in step.fields)
    assert "not a pre-execution interception hook" in text
    assert "Forensics Capture is off by default" in text
    assert "does not grant administrator access" in text
    assert "Windows consent" in text
    assert "Retrieved text and AI explanations are data" in text
    assert all(field.kind == "info" for field in step.fields)
    assert setup.collect(step, {field.key: True for field in step.fields}) == {}


def test_info_widgets_show_notes_and_loaded_opt_ins_without_saving():
    from PySide6.QtWidgets import QApplication, QLabel

    app = QApplication.instance() or QApplication([])
    cfg = configuration.Config()
    cfg.community_rules_enabled = True
    cfg.community_playbooks_enabled = False
    dummy = SimpleNamespace(_cfg=cfg)
    page = next(step for step in setup.STEPS if step.title == "Community tools, rules and playbooks")
    for key in KEYS:
        field = next(field for field in page.fields if field.key == key)
        widget = setup.SetupWizard._make_field(dummy, field)
        assert widget.isChecked() is getattr(cfg, key)
        widget.deleteLater()
    note = setup.Field("info", "_private_fixture_info", "Coverage", placeholder="Plain-language boundary")
    widget = setup.SetupWizard._make_field(dummy, note)
    assert isinstance(widget, QLabel) and widget.text() == "Plain-language boundary"
    widget.deleteLater()
    app.processEvents()
    assert not cfg.settings_path.exists()
