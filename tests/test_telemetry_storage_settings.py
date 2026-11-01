"""Typed telemetry preferences and complete setup mapping, with inert providers."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.config import (
    Config, TELEMETRY_STORAGE_DEFAULTS, TELEMETRY_STORAGE_RANGES,
    apply_telemetry_storage_policy, telemetry_storage_policy_values,
)
from angerona.core.settings_catalog import resolve_area
from angerona.gui.setup_wizard import CONFIG_KINDS, STEPS, collect, validate_setup


def test_defaults_and_saved_targets_preserve_unrelated_preferences(tmp_path, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    config = Config(data_dir=tmp_path, ollama_model="operator-kept-model")
    assert {key: getattr(config, key) for key in TELEMETRY_STORAGE_DEFAULTS} == TELEMETRY_STORAGE_DEFAULTS
    config.telemetry_storage_blocked = True
    config.telemetry_db_target_mib = 512
    config.telemetry_wal_target_mib = 128
    config.telemetry_min_free_mib = 4096
    config.save()
    loaded = Config.load()
    assert loaded.ollama_model == "operator-kept-model"
    assert telemetry_storage_policy_values(loaded) == {
        "blocked": True, "db_target_bytes": 512 * 1024**2,
        "wal_target_bytes": 128 * 1024**2, "min_free_bytes": 4096 * 1024**2,
    }


@pytest.mark.parametrize("key,value", [
    ("telemetry_storage_blocked", "false"), ("telemetry_storage_blocked", 1),
    ("telemetry_db_target_mib", True), ("telemetry_db_target_mib", 15),
    ("telemetry_db_target_mib", 16385), ("telemetry_db_target_mib", 256.0),
    ("telemetry_wal_target_mib", 3), ("telemetry_wal_target_mib", 1025),
    ("telemetry_wal_target_mib", "64"), ("telemetry_min_free_mib", 511),
    ("telemetry_min_free_mib", 65537), ("telemetry_min_free_mib", False),
])
def test_bad_saved_values_default_and_invalid_save_preserves_original(tmp_path, monkeypatch, key, value):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({key: value, "ollama_model": "kept"}), encoding="utf-8")
    config = Config.load()
    assert getattr(config, key) == TELEMETRY_STORAGE_DEFAULTS[key]
    assert config.ollama_model == "kept"
    original = path.read_bytes()
    setattr(config, key, value)
    with pytest.raises(ValueError):
        config.save()
    assert path.read_bytes() == original


def test_setup_maps_all_four_targets_and_validates_without_probes(tmp_path, monkeypatch):
    config = Config(data_dir=tmp_path)
    step = next(step for step in STEPS if step.title == "Updates and storage")
    mapped = {field.key: field for field in step.fields}
    assert mapped["telemetry_storage_blocked"].kind == "check"
    for key, low, high in TELEMETRY_STORAGE_RANGES:
        assert mapped[key].kind == "spin"
        assert (mapped[key].minimum, mapped[key].maximum) == (low, high)
        assert sum(field.key == key for page in STEPS for field in page.fields) == 1
    assert collect(step, dict(TELEMETRY_STORAGE_DEFAULTS)) == TELEMETRY_STORAGE_DEFAULTS
    values = {field.key: getattr(config, field.key) for page in STEPS for field in page.fields
              if field.kind in CONFIG_KINDS}
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Setup target validation must not inspect paths or capacity")
    with monkeypatch.context() as denied:
        denied.setattr(Path, "stat", forbidden)
        denied.setattr(Path, "lstat", forbidden)
        assert validate_setup(values) == []
        for key, invalid in (("telemetry_storage_blocked", "false"), ("telemetry_db_target_mib", True),
                             ("telemetry_wal_target_mib", 1025), ("telemetry_min_free_mib", "2048")):
            malformed = dict(values, **{key: invalid})
            assert any("Telemetry storage targets" in item for item in validate_setup(malformed))


@pytest.mark.parametrize("query", ["telemetry storage", "event database", "database target", "wal target"])
def test_storage_search_has_system_owner(query):
    assert resolve_area(query).title == "System"


def test_unavailable_or_malformed_apply_never_raises_a_startup_gate_or_claims_success():
    config = SimpleNamespace(**TELEMETRY_STORAGE_DEFAULTS)
    result = apply_telemetry_storage_policy(config, None)
    assert result["accepted"] is False and config._telemetry_storage_policy_pending
    class Broken:
        def configure_storage_policy(self, **_policy):
            raise RuntimeError("private-host-path")
    assert apply_telemetry_storage_policy(config, Broken())["accepted"] is False
    assert "private-host-path" not in config._telemetry_storage_apply_note
    class Malformed:
        def configure_storage_policy(self, **_policy):
            return {"schema": True, "accepted": True, "policy_generation": 1,
                    "reason_code": "", "probe_pending": True}
    assert apply_telemetry_storage_policy(config, Malformed())["accepted"] is False
    class Unexpected:
        def configure_storage_policy(self, **_policy):
            pytest.fail("Invalid typed preferences must not reach the writer")
    config.telemetry_storage_blocked = "false"
    assert apply_telemetry_storage_policy(config, Unexpected())["reason_code"] == "invalid_policy"
