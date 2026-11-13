"""Private settings inputs; never rewrite the real operator preferences."""
import json
import pytest
from angerona.core import config as config_module, data_paths
from angerona.core.config import Config, settings_load_warning


def load_private(tmp_path, monkeypatch, raw):
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_a: None))
    (tmp_path / "settings.json").write_text(raw, encoding="utf-8")
    return Config.load()


@pytest.mark.parametrize("field", ["mcp_port", "teams_bot_port", "aria_inbox_interval_min"])
@pytest.mark.parametrize("bad", [None, [], {}, "invalid", True, -1, float("inf")])
def test_invalid_integer_does_not_reset_later_security_preferences(tmp_path, monkeypatch, field, bad):
    original = json.dumps({field: bad, "ugcap_enabled": True,
        "adversary_combat_enabled": False, "adversary_combat_mode": "contain",
        "adversary_combat_process_action": "suspend", "require_signed_aar": True,
        "ollama_model": "preserved-model", "siem_protocol": "tls"})
    cfg = load_private(tmp_path, monkeypatch, original)
    assert cfg.ugcap_enabled is True and cfg.require_signed_aar is True
    assert cfg.adversary_combat_enabled is False
    assert cfg.adversary_combat_mode == "contain"
    assert cfg.adversary_combat_process_action == "suspend"
    assert cfg.ollama_model == "preserved-model" and cfg.siem_protocol == "tls"
    assert cfg.settings_degraded and field in cfg.settings_issues
    with pytest.raises(ValueError, match="degraded"):
        cfg.save()
    assert cfg.settings_path.read_text(encoding="utf-8") == original
    warning = settings_load_warning(cfg)
    assert warning.details["fields"] == [field]
    assert warning.details["disposition"] == "health"
    assert warning.details["response_authorized"] is False
    assert warning.details["active_attack"] is False
    assert "invalid" not in json.dumps(warning.details)


@pytest.mark.parametrize("states", [None, [], {"SpywareGuard": "false"}, {"Guard": 1}])
def test_untyped_module_states_are_held_without_losing_other_settings(tmp_path, monkeypatch, states):
    cfg = load_private(tmp_path, monkeypatch, json.dumps({"module_states": states,
        "require_signed_aar": True, "ugcap_enabled": True}))
    assert cfg.module_states == {} and "module_states" in cfg.settings_issues
    assert cfg.require_signed_aar is True and cfg.ugcap_enabled is True


@pytest.mark.parametrize("raw", ["{broken", "[]", " " * (64 * 1024 + 1)],
                         ids=["broken-json", "array", "oversized"])
def test_unreadable_existing_settings_disable_automatic_response_and_keep_saved_bytes(tmp_path, monkeypatch, raw):
    cfg = load_private(tmp_path, monkeypatch, raw)
    assert cfg.settings_degraded and "settings_document" in cfg.settings_issues
    assert cfg.adversary_combat_enabled is False
    assert cfg.breach_auto_isolate_enabled is False and cfg.spyware_auto_contain is False
    with pytest.raises(ValueError, match="degraded"):
        cfg.save()
    assert cfg.settings_path.read_text(encoding="utf-8") == raw


def test_valid_preferences_round_trip_and_fresh_defaults_still_save(tmp_path, monkeypatch):
    cfg = load_private(tmp_path, monkeypatch, json.dumps({"mcp_port": "49000",
        "module_states": {"SpywareGuard": False}, "require_signed_aar": True}))
    assert cfg.mcp_port == 49000 and cfg.module_states == {"SpywareGuard": False}
    assert cfg.settings_degraded is False and settings_load_warning(cfg) is None
    cfg.save()
    reloaded = Config.load()
    assert reloaded.require_signed_aar is True and reloaded.mcp_port == 49000
    assert not reloaded.settings_degraded
