from __future__ import annotations

import json

import pytest

from angerona.core.config import Config


def _configured(tmp_path) -> Config:
    config = Config(data_dir=tmp_path)
    config.mobile_enabled = True
    config.mobile_signal_cli = "C:/Program Files/SignalCli/signal-cli.exe"
    config.mobile_signal_cli_sha256 = "a" * 64
    config.mobile_signal_cli_publisher = "CN=Trusted Signal CLI Publisher"
    config.mobile_host_number = "+13035550100"
    config.mobile_dest_number = "+13035550101"
    return config


def test_mobile_executable_identity_pins_round_trip_in_settings(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setattr("angerona.core.data_paths.data_dir", lambda: tmp_path)
    config = _configured(tmp_path)
    config.save()

    raw = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert raw["mobile_signal_cli_sha256"] == "a" * 64
    assert raw["mobile_signal_cli_publisher"] == "CN=Trusted Signal CLI Publisher"

    loaded = Config.load()
    assert loaded.mobile_enabled is True
    assert loaded.mobile_signal_cli_sha256 == "a" * 64
    assert loaded.mobile_signal_cli_publisher == "CN=Trusted Signal CLI Publisher"


def test_mobile_settings_validate_exact_pins_and_canonical_identities(tmp_path) -> None:
    config = _configured(tmp_path)
    config.validate_mobile_settings()

    config.mobile_signal_cli_sha256 = "not-a-digest"
    with pytest.raises(ValueError, match="64 hexadecimal"):
        config.validate_mobile_settings()

    config = _configured(tmp_path)
    config.mobile_host_number = "303-555-0100"
    with pytest.raises(ValueError, match="E.164"):
        config.validate_mobile_settings()


def test_enabled_mobile_bridge_refuses_missing_executable_authority(tmp_path) -> None:
    config = _configured(tmp_path)
    config.mobile_signal_cli_publisher = ""

    with pytest.raises(ValueError, match="exact Authenticode publisher"):
        config.save()


def test_legacy_unpinned_mobile_authority_loads_disabled_for_repair(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setattr("angerona.core.data_paths.data_dir", lambda: tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "settings.json").write_text(
        json.dumps(
            {
                "mobile_enabled": True,
                "mobile_signal_cli": "C:/Tools/signal-cli.exe",
                "mobile_host_number": "+13035550100",
                "mobile_dest_number": "+13035550101",
            }
        ),
        encoding="utf-8",
    )

    loaded = Config.load()

    assert loaded.mobile_enabled is False
    assert loaded.mobile_signal_cli == "C:/Tools/signal-cli.exe"
    assert loaded.mobile_signal_cli_sha256 == ""
    assert loaded.mobile_signal_cli_publisher == ""
