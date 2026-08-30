from __future__ import annotations

import os
from dataclasses import fields
from pathlib import Path

import pytest

from angerona.core.config import Config
from angerona.gui.setup_wizard import (
    CONFIG_KINDS,
    SETUP_PROFILES,
    STEPS,
    Field,
    collect,
    field_supported,
    normalize_setup_values,
    self_test,
    validate_secret_requirements,
    validate_setup,
)


ROOT = Path(__file__).resolve().parents[1]


def _default_values() -> dict[str, object]:
    cfg = Config()
    return {
        field.key: getattr(cfg, field.key)
        for step in STEPS
        for field in step.fields
        if field.kind in CONFIG_KINDS
    }


def test_full_setup_maps_every_supported_end_user_config_option() -> None:
    mapped = {
        field.key
        for step in STEPS
        for field in step.fields
        if field.kind in CONFIG_KINDS
    }
    internal_or_runtime = {
        "data_dir",
        "module_states",
        "teams_bot_skip_auth",
        "holographic_orb_x",
        "holographic_orb_y",
    }
    configurable = {field.name for field in fields(Config)} - internal_or_runtime
    assert configurable == mapped
    assert len(STEPS) >= 15
    assert self_test()[0]


def test_setup_profiles_never_enable_egress_or_local_listeners() -> None:
    forbidden = {
        "aria_enabled",
        "perf_governor_enabled",
        "aria_voice_enabled",
        "aria_conversation_awareness",
        "aria_always_listen",
        "aria_hand_controls",
        "aria_cloud_fallback",
        "alert_analysis_cloud_fallback",
        "aria_voice_cloud_tts",
        "aria_research_egress",
        "aria_push_enabled",
        "aria_inbox_enabled",
        "teams_bot_enabled",
        "mobile_enabled",
        "mcp_enabled",
        "fleet_service_enabled",
        "ebpf_enabled",
    }
    for profile in SETUP_PROFILES.values():
        assert not any(bool(profile.get(key, False)) for key in forbidden)


def test_setup_validation_fails_closed_for_incomplete_connectors() -> None:
    values = _default_values()
    assert validate_setup(values) == []

    values["teams_bot_enabled"] = True
    values["teams_allowed_users"] = ""
    assert any("Teams bot" in error for error in validate_setup(values))

    values = _default_values()
    values["fleet_service_enabled"] = True
    values["fleet_tenant_id"] = "x"
    assert any("Fleet tenant" in error for error in validate_setup(values))

    values = _default_values()
    values["mobile_enabled"] = True
    assert any("Signal bridge" in error for error in validate_setup(values))


def test_setup_exposes_and_validates_optional_signal_cli_trust_pins() -> None:
    mobile = next(step for step in STEPS if step.title == "Signal mobile bridge")
    fields_by_key = {field.key: field for field in mobile.fields}

    digest_field = fields_by_key["mobile_signal_cli_sha256"]
    publisher_field = fields_by_key["mobile_signal_cli_publisher"]
    assert digest_field.kind == publisher_field.kind == "text"
    assert digest_field.maximum == 64
    assert publisher_field.maximum == 512

    values = _default_values()
    assert values["mobile_signal_cli_sha256"] == ""
    assert values["mobile_signal_cli_publisher"] == ""
    assert validate_setup(values) == []

    values["mobile_signal_cli_sha256"] = "AB" * 32
    values["mobile_signal_cli_publisher"] = "  CN=Approved Signal CLI  "
    normalized = normalize_setup_values(values)
    assert normalized["mobile_signal_cli_sha256"] == "ab" * 32
    assert normalized["mobile_signal_cli_publisher"] == "CN=Approved Signal CLI"
    assert validate_setup(values) == []

    values["mobile_signal_cli_sha256"] = "not-a-digest"
    assert any("SHA-256 pin" in error for error in validate_setup(values))


def test_enabled_signal_bridge_requires_both_executable_trust_pins() -> None:
    values = _default_values()
    values.update({
        "mobile_enabled": True,
        "mobile_signal_cli": "C:/Tools/signal-cli.exe",
        "mobile_host_number": "+13035550100",
        "mobile_dest_number": "+13035550101",
    })

    errors = validate_setup(values)
    assert any("signal-cli SHA-256 pin" in error for error in errors)
    assert any("exact Authenticode publisher" in error for error in errors)

    values["mobile_signal_cli_sha256"] = "A" * 64
    values["mobile_signal_cli_publisher"] = "CN=Approved Signal CLI"
    assert validate_setup(values) == []


def test_setup_requires_protected_credentials_for_enabled_connectors() -> None:
    values = _default_values()
    values.update({
        "aria_inbox_enabled": True,
        "aria_imap_host": "imap.example.com",
        "aria_imap_user": "operator@example.com",
        "teams_bot_enabled": True,
        "teams_allowed_users": "00000000-0000-0000-0000-000000000001",
        "mobile_enabled": True,
        "mobile_signal_cli": "/opt/signal-cli",
        "mobile_host_number": "+13035550100",
        "mobile_dest_number": "+13035550101",
    })
    errors = validate_secret_requirements(values, {}, {})
    assert len(errors) == 3
    assert validate_secret_requirements(values, {
        "ARIA_IMAP_PASS": "stored",
        "ANGERONA_TEAMS_APP_PASSWORD": "stored",
        "ANGERONA_MOBILE_PIN": "4821",
    }, {}) == []


def test_jarvis_authority_requires_protected_enrollment_not_environment() -> None:
    key = "ANGERONA_JARVIS_CONTROL_TOKEN"
    values = _default_values()
    values["jarvis_control_enabled"] = True
    inherited = {key: "untrusted-inherited-token-" + "x" * 40}

    errors = validate_secret_requirements(values, {}, inherited, {})
    assert any("JARVIS controls require a protected token" in error for error in errors)

    protected = {key: "protected-enrolled-token-" + "p" * 40}
    assert validate_secret_requirements(values, {}, inherited, protected) == []

    integration = next(step for step in STEPS if step.title == "Local integrations")
    token_field = next(field for field in integration.fields if field.key == key)
    regenerate = next(
        field
        for field in integration.fields
        if field.key == "regenerate_jarvis_token"
    )
    assert token_field.kind == "password_env"
    assert regenerate.kind == "action"


def test_setup_normalizes_provider_priority_and_excludes_secrets() -> None:
    normalized = normalize_setup_values({
        "ai_provider_order": " OLLAMA, openai ",
        "github_repo": " owner/repo ",
    })
    assert normalized["ai_provider_order"] == ["ollama", "openai"]
    assert normalized["github_repo"] == "owner/repo"

    provider_step = next(step for step in STEPS if "provider credentials" in step.title)
    assert collect(provider_step, {"openai": "must-not-leak"}) == {}
    mailbox_step = next(step for step in STEPS if step.title.startswith("Mailbox"))
    assert "ARIA_IMAP_PASS" not in collect(
        mailbox_step, {"ARIA_IMAP_PASS": "must-not-leak"}
    )


def test_setup_platform_gates_privileged_sensors() -> None:
    ebpf = next(
        field
        for step in STEPS
        for field in step.fields
        if field.key == "ebpf_enabled"
    )
    blackbox = next(
        field
        for step in STEPS
        for field in step.fields
        if field.key == "blackbox_enabled"
    )
    assert field_supported(ebpf, "linux")
    assert not field_supported(ebpf, "win32")
    assert field_supported(blackbox, "win32")
    assert not field_supported(blackbox, "darwin")
    assert isinstance(ebpf, Field)


def test_runtime_exposes_full_setup_but_migration_wrapper_never_launches_it() -> None:
    installer = (ROOT / "installer" / "Angerona.iss").read_text(encoding="utf-8")
    entrypoint = (ROOT / "src" / "angerona" / "__main__.py").read_text(encoding="utf-8")
    assert 'Name: "guidedsetup"' not in installer
    assert 'Angerona Full Setup' not in installer
    assert 'Parameters: "--setup"' not in installer
    assert "CreateAppDir=no" in installer
    assert "Install-Angerona-Release.ps1" in installer
    assert '"--setup" in sys.argv' in entrypoint
    assert 'arg not in {"--setup", "--chill"}' in entrypoint


@pytest.mark.skipif(os.environ.get("CI_NO_QT") == "1", reason="Qt disabled by runner")
def test_full_setup_dialog_constructs_without_writing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from angerona.gui.setup_wizard import SetupWizard

    app = QApplication.instance() or QApplication([])
    cfg = Config(data_dir=tmp_path)
    dialog = SetupWizard(cfg)
    try:
        assert dialog.windowTitle() == "Angerona — Full Setup"
        assert dialog._stack.count() == len(STEPS)
        assert not (tmp_path / "settings.json").exists()
    finally:
        dialog.close()
        app.processEvents()
