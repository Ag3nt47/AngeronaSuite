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
        # Case-scoped operator decisions are controller policy history, not
        # editable setup input or a source of new response authority.
        "breach_lifted_cases",
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
        "spyware_network_enabled",
        "spyware_beacon_enabled",
        "live_debug_enabled",
        "recorder_witness_enabled",
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


def test_independent_recorder_setup_maps_public_settings_and_enrollment_handoff() -> None:
    from angerona.core.recorder_integrity import DEFAULTS, KEY_NAME

    step = next(step for step in STEPS if step.title == "Independent recorder integrity")
    mapped = {field.key: field for field in step.fields}
    assert len(step.fields) == len(mapped) == len(DEFAULTS)
    assert set(mapped) == set(DEFAULTS)
    assert all(sum(field.key == key for page in STEPS for field in page.fields) == 1
               for key in DEFAULTS)
    values = _default_values()
    assert {key: values[key] for key in DEFAULTS} == DEFAULTS
    assert all(profile["recorder_witness_enabled"] is False for profile in SETUP_PROFILES.values())
    assert mapped["recorder_witness_enabled"].kind == "check"
    assert mapped["recorder_witness_independent_host"].kind == "check"
    assert mapped["recorder_witness_authority_public_key"].kind == "multiline"
    assert mapped["recorder_witness_authority_public_key"].maximum == 2048
    assert mapped["recorder_witness_endpoint"].maximum == 512
    assert mapped["recorder_witness_certificate_sha256"].maximum == 64
    for key in ("recorder_witness_installation_id", "recorder_witness_client_id"):
        assert mapped[key].maximum == 32
    for key in ("recorder_witness_client_certificate_path", "recorder_witness_client_key_path",
                "recorder_witness_ca_bundle_path"):
        assert mapped[key].kind == "text" and mapped[key].maximum == 4096
        assert "FILE path" in mapped[key].label
    archive = mapped["recorder_witness_archive_mib"]
    assert archive.kind == "spin" and (archive.minimum, archive.maximum) == (4, 64)
    assert "Settings > General > Independent recorder integrity" in step.intro
    assert "public enrollment key" in step.intro
    assert "local protection" in step.intro
    assert KEY_NAME not in mapped
    assert collect(step, {**DEFAULTS, KEY_NAME: "never-stage-a-private-key"}) == DEFAULTS


def test_independent_recorder_setup_validation_never_provisions_or_contacts_witness(
    tmp_path, monkeypatch
) -> None:
    from angerona.core import recorder_integrity

    def forbidden(*_args, **_kwargs):
        pytest.fail("Setup validation cannot generate protected keys or construct a witness client")

    for name in ("provision_host_identity", "client_from_settings", "provider_from_config"):
        monkeypatch.setattr(recorder_integrity, name, forbidden)
    values = _default_values()
    assert validate_setup(values) == []
    assert values["recorder_witness_enabled"] is False
    values["recorder_witness_client_key_path"] = str(tmp_path / "not-created" / "client.key")
    assert validate_setup(values) == []
    values["recorder_witness_enabled"] = True
    assert any("Independent recorder enrollment" in error for error in validate_setup(values))
    assert not (tmp_path / "not-created").exists()


@pytest.mark.parametrize("key,value", [
    ("recorder_witness_enabled", "true"),
    ("recorder_witness_independent_host", 1),
    ("recorder_witness_archive_mib", True),
    ("recorder_witness_archive_mib", 3),
    ("recorder_witness_archive_mib", 65),
    ("recorder_witness_endpoint", "https://127.0.0.1/v1/authority"),
    ("recorder_witness_endpoint", "https://public.example/v1/authority"),
    ("recorder_witness_client_key_path", "relative/client.key"),
    ("recorder_witness_authority_public_key", "private-or-invalid-PEM"),
])
def test_setup_rejects_invalid_independent_recorder_settings(key, value) -> None:
    values = _default_values()
    values[key] = value
    assert any("Independent recorder enrollment" in error for error in validate_setup(values))


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


def test_full_setup_maps_spyware_and_ugcap_to_dedicated_opt_in_sections() -> None:
    spyware = next(step for step in STEPS if step.title.startswith("SpywareGuard"))
    ugcap = next(step for step in STEPS if step.title.startswith("UGCAP"))
    assert {field.key for field in spyware.fields} == {
        "spyware_auto_contain", "spyware_network_enabled", "spyware_memory_enabled",
        "spyware_beacon_enabled", "spyware_beacon_channel", "spyware_beacon_signal",
        "spyware_research_urls",
        "spyware_scan_native_enabled", "spyware_scan_zero_breach_enabled",
        "spyware_scan_priority", "spyware_scan_cpu_percent",
        "spyware_scan_memory_mib", "spyware_scan_background_percent",
        "spyware_scan_verify_admin",
    }
    from angerona.core.ugcap_witness import WITNESS_DEFAULTS
    assert {field.key for field in ugcap.fields} == {
        "ugcap_enabled", "ugcap_cadence_hours", "ugcap_vault_path", "ugcap_key_name",
        "ugcap_lockdown",
    } | WITNESS_DEFAULTS.keys()
    defaults = _default_values()
    assert defaults["spyware_research_urls"] == []
    assert defaults["spyware_auto_contain"] is defaults["ugcap_lockdown"] is True
    assert defaults["ugcap_cadence_hours"] == 168
    assert defaults["ugcap_key_name"] == "Angerona.UGCAP.v1"
    for key in ("spyware_network_enabled", "spyware_memory_enabled",
                "spyware_beacon_enabled", "spyware_beacon_signal", "ugcap_enabled"):
        assert defaults[key] is False
    enabled = next(field for field in ugcap.fields if field.key == "ugcap_enabled")
    assert field_supported(enabled, "win32")
    assert not field_supported(enabled, "linux")
    assert "restart" in ugcap.intro.lower()


def test_setup_normalizes_saved_research_urls_without_fetching() -> None:
    values = _default_values()
    values["spyware_research_urls"] = " https://example.org/report, https://example.org/report, https://example.net/news "
    normalized = normalize_setup_values(values)
    assert normalized["spyware_research_urls"] == [
        "https://example.org/report", "https://example.net/news",
    ]
    assert validate_setup(normalized) == []
    assert normalize_setup_values({"spyware_research_urls": [" https://example.org/report ", ""]}) == {
        "spyware_research_urls": ["https://example.org/report"],
    }


@pytest.mark.parametrize("urls", [
    "http://example.org/report", "https://user@example.org/report",
    "https://example.org/report#fragment", "https://example.org:8443/report",
    "https://example.org:invalid/report", "https://example.org/report with spaces",
    "https://example.org/" + "x" * 2048,
    [f"https://example.org/report/{index}" for index in range(33)],
    [42],
])
def test_setup_rejects_invalid_or_unbounded_saved_research_urls(urls) -> None:
    values = _default_values()
    values["spyware_research_urls"] = urls
    assert any("SpywareGuard research URLs" in error for error in validate_setup(values))


def test_setup_beacon_requires_existing_authorized_destination() -> None:
    values = _default_values()
    values["spyware_beacon_enabled"] = True
    assert any("emergency beacon requires" in error for error in validate_setup(values))
    values.update(aria_enabled=True, aria_push_enabled=True,
                  aria_push_url="https://example.org/operator-webhook")
    assert validate_setup(values) == []
    values["spyware_beacon_channel"] = False
    assert any("emergency beacon requires" in error for error in validate_setup(values))


@pytest.mark.parametrize("key,value", [
    ("ugcap_cadence_hours", 0), ("ugcap_cadence_hours", 8761),
    ("ugcap_cadence_hours", True), ("ugcap_key_name", "software-key"),
    ("ugcap_key_name", "Angerona.UGCAP."), ("ugcap_vault_path", "relative.ugcap"),
    ("ugcap_vault_path", "//server/share/vault.ugcap"),
    ("ugcap_vault_path", "/tmp/vault\x00.ugcap"),
])
def test_setup_rejects_invalid_integrity_vault_settings(key, value) -> None:
    values = _default_values()
    values[key] = value
    assert any("UGCAP" in error for error in validate_setup(values))


def test_setup_accepts_integrity_plan_without_touching_media_or_hardware(tmp_path) -> None:
    values = _default_values()
    values["ugcap_enabled"] = True
    assert any("UGCAP requires" in error for error in validate_setup(values))
    values["ugcap_vault_path"] = str(tmp_path / "attached-media" / "baseline.ugcap")
    assert validate_setup(values) == []
    assert not (tmp_path / "attached-media").exists()


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
    assert 'arg not in {"--setup", "--chill", "--live-debug"}' in entrypoint


@pytest.mark.skipif(os.environ.get("CI_NO_QT") == "1", reason="Qt disabled by runner")
def test_full_setup_dialog_constructs_without_writing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from angerona.gui.setup_wizard import SetupWizard

    app = QApplication.instance() or QApplication([])
    cfg = Config(data_dir=tmp_path, spyware_research_urls=[
        "https://example.org/" + ("a" * 1900) + str(index) for index in range(32)])
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    cfg.ugcap_witness_authority_public_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    dialog = SetupWizard(cfg)
    try:
        assert dialog.windowTitle() == "Angerona — Full Setup"
        assert dialog._stack.count() == len(STEPS)
        staged, secrets, providers = dialog._staged()
        assert staged["spyware_research_urls"] == cfg.spyware_research_urls
        assert staged["ugcap_key_name"] == cfg.ugcap_key_name
        assert staged["ugcap_witness_authority_public_key"] == cfg.ugcap_witness_authority_public_key.strip()
        assert not staged["identity_session_collection_enabled"]
        assert not staged["browser_extension_inventory_enabled"]
        assert not secrets and not providers
        assert not (tmp_path / "settings.json").exists()
    finally:
        dialog.close()
        app.processEvents()


def test_witness_setup_rejects_enabled_missing_or_untrusted_enrollment():
    values = _default_values()
    values["ugcap_witness_enabled"] = True
    assert any("witness enrollment" in error for error in validate_setup(values))
    values["ugcap_witness_enabled"] = False
    values["ugcap_witness_endpoint"] = "https://public.example/v1/ugcap-witness"
    assert any("witness enrollment" in error for error in validate_setup(values))
