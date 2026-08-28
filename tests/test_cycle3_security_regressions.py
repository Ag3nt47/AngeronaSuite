from __future__ import annotations

import json
import os
import time

import pytest

from angerona.connectors.teams_bot import TeamsBot
from angerona.core import drill_resolution, privacy, report_attest, secure_store
from angerona.engines import ai_consult
from angerona.modules.cloud_escalation import _cloud_prompt
from angerona.modules.posture_hardening import PostureHardening
from angerona.modules.purple_guard import install_policies


def test_clearing_protected_credential_deletes_store_and_live_value(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_unprotect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)
    monkeypatch.setenv("TEST_ANGERONA_SECRET", "old-live-value")

    secure_store.write_secret_map({"TEST_ANGERONA_SECRET": "stored"}, tmp_path)
    secure_store.write_secret_map({"TEST_ANGERONA_SECRET": ""}, tmp_path)

    assert "TEST_ANGERONA_SECRET" not in secure_store.read_secret_map(tmp_path)
    assert "TEST_ANGERONA_SECRET" not in os.environ


def test_internal_protected_values_never_enter_process_environment(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    key = "ANGERONA_INTERNAL_TEST_BUNDLE"
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_unprotect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)
    monkeypatch.setenv(key, "leaked-old-value")

    secure_store.write_secret_map({key: "protected-only"}, tmp_path)

    assert secure_store.read_secret_map(tmp_path)[key] == "protected-only"
    assert key not in os.environ
    monkeypatch.setenv(key, "leaked-again")
    secure_store.load_into_environment(tmp_path)
    assert key not in os.environ


def test_verified_protected_secret_is_not_published_to_environment(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda data: b"P" + data)
    monkeypatch.setattr(
        secure_store,
        "_unprotect_bytes",
        lambda data: data[1:] if data.startswith(b"P") else None,
    )
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)
    secure_store.write_secret_map({"OPENAI_API_KEY": "protected"}, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "inherited-untrusted")

    secure_store.load_into_environment(tmp_path)

    assert "OPENAI_API_KEY" not in os.environ
    assert secure_store.read_secret_map(tmp_path)["OPENAI_API_KEY"] == "protected"


def test_unreadable_secret_store_is_never_overwritten(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    path = secure_store.secure_store_path(tmp_path)
    path.write_bytes(b"existing-unreadable-ciphertext")
    monkeypatch.setattr(secure_store, "_unprotect_bytes", lambda _data: None)
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda data: b"new" + data)

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        secure_store.write_secret_map({"OPENAI_API_KEY": "replacement"}, tmp_path)

    assert path.read_bytes() == b"existing-unreadable-ciphertext"


def test_cloud_privacy_redacts_short_secrets_ipv6_unc_hostname_and_urls(monkeypatch):
    monkeypatch.setenv("COMPUTERNAME", "PRIVATE-PC")
    text = privacy.redact_text(
        r"password=hunter2 on PRIVATE-PC via 2001:db8::42 at "
        r"\\fileserver\private\case.txt and https://internal.example.local/a?q=secret"
    )

    for private in ("hunter2", "PRIVATE-PC", "2001:db8::42", "fileserver",
                    "internal.example.local", "q=secret"):
        assert private not in text
    assert "[REDACTED]" in text
    assert "hunter2" not in _cloud_prompt("Sensor", "password=hunter2")


def test_configured_ai_provider_order_is_executed(monkeypatch):
    called = []

    def first(_prompt, _system):
        called.append("first")
        return "first answer"

    def second(_prompt, _system):
        called.append("second")
        return "second answer"

    monkeypatch.setattr(ai_consult, "_PROVIDERS", [("first", first), ("second", second)])
    monkeypatch.setenv("ANGERONA_AI_ORDER", "second,first")

    result = ai_consult.consult_ai("safe prompt", allow_local_fallback=False)

    assert result["provider"] == "second"
    assert called == ["second"]


def test_teams_display_name_cannot_impersonate_allowed_id():
    bot = TeamsBot(
        enabled=True, app_id="app", app_password="secret",
        allowed_users=["operator-aad-id"], handler=lambda _text: "answer",
        token_fn=lambda *_args: "token", reply_fn=lambda *_args: 200,
    )
    activity = {
        "type": "message", "text": "status",
        "from": {"aadObjectId": "attacker-id", "name": "operator-aad-id"},
        "recipient": {"id": "bot"}, "conversation": {"id": "conversation"},
        "id": "activity", "serviceUrl": "https://smba.trafficmanager.net/",
    }

    assert bot.handle_activity(activity) is None


def test_purple_candidate_requires_a_distinct_later_run(tmp_path, monkeypatch):
    key_path = tmp_path / "bus.key"
    key_path.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    module = PostureHardening(data_dir=tmp_path)
    module.record_weakness("T1003", "Credential Access", "High", None,
                           source="redteam")
    install_policies([{"mitre": "T1003"}], "run-a", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "run-a",
        tmp_path,
        installed=["T1003"],
    )

    report = {
        "run_id": "run-a",
        "verdicts": [{
            "category": "detection", "technique": "T1003 marker",
            "stage": "Credential Access", "caught": True,
            "detected_by": "Purple Remediation Guard",
        }],
    }
    aar = tmp_path / "redteam_aar.json"
    report_attest.write_signed_json(aar, report)
    module.ingest_redteam_report(aar)
    assert module.weaknesses("VULNERABLE")

    report["run_id"] = "run-b"
    state = drill_resolution.resolution_snapshot(tmp_path)["t1003"]
    proof = drill_resolution.verify_detector_evidence(
        "T1003",
        "run-b",
        detector="Purple Remediation Guard",
        event_ts=time.time() + 1,
        event_details={"mitre": "T1003", "artifact_path": "inert-marker",
                       "detector_policy": "reviewed-redteam-candidate"},
        data_dir=tmp_path,
        expected_contract_id=state["contract_id"],
        expected_contract_digest=state["contract_digest"],
    )
    assert proof["ok"]
    report["verdicts"][0]["action_contract_id"] = state["contract_id"]
    report["verdicts"][0]["action_contract_digest"] = state["contract_digest"]
    report_attest.write_signed_json(aar, report)
    module.ingest_redteam_report(aar)
    assert any(row["mitre_id"] == "T1003" for row in module.weaknesses("PATCHED"))


def test_release_installer_hardens_before_local_code_and_does_not_grant_medium_user():
    root = os.path.dirname(os.path.dirname(__file__))
    text = open(os.path.join(root, "Install-Angerona.bat"), encoding="utf-8").read()
    assert text.index("call :harden_trust_root") < text.index(":harden_trust_root")
    assert text.index("call :harden_trust_root") < text.index("-m pip")
    assert ".install-trust-v2" in text
    assert "DirectorySecurity" in text
    assert "S-1-5-18" in text and "S-1-5-32-544" in text
    assert "ANGERONA_PRINCIPAL%:(OI)(CI)F" not in text


def test_release_installer_refuses_a_volume_root_before_acl_mutation():
    root = os.path.dirname(os.path.dirname(__file__))
    text = open(os.path.join(root, "Install-Angerona.bat"), encoding="utf-8").read()
    root_guard = 'if /I "%~dp0"=="%~d0\\" ('
    assert root_guard in text
    assert "Refusing to install or harden an entire filesystem volume root" in text
    assert text.index(root_guard) < text.index("call :harden_trust_root")
    assert text.index(root_guard) < text.index("Set-Acl -LiteralPath $env:ANGERONA_INSTALL_ROOT")


def test_source_launcher_is_bounded_and_reports_early_startup_failures():
    root = os.path.dirname(os.path.dirname(__file__))
    text = open(os.path.join(root, "start-angerona.bat"), encoding="utf-8").read()
    assert "call :harden_trust_root" not in text
    assert 'icacls.exe" "%~dp0*" /reset /T' not in text
    assert "Removing an untrusted pre-existing virtual environment" not in text
    assert text.index(":validate") < text.index(":launch")
    assert "launcher-preflight.log" in text
    assert "launcher-stderr.log" in text
    assert "AddSeconds(120)" in text
    assert "dashboard-ready.signal" in text
    assert "ANGERONA_STARTUP_READY" in text
    assert "the dashboard did not become ready" in text
    assert "Start-Sleep -Milliseconds 1500" not in text
    assert "[IO.DriveInfo]::new([IO.Path]::GetPathRoot($r.FullName))" in text
    assert "$r.PSDrive.DriveType" not in text
