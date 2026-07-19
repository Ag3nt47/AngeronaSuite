from __future__ import annotations

import json
import os

from angerona.connectors.teams_bot import TeamsBot
from angerona.core import privacy, secure_store
from angerona.engines import ai_consult
from angerona.modules.cloud_escalation import _cloud_prompt
from angerona.modules.posture_hardening import PostureHardening
from angerona.modules.purple_guard import install_policies


def test_clearing_protected_credential_deletes_store_and_live_value(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_unprotect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)
    monkeypatch.setenv("TEST_ANGERONA_SECRET", "old-live-value")

    secure_store.write_secret_map({"TEST_ANGERONA_SECRET": "stored"}, tmp_path)
    secure_store.write_secret_map({"TEST_ANGERONA_SECRET": ""}, tmp_path)

    assert "TEST_ANGERONA_SECRET" not in secure_store.read_secret_map(tmp_path)
    assert "TEST_ANGERONA_SECRET" not in os.environ


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


def test_purple_candidate_requires_a_distinct_later_run(tmp_path):
    module = PostureHardening(data_dir=tmp_path)
    module.record_weakness("T1003", "Credential Access", "High", None,
                           source="redteam")
    install_policies([{"mitre": "T1003"}], "run-a", tmp_path)

    report = {
        "run_id": "run-a",
        "verdicts": [{
            "category": "detection", "technique": "T1003 marker",
            "stage": "Credential Access", "caught": True,
            "detected_by": "Purple Remediation Guard",
        }],
    }
    aar = tmp_path / "redteam_aar.json"
    aar.write_text(json.dumps(report), encoding="utf-8")
    module.ingest_redteam_report(aar)
    assert module.weaknesses("VULNERABLE")

    report["run_id"] = "run-b"
    aar.write_text(json.dumps(report), encoding="utf-8")
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


def test_source_launcher_is_bounded_and_reports_early_startup_failures():
    root = os.path.dirname(os.path.dirname(__file__))
    text = open(os.path.join(root, "start-angerona.bat"), encoding="utf-8").read()
    assert "call :harden_trust_root" not in text
    assert 'icacls.exe" "%~dp0*" /reset /T' not in text
    assert "Removing an untrusted pre-existing virtual environment" not in text
    assert text.index(":validate") < text.index(":launch")
    assert "launcher-preflight.log" in text
    assert "launcher-stderr.log" in text
