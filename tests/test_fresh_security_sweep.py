from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from angerona.core import (
    capability_manifest,
    data_paths,
    report_attest,
    secure_store,
)
from angerona.core.config import Config
from angerona.core.causal_incident_graph import build_graph
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.ir_bundle import _PrivacyFilter
from angerona.core.module_manager import ModuleManager
from angerona.core.remediation_log import RemediationLog


class _Config:
    def __init__(self, root: Path) -> None:
        self.data_dir = root
        self.module_states = {}

    @property
    def external_modules_dir(self) -> Path:
        path = self.data_dir / "modules"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save(self) -> None:
        pass


def _external_module(path: Path, marker: Path | None = None) -> None:
    side_effect = f"\nPath({str(marker)!r}).touch()\n" if marker else ""
    path.write_text(
        "from pathlib import Path\n"
        "from angerona.core.module_base import BaseModule\n"
        "class SnapshotModule(BaseModule):\n"
        "    name = 'Verified Snapshot Module'\n"
        "    enabled_by_default = False\n"
        "    def run(self):\n"
        "        return\n"
        f"{side_effect}",
        encoding="utf-8",
    )


def test_external_loader_executes_verified_snapshot_not_swapped_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _Config(tmp_path)
    module = config.external_modules_dir / "snapshot.py"
    marker = tmp_path / "SWAPPED_CODE_EXECUTED"
    _external_module(module)
    manifest = capability_manifest.sample_manifest(
        module,
        capability_id="test.verified-snapshot",
        name="Verified Snapshot Module",
    )
    module.with_name("snapshot.angerona.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    decision = capability_manifest.verify_external_module(
        module,
        tmp_path / "missing-trust.json",
        allow_unsigned=True,
    )
    assert decision.accepted and decision.source_bytes

    # Simulate an attacker replacing the path after verification but before the
    # manager executes the extension.
    _external_module(module, marker)
    monkeypatch.setenv("ANGERONA_EXTERNAL_MODULES", "1")
    monkeypatch.setenv("ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES", "1")
    monkeypatch.setenv("ANGERONA_DEVELOPMENT_MODE", "1")
    monkeypatch.delenv("ANGERONA_ENFORCE_KEY_ACL", raising=False)
    monkeypatch.setattr(
        "angerona.core.module_manager.verify_external_module",
        lambda *_args, **_kwargs: decision,
    )

    classes = ModuleManager(EventBus(), config)._external_classes()
    assert [cls.name for cls in classes] == ["Verified Snapshot Module"]
    assert not marker.exists()


def test_causal_graph_marks_receipt_as_unverified_reference() -> None:
    event = Event(
        "Untrusted Sensor",
        "claims remediation",
        Severity.HIGH,
        1.0,
        {
            "receipt_id": "RCP-claim",
            "receipt_hash": "not-a-hash",
            "verified": "false",
        },
    )
    graph = build_graph([event])
    proof = next(node for node in graph["nodes"] if node["kind"] == "proof")
    edge = next(edge for edge in graph["edges"] if edge["relation"] == "verification-proof")

    assert proof["verification_claim"] is False
    assert proof["receipt_hash"] == ""
    assert proof["authenticity"] == "not-verified-by-graph"
    assert edge["confidence"] < 1.0
    assert "not independently verified" in edge["basis"]


def test_recent_receipt_authenticity_is_verified_not_field_presence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    key = tmp_path / "bus.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    ledger = RemediationLog(tmp_path / "ledger.db")
    ledger.log(
        trigger="test",
        action_key="quarantine_file",
        outcome="applied",
        verified=1,
        record={"before": "present", "after": "quarantined"},
    )
    with ledger._lock:
        receipt_json = ledger._db.execute(
            "SELECT receipt_json FROM remediation_log WHERE id = 1"
        ).fetchone()[0]
        receipt = json.loads(receipt_json)
        receipt["outcome"] = "dry_run"
        ledger._db.execute(
            "UPDATE remediation_log SET receipt_json = ? WHERE id = 1",
            (json.dumps(receipt),),
        )
        ledger._db.commit()

    row = ledger.recent(1)[0]
    assert "_angerona_hmac" in receipt
    assert row["receipt_authenticity"] is False


def test_ir_redactor_covers_ipv6_unc_urls_and_hostnames() -> None:
    raw = (
        r"remote=2001:db8::42 share=\\fileserver\private\case.txt "
        r"url=https://internal.example.local/case?q=secret "
        r"peer=beacon.example.net"
    )
    redacted = _PrivacyFilter().text(raw)
    for secret in (
        "2001:db8::42",
        "fileserver",
        "private\\case.txt",
        "internal.example.local",
        "q=secret",
        "beacon.example.net",
    ):
        assert secret not in redacted


def test_secret_store_uses_exclusive_random_temp_not_pid_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    predictable = tmp_path / f"secrets.dpapi.{os.getpid()}.tmp"
    predictable.write_bytes(b"attacker-controlled")
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda data: b"enc:" + data)
    monkeypatch.setattr(
        secure_store,
        "_unprotect_bytes",
        lambda blob: blob[4:] if blob.startswith(b"enc:") else None,
    )
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)
    key = "ANGERONA_SWEEP_TEST_SECRET"
    try:
        path = secure_store.write_secret_map({key: "stored"}, tmp_path)
        assert predictable.read_bytes() == b"attacker-controlled"
        assert path.name == "secrets.dpapi"
        assert secure_store.read_secret_map(tmp_path)[key] == "stored"
        assert hashlib.sha256(path.read_bytes()).hexdigest()
    finally:
        os.environ.pop(key, None)


def test_malformed_boolean_settings_fail_to_security_defaults(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(secure_store, "load_into_environment", lambda _root=None: None)
    monkeypatch.setenv("ANGERONA_REQUIRE_SIGNED_AAR", "test-baseline")
    (tmp_path / "settings.json").write_text(
        json.dumps(
            {
                "mcp_enabled": 1,
                "aria_cloud_fallback": "false",
                "alert_analysis_cloud_fallback": "yes",
                "teams_bot_enabled": "true",
                "teams_bot_skip_auth": "false",
                "require_signed_aar": "false",
            }
        ),
        encoding="utf-8",
    )

    config = Config.load()
    assert config.mcp_enabled is False
    assert config.aria_cloud_fallback is False
    assert config.alert_analysis_cloud_fallback is False
    assert config.teams_bot_enabled is False
    assert config.teams_bot_skip_auth is False
    assert config.require_signed_aar is True


def test_push_webhook_is_dpapi_routed_and_omitted_from_settings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured = {}

    def _write(updates, root):
        captured.update(updates)
        return Path(root) / "secrets.dpapi"

    monkeypatch.setattr(secure_store, "write_secret_map", _write)
    config = Config(data_dir=tmp_path)
    config.aria_push_url = "https://hooks.slack.com/services/T000/B000/secret-webhook"
    config.save()

    settings = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert "aria_push_url" not in settings
    assert captured["ANGERONA_ARIA_PUSH_URL"] == config.aria_push_url
    assert "secret-webhook" not in json.dumps(settings)
