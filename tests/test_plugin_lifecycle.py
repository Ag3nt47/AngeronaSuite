import hashlib
import json
from types import SimpleNamespace

import pytest

from angerona.core.plugin_lifecycle import PluginLifecycle


def _source(tmp_path, body=b"print('reviewed')\n"):
    path = tmp_path / "sample.py"
    path.write_bytes(body)
    path.with_name("sample.angerona.json").write_text(
        json.dumps({"signed": True}), encoding="utf-8",
    )
    return path


def _verifier(source, _trust, allow_unsigned=False):
    body = source.read_bytes()
    manifest_path = source.with_name(f"{source.stem}.angerona.json")
    if not manifest_path.exists() or b"tampered" in body:
        return SimpleNamespace(
            accepted=False, reason="digest or manifest invalid",
            manifest=None, source_bytes=None,
        )
    digest = hashlib.sha256(body).hexdigest()
    manifest = SimpleNamespace(
        capability_id="sample.plugin", name="Sample", version="1.0.0",
        publisher="publisher-1", sha256=digest, entrypoint=source.name,
        raw={"signed": True},
    )
    return SimpleNamespace(
        accepted=True, reason="verified", manifest=manifest, source_bytes=body,
    )


def test_stage_activate_and_revoke_never_imports_plugin(tmp_path):
    source = _source(tmp_path)
    lifecycle = PluginLifecycle(
        tmp_path / "lifecycle", tmp_path / "active",
        tmp_path / "trust.json", verifier=_verifier,
    )
    assert lifecycle.stage(source, now=100).state == "staged"
    active = lifecycle.activate("sample.plugin", now=200)
    assert active.state == "active"
    assert (tmp_path / "active" / "sample.py").exists()
    revoked = lifecycle.revoke("sample.plugin", "publisher key compromised")
    assert revoked.state == "revoked"
    assert not (tmp_path / "active" / "sample.py").exists()
    assert list((tmp_path / "lifecycle" / "quarantine").glob("*.disabled"))


def test_activation_revalidates_and_quarantines_tampering(tmp_path):
    lifecycle = PluginLifecycle(
        tmp_path / "lifecycle", tmp_path / "active",
        tmp_path / "trust.json", verifier=_verifier,
    )
    lifecycle.stage(_source(tmp_path))
    staged = (
        tmp_path / "lifecycle" / "staging" / "sample.plugin" / "sample.py"
    )
    staged.write_bytes(b"tampered")
    with pytest.raises(PermissionError, match="revalidation"):
        lifecycle.activate("sample.plugin")
    assert not staged.exists()


def test_activation_refuses_an_unrelated_active_entrypoint(tmp_path):
    lifecycle = PluginLifecycle(
        tmp_path / "lifecycle", tmp_path / "active",
        tmp_path / "trust.json", verifier=_verifier,
    )
    lifecycle.stage(_source(tmp_path))
    active = tmp_path / "active" / "sample.py"
    active.write_bytes(b"tampered")
    active.with_name("sample.angerona.json").write_text(
        "{}", encoding="utf-8"
    )
    with pytest.raises(PermissionError, match="another or invalid"):
        lifecycle.activate("sample.plugin")
    assert active.read_bytes() == b"tampered"
