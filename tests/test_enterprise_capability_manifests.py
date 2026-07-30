from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from angerona.core.capability_manifest import (
    _canonical_signed_body,
    parse_manifest,
    sample_manifest,
    verify_external_module,
)
from angerona.core.eventbus import EventBus
from angerona.core.module_manager import ModuleManager


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


def _write_module(path: Path, body: str = "") -> None:
    path.write_text(
        "from angerona.core.module_base import BaseModule\n"
        "class EnterpriseTestModule(BaseModule):\n"
        "    name = 'Enterprise Test Module'\n"
        "    enabled_by_default = False\n"
        "    def run(self):\n"
        "        return\n"
        f"{body}",
        encoding="utf-8",
    )


def _manifest(module: Path) -> dict:
    return sample_manifest(
        module,
        capability_id="example.enterprise-test",
        name="Enterprise Test Module",
    )


def test_manifest_rejects_unannounced_high_risk_permission(tmp_path: Path) -> None:
    module = tmp_path / "example.py"
    _write_module(module)
    manifest = _manifest(module)
    manifest["permissions"] = ["event.emit", "kernel.everything"]
    with pytest.raises(ValueError, match="unknown permission"):
        parse_manifest(manifest, module)


def test_manifest_files_reject_duplicate_fields_and_boolean_schema(
    tmp_path: Path,
) -> None:
    module = tmp_path / "strict.py"
    _write_module(module)
    manifest = _manifest(module)
    manifest["schema_version"] = True
    with pytest.raises(ValueError, match="schema_version"):
        parse_manifest(manifest, module)

    raw = json.dumps(_manifest(module))
    raw = raw.replace(
        '"schema_version": 1',
        '"schema_version": 1, "schema_version": 1',
        1,
    )
    module.with_name("strict.angerona.json").write_text(raw, encoding="utf-8")
    decision = verify_external_module(
        module,
        tmp_path / "missing-trust.json",
        allow_unsigned=True,
    )
    assert not decision.accepted
    assert "duplicate JSON field" in decision.reason


def test_tampered_external_module_is_rejected_before_top_level_exec(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _Config(tmp_path)
    module = config.external_modules_dir / "example.py"
    sentinel = tmp_path / "SHOULD_NOT_EXIST"
    _write_module(module)
    manifest = _manifest(module)
    module.with_name("example.angerona.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    # Change the source after the digest was recorded. The new top-level side
    # effect proves verification happens before Python import/exec.
    _write_module(module, f"\nPath = __import__('pathlib').Path\nPath({str(sentinel)!r}).touch()\n")
    monkeypatch.setenv("ANGERONA_EXTERNAL_MODULES", "1")
    monkeypatch.setenv("ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES", "1")
    manager = ModuleManager(EventBus(), config)

    assert manager._external_classes() == []
    assert not sentinel.exists()
    assert manager.external_rejections
    assert "digest" in manager.external_rejections[0]["reason"]


def test_signed_external_module_is_accepted_from_trusted_publisher(
    tmp_path: Path,
) -> None:
    cryptography = pytest.importorskip("cryptography")
    assert cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    module = tmp_path / "signed.py"
    _write_module(module)
    manifest = _manifest(module)
    manifest["publisher"] = "example.publisher"

    key = Ed25519PrivateKey.generate()
    manifest["signature"] = base64.b64encode(key.sign(_canonical_signed_body(manifest))).decode(
        "ascii"
    )
    module.with_name("signed.angerona.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    trust = tmp_path / "publishers.json"
    trust.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "publishers": [
                    {
                        "id": "example.publisher",
                        "public_key": base64.b64encode(public).decode("ascii"),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    decision = verify_external_module(module, trust)
    assert decision.accepted is True
    assert decision.trust == "signed"
    assert decision.manifest is not None
    assert decision.manifest.capability_id == "example.enterprise-test"


def test_unsigned_module_requires_explicit_development_override(tmp_path: Path) -> None:
    module = tmp_path / "unsigned.py"
    _write_module(module)
    module.with_name("unsigned.angerona.json").write_text(
        json.dumps(_manifest(module)),
        encoding="utf-8",
    )
    trust = tmp_path / "missing-trust.json"

    refused = verify_external_module(module, trust)
    allowed = verify_external_module(module, trust, allow_unsigned=True)

    assert refused.accepted is False
    assert "unsigned" in refused.reason
    assert allowed.accepted is True
    assert allowed.trust == "hash-pinned-dev"


def test_protected_launcher_cannot_enable_unsigned_external_code(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _Config(tmp_path)
    module = config.external_modules_dir / "unsigned.py"
    _write_module(module)
    module.with_name("unsigned.angerona.json").write_text(
        json.dumps(_manifest(module)),
        encoding="utf-8",
    )
    monkeypatch.setenv("ANGERONA_EXTERNAL_MODULES", "1")
    monkeypatch.setenv("ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES", "1")
    monkeypatch.setenv("ANGERONA_DEVELOPMENT_MODE", "1")
    monkeypatch.setenv("ANGERONA_ENFORCE_KEY_ACL", "1")

    manager = ModuleManager(EventBus(), config)
    assert manager._external_classes() == []
    assert manager.external_rejections
    assert "unsigned" in manager.external_rejections[0]["reason"]
    summary = manager.extension_security_summary()
    assert summary["unsigned_development_override_requested"] is True
    assert summary["unsigned_development_override"] is False

    launcher = (Path(__file__).parents[1] / "start-angerona.bat").read_text(encoding="utf-8")
    assert 'set "ANGERONA_DEVELOPMENT_MODE=0"' in launcher
    assert 'set "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=0"' in launcher


def test_sample_manifest_binds_exact_source(tmp_path: Path) -> None:
    module = tmp_path / "sample.py"
    _write_module(module)
    manifest = _manifest(module)
    assert manifest["entrypoint"] == "sample.py"
    assert manifest["sha256"] == hashlib.sha256(module.read_bytes()).hexdigest()
