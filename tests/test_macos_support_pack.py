"""Optional macOS support pack: pin, verification, install and launch gate."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from angerona.platforms.macos import support_pack as pack

ROOT = Path(__file__).resolve().parents[1]
MODULE = b'SUPPORTED_PLATFORMS = ("macos",)\n'


def _module_manifest(name: str, body: bytes, **overrides) -> bytes:
    data = {
        "entrypoint": name, "sha256": hashlib.sha256(body).hexdigest(),
        "publisher": "", "signature": "", "permissions": ["event.emit"],
        "privacy": {"egress": "none"},
    }
    data.update(overrides)
    return json.dumps(data).encode()


def _build(tmp_path: Path, files: dict[str, bytes], *, version: str = "1.0.0"):
    """Create a fake reviewed tree and a fetcher for one pack revision."""
    rows = [
        {"path": path, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body),
         "mode": "755" if path.startswith("scripts/") else "644"}
        for path, body in sorted(files.items())
    ]
    manifest = json.dumps({
        "schema": pack.MANIFEST_SCHEMA, "name": "angerona-macos-support",
        "version": version, "platform": "macos", "minimum_macos": "10.13",
        "module_trust": pack.MODULE_TRUST, "modules": [], "files": rows,
    }).encode()
    root = tmp_path / "root"
    (root / "release").mkdir(parents=True, exist_ok=True)
    (root / pack.PIN_RELATIVE_PATH).write_text(json.dumps({
        "schema": pack.PIN_SCHEMA, "repository": pack.CANONICAL_REPOSITORY,
        "commit": "a" * 40, "version": version,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "manifest_size": len(manifest), "module_trust": pack.MODULE_TRUST,
    }))
    served = dict(files, **{"pack-manifest.json": manifest})

    def fetch(relative: str, maximum: int) -> bytes:
        return served[relative]

    return root, fetch, served


def _pack_files(body: bytes = MODULE) -> dict[str, bytes]:
    return {
        "modules/macos_fixture.py": body,
        "modules/macos_fixture.angerona.json": _module_manifest("macos_fixture.py", body),
        "scripts/kill-all-angerona.sh": b"#!/bin/sh\n",
        "README.md": b"readme\n",
    }


def test_shipped_pin_is_well_formed() -> None:
    pin = pack.load_pin(ROOT)
    assert pin.repository == "Ag3nt47/Angerona-macOS-Support"
    assert len(pin.commit) == 40 and len(pin.manifest_sha256) == 64


def test_install_verifies_and_enables(tmp_path: Path) -> None:
    root, fetch, _ = _build(tmp_path, _pack_files())
    data = tmp_path / "data"
    receipt = pack.install(root, data, fetch=fetch, platform="darwin")
    assert set(receipt["modules"]) == {"macos_fixture.py", "macos_fixture.angerona.json"}
    assert (data / "modules/macos_fixture.py").read_bytes() == MODULE
    if os.name != "nt":
        assert (data / "macos-support/current/scripts/kill-all-angerona.sh").stat().st_mode & 0o111
    assert pack.verify_installed(root, data) == (True, "support pack 1.0.0 verified")
    state = pack.status(root, data, platform="darwin")
    assert state["enabled"] and state["current"] and not state["should_ask"]


def test_any_changed_byte_installs_nothing(tmp_path: Path) -> None:
    root, fetch, served = _build(tmp_path, _pack_files())
    served["modules/macos_fixture.py"] = MODULE + b"#"
    data = tmp_path / "data"
    with pytest.raises(pack.SupportPackError, match="does not match"):
        pack.install(root, data, fetch=fetch, platform="darwin")
    assert not (data / "modules").exists() and not (data / "macos-support/enabled").exists()


def test_manifest_must_match_reviewed_pin(tmp_path: Path) -> None:
    root, fetch, served = _build(tmp_path, _pack_files())
    served["pack-manifest.json"] = served["pack-manifest.json"].replace(b"10.13", b"10.14")
    with pytest.raises(pack.SupportPackError, match="reviewed pin"):
        pack.install(root, tmp_path / "data", fetch=fetch, platform="darwin")


@pytest.mark.parametrize("path", ["modules/../x.py", "/etc/x", "modules/evil.py", "bin/tool"])
def test_unsafe_manifest_paths_are_refused(tmp_path: Path, path: str) -> None:
    files = _pack_files()
    files[path] = b"x"
    root, fetch, _ = _build(tmp_path, files)
    with pytest.raises(pack.SupportPackError):
        pack.install(root, tmp_path / "data", fetch=fetch, platform="darwin")


def test_module_manifest_must_stay_local_and_unsigned(tmp_path: Path) -> None:
    files = _pack_files()
    files["modules/macos_fixture.angerona.json"] = _module_manifest(
        "macos_fixture.py", MODULE, permissions=["network.connect"],
    )
    root, fetch, _ = _build(tmp_path, files)
    with pytest.raises(pack.SupportPackError, match="local-only"):
        pack.install(root, tmp_path / "data", fetch=fetch, platform="darwin")


def test_existing_foreign_module_is_never_replaced(tmp_path: Path) -> None:
    root, fetch, _ = _build(tmp_path, _pack_files())
    data = tmp_path / "data"
    (data / "modules").mkdir(parents=True)
    (data / "modules/macos_fixture.py").write_text("mine")
    with pytest.raises(pack.SupportPackError, match="already exists"):
        pack.install(root, data, fetch=fetch, platform="darwin")
    assert (data / "modules/macos_fixture.py").read_text() == "mine"


def test_install_refuses_other_platforms(tmp_path: Path) -> None:
    root, fetch, _ = _build(tmp_path, _pack_files())
    with pytest.raises(pack.SupportPackError, match="only on macOS"):
        pack.install(root, tmp_path / "data", fetch=fetch, platform="linux")


def _gate(root: Path, data: Path, environ: dict) -> tuple[str, str]:
    stream = io.StringIO()
    state = pack.apply_environment(root, data, environ=environ, stream=stream, platform="darwin")
    return state, stream.getvalue()


def test_gate_enables_verified_pack_with_visible_notice(tmp_path: Path) -> None:
    root, fetch, _ = _build(tmp_path, _pack_files())
    data = tmp_path / "data"
    pack.install(root, data, fetch=fetch, platform="darwin")
    environ: dict[str, str] = {}
    state, output = _gate(root, data, environ)
    assert state == "enabled" and "reduced-security" in output
    assert environ == {
        "ANGERONA_EXTERNAL_MODULES": "1",
        "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES": "1",
        "ANGERONA_DEVELOPMENT_MODE": "1",
    }


@pytest.mark.parametrize("change", ["tamper", "foreign", "disabled", "protected", "opt-out", "repinned"])
def test_gate_keeps_override_off(tmp_path: Path, change: str) -> None:
    root, fetch, _ = _build(tmp_path, _pack_files())
    data = tmp_path / "data"
    pack.install(root, data, fetch=fetch, platform="darwin")
    environ: dict[str, str] = {}
    if change == "tamper":
        (data / "modules/macos_fixture.py").write_bytes(MODULE + b"#")
    elif change == "foreign":
        (data / "modules/other.py").write_text("x = 1")
    elif change == "disabled":
        pack.set_enabled(data, False)
    elif change == "protected":
        environ["ANGERONA_ENFORCE_KEY_ACL"] = "1"
    elif change == "opt-out":
        environ["ANGERONA_MACOS_SUPPORT"] = "0"
    else:
        _build(tmp_path, _pack_files(MODULE + b"# newer\n"), version="1.0.1")
    state, _output = _gate(root, data, environ)
    assert state in {"rejected", "disabled", "held"}
    assert "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES" not in environ


def test_gate_is_inert_off_macos(tmp_path: Path) -> None:
    environ: dict[str, str] = {}
    assert pack.apply_environment(tmp_path, tmp_path, environ=environ, platform="linux") == "not-macos"
    assert environ == {}


def test_decline_and_uninstall(tmp_path: Path) -> None:
    root, fetch, _ = _build(tmp_path, _pack_files())
    data = tmp_path / "data"
    assert pack.status(root, data, platform="darwin")["should_ask"]
    pack.decline(data)
    assert not pack.status(root, data, platform="darwin")["should_ask"]
    pack.install(root, data, fetch=fetch, platform="darwin")
    assert pack.uninstall(data)
    assert not (data / "modules/macos_fixture.py").exists()
    assert pack.status(root, data, platform="darwin")["installed"] is False


def test_guided_setup_asks_before_downloading() -> None:
    script = (ROOT / "tools/native-quickstart.sh").read_text(encoding="utf-8")
    offer = script[script.index("offer_macos_support_pack() {"):]
    offer = offer[:offer.index("\n}\n")]
    assert '[ "$OS" = Darwin ] || return 0' in offer
    assert offer.index("should-ask") < offer.index("ask 'Optional") < offer.index(" install ")
    assert "decline" in offer and "reduced-security" in offer
