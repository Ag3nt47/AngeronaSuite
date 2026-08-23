from __future__ import annotations

import os
from pathlib import Path

import pytest

from angerona.core import secure_store
from angerona.modules import storage_hygiene


def _plain_dpapi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_unprotect_bytes", lambda value: value)
    monkeypatch.setattr(secure_store, "_private_acl", lambda _path: None)


def test_usb_pin_is_stored_but_never_published_to_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _plain_dpapi(monkeypatch)
    monkeypatch.setenv("ANGERONA_USB_PIN", "inherited-plaintext")

    secure_store.write_secret_map({"ANGERONA_USB_PIN": "004271"}, tmp_path)
    assert secure_store.read_secret_map(tmp_path)["ANGERONA_USB_PIN"] == "004271"
    assert "ANGERONA_USB_PIN" not in os.environ

    monkeypatch.setenv("ANGERONA_USB_PIN", "leaked-again")
    secure_store.load_into_environment(tmp_path)
    assert "ANGERONA_USB_PIN" not in os.environ

    monkeypatch.setenv("ANGERONA_USB_PIN", "inherited-on-unrelated-update")
    secure_store.write_secret_map({"OPENAI_API_KEY": "provider-secret"}, tmp_path)
    assert "ANGERONA_USB_PIN" not in os.environ


def test_jarvis_authority_is_stored_but_never_published_to_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _plain_dpapi(monkeypatch)
    key = "ANGERONA_JARVIS_CONTROL_TOKEN"
    protected = "protected-control-authority-" + "x" * 40
    monkeypatch.setenv(key, "inherited-untrusted-authority")

    secure_store.write_secret_map({key: protected}, tmp_path)
    assert secure_store.read_secret_map(tmp_path)[key] == protected
    assert key not in os.environ

    monkeypatch.setenv(key, "inherited-again")
    secure_store.load_into_environment(tmp_path)
    assert key not in os.environ


def test_legacy_env_reparse_source_is_ignored_and_not_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / ".env"
    source.write_text("OPENAI_API_KEY=plaintext\n", encoding="utf-8")
    monkeypatch.setattr(
        secure_store,
        "_path_traverses_reparse",
        lambda path: Path(path) == source,
    )
    writes: list[dict[str, object]] = []
    monkeypatch.setattr(
        secure_store, "write_secret_map",
        lambda updates, _root=None: writes.append(dict(updates)),
    )

    assert secure_store.migrate_legacy_env([source], tmp_path / "data") == []
    assert source.exists()
    assert writes == []


def test_changed_legacy_env_is_not_deleted_after_verified_store_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / ".env"
    source.write_text("OPENAI_API_KEY=first\n", encoding="utf-8")
    monkeypatch.setattr(secure_store, "read_secret_map", lambda _root=None: {})

    def write_and_change(_updates, _root=None):
        source.write_text("OPENAI_API_KEY=replaced\n", encoding="utf-8")
        monkeypatch.setattr(
            secure_store,
            "read_secret_map",
            lambda _root=None: {"OPENAI_API_KEY": "first"},
        )
        return tmp_path / "secrets.dpapi"

    monkeypatch.setattr(secure_store, "write_secret_map", write_and_change)

    assert secure_store.migrate_legacy_env([source], tmp_path) == []
    assert source.read_text(encoding="utf-8") == "OPENAI_API_KEY=replaced\n"


def test_protected_store_refuses_reparse_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _plain_dpapi(monkeypatch)
    data_root = tmp_path / "unsafe-data-root"
    monkeypatch.setattr(
        secure_store,
        "_path_traverses_reparse",
        lambda path: Path(path) == data_root,
    )

    with pytest.raises(RuntimeError, match="link or reparse"):
        secure_store.write_secret_map({"OPENAI_API_KEY": "secret"}, data_root)

    assert not (data_root / "secrets.dpapi").exists()


def test_storage_migration_refuses_reparse_descendant_without_moving_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy"
    dest = tmp_path / "runtime"
    source.mkdir()
    ordinary = source / "ordinary.log"
    redirected = source / "redirected"
    ordinary.write_text("keep", encoding="utf-8")
    redirected.mkdir()
    (redirected / "data.log").write_text("keep", encoding="utf-8")
    original = storage_hygiene._is_link_or_reparse
    monkeypatch.setattr(
        storage_hygiene,
        "_is_link_or_reparse",
        lambda path: Path(path) == redirected or original(Path(path)),
    )

    report = storage_hygiene.migrate_stray(source, dest)

    assert report["moved"] == []
    assert report["errors"] and "unsafe migration refused" in report["errors"][0]
    assert ordinary.exists()
    assert (redirected / "data.log").exists()
    assert not dest.exists()


def test_storage_migration_refuses_reparse_source_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy"
    dest = tmp_path / "runtime"
    source.mkdir()
    marker = source / "marker.log"
    marker.write_text("preserve", encoding="utf-8")
    original = storage_hygiene._is_link_or_reparse
    monkeypatch.setattr(
        storage_hygiene,
        "_is_link_or_reparse",
        lambda path: Path(path) == source or original(Path(path)),
    )

    report = storage_hygiene.migrate_stray(source, dest)

    assert report["moved"] == []
    assert report["errors"] and "unsafe migration refused" in report["errors"][0]
    assert marker.exists()
    assert not dest.exists()


def test_storage_purge_refuses_reparse_tree_without_deleting_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy"
    dest = tmp_path / "runtime"
    source.mkdir()
    redirected = source / "redirected"
    redirected.mkdir()
    marker = redirected / "marker.txt"
    marker.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(storage_hygiene, "default_c_location", lambda: source)
    monkeypatch.setattr(storage_hygiene, "canonical_root", lambda: dest)
    original = storage_hygiene._is_link_or_reparse
    monkeypatch.setattr(
        storage_hygiene,
        "_is_link_or_reparse",
        lambda path: Path(path) == redirected or original(Path(path)),
    )

    result = storage_hygiene.StorageHygieneModule().purge_stray(confirm=True)

    assert result["ok"] is False
    assert "unsafe purge refused" in result["error"]
    assert marker.exists()
