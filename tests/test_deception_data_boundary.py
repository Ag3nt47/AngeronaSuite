from __future__ import annotations

import os
from pathlib import Path

from angerona.modules import deception, smart_deception
from angerona.core.config import Config


def test_deception_defaults_to_runtime_data_not_personal_folders(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("ANGERONA_USER_FOLDER_DECEPTION", raising=False)
    monkeypatch.setattr(deception, "_repo_root", lambda: tmp_path)
    module = deception.DeceptionModule()

    assert module._base == tmp_path / "deception" / "static"
    assert module._user_scope is False


def test_smart_deception_uses_manifested_runtime_root_and_cleans_stale_decoys(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("ANGERONA_USER_FOLDER_DECEPTION", raising=False)
    monkeypatch.setattr(smart_deception, "_runtime_deception_root", lambda: tmp_path / "smart")
    first = smart_deception.SmartDeception()

    assert first._sample_documents() == []
    assert first._targets == (tmp_path / "smart",)
    first._deploy(["one.txt", "two.txt", "three.txt"])
    deployed = {Path(item) for item in first._decoys}
    assert deployed
    assert all(path.is_relative_to(tmp_path) for path in deployed)
    assert all(path.read_text(encoding="utf-8") == smart_deception.ANCHOR_TOKEN for path in deployed)
    assert first._manifest.exists()

    second = smart_deception.SmartDeception()
    second._cleanup_deployed_decoys()
    assert not any(path.exists() for path in deployed)
    assert not second._manifest.exists()


def test_personal_folder_deception_requires_explicit_opt_in(
    tmp_path: Path, monkeypatch,
) -> None:
    home = tmp_path / "profile"
    appdata = home / "AppData" / "Roaming"
    monkeypatch.setenv("ANGERONA_USER_FOLDER_DECEPTION", "1")
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setattr(smart_deception, "_runtime_deception_root", lambda: tmp_path / "data")

    module = smart_deception.SmartDeception()

    assert module._user_scope is True
    assert module._targets == (home / "Desktop", home / "Documents", appdata)
    assert module._sample_root == home / "Documents"


def test_deception_personal_scope_is_false_by_default_and_round_trips(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("ANGERONA_USER_FOLDER_DECEPTION", raising=False)
    cfg = Config(data_dir=tmp_path)
    assert cfg.deception_user_folders is False
    cfg.deception_user_folders = True
    cfg.save()

    assert '"deception_user_folders": true' in cfg.settings_path.read_text(
        encoding="utf-8"
    )
