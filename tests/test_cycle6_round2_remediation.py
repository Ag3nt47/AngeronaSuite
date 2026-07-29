from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from angerona.connectors.teams_bot import TeamsBot
from angerona.core.config import Config
from angerona.resilience import shutdown_token


def test_teams_bypass_requires_direct_process_local_opt_in(monkeypatch):
    monkeypatch.setenv("ANGERONA_TEAMS_DEV_SKIP_AUTH", "1")
    monkeypatch.setattr(
        "angerona.connectors.teams_bot._have",
        lambda name: False,
    )
    bot = TeamsBot(skip_auth=True)
    assert bot._verify_auth("", peer_host="127.0.0.1")
    assert not bot._verify_auth("", peer_host="127.0.0.1", forwarded=True)
    assert not bot._verify_auth("", peer_host="10.20.30.40")
    monkeypatch.delenv("ANGERONA_TEAMS_DEV_SKIP_AUTH")
    assert not bot._verify_auth("", peer_host="127.0.0.1")


def test_teams_bypass_is_not_loaded_or_saved(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    (tmp_path / "settings.json").write_text(
        json.dumps({"teams_bot_skip_auth": True}), encoding="utf-8"
    )
    cfg = Config.load()
    assert cfg.teams_bot_skip_auth is False
    cfg.teams_bot_skip_auth = True
    cfg.save()
    saved = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert "teams_bot_skip_auth" not in saved


def test_shutdown_key_is_separate_and_malformed_key_fails_closed(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(shutdown_token, "_data_dir", lambda: tmp_path)
    key = shutdown_token._load_key()
    assert len(key) == 32
    assert (tmp_path / "shutdown.key").is_file()
    assert not (tmp_path / "bus.key").exists()
    (tmp_path / "shutdown.key").write_text("not-a-key", encoding="ascii")
    with pytest.raises(RuntimeError, match="malformed"):
        shutdown_token._load_key()


def test_source_preflight_rejects_redirected_required_file(tmp_path):
    import importlib.util

    script = Path(__file__).parents[1] / "tools" / "source_trust_preflight.py"
    spec = importlib.util.spec_from_file_location("source_trust_preflight", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    root = tmp_path / "checkout"
    (root / "src" / "angerona").mkdir(parents=True)
    (root / "start-angerona.bat").write_text("@echo off", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]", encoding="utf-8")
    init = root / "src" / "angerona" / "__init__.py"
    init.write_text("", encoding="utf-8")
    ok, _ = module.validate_source_root(root)
    assert ok
    init.unlink()
    try:
        init.symlink_to(root / "pyproject.toml")
    except OSError:
        pytest.skip("symlink creation unavailable")
    ok, _ = module.validate_source_root(root)
    assert not ok
