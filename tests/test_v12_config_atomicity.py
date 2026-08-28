from __future__ import annotations

import pytest

from angerona.core import config as config_module
from angerona.core import secure_store
from angerona.core.config import Config


def test_config_save_failure_restores_push_secret_and_settings_bytes(tmp_path, monkeypatch) -> None:
    cfg = Config(data_dir=tmp_path)
    cfg.settings_path.write_bytes(b'{"old":true}\n')
    before = cfg.settings_path.read_bytes()
    protected = {"ANGERONA_ARIA_PUSH_URL": "https://old.example/hook"}

    monkeypatch.setattr(
        secure_store,
        "read_secret_values",
        lambda names, data_root=None, strict=False: {
            name: protected[name] for name in names if name in protected
        },
    )
    monkeypatch.setattr(
        secure_store,
        "write_secret_map",
        lambda updates, data_root=None: protected.update(
            {key: value for key, value in updates.items() if value}
        )
        or [protected.pop(key, None) for key, value in updates.items() if not value]
        or tmp_path,
    )
    monkeypatch.setattr(
        config_module,
        "_atomic_write_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    cfg.aria_push_url = "https://new.example/hook"

    with pytest.raises(OSError, match="disk full"):
        cfg.save()

    assert cfg.settings_path.read_bytes() == before
    assert protected == {"ANGERONA_ARIA_PUSH_URL": "https://old.example/hook"}


def test_atomic_settings_write_leaves_no_candidate_files(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    cfg = Config(data_dir=tmp_path)
    cfg.ollama_model = "v12-test"

    cfg.save()

    assert cfg.settings_path.is_file()
    assert "v12-test" in cfg.settings_path.read_text(encoding="utf-8")
    assert list(tmp_path.glob(".settings.json.*.tmp")) == []
