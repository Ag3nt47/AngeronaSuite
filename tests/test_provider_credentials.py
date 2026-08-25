from __future__ import annotations

import os
import sys
from types import ModuleType, SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QPushButton, QWidget

from angerona.core import autostart
from angerona.core.config import Config
from angerona.core.provider_credentials import (
    PROVIDER_CREDENTIALS,
    canonical_updates,
    configured_provider_ids,
    credential_value,
    credential_values,
    provider_form_values,
    save_provider_credentials,
)
from angerona.engines import ai_consult
from angerona.engines import self_compiler
from angerona.gui import upgrade_console
from angerona.gui.pages import ModuleInspector, SettingsDialog
from angerona.core.module_base import BaseModule
from angerona.modules.cloud_escalation import CloudEscalationModule


def _clear_provider_environment(monkeypatch) -> None:
    from angerona.core import secure_store

    monkeypatch.setattr(secure_store, "read_secret_map", lambda _root=None: {})
    for provider in PROVIDER_CREDENTIALS:
        monkeypatch.delenv(provider.environment_key, raising=False)
        for alias in provider.legacy_aliases:
            monkeypatch.delenv(alias, raising=False)


def test_gemini_legacy_names_are_read_but_canonical_value_wins(monkeypatch) -> None:
    _clear_provider_environment(monkeypatch)
    source = {
        "GEMINI_API_KEYS": "canonical-a, canonical-b",
        "GEMINI_API_KEY": "stale-singular",
        "GOOGLE_API_KEY": "stale-google-name",
    }

    assert credential_values("gemini", source) == (
        "canonical-a",
        "canonical-b",
    )
    assert credential_value("gemini", {"GOOGLE_API_KEY": "legacy-only"}) == (
        "legacy-only"
    )


def test_explicit_provider_save_clears_aliases_and_empty_credentials(
    monkeypatch,
) -> None:
    captured: list[dict[str, str]] = []
    from angerona.core import config as config_module

    monkeypatch.setattr(
        config_module,
        "write_env_keys",
        lambda updates: captured.append(dict(updates)) or "protected-store",
    )

    result = save_provider_credentials(
        {"gemini": " key-a, key-b ", "openai": ""}
    )

    assert result == "protected-store"
    assert captured == [{
        "GEMINI_API_KEYS": "key-a,key-b",
        "GEMINI_API_KEY": "",
        "GOOGLE_API_KEY": "",
        "OPENAI_API_KEY": "",
    }]
    assert canonical_updates({"anthropic": None}) == {"ANTHROPIC_API_KEY": ""}
    with pytest.raises(ValueError, match="control character"):
        canonical_updates({"openai": "safe\r\nInjected: yes"})


def test_provider_status_and_form_mapping_use_canonical_ids() -> None:
    source = {
        "ANTHROPIC_API_KEY": "anthropic-secret",
        "GROQ_API_KEY": "groq-secret",
    }

    assert configured_provider_ids(source) == ("anthropic", "groq")
    form = provider_form_values(source)
    assert form["anthropic"] == "anthropic-secret"
    assert set(form) == {provider.provider_id for provider in PROVIDER_CREDENTIALS}


def test_default_provider_lookup_is_scoped_to_protected_store(monkeypatch) -> None:
    from angerona.core import secure_store

    _clear_provider_environment(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "inherited-attacker-value")
    monkeypatch.setattr(
        secure_store,
        "read_secret_map",
        lambda _root=None: {"OPENAI_API_KEY": "protected-approved-value"},
    )

    assert credential_value("openai") == "protected-approved-value"


def test_settings_main_save_persists_and_clears_provider_credentials(
    tmp_path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    _clear_provider_environment(monkeypatch)
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    from angerona.core import config as config_module

    captured: list[dict[str, str]] = []
    monkeypatch.setattr(
        config_module,
        "write_env_keys",
        lambda updates: captured.append(dict(updates)) or tmp_path / "secrets.dpapi",
    )
    guide_module = ModuleType("angerona.core.capability_guide")
    guide_module.search_guides = lambda _query: ()
    monkeypatch.setitem(sys.modules, "angerona.core.capability_guide", guide_module)
    config = Config(data_dir=tmp_path)
    config.ai_provider_order = [
        "anthropic", "gemini", "openai", "openrouter", "ollama"
    ]
    dialog = SettingsDialog(config, lambda: None, lambda _theme: None)
    ordered = [
        dialog._ai_order_list.item(index).data(Qt.UserRole)
        for index in range(dialog._ai_order_list.count())
    ]
    assert ordered.index("groq") < ordered.index("ollama")
    dialog._key_fields["gemini"].setText("gemini-a, gemini-b")
    dialog._key_fields["openai"].setText("")

    dialog._save()

    provider_write = next(
        update for update in captured if "GEMINI_API_KEYS" in update
    )
    assert provider_write["GEMINI_API_KEYS"] == "gemini-a,gemini-b"
    assert provider_write["GEMINI_API_KEY"] == ""
    assert provider_write["GOOGLE_API_KEY"] == ""
    assert provider_write["OPENAI_API_KEY"] == ""
    assert dialog.result() == QDialog.DialogCode.Accepted
    app.processEvents()


def test_advanced_console_has_read_only_status_and_canonical_route(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    _clear_provider_environment(monkeypatch)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_start_pack_status",
        lambda _self: None,
    )
    window = upgrade_console.AngeronaUpgradeConsole()
    buttons = [button.text() for button in window.findChildren(QPushButton)]

    assert "Open Settings ▸ API Keys" in buttons
    assert "Open Settings > Mobile Integration" in buttons
    assert "Save API Key" not in buttons
    assert "Save Notification Settings" not in buttons
    assert not hasattr(window, "api_key_input")
    assert not hasattr(window, "custom_provider")
    assert not hasattr(window, "hardware_pin_input")
    assert window.model_box.isEditable() is False
    assert "Install" in buttons
    assert "Open PowerShell" not in buttons
    window.close()
    app.processEvents()


def test_module_inspector_credential_tab_is_read_only_and_routes_to_settings(
    monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    _clear_provider_environment(monkeypatch)

    class ProviderModule(BaseModule):
        name = "Provider Test"
        description = "test module"
        category = "AI"

        def run(self) -> None:
            return None

    class Manager:
        def is_enabled(self, _name: str) -> bool:
            return False

        def set_enabled(self, _name: str, _enabled: bool) -> None:
            return None

    class Owner(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.opened: list[str] = []

        def _show_settings(self, initial_tab: str | None = None) -> None:
            self.opened.append(str(initial_tab))

    class Bus:
        def recent(self, _limit: int) -> list:
            return []

    owner = Owner()
    inspector = ModuleInspector(Manager(), Bus(), ProviderModule(), owner)
    buttons = [button.text() for button in inspector.findChildren(QPushButton)]
    assert "Open Settings ▸ API Keys" in buttons
    assert "Save keys" not in buttons
    next(
        button for button in inspector.findChildren(QPushButton)
        if button.text() == "Open Settings ▸ API Keys"
    ).click()
    assert owner.opened == ["API Keys"]
    inspector.deleteLater()
    owner.deleteLater()
    app.processEvents()


def test_all_gemini_consumers_accept_the_canonical_pool(monkeypatch) -> None:
    _clear_provider_environment(monkeypatch)
    from angerona.core import secure_store

    monkeypatch.setattr(
        secure_store,
        "read_secret_map",
        lambda _root=None: {"GEMINI_API_KEYS": "primary-key,rotation-key"},
    )
    module = CloudEscalationModule()
    assert module._keys == ["primary-key", "rotation-key"]

    posted: list[tuple[str, dict[str, str], dict]] = []
    monkeypatch.setattr(
        ai_consult,
        "_post",
        lambda url, headers, payload: posted.append((url, headers, payload)) or {
            "candidates": [{"content": {"parts": [{"text": "answer"}]}}]
        },
    )
    assert ai_consult._gemini("question", "system") == "answer"
    assert "primary-key" not in posted[0][0]
    assert "rotation-key" not in posted[0][0]
    assert posted[0][1]["x-goog-api-key"] == "primary-key"


def test_groq_is_a_real_explicit_consult_provider(monkeypatch) -> None:
    _clear_provider_environment(monkeypatch)
    from angerona.core import secure_store

    monkeypatch.setattr(
        secure_store,
        "read_secret_map",
        lambda _root=None: {"GROQ_API_KEY": "groq-key"},
    )
    posted: list[tuple[str, dict[str, str], dict]] = []
    monkeypatch.setattr(
        ai_consult,
        "_post",
        lambda url, headers, payload: posted.append((url, headers, payload)) or {
            "choices": [{"message": {"content": "groq answer"}}]
        },
    )

    assert ai_consult._groq("question", "system") == "groq answer"
    assert posted[0][0] == "https://api.groq.com/openai/v1/chat/completions"
    assert posted[0][1]["Authorization"] == "Bearer groq-key"


def test_cloud_fallback_passes_canonical_gemini_key_explicitly(monkeypatch) -> None:
    from angerona.engines import cloud_fallback

    _clear_provider_environment(monkeypatch)
    from angerona.core import secure_store

    monkeypatch.setattr(
        secure_store,
        "read_secret_map",
        lambda _root=None: {"GEMINI_API_KEYS": "cloud-key,rotation-key"},
    )
    received: list[str] = []

    class Models:
        def generate_content(self, **_kwargs):
            return type("Response", (), {"text": '{"verdict":"SAFE"}'})()

    class Client:
        def __init__(self, *, api_key: str) -> None:
            received.append(api_key)
            self.models = Models()

    google = ModuleType("google")
    google.genai = SimpleNamespace(Client=Client)
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", google.genai)
    result = cloud_fallback.query_gemini_live("prompt", "system")

    assert received == ["cloud-key"]
    assert result["data"]["verdict"] == "SAFE"


def test_self_compiler_reads_canonical_key_at_call_time(monkeypatch) -> None:
    _clear_provider_environment(monkeypatch)
    from angerona.core import secure_store

    monkeypatch.setattr(
        secure_store,
        "read_secret_map",
        lambda _root=None: {"GEMINI_API_KEYS": "compiler-key"},
    )
    monkeypatch.setattr(self_compiler, "_CLOUD_SYNTHESIS_ENABLED", True)
    requests = []

    class Response:
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def read(self, _size: int = -1) -> bytes:
            return (
                b'{"candidates":[{"content":{"parts":[{"text":"print(1)"}]}}]}'
            )

    def open_request(request, **_kwargs):
        requests.append(request)
        return Response()

    monkeypatch.setattr(self_compiler, "safe_urlopen", open_request)
    result = self_compiler.query_gemini_engineer("write safe code")

    assert result == "print(1)"
    assert requests[0].get_header("X-goog-api-key") == "compiler-key"
