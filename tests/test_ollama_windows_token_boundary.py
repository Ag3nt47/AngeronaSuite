"""Independent rejection checks; every native launch/environment API is replaced."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from angerona.core import ollama_windows_token as token_launch


@pytest.mark.parametrize(
    "environment",
    [
        {"": "value"},
        {"KEY=INJECTED": "value"},
        {"KEY\0SECOND": "value"},
        {"KEY": "value\0SECOND=unexpected"},
        {"KEY": 42},
        {42: "value"},
        {"KEY": "x" * 32768},
    ],
)
def test_invalid_environment_never_reaches_native_creation(tmp_path, monkeypatch, environment):
    monkeypatch.setattr(
        token_launch.ctypes, "WinDLL",
        lambda *_a, **_k: pytest.fail("invalid environment reached native API"),
        raising=False,
    )
    native = token_launch._Native.__new__(token_launch._Native)

    with pytest.raises(ValueError, match="linked medium user token"):
        native.create_suspended(20, tmp_path / "ollama.exe", environment)


def test_oversized_command_never_reaches_native_creation(tmp_path, monkeypatch):
    monkeypatch.setattr(
        token_launch.ctypes, "WinDLL",
        lambda *_a, **_k: pytest.fail("oversized command reached native API"),
        raising=False,
    )
    native = token_launch._Native.__new__(token_launch._Native)
    image = tmp_path / ("x" * 1024) / "ollama.exe"

    with pytest.raises(ValueError, match="linked medium user token"):
        native.create_suspended(20, image, {"OLLAMA_NO_CLOUD": "1"})


def test_native_creation_failure_is_not_returned_as_a_process(tmp_path, monkeypatch):
    calls = []

    class RefusedCreate:
        def __call__(self, *args):
            calls.append(args[0])
            return 0

    library = SimpleNamespace(CreateProcessWithTokenW=RefusedCreate())
    monkeypatch.setattr(
        token_launch.ctypes, "WinDLL", lambda *_a, **_k: library, raising=False,
    )
    native = token_launch._Native.__new__(token_launch._Native)

    with pytest.raises(OSError, match="Linked-token Ollama launch failed"):
        native.create_suspended(20, tmp_path / "ollama.exe", {"OLLAMA_NO_CLOUD": "1"})

    assert calls == [20]


def test_profile_environment_only_returns_model_storage(monkeypatch):
    seen = []

    def environment(token, inherit):
        seen.append((token, inherit))
        return {
            "ollama_models": "C:\\Models",
            "OPENAI_API_KEY": "inert-test-secret",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "PATH": "C:\\untrusted-bin",
            "OLLAMA_HOST": "0.0.0.0:11434",
        }

    monkeypatch.setitem(sys.modules, "win32profile", SimpleNamespace(CreateEnvironmentBlock=environment))
    native = token_launch._Native.__new__(token_launch._Native)

    assert native.model_directory(20) == "C:\\Models"
    assert seen == [(20, False)]


def test_ambiguous_profile_model_storage_is_rejected(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "win32profile",
        SimpleNamespace(CreateEnvironmentBlock=lambda *_a: {
            "OLLAMA_MODELS": "C:\\Models",
            "ollama_models": "D:\\OtherModels",
        }),
    )
    native = token_launch._Native.__new__(token_launch._Native)

    with pytest.raises(ValueError, match="linked medium user token"):
        native.model_directory(20)
