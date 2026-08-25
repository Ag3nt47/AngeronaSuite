from __future__ import annotations

from pathlib import Path

import psutil
import pytest

from angerona.core import ollama_lifecycle, url_policy
from angerona.engines import ollama_client


class _Process:
    def __init__(self, pid: int, image: Path) -> None:
        self.pid = pid
        self._image = image

    def create_time(self) -> float:
        return 1234.5

    def exe(self) -> str:
        return str(self._image)

    def is_running(self) -> bool:
        return True


def test_attestation_binds_one_listener_to_trusted_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "ollama.exe"
    image.write_bytes(b"signed-fixture")
    monkeypatch.setattr(ollama_lifecycle, "_ollama_listener_pids", lambda _port: {42})
    monkeypatch.setattr(ollama_lifecycle, "_trusted_ollama_image", lambda path: path == image)
    monkeypatch.setattr(psutil, "Process", lambda pid: _Process(pid, image))

    proof = ollama_lifecycle.attest_ollama_service("http://127.0.0.1:11434")

    assert proof.pid == 42
    assert proof.executable == str(image.resolve())
    assert proof.create_time == 1234.5
    assert proof.port == 11434


@pytest.mark.parametrize("listeners", (set(), {10, 11}))
def test_attestation_refuses_missing_or_ambiguous_owner(monkeypatch, listeners) -> None:
    monkeypatch.setattr(
        ollama_lifecycle, "_ollama_listener_pids", lambda _port: listeners
    )

    with pytest.raises(
        ollama_lifecycle.OllamaAttestationError, match="unavailable or ambiguous"
    ):
        ollama_lifecycle.attest_ollama_service("http://127.0.0.1:11434")


def test_inference_does_not_contact_unattested_listener(monkeypatch) -> None:
    contacted = []
    monkeypatch.setattr(
        ollama_lifecycle,
        "attest_ollama_service",
        lambda _host: (_ for _ in ()).throw(
            ollama_lifecycle.OllamaAttestationError("untrusted listener")
        ),
    )
    monkeypatch.setattr(
        url_policy.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: contacted.append(True),
    )
    monkeypatch.setattr(ollama_client.g, "audit", lambda *_args, **_kwargs: None)

    result = ollama_client.call(
        {"model": "llama3", "prompt": "summarize evidence", "stream": False},
        host="http://127.0.0.1:11434",
    )

    assert result["error"] == "local model unavailable"
    assert result["error_type"] == "OllamaAttestationError"
    assert contacted == []
