from __future__ import annotations

import json

from angerona.core.analysis_worker import (
    CLOUD_MAX_PROMPT_CHARS,
    AnalysisWorker,
    _build_prompt,
)


def _low_confidence_local(_prompt: str) -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence_score": 10,
        "reasoning": "Needs a second opinion.",
        "recommended_actions": [],
    }


def test_cloud_disabled_by_default_blocks_provider_and_network(monkeypatch):
    calls = []

    def forbidden_provider(_prompt: str, _system: str) -> dict:
        calls.append("provider")
        raise AssertionError("cloud provider must not be called while disabled")

    worker = AnalysisWorker(
        {"details": "raw endpoint telemetry"},
        cloud_query=forbidden_provider,
    )
    monkeypatch.setattr(worker, "_query_ollama", _low_confidence_local)
    monkeypatch.setattr(
        "angerona.core.analysis_worker.urllib.request.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("network must not be called by this test")
        ),
    )
    results = []
    worker.finished.connect(results.append)

    # The egress boundary itself is authoritative, even for a direct caller.
    assert worker._escalate_cloud() is None
    worker.run()

    assert calls == []
    assert results and results[0]["stage"] == "local"
    assert results[0]["cloud"] is None


def test_enabled_cloud_receives_only_recursive_redacted_bounded_prompt(monkeypatch):
    windows_path = r"C:\Users\Alice\Private Cases\incident.exe"
    unc_path = r"\\fileserver\private\case.txt"
    posix_path = "/home/alice/private/case.txt"
    token = "sk_test_0123456789abcdefghijklmnopqrstuvwxyz"
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJwcml2YXRlLXVzZXIifQ."
        "0123456789abcdefghijklmnop"
    )
    ipv4 = "203.0.113.44"
    ipv6 = "2001:db8::42"
    mac = "00:11:22:33:44:55"
    email = "alice@example.com"
    url = "https://internal.example.local/case?q=secret"
    alert = {
        "pid": 42,
        "process_name": windows_path,
        "type": "EDR",
        "ancestry": [{
            "image_path": windows_path,
            "child": {"environment": {"SESSION_TOKEN": token}},
        }],
        "connections": [{
            "remote_address": ipv4,
            "nested": {"peer": f"{ipv6}:443", "adapter": mac},
        }],
        "memory_strings": [
            f"Authorization: Bearer {token}",
            f"jwt={jwt} contact={email} url={url}",
            f"opened {unc_path} and {posix_path}",
        ] + ["x" * 5_000 for _ in range(80)],
        "details": {
            "password": "correct-horse-battery-staple",
            "nested": {"message": f"{windows_path} connected to {ipv4}"},
        },
    }
    captured = []

    def provider(prompt: str, system: str) -> dict:
        captured.append((prompt, system))
        return {
            "engine": "TEST-CLOUD",
            "data": {
                "verdict": "SUSPICIOUS",
                "confidence": 0.8,
                "justification": "Sanitized evidence reviewed.",
            },
        }

    worker = AnalysisWorker(alert, allow_cloud=True, cloud_query=provider)
    monkeypatch.setattr(worker, "_query_ollama", _low_confidence_local)
    results = []
    worker.finished.connect(results.append)
    worker.run()

    assert len(captured) == 1
    prompt, system_prompt = captured[0]
    assert system_prompt
    assert len(prompt) <= CLOUD_MAX_PROMPT_CHARS
    json.loads(prompt.split("\n", 1)[1])
    assert "[REDACTED]" in prompt or "<redacted:" in prompt
    outbound_text = prompt + system_prompt

    # Local analysis retains full endpoint evidence; only the egress copy changes.
    local_prompt = _build_prompt(alert)
    local_evidence = json.loads(local_prompt.split("\n", 1)[1])
    assert local_evidence["process_name"] == windows_path
    assert token in local_prompt

    for private in (
        windows_path,
        unc_path,
        posix_path,
        token,
        jwt,
        ipv4,
        ipv6,
        mac,
        email,
        url,
        "correct-horse-battery-staple",
    ):
        assert private not in outbound_text
    for private_fragment in ("Alice", "fileserver", "incident.exe",
                             "internal.example.local"):
        assert private_fragment.casefold() not in outbound_text.casefold()

    assert results and results[0]["stage"] == "cloud"
    assert results[0]["final_verdict"] == "SUSPICIOUS"
    assert results[0]["final_confidence"] == 80
