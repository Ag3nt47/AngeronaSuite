"""Inert provider-denial diagnostics; no listener, package, model or process actions."""
from __future__ import annotations

import threading

import pytest

from angerona.core import ollama_lifecycle as lifecycle
from angerona.modules import ai_triage as triage


class NoTextOrHash:
    def __str__(self):
        raise AssertionError("Diagnostic formatting must not stringify arbitrary input")

    def __hash__(self):
        raise AssertionError("Diagnostic formatting must not hash arbitrary input")


def refuse_provider(monkeypatch, error):
    calls = []

    def denied(request, *, policy, timeout):
        assert request.full_url == "http://127.0.0.1:11434/api/tags"
        assert request.get_method() == "GET"
        assert policy is triage.OLLAMA_SERVICE_POLICY
        assert timeout == 3.0
        calls.append(request)
        # Model inventory is never returned when local admission refuses it.
        raise error

    monkeypatch.setattr(triage, "safe_urlopen", denied)
    return calls


@pytest.mark.parametrize("code,fragment", [
    ("image", "no recognized trusted Ollama installation"),
    ("package", "protected installation and DLL-tree custody"),
    ("signing", "machine-trusted code-signing evidence"),
    ("pending", "pending on a worker"),
])
def test_guarded_model_probe_remains_unready_and_explains_provider_hold(monkeypatch, code, fragment):
    calls = refuse_provider(monkeypatch, lifecycle.OllamaProviderUnavailable(code))
    record, detail = triage.AITriageModule._probe_model("http://127.0.0.1:11434", "selftest:stable")
    assert record is None
    assert len(calls) == 1
    assert detail == lifecycle.provider_hold_detail(code)
    assert fragment in detail
    assert not detail.startswith("SKIP")


@pytest.mark.parametrize("code", [
    "DO_NOT_REFLECT_USER_DATA <script>replace-baseline()</script>",
    None,
    ["package"],
    {"package": True},
    NoTextOrHash(),
], ids=["unknown-text", "none", "unhashable-list", "unhashable-map", "unsafe-dunder"])
def test_unknown_hold_codes_use_fixed_fallback_without_interpreting_input(code):
    detail = lifecycle.provider_hold_detail(code)
    assert detail == lifecycle.provider_hold_detail("unknown")
    assert "provider verification is held" in detail
    assert "dashboard can remain open" in detail
    assert "DO_NOT_REFLECT_USER_DATA" not in detail
    assert "replace-baseline" not in detail


def test_provider_exception_text_is_not_reflected_or_stringified(monkeypatch):
    error = lifecycle.OllamaProviderUnavailable("package")
    error.args = (NoTextOrHash(),)
    calls = refuse_provider(monkeypatch, error)
    record, detail = triage.AITriageModule._probe_model("http://127.0.0.1:11434", "selftest:stable")
    assert record is None and len(calls) == 1
    assert detail == lifecycle.provider_hold_detail("package")
    assert "settings and models were preserved" in detail


def test_mutated_unknown_exception_code_uses_fixed_fallback(monkeypatch):
    error = lifecycle.OllamaProviderUnavailable("package")
    error.code = NoTextOrHash()
    calls = refuse_provider(monkeypatch, error)
    record, detail = triage.AITriageModule._probe_model("http://127.0.0.1:11434", "selftest:stable")
    assert record is None and len(calls) == 1
    assert detail == lifecycle.provider_hold_detail(None)


def test_ordinary_attestation_failure_remains_a_bounded_failure(monkeypatch):
    message = "listener generation changed " + "x" * 600
    calls = refuse_provider(monkeypatch, lifecycle.OllamaAttestationError(message))
    record, detail = triage.AITriageModule._probe_model("http://127.0.0.1:11434", "selftest:stable")
    assert record is None and len(calls) == 1
    assert detail == "Ollama listener attestation failed: " + message[:500]


def test_module_selftest_retains_false_for_unverified_package(monkeypatch):
    refuse_provider(monkeypatch, lifecycle.OllamaProviderUnavailable("package"))
    monkeypatch.setattr(triage, "ollama_blocked", lambda: False)

    class InertOwner:
        lifecycle_generation = 1
        _chill_paused = False
        _model_is_installed = staticmethod(triage.AITriageModule._model_is_installed)
        _probe_model = staticmethod(triage.AITriageModule._probe_model)

        def __init__(self):
            self.stop = threading.Event()

        def _configured_endpoint(self):
            return "http://127.0.0.1:11434", "selftest:stable"

        def generation_stop_event(self):
            return self.stop

    passed, detail = triage.AITriageModule.self_test(InertOwner())
    assert passed is False
    assert detail == lifecycle.provider_hold_detail("package")
    assert not detail.startswith("SKIP")
