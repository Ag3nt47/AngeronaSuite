"""Ordered inference gates and cached stages, using inert services/transports."""
from __future__ import annotations

import io
import json
import socket
from dataclasses import replace
from types import SimpleNamespace

import pytest

from angerona.core import ollama_lifecycle, url_policy
from angerona.core.ollama_lifecycle import OllamaAttestationError
from angerona.modules import ai_triage


class Response(io.BytesIO):
    headers = {}


@pytest.fixture
def subject(monkeypatch):
    for name in ("ANGERONA_MODEL", "OLLAMA_MODEL", "ANGERONA_CHILL_ACTIVE", "ANGERONA_CHILL_AI_BLOCKED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:14184")
    module = ai_triage.AITriageModule()
    module._model = "fixture:latest"
    module._lifecycle_generation = 3
    emitted = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: emitted.append((args, kwargs)))
    monkeypatch.setattr(module, "_ensure_ollama", lambda **_kwargs: pytest.fail("request started a service"))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: pytest.fail("fixture attempted DNS"))
    monkeypatch.setattr(ai_triage, "attest_ollama_service", lambda *_args: None)
    monkeypatch.setattr(ai_triage, "safe_urlopen", lambda *_args, **_kwargs: pytest.fail("unexpected transport"))
    monkeypatch.setattr(module, "_attest_model", lambda **_kwargs: pytest.fail("unexpected model-byte verification"))
    return module, emitted


def test_refused_listener_skips_model_and_transport_and_trips_one_notice(subject, monkeypatch):
    module, emitted = subject
    checks = []

    def refused(origin):
        checks.append(origin)
        raise OllamaAttestationError("local Ollama endpoint has a wildcard listener")

    monkeypatch.setattr(ai_triage, "attest_ollama_service", refused)
    assert module._ask("inert telemetry") is None
    assert module._ask("another inert event") is None
    assert checks == ["http://127.0.0.1:14184"]
    assert module._cb_state == "open" and len(emitted) == 1
    assert module.health == 30 and "listener attestation failed" in module.health_note
    assert "wildcard listener" in module.health_note and "verification pending" not in module.health_note
    view = module.request_stage_snapshot()
    assert view["stage"] == "refused" and view["outcome"] == "circuit-open"
    assert view["stage_entries"] == {"service-check": 1, "model-check": 0, "request": 0}
    assert view["attempt_count"] == 2 and view["response_authorized"] is False


def test_accepted_service_still_requires_fresh_bytes_and_final_policy_every_attempt(subject, monkeypatch):
    module, _ = subject
    module._host = "127.0.0.1:14184"
    order, payloads = [], []
    monkeypatch.setattr(ai_triage, "attest_ollama_service", lambda origin: order.append(("service", origin)))
    monkeypatch.setattr(module, "_attest_model",
                        lambda *, expected_model: order.append(("model", expected_model)) or True)

    def transport(request, *, policy, timeout):
        order.append(("transport", request.full_url))
        assert policy is url_policy.OLLAMA_SERVICE_POLICY and timeout == module._CB_TIMEOUT_S
        payloads.append(json.loads(request.data))
        return Response(b'{"message":{"content":"inert completed verdict"}}')

    monkeypatch.setattr(ai_triage, "safe_urlopen", transport)
    assert module._ask("inert telemetry") == "inert completed verdict"
    assert module._ask("second inert event") == "inert completed verdict"
    expected = [("service", "http://127.0.0.1:14184"), ("model", "fixture:latest"),
                ("transport", "http://127.0.0.1:14184/api/chat")]
    assert order == expected * 2
    assert all(payload["model"] == "fixture:latest" for payload in payloads)
    view = module.request_stage_snapshot()
    assert view["stage"] == "idle" and view["outcome"] == "completed"
    assert view["stage_entries"] == {"service-check": 2, "model-check": 2, "request": 2}
    assert [row["stage"] for row in view["completed_stage_timings"]] == list(ai_triage._REQUEST_PHASES)
    assert view["advisory_only"] is True and view["response_authorized"] is False


def test_listener_change_after_precheck_is_refused_by_real_final_policy(subject, monkeypatch):
    module, emitted = subject
    order = []
    monkeypatch.setattr(ai_triage, "attest_ollama_service", lambda origin: order.append("early"))
    monkeypatch.setattr(module, "_attest_model", lambda **_kwargs: order.append("bytes") or True)

    def changed(_origin):
        order.append("final")
        raise OllamaAttestationError("local Ollama process identity changed")

    monkeypatch.setattr(ollama_lifecycle, "attest_ollama_service", changed)
    monkeypatch.setattr(url_policy.urllib.request, "build_opener",
                        lambda *_args: pytest.fail("unattested final listener reached opener"))
    monkeypatch.setattr(ai_triage, "safe_urlopen", url_policy.safe_urlopen)
    assert module._ask("inert telemetry") is None
    assert order == ["early", "bytes", "final"] and len(emitted) == 1
    assert module.request_stage_snapshot()["outcome"] == "service-refused"


def test_fresh_verifier_is_bound_to_captured_model_even_if_mutable_field_changes(subject, monkeypatch):
    from angerona.modules import ai_model_integrity

    module, _ = subject
    captured, payloads = [], []
    real_health = module.set_health

    def health(score, note):
        real_health(score, note)
        if "byte verification pending" in note:
            module._model = "different:latest"

    def verify(model, *, stop_event):
        captured.append(model)
        assert stop_event is module.generation_stop_event()
        module._model = "fixture:latest"
        return object()

    def transport(request, **_kwargs):
        payloads.append(json.loads(request.data)["model"])
        return Response(b'{"message":{"content":"inert completed verdict"}}')

    monkeypatch.setattr(module, "set_health", health)
    monkeypatch.setattr(module, "_attest_model", ai_triage.AITriageModule._attest_model.__get__(module))
    monkeypatch.setattr(ai_model_integrity, "require_fresh_model_attestation", verify)
    monkeypatch.setattr(ai_triage, "safe_urlopen", transport)
    assert module._ask("inert telemetry") == "inert completed verdict"
    assert captured == payloads == ["fixture:latest"]


def test_changed_model_at_attestation_admission_never_calls_fresh_verifier(subject, monkeypatch):
    from angerona.modules import ai_model_integrity

    module, _ = subject
    module._model = "different:latest"
    monkeypatch.setattr(ai_model_integrity, "require_fresh_model_attestation",
                        lambda *_args, **_kwargs: pytest.fail("changed model reached byte verification"))
    assert not ai_triage.AITriageModule._attest_model(module, expected_model="fixture:latest")
    assert module._attestation_receipt is None


@pytest.mark.parametrize("point", ["attestation", "prompt"])
@pytest.mark.parametrize("change", ["configuration", "generation"])
def test_cancelled_successful_attestation_does_not_claim_current_model_health(
    subject, monkeypatch, point, change,
):
    from angerona.engines import ai_guardrail
    from angerona.modules import ai_model_integrity

    module, emitted = subject
    module._config = SimpleNamespace(ollama_host=module._host, ollama_model=module._model)
    module.last_error = "historical readiness failure"
    real_health = module.set_health
    completed = []

    def mutate():
        if change == "configuration":
            module._config.ollama_model = "different:latest"
        else:
            module._lifecycle_generation += 1

    def health(score, note):
        real_health(score, note)
        if score == 100 and note == "exact configured model attested for local inference":
            completed.append(module._attestation_receipt)
            if point == "attestation":
                mutate()

    def protect(_prompt):
        if point == "prompt":
            mutate()
        return "inert protected telemetry"

    receipt = object()
    monkeypatch.setattr(module, "set_health", health)
    monkeypatch.setattr(module, "_attest_model", ai_triage.AITriageModule._attest_model.__get__(module))
    monkeypatch.setattr(ai_model_integrity, "require_fresh_model_attestation",
                        lambda *_args, **_kwargs: receipt)
    monkeypatch.setattr(ai_guardrail, "neutralize_telemetry", protect)
    assert module._ask("inert telemetry") is None
    assert completed == [receipt] and module._attestation_receipt is None
    assert module.health <= 70 and "request cancelled" in module.health_note
    assert "verification required before inference" in module.health_note
    assert "exact configured model attested" not in module.health_note
    assert module.last_error == "historical readiness failure"
    assert not emitted and module._cb_state == "closed"


@pytest.mark.parametrize("point", ["service", "model"])
@pytest.mark.parametrize("change", ["host", "model", "generation", "stop", "chill"])
def test_changed_configuration_or_generation_cannot_use_preceding_check(subject, monkeypatch, point, change):
    module, emitted = subject
    module._config = SimpleNamespace(ollama_host=module._host, ollama_model=module._model)
    checks = []
    blocked = [False]
    monkeypatch.setattr(ai_triage, "ollama_blocked", lambda: blocked[0])

    def mutate():
        if change == "host":
            module._config.ollama_host = "http://127.0.0.1:14185"
        elif change == "model":
            module._config.ollama_model = "different:latest"
        elif change == "generation":
            module._lifecycle_generation += 1
        elif change == "stop":
            module.generation_stop_event().set()
        else:
            blocked[0] = True

    def service(_origin):
        checks.append("service")
        if point == "service":
            mutate()

    def model(*, expected_model):
        assert expected_model == "fixture:latest"
        checks.append("model")
        mutate()
        return True

    monkeypatch.setattr(ai_triage, "attest_ollama_service", service)
    monkeypatch.setattr(module, "_attest_model", model)
    assert module._ask("inert telemetry") is None
    assert checks == (["service"] if point == "service" else ["service", "model"])
    assert not emitted and module._cb_state == "closed"
    view = module.request_stage_snapshot()
    assert view["stage_entries"]["request"] == 0
    assert view["response_authorized"] is False


def test_configuration_change_during_prompt_protection_is_rechecked(subject, monkeypatch):
    from angerona.engines import ai_guardrail

    module, _ = subject
    module._config = SimpleNamespace(ollama_host=module._host, ollama_model=module._model)
    monkeypatch.setattr(module, "_attest_model", lambda **_kwargs: True)

    def protect(_prompt):
        module._config.ollama_model = "different:latest"
        return "inert protected telemetry"

    monkeypatch.setattr(ai_guardrail, "neutralize_telemetry", protect)
    assert module._ask("inert telemetry") is None
    assert module.request_stage_snapshot()["outcome"] == "configuration-changed"


@pytest.mark.parametrize("change", ["stop", "chill", "paused", "circuit"])
def test_initial_refusal_performs_no_service_or_byte_check(subject, monkeypatch, change):
    module, _ = subject
    monkeypatch.setattr(ai_triage, "attest_ollama_service", lambda *_args: pytest.fail("initial refusal probed service"))
    if change == "stop":
        module.generation_stop_event().set()
    elif change == "chill":
        monkeypatch.setattr(ai_triage, "ollama_blocked", lambda: True)
    elif change == "paused":
        module._chill_paused = True
    else:
        module._cb_state = "open"
    assert module._ask("inert telemetry") is None
    assert module.request_stage_snapshot()["stage_entries"] == dict.fromkeys(ai_triage._REQUEST_PHASES, 0)


@pytest.mark.parametrize("host", ["http://192.0.2.1:14184", "http://0.0.0.0:14184",
                                  "http://127.0.0.1:14184/extra", "http://user:secret@127.0.0.1:14184",
                                  "file:///inert", "http://127.0.0.1:999999"])
def test_invalid_origin_never_attests_bytes_or_calls_service(subject, monkeypatch, host):
    module, _ = subject
    module._host = host
    monkeypatch.setattr(ai_triage, "attest_ollama_service", lambda *_args: pytest.fail("invalid origin reached service"))
    assert module._ask("inert telemetry") is None
    view = module.request_stage_snapshot()
    assert view["outcome"] == "configuration-refused"
    assert view["stage_entries"]["model-check"] == view["stage_entries"]["request"] == 0
    assert "secret" not in json.dumps(view)


def test_refused_model_and_failed_prompt_protection_never_reach_transport(subject, monkeypatch):
    from angerona.engines import ai_guardrail

    module, _ = subject
    monkeypatch.setattr(module, "_attest_model", lambda **_kwargs: False)
    assert module._ask("inert telemetry") is None
    assert module.request_stage_snapshot()["outcome"] == "model-refused"
    monkeypatch.setattr(module, "_attest_model", lambda **_kwargs: True)
    monkeypatch.setattr(ai_guardrail, "neutralize_telemetry",
                        lambda *_args: (_ for _ in ()).throw(ValueError("PRIVATE")))
    assert module._ask("inert telemetry") is None
    assert module.request_stage_snapshot()["outcome"] == "prompt-refused"


def test_cached_stage_snapshot_performs_no_clock_model_service_or_transport_work(subject, monkeypatch):
    module, _ = subject
    before = module._request_observation
    monkeypatch.setattr(ai_triage, "_request_clock", lambda *_args: pytest.fail("snapshot sampled a clock"))
    monkeypatch.setattr(ai_triage, "attest_ollama_service", lambda *_args: pytest.fail("snapshot probed service"))
    monkeypatch.setattr(module, "_sync_config", lambda: pytest.fail("snapshot consulted config"))
    view = module.request_stage_snapshot()
    assert view["state"] == "unmeasured" and module._request_observation is before
    assert "host" not in view and "model" not in view and "last_error" not in view


@pytest.mark.parametrize("change", [
    {"generation": True}, {"attempt": -1}, {"stage": "x" * 4096}, {"outcome": "x" * 4096},
    {"updated": float("nan")}, {"entries": (True, 0, 0)},
    {"timings": (("request", -1.0, None),)}, {"timings": tuple(("request", 0.0, 0.0) for _ in range(4))},
], ids=["bool-generation", "negative-attempt", "stage-bound", "outcome-bound", "clock-nan",
        "bool-count", "negative-time", "timing-bound"])
def test_malformed_cached_observation_is_wholly_unavailable(subject, change):
    module, _ = subject
    module._request_observation = replace(module._request_observation, **change)
    view = module.request_stage_snapshot()
    assert view["state"] == "unavailable" and view["reason_code"] == "invalid_observation"
    assert view["response_authorized"] is False
    json.dumps(view, allow_nan=False)


def test_malformed_exact_class_and_later_generation_never_claim_current_stage(subject):
    module, _ = subject
    module._request_observation = object.__new__(ai_triage._RequestStage)
    assert module.request_stage_snapshot()["state"] == "unavailable"
    module._request_observation = ai_triage._RequestStage(module._lifecycle_generation - 1, 1,
                                                         stage="model-check", outcome="in-progress")
    view = module.request_stage_snapshot()
    assert view["state"] == "unmeasured" and view["reason_code"] == "generation_changed"
    assert view["stage"] == "idle" and view["response_authorized"] is False
