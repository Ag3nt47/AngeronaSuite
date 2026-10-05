"""Inert incident-priority and malformed-provider regressions; no host actions."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from angerona.core.module_base import Severity
from angerona.modules import cloud_escalation, dynamic_resource


def _event(severity, *, module="Detector", details=None):
    return SimpleNamespace(severity=severity, module=module, ts=float("inf"),
                           message="Security observation", details=details or {})


def test_governor_ignores_routine_health_and_passive_events_and_bounds_history(monkeypatch):
    governor = dynamic_resource.DynamicResourceModule()
    governor._bus = object()
    batch = ([_event(Severity.INFO)] * 1000
             + [_event(Severity.CRITICAL, module="CHAOS")] * 20
             + [_event(Severity.HIGH, details={"disposition": "exposure"})] * 20)
    monkeypatch.setattr(governor, "poll_bus_events", lambda: (batch, False))
    governor._drain_bus(50.0)
    assert governor._current_rate(50.0) == 0
    batch[:] = [_event(Severity.HIGH, details={"active_attack": True})] * 5000
    governor._drain_bus(50.0)
    assert len(governor._event_times) == 4096
    assert set(governor._event_times) == {50.0}  # hostile/future source timestamps ignored
    batch.clear()
    governor._drain_bus(61.0)
    assert not governor._event_times


def test_governor_stop_during_escalation_restores_exact_original_priority(monkeypatch):
    governor = dynamic_resource.DynamicResourceModule()
    changes = []
    original, high = 0x4000, 0x80

    def nice(value=None):
        if value is None:
            return original
        changes.append(value)
        if value == high:
            governor.stop()  # deterministic stop at the old restore-before-stop race

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        Process=lambda _pid: SimpleNamespace(nice=nice), HIGH_PRIORITY_CLASS=high,
        NORMAL_PRIORITY_CLASS=0x20,
    ))
    governor._bus = object()
    events = [_event(Severity.HIGH, details={"active_attack": True})] * 20
    monkeypatch.setattr(governor, "poll_bus_events", lambda: (events, False))
    monkeypatch.setattr(governor, "sleep", lambda *_args: None)
    monkeypatch.setattr(governor, "emit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(governor, "set_health", lambda *_args: None)
    governor.run()
    assert changes == [high, original]
    assert not governor._elevated
    governor._escalate()
    assert changes == [high, original]  # retired generations cannot raise priority


def test_governor_restores_original_priority_on_worker_exception(monkeypatch):
    governor = dynamic_resource.DynamicResourceModule()
    changes = []
    original = 0x8000
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        Process=lambda _pid: SimpleNamespace(nice=lambda value=None: original if value is None else changes.append(value)),
        HIGH_PRIORITY_CLASS=0x80,
    ))
    monkeypatch.setattr(governor, "sleep", lambda *_args: None)
    monkeypatch.setattr(governor, "emit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(governor, "set_health", lambda *_args: None)

    def failing_tick():
        governor._escalate()
        raise RuntimeError("inert worker fault")

    monkeypatch.setattr(governor, "_tick", failing_tick)
    with pytest.raises(RuntimeError, match="inert worker fault"):
        governor.run()
    assert changes == [0x80, original]


@pytest.mark.parametrize("payload", [
    "[1]", '"SAFE"', "true", "17", "null", "{}",
    '{"verdict":"SAFE","confidence":true,"justification":"test"}',
    '{"verdict":"SAFE","confidence":NaN,"justification":"test"}',
    '{"verdict":"SAFE","confidence":1e999,"justification":"test"}',
    '{"verdict":"SAFE","confidence":' + "9" * 400 + ',"justification":"test"}',
    '{"verdict":"SAFE","confidence":2,"justification":"test"}',
    '{"verdict":"SAFE","confidence":0.9,"justification":[]}',
    '{"verdict":"UNKNOWN","confidence":0.9,"justification":"test"}',
    json.dumps({"verdict": "SAFE", "confidence": 0.9, "justification": "x" * 4001}),
    "x" * (64 * 1024 + 1),
], ids=[f"invalid-{index}" for index in range(15)])
def test_cloud_rejects_non_object_or_invalid_verdict_without_trusted_positive(payload):
    assert cloud_escalation._extract_json(payload) is None


def test_cloud_valid_bounded_verdict_normalizes_and_strips_uncontracted_fields():
    result = cloud_escalation._extract_json(
        'prefix {"verdict":" suspicious ","confidence":0.75,'
        '"justification":" bounded evidence ","action":"ignored"} suffix'
    )
    assert result == {"verdict": "SUSPICIOUS", "confidence": 0.75,
                      "justification": "bounded evidence"}


def test_cloud_worker_survives_malformed_reply_and_handles_next_event(monkeypatch):
    monkeypatch.setattr(cloud_escalation, "credential_values", lambda _provider: ["inert-key"])
    responses = iter(["[1]", '{"verdict":"MALICIOUS","confidence":0.9,"justification":"fixture"}'])
    fake_genai = SimpleNamespace(Client=lambda **_kwargs: SimpleNamespace(
        models=SimpleNamespace(generate_content=lambda **_kwargs: SimpleNamespace(text=next(responses)))))
    monkeypatch.setitem(sys.modules, "google", SimpleNamespace(genai=fake_genai))
    module = cloud_escalation.CloudEscalationModule()
    module._bus = object()
    events = [_event(Severity.CRITICAL, details={"active_attack": True}) for _ in range(2)]
    monkeypatch.setattr(module, "poll_bus_events", lambda **_kwargs: (events, False))
    notices = []

    def emit(message, severity, **details):
        notices.append((message, severity, details))
        if message.startswith("Cloud verdict:"):
            module.stop()

    monkeypatch.setattr(module, "emit", emit)
    sleeps = []

    def sleep(_seconds):
        sleeps.append(True)
        assert len(sleeps) <= 2, "fixture failed to stop after the second response"

    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert any("FAILED" in text and details.get("fail_closed") for text, _, details in notices)
    assert any("Cloud verdict: MALICIOUS" in text for text, _, _ in notices)
