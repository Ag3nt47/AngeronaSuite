from __future__ import annotations

from types import SimpleNamespace

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.ai_triage import AITriageModule
from angerona.modules.speculative_triage import SpeculativeTriageModule


def _bound_pair() -> tuple[SpeculativeTriageModule, AITriageModule, EventBus]:
    bus = EventBus()
    speculative = SpeculativeTriageModule()
    triage = AITriageModule()
    speculative.bind(bus)
    triage.bind(bus)
    triage.status = "running"
    assert speculative.bind_consumer(triage)
    return speculative, triage, bus


def test_only_exact_production_consumer_can_claim_a_frame(monkeypatch) -> None:
    speculative, triage, _bus = _bound_pair()
    monkeypatch.setattr(
        "angerona.modules.speculative_triage.time.time", lambda: 100.0
    )
    speculative._primed[41] = {
        "prompt": "ready",
        "ts": 99.0,
        "warmed": True,
        "process_birth": 12.25,
    }

    assert speculative.get_primed(41, consumer=object(), process_birth=12.25) is None
    assert 41 in speculative._primed
    assert speculative.get_primed(41, consumer=triage, process_birth=12.25)
    assert 41 not in speculative._primed
    assert speculative.hits == 1


def test_failed_stale_and_pid_reused_frames_are_never_reused(monkeypatch) -> None:
    speculative, triage, _bus = _bound_pair()
    monkeypatch.setattr(
        "angerona.modules.speculative_triage.time.time", lambda: 100.0
    )
    frames = {
        1: {"prompt": "failed", "ts": 99.0, "warmed": False, "process_birth": 1},
        2: {"prompt": "stale", "ts": 1.0, "warmed": True, "process_birth": 2},
        3: {"prompt": "reused-pid", "ts": 99.0, "warmed": True, "process_birth": 3},
    }
    speculative._primed.update(frames)

    assert speculative.get_primed(1, consumer=triage, process_birth=1) is None
    assert speculative.get_primed(2, consumer=triage, process_birth=2) is None
    assert speculative.get_primed(3, consumer=triage, process_birth=4) is None
    assert speculative.hits == 0
    assert speculative._primed == {}


def test_health_cannot_be_green_without_consumer_or_success() -> None:
    speculative, triage, _bus = _bound_pair()
    speculative._subscription_ready = True

    triage.status = "stopped"
    speculative._update_health()
    assert speculative.health == 60
    assert "consumer" in speculative.health_note

    triage.status = "running"
    speculative._update_health()
    assert speculative.health == 85
    assert "awaiting" in speculative.health_note

    speculative._last_warm_succeeded = False
    speculative.last_error = "model unavailable"
    speculative._update_health()
    assert speculative.health == 40
    assert "model unavailable" in speculative.health_note


def test_ai_triage_consumes_exact_frame_through_manager_binding(monkeypatch) -> None:
    speculative, triage, _bus = _bound_pair()
    manager = SimpleNamespace(
        config=None,
        modules={"Speculative Triage Pre-Warm": speculative},
    )
    triage.bind_manager(manager)
    monkeypatch.setattr(
        "angerona.modules.speculative_triage.time.time", lambda: 100.0
    )
    speculative._primed[77] = {
        "prompt": "ready",
        "ts": 99.0,
        "warmed": True,
        "process_birth": "7.5",
    }
    event = Event(
        module="Process Monitor",
        message="unknown process",
        severity=Severity.HIGH,
        details={"pid": 77, "process_birth": 7.5},
    )

    assert triage._consume_speculative_frame(event)
    assert speculative.hits == 1
    assert not triage._consume_speculative_frame(event)


def test_lookalike_consumer_cannot_satisfy_binding() -> None:
    speculative = SpeculativeTriageModule()
    bus = EventBus()
    speculative.bind(bus)
    lookalike = SimpleNamespace(
        name="AI Triage (Ollama)",
        _bus=bus,
        status="running",
    )

    assert not speculative.bind_consumer(lookalike)
    speculative._subscription_ready = True
    speculative._update_health()
    assert speculative.health == 60
