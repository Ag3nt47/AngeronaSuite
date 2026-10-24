"""Retained serious evidence must survive chatty presentation telemetry."""
from __future__ import annotations

from types import SimpleNamespace
import time

import pytest

from angerona.core import alert_ack, drill_resolution, process_allowlist, threat
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity


@pytest.fixture
def policy(monkeypatch):
    now = time.time()
    state = {"now": now, "acks": set(), "allowed": False, "resolved": False}
    monkeypatch.setattr(threat, "time", SimpleNamespace(time=lambda: state["now"]))
    monkeypatch.setattr(alert_ack, "acked_signatures", lambda: state["acks"])
    monkeypatch.setattr(process_allowlist, "policy_snapshot", lambda: ())
    monkeypatch.setattr(process_allowlist, "is_event_allowed", lambda *_, **__: state["allowed"])
    monkeypatch.setattr(drill_resolution, "resolution_snapshot", lambda: {})
    monkeypatch.setattr(drill_resolution, "is_resolved_event", lambda *_, **__: state["resolved"])
    return state


def _signed_bus():
    bus = EventBus()
    bus.arm(BusAuthority(b"v" * 32))
    return bus


def _flood(bus, now, count=600):
    for index in range(count):
        bus.publish(Event("Telemetry", f"inert noise {index}", Severity.INFO, now))


def _critical(bus, now, *, module="SpywareGuard", **details):
    bus.publish(Event(module, "Inert policy-driven containment request", Severity.CRITICAL,
                      now, {"active_attack": True, **details}))
    return bus.recent(1)[0]


def test_signed_priority_survives_info_flood_without_rewriting_response(policy):
    bus = _signed_bus()
    response = {"version": 1, "actions": ["isolate_host"], "targets": {"host": "local"}}
    event = _critical(bus, policy["now"], response_authorized=True, response_contract=response)
    signature = event.hmac_sig
    _flood(bus, policy["now"])

    assert event not in bus.recent(200)
    candidates = threat.recent_threat_candidates(bus)
    assert len(candidates) == 201  # presentation tail plus the retained serious event
    assert threat.active_threat_events(candidates) == [event]
    assert candidates[-1] is event
    assert event.hmac_sig == signature and bus.verify(event)
    assert event.details["response_authorized"] is True
    assert event.details["response_contract"] == response


def test_merge_uses_publication_revisions_not_hmac_or_payload_dedup(policy):
    bus = _signed_bus()
    unsigned = Event("Detector", "same signed fields", Severity.CRITICAL, policy["now"])
    bus.publish(unsigned)
    first = bus.recent(1)[0]
    bus.publish(unsigned)
    second = bus.recent(1)[0]
    assert first.hmac_sig == second.hmac_sig
    bus.publish(Event("Telemetry", "newest", Severity.INFO, policy["now"]))

    candidates = threat.recent_threat_candidates(bus, 2)
    assert [event.message for event in candidates] == ["newest", "same signed fields", "same signed fields"]
    assert candidates[1] is second and candidates[2] is first
    assert all(bus.verify(event) for event in candidates)


def test_priority_overflow_remains_bounded_and_cannot_recover_evicted_evidence(policy):
    bus = EventBus(ring_size=2, priority_ring_size=2)
    bus.arm(BusAuthority(b"b" * 32))
    events = [_critical(bus, policy["now"] + index) for index in range(3)]
    _flood(bus, policy["now"], count=10)

    candidates = threat.recent_threat_candidates(bus, 1)
    assert len(candidates) == 3
    assert candidates[1] is events[2] and candidates[2] is events[1]
    assert all(event is not events[0] for event in candidates)
    _cursor, retained, overflow = bus.priority_since(0)
    assert overflow is True and retained == events[:0:-1]


@pytest.mark.parametrize("case", ["active", "expired", "ack", "allowed", "resolved", "drill", "observation"])
def test_status_counts_retained_critical_and_preserves_existing_exclusions(tmp_path, policy, case):
    from angerona.core.status_report import StatusReporter

    bus = _signed_bus()
    when = policy["now"] - 601 if case == "expired" else policy["now"]
    module = "Telemetry Canary Drills" if case == "drill" else "SpywareGuard"
    details = {"active_attack": False, "disposition": "observation"} if case == "observation" else {}
    event = _critical(bus, when, module=module, **details)
    if case == "ack":
        policy["acks"].add(alert_ack.signature(event))
    policy["allowed"] = case == "allowed"
    policy["resolved"] = case == "resolved"
    _flood(bus, policy["now"])
    reporter = StatusReporter(
        bus, SimpleNamespace(count_since=lambda _: 601),
        SimpleNamespace(modules={}, is_enabled=lambda _: False),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=False,
                        ollama_host="local", ollama_model="test"),
    )

    snapshot = reporter._snapshot()
    expected = 1 if case == "active" else 0
    assert snapshot["counts"]["active_critical_10m"] == expected
    assert snapshot["counts"]["critical_24h"] == expected
    assert snapshot["threat_level"] == ("CRITICAL" if expected else "SECURE")
    assert snapshot["counts"]["alerts_24h"] == 601
    assert len(snapshot["recent_events"]) == 60
    assert all(row["module"] == "Telemetry" for row in snapshot["recent_events"])
    assert bus.verify(event)


def test_posture_fallbacks_keep_retained_critical(policy, monkeypatch):
    from angerona.core import posture

    bus = _signed_bus()
    _critical(bus, policy["now"])
    _flood(bus, policy["now"])
    monkeypatch.setattr(posture, "_kev_penalty", lambda: (0, 0))
    monkeypatch.setattr(posture, "_attack_penalty", lambda: 0)

    assert posture._threat_penalty(bus) == (30, 1)
    snapshot = posture.posture(bus, SimpleNamespace(modules={}))
    assert snapshot["label"] == "Critical"
    assert snapshot["factors"]["active_threats"] == 1


def test_gui_worker_preparers_use_retained_priority_without_new_widget_or_io(policy, monkeypatch):
    from angerona.core import posture
    from angerona.gui.main_window import MainWindow
    from angerona.gui.pages import DashboardCards, ThreatWindow

    bus = _signed_bus()
    event = _critical(bus, policy["now"])
    _flood(bus, policy["now"])
    owner = SimpleNamespace(bus=bus, manager=SimpleNamespace(modules={}), config=None)
    monkeypatch.setattr(posture, "_kev_penalty", lambda: (0, 0))
    monkeypatch.setattr(posture, "_attack_penalty", lambda: 0)

    count, (label, _color) = DashboardCards._prepare_threat_snapshot(owner)()
    assert count == 1 and label == "Critical"
    events, (label, _color) = ThreatWindow._prepare_threat_snapshot(owner)()
    assert events == [event] and label == "Critical"
    snapshot, _tooltip = MainWindow._prepare_posture_snapshot(owner)()
    assert snapshot["label"] == "Critical" and snapshot["factors"]["active_threats"] == 1
