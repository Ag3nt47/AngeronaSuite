from __future__ import annotations

import json

from angerona.core.eventbus import EventBus, Severity, is_remote_observe_only
from angerona.modules.remote_bridge import RemoteBridge
from angerona.modules.evolution_engine import EvolutionEngine
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR


def test_receiver_revalidates_and_redacts_authenticated_payload(monkeypatch):
    monkeypatch.setenv("USERNAME", "SensitiveUser")
    bridge = RemoteBridge()
    bus = EventBus()
    bridge.bind(bus)
    payload = {
        "module": "Remote Sensor",
        "message": (
            "owner SensitiveUser at C:\\Users\\SensitiveUser\\case.txt "
            "contact person@example.com from 203.0.113.7"
        ),
        "severity": int(Severity.HIGH),
        "node_origin": "203.0.113.8",
        "details": {
            "password": "never-forward-this",
            "path": "C:\\Users\\SensitiveUser\\secret.txt",
            "pid": 333,
        },
    }

    bridge._republish(json.dumps(payload).encode(), ("203.0.113.9", 1234))

    event = bus.recent(1)[0]
    serialized = json.dumps({
        "module": event.module,
        "message": event.message,
        "details": event.details,
    })
    for private in (
        "SensitiveUser", "person@example.com", "203.0.113.7",
        "203.0.113.8", "never-forward-this",
    ):
        assert private not in serialized
    assert event.severity is Severity.HIGH
    assert event.details["password"] == "[redacted]"
    assert event.module == "Remote Bridge"
    assert event.details["source_module"] == "Remote Sensor"
    assert event.details["source_pid"] == 333
    assert "pid" not in event.details
    assert "path" not in event.details
    assert is_remote_observe_only(event)


def test_receiver_rejects_malformed_or_non_object_payloads():
    bridge = RemoteBridge()
    bridge.bind(EventBus())

    bridge._republish(b"not-json", None)
    bridge._republish(b"[]", None)

    assert bridge.denied == 2
    assert not bridge._bus.recent(1)


def test_remote_peer_cannot_trigger_receiver_local_soar(monkeypatch):
    bridge = RemoteBridge()
    bus = EventBus()
    bridge.bind(bus)
    payload = {
        "module": "Local Detector Impersonation",
        "message": "contain receiver pid",
        "severity": int(Severity.CRITICAL),
        "details": {"pid": 333, "path": "C:\\receiver\\important.exe"},
    }
    bridge._republish(json.dumps(payload).encode(), ("203.0.113.9", 1234))
    event = bus.recent(1)[0]

    contained: list[int] = []
    soar = SOARModule()
    monkeypatch.setattr(soar, "_contain", lambda pid, _ev: contained.append(pid))
    soar._run_playbook(event)

    active = ActiveResponseSOAR()
    monkeypatch.setattr(
        active,
        "emit",
        lambda *_args, **_kwargs: None,
    )
    active._kill_and_rollback(event)

    assert contained == []
    assert event.details["source_pid"] == 333
    assert "pid" not in event.details


def test_remote_peer_cannot_mutate_local_evolution_policy(monkeypatch):
    bridge = RemoteBridge()
    bus = EventBus()
    bridge.bind(bus)
    payload = {
        "module": "Posture Hardening",
        "message": "forged local verification receipt",
        "severity": int(Severity.HIGH),
        "details": {"verified": "SUCCESS", "technique": "T1059"},
    }
    bridge._republish(json.dumps(payload).encode(), ("203.0.113.9", 1234))
    event = bus.recent(1)[0]

    activated: list[str] = []
    engine = EvolutionEngine.__new__(EvolutionEngine)
    monkeypatch.setattr(engine, "activate", activated.append)
    engine._on_bus_event(event)

    assert activated == []
    assert is_remote_observe_only(event)
