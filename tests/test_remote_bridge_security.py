from __future__ import annotations

import json

from angerona.core.eventbus import EventBus, Severity
from angerona.modules.remote_bridge import RemoteBridge


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


def test_receiver_rejects_malformed_or_non_object_payloads():
    bridge = RemoteBridge()
    bridge.bind(EventBus())

    bridge._republish(b"not-json", None)
    bridge._republish(b"[]", None)

    assert bridge.denied == 2
    assert not bridge._bus.recent(1)
