from __future__ import annotations

import time

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR


def _tampered_signed_event(**details: object) -> tuple[EventBus, Event]:
    bus = EventBus()
    bus.arm(BusAuthority(b"cycle19-integrity-gate-key-0000"))
    bus.publish(Event("Detector", "critical evidence", Severity.CRITICAL, details=details))
    event = bus.recent(1)[0]
    # Frozen Event does not freeze the legacy mapping. This simulates a buggy
    # subscriber changing response fields after the bus signed the event.
    event.details["pid"] = 424242
    assert not bus.verify(event)
    return bus, event


def test_active_response_reverifies_event_before_file_or_process_mutation(
    tmp_path,
    monkeypatch,
) -> None:
    victim = tmp_path / "do-not-delete.txt"
    victim.write_text("operator data", encoding="utf-8")
    bus, event = _tampered_signed_event(path=str(victim), pid=7)
    module = ActiveResponseSOAR()
    module.bind(bus)
    emitted: list[str] = []
    monkeypatch.setattr(
        module,
        "emit",
        lambda message, *_args, **_kwargs: emitted.append(message),
    )

    module._kill_and_rollback(event)

    assert victim.read_text(encoding="utf-8") == "operator data"
    assert any("integrity verification failed" in message for message in emitted)


def test_soar_automation_reverifies_event_before_containment(monkeypatch) -> None:
    bus, event = _tampered_signed_event(pid=7)
    module = SOARModule()
    module.bind(bus)
    module._auto = True
    module._under_attack_until = time.time() + 60
    contained: list[int] = []
    emitted: list[str] = []
    monkeypatch.setattr(module, "_is_protected_process", lambda _pid: False)
    monkeypatch.setattr(module, "_add_signal", lambda _pid, _event: True)
    monkeypatch.setattr(module, "_contain", lambda pid, _event: contained.append(pid))
    monkeypatch.setattr(
        module,
        "emit",
        lambda message, *_args, **_kwargs: emitted.append(message),
    )

    module._run_playbook(event)

    assert contained == []
    assert any("integrity verification failed" in message for message in emitted)


def test_active_response_private_sink_rechecks_configured_scope(
    tmp_path,
    monkeypatch,
) -> None:
    scope = tmp_path / "drill-sandbox"
    scope.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("operator data", encoding="utf-8")
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(scope))
    module = ActiveResponseSOAR()
    emitted: list[str] = []
    monkeypatch.setattr(
        module,
        "emit",
        lambda message, *_args, **_kwargs: emitted.append(message),
    )

    module._kill_and_rollback(
        Event(
            "Detector",
            "critical evidence",
            Severity.CRITICAL,
            details={"path": str(outside)},
        )
    )

    assert outside.read_text(encoding="utf-8") == "operator data"
    assert any("outside the authorized response scope" in message for message in emitted)
