"""Authenticated polling activity does not identify why a canary was missed."""
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.threat import is_active_threat
from angerona.modules import canary_drill as drill
from angerona.modules.adversary_combat import AdversaryCombat


def _misses(monkeypatch, count):
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(drill, "time", SimpleNamespace(monotonic=lambda:clock.now,time=lambda:1000+clock.now))
    bus = EventBus();bus.arm(BusAuthority(b"c"*32))
    module = drill.CanaryDrillModule();module.bind(bus)
    bus.subscribe(module._on_event);module._subscribed=True
    prior = "DRILLCANARY_ABCDEF0123456789"
    assert module._expectations.arm(prior,drill._PROCESS_CONTRACT,now=clock.now)
    bus.publish(Event("Telemetry Scanner",f"Process observed {prior}",Severity.INFO,
        details={"type":"process_creation","source":"psutil-fallback","pid":731}))
    signed = bus.recent(1)[0]
    assert bus.verify(signed)
    module.bind_recorder(SimpleNamespace(bounded_events_in_window=lambda *a,**k:([signed],1)))
    module._collect_echoes();module._check_durable_receipts()
    assert module._ever_caught and module._drills_caught==1
    for i in range(count):
        tag="DRILLCANARY_"+f"{i:016X}"
        assert module._expectations.arm(tag,drill._PROCESS_CONTRACT,now=clock.now)
    module._drills_fired=count+1
    clock.now+=drill.CANARY_TIMEOUT_S+1
    bus.publish(Event("Telemetry Scanner","Another process observed",Severity.INFO,
        details={"type":"process_creation","source":"psutil-fallback","pid":732}))
    assert module._last_trusted_event==clock.now
    health=[];original=module.set_health
    def record(pct,note=""):
        health.append((pct,note));original(pct,note)
    monkeypatch.setattr(module,"set_health",record)
    monkeypatch.setattr(module,"sleep",lambda _:module._stop.set())
    monkeypatch.setattr(module,"_fire_canary",lambda:pytest.fail("fixture spawned a probe"))
    module.run()
    alerts=[e for e in bus.recent(100) if e.module==module.name and e.severity>=Severity.HIGH]
    return module,bus,alerts,health


@pytest.mark.parametrize("count",[1,2])
def test_polling_activity_and_missed_probe_preserve_priority_without_hook_or_action_proof(monkeypatch,count):
    module,bus,alerts,_health=_misses(monkeypatch,count)
    assert module._consecutive_misses==count
    assert sum(e.severity==Severity.CRITICAL for e in alerts)==(1 if count>=2 else 0)
    assert sum(e.severity==Severity.HIGH for e in alerts)==count
    for event in alerts:
        assert bus.verify(event)
        assert event.details["disposition"]=="health"
        assert event.details["active_attack"] is False
        assert event.details["response_authorized"] is False
        assert event.details["cause_unconfirmed"] is True
        assert event.details["echo_path_verified"] is True
        assert event.details["source_silent"] is False
        assert "response_contract" not in event.details
        assert "blinding detected" not in event.message.casefold()
        assert not is_active_threat(event)
        # Exercise the real authenticated Combat execution boundary without
        # constructing any journal, native provider or host action facility.
        combat=object.__new__(AdversaryCombat)
        combat._bus=bus;combat._mutation_blocked=False;combat._journal_saturated=False
        combat.policy=lambda:SimpleNamespace(enabled=True,min_severity=Severity.LOW)
        decisions=[];combat._response_decision=decisions.append
        combat._act_on_process=lambda *a,**k:pytest.fail("health record acted on process")
        combat._block_remote_ip=lambda *a,**k:pytest.fail("health record changed firewall")
        combat._handle(event)
        # Canary producers are classified as practice before their health
        # detail; the missing response contract must still stop execution.
        assert decisions==["invalid_contract"]
