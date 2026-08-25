from __future__ import annotations

import time
from types import SimpleNamespace

import angerona.modules.mobile_bridge as mobile_module
import angerona.modules.shadow_shield as shadow_module
import angerona.modules.soar as soar_module
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.mobile_bridge import MobileResponseBridge
from angerona.modules.shadow_shield import ShadowShield
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR


class _CombatStub:
    status = "running"

    def __init__(self, *, process_action: str = "terminate") -> None:
        self.process_action = process_action
        self.submitted: list[Event] = []
        self.receipts: list[dict] = []

    def policy(self):
        return SimpleNamespace(
            process_action=self.process_action,
            mode="maximum",
            isolate_host=True,
        )

    def _submit(self, event: Event) -> None:
        self.submitted.append(event)

    def list_actions(self, limit: int = 250) -> list[dict]:
        return self.receipts[-limit:]

    def consume_as_success(self, event: Event) -> None:
        if event.module != "Mobile Response Bridge":
            return
        action = event.details["response_contract"]["actions"][0]
        self.receipts.append({
            "action_id": "act-mobile-exact",
            "action": action,
            "trigger_module": event.module,
            "trigger_ts": event.ts,
            "status": "applied",
            "integrity_status": "verified",
            "details": {"postcondition_verified": True},
        })


class _FakeProcess:
    created = 200.0
    executable = r"C:\Lab\sample.exe"

    def __init__(self, pid: int) -> None:
        assert pid == 4242

    def create_time(self) -> float:
        return self.created

    def exe(self) -> str:
        return self.executable

    def name(self) -> str:
        return "sample.exe"


def _process_event(*, created: float = 100.0) -> Event:
    return Event(
        "Semantic Detector",
        "corroborated exact process verdict",
        Severity.CRITICAL,
        details={
            "pid": 4242,
            "process_create_time": created,
            "exe": _FakeProcess.executable,
            "response_authorized": True,
            "response_contract": {
                "version": 1,
                "actions": ["suspend_process"],
                "targets": {"pid": 4242, "process_create_time": created},
            },
        },
    )


def test_legacy_soar_rejects_pid_reuse_before_combat_delegation(monkeypatch) -> None:
    monkeypatch.setattr(
        soar_module, "psutil", SimpleNamespace(Process=_FakeProcess)
    )
    combat = _CombatStub(process_action="suspend")
    module = SOARModule()
    module.bind_manager(SimpleNamespace(modules={"Adversary Combat": combat}))
    module._auto = True
    monkeypatch.setattr(module, "_is_protected_process", lambda _pid: False)
    monkeypatch.setattr(module, "_add_signal", lambda _pid, _event: True)

    module._run_playbook(_process_event(created=100.0))

    assert combat.submitted == []


def test_active_response_rejects_forged_or_out_of_scope_file_target(
    tmp_path, monkeypatch,
) -> None:
    scope = tmp_path / "drill-sandbox"
    scope.mkdir()
    victim = tmp_path / "operator-data.txt"
    victim.write_text("preserve", encoding="utf-8")
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(scope))
    event = Event(
        "Semantic Detector",
        "forged path",
        Severity.CRITICAL,
        details={
            "path": str(victim),
            "response_authorized": True,
            "response_contract": {
                "version": 1,
                "actions": ["quarantine_file"],
                "targets": {"path": str(victim)},
            },
        },
    )
    module = ActiveResponseSOAR()

    module._kill_and_rollback(event)

    assert victim.read_text(encoding="utf-8") == "preserve"


def test_mobile_pid_reuse_is_rejected_without_publishing(monkeypatch) -> None:
    monkeypatch.setattr(
        mobile_module, "psutil", SimpleNamespace(Process=_FakeProcess)
    )
    bus = EventBus()
    bus.arm(BusAuthority(b"m" * 32))
    combat = _CombatStub()
    bus.publish(Event(
        "Detector", "signed source", Severity.CRITICAL,
        details={"pid": 4242, "exe": _FakeProcess.executable},
    ))
    source = bus.recent(1)[0]
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge.bind_manager(SimpleNamespace(
        config=SimpleNamespace(),
        modules={"Adversary Combat": combat},
    ))

    ok, reason = bridge._execute_combat("KILL", {
        "pid": 4242,
        "process_create_time": 100.0,
        "exe": _FakeProcess.executable,
        "response_eligible": True,
        "source_event_hmac": source.hmac_sig,
    })

    assert ok is False
    assert "reused" in reason
    assert combat.submitted == []
    assert all(event.module != bridge.name for event in bus.recent(10))


def test_mobile_combat_success_is_reported_only_after_verified_receipt(
    monkeypatch,
) -> None:
    _FakeProcess.created = 200.0
    monkeypatch.setattr(
        mobile_module, "psutil", SimpleNamespace(Process=_FakeProcess)
    )
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    combat = _CombatStub()
    bus.subscribe(combat.consume_as_success)
    bus.publish(Event(
        "Detector", "signed source", Severity.CRITICAL,
        details={"pid": 4242, "exe": _FakeProcess.executable},
    ))
    source = bus.recent(1)[0]
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge.bind_manager(SimpleNamespace(
        config=SimpleNamespace(),
        modules={"Adversary Combat": combat},
    ))

    ok, receipt = bridge._execute_combat("KILL", {
        "pid": 4242,
        "process_create_time": 200.0,
        "exe": _FakeProcess.executable,
        "response_eligible": True,
        "source_event_hmac": source.hmac_sig,
    })

    assert ok is True
    assert receipt == "act-mobile-exact"
    request = bus.recent(1)[0]
    assert bus.verify(request)
    assert request.details["response_contract"]["targets"] == {
        "pid": 4242,
        "process_create_time": 200.0,
    }


def test_unsupported_mobile_directives_are_truthfully_rejected(monkeypatch) -> None:
    sent: list[str] = []
    bridge = MobileResponseBridge()
    bridge.bind(EventBus())
    bridge.bind_manager(SimpleNamespace(config=SimpleNamespace(), modules={}))
    monkeypatch.setattr(bridge, "_send", sent.append)
    monkeypatch.setattr(bridge, "_soar_event", lambda *_args, **_kwargs: None)
    bridge.pending_alerts["1234"] = {
        "pid": 4242,
        "process_create_time": 200.0,
        "exe": _FakeProcess.executable,
        "response_eligible": True,
        "timestamp": time.time(),
    }

    bridge._gated("KILL", "1234")
    bridge._lockdown()

    text = " ".join(sent).casefold()
    assert "rejected" in text
    assert "no process action" in text
    assert "no host action" in text
    assert "issued" not in text
    assert "directive dropped" not in text


def test_mobile_rollback_restores_only_one_exact_authorized_version(
    tmp_path, monkeypatch,
) -> None:
    protected = tmp_path / "Documents"
    protected.mkdir()
    data_root = tmp_path / "data"
    target = protected / "target.txt"
    other = protected / "other.txt"
    target.write_text("target-clean", encoding="utf-8")
    other.write_text("other-clean", encoding="utf-8")
    monkeypatch.setattr(shadow_module, "PROTECTED_DIRS", [str(protected)])
    monkeypatch.setattr(shadow_module, "_data_base", lambda: data_root)
    shield = ShadowShield()
    shield._cache_version(str(target.resolve()))
    shield._cache_version(str(other.resolve()))
    artifact = shield.prepare_rollback_artifact(
        str(target.resolve()), before_ts=time.time() + 1.0
    )
    assert artifact is not None
    target.write_text("target-encrypted", encoding="utf-8")
    other.write_text("other-encrypted", encoding="utf-8")

    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    bus.publish(Event(
        "Ransomware Correlator",
        "exact rollback target",
        Severity.CRITICAL,
        details={"path": str(target.resolve())},
    ))
    source = bus.recent(1)[0]
    bridge = MobileResponseBridge()
    bridge.bind(bus)
    bridge.bind_manager(SimpleNamespace(
        config=SimpleNamespace(),
        modules={"Shadow Shield": shield},
    ))
    bridge.pending_alerts["9876"] = {
        "pid": None,
        "rollback_artifact": artifact,
        "response_eligible": True,
        "source_event_hmac": source.hmac_sig,
        "timestamp": time.time(),
    }
    sent: list[str] = []
    monkeypatch.setattr(bridge, "_send", sent.append)

    bridge._gated("ROLLBACK", "9876")

    assert target.read_text(encoding="utf-8") == "target-clean"
    assert other.read_text(encoding="utf-8") == "other-encrypted"
    assert "one exact" in sent[-1].casefold()

    forged = dict(artifact, source_path=str(other.resolve()))
    ok, _reason = bridge._rollback({
        "pid": None,
        "rollback_artifact": forged,
        "response_eligible": True,
        "source_event_hmac": source.hmac_sig,
    })
    assert ok is False
    assert other.read_text(encoding="utf-8") == "other-encrypted"
