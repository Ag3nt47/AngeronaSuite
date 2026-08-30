from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.authorization import (
    AuthorizationPolicy,
    AuthorizationRequest,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
)
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.assurance_receipts import (
    PRODUCER_CONTRACTS,
    AssuranceReceiptBroker,
)
from angerona.modules import adversary_combat as combat_module
from angerona.modules import api_patch_detector as api_patch_module
from angerona.modules import etw_listener as etw_module
from angerona.modules.adversary_combat import AdversaryCombat, CombatAction
from angerona.modules.api_patch_detector import ApiPatchDetectorModule
from angerona.modules.chaos_harness import ChaosHarness
from angerona.modules.etw_listener import EtwListenerModule
from angerona.modules.file_integrity import (
    FileIntegrityModule,
    register_runtime_watch,
    unregister_runtime_watch,
)


_COMBAT_TEST_ANCHORS: dict[str, dict[str, str]] = {}
_ETW_TEST_ANCHORS: dict[str, dict[str, str]] = {}


def _new_combat(tmp_path: Path) -> AdversaryCombat:
    anchor = _COMBAT_TEST_ANCHORS.setdefault(str(tmp_path.resolve()), {})
    return AdversaryCombat(tmp_path, rollback_anchor=anchor)


def _nonreversible_intent(module: AdversaryCombat) -> CombatAction:
    action = CombatAction(
        action_id="act-1111111111111111",
        combat_id="combat-aaaaaaaaaaaa",
        action="terminate_process",
        applied_at=100.0,
        reversible=False,
        target="4242",
        details={"pid": 4242, "create_time": 50.0},
        trigger_module="inert-test",
        trigger_ts=99.0,
    )
    module._journal_intent(action)
    return action


def _operator_policy(
    *, kind: PrincipalKind = PrincipalKind.HUMAN
) -> AuthorizationPolicy:
    expires = time.time() + 10_000.0 if kind is PrincipalKind.SERVICE else 0.0
    return AuthorizationPolicy(
        (Principal("operator-one", kind, expires_at=expires),),
        (Role("recovery-responder", ("response.execute",)),),
        (
            RoleBinding(
                "operator-one",
                "recovery-responder",
                "response/adversary-combat",
                expires_at=expires,
            ),
        ),
        b"cycle27-recovery-authorization-key" * 2,
    )


def _operator_decision(
    policy: AuthorizationPolicy,
    resource_id: str,
    *,
    now: float | None = None,
    request_id: str = "recovery-request-one",
):
    stamp = time.time() if now is None else now
    return policy.decide(
        AuthorizationRequest(
            request_id=request_id,
            principal_id="operator-one",
            permission="response.execute",
            scope="response/adversary-combat",
            resource_id=resource_id,
        ),
        now=stamp,
    )


_RECOVERY_REASON = "Reviewed exact process identity and incident evidence."


def test_nonreversible_crash_intent_stays_recovery_required_across_restarts(
    tmp_path,
) -> None:
    original = _new_combat(tmp_path)
    action = _nonreversible_intent(original)

    first_restart = _new_combat(tmp_path)
    assert first_restart._reconcile_state() is True
    assert first_restart._mutation_blocked is True
    assert first_restart.response_ready() is False
    assert first_restart.health == 0
    assert first_restart.list_actions()[0]["status"] == "recovery_required"
    records, _legacy = first_restart._read_journal(strict=True)
    assert [record["record_type"] for record in records] == ["intent", "orphan"]
    assert records[-1]["mutation_started"] is True

    second_restart = _new_combat(tmp_path)
    assert second_restart._reconcile_state() is True
    assert second_restart._mutation_blocked is True
    assert second_restart._pending_recovery_records()[action.action_id]
    records, _legacy = second_restart._read_journal(strict=True)
    assert all(record["record_type"] != "failure" for record in records)
    assert [record["record_type"] for record in records] == ["intent", "orphan"]


def test_nonreversible_recovery_requires_fresh_exact_human_authority(
    tmp_path, monkeypatch
) -> None:
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True

    service_policy = _operator_policy(kind=PrincipalKind.SERVICE)
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=service_policy))
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_applied",
        reason=_RECOVERY_REASON,
    )
    assert resource
    service_receipt = _operator_decision(service_policy, resource)
    rejected = module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_applied",
        reason=_RECOVERY_REASON,
        decision=service_receipt,
    )
    assert rejected["ok"] is False
    assert module._mutation_blocked is True

    human_policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=human_policy))
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
    )
    human_receipt = _operator_decision(human_policy, resource)
    tampered = dataclasses.replace(human_receipt, resource_id="act-2222222222222222")
    rejected = module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
        decision=tampered,
    )
    assert rejected["ok"] is False
    assert module._mutation_blocked is True

    stale_receipt = _operator_decision(
        human_policy,
        resource,
        now=time.time() - 301.0,
        request_id="recovery-request-stale",
    )
    issued_monotonic = float(
        module._recovery_challenges[action.action_id]["issued_monotonic"]
    )
    monkeypatch.setattr(
        combat_module.time,
        "monotonic",
        lambda: issued_monotonic + 301.0,
    )
    stale = module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
        decision=stale_receipt,
    )
    assert stale["ok"] is False
    assert module._mutation_blocked is True


def test_human_disposition_is_durable_and_only_then_rearms(tmp_path) -> None:
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True
    policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    reason = "Reviewed the exact PID birth identity and response evidence."
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_applied",
        reason=reason,
    )
    receipt = _operator_decision(policy, resource)

    result = module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_applied",
        reason=reason,
        decision=receipt,
    )

    assert result["ok"] is True
    assert result["recovery_required"] is False
    assert module._mutation_blocked is False
    records, _legacy = module._read_journal(strict=True)
    assert records[-1]["record_type"] == "operator_disposition"
    assert records[-2]["record_type"] == "recovery_challenge"
    assert records[-3]["record_type"] == "orphan"
    assert records[-1]["bound_record_hmac"] == records[-3]["record_hmac"]
    assert records[-1]["bound_challenge_hmac"] == records[-2]["record_hmac"]

    restarted = _new_combat(tmp_path)
    restarted.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    assert restarted._reconcile_state() is True
    assert restarted._mutation_blocked is False
    assert restarted._pending_recovery_records() == {}


class _UncertainKillProcess:
    def __init__(self, executable: Path) -> None:
        self._executable = executable
        self.killed = False

    def create_time(self) -> float:
        return 50.0

    def name(self) -> str:
        return "inert-uncertain.exe"

    def exe(self) -> str:
        return str(self._executable)

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float) -> int:
        return 0

    def is_running(self) -> bool:
        raise RuntimeError("inert postcondition transport failure")


def test_uncertain_kill_postcondition_durably_blocks_mutation_across_restart(
    tmp_path, monkeypatch
) -> None:
    """Exact inert replay of independent A01's fake-completed kill."""
    process = _UncertainKillProcess(tmp_path / "inert-uncertain.exe")
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: process, STATUS_STOPPED="stopped"),
    )
    module = _new_combat(tmp_path)
    monkeypatch.setattr(module, "_is_system_path", lambda _path: False)
    policy = dataclasses.replace(module.policy(), block_network=False)

    result = module._act_on_process(
        4242,
        policy,
        Event("inert-test", "uncertain termination", Severity.HIGH),
        "combat-aaaaaaaaaaaa",
        allowed_actions=frozenset({"terminate_process"}),
    )

    assert result == []
    assert process.killed is True
    assert module._mutation_blocked is True
    assert module.response_ready() is False
    assert module.health == 0
    records, _legacy = module._read_journal(strict=True)
    assert [record["record_type"] for record in records] == ["intent", "orphan"]
    assert records[-1]["mutation_started"] is True
    assert records[-1]["rollback_state"] == "operator_disposition_required"

    restarted = _new_combat(tmp_path)
    assert restarted._reconcile_state() is True
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert restarted._pending_recovery_records()[records[0]["action_id"]]


class _BlockedUncertainKillProcess(_UncertainKillProcess):
    def __init__(self, executable: Path) -> None:
        super().__init__(executable)
        self.kill_entered = threading.Event()
        self.release_kill = threading.Event()

    def kill(self) -> None:
        self.kill_entered.set()
        if not self.release_kill.wait(2.0):
            raise RuntimeError("inert kill barrier timed out")
        self.killed = True


def test_inflight_intent_cannot_be_disposed_before_later_orphan(
    tmp_path, monkeypatch
) -> None:
    """Exact inert replay of second re-audit's blocked-kill disposition race."""
    process = _BlockedUncertainKillProcess(tmp_path / "blocked-inert.exe")
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: process, STATUS_STOPPED="stopped"),
    )
    module = _new_combat(tmp_path)
    monkeypatch.setattr(module, "_is_system_path", lambda _path: False)
    policy = dataclasses.replace(module.policy(), block_network=False)
    captured: dict[str, CombatAction] = {}
    original_action = module._action

    def capture_action(*args, **kwargs):
        action = original_action(*args, **kwargs)
        captured["action"] = action
        return action

    monkeypatch.setattr(module, "_action", capture_action)
    worker = threading.Thread(
        target=module._act_on_process,
        args=(4242, policy, Event("inert-test", "race", Severity.HIGH), "combat-race"),
        kwargs={"allowed_actions": frozenset({"terminate_process"})},
        daemon=True,
    )
    worker.start()
    assert process.kill_entered.wait(1.0)
    action = captured["action"]

    operator_policy = _operator_policy()
    module.bind_manager(
        SimpleNamespace(recovery_authorization_policy=operator_policy)
    )
    # This is the formerly accepted bare-intent authorization shape.
    bare_intent_decision = _operator_decision(
        operator_policy,
        action.action_id,
        request_id="recovery-race-bare-intent",
    )
    disposition_result: dict[str, object] = {}
    disposition_started = threading.Event()
    disposition_done = threading.Event()

    def dispose_while_kill_is_blocked() -> None:
        disposition_started.set()
        disposition_result.update(module.resolve_nonreversible_recovery(
            action.action_id,
            disposition="confirmed_not_applied",
            reason="Operator checked before the inert kill barrier was released.",
            decision=bare_intent_decision,
        ))
        disposition_done.set()

    disposer = threading.Thread(target=dispose_while_kill_is_blocked, daemon=True)
    disposer.start()
    assert disposition_started.wait(1.0)
    assert disposition_done.wait(0.05) is False
    process.release_kill.set()
    worker.join(2.0)
    disposer.join(2.0)

    assert not worker.is_alive()
    assert not disposer.is_alive()
    assert process.killed is True
    assert disposition_result["ok"] is False
    assert module._mutation_blocked is True
    records, _legacy = module._read_journal(strict=True)
    assert [record["record_type"] for record in records] == ["intent", "orphan"]

    restarted = _new_combat(tmp_path)
    assert restarted._reconcile_state() is True
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    pending = restarted._pending_recovery_records()
    assert pending[action.action_id]["record_type"] == "orphan"


def test_historical_intent_disposition_orphan_order_reopens_on_replay(
    tmp_path,
) -> None:
    """An old HMAC-valid but phase-invalid terminal can never hide a later orphan."""
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True
    policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    reason = "Historical exact disposition before later inert orphan replay."
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=reason,
    )
    decision = _operator_decision(policy, resource, request_id="historical-race")
    assert module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=reason,
        decision=decision,
    )["ok"] is True
    module._mark_nonreversible_uncertain(
        action, "effect completed after historical disposition"
    )
    assert [
        record["record_type"] for record in module._read_journal(strict=True)[0]
    ] == [
        "intent",
        "orphan",
        "recovery_challenge",
        "operator_disposition",
        "orphan",
    ]

    restarted = _new_combat(tmp_path)
    restarted.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    assert restarted._reconcile_state() is True
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    pending = restarted._pending_recovery_records()
    assert pending[action.action_id]["record_type"] == "orphan"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("action", "isolate_host"),
        ("status", "failed"),
        ("disposition", "fabricated"),
        ("combat_id", "combat-wrong"),
    ),
)
def test_exact_bound_but_semantically_invalid_terminal_never_rearms(
    tmp_path, field: str, value: str
) -> None:
    """Exact inert replay of the third re-audit's trusted-writer terminals."""
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True
    policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    reason = "Operator reviewed the exact orphan before inert terminal replay."
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=reason,
    )
    decision = _operator_decision(policy, resource, request_id=f"malformed-{field}")
    challenge = module._recovery_challenges[action.action_id]["record"]
    orphan = module._pending_recovery_records()[action.action_id]
    reason_digest = hashlib.sha256(reason.encode()).hexdigest()
    payload = {
        "record_type": "operator_disposition",
        "action_id": action.action_id,
        "combat_id": orphan["combat_id"],
        "action": orphan["action"],
        "status": "operator_disposed",
        "disposition": "confirmed_not_applied",
        "reason": reason,
        "reason_digest": reason_digest,
        "disposed_at": time.time(),
        "operator_principal": decision.principal_id,
        "authorization_request_id": decision.request_id,
        "authorization_request_digest": decision.request_digest,
        "authorization_policy_hash": decision.policy_hash,
        "authorization_resource": resource,
        "authorization_decision": dataclasses.asdict(decision),
        "bound_record_hmac": orphan["record_hmac"],
        "bound_record_sequence": orphan["sequence"],
        "mutation_generation": orphan["details"]["mutation_generation"],
        "bound_challenge_hmac": challenge["record_hmac"],
        "bound_challenge_sequence": challenge["sequence"],
        "bound_challenge_counter": challenge["challenge_counter"],
        "bound_challenge_nonce": challenge["challenge_nonce"],
        "install_epoch": challenge["install_epoch"],
    }
    payload[field] = value
    module._append_journal(payload)

    restarted = _new_combat(tmp_path)
    restarted.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    assert restarted._reconcile_state() is True
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert restarted._pending_recovery_records()[action.action_id]


def test_recovery_resource_binds_selected_outcome_and_normalized_reason(
    tmp_path,
) -> None:
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True
    policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    reason = "Operator   reviewed the exact process and recovery evidence."
    normalized = " ".join(reason.split())
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_applied",
        reason=reason,
    )
    assert "confirmed_applied" in resource
    assert hashlib.sha256(normalized.encode()).hexdigest() in resource
    decision = _operator_decision(policy, resource, request_id="bound-outcome-reason")

    assert module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=reason,
        decision=decision,
    )["ok"] is False
    assert module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_applied",
        reason="Operator reviewed a different recovery evidence set.",
        decision=decision,
    )["ok"] is False
    assert module._mutation_blocked is True


def test_recovery_challenge_cannot_survive_restart_or_wall_clock_rollback(
    tmp_path, monkeypatch
) -> None:
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True
    policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    first_resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
    )
    old_decision = _operator_decision(
        policy, first_resource, request_id="pre-restart-recovery"
    )

    restarted = _new_combat(tmp_path)
    restarted.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    assert restarted._reconcile_state() is True
    second_resource = restarted.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
    )
    assert second_resource != first_resource
    monkeypatch.setattr(combat_module.time, "time", lambda: 1001.0)
    rejected = restarted.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
        decision=old_decision,
    )
    assert rejected["ok"] is False
    assert restarted._mutation_blocked is True


@pytest.mark.parametrize("operation", ("rollback", "delete"))
def test_recovery_anchor_rejects_journal_rollback_or_deletion(
    tmp_path, operation: str
) -> None:
    module = _new_combat(tmp_path)
    action = _nonreversible_intent(module)
    assert module._reconcile_state() is True
    orphan_journal = module.receipt_path.read_bytes()
    policy = _operator_policy()
    module.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    resource = module.recovery_authorization_resource(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
    )
    decision = _operator_decision(policy, resource, request_id=f"anchor-{operation}")
    assert module.resolve_nonreversible_recovery(
        action.action_id,
        disposition="confirmed_not_applied",
        reason=_RECOVERY_REASON,
        decision=decision,
    )["ok"] is True

    if operation == "rollback":
        module.receipt_path.write_bytes(orphan_journal)
    else:
        module.receipt_path.unlink()
    restarted = _new_combat(tmp_path)
    restarted.bind_manager(SimpleNamespace(recovery_authorization_policy=policy))
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0


class _Detector:
    def __init__(self, code: str) -> None:
        contract = PRODUCER_CONTRACTS[code]
        self.CODE = code
        self.name = contract[0]
        self._lifecycle_generation = 7


def _armed_harness() -> tuple[
    ChaosHarness, EventBus, AssuranceReceiptBroker, dict[str, object]
]:
    bus = EventBus(ring_size=64)
    bus.arm(BusAuthority(b"c" * 32))
    registry: dict[str, object] = {}
    broker = AssuranceReceiptBroker(lambda: registry)
    harness = ChaosHarness(cycle_seconds=60.0)
    harness.ECHO_TIMEOUT_S = 1.0
    harness.bind(bus)
    broker.enroll_consumer(harness)
    harness.bind_manager(SimpleNamespace(assurance_receipt_broker=broker))
    harness.sleep = lambda _seconds: None  # type: ignore[method-assign]
    return harness, bus, broker, registry


def _enroll_detector(
    broker: AssuranceReceiptBroker,
    registry: dict[str, object],
    code: str,
    producer: object | None = None,
):
    detector = producer or _Detector(code)
    module_name, capability_id, _observations = PRODUCER_CONTRACTS[code]
    registry[module_name] = detector
    issuer = broker.enroll_producer(
        detector,
        code=code,
        module_name=module_name,
        capability_id=capability_id,
    )
    return detector, issuer


def test_generic_bus_publisher_cannot_forge_allowlisted_detector_receipt() -> None:
    """Exact replay of independent A10's shared-EventBus field forgery."""
    harness, bus, broker, registry = _armed_harness()
    _detector, _issuer = _enroll_detector(broker, registry, "APID")
    challenge = harness._register_challenge(
        "apid", "ntdll-kernel32-prologues-v1", probe_id="1" * 32
    )
    assert challenge is not None
    module_name, capability_id, observations = PRODUCER_CONTRACTS["APID"]
    forged = {
        "assurance_receipt_version": 1,
        "receipt_type": "detector_object_observation",
        "probe_id": challenge.probe_id,
        "probe_kind": challenge.probe_kind,
        "challenge_digest": challenge.challenge_digest,
        "target_digest": challenge.target_digest,
        "responder_code": "APID",
        "responder_module": module_name,
        "capability_id": capability_id,
        "observation": next(iter(observations["apid"])),
        "source_epoch": "attacker_named_epoch",
        "lifecycle_generation": 7,
        "observed_at": time.time(),
        "producer_mac": "0" * 64,
    }
    # EventBus signs this because every in-process publisher shares that path.
    bus.publish(Event(module_name, "forged detector receipt", details=forged))

    assert bus.verify(bus.recent(1)[0]) is True
    assert harness._wait_for_echo(challenge) is False


def test_only_registered_detector_object_can_mint_one_time_receipt() -> None:
    harness, bus, broker, registry = _armed_harness()
    detector, issuer = _enroll_detector(broker, registry, "APID")
    challenge = harness._register_challenge(
        "apid", "ntdll-kernel32-prologues-v1", probe_id="2" * 32
    )
    assert challenge is not None
    impostor = _Detector("APID")
    assert issuer.issue(
        impostor,
        challenge.probe_id,
        observation="api_prolog_integrity_observed",
        observed_target_digest=challenge.target_digest,
    ) is None
    receipt = issuer.issue(
        detector,
        challenge.probe_id,
        observation="api_prolog_integrity_observed",
        observed_target_digest=challenge.target_digest,
    )
    assert receipt is not None
    bus.publish(Event(detector.name, "object-bound detector receipt", details=receipt))

    assert harness._wait_for_echo(challenge) is True
    assert broker.verify_and_consume(harness, receipt) is False


def test_apid_receipt_requires_complete_live_prologue_observation(monkeypatch) -> None:
    harness, bus, broker, registry = _armed_harness()
    detector = ApiPatchDetectorModule()
    detector.bind(bus)
    _detector, issuer = _enroll_detector(broker, registry, "APID", detector)
    detector.bind_assurance_receipt_issuer(issuer)
    challenge = harness._register_challenge(
        "apid", "ntdll-kernel32-prologues-v1", probe_id="3" * 32
    )
    assert challenge is not None
    pristine = b"\x4c\x8b\xd1\xb8\x00\x00\x00\x00\x0f\x05\xc3\x90\x90\x90\x90\x90"
    monkeypatch.setattr(
        detector,
        "_disk_prologues",
        lambda dll: {name: pristine for name in api_patch_module._WATCH[dll]},
    )
    monkeypatch.setattr(detector, "_mem_prologue", lambda _dll, _name: pristine)

    assert detector.scan_once() == []
    detector._publish_assurance_receipts()

    assert harness._wait_for_echo(challenge) is True


def test_fim_receipt_is_bound_to_content_read_from_exact_watched_path(tmp_path) -> None:
    harness, bus, broker, registry = _armed_harness()
    detector = FileIntegrityModule()
    detector.bind(bus)
    _detector, issuer = _enroll_detector(broker, registry, "FIM", detector)
    detector.bind_assurance_receipt_issuer(issuer)
    path = tmp_path / "inert-fim-marker.txt"
    content = b"cycle27 inert FIM assurance marker\n"
    path.write_bytes(content)
    assert register_runtime_watch(tmp_path)
    try:
        challenge = harness._register_challenge(
            "fim",
            str(path.resolve()),
            hashlib.sha256(content).hexdigest(),
            probe_id="4" * 32,
        )
        assert challenge is not None
        detector._publish_assurance_receipts()
        assert harness._wait_for_echo(challenge) is True
    finally:
        unregister_runtime_watch(tmp_path)


@dataclasses.dataclass
class _FakeEventRecord:
    RecordNumber: int
    EventID: int = 4688
    TimeGenerated: str = "generation-one"
    StringInserts: tuple[str, ...] = (r"C:\Windows\System32\cmd.exe",)
    SourceName: str = "Microsoft-Windows-Security-Auditing"
    ComputerName: str = "HOST"
    EventCategory: int = 0


class _FakeEventLog(SimpleNamespace):
    EVENTLOG_FORWARDS_READ = 1
    EVENTLOG_SEEK_READ = 2

    def __init__(self, records: list[_FakeEventRecord], page_size: int = 3):
        super().__init__()
        self.records = records
        self.page_size = page_size
        self.read_offsets: list[int] = []

    def OpenEventLog(self, _server, _channel):
        return self

    def CloseEventLog(self, _handle):
        return None

    def GetNumberOfEventLogRecords(self, _handle):
        return len(self.records)

    def GetOldestEventLogRecord(self, _handle):
        return min(record.RecordNumber for record in self.records)

    def ReadEventLog(self, _handle, _flags, offset):
        self.read_offsets.append(offset)
        return [
            record for record in self.records if record.RecordNumber >= offset
        ][0:self.page_size]


def _install_event_log(monkeypatch, fake: _FakeEventLog) -> None:
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)


_ETW_AUTHORITY_KEY = b"e" * 32


def _new_etw(tmp_path, *, host_identity: str = "cycle27-host-a"):
    bus = EventBus(ring_size=64)
    bus.arm(BusAuthority(_ETW_AUTHORITY_KEY))
    anchor = _ETW_TEST_ANCHORS.setdefault(str(tmp_path.resolve()), {})
    module = EtwListenerModule(
        tmp_path,
        host_identity=host_identity,
        rollback_anchor=anchor,
    )
    module.bind(bus)
    return module


def _enrollment_policy() -> AuthorizationPolicy:
    return AuthorizationPolicy(
        (Principal("telemetry-operator", PrincipalKind.HUMAN),),
        (Role("telemetry-enroller", ("policy.approve",)),),
        (
            RoleBinding(
                "telemetry-operator",
                "telemetry-enroller",
                "telemetry/security-channel",
            ),
        ),
        b"cycle27-etw-enrollment-authorization-key" * 2,
    )


_ETW_ENROLLMENT_REASON = (
    "Operator reviewed the caught-up Security channel boundary."
)


def _etw_approval(
    module: EtwListenerModule,
    request_id: str,
    *,
    policy: AuthorizationPolicy | None = None,
    reason: str = _ETW_ENROLLMENT_REASON,
):
    policy = policy or _enrollment_policy()
    module.bind_manager(
        SimpleNamespace(telemetry_enrollment_authorization_policy=policy)
    )
    resource = module.security_enrollment_resource(reason)
    assert resource
    decision = policy.decide(
        AuthorizationRequest(
            request_id=request_id,
            principal_id="telemetry-operator",
            permission="policy.approve",
            scope="telemetry/security-channel",
            resource_id=resource,
        )
    )
    return policy, decision


def _enroll_etw(module: EtwListenerModule, request_id: str) -> dict[str, object]:
    policy = _enrollment_policy()
    _policy, decision = _etw_approval(module, request_id, policy=policy)
    return module.enroll_security_cursor(
        decision=decision,
        reason=_ETW_ENROLLMENT_REASON,
    )


def test_security_log_forward_pagination_drains_sampled_high_watermark(
    tmp_path, monkeypatch,
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 11)])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)

    events = module._read_security_log()

    assert [event["record"] for event in events] == list(range(1, 11))
    assert module._last_record == 10
    assert fake.read_offsets[:4] == [1, 4, 7, 10]
    assert fake.read_offsets[4:] == [1, 4, 7, 10]
    assert module._security_backlog is False
    assert module.health == 45
    assert "missing" in module.health_note.casefold()
    assert _enroll_etw(module, "etw-enroll-forward")["ok"] is True
    assert module.health == 100


def test_security_log_bound_never_advances_past_unread_records(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 21)], 5)
    _install_event_log(monkeypatch, fake)
    monkeypatch.setattr(etw_module, "_MAX_SECURITY_RECORDS", 7)
    module = _new_etw(tmp_path)

    first = module._read_security_log()
    assert [event["record"] for event in first] == list(range(1, 8))
    assert module._last_record == 7
    assert module._security_backlog is True
    assert module.health == 45
    assert _enroll_etw(module, "etw-enroll-too-early")["ok"] is False

    second = module._read_security_log()
    assert [event["record"] for event in second] == list(range(8, 15))
    assert module._last_record == 14
    third = module._read_security_log()
    assert [event["record"] for event in third] == list(range(15, 21))
    assert module._last_record == 20
    assert module._security_backlog is False
    assert module.health == 45
    assert _enroll_etw(module, "etw-enroll-caught-up")["ok"] is True
    assert module.health == 100


def test_security_channel_reset_replays_new_generation_and_stays_degraded(
    tmp_path, monkeypatch,
) -> None:
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="generation-one")
        for number in range(50, 56)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, "etw-enroll-before-reset")["ok"] is True
    first_generation = module._security_generation

    fake.records = [
        _FakeEventRecord(number, TimeGenerated="generation-two")
        for number in range(1, 5)
    ]
    events = module._read_security_log()

    assert [event["record"] for event in events] == [1, 2, 3, 4]
    assert module._security_generation == first_generation + 1
    assert module._last_record == 4
    assert module.health == 45
    assert "reset" in module.health_note.casefold()
    module._ack_security_delivery_outbox(events)

    restarted = _new_etw(tmp_path)
    restarted._read_security_log()
    assert restarted._security_generation == module._security_generation
    assert restarted._last_record == 4
    assert restarted.health == 45


def test_security_channel_reused_record_anchor_detects_generation_change(
    tmp_path, monkeypatch,
) -> None:
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="generation-one")
        for number in range(1, 6)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, "etw-enroll-before-refill")["ok"] is True

    fake.records = [
        _FakeEventRecord(number, TimeGenerated="generation-two")
        for number in range(1, 11)
    ]
    events = module._read_security_log()

    assert [event["record"] for event in events] == list(range(1, 11))
    assert module._last_record == 10
    assert module.health == 45
    assert "replaced" in module.health_note.casefold()


def test_security_log_gap_stops_before_missing_record(tmp_path, monkeypatch) -> None:
    fake = _FakeEventLog(
        [_FakeEventRecord(1), _FakeEventRecord(3), _FakeEventRecord(4)],
        page_size=3,
    )
    # Simulate a sampled high watermark that proves records 1..4 should exist.
    fake.GetNumberOfEventLogRecords = lambda _handle: 4
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)

    events = module._read_security_log()

    assert [event["record"] for event in events] == [1]
    assert module._last_record == 1
    assert module.health == 45
    assert "expected record 2" in module.health_note


def test_security_clear_refill_is_detected_by_new_process_from_durable_cursor(
    tmp_path, monkeypatch
) -> None:
    """Exact inert replay of independent A16's process-restart evasion."""
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="generation-one")
        for number in range(50, 56)
    ])
    _install_event_log(monkeypatch, fake)
    first = _new_etw(tmp_path)
    first._read_security_log()
    assert _enroll_etw(first, "etw-enroll-persisted")["ok"] is True
    first_generation = first._security_generation
    assert first.cursor_state_path is not None
    assert first.cursor_state_path.exists()

    fake.records = [
        _FakeEventRecord(number, TimeGenerated="generation-two")
        for number in range(1, 5)
    ]
    restarted = _new_etw(tmp_path)
    events = restarted._read_security_log()

    assert [event["record"] for event in events] == [1, 2, 3, 4]
    assert restarted._security_generation == first_generation + 1
    assert restarted._last_record == 4
    assert restarted.health == 45
    assert "reset" in restarted.health_note.casefold()
    restarted._ack_security_delivery_outbox(events)

    second_restart = _new_etw(tmp_path)
    assert second_restart._read_security_log() == []
    assert second_restart._last_record == 4
    assert second_restart.health == 45
    assert "reset" in second_restart.health_note.casefold()


def test_tampered_or_host_mismatched_cursor_cannot_restore_complete_health(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    _install_event_log(monkeypatch, fake)
    enrolled = _new_etw(tmp_path)
    enrolled._read_security_log()
    assert _enroll_etw(enrolled, "etw-enroll-before-tamper")["ok"] is True
    path = enrolled.cursor_state_path
    assert path is not None
    document = json.loads(path.read_text(encoding="utf-8"))
    document["last_record"] = 1
    path.write_text(json.dumps(document), encoding="utf-8")

    tampered = _new_etw(tmp_path)
    tampered._read_security_log()
    assert tampered.health == 45
    assert "unverifiable" in tampered.health_note.casefold()

    # Re-enroll a valid state, then prove it cannot migrate to another host ID.
    assert _enroll_etw(tampered, "etw-enroll-after-tamper")["ok"] is True
    other_host = _new_etw(tmp_path, host_identity="cycle27-host-b")
    other_host._read_security_log()
    assert other_host.health == 45
    assert "unverifiable" in other_host.health_note.casefold()


def test_security_gap_approval_is_single_use_and_bound_to_exact_generation(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="generation-one")
        for number in range(1, 4)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    policy, first_decision = _etw_approval(module, "etw-approval-generation-one")
    first = module.enroll_security_cursor(
        decision=first_decision,
        reason=_ETW_ENROLLMENT_REASON,
    )
    assert first["ok"] is True

    fake.records = [
        _FakeEventRecord(number, TimeGenerated="generation-two")
        for number in range(1, 3)
    ]
    reset_events = module._read_security_log()
    assert module.health == 45
    assert module._security_generation == 2
    module._ack_security_delivery_outbox(reset_events)

    replay = module.enroll_security_cursor(
        decision=first_decision,
        reason=_ETW_ENROLLMENT_REASON,
    )
    assert replay["ok"] is False
    assert module.health == 45
    assert module._security_gap

    restarted = _new_etw(tmp_path)
    restarted.bind_manager(
        SimpleNamespace(telemetry_enrollment_authorization_policy=policy)
    )
    assert restarted._read_security_log() == []
    assert restarted.health == 45
    replay_after_restart = restarted.enroll_security_cursor(
        decision=first_decision,
        reason=_ETW_ENROLLMENT_REASON,
    )
    assert replay_after_restart["ok"] is False
    assert restarted.health == 45

    _policy, second_decision = _etw_approval(
        restarted,
        "etw-approval-generation-two",
        policy=policy,
    )
    second = restarted.enroll_security_cursor(
        decision=second_decision,
        reason=_ETW_ENROLLMENT_REASON,
    )
    assert second["ok"] is True
    final_restart = _new_etw(tmp_path)
    final_restart._read_security_log()
    assert final_restart.health == 100


def test_authenticated_cursor_rollback_is_rejected_by_independent_highwater(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="one-generation")
        for number in range(1, 6)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, "etw-enroll-before-rollback")["ok"] is True
    cursor_path = module.cursor_state_path
    highwater_path = module.cursor_highwater_path
    assert cursor_path is not None and highwater_path is not None
    old_cursor = cursor_path.read_bytes()
    old_sequence = module._cursor_sequence

    fake.records = [
        _FakeEventRecord(number, TimeGenerated="one-generation")
        for number in range(1, 11)
    ]
    progressed = module._read_security_log()
    assert [event["record"] for event in progressed] == list(range(6, 11))
    assert module._cursor_sequence > old_sequence
    latest_highwater = highwater_path.read_bytes()

    # Restore the old but correctly authenticated cursor and matching old
    # Security-channel snapshot, leaving the independent high-water current.
    cursor_path.write_bytes(old_cursor)
    fake.records = [
        _FakeEventRecord(number, TimeGenerated="one-generation")
        for number in range(1, 6)
    ]
    restarted = _new_etw(tmp_path)
    restarted._read_security_log()

    assert highwater_path.read_bytes() == latest_highwater
    assert restarted._cursor_sequence >= module._cursor_sequence
    assert restarted.health == 45
    assert "rollback" in restarted.health_note.casefold()
    assert restarted._security_gap

    second_restart = _new_etw(tmp_path)
    second_restart._read_security_log()
    assert second_restart.health == 45
    assert "rollback" in second_restart.health_note.casefold()


def test_deleted_cursor_pair_cannot_recreate_or_reuse_enrollment_approval(
    tmp_path, monkeypatch
) -> None:
    """Exact inert replay of the third re-audit's two-file deletion bypass."""
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 6)])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    policy, old_decision = _etw_approval(module, "delete-pair-first")
    old_resource = old_decision.resource_id
    assert module.enroll_security_cursor(
        decision=old_decision,
        reason=_ETW_ENROLLMENT_REASON,
    )["ok"] is True
    assert module.cursor_state_path is not None
    assert module.cursor_highwater_path is not None
    module.cursor_state_path.unlink()
    module.cursor_highwater_path.unlink()

    restarted = _new_etw(tmp_path)
    restarted.bind_manager(
        SimpleNamespace(telemetry_enrollment_authorization_policy=policy)
    )
    restarted._read_security_log()
    assert restarted.health == 45
    assert "fresh distinct enrollment" in restarted.health_note.casefold()
    new_resource = restarted.security_enrollment_resource(_ETW_ENROLLMENT_REASON)
    assert new_resource and new_resource != old_resource
    assert restarted.enroll_security_cursor(
        decision=old_decision,
        reason=_ETW_ENROLLMENT_REASON,
    )["ok"] is False
    fresh = policy.decide(
        AuthorizationRequest(
            request_id="delete-pair-fresh",
            principal_id="telemetry-operator",
            permission="policy.approve",
            scope="telemetry/security-channel",
            resource_id=new_resource,
        )
    )
    assert restarted.enroll_security_cursor(
        decision=fresh,
        reason=_ETW_ENROLLMENT_REASON,
    )["ok"] is True


def test_paired_cursor_highwater_and_channel_rollback_hits_protected_anchor(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="generation-one")
        for number in range(1, 6)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, "paired-rollback-enroll")["ok"] is True
    assert module.cursor_state_path is not None
    assert module.cursor_highwater_path is not None
    old_cursor = module.cursor_state_path.read_bytes()
    old_highwater = module.cursor_highwater_path.read_bytes()
    old_records = list(fake.records)

    fake.records.extend([
        _FakeEventRecord(number, TimeGenerated="generation-one")
        for number in range(6, 11)
    ])
    assert [
        event["record"] for event in module._read_security_log()
    ] == list(range(6, 11))
    module.cursor_state_path.write_bytes(old_cursor)
    module.cursor_highwater_path.write_bytes(old_highwater)
    fake.records = old_records

    restarted = _new_etw(tmp_path)
    restarted._read_security_log()
    assert restarted.health == 45
    assert "rollback-anchor" in restarted.health_note.casefold()
    assert restarted._security_gap


def test_enrollment_detects_prebookmark_replacement_across_durable_commit(
    tmp_path, monkeypatch
) -> None:
    """Exact inert replay of the final-sample channel replacement race."""
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="before-enrollment")
        for number in range(1, 6)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    policy, decision = _etw_approval(module, "identity-race")
    original_persist = module._persist_cursor_state
    calls = 0

    def persist_then_replace() -> bool:
        nonlocal calls
        calls += 1
        result = original_persist()
        if calls == 1:
            fake.records[0] = dataclasses.replace(
                fake.records[0], TimeGenerated="replaced-during-commit"
            )
            fake.records[1] = dataclasses.replace(
                fake.records[1], TimeGenerated="replaced-during-commit"
            )
        return result

    monkeypatch.setattr(module, "_persist_cursor_state", persist_then_replace)
    result = module.enroll_security_cursor(
        decision=decision,
        reason=_ETW_ENROLLMENT_REASON,
    )
    assert result["ok"] is False
    assert module.health == 45
    assert "changed across enrollment commit" in module.health_note.casefold()

    restarted = _new_etw(tmp_path)
    restarted.bind_manager(
        SimpleNamespace(telemetry_enrollment_authorization_policy=policy)
    )
    replayed = restarted._read_security_log()
    assert [event["record"] for event in replayed] == list(range(1, 6))
    assert restarted.health == 45
    assert "replaced" in restarted.health_note.casefold()


def test_security_health_cannot_complete_without_external_rollback_anchor(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)

    def unavailable() -> str:
        raise RuntimeError("inert protected store outage")

    monkeypatch.setattr(module, "_read_rollback_anchor_value", unavailable)
    module._read_security_log()
    assert module.health == 45
    assert "health cannot be complete" in module.health_note.casefold()
    assert module.security_enrollment_resource(_ETW_ENROLLMENT_REASON) == ""


@pytest.mark.parametrize("operation", ("delete", "rollback"))
def test_combat_paired_journal_anchor_loss_is_caught_by_signing_key_witness(
    tmp_path, operation: str
) -> None:
    module = _new_combat(tmp_path)
    assert module._reconcile_state() is True
    anchor_name = module._recovery_anchor_name()
    anchor_store = _COMBAT_TEST_ANCHORS[str(tmp_path.resolve())]
    empty_anchor = anchor_store[anchor_name]
    signing_key = module.journal_key_path.read_bytes()

    _nonreversible_intent(module)
    assert module._reconcile_state() is True
    assert module._mutation_blocked is True
    assert module.recovery_witness_path.is_file()

    module.receipt_path.unlink()
    if operation == "delete":
        anchor_store.pop(anchor_name)
    else:
        anchor_store[anchor_name] = empty_anchor

    restarted = _new_combat(tmp_path)
    assert restarted.journal_key_path.read_bytes() == signing_key
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert "witness" in restarted._journal_error.casefold()


@pytest.mark.parametrize("variant", ("long-tail", "insert-65"))
def test_security_record_anchor_covers_every_full_insertion(
    tmp_path, monkeypatch, variant: str
) -> None:
    common = "A" * 4096
    if variant == "long-tail":
        original_inserts = (common + "-original-tail",)
        replacement_inserts = (common + "-replacement-tail",)
    else:
        prefix = tuple(f"insert-{index}" for index in range(64))
        original_inserts = (*prefix, "insert-65-original")
        replacement_inserts = (*prefix, "insert-65-replaced")
    original = _FakeEventRecord(1, StringInserts=original_inserts)
    replacement = _FakeEventRecord(1, StringInserts=replacement_inserts)
    assert EtwListenerModule._record_anchor(original) != EtwListenerModule._record_anchor(
        replacement
    )

    fake = _FakeEventLog([original, _FakeEventRecord(2), _FakeEventRecord(3)])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, f"full-record-{variant}")["ok"] is True

    fake.records[0] = replacement
    restarted = _new_etw(tmp_path)
    replayed = restarted._read_security_log()
    assert [event["record"] for event in replayed] == [1, 2, 3]
    assert restarted.health == 45
    assert "replaced" in restarted.health_note.casefold()


def test_security_record_over_budget_never_advances_or_enrolls(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(etw_module, "_MAX_SECURITY_RECORD_IDENTITY_BYTES", 1024)
    fake = _FakeEventLog([
        _FakeEventRecord(1, StringInserts=("X" * 2048,)),
        _FakeEventRecord(2),
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)

    assert module._read_security_log() == []
    assert module._last_record == 0
    assert module.health == 45
    assert "identity is incomplete" in module.health_note.casefold()
    _policy, decision = _etw_approval(module, "over-budget-enrollment")
    assert module.enroll_security_cursor(
        decision=decision, reason=_ETW_ENROLLMENT_REASON
    )["ok"] is False


@pytest.mark.parametrize("lost", ("cursor", "highwater", "anchor"))
def test_live_security_authority_loss_is_visible_on_same_process_poll(
    tmp_path, monkeypatch, lost: str
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, f"live-loss-{lost}")["ok"] is True
    if lost == "cursor":
        assert module.cursor_state_path is not None
        module.cursor_state_path.unlink()
    elif lost == "highwater":
        assert module.cursor_highwater_path is not None
        module.cursor_highwater_path.unlink()
    else:
        _ETW_TEST_ANCHORS[str(tmp_path.resolve())].pop(
            module._rollback_anchor_name()
        )

    assert module._read_security_log() == []
    assert module.health == 45
    assert "transaction" in module.health_note.casefold()


def test_security_cursor_duplicate_writers_serialize_and_leave_valid_state(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    _install_event_log(monkeypatch, fake)
    writers = [_new_etw(tmp_path), _new_etw(tmp_path)]
    for writer in writers:
        writer._read_security_log()
        anchor = writer._rollback_anchor(allow_create=False)
        writer._install_epoch = str(anchor["install_epoch"])
        writer._cursor_enrolled = True
        writer._cursor_enrolled_at = time.time()
        writer._security_gap = ""
        writer._cursor_state_error = ""

    barrier = threading.Barrier(2)
    results: list[bool] = []

    def commit(writer: EtwListenerModule) -> None:
        barrier.wait(timeout=5)
        results.append(writer._persist_cursor_state())

    threads = [threading.Thread(target=commit, args=(writer,)) for writer in writers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()

    assert sorted(results) == [False, True]
    restarted = _new_etw(tmp_path)
    restarted._read_security_log()
    assert restarted.health == 100


def test_paired_etw_state_and_protected_anchor_rollback_hits_identity_witness(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeEventLog([
        _FakeEventRecord(number, TimeGenerated="stable-generation")
        for number in range(1, 4)
    ])
    _install_event_log(monkeypatch, fake)
    module = _new_etw(tmp_path)
    module._read_security_log()
    assert _enroll_etw(module, "witness-paired-rollback")["ok"] is True
    assert module.cursor_state_path is not None
    assert module.cursor_highwater_path is not None
    anchor_name = module._rollback_anchor_name()
    anchor_store = _ETW_TEST_ANCHORS[str(tmp_path.resolve())]
    old_anchor = anchor_store[anchor_name]
    old_cursor = module.cursor_state_path.read_bytes()
    old_highwater = module.cursor_highwater_path.read_bytes()
    old_records = list(fake.records)

    fake.records.extend([
        _FakeEventRecord(number, TimeGenerated="stable-generation")
        for number in range(4, 7)
    ])
    assert [event["record"] for event in module._read_security_log()] == [4, 5, 6]
    module.cursor_state_path.write_bytes(old_cursor)
    module.cursor_highwater_path.write_bytes(old_highwater)
    anchor_store[anchor_name] = old_anchor
    fake.records = old_records

    restarted = _new_etw(tmp_path)
    restarted._read_security_log()
    assert restarted.health == 45
    assert "witness" in restarted.health_note.casefold()
