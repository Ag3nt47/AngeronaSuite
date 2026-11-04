"""UNEXECUTED draft: apply only after the canonical freeze and owner review.

All targets below are inert fixtures. These tests do not attest live native
collection, installed authority, or kernel/PPL isolation. Existing complete
cohorts named in REVIEW.md remain required before promotion.
"""
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace
import threading

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule
from angerona.core.response_proof import ProducerResponseProofs, event_proof_digest, proof_digest
from angerona.core.werfault_guard import OwnedProcessIdentity
from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.modules.adversary_combat import AdversaryCombat, HostMutationHeld
from angerona.modules.yara_scanner import YaraScannerModule
from test_spyware_guard import make_module, NOW


def _event():
    return Event("SpywareGuard", "inert native hash fixture", Severity.HIGH, NOW, {
        "pid": 45001, "process_create_time": NOW - 10,
        "response_authorized": True,
        "response_contract": {"version": 1, "actions": ["terminate_process"],
                              "targets": {"pid": 45001, "process_create_time": NOW - 10}},
    })


@pytest.mark.parametrize("payload", [
    "x" * 16385, {"key": float("nan")}, {"key": float("inf")},
    {str(index): index for index in range(65)}, [0] * 129,
    [[[[[[[[[0]]]]]]]]], {"key": object()}, 1 << 65,
], ids=["utf8-budget", "nan", "infinity", "mapping-limit", "sequence-limit",
        "depth-limit", "custom-object", "integer-width"])
def test_proof_payload_bounds_reject_before_json(payload):
    with pytest.raises(ValueError):
        proof_digest(payload)


def test_proof_node_budget_is_independent_of_each_container_limit():
    with pytest.raises(ValueError, match="payload_bounds"):
        proof_digest([[0] * 128 for _ in range(5)])


def test_custom_builtin_subclasses_cannot_run_serialization_hooks():
    class Untrusted(dict):
        def items(self):
            pytest.fail("untrusted adapter executed")
    with pytest.raises(ValueError, match="plain_types"):
        proof_digest(Untrusted(value="inert"))


def test_receipt_is_exact_bounded_generation_bound_and_not_renewed():
    event, receipts, review = _event(), ProducerResponseProofs(), {"inert": "review"}
    receipts.retain(event, generation=7, now=100.0, review=review)
    assert receipts.verify(event, generation=7, now=129.99, review=review)
    receipts.retain(event, generation=7, now=129.0, review=review)
    assert not receipts.verify(event, generation=7, now=130.0, review=review)
    assert not receipts.verify(event, generation=8, now=110.0, review=review)
    assert not receipts.verify(event, generation=7, now=99.0, review=review)
    changed = replace(event, ts=event.ts + 1)
    assert event_proof_digest(changed) != event_proof_digest(event)
    assert not receipts.verify(changed, generation=7, now=110.0, review=review)
    assert not receipts.verify(event, generation=7, now=110.0, review={"inert": "revoked"})


def test_registry_never_exceeds_4096_complete_receipts():
    receipts = ProducerResponseProofs()
    for index in range(4100):
        event = replace(_event(), message="inert bounded receipt " + str(index))
        receipts.retain(event, generation=1, now=100.0, review={})
    assert len(receipts._receipts) == 4096


@pytest.mark.parametrize("finding", [
    {"pid": 45001, "process_create_time": NOW - 10, "kind": "screen_capture"},
    {"pid": 45001, "response_eligible": True, "malware_confirmed": True},
    {"response_eligible": True, "evidence": {"indicator_kind": "sha256", "reviewed": True}},
    {"kind": "definition_ip_indicator_match", "remote_ip": "8.8.8.8"},
    {"kind": "unbound_heuristic"},
], ids=["single-api-heuristic", "caller-flags", "copied-hash-prose", "ip-review", "no-target"])
def test_unattended_findings_without_native_sample_stay_visible_observations(finding):
    module, bus = make_module()
    module._publish(dict(finding, severity="HIGH"), local_authority=True)
    event = bus.recent(1)[0]
    assert event.details["response_authorized"] is False
    assert event.details["spyware_confirmed"] is False
    assert "response_contract" not in event.details
    assert len(module.dashboard_snapshot()["hits"]) == 1


def test_fixture_native_hash_receipt_cannot_be_forged_by_flags_and_is_revocable(monkeypatch):
    # This seeds the native seam to test admission logic; it is not a native
    # collector test or evidence of file/loaded-image identity on a host.
    module, bus = make_module()
    digest = "a" * 64
    review = {"indicator_kind": "sha256", "indicator": digest, "locally_activated": True}
    monkeypatch.setattr(module, "_current_hash_review", lambda value: review if value == digest else None)
    monkeypatch.setattr("angerona.modules.spyware_guard.time.monotonic", lambda: 100.0)
    record = {"kind": "definition_sha256_indicator_match", "pid": 45001,
              "process_create_time": NOW - 10, "path": "C:/inert/fixture.exe",
              "observed_content_sha256": digest, "evidence": review, "severity": "HIGH"}
    token = object()
    module._native_hash_samples[token] = (
        module.lifecycle_generation, module._stop, 100.0, record["path"], digest, 45001, NOW - 10)
    module._publish(record, local_authority=True, native_sample=token)
    event = bus.recent(1)[0]
    assert event.details["response_authorized"] is True
    assert "isolate_host" not in event.details["response_contract"]["actions"]
    assert event.details["spyware_confirmed"] is False
    assert module.verify_response_event(event)
    changed = replace(event, ts=event.ts + 1)
    assert not module.verify_response_event(changed)
    monkeypatch.setattr(module, "_current_hash_review", lambda _: None)
    assert not module.verify_response_event(event)


def test_retention_racing_restart_cannot_rebind_old_native_sample(monkeypatch):
    module, bus = make_module()
    digest = "a" * 64
    review = {"indicator_kind": "sha256", "indicator": digest, "locally_activated": True}
    monkeypatch.setattr(module, "_current_hash_review", lambda _: review)
    monkeypatch.setattr("angerona.modules.spyware_guard.time.monotonic", lambda: 100.0)
    record = {"kind": "definition_sha256_indicator_match", "pid": 45001,
              "process_create_time": NOW - 10, "path": "C:/inert/fixture.exe",
              "observed_content_sha256": digest, "evidence": review, "severity": "HIGH"}
    token, original_stop = object(), module._stop
    module._native_hash_samples[token] = (
        module.lifecycle_generation, original_stop, 100.0, record["path"], digest, 45001, NOW - 10)
    retain = module._retain_native_hash_response
    def restart_before_retention(*args):
        original_stop.set()
        module._lifecycle_generation += 1
        module._stop = threading.Event()
        return retain(*args)
    monkeypatch.setattr(module, "_retain_native_hash_response", restart_before_retention)
    module._publish(record, local_authority=True, native_sample=token)
    event = bus.recent(1)[0]
    assert event.details["response_authorized"] is False
    assert not module.verify_response_admission(event)
    assert not module._response_proofs._receipts


def test_admission_uses_only_cached_receipt_and_never_reads_intel(monkeypatch):
    module, _bus = make_module()
    event = _event()
    review = {"indicator_kind": "sha256", "indicator": "a" * 64}
    event = replace(event, details=dict(event.details, evidence=review))
    module._response_proofs.retain(event, generation=module.lifecycle_generation, now=100.0, review=review)
    monkeypatch.setattr("angerona.modules.spyware_guard.time.monotonic", lambda: 110.0)
    monkeypatch.setattr(module, "_current_hash_review", lambda *_: pytest.fail("publisher entered intel lock"))
    assert module.verify_response_admission(event)


def _ownership_combat(monkeypatch, supplier):
    module = AdversaryCombat()
    module.bind_manager(SimpleNamespace(modules={}, owned_process_identities=supplier))
    monkeypatch.setattr("angerona.modules.adversary_combat.time.monotonic", lambda: 101.0)
    return module


def _owned(pid=50001, birth=133800000000000000, image=r"C:\Python\python.exe"):
    return OwnedProcessIdentity(pid, str(birth), (birth - 116444736000000000) / 10_000_000,
                                image, "scanner", 100.0, 102.0)


def test_companion_match_requires_exact_pid_raw_birth_and_image(monkeypatch):
    row = _owned()
    module = _ownership_combat(monkeypatch, lambda: (row,))
    with pytest.raises(HostMutationHeld, match="owned-companion"):
        module._require_not_owned_identity(ProcessObjectIdentity(row.pid, int(row.birth_ticks), row.image))
    # A reused PID with a different raw birth never inherits protection.
    module._require_not_owned_identity(ProcessObjectIdentity(row.pid, int(row.birth_ticks) + 1, row.image))
    # Python itself is not a protected name or an unrestricted allowlist.
    module._require_not_owned_identity(ProcessObjectIdentity(row.pid + 1, int(row.birth_ticks), row.image))
    with pytest.raises(HostMutationHeld, match="owned-image-mismatch"):
        module._require_not_owned_identity(ProcessObjectIdentity(row.pid, int(row.birth_ticks), r"C:\Other\python.exe"))


@pytest.mark.parametrize("case", ["absent", "empty", "failed", "expired", "wrong-type"],
                         ids=["unbound-fixture", "empty-roster", "supplier-failure", "expired-roster", "mutable-roster"])
def test_unknown_companion_roster_holds_with_fixed_reason(monkeypatch, case):
    def failed():
        raise RuntimeError("untrusted exception text")
    row = _owned()
    supplier = {"absent": None, "empty": lambda: (), "failed": failed,
                "expired": lambda: (OwnedProcessIdentity(row.pid, row.birth_ticks, row.create_time,
                    row.image, row.role, 98.0, 100.0),), "wrong-type": lambda: [row]}[case]
    module = _ownership_combat(monkeypatch, supplier)
    with pytest.raises(HostMutationHeld, match="ownership is unknown"):
        module._require_not_owned_identity(ProcessObjectIdentity(45001, int(row.birth_ticks), row.image))
    assert "untrusted exception text" not in module._owned_process_hold_reason


def test_cached_readiness_keeps_desired_policy_separate_from_host_authority(monkeypatch):
    module = AdversaryCombat()
    module.status = "running"
    module._response_initialized = True
    def forbidden(*_args, **_kwargs):
        pytest.fail("cached getter tried to inspect host authority")
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", forbidden)
    snapshot = module.response_snapshot()
    assert snapshot["policy_armed"] is True
    assert snapshot["host_authority_verified"] is False
    assert snapshot["ready"] is False
    assert snapshot["state"] == "AUTHORITY HELD"


def _response_owner(monkeypatch):
    producer, bus = make_module()
    combat = AdversaryCombat()
    combat.bind(bus)
    combat.bind_manager(SimpleNamespace(modules={producer.name: producer}))
    event = _event()
    bus.publish(event)
    event = bus.recent(1)[0]
    current = {"valid": True}
    monkeypatch.setattr(producer, "verify_response_event", lambda _: current["valid"])
    monkeypatch.setattr("angerona.modules.adversary_combat.time.time", lambda: NOW)
    return combat, producer, event, current


def test_producer_revocation_during_durable_intent_holds_before_effect(monkeypatch):
    # Seed only the existing inert native-sample seam. Retention, event signing
    # and the producer's actual verifier still establish/revoke this unit proof.
    producer, bus = make_module()
    digest = "a" * 64
    review = {"indicator_kind": "sha256", "indicator": digest, "locally_activated": True}
    current = {"valid": True, "phase": "before-intent"}
    review_calls = []

    def current_review(value):
        available = current["valid"] and value == digest
        review_calls.append((current["phase"], value, available))
        return review if available else None

    monkeypatch.setattr(producer, "_current_hash_review", current_review)
    monkeypatch.setattr("angerona.modules.spyware_guard.time.monotonic", lambda: 100.0)
    monkeypatch.setattr("angerona.modules.adversary_combat.time.time", lambda: NOW)
    record = {"kind": "definition_sha256_indicator_match", "pid": 45001,
              "process_create_time": NOW - 10, "path": "C:/inert/fixture.exe",
              "observed_content_sha256": digest, "evidence": review, "severity": "HIGH"}
    token = object()
    producer._native_hash_samples[token] = (
        producer.lifecycle_generation, producer._stop, 100.0, record["path"], digest, 45001, NOW - 10)
    producer._publish(record, local_authority=True, native_sample=token)
    event = bus.recent(1)[0]
    assert bus.verify(event) and producer.verify_response_event(event)
    assert "terminate_process" in event.details["response_contract"]["actions"]

    combat = AdversaryCombat()
    combat.bind(bus)
    combat.bind_manager(SimpleNamespace(modules={producer.name: producer}))
    # Installed/native observations are inert in this admission unit; never
    # replace the combined guard or the original producer verifier itself.
    monkeypatch.setattr("angerona.core.breach_state.protect_authority",
                        lambda: (True, "Inert installed-authority observation fixture"))
    ownership_calls = []

    def observe_target(pid, created, _image):
        assert (pid, created) == (45001, NOW - 10)
        ownership_calls.append(current["phase"])

    monkeypatch.setattr(combat, "_require_process_not_owned", observe_target)
    monkeypatch.setattr(combat, "_journal_writer_lease", nullcontext)
    monkeypatch.setattr(combat, "_pinned_journal_session", lambda **_: nullcontext())
    monkeypatch.setattr(combat, "_reserve_journal_capacity", lambda _: None)
    monkeypatch.setattr(combat, "_validated_active_journal_cache", lambda: object())
    intents = []

    def durable_intent(candidate):
        intents.append(candidate)
        assert producer.verify_response_event(event)
        current.update(valid=False, phase="after-intent")

    monkeypatch.setattr(combat, "_journal_intent", durable_intent)
    action = combat._action("terminate_process", "inert fixture", event, "inert-case",
                            reversible=False, details={"pid": 45001, "create_time": NOW - 10})
    effects = []
    with pytest.raises(HostMutationHeld, match="immutable producer proof"):
        with combat._journaled_mutation(action, event=event):
            effects.append("native effect must remain unreachable")
    assert intents == [action] and current["valid"] is False
    assert "after-intent" in ownership_calls
    assert any(phase == "after-intent" and value == digest and available is False
               for phase, value, available in review_calls)
    assert effects == []


def test_expiry_after_held_process_lease_is_rechecked_before_dispatch(monkeypatch):
    combat, _producer, event, current = _response_owner(monkeypatch)
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "inert fixture"))
    action = combat._action("terminate_process", "inert fixture", event, "inert-case",
                            reversible=False,
                            details={"pid": 45001, "create_time": NOW - 10, "exe": "C:/inert/fixture.exe"})
    combat._response_dispatch_local.context = (event, None, action, None)
    monkeypatch.setattr(combat, "_require_process_not_owned", lambda *_: current.update(valid=False))
    with pytest.raises(HostMutationHeld, match="immutable producer proof"):
        combat._require_host_mutation_authority(action=action)
    combat._response_dispatch_local.context = None


def test_generic_existing_contract_families_are_not_disabled_by_missing_new_api(monkeypatch):
    combat, _producer, event, _current = _response_owner(monkeypatch)
    # The admitted legacy family keeps exact contracts and transport checks;
    # this is explicit unmigrated coverage, not a producer-proof claim.
    legacy = replace(event, module="Inert Legacy Contract Fixture")
    combat._bus.publish(legacy)
    combat._require_current_response_event(combat._bus.recent(1)[0], admission=True)


def test_new_spyware_route_requires_retained_owner_even_on_valid_transport(monkeypatch):
    combat, producer, event, _current = _response_owner(monkeypatch)
    monkeypatch.setattr(producer, "verify_response_event", None)
    with pytest.raises(HostMutationHeld, match="native producer proof"):
        combat._require_current_response_event(event, admission=True)


def test_existing_yara_immutable_verifier_is_rechecked_on_generation_change(monkeypatch):
    combat, _producer, event, _current = _response_owner(monkeypatch)
    # Bypass rule loading in this inert fixture; initialize only BaseModule's
    # memory lifecycle and YARA's existing immutable receipt fields.
    yara = YaraScannerModule.__new__(YaraScannerModule)
    BaseModule.__init__(yara)
    yara._receipt_lock = threading.RLock()
    yara._detection_receipts = {}
    yara.bind(combat._bus)
    combat._manager.modules[yara.name] = yara
    event = replace(event, module=yara.name)
    yara._detection_receipts[YaraScannerModule._event_digest(event)] = yara.lifecycle_generation
    combat._bus.publish(event)
    event = combat._bus.recent(1)[0]
    combat._require_current_response_event(event)
    yara._lifecycle_generation += 1
    with pytest.raises(HostMutationHeld, match="immutable producer proof"):
        combat._require_current_response_event(event)


def test_expired_detector_proof_does_not_block_exact_restorative_receipt_path(monkeypatch):
    combat, _producer, event, current = _response_owner(monkeypatch)
    action = combat._action("isolate_program", "inert fixture", event, "inert-case",
                            reversible=True, details={"pid": 45001, "create_time": NOW - 10})
    combat._response_dispatch_local.context = (event, None, action, None)
    current["valid"] = False
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (True, "inert fixture"))
    monkeypatch.setattr(combat, "_require_process_not_owned", lambda *_: pytest.fail("restoration queried dead PID"))
    combat._require_host_mutation_authority(check_policy=False, restoring=True, action=action)
    # Original installed-authority requirement still applies to restoration.
    monkeypatch.setattr("angerona.core.breach_state.protect_authority", lambda: (False, "source observe fixture"))
    with pytest.raises(HostMutationHeld, match="source observe fixture"):
        combat._require_host_mutation_authority(check_policy=False, restoring=True, action=action)


def test_practice_proof_keeps_the_same_action_and_pin_for_handoff_validation(monkeypatch):
    from angerona.core import practice_scope
    from angerona.core.threat import event_disposition

    combat, _producer, event, _current = _response_owner(monkeypatch)
    assert event_disposition(event) != "practice"
    run_id = practice_scope.register_run("proof-handoff-inert-fixture", kind="red-team", ttl=30)
    try:
        # Use a real registered structured run binding. Cosmetic practice flags
        # alone must never select this production classifier branch.
        event = replace(event, details=dict(event.details, practice_run_id=run_id))
        combat._bus.publish(event)
        event = combat._bus.recent(1)[0]
        assert event_disposition(event) == "practice"
        canary, action, pin = object(), object(), object()
        calls = []
        def same_custody(value, **kwargs):
            calls.append((value, kwargs))
            return value is canary and kwargs.get("action") is action and kwargs.get("pinned") is pin
        monkeypatch.setattr(combat, "_canary_mutation_valid", same_custody)
        combat._require_current_response_event(event, canary=canary, action=action, pinned=pin)
        assert calls == [(canary, {"action": action, "pinned": pin})]
        with pytest.raises(HostMutationHeld, match="issuer-owned practice proof"):
            combat._require_current_response_event(event, canary=canary, action=action, pinned=object())
    finally:
        practice_scope.unregister_run(run_id)
    assert event_disposition(event) != "practice"
