"""Native writer tests use inert adapters exclusively; never change host policy."""
from dataclasses import asdict, replace
import base64
import hashlib
import json
from pathlib import Path
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from angerona.core.approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof
from angerona.core.privileged_pipe import NativePeer
from angerona.core.privileged_service import PrivilegedService, PrivilegedServiceClient
from angerona.core.response_broker import ResponseBroker
from angerona.core.response_capability import PrivilegedOpcode, ResponseCapabilityAuthority
from angerona.core.windows_prevention import (
    LOGON_GUID, RESOURCE, LogonAuditPlan, NativeLogonAuditExecutor, PreventionJournal,
    WindowsPreventionBackend, inspect_logon_policy, prepare_logon_plan, validate_arguments,
)


class Native:
    def __init__(self, bits=0):
        self.bits, self.calls, self.after_set = bits, [], None

    def query_bits(self):
        self.calls.append(("query", self.bits))
        return self.bits

    def set_bits(self, bits):
        self.calls.append(("set", bits))
        self.bits = bits
        if self.after_set:
            self.after_set()


def peer(index=1):
    return NativePeer(f"S-1-5-21-100-200-300-{index}", "S-1-5-5-1-2", "1:2", 1234, 100.0)


def private(index):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"inert-prevention-{index}".encode()).digest())


def composition(tmp_path, *, native=None, consumer=True, guard=lambda: True):
    clock = lambda: 101.0
    records = [PrincipalCredential(f"operator-{index}", "windows-token", peer(index).user_sid,
        private(index).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        for index in (1, 2, 3)]
    broker = ResponseBroker(b"b" * 32, identity_verifier=ApprovalIdentityVerifier(records, clock=clock),
                            state_path=tmp_path / "broker" / "state.json", clock=clock)
    journal = PreventionJournal(tmp_path / "prevention" / "state.json", b"j" * 32)
    authority = ResponseCapabilityAuthority(b"a" * 32, state_path=tmp_path / "authority" / "state.json")
    native = native or Native()
    executor = NativeLogonAuditExecutor(native=native, journal=journal, installed_guard=guard, clock=clock)
    service = PrivilegedService(capabilities=authority, transport_key=b"t" * 32, executor=executor)

    class Transport:
        def exchange(self, document):
            return service.handle(document)

    client = PrivilegedServiceClient(transport_key=b"t" * 32, transport=Transport())

    def consume(**kwargs):
        return client.execute(request_id=kwargs["parameters"]["plan_id"], **kwargs)

    backend = WindowsPreventionBackend(broker, journal, native=native, capabilities=authority,
                                       consumer=consume if consumer else None, clock=clock)
    return backend, native, authority


@pytest.fixture
def system(tmp_path):
    backend, native, authority = composition(tmp_path)
    yield backend, native, authority
    backend.broker.close()
    backend.journal.close()
    authority.close()


def proof(proposal, index):
    record = PrincipalCredential(f"operator-{index}", "windows-token", peer(index).user_sid,
        private(index).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    unsigned = SignedPrincipalProof.unsigned(record, proposal.digest, 100, 400, str(index) * 32)
    return replace(unsigned, signature=base64.urlsafe_b64encode(private(index).sign(unsigned.signing_bytes())).decode().rstrip("="))


def approved(backend, plan):
    proposal = backend.proposal(plan, peer())
    for index in (2, 3):
        backend.approve(proposal, proof(proposal, index), peer(index))
    return proposal


def test_actual_durable_broker_capability_service_and_inverse_recovery(system):
    backend, native, authority = system
    plan = prepare_logon_plan(0, clock=lambda: 100)
    proposal = approved(backend, plan)
    receipt = backend.execute(proposal, peer())
    assert receipt.outcome == "completed" and backend.broker.verify_receipt(receipt)
    assert receipt.result["runtime"] == receipt.result["event_collection"] == "unknown"
    assert native.bits == 3 and authority.health().consumed_sequence == 1
    assert backend.execute(proposal, peer()) == receipt
    assert [row for row in native.calls if row[0] == "set"] == [("set", 3)]
    restoration = backend.prepare_restore(plan.plan_id)
    assert restoration.target_bits == 0 and restoration.expected_bits == 3
    recovery = approved(backend, restoration)
    assert backend.execute(recovery, peer()).outcome == "completed"
    assert native.bits == 0 and authority.health().consumed_sequence == 2
    with pytest.raises(PermissionError, match="unspent"):
        backend.prepare_restore(plan.plan_id)


def test_signed_native_peer_binding_and_two_independent_nonrequester_operators(system):
    backend, native, _authority = system
    proposal = backend.proposal(prepare_logon_plan(0, clock=lambda: 100), peer())
    with pytest.raises(PermissionError, match="native pipe user SID"):
        backend.approve(proposal, proof(proposal, 2), peer(3))
    with pytest.raises(PermissionError, match="own"):
        backend.approve(proposal, proof(proposal, 1), peer())
    backend.approve(proposal, proof(proposal, 2), peer(2))
    with pytest.raises(PermissionError, match="2 approval"):
        backend.execute(proposal, peer())
    with pytest.raises(PermissionError, match="requester"):
        backend.execute(proposal, peer(2))
    with pytest.raises(PermissionError, match="OS-authenticated"):
        backend.proposal(prepare_logon_plan(0, clock=lambda: 100), {"user_sid": peer().user_sid})
    assert not native.calls


def test_dry_run_preview_does_not_prevent_separately_approved_execution(system):
    backend, native, authority = system
    plan = prepare_logon_plan(0, clock=lambda: 100)
    preview = backend.execute(backend.proposal(plan, peer(), dry_run=True), peer())
    assert preview.outcome == "previewed" and not preview.executed
    assert not native.calls and authority.health().issued_sequence == 0
    assert backend.execute(approved(backend, plan), peer()).outcome == "completed"


@pytest.mark.parametrize("key,value", [
    ("plan_id", "F" * 32), ("subcategory", "0CCE9215-69AE-11D9-BED3-505054503030"),
    ("expected_bits", True), ("target_bits", 1), ("target_bits", False),
    ("expires_at", float("inf")), ("created_at", float("nan")),
    ("expires_at", 401), ("restore_of", "../state.json"),
])
def test_closed_plan_schema_rejects_wrong_types_scope_and_lifetime(key, value):
    arguments = asdict(prepare_logon_plan(0, clock=lambda: 100))
    arguments[key] = value
    with pytest.raises((ValueError, PermissionError)):
        validate_arguments(arguments)


def test_expired_future_and_extra_field_plans_are_rejected():
    arguments = asdict(prepare_logon_plan(0, clock=lambda: 100))
    for now in (99, 400, 401):
        with pytest.raises(PermissionError):
            validate_arguments(arguments, now=now)
    with pytest.raises(ValueError, match="Exact"):
        validate_arguments(dict(arguments, path="arbitrary"))


def test_recovery_cannot_relabel_approval_operation_or_change_original_bits(system):
    backend, _native, _authority = system
    plan = prepare_logon_plan(0, clock=lambda: 100)
    backend.execute(approved(backend, plan), peer())
    restoration = backend.prepare_restore(plan.plan_id)
    with pytest.raises(PermissionError, match="durable original"):
        backend.proposal(replace(restoration, target_bits=2), peer())
    proposal = backend.proposal(restoration, peer())
    wrong = replace(proposal, operation_id=PrivilegedOpcode.LOGON_AUDIT_CONFIGURE.value)
    with pytest.raises(PermissionError, match="purpose"):
        backend.approve(wrong, proof(wrong, 2), peer(2))


def test_policy_drift_burns_attempt_before_any_set_and_cannot_retry(system):
    backend, native, _authority = system
    plan = prepare_logon_plan(0, clock=lambda: 100)
    proposal = approved(backend, plan)
    native.bits = 2
    with pytest.raises(PermissionError, match="changed"):
        backend.execute(proposal, peer())
    native.bits = 0
    with pytest.raises(PermissionError, match="Prior response attempt"):
        backend.execute(proposal, peer())
    assert not [row for row in native.calls if row[0] == "set"]


def test_clock_rollback_within_plan_window_latches_backend_held(system):
    backend, native, _authority = system
    proposal = approved(backend, prepare_logon_plan(0, clock=lambda: 100))
    backend._clock = lambda: 100.5  # Still inside the plan lifetime, but behind observed 101.
    with pytest.raises(PermissionError, match="clock rollback"):
        backend.execute(proposal, peer())
    assert native.calls == [] and backend.status()["state"] == "held"


def test_inmemory_test_capability_authority_cannot_enable_backend(system):
    backend, native, _authority = system
    memory = ResponseCapabilityAuthority(b"x" * 32, test_only=True)
    try:
        backend._capabilities = memory
        assert backend.status()["state"] == "held"
        with pytest.raises(PermissionError, match="consumer unavailable"):
            backend.execute(approved(backend, prepare_logon_plan(0, clock=lambda: 100)), peer())
        assert native.calls == []
    finally:
        memory.close()


def test_failed_postcondition_never_becomes_completed(system):
    backend, native, _authority = system
    native.after_set = lambda: setattr(native, "bits", 1)
    receipt = backend.execute(approved(backend, prepare_logon_plan(0, clock=lambda: 100)), peer())
    assert receipt.outcome == "verification-failed" and receipt.executed
    assert native.bits == 1


def test_uninstalled_consumer_and_unauthenticated_executor_remain_inert(tmp_path):
    backend, native, authority = composition(tmp_path, consumer=False)
    try:
        assert backend.status()["state"] == "held"
        proposal = approved(backend, prepare_logon_plan(0, clock=lambda: 100))
        with pytest.raises(PermissionError, match="consumer unavailable"):
            backend.execute(proposal, peer())
        executor = NativeLogonAuditExecutor(native=native, clock=lambda: 101)
        with pytest.raises(PermissionError, match="protected prevention consumer"):
            executor.execute(PrivilegedOpcode.LOGON_AUDIT_CONFIGURE, RESOURCE, dict(proposal.arguments))
        assert native.calls == []
    finally:
        backend.broker.close()
        backend.journal.close()
        authority.close()


def test_cancel_before_execution_does_not_spend_authority_or_mutate(system):
    backend, native, authority = system
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(PermissionError, match="cancelled"):
        backend.execute(approved(backend, prepare_logon_plan(0, clock=lambda: 100)), peer(), cancel=cancel)
    assert native.calls == [] and authority.health().issued_sequence == 0


def test_cancel_after_durable_intent_before_capability_mint_is_safe(system, monkeypatch):
    backend, native, authority = system
    cancel = threading.Event()
    original = backend.journal.begin

    def begin(arguments):
        original(arguments)
        cancel.set()

    monkeypatch.setattr(backend.journal, "begin", begin)
    plan = prepare_logon_plan(0, clock=lambda: 100)
    with pytest.raises(PermissionError, match="cancelled"):
        backend.execute(approved(backend, plan), peer(), cancel=cancel)
    assert native.calls == [] and authority.health().issued_sequence == 0
    with pytest.raises(PermissionError, match="unspent"):
        backend.journal.original(plan.plan_id)


def test_cancelled_nondispatched_recovery_releases_original_for_new_approvals(system, monkeypatch):
    backend, native, authority = system
    original_plan = prepare_logon_plan(0, clock=lambda: 100)
    backend.execute(approved(backend, original_plan), peer())
    cancelled_plan = backend.prepare_restore(original_plan.plan_id)
    cancelled_proposal = approved(backend, cancelled_plan)
    cancel = threading.Event()
    original_begin = backend.journal.begin

    def begin(arguments):
        original_begin(arguments)
        if arguments["restore_of"]:
            cancel.set()

    monkeypatch.setattr(backend.journal, "begin", begin)
    with pytest.raises(PermissionError, match="cancelled"):
        backend.execute(cancelled_proposal, peer(), cancel=cancel)
    assert native.bits == 3 and authority.health().issued_sequence == 1
    with pytest.raises(PermissionError, match="Prior response attempt"):
        backend.execute(cancelled_proposal, peer())
    monkeypatch.setattr(backend.journal, "begin", original_begin)
    new_plan = backend.prepare_restore(original_plan.plan_id)
    assert new_plan.plan_id != cancelled_plan.plan_id
    with pytest.raises(PermissionError, match="2 approval"):
        backend.execute(backend.proposal(new_plan, peer()), peer())
    assert backend.execute(approved(backend, new_plan), peer()).outcome == "completed"
    assert native.bits == 0 and authority.health().consumed_sequence == 2


def test_dispatched_uncertain_recovery_stays_spent_even_if_cancelled(system):
    backend, native, _authority = system
    plan = prepare_logon_plan(0, clock=lambda: 100)
    backend.execute(approved(backend, plan), peer())
    restoration = backend.prepare_restore(plan.plan_id)
    cancel = threading.Event()

    def uncertain():
        cancel.set()
        raise OSError("inert result lost after native restore")

    native.after_set = uncertain
    with pytest.raises(Exception):
        backend.execute(approved(backend, restoration), peer(), cancel=cancel)
    assert native.bits == 0
    with pytest.raises(PermissionError, match="unspent"):
        backend.prepare_restore(plan.plan_id)
    with pytest.raises(PermissionError, match="pending intent"):
        backend.journal.finish(asdict(restoration), "cancelled")


def test_cancelled_child_and_original_release_are_durable_together(tmp_path):
    path = tmp_path / "protected" / "journal.json"
    original = prepare_logon_plan(0, clock=lambda: 100)
    recovery = LogonAuditPlan("f" * 32, LOGON_GUID, 3, 0, 101, 401, original.plan_id)
    journal = PreventionJournal(path, b"j" * 32)
    journal.begin(asdict(original))
    journal.finish(asdict(original), "configured")
    journal.begin(asdict(recovery))
    journal.finish(asdict(recovery), "cancelled")
    journal.close()
    restored = PreventionJournal(path, b"j" * 32)
    try:
        assert restored.original(original.plan_id)["expected_bits"] == 0
        with pytest.raises(PermissionError, match="replay"):
            restored.begin(asdict(recovery))
    finally:
        restored.close()


def test_journal_persistence_failure_blocks_native_write_and_latches_held(system, monkeypatch):
    backend, native, authority = system
    proposal = approved(backend, prepare_logon_plan(0, clock=lambda: 100))
    from angerona.core import atomic_io
    original = atomic_io.replace_with_retry

    def fail_intent(source, target, *args, **kwargs):
        if target == backend.journal.path:
            raise OSError("inert durable intent failure")
        return original(source, target, *args, **kwargs)

    monkeypatch.setattr(atomic_io, "replace_with_retry", fail_intent)
    with pytest.raises(OSError, match="intent failure"):
        backend.execute(proposal, peer())
    assert native.calls == [] and authority.health().issued_sequence == 0
    assert backend.status()["state"] == "held"


def test_cancel_during_uncertain_dispatched_write_retains_recovery(system):
    backend, native, _authority = system
    cancel = threading.Event()
    plan = prepare_logon_plan(0, clock=lambda: 100)

    def uncertain():
        cancel.set()
        raise OSError("inert transport result lost")

    native.after_set = uncertain
    with pytest.raises(Exception):
        backend.execute(approved(backend, plan), peer(), cancel=cancel)
    assert native.bits == 3
    assert backend.journal.original(plan.plan_id)["expected_bits"] == 0


def test_journal_restart_authentication_enrollment_and_prior_state(tmp_path):
    path = tmp_path / "protected" / "journal.json"
    plan = prepare_logon_plan(2, clock=lambda: 100)
    journal = PreventionJournal(path, b"j" * 32)
    journal.begin(asdict(plan))
    journal.close()
    restored = PreventionJournal(path, b"j" * 32)
    assert restored.original(plan.plan_id)["expected_bits"] == 2
    restored.close()
    document = json.loads(path.read_text())
    document["rows"][plan.plan_id]["arguments"]["expected_bits"] = 0
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="authentication"):
        PreventionJournal(path, b"j" * 32)
    path.unlink()
    with pytest.raises(ValueError, match="missing"):
        PreventionJournal(path, b"j" * 32)


def test_journal_refuses_hardlinked_state_and_unprotected_aliases(tmp_path):
    import os
    path = tmp_path / "protected" / "journal.json"
    journal = PreventionJournal(path, b"j" * 32)
    journal.close()
    os.link(path, tmp_path / "alias.json")
    with pytest.raises(Exception, match="Unsafe engine state"):
        PreventionJournal(path, b"j" * 32)
    with pytest.raises(ValueError, match="absolute local"):
        PreventionJournal(Path("relative-journal.json"), b"j" * 32)


def test_readonly_policy_inspection_distinguishes_configuration_from_telemetry():
    native = Native(3)
    observation = inspect_logon_policy(native=native, clock=lambda: 100)
    assert observation["state"] == "configured" and observation["event_collection"] == "unknown"
    assert native.calls == [("query", 3)]

    class Denied:
        def query_bits(self):
            raise PermissionError("private error should not be exported")

    observation = inspect_logon_policy(native=Denied(), clock=lambda: 100)
    assert observation["state"] == "denied" and observation["bits"] is None
    assert "private" not in str(observation)


def test_native_set_zero_means_explicit_none_not_unchanged(monkeypatch):
    # Exercise the actual ctypes adapter without touching Windows APIs.
    import ctypes
    from angerona.core.windows_prevention import _WindowsAuditApi

    class Policy(ctypes.Structure):
        _fields_ = [("subcategory", ctypes.c_uint), ("information", ctypes.c_uint)]

    calls = []

    class Dll:
        def AuditSetSystemPolicy(self, pointer, count):
            calls.append((ctypes.cast(pointer, ctypes.POINTER(Policy)).contents.information, count))
            return True

    api = _WindowsAuditApi.__new__(_WindowsAuditApi)
    api._policy, api._guid, api._dll = Policy, 123, Dll()
    api.set_bits(0)
    api.set_bits(3)
    assert calls == [(4, 1), (3, 1)]
