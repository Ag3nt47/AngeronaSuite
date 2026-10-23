import base64
import hashlib
import os
from dataclasses import replace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from angerona.core.approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof
import pytest
import threading

from angerona.core.engine_transport import create_private_file, verify_private
from angerona.core.response_broker import (
    ResponseBroker, ResponseOperation, ResponseProposal,
)
from angerona.core.safe_response_session import (
    ReadOnlyQuery, ResponseSessionSpec, SafeResponseSessionManager,
)


def _private(alias):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("inert-test:" + alias).encode()).digest())


def _proof(broker, digest, alias):
    record = broker._identity_verifier.credentials[alias]
    unsigned = SignedPrincipalProof.unsigned(record, digest, 100, 1000, "1" * 32)
    return replace(unsigned, signature=base64.urlsafe_b64encode(_private(alias).sign(unsigned.signing_bytes())).decode().rstrip("="))


def _query(calls):
    def validate(parameters):
        if set(parameters) != {"limit"} or not 1 <= parameters["limit"] <= 10:
            raise ValueError("limit required")

    return ReadOnlyQuery(
        "process.snapshot", "Read bounded process identities", validate,
        lambda target, parameters: calls.append((target, parameters))
        or {"count": 1, "items": [{"process_token": "tok_1"}]},
    )


def _broker(tmp_path, calls):
    records = []
    for alias in ("analyst-001", "analyst-002", "analyst-003"):
        public = _private(alias).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        records.append(PrincipalCredential(alias, "fixture-issuer", alias, public))
    broker = ResponseBroker(b"k" * 32, clock=lambda: 110,
        identity_verifier=ApprovalIdentityVerifier(records, clock=lambda: 110),
        state_path=tmp_path / "broker" / "state.json")

    def validate(arguments):
        if set(arguments) != {"reason"}:
            raise ValueError("reason required")

    broker.register(ResponseOperation(
        "endpoint.isolate", "high", "Isolate endpoint",
        "Restore prior network policy", validate,
        lambda arguments: calls.append(arguments) or {"isolated": True},
        verify_outcome=lambda arguments, result: arguments in calls and result.get("isolated") is True,
    ))
    return broker


def _spec(*, response=(), expires=200):
    return ResponseSessionSpec(
        "session-001", "device-001", "analyst-001",
        ("process.snapshot",), response, 100, expires,
    )


def test_read_only_session_is_approved_expiring_idempotent_and_persistent(tmp_path):
    calls = []
    broker = _broker(tmp_path, [])
    path = tmp_path / "sessions" / "sessions.json"
    manager = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query(calls),), clock=lambda: 110,
    )
    spec = _spec()
    manager.create(spec)
    verify_private(path)
    with pytest.raises(PermissionError, match="1 approval"):
        manager.open(spec.session_id)
    manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-002"))
    manager.open(spec.session_id)
    result, event = manager.query(
        spec.session_id, "request-001", "process.snapshot", {"limit": 5},
    )
    assert result["count"] == 1 and not event.host_changed
    replay, same = manager.query(
        spec.session_id, "request-001", "process.snapshot", {"limit": 5},
    )
    assert replay["replayed"] and same == event and len(calls) == 1
    receipt = manager.close_session(spec.session_id)
    verify_private(path)
    assert manager.verify_receipt(receipt)
    assert manager.transcript(spec.session_id) == (event,)

    manager.close()
    restored = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
    )
    assert restored.transcript_receipt(spec.session_id).chain_head == receipt.chain_head


def test_change_session_needs_session_and_operation_approvals(tmp_path):
    query_calls, response_calls = [], []
    broker = _broker(tmp_path, response_calls)
    manager = SafeResponseSessionManager(
        tmp_path / "sessions" / "sessions.json", b"s" * 32, broker,
        (_query(query_calls),), clock=lambda: 110,
    )
    spec = _spec(response=("endpoint.isolate",))
    manager.create(spec)
    manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-002"))
    with pytest.raises(PermissionError, match="2 approval"):
        manager.open(spec.session_id)
    manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-003"))
    manager.open(spec.session_id)
    proposal = ResponseProposal(
        "proposal-001", "endpoint.isolate", {"reason": "confirmed"},
        "device-001", "analyst-001", 100, 200, False,
    )
    broker.approve(proposal, _proof(broker, proposal.digest, "analyst-002"))
    broker.approve(proposal, _proof(broker, proposal.digest, "analyst-003"))
    receipt, event = manager.execute_response(spec.session_id, proposal)
    assert receipt.executed and event.host_changed
    assert response_calls == [{"reason": "confirmed"}]


def test_session_rejects_shell_fields_scope_escape_expiry_and_tampering(tmp_path):
    calls = []
    broker = _broker(tmp_path, [])
    path = tmp_path / "sessions" / "sessions.json"
    manager = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query(calls),), clock=lambda: 110,
    )
    with pytest.raises(ValueError, match="executable"):
        ResponseSessionSpec(
            "session-001", "device-001", "analyst-001",
            ("shell.exec",), (), 100, 200,
        )
    spec = _spec()
    manager.create(spec)
    manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-002"))
    manager.open(spec.session_id)
    with pytest.raises(ValueError, match="executable"):
        manager.query(
            spec.session_id, "request-001", "process.snapshot",
            {"command": "whoami"},
        )
    with pytest.raises(PermissionError, match="outside"):
        manager.query(
            spec.session_id, "request-002", "network.connections", {},
        )
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace('"active"', '"closed"'), encoding="utf-8")
    manager.close()
    with pytest.raises(ValueError, match="authentication"):
        SafeResponseSessionManager(
            path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
        )

    expiring_path = tmp_path / "expiring" / "sessions.json"
    expired = SafeResponseSessionManager(
        expiring_path, b"s" * 32, broker, (_query([]),), clock=lambda: 201,
    )
    expired.create(_spec(expires=200))
    with pytest.raises(PermissionError, match="approvable"):
        expired.approve("session-001", _proof(broker, _spec(expires=200).digest, "analyst-002"))


def test_slow_query_does_not_hold_session_lock_and_closed_result_is_discarded(tmp_path):
    started = threading.Event()
    release = threading.Event()
    outcomes = []

    def handler(_target, _parameters):
        started.set()
        assert release.wait(10)
        return {"items": []}

    query = ReadOnlyQuery(
        "process.snapshot", "Bounded process query",
        lambda _parameters: None, handler,
    )
    broker = _broker(tmp_path, [])
    manager = SafeResponseSessionManager(
        tmp_path / "sessions" / "sessions.json", b"s" * 32, broker, (query,),
        clock=lambda: 110,
    )
    manager.create(_spec())
    manager.approve("session-001", _proof(broker, _spec().digest, "analyst-002"))
    manager.open("session-001")

    def run_query():
        try:
            manager.query(
                "session-001", "request-001", "process.snapshot", {},
            )
        except Exception as exc:
            outcomes.append(exc)

    thread = threading.Thread(target=run_query)
    thread.start()
    try:
        assert started.wait(5)
        receipt = manager.close_session("session-001")
        assert receipt.state == "closed"
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert len(outcomes) == 1
    assert isinstance(outcomes[0], PermissionError)
    assert manager.transcript("session-001")[0].outcome == "discarded-closed"


def test_active_session_rechecks_credential_revocation_before_query(tmp_path):
    calls = []
    broker = _broker(tmp_path, [])
    manager = SafeResponseSessionManager(tmp_path / "sessions" / "state.json", b"s" * 32,
                                        broker, (_query(calls),), clock=lambda: 110)
    spec = _spec()
    manager.create(spec)
    manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-002"))
    manager.open(spec.session_id)
    broker.revoke_credential("analyst-002")
    with pytest.raises(PermissionError, match="approvals"):
        manager.query(spec.session_id, "request-001", "process.snapshot", {"limit": 1})
    assert calls == []
    manager.revoke_approvals(spec.session_id)
    manager.close()
    restored = SafeResponseSessionManager(tmp_path / "sessions" / "state.json", b"s" * 32,
                                         broker, (_query(calls),), clock=lambda: 110)
    with pytest.raises(PermissionError, match="not active"):
        restored.query(spec.session_id, "request-002", "process.snapshot", {"limit": 1})
    restored.close()
    broker.close()


def test_legacy_saved_label_approvals_remain_history_without_execution_authority(tmp_path):
    import json
    import hmac
    from dataclasses import asdict
    from angerona.core.safe_response_session import _canonical
    from angerona.core.engine_transport import private_directory
    calls = []
    broker = _broker(tmp_path, [])
    path = private_directory(tmp_path / "sessions") / "legacy.json"
    spec = _spec()
    records = {spec.session_id: dict(spec=asdict(spec), state="active",
                approvals=["analyst-002", "analyst-003"], transcript=[])}
    encoded = json.dumps(dict(schema_version=1, records=records,
        hmac=hmac.new(b"s" * 32, _canonical(records), hashlib.sha256).hexdigest())).encode("utf-8")
    with os.fdopen(create_private_file(path), "wb") as stream:
        stream.write(encoded)
    verify_private(path)
    manager = SafeResponseSessionManager(path, b"s" * 32, broker, (_query(calls),), clock=lambda: 110)
    assert manager._records[spec.session_id]["legacy_approval_labels"] == ["analyst-002", "analyst-003"]
    with pytest.raises(PermissionError, match="authenticated approvals"):
        manager.query(spec.session_id, "request-001", "process.snapshot", {"limit": 1})
    assert calls == []
    manager.close()
    broker.close()


def test_revoked_credential_discards_inflight_query_result(tmp_path):
    entered, release = threading.Event(), threading.Event()
    broker = _broker(tmp_path, [])
    def handler(_target, _parameters):
        entered.set()
        if not release.wait(10):
            raise TimeoutError("inert test barrier")
        return {"private_result": "must not be released"}
    query = ReadOnlyQuery("process.snapshot", "Read bounded process metadata", lambda _args: None, handler)
    manager = SafeResponseSessionManager(tmp_path / "sessions" / "state.json", b"s" * 32,
                                         broker, (query,), clock=lambda: 110)
    spec = _spec()
    manager.create(spec)
    manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-002"))
    manager.open(spec.session_id)
    outcomes = []
    def run_query():
        try:
            outcomes.append(manager.query(spec.session_id, "request-001", "process.snapshot", {}))
        except BaseException as error:
            outcomes.append(error)
    worker = threading.Thread(target=run_query)
    worker.start()
    try:
        assert entered.wait(5)
        broker.revoke_credential("analyst-002")
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], PermissionError)
    assert manager.transcript(spec.session_id)[0].outcome == "discarded-approval-revoked"
    manager.close()
    broker.close()


def test_session_exclusive_temp_collision_preserves_existing_file(tmp_path, monkeypatch):
    import angerona.core.safe_response_session as session_module

    broker = _broker(tmp_path, [])
    path = tmp_path / "sessions" / "sessions.json"
    manager = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
    )
    monkeypatch.setattr(session_module.secrets, "token_hex", lambda _size: "c" * 16)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}." + "c" * 16 + ".tmp")
    with os.fdopen(create_private_file(temporary), "wb") as stream:
        stream.write(b"pre-existing temporary bytes")
    try:
        with pytest.raises(FileExistsError):
            manager.create(_spec())
        assert temporary.read_bytes() == b"pre-existing temporary bytes"
        verify_private(temporary)
        assert not path.exists()
        with pytest.raises(PermissionError, match="degraded"):
            manager.open("session-001")
    finally:
        manager.close()
        broker.close()


def test_session_save_rejects_existing_destination_outside_private_boundary(tmp_path, monkeypatch):
    import angerona.core.engine_transport as transport

    broker = _broker(tmp_path, [])
    path = tmp_path / "sessions" / "sessions.json"
    manager = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
    )
    spec = _spec()
    manager.create(spec)
    original = path.read_bytes()
    entries = {candidate.name for candidate in path.parent.iterdir()}
    verify = transport.verify_private

    def reject_destination(candidate, *, directory=False):
        if candidate == path and not directory:
            raise transport.EngineError("Inert foreign destination owner")
        verify(candidate, directory=directory)

    monkeypatch.setattr(transport, "verify_private", reject_destination)
    try:
        with pytest.raises(transport.EngineError, match="foreign destination owner"):
            manager.approve(spec.session_id, _proof(broker, spec.digest, "analyst-002"))
        assert path.read_bytes() == original
        assert {candidate.name for candidate in path.parent.iterdir()} == entries
        with pytest.raises(PermissionError, match="degraded"):
            manager.open(spec.session_id)
    finally:
        manager.close()
        broker.close()


def test_session_fdopen_failure_closes_descriptor_and_removes_owned_temp(tmp_path, monkeypatch):
    import angerona.core.engine_transport as transport
    import angerona.core.safe_response_session as session_module

    broker = _broker(tmp_path, [])
    path = tmp_path / "sessions" / "sessions.json"
    manager = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
    )
    create = transport.create_private_file
    allocated = []

    def capture_create(candidate):
        descriptor = create(candidate)
        allocated.append((candidate, descriptor))
        return descriptor

    def reject_fdopen(_descriptor, _mode):
        raise OSError("Inert fdopen failure before descriptor handoff")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(transport, "create_private_file", capture_create)
            patch.setattr(session_module.os, "fdopen", reject_fdopen)
            with pytest.raises(OSError, match="before descriptor handoff"):
                manager.create(_spec())
        assert len(allocated) == 1
        temporary, descriptor = allocated[0]
        assert not temporary.exists() and not path.exists()
        with pytest.raises(OSError):
            os.fstat(descriptor)
        with pytest.raises(PermissionError, match="degraded"):
            manager.open("session-001")
    finally:
        manager.close()
        broker.close()
