import pytest
import threading

from angerona.core.response_broker import (
    ResponseBroker, ResponseOperation, ResponseProposal,
)
from angerona.core.safe_response_session import (
    ReadOnlyQuery, ResponseSessionSpec, SafeResponseSessionManager,
)


def _query(calls):
    def validate(parameters):
        if set(parameters) != {"limit"} or not 1 <= parameters["limit"] <= 10:
            raise ValueError("limit required")

    return ReadOnlyQuery(
        "process.snapshot", "Read bounded process identities", validate,
        lambda target, parameters: calls.append((target, parameters))
        or {"count": 1, "items": [{"process_token": "tok_1"}]},
    )


def _broker(calls):
    broker = ResponseBroker(b"k" * 32, clock=lambda: 110)

    def validate(arguments):
        if set(arguments) != {"reason"}:
            raise ValueError("reason required")

    broker.register(ResponseOperation(
        "endpoint.isolate", "high", "Isolate endpoint",
        "Restore prior network policy", validate,
        lambda arguments: calls.append(arguments) or {"isolated": True},
    ))
    return broker


def _spec(*, response=(), expires=200):
    return ResponseSessionSpec(
        "session-001", "device-001", "analyst-001",
        ("process.snapshot",), response, 100, expires,
    )


def test_read_only_session_is_approved_expiring_idempotent_and_persistent(tmp_path):
    calls = []
    broker = _broker([])
    path = tmp_path / "sessions.json"
    manager = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query(calls),), clock=lambda: 110,
    )
    spec = _spec()
    manager.create(spec)
    with pytest.raises(PermissionError, match="1 approval"):
        manager.open(spec.session_id)
    manager.approve(spec.session_id, "analyst-002")
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
    assert manager.verify_receipt(receipt)
    assert manager.transcript(spec.session_id) == (event,)

    restored = SafeResponseSessionManager(
        path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
    )
    assert restored.transcript_receipt(spec.session_id).chain_head == receipt.chain_head


def test_change_session_needs_session_and_operation_approvals(tmp_path):
    query_calls, response_calls = [], []
    broker = _broker(response_calls)
    manager = SafeResponseSessionManager(
        tmp_path / "sessions.json", b"s" * 32, broker,
        (_query(query_calls),), clock=lambda: 110,
    )
    spec = _spec(response=("endpoint.isolate",))
    manager.create(spec)
    manager.approve(spec.session_id, "analyst-002")
    with pytest.raises(PermissionError, match="2 approval"):
        manager.open(spec.session_id)
    manager.approve(spec.session_id, "analyst-003")
    manager.open(spec.session_id)
    proposal = ResponseProposal(
        "proposal-001", "endpoint.isolate", {"reason": "confirmed"},
        "device-001", "analyst-001", 100, 200, False,
    )
    broker.approve(proposal, "analyst-002")
    broker.approve(proposal, "analyst-003")
    receipt, event = manager.execute_response(spec.session_id, proposal)
    assert receipt.executed and event.host_changed
    assert response_calls == [{"reason": "confirmed"}]


def test_session_rejects_shell_fields_scope_escape_expiry_and_tampering(tmp_path):
    calls = []
    broker = _broker([])
    path = tmp_path / "sessions.json"
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
    manager.approve(spec.session_id, "analyst-002")
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
    with pytest.raises(ValueError, match="authentication"):
        SafeResponseSessionManager(
            path, b"s" * 32, broker, (_query([]),), clock=lambda: 110,
        )

    expiring_path = tmp_path / "expiring.json"
    expired = SafeResponseSessionManager(
        expiring_path, b"s" * 32, broker, (_query([]),), clock=lambda: 201,
    )
    expired.create(_spec(expires=200))
    with pytest.raises(PermissionError, match="approvable"):
        expired.approve("session-001", "analyst-002")


def test_slow_query_does_not_hold_session_lock_and_closed_result_is_discarded(tmp_path):
    started = threading.Event()
    release = threading.Event()
    outcomes = []

    def handler(_target, _parameters):
        started.set()
        assert release.wait(2)
        return {"items": []}

    query = ReadOnlyQuery(
        "process.snapshot", "Bounded process query",
        lambda _parameters: None, handler,
    )
    broker = _broker([])
    manager = SafeResponseSessionManager(
        tmp_path / "sessions.json", b"s" * 32, broker, (query,),
        clock=lambda: 110,
    )
    manager.create(_spec())
    manager.approve("session-001", "analyst-002")
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
    assert started.wait(1)
    receipt = manager.close_session("session-001")
    assert receipt.state == "closed"
    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert len(outcomes) == 1
    assert isinstance(outcomes[0], PermissionError)
    assert manager.transcript("session-001")[0].outcome == "discarded-closed"
