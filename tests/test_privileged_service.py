from __future__ import annotations

import copy

import pytest

from angerona.core.privileged_service import (
    PrivilegedService,
    PrivilegedServiceClient,
    PrivilegedServiceError,
    build_privileged_request,
)
from angerona.core.response_capability import (
    PrivilegedOpcode,
    ResponseCapabilityAuthority,
)


KEY = b"t" * 32
AUTHORITY = b"c" * 32
REQUEST_ID = "1" * 32
PARAMETERS = {"channel": "Security", "max_records": 100}


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, opcode, resource, parameters):
        self.calls.append((opcode, resource, parameters))
        return {"records_exported": 42, "status": "complete"}


class InMemoryTransport:
    def __init__(self, service: PrivilegedService) -> None:
        self.service = service

    def exchange(self, envelope):
        return self.service.handle(envelope)


class FailingExecutor:
    def execute(self, opcode, resource, parameters):
        raise OSError("simulated boundary failure")


def _configured(executor=None):
    authority = ResponseCapabilityAuthority(AUTHORITY, test_only=True)
    selected = executor or RecordingExecutor()
    service = PrivilegedService(authority, transport_key=KEY, executor=selected)
    client = PrivilegedServiceClient(
        transport_key=KEY,
        transport=InMemoryTransport(service),
    )
    capability = authority.issue(
        PrivilegedOpcode.EVENT_LOG_EXPORT,
        "event-log/Security",
        PARAMETERS,
    )
    return authority, selected, service, client, capability


def test_service_and_client_are_inert_until_dependencies_are_injected() -> None:
    service = PrivilegedService()
    client = PrivilegedServiceClient()

    assert service.health().state == "unconfigured"
    assert client.health().state == "unconfigured"
    with pytest.raises(PrivilegedServiceError) as caught:
        service.handle({})
    assert caught.value.code == "unconfigured"
    with pytest.raises(PrivilegedServiceError) as caught:
        client.execute(
            request_id=REQUEST_ID,
            capability={},
            opcode=PrivilegedOpcode.EVENT_LOG_EXPORT,
            resource="event-log/Security",
            parameters=PARAMETERS,
        )
    assert caught.value.code == "unconfigured"
    partial = PrivilegedService(transport_key=KEY)
    assert partial.health().state == "degraded"


def test_authenticated_request_executes_closed_opcode_once_and_binds_response() -> None:
    _authority, executor, service, client, capability = _configured()

    result = client.execute(
        request_id=REQUEST_ID,
        capability=capability,
        opcode=PrivilegedOpcode.EVENT_LOG_EXPORT,
        resource="event-log/Security",
        parameters=PARAMETERS,
    )

    assert result.request_id == REQUEST_ID
    assert result.opcode is PrivilegedOpcode.EVENT_LOG_EXPORT
    assert result.result == {"records_exported": 42, "status": "complete"}
    assert executor.calls == [
        (PrivilegedOpcode.EVENT_LOG_EXPORT, "event-log/Security", PARAMETERS)
    ]
    assert service.health().state == "ready"

    with pytest.raises(PrivilegedServiceError) as caught:
        client.execute(
            request_id="2" * 32,
            capability=capability,
            opcode=PrivilegedOpcode.EVENT_LOG_EXPORT,
            resource="event-log/Security",
            parameters=PARAMETERS,
        )
    assert caught.value.code == "capability-replay"
    assert len(executor.calls) == 1


def test_request_hmac_tamper_and_unknown_opcode_never_reach_executor() -> None:
    _authority, executor, service, _client, capability = _configured()
    request = build_privileged_request(
        KEY,
        request_id=REQUEST_ID,
        capability=capability,
        opcode=PrivilegedOpcode.EVENT_LOG_EXPORT,
        resource="event-log/Security",
        parameters=PARAMETERS,
    )
    tampered = copy.deepcopy(request)
    tampered["payload"]["parameters"]["max_records"] = 1000

    with pytest.raises(PrivilegedServiceError) as caught:
        service.handle(tampered)
    assert caught.value.code == "authentication"
    assert executor.calls == []

    unknown = copy.deepcopy(request)
    unknown["payload"]["opcode"] = "shell.execute"
    # Re-signing is unavailable to an untrusted transport; even a key-owning
    # local client cannot use build_privileged_request with a generic opcode.
    with pytest.raises(PrivilegedServiceError) as caught:
        build_privileged_request(
            KEY,
            request_id=REQUEST_ID,
            capability=capability,
            opcode="shell.execute",  # type: ignore[arg-type]
            resource="host/local",
            parameters={},
        )
    assert caught.value.code == "opcode"
    with pytest.raises(PrivilegedServiceError) as caught:
        service.handle(unknown)
    assert caught.value.code == "authentication"
    assert executor.calls == []


def test_executor_failure_burns_capability_and_degrades_service() -> None:
    _authority, _executor, service, client, capability = _configured(FailingExecutor())

    with pytest.raises(PrivilegedServiceError) as caught:
        client.execute(
            request_id=REQUEST_ID,
            capability=capability,
            opcode=PrivilegedOpcode.EVENT_LOG_EXPORT,
            resource="event-log/Security",
            parameters=PARAMETERS,
        )
    assert caught.value.code == "execution"
    assert service.health().state == "degraded"
    assert client.health().state == "degraded"


def test_capability_scope_is_checked_after_transport_authentication() -> None:
    authority, executor, service, _client, _capability = _configured()
    wrong_scope = authority.issue(
        PrivilegedOpcode.EVENT_LOG_EXPORT,
        "event-log/System",
        PARAMETERS,
    )
    request = build_privileged_request(
        KEY,
        request_id=REQUEST_ID,
        capability=wrong_scope,
        opcode=PrivilegedOpcode.EVENT_LOG_EXPORT,
        resource="event-log/Security",
        parameters=PARAMETERS,
    )

    with pytest.raises(PrivilegedServiceError) as caught:
        service.handle(request)
    assert caught.value.code == "capability-scope"
    assert executor.calls == []
