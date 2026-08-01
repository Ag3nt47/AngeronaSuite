from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.error
import urllib.request

import pytest

from angerona.core import fleet_service
from angerona.core.fleet_control_plane import FleetControlPlane, FleetDevice
from angerona.core.fleet_credentials import (
    FleetCredential,
    FleetCredentialKind,
    FleetCredentialRegistry,
)
from angerona.core.fleet_service import (
    FLEET_DEVICE_PERMISSIONS,
    FLEET_TENANT_PERMISSIONS,
    FleetLoopbackService,
    sign_request,
)


def _device(device_id: str, *, tenant: str = "tenant-a") -> FleetDevice:
    return FleetDevice(
        tenant,
        device_id,
        f"key-{device_id}",
        f"tok_{device_id}",
        "windows",
        "1.9.4",
    )


def _credential(
    kind: FleetCredentialKind, *, device_id: str = ""
) -> FleetCredential:
    if kind is FleetCredentialKind.DEVICE:
        return FleetCredential(
            "device-credential-a",
            "tenant-a",
            kind,
            b"d" * 32,
            FLEET_DEVICE_PERMISSIONS,
            device_id=device_id or "device-a",
        )
    return FleetCredential(
        "tenant-credential-a",
        "tenant-a",
        kind,
        b"t" * 32,
        FLEET_TENANT_PERMISSIONS,
    )


def _request(
    base: str,
    credential: FleetCredential,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    timestamp: float | None = None,
    nonce: str | None = None,
):
    headers = sign_request(
        credential.secret,
        method,
        path,
        body,
        timestamp=timestamp,
        nonce=nonce,
        credential_id=credential.credential_id,
    )
    headers["Content-Type"] = "application/json"
    return urllib.request.urlopen(
        urllib.request.Request(
            base + path,
            data=body if method == "POST" else None,
            headers=headers,
            method=method,
        ),
        timeout=3,
    )


def _raw_response(
    port: int, request: bytes, *, shutdown_write: bool = False
) -> tuple[int, bytes]:
    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        connection.sendall(request)
        if shutdown_write:
            connection.shutdown(socket.SHUT_WR)
        response = http.client.HTTPResponse(connection)
        response.begin()
        return response.status, response.read()
    finally:
        connection.close()


@pytest.mark.parametrize(
    "body",
    [
        b'{"device_id":"device-a","event_id":"event-a",'
        b'"body":{"value":1,"value":2}}',
        b'{"device_id":"device-a","event_id":"event-a",'
        b'"body":{"value":NaN}}',
        b'{"device_id":"device-a","event_id":"event-a",'
        b'"body":{"value":1e9999}}',
    ],
)
def test_http_ingestion_rejects_ambiguous_or_nonfinite_json(tmp_path, body):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    plane.register_device(_device("device-a"))
    credential = _credential(FleetCredentialKind.DEVICE)
    service = FleetLoopbackService(
        plane,
        FleetCredentialRegistry((credential,)),
        tmp_path / "replay",
        port=0,
    )
    base = f"http://127.0.0.1:{service.start()}"
    try:
        with pytest.raises(urllib.error.HTTPError) as rejected:
            _request(
                base,
                credential,
                "POST",
                "/v1/tenants/tenant-a/events",
                body,
            )
        assert rejected.value.code == 400
        assert plane.events("tenant-a") == ()
    finally:
        assert service.stop()
        plane.close()


def test_incomplete_and_slow_request_bodies_are_bounded(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane,
        b"s" * 32,
        tmp_path / "replay",
        port=0,
        client_timeout_seconds=0.1,
    )
    port = service.start()
    headers = (
        b"POST /v1/tenants/tenant-a/devices HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
        b"Content-Length: 20\r\nConnection: close\r\n\r\n{}"
    )
    try:
        incomplete_status, _ = _raw_response(
            port, headers, shutdown_write=True
        )
        assert incomplete_status == 400
        slow_status, slow_body = _raw_response(port, headers)
        assert slow_status == 408
        assert b"timed out" in slow_body
    finally:
        assert service.stop()
        plane.close()


@pytest.mark.parametrize(
    "framing",
    [
        b"Content-Length: 2\r\nContent-Length: 2\r\n",
        b"Transfer-Encoding: chunked\r\n",
    ],
)
def test_ambiguous_post_framing_is_rejected_and_connection_closed(
    tmp_path, framing
):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane, b"s" * 32, tmp_path / "replay", port=0,
    )
    port = service.start()
    request = (
        b"POST /v1/tenants/tenant-a/devices HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
        + framing
        + b"Connection: keep-alive\r\n\r\n{}"
    )
    try:
        status, _body = _raw_response(port, request)
        assert status == 400
    finally:
        assert service.stop()
        plane.close()


def test_get_body_framing_is_rejected_before_health_route(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane, b"s" * 32, tmp_path / "replay", port=0,
    )
    port = service.start()
    try:
        status, body = _raw_response(
            port,
            b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Length: 2\r\nConnection: keep-alive\r\n\r\n{}",
        )
        assert status == 400
        assert b"cannot contain a body" in body
    finally:
        assert service.stop()
        plane.close()


def test_handler_limit_rejects_then_recovers_after_clients_leave(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(fleet_service, "MAX_HANDLER_THREADS", 2)
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane,
        b"s" * 32,
        tmp_path / "replay",
        port=0,
        client_timeout_seconds=1,
    )
    port = service.start()
    blockers: list[socket.socket] = []
    try:
        for _ in range(2):
            connection = socket.create_connection(("127.0.0.1", port), timeout=2)
            connection.sendall(
                b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            )
            blockers.append(connection)
        deadline = time.monotonic() + 2
        while service._server._active_handlers != 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert service._server._active_handlers == 2

        with pytest.raises(urllib.error.HTTPError) as saturated:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=2
            )
        assert saturated.value.code == 503

        for connection in blockers:
            connection.close()
        blockers.clear()
        deadline = time.monotonic() + 2
        while service._server._active_handlers and time.monotonic() < deadline:
            time.sleep(0.01)
        assert service._server._active_handlers == 0
        assert json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health", timeout=2
        ))["ok"]
    finally:
        for connection in blockers:
            connection.close()
        assert service.stop()
        plane.close()


def test_nonce_replay_survives_service_restart_and_handles_are_closed(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    credential = _credential(FleetCredentialKind.TENANT)
    registry = FleetCredentialRegistry((credential,))
    replay_path = tmp_path / "replay"
    path = "/v1/tenants/tenant-a/devices"
    nonce = "persistent-nonce-token-1234567890"
    timestamp = 1000

    first = FleetLoopbackService(plane, registry, replay_path, port=0)
    first.auth._clock = lambda: timestamp
    first_base = f"http://127.0.0.1:{first.start()}"
    assert json.load(_request(
        first_base,
        credential,
        "GET",
        path,
        timestamp=timestamp,
        nonce=nonce,
    ))["ok"]
    assert first.stop()
    assert first.auth._replay._db is None

    second = FleetLoopbackService(plane, registry, replay_path, port=0)
    second.auth._clock = lambda: timestamp
    second_base = f"http://127.0.0.1:{second.start()}"
    try:
        with pytest.raises(urllib.error.HTTPError) as replayed:
            _request(
                second_base,
                credential,
                "GET",
                path,
                timestamp=timestamp,
                nonce=nonce,
            )
        assert replayed.value.code == 401
        assert json.load(_request(
            second_base,
            credential,
            "GET",
            path,
            timestamp=timestamp,
            nonce="fresh-nonce-token-1234567890123",
        ))["ok"]
    finally:
        assert second.stop()
        assert second.auth._replay._db is None
        plane.close()


def test_device_batch_cannot_mix_device_identities(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    plane.register_device(_device("device-a"))
    plane.register_device(_device("device-b"))
    credential = _credential(FleetCredentialKind.DEVICE)
    service = FleetLoopbackService(
        plane,
        FleetCredentialRegistry((credential,)),
        tmp_path / "replay",
        port=0,
    )
    base = f"http://127.0.0.1:{service.start()}"
    body = json.dumps({"events": [
        {"device_id": "device-a", "event_id": "event-a", "body": {}},
        {"device_id": "device-b", "event_id": "event-b", "body": {}},
    ]}).encode("utf-8")
    try:
        with pytest.raises(urllib.error.HTTPError) as rejected:
            _request(
                base,
                credential,
                "POST",
                "/v1/tenants/tenant-a/event-batches",
                body,
            )
        assert rejected.value.code == 403
        assert plane.events("tenant-a") == ()
    finally:
        assert service.stop()
        plane.close()


def test_event_http_response_honors_exact_byte_and_item_budgets(
    tmp_path, monkeypatch
):
    response_budget = 2500
    monkeypatch.setattr(
        fleet_service, "MAX_QUERY_RESPONSE_BYTES", response_budget
    )
    now = [1000.0]
    plane = FleetControlPlane(
        tmp_path / "fleet.db",
        {"tenant-a": b"a" * 32},
        clock=lambda: now[0],
    )
    plane.register_device(_device("device-a"))
    for index in range(20):
        now[0] += 1
        plane.ingest(
            "tenant-a",
            "device-a",
            f"event-{index:03d}",
            {"payload": "x" * 400},
        )
    credential = _credential(FleetCredentialKind.TENANT)
    service = FleetLoopbackService(
        plane,
        FleetCredentialRegistry((credential,)),
        tmp_path / "replay",
        port=0,
    )
    base = f"http://127.0.0.1:{service.start()}"
    path = "/v1/tenants/tenant-a/events?limit=99999"
    try:
        with _request(base, credential, "GET", path) as response:
            wire_body = response.read()
            assert int(response.headers["Content-Length"]) == len(wire_body)
        assert len(wire_body) <= response_budget
        payload = json.loads(wire_body)
        assert 0 < len(payload["items"]) <= 500
        assert len(payload["items"]) < 20
        assert payload["truncated"]
        assert payload["next_cursor"]
    finally:
        assert service.stop()
        plane.close()


def test_supervised_stop_interrupts_stalled_handler_and_closes_replay(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane,
        b"s" * 32,
        tmp_path / "replay",
        port=0,
        client_timeout_seconds=30,
    )
    port = service.start()
    blocker = socket.create_connection(("127.0.0.1", port), timeout=2)
    blocker.sendall(
        b"POST /v1/tenants/tenant-a/devices HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nContent-Length: 100\r\n\r\n{}"
    )
    deadline = time.monotonic() + 2
    while service._server._active_handlers != 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert service._server._active_handlers == 1
    started = time.monotonic()
    try:
        assert service.stop(timeout=0.2)
        assert time.monotonic() - started < 1.5
        assert service.auth._replay._db is None
    finally:
        blocker.close()
        service.stop()
        plane.close()
