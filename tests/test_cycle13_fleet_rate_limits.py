from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from angerona.core.fleet_control_plane import (
    FleetControlPlane,
    FleetDevice,
    FleetIngestionRateLimiter,
    FleetRateLimitError,
)
from angerona.core.fleet_service import FleetLoopbackService, openapi_contract, sign_request


def _device(device_id: str) -> FleetDevice:
    return FleetDevice(
        "tenant-a", device_id, f"key-{device_id}", f"tok_{device_id}",
        "windows", "1.9.4", last_seen=1,
    )


def _plane(tmp_path, limiter: FleetIngestionRateLimiter) -> FleetControlPlane:
    plane = FleetControlPlane(
        tmp_path / "fleet.db",
        {"tenant-a": b"a" * 32},
        clock=lambda: 1000,
        rate_limiter=limiter,
    )
    plane.register_device(_device("device-a"))
    return plane


def test_device_rate_limit_rejects_before_write_and_refills(tmp_path):
    now = [0.0]
    limiter = FleetIngestionRateLimiter(
        tenant_rate=10, tenant_burst=10,
        device_rate=1, device_burst=1,
        clock=lambda: now[0],
    )
    plane = _plane(tmp_path, limiter)
    plane.ingest("tenant-a", "device-a", "event-one", {"sequence": 1})

    with pytest.raises(FleetRateLimitError) as limited:
        plane.ingest("tenant-a", "device-a", "event-two", {"sequence": 2})
    assert limited.value.retry_after_ms == 1000
    assert {event["event_id"] for event in plane.events("tenant-a")} == {
        "event-one"
    }
    health = plane.ingestion_health("tenant-a")
    assert health["stored_events"] == 1
    assert health["admission"]["admitted_events"] == 1
    assert health["admission"]["rejected_events"] == 1

    now[0] = 1.0
    plane.ingest("tenant-a", "device-a", "event-two", {"sequence": 2})
    assert len(plane.events("tenant-a")) == 2
    plane.close()


def test_tenant_limit_is_atomic_across_multiple_devices(tmp_path):
    limiter = FleetIngestionRateLimiter(
        tenant_rate=1, tenant_burst=2,
        device_rate=10, device_burst=10,
        clock=lambda: 0,
    )
    plane = _plane(tmp_path, limiter)
    plane.register_device(_device("device-b"))
    events = [{
        "device_id": device_id,
        "event_id": f"event-{device_id}",
        "body": {"device": device_id},
    } for device_id in ("device-a", "device-b")]
    plane.ingest_batch("tenant-a", events)

    with pytest.raises(FleetRateLimitError):
        plane.ingest_batch("tenant-a", [{
            "device_id": "device-a",
            "event_id": "event-limited",
            "body": {},
        }])
    assert len(plane.events("tenant-a")) == 2
    plane.close()


def test_http_rate_limit_uses_429_retry_after_and_contract(tmp_path):
    limiter = FleetIngestionRateLimiter(
        tenant_rate=10, tenant_burst=10,
        device_rate=1, device_burst=1,
        clock=lambda: 0,
    )
    plane = _plane(tmp_path, limiter)
    key = b"s" * 32
    service = FleetLoopbackService(plane, key, tmp_path / "replay.json", port=0)
    base = f"http://127.0.0.1:{service.start()}"
    path = "/v1/tenants/tenant-a/events"

    def post(event_id: str):
        body = json.dumps({
            "device_id": "device-a", "event_id": event_id, "body": {},
        }).encode()
        headers = sign_request(key, "POST", path, body)
        headers["Content-Type"] = "application/json"
        return urllib.request.urlopen(urllib.request.Request(
            base + path, data=body, headers=headers, method="POST"
        ), timeout=3)

    try:
        assert json.load(post("event-one"))["ok"]
        with pytest.raises(urllib.error.HTTPError) as limited:
            post("event-two")
        assert limited.value.code == 429
        assert limited.value.headers["Retry-After"] == "1"
        error = json.load(limited.value)
        assert error["retry_after_ms"] == 1000
        event_responses = openapi_contract()["paths"][
            "/v1/tenants/{tenant_id}/events"
        ]["post"]["responses"]
        assert "429" in event_responses
    finally:
        assert service.stop()
        plane.close()
