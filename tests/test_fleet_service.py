import json
import urllib.error
import urllib.request

import pytest

from angerona.core.fleet_control_plane import FleetControlPlane
from angerona.core.fleet_service import FleetLoopbackService, sign_request


def request(url, method, key, path, payload=None, **auth_kwargs):
    body = b"" if payload is None else json.dumps(payload).encode()
    headers = sign_request(key, method, path, body, **auth_kwargs)
    headers["Content-Type"] = "application/json"
    return urllib.request.urlopen(
        urllib.request.Request(url + path, data=body if method == "POST" else None,
                               headers=headers, method=method),
        timeout=3,
    )


def test_loopback_service_auth_replay_tenant_and_lifecycle(tmp_path):
    key = b"s" * 32
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane, key, tmp_path / "replay.json", port=0
    )
    port = service.start()
    base = f"http://127.0.0.1:{port}"
    assert json.load(urllib.request.urlopen(base + "/health", timeout=3))["ok"]
    path = "/v1/tenants/tenant-a/devices"
    device = {
        "device_id": "device-a", "public_key": "key-device-a",
        "hostname_token": "tok_device-a", "platform": "windows",
        "version": "1.0", "group_id": "default", "state": "active",
        "last_seen": 1,
    }
    assert json.load(request(base, "POST", key, path, device))["ok"]
    listing = json.load(request(base, "GET", key, "/v1/tenants/tenant-a"))
    assert listing["items"][0]["device_id"] == "device-a"

    nonce = "fixed-nonce-token-1234567890"
    stamp = 1000
    service.auth._clock = lambda: stamp
    signed_path = "/v1/tenants/tenant-a"
    assert json.load(request(
        base, "GET", key, signed_path, timestamp=stamp, nonce=nonce
    ))["ok"]
    with pytest.raises(urllib.error.HTTPError) as replayed:
        request(base, "GET", key, signed_path, timestamp=stamp, nonce=nonce)
    assert replayed.value.code == 401
    assert service.stop()
    plane.close()


def test_service_refuses_non_loopback_and_bad_signature(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    with pytest.raises(ValueError, match="loopback"):
        FleetLoopbackService(plane, b"s" * 32, tmp_path / "r", host="0.0.0.0")
    service = FleetLoopbackService(
        plane, b"s" * 32, tmp_path / "replay.json", port=0
    )
    port = service.start()
    request_obj = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/tenants/tenant-a",
        headers=sign_request(b"x" * 32, "GET", "/v1/tenants/tenant-a"),
    )
    with pytest.raises(urllib.error.HTTPError) as denied:
        urllib.request.urlopen(request_obj, timeout=3)
    assert denied.value.code == 401
    assert service.stop()
    plane.close()


def test_query_parameters_are_covered_by_request_signature(tmp_path):
    key = b"s" * 32
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane, key, tmp_path / "replay.json", port=0
    )
    port = service.start()
    base = f"http://127.0.0.1:{port}"
    signed = "/v1/tenants/tenant-a?resource=devices"
    tampered = "/v1/tenants/tenant-a?resource=events"
    request_obj = urllib.request.Request(
        base + tampered, headers=sign_request(key, "GET", signed),
    )
    with pytest.raises(urllib.error.HTTPError) as denied:
        urllib.request.urlopen(request_obj, timeout=3)
    assert denied.value.code == 401
    assert service.stop()
    plane.close()
