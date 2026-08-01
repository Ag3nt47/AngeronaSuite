from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.request

import pytest

from angerona.core.fleet_control_plane import FleetControlPlane, FleetDevice
from angerona.core.fleet_service import (
    MAX_DECODED_BODY,
    BodyTooLarge,
    FleetLoopbackService,
    _decode_request_body,
    ingestion_capabilities,
    openapi_contract,
    sign_request,
)


def _plane(tmp_path) -> FleetControlPlane:
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(FleetDevice(
        "tenant-a", "device-a", "key-device-a", "tok_device-a",
        "windows", "1.9.4", last_seen=1,
    ))
    return plane


def _post(base: str, key: bytes, path: str, body: bytes, encoding: str):
    headers = sign_request(key, "POST", path, body)
    headers.update({
        "Content-Type": "application/json",
        "Content-Encoding": encoding,
    })
    return urllib.request.urlopen(urllib.request.Request(
        base + path, data=body, headers=headers, method="POST"
    ), timeout=3)


def test_gzip_decoder_is_bounded_and_rejects_ambiguity():
    original = json.dumps({"events": []}).encode()
    compressed = gzip.compress(original, mtime=0)
    assert _decode_request_body(compressed, "gzip") == original
    assert _decode_request_body(original, "identity") == original
    with pytest.raises(ValueError, match="exactly one"):
        _decode_request_body(compressed + b"trailing", "gzip")
    with pytest.raises(ValueError, match="identity or gzip"):
        _decode_request_body(original, "br")
    bomb = gzip.compress(b"x" * (MAX_DECODED_BODY + 1), mtime=0)
    with pytest.raises(BodyTooLarge, match="byte budget"):
        _decode_request_body(bomb, "gzip")


def test_authenticated_gzip_batch_and_capability_negotiation(tmp_path):
    key = b"s" * 32
    plane = _plane(tmp_path)
    service = FleetLoopbackService(plane, key, tmp_path / "replay.json", port=0)
    base = f"http://127.0.0.1:{service.start()}"
    batch_path = "/v1/tenants/tenant-a/event-batches"
    payload = {"events": [{
        "device_id": "device-a",
        "event_id": f"event-{index:03d}",
        "body": {"kind": "process", "repeated": "x" * 512},
        "observed_at": 999,
    } for index in range(20)]}
    body = gzip.compress(json.dumps(payload).encode(), mtime=0)
    capability_path = "/v1/ingestion-capabilities"
    try:
        result = json.load(_post(base, key, batch_path, body, "gzip"))
        assert result["ok"]
        assert len(result["receipts"]) == 20

        headers = sign_request(key, "GET", capability_path)
        capabilities = json.load(urllib.request.urlopen(urllib.request.Request(
            base + capability_path, headers=headers, method="GET"
        ), timeout=3))
        assert capabilities == ingestion_capabilities()
        assert capabilities["encodings"] == ["identity", "gzip"]
        assert capabilities["maximum_batch_events"] == 256

        contract = openapi_contract()
        assert contract["info"]["version"] == "2.0.0"
        assert capability_path in contract["paths"]
        assert contract["x-angerona-boundaries"]["requestEncodings"] == [
            "identity", "gzip",
        ]
    finally:
        assert service.stop()
        plane.close()


def test_http_rejects_gzip_bomb_and_trailing_member(tmp_path):
    key = b"s" * 32
    plane = _plane(tmp_path)
    service = FleetLoopbackService(plane, key, tmp_path / "replay.json", port=0)
    base = f"http://127.0.0.1:{service.start()}"
    path = "/v1/tenants/tenant-a/event-batches"
    try:
        bomb = gzip.compress(b"x" * (MAX_DECODED_BODY + 1), mtime=0)
        with pytest.raises(urllib.error.HTTPError) as oversized:
            _post(base, key, path, bomb, "gzip")
        assert oversized.value.code == 413

        valid = gzip.compress(b'{"events":[]}', mtime=0) + b"trailing"
        with pytest.raises(urllib.error.HTTPError) as ambiguous:
            _post(base, key, path, valid, "gzip")
        assert ambiguous.value.code == 415
        assert plane.events("tenant-a") == ()
    finally:
        assert service.stop()
        plane.close()
