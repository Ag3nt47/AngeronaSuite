from __future__ import annotations

import json
import urllib.request

import pytest

from angerona.core.fleet_control_plane import (
    MAX_INGEST_BATCH,
    FleetControlPlane,
    FleetDevice,
)
from angerona.core.fleet_service import (
    FleetLoopbackService,
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


def _events(count: int, *, start: int = 0) -> list[dict[str, object]]:
    return [{
        "device_id": "device-a",
        "event_id": f"event-{index:04d}",
        "body": {"sequence": index},
        "observed_at": 999,
    } for index in range(start, start + count)]


def test_batch_ingestion_is_atomic_signed_and_idempotent(tmp_path):
    plane = _plane(tmp_path)
    statements: list[str] = []
    plane._db.set_trace_callback(statements.append)

    receipts = plane.ingest_batch("tenant-a", _events(100))

    assert len(receipts) == 100
    assert all(not receipt.duplicate for receipt in receipts)
    assert all(plane.verify_receipt(receipt) for receipt in receipts)
    assert len(plane.events("tenant-a", limit=500)) == 100
    assert sum(line == "BEGIN IMMEDIATE" for line in statements) == 1
    assert sum(line == "COMMIT" for line in statements) == 1

    retried = plane.ingest_batch("tenant-a", _events(100))
    assert all(receipt.duplicate for receipt in retried)
    assert [item.received_at for item in retried] == [
        item.received_at for item in receipts
    ]
    health = plane.ingestion_health("tenant-a")
    assert health["stored_events"] == 100
    assert health["duplicate_retries"] == 100
    assert health["clock_quality"]["synchronized"] == 100
    assert health["batches"] == {
        "accepted": 2, "event_attempts": 200, "largest": 100,
    }
    plane.close()


def test_conflicting_batch_rolls_back_events_devices_and_counters(tmp_path):
    plane = _plane(tmp_path)
    plane.ingest("tenant-a", "device-a", "event-existing", {"value": 1})
    before_health = plane.ingestion_health("tenant-a")
    before_seen = plane.devices("tenant-a")[0].last_seen

    with pytest.raises(ValueError, match="different evidence"):
        plane.ingest_batch("tenant-a", [
            *_events(1, start=500),
            {
                "device_id": "device-a",
                "event_id": "event-existing",
                "body": {"value": 2},
            },
        ])

    assert {item["event_id"] for item in plane.events("tenant-a")} == {
        "event-existing"
    }
    after_health = plane.ingestion_health("tenant-a")
    assert {
        key: value for key, value in after_health.items() if key != "admission"
    } == {
        key: value for key, value in before_health.items() if key != "admission"
    }
    assert after_health["admission"]["admitted_events"] == (
        before_health["admission"]["admitted_events"] + 2
    )
    assert plane.devices("tenant-a")[0].last_seen == before_seen
    plane.close()


def test_batch_rejects_invalid_counts_fields_and_aggregate_size(tmp_path):
    plane = _plane(tmp_path)
    with pytest.raises(ValueError, match="1 to"):
        plane.ingest_batch("tenant-a", [])
    with pytest.raises(ValueError, match="1 to"):
        plane.ingest_batch("tenant-a", _events(MAX_INGEST_BATCH + 1))
    invalid = _events(1)
    invalid[0]["unexpected"] = True
    with pytest.raises(ValueError, match="unknown fields"):
        plane.ingest_batch("tenant-a", invalid)
    large = [{
        "device_id": "device-a",
        "event_id": f"large-{index:03d}",
        "body": {"value": "x" * 250_000},
    } for index in range(17)]
    with pytest.raises(ValueError, match="aggregate"):
        plane.ingest_batch("tenant-a", large)
    assert plane.events("tenant-a") == ()
    plane.close()


def test_authenticated_batch_route_and_contract(tmp_path):
    key = b"s" * 32
    plane = _plane(tmp_path)
    service = FleetLoopbackService(plane, key, tmp_path / "replay.json", port=0)
    base = f"http://127.0.0.1:{service.start()}"
    path = "/v1/tenants/tenant-a/event-batches"
    payload = {"events": _events(2)}
    body = json.dumps(payload).encode("utf-8")
    headers = sign_request(key, "POST", path, body)
    headers["Content-Type"] = "application/json"
    try:
        response = urllib.request.urlopen(urllib.request.Request(
            base + path, data=body, headers=headers, method="POST"
        ), timeout=3)
        result = json.load(response)
        assert result["ok"]
        assert len(result["receipts"]) == 2
        contract = openapi_contract()
        operation = contract["paths"][path.replace("tenant-a", "{tenant_id}")]
        assert operation["post"]["operationId"] == "ingestFleetEventBatch"
        assert contract["info"]["version"] == "2.0.0"
        assert contract["x-angerona-boundaries"]["maximumBatchEvents"] == 256
    finally:
        assert service.stop()
        plane.close()
