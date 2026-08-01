from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

from angerona.core.fleet_control_plane import FleetControlPlane, FleetDevice
from angerona.core.fleet_service import (
    FleetLoopbackService,
    openapi_contract,
    openapi_contract_sha256,
    sign_request,
)


def _device(device_id: str) -> FleetDevice:
    return FleetDevice(
        "tenant-a",
        device_id,
        f"key-{device_id}",
        f"tok_{device_id}",
        "windows",
        "1.9.4",
        last_seen=1,
    )


def _request(
    base: str,
    key: bytes,
    method: str,
    path: str,
    payload: object | None = None,
    *,
    content_type: str = "application/json",
):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    headers = sign_request(key, method, path, body)
    headers["Content-Type"] = content_type
    return urllib.request.urlopen(
        urllib.request.Request(
            base + path,
            data=body if method == "POST" else None,
            headers=headers,
            method=method,
        ),
        timeout=3,
    )


def test_ingestion_classifies_clock_quality_and_uses_server_last_seen(tmp_path):
    now = [1_000_000.0]
    plane = FleetControlPlane(
        tmp_path / "fleet.db",
        {"tenant-a": b"a" * 32},
        clock=lambda: now[0],
    )
    plane.register_device(_device("device-a"))

    synchronized = plane.ingest(
        "tenant-a", "device-a", "event-sync", {"kind": "sync"},
        observed_at=now[0] - 60,
    )
    skewed = plane.ingest(
        "tenant-a", "device-a", "event-skew", {"kind": "skew"},
        observed_at=now[0] + 600,
    )
    untrusted = plane.ingest(
        "tenant-a", "device-a", "event-old", {"kind": "old"}, observed_at=1,
    )
    assigned = plane.ingest(
        "tenant-a", "device-a", "event-assigned", {"kind": "assigned"}
    )

    assert synchronized.clock_quality == "synchronized"
    assert synchronized.clock_skew_seconds == -60
    assert skewed.clock_quality == "skewed"
    assert untrusted.clock_quality == "untrusted"
    assert assigned.clock_quality == "server-assigned"
    assert assigned.recorded_at == assigned.received_at == now[0]
    assert all(plane.verify_receipt(item) for item in (
        synchronized, skewed, untrusted, assigned,
    ))
    assert plane.devices("tenant-a")[0].last_seen == now[0]

    health = plane.ingestion_health("tenant-a")
    assert health["schema"] == "angerona.fleet-ingestion-health/v1"
    assert health["stored_events"] == 4
    assert health["clock_quality"] == {
        "synchronized": 1,
        "skewed": 1,
        "untrusted": 1,
        "server_assigned": 1,
        "legacy": 0,
    }
    assert health["clock_quality_state"] == "degraded"
    plane.close()


@pytest.mark.parametrize("observed", [math.nan, math.inf, -math.inf, 0, -1])
def test_ingestion_rejects_invalid_observation_times(tmp_path, observed):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device("device-a"))
    with pytest.raises(ValueError, match="finite and positive"):
        plane.ingest(
            "tenant-a", "device-a", "event-bad", {"kind": "bad"},
            observed_at=observed,
        )
    assert plane.events("tenant-a") == ()
    plane.close()


def test_duplicate_identity_is_device_bound_and_preserves_original_time(tmp_path):
    now = [1000.0]
    plane = FleetControlPlane(
        tmp_path / "fleet.db",
        {"tenant-a": b"a" * 32},
        clock=lambda: now[0],
    )
    plane.register_device(_device("device-a"))
    plane.register_device(_device("device-b"))
    original = plane.ingest(
        "tenant-a", "device-a", "event-one", {"kind": "process"}, observed_at=990
    )

    now[0] = 2000
    retry = plane.ingest(
        "tenant-a", "device-a", "event-one", {"kind": "process"}, observed_at=1990
    )
    assert retry.duplicate
    assert retry.recorded_at == original.recorded_at
    assert retry.received_at == original.received_at
    assert retry.clock_quality == original.clock_quality
    assert plane.ingestion_health("tenant-a")["duplicate_retries"] == 1

    with pytest.raises(ValueError, match="another device"):
        plane.ingest(
            "tenant-a", "device-b", "event-one", {"kind": "process"},
            observed_at=1990,
        )
    assert len(plane.events("tenant-a")) == 1
    plane.close()


@pytest.mark.parametrize(
    "body,error",
    [
        ({"value": math.nan}, "finite"),
        ({1: "ambiguous"}, "keys"),
        ({"value": object()}, "plain JSON"),
        ({"value": 2**80}, "64-bit"),
        ({"value": "\ud800"}, "UTF-8"),
    ],
)
def test_ingestion_accepts_only_bounded_plain_json(tmp_path, body, error):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device("device-a"))
    with pytest.raises((TypeError, ValueError), match=error):
        plane.ingest("tenant-a", "device-a", "event-json", body)
    assert plane.events("tenant-a") == ()
    plane.close()


def test_ingestion_rejects_cyclic_or_excessively_deep_json(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device("device-a"))
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(ValueError, match="depth"):
        plane.ingest("tenant-a", "device-a", "event-cycle", cyclic)

    nested: dict[str, object] = {}
    cursor = nested
    for _ in range(40):
        child: dict[str, object] = {}
        cursor["next"] = child
        cursor = child
    with pytest.raises(ValueError, match="depth"):
        plane.ingest("tenant-a", "device-a", "event-deep", nested)
    plane.close()


def test_legacy_fleet_database_is_migrated_without_losing_evidence(tmp_path):
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE fleet_devices(
          tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
          public_key TEXT NOT NULL, hostname_token TEXT NOT NULL,
          platform TEXT NOT NULL, version TEXT NOT NULL, group_id TEXT NOT NULL,
          state TEXT NOT NULL, last_seen REAL NOT NULL,
          PRIMARY KEY(tenant_id, device_id));
        CREATE TABLE fleet_events(
          tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, device_id TEXT NOT NULL,
          observed_at REAL NOT NULL, event_hash TEXT NOT NULL, body_json TEXT NOT NULL,
          PRIMARY KEY(tenant_id, event_id));
    """)
    body = json.dumps({"kind": "legacy"}, sort_keys=True, separators=(",", ":"))
    db.execute(
        "INSERT INTO fleet_devices VALUES(?,?,?,?,?,?,?,?,?)",
        ("tenant-a", "device-a", "key-device-a", "tok_device-a", "windows",
         "1.0", "default", "active", 10),
    )
    db.execute(
        "INSERT INTO fleet_events VALUES(?,?,?,?,?,?)",
        ("tenant-a", "event-old", "device-a", 10,
         hashlib.sha256(body.encode()).hexdigest(), body),
    )
    db.commit()
    db.close()

    plane = FleetControlPlane(path, {"tenant-a": b"a" * 32}, clock=lambda: 20)
    event = plane.events("tenant-a")[0]
    assert event["body"] == {"kind": "legacy"}
    assert event["received_at"] == 10
    assert event["clock_quality"] == "legacy"
    health = plane.ingestion_health("tenant-a")
    assert health["stored_events"] == 1
    assert health["clock_quality"]["legacy"] == 1
    assert health["clock_quality_state"] == "degraded"
    plane.close()


def test_openapi_contract_matches_authenticated_canonical_routes(tmp_path):
    first = openapi_contract()
    second = openapi_contract()
    assert first == second
    assert first is not second
    assert first["openapi"] == "3.1.0"
    assert first["x-angerona-boundaries"]["transport"] == "loopback-only"
    assert first["x-angerona-boundaries"]["productionMutualTls"] is False
    assert len(openapi_contract_sha256()) == 64
    encoded = json.dumps(first)
    assert "tenant-a" not in encoded
    assert "aaaaaaaa" not in encoded

    key = b"s" * 32
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device("device-a"))
    service = FleetLoopbackService(plane, key, tmp_path / "replay.json", port=0)
    port = service.start()
    base = f"http://127.0.0.1:{port}"
    try:
        with pytest.raises(urllib.error.HTTPError) as unsigned:
            urllib.request.urlopen(base + "/v1/openapi", timeout=3)
        assert unsigned.value.code == 401

        response = _request(base, key, "GET", "/v1/openapi")
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert json.load(response) == first

        devices = json.load(_request(
            base, key, "GET", "/v1/tenants/tenant-a/devices"
        ))
        assert devices["items"][0]["device_id"] == "device-a"
        health = json.load(_request(
            base, key, "GET", "/v1/tenants/tenant-a/ingestion-health"
        ))
        assert health["clock_quality_state"] == "unknown"

        payload = {"device_id": "device-a", "event_id": "event-api", "body": {}}
        with pytest.raises(urllib.error.HTTPError) as wrong_media:
            _request(
                base, key, "POST", "/v1/tenants/tenant-a/events", payload,
                content_type="text/plain",
            )
        assert wrong_media.value.code == 415
    finally:
        assert service.stop()
        plane.close()


def test_concurrent_ingestion_preserves_counts_and_device_binding(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device("device-a"))

    def ingest(index: int):
        event_index = index % 100
        return plane.ingest(
            "tenant-a",
            "device-a",
            f"event-{event_index:03d}",
            {"sequence": event_index},
            observed_at=999,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(ingest, range(120)))

    assert len(plane.events("tenant-a", limit=500)) == 100
    assert sum(receipt.duplicate for receipt in receipts) == 20
    assert all(plane.verify_receipt(receipt) for receipt in receipts)
    health = plane.ingestion_health("tenant-a")
    assert health["stored_events"] == 100
    assert health["duplicate_retries"] == 20
    assert health["clock_quality"]["synchronized"] == 100
    plane.close()
