import json

import pytest

from angerona.core.fleet_control_plane import (
    MAX_QUERY_RESPONSE_BYTES,
    FleetControlPlane,
    FleetDevice,
)


def _device() -> FleetDevice:
    return FleetDevice(
        "tenant-a", "device-a", "key-device-a", "tok_device-a",
        "windows", "1.9.4",
    )


def test_event_body_and_signed_metadata_tampering_fail_closed(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device())
    plane.ingest(
        "tenant-a", "device-a", "event-one", {"kind": "original"},
        observed_at=999,
    )
    assert plane.events("tenant-a")[0]["integrity"] == "verified"

    plane._db.execute(
        "UPDATE fleet_events SET body_json=? WHERE tenant_id=? AND event_id=?",
        (json.dumps({"kind": "injected"}), "tenant-a", "event-one"),
    )
    with pytest.raises(RuntimeError, match="integrity"):
        plane.event_page("tenant-a")

    plane._db.execute(
        "UPDATE fleet_events SET body_json=?,received_at=? "
        "WHERE tenant_id=? AND event_id=?",
        (
            json.dumps({"kind": "original"}, sort_keys=True, separators=(",", ":")),
            2000,
            "tenant-a",
            "event-one",
        ),
    )
    with pytest.raises(RuntimeError, match="integrity"):
        plane.event_page("tenant-a")
    plane.close()


def test_event_pages_are_bounded_cursor_signed_and_server_ordered(tmp_path):
    now = [1000.0]
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: now[0]
    )
    plane.register_device(_device())
    for index, observed in enumerate((9_999_999_999, 10, 20)):
        now[0] += 1
        plane.ingest(
            "tenant-a", "device-a", f"event-{index}",
            {"payload": "x" * 2000}, observed_at=observed,
        )

    first = plane.event_page("tenant-a", limit=2)
    assert first.truncated and first.next_cursor
    assert first.encoded_bytes <= MAX_QUERY_RESPONSE_BYTES
    assert [item["event_id"] for item in first.items] == ["event-2", "event-1"]
    second = plane.event_page("tenant-a", limit=2, cursor=first.next_cursor)
    assert [item["event_id"] for item in second.items] == ["event-0"]
    assert not second.truncated

    tampered = first.next_cursor[:-1] + (
        "A" if first.next_cursor[-1] != "A" else "B"
    )
    with pytest.raises(ValueError, match="cursor"):
        plane.event_page("tenant-a", cursor=tampered)
    with pytest.raises(ValueError, match="bounded page"):
        plane.events("tenant-a", limit=2)
    plane.close()


def test_device_inventory_and_state_tampering_fail_closed(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1000
    )
    plane.register_device(_device())
    plane._db.execute(
        "UPDATE fleet_devices SET state='revoked' "
        "WHERE tenant_id='tenant-a' AND device_id='device-a'"
    )
    with pytest.raises(RuntimeError, match="device integrity"):
        plane.devices("tenant-a")
    with pytest.raises(RuntimeError, match="device integrity"):
        plane.ingest("tenant-a", "device-a", "event-one", {"kind": "x"})
    with pytest.raises(RuntimeError, match="device integrity"):
        plane.ingestion_health("tenant-a")
    plane.close()
