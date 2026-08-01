from dataclasses import replace

import pytest

from angerona.core.fleet_control_plane import (
    FleetControlPlane, FleetDevice,
)


def device(tenant, device_id):
    return FleetDevice(
        tenant, device_id, f"key-{device_id}", f"tok_{device_id}",
        "windows", "1.0", last_seen=1,
    )


def test_tenant_isolation_dedup_and_authenticated_receipts(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32, "tenant-b": b"b" * 32}
    )
    plane.register_device(device("tenant-a", "device-a"))
    plane.register_device(device("tenant-b", "device-b"))
    receipt = plane.ingest(
        "tenant-a", "device-a", "event-001", {"kind": "process"}, observed_at=2
    )
    assert plane.verify_receipt(receipt)
    assert plane.ingest(
        "tenant-a", "device-a", "event-001", {"kind": "process"}, observed_at=2
    ).duplicate
    assert [item.device_id for item in plane.devices("tenant-a")] == ["device-a"]
    assert plane.events("tenant-a")[0]["body"]["kind"] == "process"
    assert plane.events("tenant-b") == ()
    assert not plane.verify_receipt(replace(receipt, tenant_id="tenant-b"))
    plane.close()


def test_cross_tenant_and_conflicting_identity_operations_fail_closed(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32, "tenant-b": b"b" * 32}
    )
    plane.register_device(device("tenant-a", "device-a"))
    with pytest.raises(PermissionError):
        plane.ingest("tenant-b", "device-a", "event-001", {"kind": "x"})
    with pytest.raises(ValueError, match="key conflict"):
        plane.register_device(
            replace(device("tenant-a", "device-a"), public_key="different")
        )
    plane.ingest("tenant-a", "device-a", "event-001", {"kind": "x"})
    with pytest.raises(ValueError, match="conflicts"):
        plane.ingest("tenant-a", "device-a", "event-001", {"kind": "y"})
    plane.close()


def test_quarantined_devices_cannot_ingest(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    enrolled = device("tenant-a", "device-a")
    plane.register_device(enrolled)
    plane.transition_device_state(
        "tenant-a", "device-a", "quarantined", expected_state="active"
    )
    with pytest.raises(PermissionError, match="quarantined"):
        plane.ingest("tenant-a", "device-a", "event-001", {"kind": "x"})
    plane.close()


@pytest.mark.parametrize("state", ["quarantined", "revoked", "retired"])
def test_reenrollment_cannot_clear_restrictive_device_state(tmp_path, state):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 100
    )
    enrolled = device("tenant-a", "device-a")
    plane.register_device(enrolled)
    plane.transition_device_state(
        "tenant-a", "device-a", state, expected_state="active"
    )
    with pytest.raises(PermissionError, match="administrative API"):
        plane.register_device(enrolled)
    assert plane.devices("tenant-a")[0].state == state
    plane.close()


def test_device_state_transition_is_compare_and_swap_and_terminal(tmp_path):
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    plane.register_device(device("tenant-a", "device-a"))
    plane.transition_device_state(
        "tenant-a", "device-a", "revoked", expected_state="active"
    )
    with pytest.raises(RuntimeError, match="changed concurrently"):
        plane.transition_device_state(
            "tenant-a", "device-a", "retired", expected_state="active"
        )
    with pytest.raises(PermissionError, match="not permitted"):
        plane.transition_device_state(
            "tenant-a", "device-a", "active", expected_state="revoked"
        )
    plane.close()


def test_registration_uses_server_time_not_caller_last_seen(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}, clock=lambda: 1234
    )
    plane.register_device(replace(
        device("tenant-a", "device-a"), last_seen=9_999_999_999
    ))
    assert plane.devices("tenant-a")[0].last_seen == 1234
    plane.close()
