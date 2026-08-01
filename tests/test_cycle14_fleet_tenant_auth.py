import json
import urllib.error
import urllib.request

import pytest

from angerona.core.authorization import (
    AuthorizationPolicy,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
)
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
    openapi_contract,
    sign_request,
)


def _device(tenant: str, device_id: str) -> FleetDevice:
    return FleetDevice(
        tenant, device_id, f"key-{device_id}", f"tok_{device_id}",
        "windows", "1.9.4",
    )


def _call(base, credential, method, path, payload=None, *, signed_as=None):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    signer = signed_as or credential
    headers = sign_request(
        signer.secret,
        method,
        path,
        body,
        credential_id=credential.credential_id,
    )
    headers["Content-Type"] = "application/json"
    return urllib.request.urlopen(urllib.request.Request(
        base + path,
        data=body if method == "POST" else None,
        headers=headers,
        method=method,
    ), timeout=3)


def test_credentials_are_tenant_and_device_bound_at_every_route(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db",
        {"tenant-a": b"a" * 32, "tenant-b": b"b" * 32},
    )
    plane.register_device(_device("tenant-a", "device-a"))
    plane.register_device(_device("tenant-b", "device-b"))
    operator_a = FleetCredential(
        "operator-a", "tenant-a", FleetCredentialKind.TENANT, b"o" * 32,
        FLEET_TENANT_PERMISSIONS,
    )
    device_a = FleetCredential(
        "device-auth-a", "tenant-a", FleetCredentialKind.DEVICE, b"d" * 32,
        FLEET_DEVICE_PERMISSIONS, device_id="device-a",
    )
    registry = FleetCredentialRegistry((operator_a, device_a))
    service = FleetLoopbackService(
        plane, registry, tmp_path / "replay", port=0
    )
    port = service.start()
    base = f"http://127.0.0.1:{port}"
    try:
        assert json.load(_call(
            base, operator_a, "GET", "/v1/tenants/tenant-a/devices"
        ))["items"][0]["device_id"] == "device-a"

        with pytest.raises(urllib.error.HTTPError) as cross_tenant:
            _call(base, operator_a, "GET", "/v1/tenants/tenant-b/devices")
        assert cross_tenant.value.code == 403

        event = {
            "device_id": "device-a", "event_id": "event-a", "body": {}
        }
        with pytest.raises(urllib.error.HTTPError) as operator_ingest:
            _call(
                base, operator_a, "POST",
                "/v1/tenants/tenant-a/events", event,
            )
        assert operator_ingest.value.code == 403

        wrong_device = {
            "device_id": "device-b", "event_id": "event-b", "body": {}
        }
        with pytest.raises(urllib.error.HTTPError) as impersonation:
            _call(
                base, device_a, "POST",
                "/v1/tenants/tenant-a/events", wrong_device,
            )
        assert impersonation.value.code == 403

        accepted = json.load(_call(
            base, device_a, "POST", "/v1/tenants/tenant-a/events", event,
        ))
        assert accepted["receipt"]["accepted"]
    finally:
        assert service.stop()
        plane.close()


def test_credential_id_is_signed_and_legacy_key_refuses_multiple_tenants(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db",
        {"tenant-a": b"a" * 32, "tenant-b": b"b" * 32},
    )
    with pytest.raises(ValueError, match="one tenant"):
        FleetLoopbackService(plane, b"s" * 32, tmp_path / "replay", port=0)

    first = FleetCredential(
        "operator-a", "tenant-a", FleetCredentialKind.TENANT, b"1" * 32,
        FLEET_TENANT_PERMISSIONS,
    )
    second = FleetCredential(
        "operator-b", "tenant-a", FleetCredentialKind.TENANT, b"2" * 32,
        FLEET_TENANT_PERMISSIONS,
    )
    service = FleetLoopbackService(
        plane, FleetCredentialRegistry((first, second)),
        tmp_path / "replay-two", port=0,
    )
    port = service.start()
    base = f"http://127.0.0.1:{port}"
    try:
        with pytest.raises(urllib.error.HTTPError) as substituted:
            _call(
                base, second, "GET", "/v1/tenants/tenant-a/devices",
                signed_as=first,
            )
        assert substituted.value.code == 401
    finally:
        assert service.stop()
        plane.close()


def test_contract_declares_bound_credential_and_authorization_failures():
    contract = openapi_contract()
    schemes = contract["components"]["securitySchemes"]
    assert schemes["AngeronaCredential"]["name"] == (
        "X-Angerona-Credential-ID"
    )
    for route in (
        "/v1/tenants/{tenant_id}/devices",
        "/v1/tenants/{tenant_id}/events",
        "/v1/tenants/{tenant_id}/ingestion-health",
    ):
        for operation in contract["paths"][route].values():
            if isinstance(operation, dict) and "responses" in operation:
                assert "401" in operation["responses"]
                assert "403" in operation["responses"]


def test_authorization_audit_failure_prevents_control_plane_execution(tmp_path):
    plane = FleetControlPlane(
        tmp_path / "fleet.db", {"tenant-a": b"a" * 32}
    )
    plane.register_device(_device("tenant-a", "device-a"))
    device = FleetCredential(
        "device-auth-a", "tenant-a", FleetCredentialKind.DEVICE, b"d" * 32,
        FLEET_DEVICE_PERMISSIONS, device_id="device-a",
    )

    def unavailable(_decision):
        raise RuntimeError("audit unavailable")

    policy = AuthorizationPolicy(
        (Principal(
            device.authenticated_context(1).principal_id,
            PrincipalKind.SERVICE,
            expires_at=9_999_999_999,
        ),),
        (Role("device-role", FLEET_DEVICE_PERMISSIONS),),
        (RoleBinding(
            device.authenticated_context(1).principal_id,
            "device-role",
            "fleet/tenant-a/device/device-a",
        ),),
        b"p" * 32,
        audit_sink=unavailable,
    )
    service = FleetLoopbackService(
        plane,
        FleetCredentialRegistry((device,)),
        tmp_path / "replay-audit",
        port=0,
        authorization_policy=policy,
    )
    port = service.start()
    base = f"http://127.0.0.1:{port}"
    payload = {
        "device_id": "device-a", "event_id": "event-a", "body": {}
    }
    try:
        with pytest.raises(urllib.error.HTTPError) as blocked:
            _call(
                base, device, "POST", "/v1/tenants/tenant-a/events", payload
            )
        assert blocked.value.code == 503
        assert plane.events("tenant-a") == ()
    finally:
        assert service.stop()
        plane.close()
