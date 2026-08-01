import hashlib
import hmac
import json
import math
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from angerona.core.fleet_credentials import (
    INTERNAL_FLEET_CREDENTIALS_KEY,
    LEGACY_FLEET_SERVICE_KEY,
    LOCAL_FLEET_DEVICE_CREDENTIAL_ID,
    LOCAL_FLEET_OPERATOR_CREDENTIAL_ID,
    MAX_LOCAL_FLEET_BUNDLE_BYTES,
    MAX_FLEET_CREDENTIALS,
    AuthenticatedFleetContext,
    FleetCredential,
    FleetCredentialKind,
    FleetCredentialRegistry,
    LocalFleetCredentialSet,
    load_or_migrate_local_credentials,
)


SECRET = b"c" * 32


class MemorySecretStore:
    def __init__(self):
        self.values = {}
        self.writes = []

    def read(self, _data_root):
        return dict(self.values)

    def write(self, updates, data_root):
        self.writes.append(dict(updates))
        for key, value in updates.items():
            if value in (None, ""):
                self.values.pop(key, None)
            else:
                self.values[key] = str(value)
        return Path(data_root) / "secrets.dpapi"


@pytest.fixture
def memory_store(monkeypatch):
    from angerona.core import secure_store

    store = MemorySecretStore()
    monkeypatch.setattr(secure_store, "read_secret_map", store.read)
    monkeypatch.setattr(secure_store, "write_secret_map", store.write)
    return store


def credential(
    credential_id: str = "credential-one", **changes
) -> FleetCredential:
    values = {
        "credential_id": credential_id,
        "tenant_id": "tenant-acme",
        "kind": FleetCredentialKind.TENANT,
        "secret": SECRET,
        "permissions": ("device.read", "event.read"),
    }
    values.update(changes)
    return FleetCredential(**values)


def test_credential_is_frozen_canonical_and_secret_is_not_in_repr():
    item = credential(permissions=("event.read", "device.read"))
    assert item.permissions == ("device.read", "event.read")
    assert "cccccccc" not in repr(item)
    with pytest.raises(FrozenInstanceError):
        item.tenant_id = "tenant-other"


@pytest.mark.parametrize("field,value", (
    ("credential_id", "../credential"),
    ("credential_id", "ab"),
    ("tenant_id", "tenant/acme"),
    ("tenant_id", " tenant-acme"),
))
def test_credential_rejects_noncanonical_identifiers(field, value):
    with pytest.raises(ValueError, match="invalid"):
        credential(**{field: value})


def test_kind_strictly_controls_device_binding():
    device = credential(
        kind=FleetCredentialKind.DEVICE, device_id="device-123"
    )
    assert device.device_id == "device-123"
    with pytest.raises(ValueError, match="device ID"):
        credential(kind=FleetCredentialKind.DEVICE)
    with pytest.raises(ValueError, match="must not bind"):
        credential(device_id="device-123")
    with pytest.raises(ValueError, match="kind"):
        credential(kind="tenant")


@pytest.mark.parametrize("secret", (b"short", bytearray(b"x" * 32), b"x" * 4097))
def test_secret_must_be_bounded_immutable_bytes(secret):
    with pytest.raises(ValueError, match="secret"):
        credential(secret=secret)


@pytest.mark.parametrize("permissions", (
    [],
    (),
    ("read",),
    ("*.read",),
    ("device.*.read",),
    ("Device.read",),
    ("device.read", "device.read"),
))
def test_permissions_use_authorization_grammar_and_are_unique_tuple(permissions):
    with pytest.raises(ValueError, match="permission"):
        credential(permissions=permissions)


@pytest.mark.parametrize("field,value", (
    ("not_before", math.nan),
    ("not_before", math.inf),
    ("expires_at", -1),
    ("expires_at", True),
    ("revoked_at", -math.inf),
))
def test_validity_timestamps_are_finite_and_nonnegative(field, value):
    with pytest.raises(ValueError, match="finite"):
        credential(**{field: value})
    with pytest.raises(ValueError, match="follow"):
        credential(not_before=100, expires_at=100)


def test_registry_rejects_duplicates_wrong_entries_and_bounds():
    item = credential()
    with pytest.raises(ValueError, match="duplicate"):
        FleetCredentialRegistry((item, item))
    with pytest.raises(TypeError, match="FleetCredential"):
        FleetCredentialRegistry((item, object()))
    with pytest.raises(ValueError, match="bound"):
        FleetCredentialRegistry((item,), max_credentials=0)
    with pytest.raises(ValueError, match="bound"):
        FleetCredentialRegistry(
            tuple(credential(f"credential-{index:05d}") for index in range(2)),
            max_credentials=1,
        )
    assert MAX_FLEET_CREDENTIALS == 10_000


def test_resolve_uses_generic_miss_for_every_inactive_or_invalid_state():
    registry = FleetCredentialRegistry((
        credential("credential-active"),
        credential("credential-pending", not_before=200),
        credential("credential-expired", expires_at=100),
        credential("credential-revoked", revoked_at=100),
    ))
    assert registry.resolve("credential-active", now=100).credential_id == (
        "credential-active"
    )
    for candidate in (
        "credential-missing", "../invalid", None,
        "credential-pending", "credential-expired", "credential-revoked",
    ):
        assert registry.resolve(candidate, now=100) is None


def test_resolution_clock_fails_closed():
    registry = FleetCredentialRegistry(
        (credential(),), clock=lambda: math.nan
    )
    with pytest.raises(RuntimeError, match="clock"):
        registry.resolve("credential-one")
    with pytest.raises(RuntimeError, match="clock"):
        registry.resolve("credential-one", now=-1)


def test_authenticated_context_is_secret_free_scoped_and_permission_aware():
    item = credential(
        kind=FleetCredentialKind.DEVICE,
        device_id="device-123",
        permissions=("event.*", "device.read"),
    )
    context = item.authenticated_context(50)
    assert isinstance(context, AuthenticatedFleetContext)
    assert context.principal_id == "fleet-credential:credential-one"
    assert context.scope == "fleet/tenant-acme/device/device-123"
    assert context.allows("event.append")
    assert context.allows("device.read")
    assert not context.allows("device.revoke")
    assert not hasattr(context, "secret")
    with pytest.raises(ValueError, match="not active"):
        credential(expires_at=50).authenticated_context(50)


def test_public_snapshot_is_fixed_key_secret_free_and_immutable():
    registry = FleetCredentialRegistry((
        credential("credential-active"),
        credential(
            "credential-device",
            kind=FleetCredentialKind.DEVICE,
            device_id="device-123",
            not_before=200,
        ),
        credential("credential-expired", expires_at=50),
        credential("credential-revoked", revoked_at=50),
    ))
    snapshot = registry.public_snapshot(now=100)
    assert snapshot == {
        "schema": "angerona.fleet-credential-registry/v1",
        "configured": 4,
        "capacity": MAX_FLEET_CREDENTIALS,
        "active": 1,
        "pending": 1,
        "expired": 1,
        "revoked": 1,
        "tenant_credentials": 3,
        "device_credentials": 1,
    }
    serialized = repr(dict(snapshot))
    assert "credential-active" not in serialized
    assert SECRET.hex() not in serialized
    with pytest.raises(TypeError):
        snapshot["active"] = 99


def test_one_time_legacy_migration_preserves_derivations_and_separates_keys(
    tmp_path, memory_store
):
    legacy = "legacy-protected-secret-0123456789-ABCDEFG"
    memory_store.values[LEGACY_FLEET_SERVICE_KEY] = legacy

    loaded = load_or_migrate_local_credentials(
        tmp_path, "tenant-acme", "device-123", clock=lambda: 100
    )

    expected_operator = hashlib.sha256(
        b"angerona-fleet-service-v1\0" + legacy.encode("utf-8")
    ).digest()
    expected_receipt = hmac.new(
        expected_operator,
        b"angerona-fleet-tenant-v1\0tenant-acme",
        hashlib.sha256,
    ).digest()
    assert isinstance(loaded, LocalFleetCredentialSet)
    assert loaded.operator is loaded.operator_credential
    assert loaded.device is loaded.device_credential
    assert loaded.operator.secret == expected_operator
    assert loaded.receipt_signing_key == expected_receipt
    assert loaded.operator.tenant_id == "tenant-acme"
    assert loaded.device.device_id == "device-123"
    assert loaded.registry.resolve(
        LOCAL_FLEET_OPERATOR_CREDENTIAL_ID, now=100
    ) == loaded.operator
    assert loaded.registry.resolve(
        LOCAL_FLEET_DEVICE_CREDENTIAL_ID, now=100
    ) == loaded.device
    distinct = {
        loaded.operator.secret,
        loaded.device.secret,
        loaded.receipt_signing_key,
        loaded.authorization_audit_key,
    }
    assert len(distinct) == 4
    assert INTERNAL_FLEET_CREDENTIALS_KEY in memory_store.values
    assert LEGACY_FLEET_SERVICE_KEY not in memory_store.values
    assert list(memory_store.writes[0]) == [INTERNAL_FLEET_CREDENTIALS_KEY]
    assert memory_store.writes[1] == {LEGACY_FLEET_SERVICE_KEY: ""}


def test_existing_v1_wins_over_every_legacy_source_and_retries_cleanup(
    tmp_path, memory_store
):
    original = load_or_migrate_local_credentials(
        tmp_path,
        "tenant-acme",
        "device-123",
        legacy_secret="a" * 48,
        clock=lambda: 100,
    )
    encoded = memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY]
    memory_store.values[LEGACY_FLEET_SERVICE_KEY] = "b" * 48

    reloaded = load_or_migrate_local_credentials(
        tmp_path,
        "tenant-acme",
        "device-123",
        legacy_secret="c" * 48,
        clock=lambda: 100,
    )

    assert reloaded.operator.secret == original.operator.secret
    assert reloaded.device.secret == original.device.secret
    assert memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY] == encoded
    assert LEGACY_FLEET_SERVICE_KEY not in memory_store.values


@pytest.mark.parametrize("payload", (
    "{not-json",
    "x" * (MAX_LOCAL_FLEET_BUNDLE_BYTES + 1),
), ids=("invalid-json", "oversize"))
def test_existing_corrupt_or_oversize_v1_fails_closed_without_legacy_fallback(
    tmp_path, memory_store, payload
):
    memory_store.values.update({
        INTERNAL_FLEET_CREDENTIALS_KEY: payload,
        LEGACY_FLEET_SERVICE_KEY: "z" * 48,
    })
    with pytest.raises(ValueError, match="bundle|invalid|byte bound"):
        load_or_migrate_local_credentials(
            tmp_path,
            "tenant-acme",
            "device-123",
            legacy_secret="y" * 48,
            clock=lambda: 100,
        )
    assert memory_store.values[LEGACY_FLEET_SERVICE_KEY] == "z" * 48
    assert memory_store.writes == []


@pytest.mark.parametrize("field,replacement", (
    ("tenant_id", "tenant-other"),
    ("device_id", "device-other"),
))
def test_v1_must_match_exact_runtime_tenant_and_device(
    tmp_path, memory_store, field, replacement
):
    load_or_migrate_local_credentials(
        tmp_path,
        "tenant-acme",
        "device-123",
        legacy_secret="a" * 48,
        clock=lambda: 100,
    )
    value = json.loads(memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY])
    value[field] = replacement
    memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY] = json.dumps(value)
    with pytest.raises(ValueError, match="binding mismatch"):
        load_or_migrate_local_credentials(
            tmp_path, "tenant-acme", "device-123", clock=lambda: 100
        )


def test_v1_rejects_unknown_fields_noncanonical_keys_and_excess_credentials(
    tmp_path, memory_store
):
    load_or_migrate_local_credentials(
        tmp_path,
        "tenant-acme",
        "device-123",
        legacy_secret="a" * 48,
        clock=lambda: 100,
    )
    original = json.loads(memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY])

    unknown = {**original, "future_field": True}
    memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY] = json.dumps(unknown)
    with pytest.raises(ValueError, match="unknown or missing"):
        load_or_migrate_local_credentials(
            tmp_path, "tenant-acme", "device-123", clock=lambda: 100
        )

    padded = json.loads(json.dumps(original))
    padded["receipt_signing_key"] += "="
    memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY] = json.dumps(padded)
    with pytest.raises(ValueError, match="canonical base64url"):
        load_or_migrate_local_credentials(
            tmp_path, "tenant-acme", "device-123", clock=lambda: 100
        )

    excessive = json.loads(json.dumps(original))
    excessive["credentials"] = excessive["credentials"] * 5
    memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY] = json.dumps(excessive)
    with pytest.raises(ValueError, match="count"):
        load_or_migrate_local_credentials(
            tmp_path, "tenant-acme", "device-123", clock=lambda: 100
        )


def test_first_protected_write_failure_keeps_legacy_intact(
    tmp_path, memory_store, monkeypatch
):
    from angerona.core import secure_store

    legacy = "legacy-protected-secret-0123456789-ABCDEFG"
    memory_store.values[LEGACY_FLEET_SERVICE_KEY] = legacy

    def fail_write(_updates, _data_root):
        raise RuntimeError("simulated protected write failure")

    monkeypatch.setattr(secure_store, "write_secret_map", fail_write)
    with pytest.raises(RuntimeError, match="simulated"):
        load_or_migrate_local_credentials(
            tmp_path, "tenant-acme", "device-123", clock=lambda: 100
        )
    assert memory_store.values == {LEGACY_FLEET_SERVICE_KEY: legacy}


def test_cleanup_failure_keeps_verified_v1_and_next_load_retries(
    tmp_path, memory_store, monkeypatch
):
    from angerona.core import secure_store

    legacy = "legacy-protected-secret-0123456789-ABCDEFG"
    memory_store.values[LEGACY_FLEET_SERVICE_KEY] = legacy
    attempts = 0

    def fail_first_cleanup(updates, data_root):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise RuntimeError("simulated cleanup failure")
        return memory_store.write(updates, data_root)

    monkeypatch.setattr(secure_store, "write_secret_map", fail_first_cleanup)
    first = load_or_migrate_local_credentials(
        tmp_path, "tenant-acme", "device-123", clock=lambda: 100
    )
    assert first.operator
    assert INTERNAL_FLEET_CREDENTIALS_KEY in memory_store.values
    assert memory_store.values[LEGACY_FLEET_SERVICE_KEY] == legacy

    second = load_or_migrate_local_credentials(
        tmp_path, "tenant-acme", "device-123", clock=lambda: 100
    )
    assert second.operator.secret == first.operator.secret
    assert LEGACY_FLEET_SERVICE_KEY not in memory_store.values
    assert attempts == 3


@pytest.mark.parametrize("credential_id,state_field", (
    (LOCAL_FLEET_OPERATOR_CREDENTIAL_ID, "expires_at"),
    (LOCAL_FLEET_DEVICE_CREDENTIAL_ID, "revoked_at"),
))
def test_expired_or_revoked_protected_credentials_fail_closed(
    tmp_path, memory_store, credential_id, state_field
):
    load_or_migrate_local_credentials(
        tmp_path,
        "tenant-acme",
        "device-123",
        legacy_secret="a" * 48,
        clock=lambda: 10,
    )
    value = json.loads(memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY])
    target = next(
        row for row in value["credentials"]
        if row["credential_id"] == credential_id
    )
    target[state_field] = 50
    memory_store.values[INTERNAL_FLEET_CREDENTIALS_KEY] = json.dumps(value)
    with pytest.raises(RuntimeError, match="inactive"):
        load_or_migrate_local_credentials(
            tmp_path, "tenant-acme", "device-123", clock=lambda: 100
        )
