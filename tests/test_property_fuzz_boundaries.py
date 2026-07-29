"""Deterministic property fuzzing for Angerona's untrusted data boundaries.

These tests are development-only.  They use no network, retain no example
database, and deliberately derive the same cases on every run so a CI failure
can be replayed offline.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from angerona.core.backup_restore import _parse_header, _parse_manifest, _relative
from angerona.core.capability_manifest import ManifestError, parse_manifest
from angerona.core.detection_packages import (
    PackageValidationError,
    seal_package,
    validate_package,
)
from angerona.core.fleet_service import RequestAuthenticator, sign_request
from angerona.core.sensor_events import SensorEvent, SensorEventError

FUZZ = settings(
    max_examples=120,
    deadline=None,
    database=None,
    derandomize=True,
    suppress_health_check=(HealthCheck.function_scoped_fixture,),
)

JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=96),
)
JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(max_size=40), children, max_size=8),
    ),
    max_leaves=24,
)


def _sensor_event() -> dict:
    return {
        "schema_version": 1,
        "event_id": "event-001",
        "observed_at": 1_000.0,
        "platform": "windows",
        "sensor": "property-fuzzer",
        "kind": "process",
        "action": "create",
        "process": {},
        "file": {},
        "network": {},
        "security": {},
        "privacy_classes": [],
    }


def _capability_manifest() -> dict:
    return {
        "schema_version": 1,
        "id": "sample.plugin",
        "name": "Sample plugin",
        "version": "1.0.0",
        "api_version": "1",
        "entrypoint": "sample.py",
        "sha256": "0" * 64,
        "permissions": ["event.emit"],
        "events": {"inputs": [], "outputs": []},
        "mitre": [],
        "privacy": {
            "data_classes": ["none"],
            "egress": "none",
            "retention": "memory",
        },
        "performance": {
            "cpu_budget_pct": 5.0,
            "memory_budget_mb": 128,
            "poll_interval_s": 1.0,
        },
        "publisher": "",
        "signature": "",
    }


def _detection_package() -> dict:
    return seal_package({
        "schema_version": 1,
        "id": "org.angerona.property-test",
        "version": "1.0.0",
        "owner": "Angerona",
        "description": "Bounded parser property fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "low",
        "confidence": 80,
        "logic": {
            "type": "sigma-subset",
            "detection": {
                "selection": {"image|endswith": "example.exe"},
                "condition": "selection",
            },
        },
        "fixtures": [{
            "name": "safe miss",
            "event": {"image": "other.exe"},
            "expected_match": False,
        }],
        "performance": {
            "max_eval_ms": 50,
            "max_events_per_second": 1_000,
        },
        "rollback": {
            "previous_digest": None,
            "instructions": "Disable the property fixture.",
        },
        "expires_at": "2035-01-01T00:00:00Z",
    })


def _backup_manifest() -> dict:
    return {
        "schema": "angerona.backup/v1",
        "backup_id": "backup-001",
        "source_scope": "endpoint-001",
        "created_at": 1_000.0,
        "items": [{
            "relative_path": "state/settings.json",
            "kind": "file",
            "privacy_class": "restricted",
            "sha256": "0" * 64,
            "size_bytes": 0,
        }],
        "total_bytes": 0,
    }


@FUZZ
@given(
    field=st.sampled_from(tuple(_sensor_event())),
    value=JSON_VALUE,
)
def test_sensor_event_mutations_normalize_or_raise_documented_error(field, value):
    payload = _sensor_event()
    payload[field] = value
    try:
        event = SensorEvent.from_dict(payload)
    except SensorEventError:
        return
    assert SensorEvent.from_dict(event.as_dict()).as_dict() == event.as_dict()


def test_sensor_event_mixed_unknown_fields_and_list_types_fail_closed():
    with pytest.raises(SensorEventError, match="2 unknown"):
        SensorEvent.from_dict({**_sensor_event(), 7: "hidden", "extra": True})
    malformed = _sensor_event()
    malformed["process"] = {"ancestors": ["safe.exe", 7]}
    with pytest.raises(SensorEventError, match="only strings"):
        SensorEvent.from_dict(malformed)


@FUZZ
@given(
    field=st.sampled_from(tuple(_capability_manifest())),
    value=JSON_VALUE,
)
def test_capability_manifest_mutations_accept_or_raise_manifest_error(field, value):
    document = _capability_manifest()
    document[field] = value
    try:
        manifest = parse_manifest(document, Path("sample.py"))
    except ManifestError:
        return
    assert manifest.entrypoint == "sample.py"
    assert manifest.capability_id == "sample.plugin"


def test_capability_manifest_rejects_schema_smuggling():
    document = _capability_manifest()
    document["execute_after_verify"] = True
    with pytest.raises(ManifestError, match="1 unknown"):
        parse_manifest(document, Path("sample.py"))


@FUZZ
@given(
    field=st.sampled_from(tuple(_detection_package())),
    value=JSON_VALUE,
)
def test_detection_package_mutations_accept_or_raise_package_error(field, value):
    document = _detection_package()
    document[field] = value
    try:
        accepted = validate_package(
            document,
            now=datetime(2030, 1, 1, tzinfo=timezone.utc),
            verify_digest=False,
        )
    except PackageValidationError:
        return
    assert accepted["id"] == "org.angerona.property-test"


def test_detection_package_mixed_unknown_fields_fail_closed():
    document = _detection_package()
    document[7] = "hidden"
    document["extra"] = True
    with pytest.raises(PackageValidationError, match="2 unknown"):
        validate_package(document, verify_digest=False)


@FUZZ
@given(
    method=st.one_of(JSON_VALUE, st.text(max_size=64)),
    path=st.one_of(JSON_VALUE, st.text(max_size=256)),
    headers=st.dictionaries(st.text(max_size=40), JSON_VALUE, max_size=10),
    body=st.one_of(JSON_VALUE, st.binary(max_size=512)),
)
def test_fleet_authenticator_denies_malformed_inputs_without_exception(
    tmp_path, method, path, headers, body,
):
    authenticator = RequestAuthenticator(
        b"k" * 32,
        tmp_path / "malformed-replay.json",
        clock=lambda: 1_000,
    )
    result = authenticator.verify(method, path, headers, body)
    assert result[0] is False
    assert isinstance(result[1], str)


@FUZZ
@given(
    method=st.sampled_from(("GET", "POST", "DELETE")),
    path=st.text(
        alphabet=st.characters(
            whitelist_categories=("Ll", "Lu", "Nd"),
            whitelist_characters="/?=&_-.",
        ),
        min_size=1,
        max_size=96,
    ),
    body=st.binary(max_size=512),
    suffix=st.binary(min_size=1, max_size=32),
)
def test_fleet_authentication_binds_exact_body_bytes(
    tmp_path, method, path, body, suffix,
):
    key = b"k" * 32
    headers = sign_request(
        key,
        method,
        path,
        body,
        timestamp=1_000,
        nonce="property-fuzz-nonce-123456789",
    )
    authenticator = RequestAuthenticator(
        key,
        tmp_path / "mutation-replay.json",
        clock=lambda: 1_000,
    )
    ok, _reason = authenticator.verify(method, path, headers, body + suffix)
    assert not ok


@FUZZ
@given(value=st.one_of(JSON_VALUE, st.binary(max_size=96)))
def test_backup_header_parser_accepts_exact_schema_or_value_error(value):
    try:
        parsed = _parse_header(value)
    except ValueError:
        return
    assert set(parsed) == {"schema", "backup_id", "salt", "nonce"}


@FUZZ
@given(
    field=st.sampled_from(tuple(_backup_manifest())),
    value=JSON_VALUE,
)
def test_backup_manifest_mutations_accept_or_raise_value_error(field, value):
    document = copy.deepcopy(_backup_manifest())
    document[field] = value
    try:
        manifest = _parse_manifest(document)
    except ValueError:
        return
    assert manifest.backup_id == "backup-001"
    assert manifest.total_bytes == sum(item.size_bytes for item in manifest.items)


@FUZZ
@given(value=st.text(max_size=700))
def test_backup_relative_paths_never_escape_or_use_windows_aliases(value):
    try:
        path = _relative(value)
    except ValueError:
        return
    assert not path.is_absolute()
    assert ".." not in path.parts
    assert all(":" not in part for part in path.parts)


@pytest.mark.parametrize(
    "unsafe",
    (
        "../outside.json",
        "state/../../outside.json",
        "state/events.db:secret",
        "NUL",
        "aux.txt",
        "state/COM1.log",
        "state/trailing.",
        "state/trailing ",
    ),
)
def test_backup_paths_reject_traversal_ads_and_device_aliases(unsafe):
    with pytest.raises(ValueError, match="safe relative"):
        _relative(unsafe)
