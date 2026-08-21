from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from angerona.core.telemetry_coverage import TelemetryCoverageAccountant
from angerona.core.eventbus import EventBus
from angerona.core.status_report import StatusReporter
from angerona.core.visibility_attestation import (
    FORMAT,
    MAX_CANARY_FAMILIES,
    MAX_DOCUMENT_BYTES,
    VisibilityAttestationRegistry,
    sign_visibility_attestation,
)


AUTHORITY = b"v" * 32
BUILD = "1" * 64
POLICY = "2" * 64


def _payload(
    *,
    sensor_id: str = "etw-core",
    epoch: int = 10,
    sequence: int = 1,
    expected: tuple[str, ...] = ("heartbeat", "process"),
    observed: tuple[str, ...] = ("heartbeat", "process"),
    drops: int = 0,
    issued: int = 1_000,
    expires: int = 1_120,
    clock_quality: str = "synchronized",
) -> dict[str, object]:
    return {
        "format": FORMAT,
        "sensor_id": sensor_id,
        "platform": "windows",
        "build_sha256": BUILD,
        "policy_sha256": POLICY,
        "session_epoch": epoch,
        "sequence": sequence,
        "expected_canary_families": sorted(expected),
        "observed_canary_families": sorted(observed),
        "drop_count": drops,
        "issued_at": issued,
        "expires_at": expires,
        "clock_quality": clock_quality,
    }


def _signed(**kwargs) -> dict[str, object]:
    return sign_visibility_attestation(_payload(**kwargs), AUTHORITY)


def test_canonical_hmac_and_healthy_coverage_integration() -> None:
    payload = _payload()
    reversed_payload = dict(reversed(list(payload.items())))
    first = sign_visibility_attestation(payload, AUTHORITY)
    second = sign_visibility_attestation(reversed_payload, AUTHORITY)
    assert first["hmac_sha256"] == second["hmac_sha256"]

    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    coverage = TelemetryCoverageAccountant(
        clock=lambda: 1_010, visibility_registry=registry
    )
    result = coverage.observe_visibility_attestation(first)
    assert result.classification == "healthy"
    snapshot = coverage.visibility_snapshot(now=1_010)
    assert snapshot["authority_configured"] is True
    assert snapshot["sensors"]["etw-core"]["classification"] == "healthy"
    assert "hardware-backed" in snapshot["limitation"]
    assert "response authority" in snapshot["limitation"]


def test_forgery_is_untrusted_and_cannot_create_registry_identity() -> None:
    document = _signed()
    document["payload"]["sequence"] = 2
    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)

    result = registry.ingest(document)

    assert result.classification == "untrusted"
    assert result.accepted is False
    assert result.reason == "forgery"
    assert registry.snapshot() == {}
    assert registry.rejected_documents == 1


def test_replay_and_sequence_regression_are_rejected_without_lowering_high_water() -> None:
    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    current = _signed(sequence=3)
    assert registry.ingest(current).classification == "healthy"

    replay = registry.ingest(current)
    regression = registry.ingest(_signed(sequence=2))
    recovered = registry.ingest(_signed(sequence=4))

    assert replay.classification == "untrusted"
    assert "replayed" in replay.reason
    assert regression.classification == "untrusted"
    assert "regression" in regression.reason
    assert recovered.classification == "healthy"
    assert registry.snapshot()["etw-core"].sequence == 4


def test_future_clock_is_untrusted_and_expired_attestation_is_blind() -> None:
    registry = VisibilityAttestationRegistry(
        AUTHORITY, clock=lambda: 1_000, future_skew_s=10
    )
    future = registry.ingest(_signed(issued=1_011, expires=1_100))
    stale = registry.ingest(
        _signed(sensor_id="stale-sensor", issued=800, expires=900)
    )

    assert future.classification == "untrusted"
    assert future.reason == "future_clock"
    assert stale.classification == "blind"
    assert stale.accepted is False
    assert "stale" in stale.reason
    assert registry.snapshot()["stale-sensor"].classification == "blind"


@pytest.mark.parametrize(
    ("observed", "expected_classification"),
    [
        (("heartbeat",), "degraded"),
        ((), "blind"),
    ],
)
def test_missing_canary_classification(
    observed: tuple[str, ...], expected_classification: str
) -> None:
    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    result = registry.ingest(_signed(observed=observed))
    assert result.classification == expected_classification
    assert result.missing_canary_families


def test_drop_counter_degrades_and_cannot_regress_in_one_session() -> None:
    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    degraded = registry.ingest(_signed(sequence=1, drops=4))
    regressed = registry.ingest(_signed(sequence=2, drops=3))
    reset_session = registry.ingest(_signed(epoch=11, sequence=0, drops=0))

    assert degraded.classification == "degraded"
    assert "dropped" in degraded.reason
    assert regressed.classification == "untrusted"
    assert "drop counter regression" in regressed.reason
    assert reset_session.classification == "healthy"


def test_registry_eviction_is_bounded_and_lru() -> None:
    registry = VisibilityAttestationRegistry(
        AUTHORITY, max_sensors=2, clock=lambda: 1_010
    )
    registry.ingest(_signed(sensor_id="sensor-a"))
    registry.ingest(_signed(sensor_id="sensor-b"))
    registry.ingest(_signed(sensor_id="sensor-a", sequence=2))
    registry.ingest(_signed(sensor_id="sensor-c"))

    assert set(registry.snapshot()) == {"sensor-a", "sensor-c"}
    assert registry.evicted_sensors == 1


def test_privacy_schema_rejects_paths_users_commands_network_and_actions() -> None:
    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    sensitive_values = {
        "path": r"C:\Users\ExampleUser\secret.txt",
        "username": "ExampleUser",
        "command_line": "powershell -enc secret",
        "remote_address": "203.0.113.44:443",
        "response_action": "kill 1234",
        "raw_telemetry": {"process": "protonvpn.exe"},
    }
    for field, value in sensitive_values.items():
        payload = _payload(sensor_id=f"privacy-{field.replace('_', '-')}")
        payload[field] = value
        # Signing itself fails closed so producers cannot create an expanded document.
        with pytest.raises(ValueError):
            sign_visibility_attestation(payload, AUTHORITY)

    result = registry.ingest(
        json.dumps({"payload": _payload(), "hmac_sha256": "0" * 64, **sensitive_values})
    )
    assert result.classification == "untrusted"
    rendered = json.dumps(vars(result), sort_keys=True)
    for value in ("ExampleUser", "secret.txt", "203.0.113.44", "protonvpn.exe", "kill 1234"):
        assert value not in rendered


def test_strict_key_cardinality_and_dynamic_expiry_bounds() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        VisibilityAttestationRegistry(b"short")
    with pytest.raises(ValueError, match="bound"):
        sign_visibility_attestation(
            _payload(
                expected=tuple(f"family-{index:02d}" for index in range(MAX_CANARY_FAMILIES + 1)),
                observed=(),
            ),
            AUTHORITY,
        )
    with pytest.raises(ValueError, match="lifetime"):
        sign_visibility_attestation(
            _payload(issued=1_000, expires=1_601), AUTHORITY
        )
    oversized = b"{" + (b" " * MAX_DOCUMENT_BYTES) + b"}"
    oversized_result = VisibilityAttestationRegistry(AUTHORITY).ingest(oversized)
    assert oversized_result.classification == "untrusted"
    assert oversized_result.reason == "size"

    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    registry.ingest(_signed(expires=1_020))
    assert registry.snapshot(now=1_020)["etw-core"].classification == "blind"


def test_unconfigured_coverage_is_explicitly_unknown_not_healthy() -> None:
    snapshot = TelemetryCoverageAccountant(clock=lambda: 1_010).visibility_snapshot()
    assert snapshot["authority_configured"] is False
    assert snapshot["sensors"] == {}
    assert "does not prove" in snapshot["limitation"]


def test_status_report_exposes_only_honest_visibility_metadata(tmp_path) -> None:
    registry = VisibilityAttestationRegistry(AUTHORITY, clock=lambda: 1_010)
    coverage = TelemetryCoverageAccountant(visibility_registry=registry)
    coverage.observe_visibility_attestation(_signed())
    reporter = StatusReporter(
        EventBus(),
        SimpleNamespace(count_since=lambda _since: 0),
        SimpleNamespace(modules={}, is_enabled=lambda _name: False),
        SimpleNamespace(data_dir=tmp_path, ollama_host="local", ollama_model="test"),
        telemetry_coverage=coverage,
    )

    snapshot = reporter._snapshot()
    visibility = snapshot["sensor_visibility_attestations"]
    assert visibility["sensors"]["etw-core"]["classification"] == "healthy"
    assert "hardware-backed" in visibility["limitation"]
    text = reporter._render_text(snapshot)
    assert "SENSOR VISIBILITY ATTESTATIONS" in text
    assert "etw-core" in text
    for forbidden in ("command_line", "username", "remote_address", "response_action"):
        assert forbidden not in json.dumps(visibility)
