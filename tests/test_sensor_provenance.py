from __future__ import annotations

import copy
import json

import pytest

from angerona.core.sensor_provenance import (
    MAX_EVENT_AGE_NS,
    SensorProvenanceBroker,
    SensorProvenanceError,
    sign_sensor_event,
)


class Clock:
    def __init__(self, value: int = 1_000_000_000_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _event(credential, clock: Clock, sequence: int = 1, reported_loss: int = 0):
    return sign_sensor_event(
        credential,
        sequence=sequence,
        reported_loss=reported_loss,
        issued_monotonic_ns=clock.value,
        event_type="process.start",
        event={"pid": 41, "image_sha256": "a" * 64},
    )


def test_broker_is_explicitly_unconfigured_and_callers_cannot_choose_authority() -> None:
    broker = SensorProvenanceBroker()

    assert broker.health().state == "unconfigured"
    with pytest.raises(SensorProvenanceError) as caught:
        broker.provision("sysmon")
    assert caught.value.code == "unconfigured"
    with pytest.raises(TypeError):
        broker.provision("sysmon", sensor_id="caller-chosen")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        SensorProvenanceBroker(b"short")


def test_broker_assigns_immutable_distinct_identities_and_per_sensor_keys() -> None:
    clock = Clock()
    broker = SensorProvenanceBroker(b"b" * 32, clock_ns=clock)
    first = broker.provision("process-sensor")
    second = broker.provision("network-sensor")

    assert first.sensor_id != second.sensor_id
    assert first.key != second.key
    assert first.broker_instance == second.broker_instance == broker.broker_instance
    assert "<redacted>" in repr(first)
    assert first.key.hex() not in repr(first)
    with pytest.raises(Exception):
        first.sensor_id = "sensor-" + "0" * 32  # type: ignore[misc]

    accepted = broker.ingest(_event(first, clock))
    assert accepted.sensor_id == first.sensor_id
    assert accepted.sequence == 1
    assert accepted.coverage_state == "ready"
    assert broker.status(first.sensor_id).state == "ready"
    # A provisioned but silent sensor means the broker cannot claim complete coverage.
    assert broker.health().state == "degraded"


def test_identity_substitution_tamper_replay_and_foreign_broker_fail_closed() -> None:
    clock = Clock()
    broker = SensorProvenanceBroker(b"b" * 32, clock_ns=clock)
    first = broker.provision("first")
    second = broker.provision("second")
    original = _event(first, clock)

    substituted = copy.deepcopy(original)
    substituted["payload"]["sensor_id"] = second.sensor_id
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(substituted)
    assert caught.value.code == "authentication"

    tampered = copy.deepcopy(original)
    tampered["payload"]["event"]["pid"] = 99
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(tampered)
    assert caught.value.code == "authentication"

    broker.ingest(original)
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(original)
    assert caught.value.code == "replay"

    foreign = SensorProvenanceBroker(b"f" * 32, clock_ns=clock)
    foreign_credential = foreign.provision("foreign")
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(_event(foreign_credential, clock))
    assert caught.value.code == "identity"


def test_sequence_gaps_and_source_loss_are_preserved_as_degraded_evidence() -> None:
    clock = Clock()
    broker = SensorProvenanceBroker(b"k" * 32, clock_ns=clock)
    credential = broker.provision("etw")

    broker.ingest(_event(credential, clock, 1))
    gap = broker.ingest(_event(credential, clock, 4, reported_loss=2))

    assert gap.sequence_gap == 2
    assert gap.observed_gap_total == 2
    assert gap.reported_loss == 2
    assert gap.coverage_state == "degraded"
    status = broker.status(credential.sensor_id)
    assert status.state == "degraded"
    assert status.reason == "telemetry-loss-observed"

    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(_event(credential, clock, 5, reported_loss=1))
    assert caught.value.code == "loss-regression"


def test_consumer_schema_rejection_does_not_advance_sensor_continuity() -> None:
    clock = Clock()
    broker = SensorProvenanceBroker(b"s" * 32, clock_ns=clock)
    credential = broker.provision("process-sensor")
    envelope = _event(credential, clock, sequence=1)

    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(
            envelope,
            expected_label="process-sensor",
            expected_event_type="process.exec",
            event_validator=lambda event: event.get("pid") == 41,
        )
    assert caught.value.code == "consumer-schema"
    rejected = broker.status(credential.sensor_id)
    assert rejected.last_sequence == 0
    assert rejected.accepted_events == 0
    assert rejected.state == "unconfigured"

    accepted = broker.ingest(
        envelope,
        expected_label="process-sensor",
        expected_event_type="process.start",
        event_validator=lambda event: event.get("pid") == 41,
    )
    assert accepted.sequence == 1
    assert accepted.coverage_state == "ready"


def test_time_schema_size_revocation_and_duplicate_json_bounds_fail_closed() -> None:
    clock = Clock()
    broker = SensorProvenanceBroker(b"k" * 32, clock_ns=clock)
    credential = broker.provision("event-log")

    stale = sign_sensor_event(
        credential,
        sequence=1,
        reported_loss=0,
        issued_monotonic_ns=clock.value - MAX_EVENT_AGE_NS - 1,
        event_type="event-log.record",
        event={"record_id": 7},
    )
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(stale)
    assert caught.value.code == "expired"

    with pytest.raises(SensorProvenanceError) as caught:
        sign_sensor_event(
            credential,
            sequence=1,
            reported_loss=0,
            issued_monotonic_ns=clock.value,
            event_type="event-log.record",
            event={"oversized": "x" * 5000},
        )
    assert caught.value.code == "bounds"

    wrapper = _event(credential, clock)
    duplicate = json.dumps(wrapper).replace(
        '"hmac_sha256":', '"hmac_sha256":"' + "0" * 64 + '","hmac_sha256":', 1
    )
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(duplicate)
    assert caught.value.code == "schema"

    broker.revoke(credential.sensor_id)
    with pytest.raises(SensorProvenanceError) as caught:
        broker.ingest(wrapper)
    assert caught.value.code == "revoked"
