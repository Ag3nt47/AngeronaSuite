from __future__ import annotations

import pytest

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.sensor_provenance import SensorProvenanceBroker, sign_sensor_event
from angerona.core.identity_session import (
    SCHEMA,
    IdentitySessionAnalytics,
    IdentitySessionError,
    IdentitySessionEvidence,
    derive_identity_session_key,
    evidence_from_mapping,
)
from angerona.modules.identity_session_guard import IdentitySessionGuardModule


KEY = derive_identity_session_key(b"I" * 32)


def _analytics(*, max_events: int = 128) -> IdentitySessionAnalytics:
    return IdentitySessionAnalytics(KEY, max_events=max_events, clock=lambda: 1000.0)


def test_device_code_new_device_is_tokenized_and_observe_only() -> None:
    analytics = _analytics()
    analytics.observe(IdentitySessionEvidence(
        900.0,
        "device_code_flow",
        principal_ref="private-person@example.invalid",
        source_ref="private-source",
        outcome="success",
    ), evidence_grade="broker-provenanced")
    result = analytics.observe(IdentitySessionEvidence(
        910.0,
        "new_device",
        principal_ref="private-person@example.invalid",
        device_ref="private-device-id",
        outcome="success",
    ), evidence_grade="broker-provenanced")

    rules = {item.rule_id for item in result.findings}
    assert "identity_session.device_code_new_device" in rules
    assert all(item.response_authorized is False for item in result.findings)
    assert all(item.evidence_grade == "broker-provenanced" for item in result.findings)
    rendered = repr(analytics.retained_events)
    for raw in ("private-person", "private-source", "private-device-id"):
        assert raw not in rendered


@pytest.mark.parametrize("secret", [
    "Bearer abcdefghijklmnopqrstuvwxyz",
    "refresh_token=private",
    "eyJabcdefghijk.abcdefghijkl.abcdefghijkl",
])
def test_secret_or_token_material_is_rejected(secret: str) -> None:
    with pytest.raises(IdentitySessionError, match="secret or token"):
        IdentitySessionEvidence(
            900.0,
            "new_device",
            principal_ref="person",
            device_ref=secret,
        )


def test_luid_and_session_rebinding_are_detected() -> None:
    analytics = _analytics()
    analytics.observe(IdentitySessionEvidence(
        900.0,
        "logon_session",
        principal_ref="first-person",
        luid="0x1234",
        session_ref="session-7",
        device_ref="device-a",
        outcome="success",
    ))
    result = analytics.observe(IdentitySessionEvidence(
        901.0,
        "logon_session",
        principal_ref="second-person",
        luid="0x1234",
        session_ref="session-7",
        device_ref="device-b",
        outcome="success",
    ))
    rules = {item.rule_id for item in result.findings}
    assert {
        "identity_session.luid_rebinding",
        "identity_session.session_rebinding",
    }.issubset(rules)


def test_session_end_releases_association_and_denied_transitions_do_not_correlate() -> None:
    analytics = _analytics()
    analytics.observe(IdentitySessionEvidence(
        900.0,
        "logon_session",
        principal_ref="first-person",
        luid="0x99",
        session_ref="session-99",
        outcome="success",
    ))
    analytics.observe(IdentitySessionEvidence(
        901.0,
        "session_end",
        luid="0x99",
        session_ref="session-99",
        outcome="success",
    ))
    reused = analytics.observe(IdentitySessionEvidence(
        902.0,
        "logon_session",
        principal_ref="second-person",
        luid="0x99",
        session_ref="session-99",
        outcome="success",
    ))
    assert not any("rebinding" in item.rule_id for item in reused.findings)

    analytics.observe(IdentitySessionEvidence(
        903.0,
        "device_code_flow",
        principal_ref="second-person",
        outcome="denied",
    ))
    denied = analytics.observe(IdentitySessionEvidence(
        904.0,
        "new_device",
        principal_ref="second-person",
        device_ref="denied-device",
        outcome="denied",
    ))
    assert not any(
        item.rule_id in {
            "identity_session.new_device_enrollment",
            "identity_session.device_code_new_device",
        }
        for item in denied.findings
    )


def test_browser_store_rmm_and_privilege_transitions_correlate() -> None:
    analytics = _analytics()
    analytics.observe(IdentitySessionEvidence(
        900.0,
        "browser_token_store_access",
        principal_ref="person",
        session_ref="session-1",
        process_ref="browser-process-birth",
        outcome="success",
    ))
    analytics.observe(IdentitySessionEvidence(
        901.0,
        "rmm_session",
        principal_ref="person",
        session_ref="session-1",
        source_ref="remote-source",
        remote=True,
        outcome="success",
    ))
    result = analytics.observe(IdentitySessionEvidence(
        902.0,
        "privilege_change",
        principal_ref="person",
        session_ref="session-1",
        privileged=True,
        remote=True,
        outcome="success",
    ))
    rules = {item.rule_id for item in result.findings}
    assert "identity_session.browser_store_transition" in rules
    assert "identity_session.rmm_privilege_transition" in rules
    assert "identity_session.remote_privilege_transition" in rules


def test_strict_supplied_schema_has_no_secret_or_token_value_field() -> None:
    evidence = evidence_from_mapping({
        "schema": SCHEMA,
        "timestamp": 900.0,
        "kind": "new_device",
        "principal_ref": "person",
        "device_ref": "device",
    })
    assert evidence.kind == "new_device"
    with pytest.raises(IdentitySessionError, match="unknown fields"):
        evidence_from_mapping({
            "schema": SCHEMA,
            "timestamp": 900.0,
            "kind": "new_device",
            "principal_ref": "person",
            "device_ref": "device",
            "access_token": "forbidden",
        })
    with pytest.raises(IdentitySessionError, match="timestamp"):
        IdentitySessionEvidence(
            float("nan"),
            "new_device",
            principal_ref="person",
            device_ref="device",
        )


def test_overflow_and_missing_coverage_are_explicit() -> None:
    analytics = _analytics(max_events=32)
    assert analytics.mark_coverage("missing", "producer gap").state == "missing"
    analytics.mark_coverage("observing", "recovered")
    result = None
    for index in range(33):
        result = analytics.observe(IdentitySessionEvidence(
            900.0 + index,
            "new_device",
            principal_ref=f"person-{index}",
            device_ref=f"device-{index}",
        ))
    assert result is not None
    assert result.state == "overflow"
    assert result.dropped_events == 1
    assert result.raw_values_retained is False


def test_duplicate_index_tracks_capacity_eviction_without_changing_replay_semantics() -> None:
    analytics = _analytics(max_events=32)
    first = IdentitySessionEvidence(
        900.0,
        "new_device",
        principal_ref="first-person",
        device_ref="first-device",
    )
    admitted = analytics.observe(first)
    duplicate = analytics.observe(first)
    assert duplicate.reason == "duplicate tokenized evidence was ignored"
    assert duplicate.retained_events == admitted.retained_events

    for index in range(32):
        analytics.observe(IdentitySessionEvidence(
            901.0 + index,
            "new_device",
            principal_ref=f"person-{index}",
            device_ref=f"device-{index}",
        ))

    # Capacity eviction removed the first digest from both the ordered window
    # and its acceleration index, so the old behavior of admitting it again is
    # preserved exactly.
    first_digest = analytics.tokenize(first).event_digest
    replay_after_eviction = analytics.observe(first)
    assert any(
        row.event_digest == first_digest for row in analytics.retained_events
    )
    assert replay_after_eviction.dropped_events == 2


def test_module_outputs_only_pseudonyms_and_no_response_authority(tmp_path) -> None:
    bus = EventBus()
    module = IdentitySessionGuardModule(
        data_root=tmp_path,
        master_key=b"I" * 32,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    module.observe_evidence(IdentitySessionEvidence(
        900.0,
        "device_code_flow",
        principal_ref="TOP_PRIVATE_PERSON",
        outcome="success",
    ), evidence_grade="broker-provenanced")
    module.observe_evidence(IdentitySessionEvidence(
        901.0,
        "new_device",
        principal_ref="TOP_PRIVATE_PERSON",
        device_ref="TOP_PRIVATE_DEVICE",
        outcome="success",
    ), evidence_grade="broker-provenanced")
    emitted = bus.recent(100)
    assert any(
        event.details.get("finding_code") == "identity_session.device_code_new_device"
        for event in emitted
    )
    assert all(event.details.get("response_authorized") is False for event in emitted)
    assert "TOP_PRIVATE" not in repr(emitted)
    assert module.self_test()[0] is True


def test_live_ingress_queue_immediately_discards_raw_mapping(tmp_path) -> None:
    bus = EventBus()
    module = IdentitySessionGuardModule(
        data_root=tmp_path,
        master_key=b"I" * 32,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    module._active.set()
    event = Event(
        "Structured Identity Producer",
        "supplied",
        Severity.MEDIUM,
        900.0,
        {"identity_session_evidence": {
            "schema": SCHEMA,
            "timestamp": 900.0,
            "kind": "new_device",
            "principal_ref": "QUEUE_PRIVATE_PERSON",
            "device_ref": "QUEUE_PRIVATE_DEVICE",
            "outcome": "success",
        }},
    )
    module._on_bus_event(event)
    assert len(module._pending) == 1
    assert "QUEUE_PRIVATE" not in repr(module._pending)
    module._drain_pending()
    assert not module._pending


def test_schema_only_identity_evidence_is_capped_and_wrong_producer_is_ignored(tmp_path) -> None:
    analytics = _analytics()
    analytics.observe(
        IdentitySessionEvidence(
            900.0,
            "device_code_flow",
            principal_ref="person",
            outcome="success",
        ),
        evidence_grade="schema-admitted-local",
    )
    result = analytics.observe(
        IdentitySessionEvidence(
            901.0,
            "new_device",
            principal_ref="person",
            device_ref="device",
            outcome="success",
        ),
        evidence_grade="schema-admitted-local",
    )
    assert result.findings
    assert all(item.severity == "Medium" for item in result.findings)

    bus = EventBus()
    module = IdentitySessionGuardModule(
        data_root=tmp_path,
        master_key=b"I" * 32,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    module._active.set()
    module._on_bus_event(Event(
        "Arbitrary In-Process Module",
        "supplied",
        Severity.HIGH,
        900.0,
        {"identity_session_evidence": {
            "schema": SCHEMA,
            "timestamp": 900.0,
            "kind": "new_device",
            "principal_ref": "person",
            "device_ref": "device",
        }},
    ))
    assert not module._pending


def test_broker_provenanced_identity_chain_can_retain_high_confidence(tmp_path) -> None:
    now_ns = 7_000_000_000
    broker = SensorProvenanceBroker(b"P" * 32, clock_ns=lambda: now_ns)
    credential = broker.provision("Structured Identity Producer")
    bus = EventBus()
    module = IdentitySessionGuardModule(
        data_root=tmp_path,
        master_key=b"I" * 32,
        provenance_broker=broker,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    module._active.set()
    evidence_rows = (
        {
            "schema": SCHEMA,
            "timestamp": 900.0,
            "kind": "device_code_flow",
            "principal_ref": "person",
            "outcome": "success",
        },
        {
            "schema": SCHEMA,
            "timestamp": 901.0,
            "kind": "new_device",
            "principal_ref": "person",
            "device_ref": "device",
            "outcome": "success",
        },
    )
    for sequence, evidence in enumerate(evidence_rows, start=1):
        envelope = sign_sensor_event(
            credential,
            sequence=sequence,
            reported_loss=0,
            event_type="angerona.identity-session-input.v1",
            event=evidence,
            issued_monotonic_ns=now_ns,
        )
        module._on_bus_event(Event(
            "Broker Transport",
            "supplied",
            Severity.INFO,
            evidence["timestamp"],
            {"sensor_provenance_envelope": envelope},
        ))
    module._drain_pending()
    finding = next(
        event for event in bus.recent(20)
        if event.details.get("finding_code") == "identity_session.device_code_new_device"
    )
    assert finding.severity == Severity.CRITICAL
    assert finding.details["evidence_grade"] == "broker-provenanced"
