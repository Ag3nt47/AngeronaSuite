from __future__ import annotations

import json
from pathlib import Path

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.sensor_provenance import SensorProvenanceBroker, sign_sensor_event
from angerona.core.temporal_tradecraft import (
    TemporalTradecraftEngine,
    derive_temporal_keys,
)
from angerona.modules.temporal_tradecraft_correlator import (
    TemporalTradecraftCorrelatorModule,
)


MASTER = b"T" * 32


def _engine(tmp_path: Path, *, max_signals: int = 64, clock=lambda: 1000.0):
    state_key, privacy_key = derive_temporal_keys(MASTER)
    return TemporalTradecraftEngine(
        tmp_path / "temporal.json",
        state_key=state_key,
        privacy_key=privacy_key,
        max_signals=max_signals,
        clock=clock,
    )


def _event(kind: str, ts: float, private: str = "") -> Event:
    details: dict[str, object]
    if kind == "key":
        details = {
            "finding_code": "ssh.baseline.drift",
            "changes": {"keys_added": [private or "private-key-fingerprint"]},
            "subject_token": private or "private-subject",
        }
    elif kind == "session":
        details = {
            "finding_code": "ssh.logs.successful_key_auth",
            "account_token": private or "private-account",
        }
    elif kind == "tunnel":
        details = {
            "finding_code": "ssh.runtime.client_forwarding_process",
            "process_token": private or "private-process",
        }
    elif kind == "path":
        details = {
            # NetworkTrustFinding.event_details uses finding_type; keep this
            # fixture aligned with the real producer contract.
            "finding_type": "network.default_route_drift",
            "interface_token": private or "private-interface",
        }
    else:
        details = {"classification": "audit-log-cleared", "record_id": 1102}
    if kind in {"key", "session", "tunnel"}:
        module = "SSH Surface / Key / Tunnel Guard"
    elif kind == "path":
        module = "Zero-Trust Network Path Monitor"
    else:
        module = "Audit Log Integrity Guard"
    return Event(module, "private message", Severity.HIGH, ts, details, "signed")


def test_full_sequence_matches_without_retaining_raw_identity(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    result = None
    for offset, kind in enumerate(("key", "session", "tunnel", "path", "clear")):
        result = engine.observe_event(
            _event(kind, 900.0 + offset, private="RAW_PRIVATE_IDENTITY"),
            integrity_verified=True,
            evidence_grade="broker-provenanced",
        )
    assert result is not None
    rules = {item.pattern_id for item in result.findings}
    assert "temporal.ssh_key_session_tunnel_path_log_clear" in rules
    assert all(item.response_authorized is False for item in result.findings)
    assert all(item.evidence_grade == "broker-provenanced" for item in result.findings)
    rendered = repr(engine.retained_signals)
    assert "RAW_PRIVATE_IDENTITY" not in rendered
    assert "SSH Surface / Key / Tunnel Guard" not in rendered
    assert "private message" not in rendered


def test_authenticated_restart_roundtrip_and_signal_attestations(tmp_path: Path) -> None:
    first = _engine(tmp_path)
    first.observe_event(
        _event("key", 900.0),
        integrity_verified=True,
        evidence_grade="broker-provenanced",
    )
    first.observe_event(
        _event("session", 901.0),
        integrity_verified=True,
        evidence_grade="broker-provenanced",
    )
    before = first.retained_signals

    second = _engine(tmp_path)
    assert second.persistence_status == "authenticated"
    assert second.retained_signals == before
    assert all(len(item.attestation) == 64 for item in second.retained_signals)


def test_state_tamper_and_duplicate_fields_fail_closed(tmp_path: Path) -> None:
    first = _engine(tmp_path)
    first.observe_event(
        _event("key", 900.0),
        integrity_verified=True,
        evidence_grade="broker-provenanced",
    )
    state_path = tmp_path / "temporal.json"
    document = json.loads(state_path.read_text(encoding="utf-8"))
    document["document"]["revision"] += 1
    state_path.write_text(json.dumps(document), encoding="utf-8")

    tampered = _engine(tmp_path)
    assert tampered.persistence_status == "untrusted"
    assert tampered.retained_signals == ()
    assert tampered.mark_missing("test").state == "blind"

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        '{"document":{},"document":{},"hmac_sha256":"' + "0" * 64 + '"}',
        encoding="utf-8",
    )
    state_key, privacy_key = derive_temporal_keys(MASTER)
    duplicate = TemporalTradecraftEngine(
        duplicate_path,
        state_key=state_key,
        privacy_key=privacy_key,
        clock=lambda: 1000.0,
    )
    assert duplicate.persistence_status == "untrusted"


def test_missing_blind_and_overflow_are_explicit(tmp_path: Path) -> None:
    engine = _engine(tmp_path, max_signals=16)
    assert engine.mark_missing("restart-gap").state == "missing"
    assert engine.mark_blind("private-sensor").state == "blind"
    recovered = engine.mark_recovered("private-sensor")
    assert recovered.state == "missing"

    result = recovered
    for index in range(17):
        result = engine.observe_event(
            _event("session" if index % 2 else "path", 900.0 + index, str(index)),
            integrity_verified=True,
        )
    assert result.state == "overflow"
    assert result.dropped_signals == 1
    assert result.response_authorized is False


def test_stale_nonmonotonic_and_invalid_event_auth_do_not_complete(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    stale = engine.observe_event(_event("key", 1.0), integrity_verified=True)
    assert stale.state == "missing" and stale.findings == ()
    blind = engine.observe_event(_event("session", 900.0), integrity_verified=False)
    assert blind.state == "blind" and blind.findings == ()

    not_a_number = engine.observe_event(
        _event("session", float("nan")), integrity_verified=True
    )
    assert not_a_number.state == "blind" and not_a_number.findings == ()


def test_ephemeral_mode_never_poison_writes_restart_state(tmp_path: Path) -> None:
    state_key, privacy_key = derive_temporal_keys(MASTER)
    path = tmp_path / "must-not-exist.json"
    engine = TemporalTradecraftEngine(
        path,
        state_key=state_key,
        privacy_key=privacy_key,
        persistence_enabled=False,
        clock=lambda: 1000.0,
    )
    result = engine.observe_event(_event("session", 900.0), integrity_verified=True)
    assert result.state == "blind"
    assert result.persistence_status == "unavailable"
    assert not path.exists()


def test_module_emits_observe_only_sanitized_findings(tmp_path: Path) -> None:
    bus = EventBus()
    module = TemporalTradecraftCorrelatorModule(
        data_root=tmp_path,
        master_key=MASTER,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    for offset, kind in enumerate(("key", "session", "tunnel")):
        module.observe_event(_event(kind, 900.0 + offset, "VERY_PRIVATE"))
    findings = [
        event for event in bus.recent(100)
        if event.details.get("finding_code") == "temporal.ssh_key_session_tunnel"
    ]
    assert findings
    assert all(event.details["response_authorized"] is False for event in findings)
    assert "VERY_PRIVATE" not in repr(findings)
    assert module.self_test()[0] is True


def test_live_ingress_queue_is_bounded_and_contains_no_raw_event(tmp_path: Path) -> None:
    bus = EventBus()
    module = TemporalTradecraftCorrelatorModule(
        data_root=tmp_path,
        master_key=MASTER,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    module._active.set()
    module._on_bus_event(_event("session", 900.0, "QUEUE_PRIVATE_VALUE"))
    assert len(module._pending) == 1
    assert "QUEUE_PRIVATE_VALUE" not in repr(module._pending)
    assert "private message" not in repr(module._pending)
    module._drain_pending()
    assert not module._pending


def test_unprovenanced_or_wrong_producer_cannot_create_high_confidence_campaign(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path)
    spoofed = _event("session", 900.0)
    spoofed = Event(
        "Arbitrary In-Process Module",
        spoofed.message,
        spoofed.severity,
        spoofed.ts,
        spoofed.details,
        spoofed.hmac_sig,
    )
    assert engine.classify(spoofed) is None

    result = None
    for offset, kind in enumerate(("key", "session", "tunnel")):
        result = engine.observe_event(
            _event(kind, 900.0 + offset),
            integrity_verified=True,
            evidence_grade="schema-admitted-local",
        )
    assert result is not None and result.findings
    assert all(item.severity == "Medium" for item in result.findings)
    assert all(item.evidence_grade == "schema-admitted-local" for item in result.findings)


def test_broker_assigned_sensor_identity_preserves_high_confidence(tmp_path: Path) -> None:
    now_ns = 5_000_000_000
    broker = SensorProvenanceBroker(b"P" * 32, clock_ns=lambda: now_ns)
    credential = broker.provision("SSH Surface Key Tunnel Guard")
    bus = EventBus()
    module = TemporalTradecraftCorrelatorModule(
        data_root=tmp_path,
        master_key=MASTER,
        provenance_broker=broker,
        clock=lambda: 1000.0,
    )
    module.bind(bus)
    result = None
    for sequence, kind in enumerate(("key", "session", "tunnel"), start=1):
        inner = _event(kind, 900.0 + sequence)
        envelope = sign_sensor_event(
            credential,
            sequence=sequence,
            reported_loss=0,
            event_type="angerona.temporal-input.v1",
            event={
                "module": inner.module,
                "message": inner.message,
                "severity": int(inner.severity),
                "ts": inner.ts,
                "details": inner.details,
            },
            issued_monotonic_ns=now_ns,
        )
        result = module.observe_event(Event(
            "Broker Transport",
            "supplied",
            Severity.INFO,
            inner.ts,
            {"sensor_provenance_envelope": envelope},
        ))
    assert result is not None and result.findings
    assert all(item.severity == "High" for item in result.findings)
    assert all(item.evidence_grade == "broker-provenanced" for item in result.findings)
