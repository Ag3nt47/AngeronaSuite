from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.device_security_lab import (
    MAX_EVIDENCE_BYTES,
    MAX_OBSERVATIONS,
    ConnectionKind,
    ConnectionObservation,
    DeviceLabError,
    DeviceSecurityLab,
    EvidenceEnvelope,
)


AUTHORITY = b"device-lab-controller-authority" * 2


class MutableClock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _public_raw(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _observation(
    connection: ConnectionKind = ConnectionKind.WIFI,
    *,
    source: str = "enrolled_agent",
    observed_at: int = 1_000,
    **attributes: object,
) -> ConnectionObservation:
    defaults: dict[str, object] = {
        "supported": True,
        "present": True,
        "software_version_status": "current",
        "configuration_baseline": "compliant",
    }
    defaults.update(attributes)
    return ConnectionObservation(connection, source, observed_at, defaults)


def _enroll_agent(tmp_path, clock: MutableClock):
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    private = Ed25519PrivateKey.generate()
    pending, challenge = lab.create_enrollment(
        "Authorized lab device", True, evidence_source="enrolled_agent"
    )
    signature = lab.build_enrollment_proof(challenge, private)
    active = lab.confirm_enrollment(pending.enrollment_id, signature, _public_raw(private))
    return lab, private, active


def test_explicit_authorization_is_required_and_identifiers_are_rejected(tmp_path) -> None:
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY)
    with pytest.raises(DeviceLabError) as denied:
        lab.create_enrollment("Lab device", False)
    assert denied.value.code == "authorization_required"

    for identifying_label in (
        "192.0.2.4",
        "aa:bb:cc:dd:ee:ff",
        r"C:\Users\person",
        "operator@example.test",
    ):
        with pytest.raises(DeviceLabError) as private:
            lab.create_enrollment(identifying_label, True)
        assert private.value.code == "privacy"


def test_ed25519_enrollment_proves_possession_and_stores_only_public_material(
    tmp_path,
) -> None:
    clock = MutableClock()
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    private = Ed25519PrivateKey.generate()
    pending, challenge = lab.create_enrollment("Travel laptop", True)
    proof = lab.build_enrollment_proof(challenge, private)

    record = lab.confirm_enrollment(pending.enrollment_id, proof, _public_raw(private))

    assert record.status == "active"
    assert len(record.public_key_fingerprint) == 64
    state = json.loads((tmp_path / "device_security_lab_state.json").read_text("utf-8"))
    serialized = json.dumps(state, sort_keys=True)
    assert "private" not in serialized.casefold()
    assert "sealed" not in serialized.casefold()
    assert base64.urlsafe_b64encode(_public_raw(private)).decode("ascii") in serialized
    assert len(lab.audit_log()) == 2


def test_forged_or_replayed_enrollment_challenge_fails_closed(tmp_path) -> None:
    clock = MutableClock()
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    legitimate = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    pending, challenge = lab.create_enrollment("Authorized endpoint", True)
    forged = lab.build_enrollment_proof(challenge, attacker)

    with pytest.raises(DeviceLabError) as rejected:
        lab.confirm_enrollment(pending.enrollment_id, forged, _public_raw(legitimate))
    assert rejected.value.code == "forgery"
    with pytest.raises(DeviceLabError) as consumed:
        lab.confirm_enrollment(
            pending.enrollment_id,
            lab.build_enrollment_proof(challenge, legitimate),
            _public_raw(legitimate),
        )
    assert consumed.value.code == "challenge"


def test_expired_challenge_and_wrong_confirmation_path_are_rejected(tmp_path) -> None:
    clock = MutableClock()
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock, challenge_ttl_s=5)
    private = Ed25519PrivateKey.generate()
    pending, challenge = lab.create_enrollment("Remote lab", True)
    clock.value = challenge.expires_at
    with pytest.raises(DeviceLabError) as expired:
        lab.confirm_enrollment(
            pending.enrollment_id,
            lab.build_enrollment_proof(challenge, private),
            _public_raw(private),
        )
    assert expired.value.code == "expired"

    pending, _ = lab.create_enrollment("This computer", True, evidence_source="local")
    with pytest.raises(DeviceLabError) as wrong_path:
        lab.confirm_enrollment(pending.enrollment_id, b"0" * 64, _public_raw(private))
    assert wrong_path.value.code == "source"


def test_signed_agent_evidence_produces_deterministic_guidance(tmp_path) -> None:
    clock = MutableClock()
    lab, private, record = _enroll_agent(tmp_path, clock)
    observations = (
        _observation(
            security_protocol="open",
            firewall_enabled=False,
            randomized_mac=False,
            hotspot_enabled=True,
        ),
        _observation(
            ConnectionKind.USB,
            autorun_enabled=True,
            device_control_policy="unrestricted",
            unsigned_driver_present=True,
        ),
        _observation(
            ConnectionKind.BLUETOOTH,
            enabled=True,
            discoverable=True,
            paired_count=2,
            legacy_pairing_allowed=True,
        ),
        _observation(
            ConnectionKind.ETHERNET,
            firewall_enabled=True,
            listening_ports=[443, 445, 3389],
            network_profile="private",
            ieee8021x_enabled=False,
            interface_count=1,
            up_count=1,
        ),
    )
    evidence = lab.sign_evidence(record.enrollment_id, observations, private, sequence=0)

    report = lab.assess(record.enrollment_id, observations, evidence=evidence)

    assert report.outcome == "needs_attention"
    findings = {item.finding_id: item for item in report.findings}
    assert "dsl-wifi-weak_wireless_security" in findings
    assert "dsl-usb-usb_autorun" in findings
    assert "dsl-bluetooth-bluetooth_discoverable" in findings
    assert "dsl-ethernet-sensitive_listener" in findings
    assert all(item.remediation and item.patch_guidance and item.response_options for item in findings.values())
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert "192.0.2." not in rendered
    assert "aa:bb:" not in rendered
    assert "ssid" not in rendered.casefold()
    assert "command_line" not in rendered


def test_evidence_forgery_target_swap_mismatch_and_replay_are_rejected(tmp_path) -> None:
    clock = MutableClock()
    lab, private, record = _enroll_agent(tmp_path, clock)
    observations = (_observation(security_protocol="wpa3"),)
    evidence = lab.sign_evidence(record.enrollment_id, observations, private, sequence=7)
    tampered = evidence.to_dict()
    tampered["payload"]["observations"][0]["attributes"]["security_protocol"] = "open"
    with pytest.raises(DeviceLabError) as forgery:
        lab.assess(
            record.enrollment_id,
            (ConnectionObservation.from_dict(tampered["payload"]["observations"][0]),),
            evidence=tampered,
        )
    assert forgery.value.code == "forgery"

    mismatch = (_observation(security_protocol="wpa2"),)
    with pytest.raises(DeviceLabError) as mismatched:
        lab.assess(record.enrollment_id, mismatch, evidence=evidence)
    assert mismatched.value.code == "forgery"

    assert lab.assess(record.enrollment_id, observations, evidence=evidence).outcome == "pass"
    with pytest.raises(DeviceLabError) as replay:
        lab.assess(record.enrollment_id, observations, evidence=evidence)
    assert replay.value.code == "replay"

    other_lab = DeviceSecurityLab(tmp_path / "other", authority=AUTHORITY, clock=clock)
    other_private = Ed25519PrivateKey.generate()
    pending, challenge = other_lab.create_enrollment("Second device", True)
    other = other_lab.confirm_enrollment(
        pending.enrollment_id,
        other_lab.build_enrollment_proof(challenge, other_private),
        _public_raw(other_private),
    )
    swapped = other_lab.sign_evidence(other.enrollment_id, observations, other_private, sequence=0)
    with pytest.raises(DeviceLabError) as wrong_target:
        lab.assess(record.enrollment_id, observations, evidence=swapped)
    assert wrong_target.value.code == "scope"


def test_stale_future_and_unsigned_remote_evidence_are_rejected(tmp_path) -> None:
    clock = MutableClock()
    lab, private, record = _enroll_agent(tmp_path, clock)
    observations = (_observation(security_protocol="wpa3"),)
    with pytest.raises(DeviceLabError) as unsigned:
        lab.assess(record.enrollment_id, observations)
    assert unsigned.value.code == "authentication_required"

    stale = lab.sign_evidence(record.enrollment_id, observations, private, sequence=0)
    clock.value = stale.expires_at
    with pytest.raises(DeviceLabError) as expired:
        lab.assess(record.enrollment_id, observations, evidence=stale)
    assert expired.value.code == "stale"

    clock.value = 1_000
    future_observations = (_observation(observed_at=1_100, security_protocol="wpa3"),)
    future = lab.sign_evidence(
        record.enrollment_id, future_observations, private, sequence=1, issued_at=1_100
    )
    with pytest.raises(DeviceLabError) as future_clock:
        lab.assess(record.enrollment_id, future_observations, evidence=future)
    assert future_clock.value.code == "future_clock"


def test_local_enrollment_is_controller_authenticated_and_never_accepts_agent_envelope(
    tmp_path,
) -> None:
    clock = MutableClock()
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    pending, _ = lab.create_enrollment(
        "This computer", True, evidence_source="local", allowed_connections=["ethernet"]
    )
    record = lab.confirm_local_enrollment(pending.enrollment_id, owner_attested=True)
    observations = (
        _observation(
            ConnectionKind.ETHERNET,
            source="local",
            firewall_enabled=True,
            listening_ports=[443],
            network_profile="private",
            ieee8021x_enabled=True,
            interface_count=1,
            up_count=1,
        ),
    )
    assert not record.public_key_fingerprint
    assert lab.assess(record.enrollment_id, observations).outcome == "pass"

    private = Ed25519PrivateKey.generate()
    envelope = lab.sign_evidence(record.enrollment_id, observations, private, sequence=0)
    with pytest.raises(DeviceLabError) as wrong_source:
        lab.assess(record.enrollment_id, observations, evidence=envelope)
    assert wrong_source.value.code == "source"


def test_passive_local_collection_has_bounded_redacted_schema(tmp_path) -> None:
    clock = MutableClock()
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    pending, _ = lab.create_enrollment("This computer", True, evidence_source="local")
    record = lab.confirm_local_enrollment(pending.enrollment_id, owner_attested=True)
    with pytest.raises(DeviceLabError) as denied:
        lab.collect_local_observations(record.enrollment_id, owner_attested=False)
    assert denied.value.code == "authorization_required"

    observations = lab.collect_local_observations(record.enrollment_id, owner_attested=True)

    assert 1 <= len(observations) <= len(ConnectionKind)
    assert all(item.source == "local" for item in observations)
    rendered = json.dumps([item.to_dict() for item in observations], sort_keys=True)
    for forbidden in ("address", "hostname", "mac", "pid", "process", "ssid", "username"):
        assert forbidden not in rendered.casefold()


def test_observation_schema_rejects_arbitrary_targets_and_oversized_evidence(tmp_path) -> None:
    for forbidden, value in {
        "target": "remote-device",
        "ip": "192.0.2.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "ssid": "private-network",
        "command": "scan --target host",
        "path": r"C:\Users\person",
    }.items():
        with pytest.raises(DeviceLabError) as rejected:
            ConnectionObservation(
                ConnectionKind.WIFI,
                "local",
                1_000,
                {"supported": True, forbidden: value},
            )
        assert rejected.value.code == "privacy"

    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY)
    observation = _observation()
    with pytest.raises(DeviceLabError) as too_many:
        lab._normalize_observations([observation] * (MAX_OBSERVATIONS + 1))
    assert too_many.value.code == "cardinality"
    assert MAX_EVIDENCE_BYTES <= 64 * 1024


def test_connection_scope_and_attribute_types_fail_closed(tmp_path) -> None:
    clock = MutableClock()
    lab = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    pending, _ = lab.create_enrollment(
        "Wired sensor", True, evidence_source="local", allowed_connections=["ethernet"]
    )
    record = lab.confirm_local_enrollment(pending.enrollment_id, owner_attested=True)
    wifi = (_observation(source="local", security_protocol="wpa3"),)
    with pytest.raises(DeviceLabError) as scope:
        lab.assess(record.enrollment_id, wifi)
    assert scope.value.code == "scope"

    with pytest.raises(DeviceLabError) as invalid_bool:
        _observation(firewall_enabled="yes")
    assert invalid_bool.value.code == "schema"
    with pytest.raises(DeviceLabError) as invalid_port:
        _observation(ConnectionKind.ETHERNET, listening_ports=[0, 70000])
    assert invalid_port.value.code == "bounds"


def test_authenticated_state_reloads_and_tampering_is_detected(tmp_path) -> None:
    clock = MutableClock()
    lab, private, record = _enroll_agent(tmp_path, clock)
    reloaded = DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    assert reloaded.list_enrollments()[0].authenticator == record.authenticator
    observations = (_observation(security_protocol="wpa3"),)
    evidence = reloaded.sign_evidence(record.enrollment_id, observations, private, sequence=0)
    assert reloaded.assess(record.enrollment_id, observations, evidence=evidence).outcome == "pass"

    state_path = tmp_path / "device_security_lab_state.json"
    state = json.loads(state_path.read_text("utf-8"))
    state["records"][0]["record"]["allowed_connections"] = ["usb"]
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(DeviceLabError) as forged:
        DeviceSecurityLab(tmp_path, authority=AUTHORITY, clock=clock)
    assert forged.value.code == "forgery"


def test_imported_evidence_schema_is_strict_and_bounded(tmp_path) -> None:
    clock = MutableClock()
    lab, private, record = _enroll_agent(tmp_path, clock)
    observations = (_observation(security_protocol="wpa3"),)
    evidence = lab.sign_evidence(record.enrollment_id, observations, private, sequence=0)
    decoded = EvidenceEnvelope.from_dict(evidence.to_dict())
    assert decoded == evidence

    expanded = evidence.to_dict()
    expanded["payload"]["target"] = "remote-host"
    with pytest.raises(DeviceLabError) as extra:
        EvidenceEnvelope.from_dict(expanded)
    assert extra.value.code == "schema"

    oversized = evidence.to_dict()
    oversized["payload"]["observations"] = [
        observations[0].to_dict() for _ in range(MAX_OBSERVATIONS + 1)
    ]
    with pytest.raises(DeviceLabError) as too_many:
        EvidenceEnvelope.from_dict(oversized)
    assert too_many.value.code == "cardinality"
