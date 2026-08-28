"""Fail-closed trusted-time appraisal for security evidence.

Local wall time is compared with monotonic time inside one boot.  A boot change
ends that local continuity claim.  An optional Personal Sentinel receipt adds
an independently signed time observation, but it does not make the host clock
or boot measurements intrinsically trustworthy.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import platform
import time
from dataclasses import dataclass
from typing import Callable

import psutil

from angerona.core.personal_sentinel_authority import (
    SentinelVerifier,
    SentinelResponseFloor,
    SignedTimeReceipt,
    TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE,
)


@dataclass(frozen=True)
class LocalTimeSample:
    wall_time: float
    monotonic_time: float
    boot_id: str

    def __post_init__(self) -> None:
        for label, value in (
            ("wall time", self.wall_time),
            ("monotonic time", self.monotonic_time),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or float(value) < 0.0
            ):
                raise ValueError(f"{label} is invalid")
        if (
            not isinstance(self.boot_id, str)
            or not 16 <= len(self.boot_id) <= 128
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in self.boot_id)
        ):
            raise ValueError("boot identity token is invalid")


@dataclass(frozen=True)
class TrustedTimeAssessment:
    state: str
    continuity_valid: bool
    independently_witnessed: bool
    response_authorized: bool
    drift_seconds: float | None
    witness_sequence: int
    reasons: tuple[str, ...]

    def event_details(self) -> dict:
        return {
            "schema": "angerona.trusted-time-assessment.v1",
            "state": self.state,
            "continuity_valid": self.continuity_valid,
            "independently_witnessed": self.independently_witnessed,
            "drift_seconds": self.drift_seconds,
            "witness_sequence": self.witness_sequence,
            "reason_codes": list(self.reasons),
            "raw_clock_or_host_identifiers_omitted": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


def capture_local_time_sample(
    *,
    wall_clock: Callable[[], float] = time.time,
    monotonic_clock: Callable[[], float] = time.monotonic,
    boot_time_source: Callable[[], float] = psutil.boot_time,
) -> LocalTimeSample:
    """Capture a privacy-safe OS-reported boot token and both local clocks.

    The token is useful for continuity bookkeeping only.  It is not hardware
    attestation and a compromised kernel can falsify every input.
    """

    boot_material = (
        f"{platform.system().casefold()}|{platform.machine().casefold()}|"
        f"{float(boot_time_source()):.6f}"
    ).encode("utf-8")
    return LocalTimeSample(
        float(wall_clock()),
        float(monotonic_clock()),
        hashlib.sha256(boot_material).hexdigest(),
    )


def assess_trusted_time(
    current: LocalTimeSample,
    *,
    previous: LocalTimeSample | None = None,
    witness: SignedTimeReceipt | None = None,
    verifier: SentinelVerifier | None = None,
    expected_installation_id: str = "",
    expected_client_instance_id: str = "",
    expected_witness_challenge: str = "",
    witness_floor: SentinelResponseFloor | None = None,
    max_local_drift: float = 5.0,
    max_witness_difference: float = 30.0,
) -> TrustedTimeAssessment:
    """Appraise local continuity and an optional signed external witness.

    ``continuity_valid`` means only that the two local clocks progressed
    consistently in the same boot.  ``independently_witnessed`` requires a
    valid, fresh receipt with the expected identities.  Neither field grants
    response authority.
    """

    if not isinstance(current, LocalTimeSample):
        raise TypeError("current trusted-time sample is invalid")
    if previous is not None and not isinstance(previous, LocalTimeSample):
        raise TypeError("previous trusted-time sample is invalid")
    for label, value in (
        ("local drift bound", max_local_drift),
        ("witness difference bound", max_witness_difference),
    ):
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or not 0.1 <= float(value) <= 300.0
        ):
            raise ValueError(f"{label} is invalid")
    if not isinstance(expected_witness_challenge, str):
        raise ValueError("expected witness challenge is invalid")
    if expected_witness_challenge and (
        not 32 <= len(expected_witness_challenge) <= 128
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            for character in expected_witness_challenge
        )
    ):
        raise ValueError("expected witness challenge is invalid")

    reasons: list[str] = []
    drift: float | None = None
    continuity_valid = False
    boot_changed = False
    local_compromise_signal = False
    if previous is None:
        reasons.append("no-prior-local-sample")
    elif current.boot_id != previous.boot_id:
        boot_changed = True
        reasons.append("boot-changed-local-continuity-ended")
    else:
        monotonic_delta = current.monotonic_time - previous.monotonic_time
        wall_delta = current.wall_time - previous.wall_time
        if monotonic_delta < 0.0:
            reasons.append("monotonic-rollback-same-boot")
            local_compromise_signal = True
        else:
            drift = abs(wall_delta - monotonic_delta)
            if wall_delta < -float(max_local_drift):
                reasons.append("wall-clock-rollback")
                local_compromise_signal = True
            elif drift > float(max_local_drift):
                reasons.append("wall-monotonic-discontinuity")
                local_compromise_signal = True
            else:
                continuity_valid = True

    independently_witnessed = False
    historical_witness = False
    witness_sequence = 0
    if witness is None:
        reasons.append("external-time-witness-absent")
    elif verifier is None:
        reasons.append("external-time-witness-verifier-absent")
    elif not isinstance(witness, SignedTimeReceipt):
        reasons.append("external-time-witness-contract-invalid")
    else:
        witness_sequence = witness.sequence if type(witness.sequence) is int else 0
        identity_matches = (
            bool(expected_installation_id)
            and bool(expected_client_instance_id)
            and witness.installation_id == expected_installation_id
            and witness.client_instance_id == expected_client_instance_id
        )
        fresh = (
            witness.received_at <= current.wall_time + float(max_witness_difference)
            and current.wall_time - witness.received_at <= float(max_witness_difference)
            and witness.expires_at >= current.wall_time
            and witness.expires_at > witness.received_at
        )
        signature_valid = witness.verify(verifier)
        operation_valid = witness.operation == "time-receipt"
        challenge_bound = bool(expected_witness_challenge) and hmac.compare_digest(
            witness.request_nonce, expected_witness_challenge
        )
        if not signature_valid:
            reasons.append("external-time-witness-signature-invalid")
        elif not operation_valid:
            reasons.append("external-time-witness-operation-invalid")
        elif not identity_matches:
            reasons.append("external-time-witness-identity-mismatch")
        elif not fresh:
            reasons.append("external-time-witness-stale-or-divergent")
        elif not expected_witness_challenge:
            historical_witness = True
            reasons.append("external-time-witness-historical-unbound")
        elif not challenge_bound:
            reasons.append("external-time-witness-challenge-mismatch")
        elif witness_floor is None:
            historical_witness = True
            reasons.append("external-time-witness-durable-floor-absent")
        else:
            try:
                advanced = witness_floor.compare_and_advance(
                    namespace=TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE,
                    installation_id=expected_installation_id,
                    client_instance_id=expected_client_instance_id,
                    sequence=witness.sequence,
                    received_at=witness.received_at,
                )
            except Exception:
                reasons.append("external-time-witness-durable-floor-unavailable")
            else:
                if advanced is True:
                    independently_witnessed = True
                else:
                    reasons.append("external-time-witness-sequence-or-time-regressed")

    if local_compromise_signal:
        state = "untrusted-clock-discontinuity"
    elif historical_witness:
        state = "historical-witness"
    elif witness is not None and not independently_witnessed:
        state = "untrusted-witness"
    elif independently_witnessed and (continuity_valid or previous is None or boot_changed):
        state = "externally-witnessed"
    elif boot_changed:
        state = "new-boot-unwitnessed"
    elif continuity_valid:
        state = "local-continuity-only"
    else:
        state = "provisional-unwitnessed"

    return TrustedTimeAssessment(
        state=state,
        continuity_valid=continuity_valid,
        independently_witnessed=independently_witnessed,
        response_authorized=False,
        drift_seconds=drift,
        witness_sequence=witness_sequence,
        reasons=tuple(reasons),
    )


def self_test() -> tuple[bool, str]:
    previous = LocalTimeSample(1000.0, 100.0, "a" * 64)
    current = LocalTimeSample(1010.0, 110.0, "a" * 64)
    result = assess_trusted_time(current, previous=previous)
    if not result.continuity_valid or result.independently_witnessed:
        return False, "local continuity appraisal did not preserve its trust boundary"
    rollback = assess_trusted_time(
        LocalTimeSample(900.0, 111.0, "a" * 64), previous=current
    )
    if not rollback.state.startswith("untrusted"):
        return False, "wall-clock rollback was not rejected"
    return True, "wall/monotonic continuity and fail-closed witness boundary verified"


__all__ = [
    "LocalTimeSample",
    "TrustedTimeAssessment",
    "assess_trusted_time",
    "capture_local_time_sample",
    "self_test",
]
