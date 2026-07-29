"""Deterministic, bounded recovery drills for local Angerona components."""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import asdict, dataclass
from typing import Callable, TypeVar

T = TypeVar("T")
_SCENARIOS = {
    "collector-unavailable",
    "control-plane-unavailable",
    "database-locked",
    "partial-state-corruption",
    "slow-storage",
    "transient-io",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")


@dataclass(frozen=True)
class RecoveryPolicy:
    max_attempts: int = 4
    base_delay_seconds: float = 0.05
    max_delay_seconds: float = 1.0
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        values = (
            self.base_delay_seconds, self.max_delay_seconds, self.timeout_seconds,
        )
        if not 1 <= int(self.max_attempts) <= 12:
            raise ValueError("recovery attempts must be between 1 and 12")
        if any(not math.isfinite(float(value)) or float(value) < 0 for value in values):
            raise ValueError("recovery timing must be finite and non-negative")
        if self.base_delay_seconds > self.max_delay_seconds:
            raise ValueError("base recovery delay exceeds maximum delay")
        if not 0.01 <= self.timeout_seconds <= 300:
            raise ValueError("recovery timeout must be between 0.01 and 300 seconds")


@dataclass(frozen=True)
class RecoveryEvidence:
    scenario: str
    outcome: str
    attempts: int
    elapsed_seconds: float
    error_types: tuple[str, ...]
    result_sha256: str
    evidence_sha256: str


def run_recovery_drill(
    scenario: str,
    operation: Callable[[], T],
    *,
    retryable: tuple[type[Exception], ...],
    policy: RecoveryPolicy = RecoveryPolicy(),
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[T | None, RecoveryEvidence]:
    """Run a fixed-name drill without shell, network, or unbounded retries."""
    if scenario not in _SCENARIOS:
        raise ValueError("unregistered reliability drill")
    if not retryable or any(
        not isinstance(error_type, type)
        or not issubclass(error_type, Exception)
        for error_type in retryable
    ):
        raise ValueError("reliability drill requires explicit retryable errors")
    started = float(clock())
    errors: list[str] = []
    result: T | None = None
    outcome = "failed"
    attempts = 0
    for index in range(policy.max_attempts):
        attempts = index + 1
        try:
            result = operation()
            outcome = "recovered" if errors else "passed"
            break
        except retryable as exc:
            errors.append(type(exc).__name__[:120])
            elapsed = max(0.0, float(clock()) - started)
            if attempts >= policy.max_attempts or elapsed >= policy.timeout_seconds:
                break
            delay = min(
                policy.max_delay_seconds,
                policy.base_delay_seconds * (2 ** index),
            )
            if elapsed + delay > policy.timeout_seconds:
                break
            sleeper(delay)
    elapsed = round(max(0.0, float(clock()) - started), 6)
    result_digest = hashlib.sha256(
        _canonical(result if outcome != "failed" else None)
    ).hexdigest()
    core = {
        "scenario": scenario, "outcome": outcome, "attempts": attempts,
        "elapsed_seconds": elapsed, "error_types": tuple(errors),
        "result_sha256": result_digest,
    }
    evidence = RecoveryEvidence(
        **core, evidence_sha256=hashlib.sha256(_canonical(core)).hexdigest(),
    )
    return result, evidence


def verify_recovery_evidence(evidence: RecoveryEvidence) -> bool:
    value = asdict(evidence)
    digest = value.pop("evidence_sha256")
    return hashlib.sha256(_canonical(value)).hexdigest() == digest
