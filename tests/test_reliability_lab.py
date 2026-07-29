import pytest

from angerona.core.reliability_lab import (
    RecoveryPolicy, run_recovery_drill, verify_recovery_evidence,
)


def test_transient_failure_recovers_with_bounded_backoff():
    attempts = []
    delays = []

    def operation():
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError("temporarily locked")
        return {"state": "healthy"}

    result, evidence = run_recovery_drill(
        "database-locked", operation, retryable=(PermissionError,),
        policy=RecoveryPolicy(
            max_attempts=4, base_delay_seconds=0.1,
            max_delay_seconds=1, timeout_seconds=5,
        ),
        clock=lambda: 0, sleeper=delays.append,
    )
    assert result == {"state": "healthy"}
    assert evidence.outcome == "recovered"
    assert evidence.attempts == 3
    assert delays == [0.1, 0.2]
    assert verify_recovery_evidence(evidence)


def test_permanent_failure_stops_at_budget():
    calls = []

    def operation():
        calls.append(1)
        raise TimeoutError("offline")

    result, evidence = run_recovery_drill(
        "collector-unavailable", operation, retryable=(TimeoutError,),
        policy=RecoveryPolicy(
            max_attempts=3, base_delay_seconds=0,
            max_delay_seconds=0, timeout_seconds=1,
        ),
        clock=lambda: 0, sleeper=lambda _delay: None,
    )
    assert result is None
    assert evidence.outcome == "failed"
    assert evidence.attempts == 3
    assert len(calls) == 3


def test_unknown_faults_fail_immediately_and_scenarios_are_closed():
    with pytest.raises(RuntimeError, match="unsafe"):
        run_recovery_drill(
            "transient-io",
            lambda: (_ for _ in ()).throw(RuntimeError("unsafe")),
            retryable=(PermissionError,),
        )
    with pytest.raises(ValueError, match="unregistered"):
        run_recovery_drill(
            "execute-arbitrary-script", lambda: None,
            retryable=(PermissionError,),
        )
