import pytest

from angerona.core.identity_analytics import (
    AuthenticationEvent, IdentityAnalytics,
)


def test_password_spray_uses_tokens_and_bounded_window():
    detector = IdentityAnalytics(b"k" * 32, clock=lambda: 1000)
    findings = ()
    for index in range(5):
        findings = detector.observe(AuthenticationEvent(
            1000, f"user-{index}", "10.0.0.4", False,
        ))
    spray = next(item for item in findings if item.rule_id.endswith("password_spray"))
    assert spray.evidence_count == 5
    assert spray.account_token.startswith("tok_")
    assert "user-" not in repr(detector._events)
    assert "10.0.0.4" not in repr(detector._events)


def test_distributed_targeting_and_repeated_failures():
    detector = IdentityAnalytics(b"k" * 32, clock=lambda: 1000)
    findings = ()
    for index in range(5):
        findings = detector.observe(AuthenticationEvent(
            1000, "target", f"10.0.0.{index + 1}", False,
        ))
    assert any(
        item.rule_id.endswith("distributed_account_attack") for item in findings
    )
    for _ in range(10):
        findings = detector.observe(AuthenticationEvent(
            1000, "repeat", "10.0.0.99", False,
        ))
    assert any(item.rule_id.endswith("repeated_failure") for item in findings)


def test_service_account_and_privileged_source_changes():
    detector = IdentityAnalytics(b"k" * 32, clock=lambda: 1000)
    findings = detector.observe(AuthenticationEvent(
        1000, "svc-backup", "host-a", True, service_account=True,
    ))
    assert findings[0].rule_id.endswith("service_account_interactive")
    assert detector.observe(AuthenticationEvent(
        1000, "admin", "host-a", True, privileged=True,
    )) == ()
    findings = detector.observe(AuthenticationEvent(
        1000, "admin", "host-b", True, privileged=True,
    ))
    assert any(item.rule_id.endswith("privileged_new_source") for item in findings)


def test_invalid_or_stale_events_fail_closed():
    detector = IdentityAnalytics(b"k" * 32, clock=lambda: 10_000)
    with pytest.raises(ValueError, match="stale"):
        detector.observe(AuthenticationEvent(1, "user", "host-a", False))
    with pytest.raises(ValueError, match="source"):
        AuthenticationEvent(1, "user", "bad source!", False)
