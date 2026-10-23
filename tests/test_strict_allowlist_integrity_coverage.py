"""The stricter trust entry point must have its own live integrity coverage."""
from angerona.core import process_allowlist
from angerona.modules.self_integrity import SelfIntegrityEngine


def test_privileged_digest_predicate_monkeypatch_is_detected(monkeypatch):
    engine = SelfIntegrityEngine()
    target = "angerona.core.process_allowlist:is_digest_pinned_allowed"
    assert target in engine._targets
    assert engine.arm() == engine.expected_count
    monkeypatch.setattr(process_allowlist, "is_digest_pinned_allowed", lambda *_a, **_k: True)
    assert any(target in finding for finding in engine.check())


def test_missing_privileged_predicate_is_not_complete_coverage(monkeypatch):
    monkeypatch.delattr(process_allowlist, "is_digest_pinned_allowed")
    engine = SelfIntegrityEngine()
    engine.arm()
    target = "angerona.core.process_allowlist:is_digest_pinned_allowed"
    assert target in engine.unresolved
    assert any(target in finding for finding in engine.check())
