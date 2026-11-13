from __future__ import annotations

import pytest

import angerona.modules.self_integrity as integrity
from angerona.resilience import supervisor


_SUPERVISOR_PREFIX = "angerona.resilience.supervisor:ProcessSupervisor."
_LOCKED_METHODS = ("_authenticated_record_locked", "_verified_peer_state_locked")


def _inert_target():
    """Stand in for unrelated targets without importing or calling providers."""
    return "inert"


def _supervisor_resolver():
    def resolve(spec):
        if spec.startswith(_SUPERVISOR_PREFIX):
            return getattr(supervisor.ProcessSupervisor, spec.rsplit(".", 1)[1], None)
        return _inert_target

    return resolve


@pytest.mark.parametrize("method", _LOCKED_METHODS)
def test_default_integrity_graph_detects_locked_supervisor_body_replacement(monkeypatch, method):
    # Class definitions only: do not construct a supervisor, heartbeat reader,
    # component or native process probe, and do not call any watched method.
    monkeypatch.setattr(integrity, "_resolve", _supervisor_resolver())
    engine = integrity.SelfIntegrityEngine()
    target = _SUPERVISOR_PREFIX + method
    assert target in engine._targets
    assert engine.arm() == engine.expected_count
    assert engine.check() == []
    baseline = engine.evidence(target)
    wrapper = method.removesuffix("_locked")
    wrapper_fingerprint = integrity._fingerprint(getattr(supervisor.ProcessSupervisor, wrapper))

    def replacement(*_args, **_kwargs):
        return "inert replacement"

    value = staticmethod(replacement) if method == "_authenticated_record_locked" else replacement
    monkeypatch.setattr(supervisor.ProcessSupervisor, method, value)
    assert integrity._fingerprint(getattr(supervisor.ProcessSupervisor, wrapper)) == wrapper_fingerprint
    findings = engine.check()
    assert any(target in finding for finding in findings)
    assert engine.tamper_kind(target) == "runtime-callable-drift"
    assert engine.evidence(target) == baseline


@pytest.mark.parametrize("method", _LOCKED_METHODS)
@pytest.mark.parametrize("missing_at_arm", (True, False))
def test_default_integrity_graph_reports_missing_locked_supervisor_coverage(monkeypatch, method, missing_at_arm):
    resolve = _supervisor_resolver()
    target = _SUPERVISOR_PREFIX + method
    unavailable = missing_at_arm

    def maybe_resolve(spec):
        return None if unavailable and spec == target else resolve(spec)

    monkeypatch.setattr(integrity, "_resolve", maybe_resolve)
    engine = integrity.SelfIntegrityEngine()
    assert target in engine._targets
    assert engine.arm() == engine.expected_count - int(missing_at_arm)
    if missing_at_arm:
        assert target in engine.unresolved
        assert engine.evidence(target) == {}
    else:
        assert engine.check() == []
        unavailable = True
    findings = engine.check()
    assert any(target in finding for finding in findings)
    assert engine.tamper_kind(target) == "coverage-unavailable"
