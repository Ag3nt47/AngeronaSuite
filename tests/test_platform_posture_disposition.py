"""Real platform assessment envelopes retain severity without claiming intrusion."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.core.threat import active_threat_events, event_disposition
from angerona.modules.platform_attestation_guard import PlatformAttestationGuard
from test_measured_boot import NONCE, _document, _quote, AcceptingVerifier


def observation(document, *, verifier=None):
    class Provider:
        def collect(self, _nonce):
            return copy.deepcopy(document)

    authority = BusAuthority(b'platform-disposition-fixture-key')
    bus = EventBus()
    bus.arm(authority)
    guard = PlatformAttestationGuard(Provider(), nonce_factory=lambda: NONCE,
                                     quote_verifier=verifier)
    guard.bind(bus)
    guard.observe_once()
    event, = bus.recent(1)
    assert authority.verify(event)
    return event, authority, guard


@pytest.mark.parametrize('field,value', [
    ('secure_boot', False), ('vbs_running', False), ('hvci_running', False),
    ('code_integrity_enabled', False), ('test_signing', True), ('boot_debug', True),
    ('dma_protection_available', False), ('external_dma_policy_restrictive', False),
])
def test_exact_native_producer_posture_is_exposure_with_original_high_evidence(field, value):
    event, authority, guard = observation(_document(**{field: value}))
    original = copy.deepcopy(event)
    assert event.severity is Severity.HIGH and guard.health == 20
    assert event_disposition(event) == 'exposure'
    assert not active_threat_events([event])
    assert event == original and authority.verify(event)
    assert event.details['response_authorized'] is False


@pytest.mark.parametrize('quote,verifier', [(None, None), (_quote(), None), (_quote(), AcceptingVerifier())])
def test_posture_with_absent_unverified_or_verified_quote_stays_separately_risky(quote, verifier):
    event, authority, guard = observation(_document(quote=quote, dma_protection_available=False), verifier=verifier)
    assert event_disposition(event) == 'exposure' and authority.verify(event)
    assert guard.health == 20


@pytest.mark.parametrize('field,value', [
    ('response_authorized', True), ('response_contract', {}), ('active_attack', True),
    ('active_exploitation', True), ('new_unknown_field', 'unrecognized'),
    ('risk_codes', ['kernel-dma-protection-unavailable', 'tpm-quote-verification-failed']),
    ('risk_codes', ['kernel-dma-protection-unavailable', 'unknown-new-risk']),
    ('risk_codes', ['kernel-dma-protection-unavailable'] * 2),
    ('posture_consistent', 0), ('hardware_attested', 0),
    ('unknown_fields', ['unrecognized']), ('unknown_fields', 'dma_protection_available'),
    ('evidence_sha256', 'not-a-digest'), ('quote_state', 'verification-failed'),
    ('mitre_tags', ('T1547', 'T1562.001')),
])
def test_unknown_or_active_extensions_do_not_gain_passive_classification(field, value):
    event, _authority, _guard = observation(_document(dma_protection_available=False))
    details = copy.deepcopy(event.details)
    details[field] = value
    changed = replace(event, details=details)
    assert event_disposition(changed) == 'active'


def test_other_producer_and_critical_platform_record_remain_active():
    event, _authority, _guard = observation(_document(dma_protection_available=False))
    assert event_disposition(replace(event, module='Other Detector')) == 'active'
    assert event_disposition(replace(event, severity=Severity.CRITICAL)) == 'active'


@pytest.mark.parametrize('quote', [_quote('x' * 43), _quote()])
def test_actual_quote_integrity_failure_remains_active(quote):
    class Reject:
        def verify(self, *_args, **_kwargs):
            return False

    event, authority, guard = observation(_document(quote=quote, dma_protection_available=False), verifier=Reject())
    assert event_disposition(event) == 'active' and authority.verify(event)
    assert guard.health == 10
