"""Inert regression: a SOAR wrapper cannot renew an original producer proof."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule
from angerona.modules.adversary_combat import AdversaryCombat, HostMutationHeld
from angerona.modules.soar_engine import ActiveResponseSOAR


def event(module, **details):
    return Event(module, "Inert retained finding", Severity.HIGH, time.time(),
                 dict(disposition="active", response_authorized=True, **details))


@pytest.mark.parametrize("admission", [False, True])
@pytest.mark.parametrize("origin", ["SpywareGuard", "YARA Scanner", "Legacy Detector"])
@pytest.mark.parametrize("revocation", ["expired", "review-revoked"])
def test_fresh_signed_soar_wrapper_cannot_replace_original_proof(admission, origin, revocation):
    request = event("Active Response SOAR Request", origin_module=origin,
                    origin_event_digest="a" * 64, origin_ts=time.time() - 3600,
                    original_proof_status=revocation,
                    queue_request_id="b" * 32)
    # The signature/integrity seam deliberately succeeds: transport
    # authentication must not supply the missing original detector receipt.
    combat = SimpleNamespace(_integrity_ok=lambda _event: True,
                             _manager=SimpleNamespace(modules={}))
    with pytest.raises(HostMutationHeld, match="exact original producer proof"):
        AdversaryCombat._require_current_response_event(combat, request, admission=admission)


def test_direct_original_spyware_proof_still_rechecks_the_actual_producer():
    class Producer(BaseModule):
        __module__ = "angerona.modules.spyware_guard"
        name = "SpywareGuard"
        def __init__(self):
            self._stop = threading.Event()
            self._run_context = threading.local()
            self.current = True
            self.seen = []
        def verify_response_event(self, original):
            self.seen.append(original)
            return self.current

    producer = Producer()
    original = event("SpywareGuard")
    combat = SimpleNamespace(_integrity_ok=lambda _event: True,
                             _manager=SimpleNamespace(modules={"SpywareGuard": producer}))
    AdversaryCombat._require_current_response_event(combat, original)
    producer.current = False
    with pytest.raises(HostMutationHeld, match="expired or was revoked"):
        AdversaryCombat._require_current_response_event(combat, original)
    assert producer.seen == [original, original]


def test_practice_markers_cannot_bypass_synthetic_envelope_hold():
    request = Event("Active Response SOAR Request", "Inert wrapper", Severity.HIGH,
                    time.time(), {"disposition": "practice", "response_authorized": True,
                                  "receipt_type": "purple_simulation_validation"})
    combat = SimpleNamespace(_integrity_ok=lambda _event: True,
                             _manager=SimpleNamespace(modules={}))
    with pytest.raises(HostMutationHeld, match="exact original producer proof"):
        AdversaryCombat._require_current_response_event(combat, request, admission=True)


def test_direct_legacy_family_keeps_existing_non_synthetic_boundary():
    combat = SimpleNamespace(_integrity_ok=lambda _event: True,
                             _manager=SimpleNamespace(modules={}))
    AdversaryCombat._require_current_response_event(combat, event("Legacy Detector"))


@pytest.mark.parametrize("practice", [False, True])
def test_soar_never_mints_fresh_wrapper_and_preserves_exact_issuer_adapter(practice):
    published, emitted, delegated = [], [], []
    original = event("Purple Remediation Guard" if practice else "SpywareGuard",
                     **({"receipt_type": "purple_simulation_validation"} if practice else {}))

    def native_forbidden(*_args):
        pytest.fail("Held delegation must not resolve a live process or request Combat")

    soar = SimpleNamespace(
        _event_integrity_ok=lambda _event: True,
        _event_in_response_scope=lambda _event: True,
        _event_path=lambda _event: "",
        _exact_process_binding_ok=native_forbidden,
        _combat_consumer=native_forbidden,
        _delegate_issuer_original=lambda original, **_kwargs: delegated.append(original),
        publish_event=published.append,
        emit=lambda message, severity, **details: emitted.append((message, severity, details)),
    )
    ActiveResponseSOAR._kill_and_rollback(soar, original)
    assert published == []
    if practice:
        assert delegated == [original] and emitted == []
    else:
        assert delegated == [] and len(emitted) == 1
        details = emitted[0][2]
        assert details["response_authorized"] is False and details["mitigated"] is False
        assert details["receipt_status"] == "held-original-proof-adapter"
        assert details["trigger_ts"] == original.ts
